//! Shared application state: the single source of truth wired into both the MCP
//! server (AI-facing) and the Web UI (human-facing). Credential boundaries are
//! enforced here — AI paths only ever see redacted host data.

use crate::audit::AuditLog;
use crate::config::Config;
use crate::jumpserver::{Asset, JumpServerClient};
use crate::error::{ConnectorError, Result};
use crate::session::{ExecLimits, SessionManager};
use crate::ssh::ConnectionPool;
use crate::types::{
    DirEntry, ExecPayload, ExecResult, HostDetail, HostSpec, HostStatus, HostSummary, KeyName,
    ReadResult, ScreenSnapshot, SessionInfo,
};
use crate::vault::Vault;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct LocalFileTransfer {
    pub local_path: PathBuf,
    pub remote_path: String,
    pub bytes: u64,
    pub sha256: String,
    pub verified: bool,
}

pub struct AppState {
    pub vault: Arc<Vault>,
    pub pool: Arc<ConnectionPool>,
    pub sessions: Arc<SessionManager>,
    pub audit: Arc<AuditLog>,
    pub config: Config,
    /// Loopback bearer token shared with the local MCP stdio shim.
    pub local_token: String,
    pub jumpserver: Option<Arc<JumpServerClient>>,
}

impl AppState {
    pub fn new(
        vault: Arc<Vault>,
        audit: Arc<AuditLog>,
        config: Config,
        local_token: String,
    ) -> Result<Arc<Self>> {
        let pool = Arc::new(ConnectionPool::new(vault.clone(), config.keepalive_secs));
        let limits = ExecLimits {
            timeout: Duration::from_millis(config.exec_timeout_ms),
            output_cap_bytes: config.exec_output_cap_bytes,
        };
        let sessions = SessionManager::new(
            pool.clone(),
            limits,
            Duration::from_secs(config.pty_idle_ttl_secs),
        );
        Ok(Arc::new(Self {
            vault,
            pool,
            sessions,
            audit,
            jumpserver: config
                .jumpserver
                .clone()
                .map(JumpServerClient::new)
                .transpose()?
                .map(Arc::new),
            config,
            local_token,
        }))
    }

    // --- Host management (AI may create/update; reads are redacted) ---

    pub fn add_host(&self, spec: HostSpec) -> Result<String> {
        let detail = host_spec_audit_detail(&spec);
        let id = self.vault.add_host(spec)?;
        self.audit.record(
            AuditLog::entry("host_add")
                .with_host(&id)
                .with_detail(detail),
        );
        Ok(id)
    }

    pub fn update_host(&self, id: &str, spec: HostSpec) -> Result<()> {
        let detail = host_spec_audit_detail(&spec);
        self.vault.update_host(id, spec)?;
        self.audit.record(
            AuditLog::entry("host_update")
                .with_host(id)
                .with_detail(detail),
        );
        Ok(())
    }

    pub async fn remove_host(&self, id: &str) -> Result<()> {
        self.pool.disconnect(id).await;
        self.vault.remove_host(id)?;
        self.audit
            .record(AuditLog::entry("host_remove").with_host(id));
        Ok(())
    }

    /// AI-facing host list: summaries only, never secrets.
    pub async fn list_hosts(&self) -> Result<Vec<HostSummary>> {
        let configs = self.vault.list_host_configs()?;
        let mut out = Vec::with_capacity(configs.len());
        for c in &configs {
            let status = self.pool.status(&c.id).await;
            out.push(HostSummary::from_config(c, status));
        }
        Ok(out)
    }

    pub async fn list_host_details(&self) -> Result<Vec<HostDetail>> {
        let configs = self.vault.list_host_configs()?;
        let mut out = Vec::with_capacity(configs.len());
        for c in &configs {
            let status = self.pool.status(&c.id).await;
            out.push(HostDetail::from_config(c, status));
        }
        Ok(out)
    }

    pub async fn host_status(&self, id: &str) -> HostStatus {
        self.pool.status(id).await
    }

    pub async fn connect_host(&self, id: &str) -> Result<()> {
        match self.pool.connect(id).await {
            Ok(()) => {
                self.audit
                    .record(AuditLog::entry("host_connect").with_host(id));
                Ok(())
            }
            Err(e) => {
                self.audit.record(
                    AuditLog::entry("host_connect_failed")
                        .with_host(id)
                        .with_detail(error_audit_detail(&e)),
                );
                Err(e)
            }
        }
    }

    pub async fn disconnect_host(&self, id: &str) -> Result<()> {
        self.pool.disconnect(id).await;
        self.audit
            .record(AuditLog::entry("host_disconnect").with_host(id));
        Ok(())
    }

    pub async fn jumpserver_assets(&self) -> Result<Vec<Asset>> {
        let client = self.jumpserver.as_ref().ok_or_else(|| ConnectorError::bad_request("JumpServer is not configured"))?;
        client.list_assets().await
    }

    pub async fn jumpserver_accounts(&self, asset_id: &str) -> Result<Vec<crate::jumpserver::Account>> {
        let client = self.jumpserver.as_ref().ok_or_else(|| ConnectorError::bad_request("JumpServer is not configured"))?;
        client.list_accounts(asset_id).await
    }

    pub async fn jumpserver_asset_session(
        &self,
        asset_id: &str,
        account_id: &str,
        rows: u16,
        cols: u16,
    ) -> Result<SessionInfo> {
        let client = self.jumpserver.as_ref().ok_or_else(|| ConnectorError::bad_request("JumpServer is not configured"))?;
        let password_host_id = client.ssh_password_host_id();
        let password_cfg = self.vault.get_host_config(password_host_id)?;
        let cfg = client.resolve_target(asset_id, account_id, password_cfg.auth).await?;
        let target = cfg;
        let host_id = target.id.clone();
        self.sessions.open_pty_on_config(&host_id, &target, rows, cols).await
    }


    // --- Exec / PTY / SFTP (delegated to the session manager) ---

    pub async fn exec(&self, host_id: &str, payload: &ExecPayload) -> Result<ExecResult> {
        match self.sessions.exec(host_id, payload).await {
            Ok(r) => {
                self.audit.record(
                    AuditLog::entry("exec")
                        .with_host(host_id)
                        .with_exit(r.exit_code)
                        .with_detail(json!({
                            "payload": exec_payload_audit_detail(payload),
                            "stdout_bytes": r.stdout.len(),
                            "stderr_bytes": r.stderr.len(),
                            "duration_ms": r.duration_ms,
                            "truncated": r.truncated,
                            "timed_out": r.timed_out,
                            "had_invalid_utf8": r.had_invalid_utf8,
                        })),
                );
                Ok(r)
            }
            Err(e) => {
                self.audit.record(
                    AuditLog::entry("exec_failed")
                        .with_host(host_id)
                        .with_detail(json!({
                            "payload": exec_payload_audit_detail(payload),
                            "error": error_audit_detail(&e),
                        })),
                );
                Err(e)
            }
        }
    }

    pub async fn open_pty(&self, host_id: &str, rows: u16, cols: u16) -> Result<SessionInfo> {
        match self.sessions.open_pty(host_id, rows, cols).await {
            Ok(info) => {
                self.audit.record(
                    AuditLog::entry("pty_open")
                        .with_host(host_id)
                        .with_session(&info.session_id)
                        .with_detail(json!({ "rows": rows, "cols": cols })),
                );
                Ok(info)
            }
            Err(e) => {
                self.audit.record(
                    AuditLog::entry("pty_open_failed")
                        .with_host(host_id)
                        .with_detail(json!({
                            "rows": rows,
                            "cols": cols,
                            "error": error_audit_detail(&e),
                        })),
                );
                Err(e)
            }
        }
    }

    pub async fn open_root_pty(&self, host_id: &str, rows: u16, cols: u16) -> Result<SessionInfo> {
        let cfg = self.vault.get_host_config(host_id)?;
        let result = self
            .sessions
            .open_root_pty(host_id, rows, cols, cfg.become_root.as_ref())
            .await;
        match result {
            Ok(info) => {
                self.audit.record(
                    AuditLog::entry("pty_open_root")
                        .with_host(host_id)
                        .with_session(&info.session_id)
                        .with_detail(json!({ "rows": rows, "cols": cols, "method": "su" })),
                );
                Ok(info)
            }
            Err(e) => {
                self.audit.record(
                    AuditLog::entry("pty_open_root_failed")
                        .with_host(host_id)
                        .with_detail(json!({
                            "rows": rows,
                            "cols": cols,
                            "method": "su",
                            "error": error_audit_detail(&e),
                        })),
                );
                Err(e)
            }
        }
    }

    pub async fn pty_send_text(&self, session_id: &str, text: &str) -> Result<()> {
        self.sessions.pty_send_text(session_id, text).await?;
        self.audit.record(
            AuditLog::entry("pty_send_text")
                .with_session(session_id)
                .with_detail(json!({ "bytes": text.len(), "redacted": true })),
        );
        Ok(())
    }

    pub async fn pty_send_key(&self, session_id: &str, key: &KeyName) -> Result<()> {
        self.sessions.pty_send_key(session_id, key).await?;
        self.audit.record(
            AuditLog::entry("pty_send_key")
                .with_session(session_id)
                .with_detail(json!({ "key": format!("{key:?}") })),
        );
        Ok(())
    }

    pub async fn pty_snapshot(&self, session_id: &str) -> Result<ScreenSnapshot> {
        self.sessions.pty_snapshot(session_id).await
    }

    pub async fn pty_read(&self, session_id: &str) -> Result<ReadResult> {
        self.sessions.pty_read(session_id).await
    }

    pub async fn pty_resize(&self, session_id: &str, rows: u16, cols: u16) -> Result<()> {
        self.sessions.pty_resize(session_id, rows, cols).await
    }

    pub async fn close_pty(&self, session_id: &str) -> Result<()> {
        self.sessions.close_pty(session_id).await?;
        self.audit
            .record(AuditLog::entry("pty_close").with_session(session_id));
        Ok(())
    }

    pub async fn list_sessions(&self) -> Vec<SessionInfo> {
        self.sessions.list_sessions().await
    }

    /// Raw stdin from a Web-UI terminal takeover (bypasses audit-per-keystroke).
    pub async fn pty_input_ws(&self, session_id: &str, bytes: Vec<u8>) -> Result<()> {
        self.sessions.pty_input(session_id, bytes).await
    }

    pub async fn sftp_list(&self, host_id: &str, path: &str) -> Result<Vec<DirEntry>> {
        let entries = self.sessions.sftp_list(host_id, path).await?;
        self.audit.record(
            AuditLog::entry("sftp_list")
                .with_host(host_id)
                .with_detail(json!({ "path": path, "entries": entries.len() })),
        );
        Ok(entries)
    }

    pub async fn sftp_get(&self, host_id: &str, path: &str) -> Result<Vec<u8>> {
        let d = self.sessions.sftp_get(host_id, path).await?;
        self.audit.record(
            AuditLog::entry("sftp_get")
                .with_host(host_id)
                .with_detail(json!({ "path": path, "bytes": d.len() })),
        );
        Ok(d)
    }

    pub async fn sftp_put(&self, host_id: &str, path: &str, data: &[u8]) -> Result<()> {
        self.sessions.sftp_put(host_id, path, data).await?;
        self.audit.record(
            AuditLog::entry("sftp_put")
                .with_host(host_id)
                .with_detail(json!({ "path": path, "bytes": data.len() })),
        );
        Ok(())
    }

    pub async fn sftp_download_file(
        &self,
        host_id: &str,
        remote_path: &str,
        local_path: &str,
        overwrite: bool,
        create_parent_dirs: bool,
        chunk_size: usize,
        verify: bool,
    ) -> Result<LocalFileTransfer> {
        let local_path = allowed_local_write_path(local_path, create_parent_dirs)?;
        if local_path.exists() && !overwrite {
            return Err(ConnectorError::bad_request(format!(
                "local file already exists: {}; pass overwrite=true to replace it",
                local_path.display()
            )));
        }
        let report = self
            .sessions
            .sftp_download_file(
                host_id,
                remote_path,
                &local_path,
                overwrite,
                chunk_size,
                verify,
            )
            .await?;
        self.audit.record(
            AuditLog::entry("sftp_download_file")
                .with_host(host_id)
                .with_detail(json!({
                    "remote_path": remote_path,
                    "local_path": local_path.display().to_string(),
                    "bytes": report.bytes,
                    "sha256": report.sha256,
                    "verified": report.verified,
                    "overwrite": overwrite,
                    "create_parent_dirs": create_parent_dirs,
                    "chunk_size_bytes": chunk_size,
                })),
        );
        Ok(LocalFileTransfer {
            local_path,
            remote_path: remote_path.to_string(),
            bytes: report.bytes,
            sha256: report.sha256,
            verified: report.verified,
        })
    }

    pub async fn sftp_upload_file(
        &self,
        host_id: &str,
        local_path: &str,
        remote_path: &str,
        overwrite: bool,
        create_parent_dirs: bool,
        chunk_size: usize,
        verify: bool,
    ) -> Result<LocalFileTransfer> {
        let local_path = allowed_local_read_path(local_path)?;
        let report = self
            .sessions
            .sftp_upload_file(
                host_id,
                &local_path,
                remote_path,
                overwrite,
                create_parent_dirs,
                chunk_size,
                verify,
            )
            .await?;
        self.audit.record(
            AuditLog::entry("sftp_upload_file")
                .with_host(host_id)
                .with_detail(json!({
                    "local_path": local_path.display().to_string(),
                    "remote_path": remote_path,
                    "bytes": report.bytes,
                    "sha256": report.sha256,
                    "verified": report.verified,
                    "overwrite": overwrite,
                    "create_parent_dirs": create_parent_dirs,
                    "chunk_size_bytes": chunk_size,
                })),
        );
        Ok(LocalFileTransfer {
            local_path,
            remote_path: remote_path.to_string(),
            bytes: report.bytes,
            sha256: report.sha256,
            verified: report.verified,
        })
    }
}

fn host_spec_audit_detail(spec: &HostSpec) -> serde_json::Value {
    json!({
        "alias": spec.alias,
        "host": spec.host,
        "port": spec.port,
        "user": spec.user,
        "auth_kind": spec.auth.kind(),
        "jump_count": spec.jump_hosts.len(),
        "env_keys": spec.env.keys().cloned().collect::<Vec<_>>(),
        "become_root_enabled": spec.become_root.as_ref().map(|c| c.enabled).unwrap_or(false),
        "become_root_command": spec.become_root.as_ref().map(|c| c.command.clone()),
    })
}

fn exec_payload_audit_detail(payload: &ExecPayload) -> serde_json::Value {
    match payload {
        ExecPayload::Argv { argv } => json!({
            "type": "argv",
            "argc": argv.len(),
            "preview": argv_preview(argv),
        }),
        ExecPayload::Script { script } => json!({
            "type": "script",
            "bytes": script.len(),
            "lines": script.lines().count(),
            "preview": text_preview(script),
        }),
        ExecPayload::Raw { raw } => json!({
            "type": "raw",
            "bytes": raw.len(),
            "preview": text_preview(raw),
        }),
    }
}

fn argv_preview(argv: &[String]) -> String {
    let joined = argv.join(" ");
    text_preview(&joined)
}

fn text_preview(text: &str) -> String {
    const MAX: usize = 240;
    let sanitized = text.replace('\n', "\\n").replace('\r', "\\r");
    if sanitized.chars().count() <= MAX {
        sanitized
    } else {
        format!("{}...", sanitized.chars().take(MAX).collect::<String>())
    }
}

fn error_audit_detail(error: &ConnectorError) -> serde_json::Value {
    json!({
        "code": error.code,
        "message": error.message,
        "context": error.context,
    })
}

fn allowed_local_roots() -> Result<Vec<PathBuf>> {
    let cwd = std::env::current_dir()
        .map_err(|e| ConnectorError::internal(format!("read current dir: {e}")))?
        .canonicalize()
        .map_err(|e| ConnectorError::internal(format!("canonicalize current dir: {e}")))?;
    let tmp = Path::new("/tmp")
        .canonicalize()
        .map_err(|e| ConnectorError::internal(format!("canonicalize /tmp: {e}")))?;
    Ok(vec![tmp, cwd])
}

fn is_allowed_local_path(path: &Path) -> Result<bool> {
    Ok(allowed_local_roots()?
        .iter()
        .any(|root| path == root || path.starts_with(root)))
}

fn allowed_local_read_path(path: &str) -> Result<PathBuf> {
    let path = Path::new(path);
    let canonical = path
        .canonicalize()
        .map_err(|e| ConnectorError::bad_request(format!("local file is not readable: {e}")))?;
    if !canonical.is_file() {
        return Err(ConnectorError::bad_request(format!(
            "local path is not a file: {}",
            canonical.display()
        )));
    }
    if !is_allowed_local_path(&canonical)? {
        return Err(ConnectorError::bad_request(format!(
            "local path is outside allowed roots (/tmp and current project): {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn allowed_local_write_path(path: &str, create_parent_dirs: bool) -> Result<PathBuf> {
    let path = lexical_local_path(path)?;
    let parent = path.parent().ok_or_else(|| {
        ConnectorError::bad_request(
            "local_path must include a parent directory under /tmp or current project",
        )
    })?;
    if !is_lexically_allowed_local_path(&path)? {
        return Err(ConnectorError::bad_request(format!(
            "local path is outside allowed roots (/tmp and current project): {}",
            path.display()
        )));
    }
    if create_parent_dirs {
        create_allowed_local_parents(parent)?;
    }
    let parent = parent
        .canonicalize()
        .map_err(|e| ConnectorError::bad_request(format!("local parent is not writable: {e}")))?;
    if !parent.is_dir() {
        return Err(ConnectorError::bad_request(format!(
            "local parent is not a directory: {}",
            parent.display()
        )));
    }
    if !is_allowed_local_path(&parent)? {
        return Err(ConnectorError::bad_request(format!(
            "local path is outside allowed roots (/tmp and current project): {}",
            parent.display()
        )));
    }
    let filename = path.file_name().ok_or_else(|| {
        ConnectorError::bad_request("local_path must end with a file name, not a directory")
    })?;
    let destination = parent.join(filename);
    if destination.exists() {
        let canonical = destination.canonicalize().map_err(|e| {
            ConnectorError::bad_request(format!("canonicalize local destination: {e}"))
        })?;
        if !is_allowed_local_path(&canonical)? {
            return Err(ConnectorError::bad_request(
                "local destination resolves outside /tmp or the current project",
            ));
        }
    }
    Ok(destination)
}

fn create_allowed_local_parents(parent: &Path) -> Result<()> {
    let mut cursor = parent.to_path_buf();
    let mut missing = Vec::new();
    while !cursor.exists() {
        let name = cursor.file_name().ok_or_else(|| {
            ConnectorError::bad_request("local parent path has no existing ancestor")
        })?;
        missing.push(name.to_os_string());
        cursor = cursor
            .parent()
            .ok_or_else(|| {
                ConnectorError::bad_request("local parent path has no existing ancestor")
            })?
            .to_path_buf();
    }

    let mut canonical = cursor.canonicalize().map_err(|e| {
        ConnectorError::bad_request(format!("canonicalize local parent ancestor: {e}"))
    })?;
    if !canonical.is_dir() || !is_allowed_local_path(&canonical)? {
        return Err(ConnectorError::bad_request(
            "local parent resolves outside /tmp or the current project",
        ));
    }

    for name in missing.iter().rev() {
        let candidate = canonical.join(name);
        match std::fs::create_dir(&candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(ConnectorError::bad_request(format!(
                    "create local parent directory: {error}"
                )));
            }
        }
        canonical = candidate.canonicalize().map_err(|e| {
            ConnectorError::bad_request(format!("canonicalize created local parent: {e}"))
        })?;
        if !canonical.is_dir() || !is_allowed_local_path(&canonical)? {
            return Err(ConnectorError::bad_request(
                "created local parent resolves outside /tmp or the current project",
            ));
        }
    }
    Ok(())
}

fn lexical_local_path(path: &str) -> Result<PathBuf> {
    let path = Path::new(path);
    let mut absolute = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir()
            .map_err(|e| ConnectorError::internal(format!("read current dir: {e}")))?
    };
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => absolute.push(prefix.as_os_str()),
            std::path::Component::RootDir => absolute.push(Path::new("/")),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err(ConnectorError::bad_request(
                    "local_path must not contain '..' components",
                ));
            }
            std::path::Component::Normal(part) => absolute.push(part),
        }
    }
    Ok(absolute)
}

fn is_lexically_allowed_local_path(path: &Path) -> Result<bool> {
    let cwd = std::env::current_dir()
        .map_err(|e| ConnectorError::internal(format!("read current dir: {e}")))?;
    Ok(path.starts_with("/tmp") || path.starts_with("/private/tmp") || path.starts_with(cwd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_tmp_write_paths() {
        let path = allowed_local_write_path("/tmp/ssh-connector-test.bin", true).unwrap();
        assert!(path.starts_with(Path::new("/tmp")) || path.starts_with(Path::new("/private/tmp")));
    }

    #[test]
    fn rejects_paths_outside_allowed_roots() {
        let err = allowed_local_read_path("/etc/hosts").unwrap_err();
        assert_eq!(err.code, crate::error::ErrorCode::BadRequest);
    }

    #[test]
    fn creates_nested_tmp_parent_when_requested() {
        let unique = format!(
            "/tmp/ssh-connector-state-test-{}/nested/file.bin",
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        let path = allowed_local_write_path(&unique, true).unwrap();
        assert!(path.parent().unwrap().is_dir());
        std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).unwrap();
    }

    #[test]
    fn rejects_local_parent_traversal() {
        let error = allowed_local_write_path("/tmp/../etc/blocked", true).unwrap_err();
        assert_eq!(error.code, crate::error::ErrorCode::BadRequest);
    }

    #[test]
    fn rejects_symlinked_parent_before_creating_outside_allowed_roots() {
        let token = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
        let base = PathBuf::from(format!("/tmp/ssh-connector-symlink-test-{token}"));
        let outside = PathBuf::from(std::env::var("HOME").unwrap())
            .join(format!(".ssh-connector-symlink-target-{token}"));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, base.join("link")).unwrap();

        let error =
            allowed_local_write_path(base.join("link/nested/file.bin").to_str().unwrap(), true)
                .unwrap_err();
        assert_eq!(error.code, crate::error::ErrorCode::BadRequest);
        assert!(!outside.join("nested").exists());

        std::fs::remove_dir_all(&base).unwrap();
        std::fs::remove_dir_all(&outside).unwrap();
    }

    #[test]
    fn audit_preview_truncates_unicode_on_character_boundaries() {
        let preview = text_preview(&"中".repeat(241));
        assert!(preview.ends_with("..."));
        assert_eq!(preview.chars().count(), 243);
    }
}
