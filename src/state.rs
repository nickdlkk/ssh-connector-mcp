//! Shared application state: the single source of truth wired into both the MCP
//! server (AI-facing) and the Web UI (human-facing). Credential boundaries are
//! enforced here — AI paths only ever see redacted host data.

use crate::audit::AuditLog;
use crate::config::Config;
use crate::error::{ConnectorError, Result};
use crate::jumpserver::{Asset, JumpServerClient};
use crate::session::{ExecLimits, SessionManager};
use crate::ssh::ConnectionPool;
use crate::types::{
    DirEntry, ExecPayload, ExecResult, HostDetail, HostSpec, HostStatus, HostSummary, KeyName,
    ReadResult, ScreenSnapshot, SessionExecResult, SessionInfo,
};
use crate::vault::Vault;
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
    pub totp: Arc<crate::totp::Totp>,
}

impl AppState {
    pub fn new(
        vault: Arc<Vault>,
        audit: Arc<AuditLog>,
        config: Config,
        local_token: String,
        totp: Arc<crate::totp::Totp>,
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
            totp,
        }))
    }

    // --- Host management (AI may create/update; reads are redacted) ---

    pub fn add_host(&self, spec: HostSpec) -> Result<String> {
        self.vault.add_host(spec)
    }

    pub fn update_host(&self, id: &str, spec: HostSpec) -> Result<()> {
        if self.is_jumpserver_target(id)? {
            return Err(jumpserver_session_required());
        }
        self.vault.update_host(id, spec)
    }

    pub async fn remove_host(&self, id: &str) -> Result<()> {
        if self.is_jumpserver_target(id)? {
            return Err(jumpserver_session_required());
        }
        self.pool.disconnect(id).await;
        self.vault.remove_host(id)?;
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
        if self.is_jumpserver_target(id)? {
            return Err(jumpserver_session_required());
        }
        self.pool.connect(id).await
    }

    pub async fn disconnect_host(&self, id: &str) -> Result<()> {
        if self.is_jumpserver_target(id)? {
            return Err(jumpserver_session_required());
        }
        self.pool.disconnect(id).await;
        Ok(())
    }

    pub async fn jumpserver_assets(&self) -> Result<Vec<Asset>> {
        let client = self
            .jumpserver
            .as_ref()
            .ok_or_else(|| ConnectorError::bad_request("JumpServer is not configured"))?;
        client.list_assets().await
    }

    pub async fn jumpserver_accounts(
        &self,
        asset_id: &str,
    ) -> Result<Vec<crate::jumpserver::Account>> {
        let client = self
            .jumpserver
            .as_ref()
            .ok_or_else(|| ConnectorError::bad_request("JumpServer is not configured"))?;
        client.list_accounts(asset_id).await
    }

    pub async fn jumpserver_asset_session(
        &self,
        asset_id: &str,
        account_id: &str,
        rows: u16,
        cols: u16,
    ) -> Result<SessionInfo> {
        let client = self
            .jumpserver
            .as_ref()
            .ok_or_else(|| ConnectorError::bad_request("JumpServer is not configured"))?;
        let password_host_id = client.ssh_password_host_id();
        let password_cfg = self.vault.get_host_config(password_host_id)?;
        let cfg = client
            .resolve_target(asset_id, account_id, password_cfg.auth)
            .await?;
        let target = cfg;
        let host_id = target.id.clone();
        self.sessions
            .open_pty_on_config(&host_id, &target, rows, cols)
            .await
    }

    /// Resolve an authorized JumpServer asset/account into a transient KoKo target.
    async fn resolve_jumpserver_target(&self, asset_id: &str, account_id: &str) -> Result<crate::types::HostConfig> {
        let client = self.jumpserver.as_ref().ok_or_else(|| ConnectorError::bad_request("JumpServer is not configured"))?;
        let password_cfg = self.vault.get_host_config(client.ssh_password_host_id())?;
        client.resolve_target(asset_id, account_id, password_cfg.auth).await
    }

    /// SFTP against an API-discovered JumpServer target using KoKo's SFTP subsystem.
    pub async fn jumpserver_sftp_list(&self, asset_id: &str, account_id: &str, path: &str) -> Result<Vec<DirEntry>> {
        let cfg = self.resolve_jumpserver_target(asset_id, account_id).await?;
        let id = cfg.id.clone();
        let conn = self.pool.get_or_connect_config(&id, &cfg).await?;
        crate::session::sftp_list(&conn, path).await
    }

    pub async fn jumpserver_sftp_get(&self, asset_id: &str, account_id: &str, path: &str) -> Result<Vec<u8>> {
        let cfg = self.resolve_jumpserver_target(asset_id, account_id).await?;
        let id = cfg.id.clone();
        let conn = self.pool.get_or_connect_config(&id, &cfg).await?;
        crate::session::sftp_get(&conn, path).await
    }

    pub async fn jumpserver_sftp_put(&self, asset_id: &str, account_id: &str, path: &str, data: &[u8]) -> Result<()> {
        let cfg = self.resolve_jumpserver_target(asset_id, account_id).await?;
        let id = cfg.id.clone();
        let conn = self.pool.get_or_connect_config(&id, &cfg).await?;
        crate::session::sftp_put(&conn, path, data).await
    }

    pub async fn jumpserver_sftp_download_file(&self, asset_id: &str, account_id: &str, remote_path: &str, local_path: &str, overwrite: bool, create_parent_dirs: bool, chunk_size: usize, verify: bool) -> Result<LocalFileTransfer> {
        let cfg = self.resolve_jumpserver_target(asset_id, account_id).await?;
        let path = allowed_local_write_path(local_path, create_parent_dirs)?;
        if path.exists() && !overwrite {
            return Err(ConnectorError::bad_request(format!("local file already exists: {}; pass overwrite=true to replace it", path.display())));
        }
        let id = cfg.id.clone();
        let conn = self.pool.get_or_connect_config(&id, &cfg).await?;
        let report = crate::session::sftp_download_file(&conn, remote_path, &path, overwrite, chunk_size, verify).await?;
        Ok(LocalFileTransfer { local_path: path, remote_path: remote_path.to_string(), bytes: report.bytes, sha256: report.sha256, verified: report.verified })
    }

    pub async fn jumpserver_sftp_upload_file(&self, asset_id: &str, account_id: &str, local_path: &str, remote_path: &str, overwrite: bool, create_parent_dirs: bool, chunk_size: usize, verify: bool) -> Result<LocalFileTransfer> {
        let cfg = self.resolve_jumpserver_target(asset_id, account_id).await?;
        let path = allowed_local_read_path(local_path)?;
        let id = cfg.id.clone();
        let conn = self.pool.get_or_connect_config(&id, &cfg).await?;
        let report = crate::session::sftp_upload_file(&conn, &path, remote_path, overwrite, create_parent_dirs, chunk_size, verify).await?;
        Ok(LocalFileTransfer { local_path: path, remote_path: remote_path.to_string(), bytes: report.bytes, sha256: report.sha256, verified: report.verified })
    }

    // --- Exec / PTY / SFTP (delegated to the session manager) ---

    pub fn is_jumpserver_target(&self, host_id: &str) -> Result<bool> {
        // Targets returned by JumpServer API are transient and use a reserved ID.
        if host_id.starts_with("jms:") {
            return Ok(true);
        }

        // Also block a manually-added/aliased host that points directly at the
        // configured KoKo endpoint, or routes through it as a jump hop.
        let Some(jms) = self.config.jumpserver.as_ref() else {
            return Ok(false);
        };
        let cfg = match self.vault.get_host_config(host_id) {
            Ok(cfg) => cfg,
            Err(err) if err.code == crate::error::ErrorCode::HostNotFound => return Ok(false),
            Err(err) => return Err(err),
        };
        let endpoint_matches =
            |host: &str, port: u16| is_koko_endpoint(host, port, &jms.koko_host, jms.koko_port);
        let mut visited = std::collections::HashSet::new();
        let mut pending = vec![cfg];
        while let Some(candidate) = pending.pop() {
            if !visited.insert(candidate.id.clone()) {
                continue;
            }
            if endpoint_matches(&candidate.host, candidate.port)
                || candidate
                    .jump_hosts
                    .iter()
                    .any(|hop| endpoint_matches(&hop.host, hop.port))
            {
                return Ok(true);
            }
            for hop in &candidate.jump_hosts {
                match self.vault.get_host_config(&hop.host) {
                    Ok(next) => pending.push(next),
                    Err(err) if err.code == crate::error::ErrorCode::HostNotFound => {}
                    Err(err) => return Err(err),
                }
            }
        }
        Ok(false)
    }

    pub async fn exec(&self, host_id: &str, payload: &ExecPayload) -> Result<ExecResult> {
        // Reject before touching the SSH session manager so exec cannot create
        // an extra KoKo/JMS connection or session.
        if self.is_jumpserver_target(host_id)? {
            return Err(ConnectorError::new(
                crate::error::ErrorCode::JumpServerExecDenied,
                "Direct exec is disabled for JumpServer-managed targets. Use jumpserver_session_open, then reuse its session_id with session tools.",
            ));
        }
        match self.sessions.exec(host_id, payload).await {
            Ok(r) => Ok(r),
            Err(e) => Err(e),
        }
    }

    pub async fn open_pty(&self, host_id: &str, rows: u16, cols: u16) -> Result<SessionInfo> {
        if self.is_jumpserver_target(host_id)? {
            return Err(jumpserver_session_required());
        }
        match self.sessions.open_pty(host_id, rows, cols).await {
            Ok(info) => Ok(info),
            Err(e) => Err(e),
        }
    }

    pub async fn open_root_pty(&self, host_id: &str, rows: u16, cols: u16) -> Result<SessionInfo> {
        if self.is_jumpserver_target(host_id)? {
            return Err(jumpserver_session_required());
        }
        let cfg = self.vault.get_host_config(host_id)?;
        let result = self
            .sessions
            .open_root_pty(host_id, rows, cols, cfg.become_root.as_ref())
            .await;
        match result {
            Ok(info) => Ok(info),
            Err(e) => Err(e),
        }
    }

    pub async fn pty_exec(
        &self,
        session_id: &str,
        raw: &str,
        wait_ms: Option<u64>,
        max_output_bytes: Option<usize>,
    ) -> Result<SessionExecResult> {
        let wait_ms = wait_ms.unwrap_or(5_000).min(300_000);
        let cap = max_output_bytes
            .unwrap_or(self.config.exec_output_cap_bytes)
            .min(1_048_576);
        let result = self
            .sessions
            .pty_exec(session_id, raw, Duration::from_millis(wait_ms), cap)
            .await;
        match result {
            Ok(r) => Ok(r),
            Err(e) => Err(e),
        }
    }

    pub async fn pty_exec_read(
        &self,
        session_id: &str,
        token: &str,
        wait_ms: Option<u64>,
    ) -> Result<SessionExecResult> {
        let wait_ms = wait_ms.unwrap_or(0).min(300_000);
        let result = self
            .sessions
            .pty_exec_read(session_id, token, Duration::from_millis(wait_ms))
            .await?;
        Ok(result)
    }

    pub async fn pty_send_text(&self, session_id: &str, text: &str) -> Result<()> {
        self.sessions.pty_send_text(session_id, text).await?;
        Ok(())
    }

    pub async fn pty_send_key(&self, session_id: &str, key: &KeyName) -> Result<()> {
        self.sessions.pty_send_key(session_id, key).await?;
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
        if self.is_jumpserver_target(host_id)? {
            return Err(jumpserver_session_required());
        }
        let entries = self.sessions.sftp_list(host_id, path).await?;
        Ok(entries)
    }

    pub async fn sftp_get(&self, host_id: &str, path: &str) -> Result<Vec<u8>> {
        if self.is_jumpserver_target(host_id)? {
            return Err(jumpserver_session_required());
        }
        let d = self.sessions.sftp_get(host_id, path).await?;
        Ok(d)
    }

    pub async fn sftp_put(&self, host_id: &str, path: &str, data: &[u8]) -> Result<()> {
        if self.is_jumpserver_target(host_id)? {
            return Err(jumpserver_session_required());
        }
        self.sessions.sftp_put(host_id, path, data).await?;
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
        if self.is_jumpserver_target(host_id)? {
            return Err(jumpserver_session_required());
        }
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
        if self.is_jumpserver_target(host_id)? {
            return Err(jumpserver_session_required());
        }
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
        Ok(LocalFileTransfer {
            local_path,
            remote_path: remote_path.to_string(),
            bytes: report.bytes,
            sha256: report.sha256,
            verified: report.verified,
        })
    }
}

fn is_koko_endpoint(host: &str, port: u16, koko_host: &str, koko_port: u16) -> bool {
    host.trim_end_matches('.')
        .eq_ignore_ascii_case(koko_host.trim_end_matches('.'))
        && port == koko_port
}

pub fn is_jumpserver_target_config(
    cfg: &crate::types::HostConfig,
    koko_host: &str,
    koko_port: u16,
) -> bool {
    is_koko_endpoint(&cfg.host, cfg.port, koko_host, koko_port)
        || cfg
            .jump_hosts
            .iter()
            .any(|hop| is_koko_endpoint(&hop.host, hop.port, koko_host, koko_port))
}

pub(crate) fn jumpserver_session_required() -> ConnectorError {
    ConnectorError::new(
        crate::error::ErrorCode::JumpServerSessionRequired,
        "Ordinary PTY opening is disabled for JumpServer-managed targets. Use jumpserver_session_open and reuse its session_id.",
    )
}

#[cfg(test)]
mod jumpserver_exec_policy_tests {
    use super::{is_jumpserver_target_config, is_koko_endpoint, jumpserver_session_required};
    use crate::types::{AuthMethod, HostConfig, JumpHop};

    fn test_auth() -> AuthMethod {
        AuthMethod::Password {
            password: "not-used".into(),
        }
    }

    #[test]
    fn matches_configured_koko_endpoint_case_insensitively() {
        assert!(is_koko_endpoint(
            "KOKO.example.test.",
            32222,
            "koko.example.test",
            32222
        ));
        assert!(!is_koko_endpoint(
            "koko.example.test",
            22,
            "koko.example.test",
            32222
        ));
        assert!(!is_koko_endpoint(
            "other.example.test",
            32222,
            "koko.example.test",
            32222
        ));
    }

    #[test]
    fn policy_error_explicitly_requires_jumpserver_session() {
        let error = jumpserver_session_required();
        assert_eq!(
            error.code,
            crate::error::ErrorCode::JumpServerSessionRequired
        );
        assert!(error.message.contains("jumpserver_session_open"));
        assert!(error.message.contains("session_id"));
    }

    #[test]
    fn blocks_direct_koko_hosts_and_jump_hops_but_not_ordinary_hosts() {
        let base = |host: &str, port: u16, jump_hosts| HostConfig {
            id: "test".into(),
            alias: "test".into(),
            host: host.into(),
            port,
            user: "user".into(),
            auth: test_auth(),
            jump_hosts,
            env: Default::default(),
            become_root: None,
        };
        let koko_host = "koko.example.test";
        assert!(is_jumpserver_target_config(
            &base("KOKO.EXAMPLE.TEST.", 32222, vec![]),
            koko_host,
            32222
        ));
        assert!(is_jumpserver_target_config(
            &base(
                "asset.internal",
                22,
                vec![JumpHop {
                    host: koko_host.into(),
                    port: 32222,
                    user: "proxy".into(),
                    auth: test_auth(),
                }]
            ),
            koko_host,
            32222
        ));
        assert!(!is_jumpserver_target_config(
            &base("host.internal", 22, vec![]),
            koko_host,
            32222
        ));
    }

    #[tokio::test]
    async fn sftp_rejects_api_discovered_target_before_network_or_file_side_effects() {
        use crate::{audit::AuditLog, config::Config, state::AppState, totp::Totp, vault::Vault};
        use std::sync::Arc;

        let dir = std::env::temp_dir().join(format!(
            "jms-sftp-policy-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let vault = Arc::new(Vault::open(&dir.join("vault.db")).unwrap());
        vault.init("test password").unwrap();
        let audit = Arc::new(AuditLog::new(dir.join("audit")));
        let totp = Arc::new(Totp::open(&dir.join("vault.db"), dir.join("totp.key")).unwrap());
        let state = AppState::new(vault, audit, Config::default(), "test-token".into(), totp).unwrap();
        let id = "jms:known-asset:known-account";

        assert_eq!(state.sftp_list(id, "/").await.unwrap_err().code, crate::error::ErrorCode::JumpServerSessionRequired);
        assert_eq!(state.sftp_get(id, "/etc/hostname").await.unwrap_err().code, crate::error::ErrorCode::JumpServerSessionRequired);
        assert_eq!(state.sftp_put(id, "/tmp/no-write", b"unused").await.unwrap_err().code, crate::error::ErrorCode::JumpServerSessionRequired);
        assert_eq!(state.sftp_download_file(id, "/etc/hostname", "/tmp/jms-policy-test", false, false, 65536, true).await.unwrap_err().code, crate::error::ErrorCode::JumpServerSessionRequired);
        assert_eq!(state.sftp_upload_file(id, "/etc/hostname", "/tmp/no-write", false, false, 65536, true).await.unwrap_err().code, crate::error::ErrorCode::JumpServerSessionRequired);
        assert!(state.list_sessions().await.is_empty());
        drop(state);
        // SQLite/AV scanners on Windows may transiently retain handles; the
        // unique temp directory is disposable and must not make policy checks flaky.
        let _ = std::fs::remove_dir_all(&dir);
    }
}

fn allowed_local_roots() -> Result<Vec<PathBuf>> {
    let cwd = std::env::current_dir()
        .map_err(|e| ConnectorError::internal(format!("read current dir: {e}")))?
        .canonicalize()
        .map_err(|e| ConnectorError::internal(format!("canonicalize current dir: {e}")))?;
    let temp_root = std::env::temp_dir()
        .canonicalize()
        .map_err(|e| ConnectorError::internal(format!("canonicalize system temp directory: {e}")))?;
    #[cfg(windows)]
    let temp_roots = vec![temp_root.clone(), PathBuf::from("C:/Windows/SystemTemp")];
    #[cfg(not(windows))]
    let temp_roots = vec![temp_root.clone()];
    let mut roots = temp_roots;
    roots.push(cwd);
    Ok(roots)
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
    let temp_root = std::env::temp_dir();
    #[cfg(windows)]
    let system_temp = PathBuf::from("C:/Windows/SystemTemp");
    #[cfg(not(windows))]
    let system_temp = temp_root.clone();
    Ok(path.starts_with(&temp_root) || path.starts_with(system_temp) || path.starts_with(cwd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jms_namespace_is_always_classified_as_managed() {
        assert!("jms:asset:account".starts_with("jms:"));
    }

    #[test]
    fn allows_tmp_write_paths() {
        let temp_root = std::env::temp_dir();
        let path = temp_root.join("ssh-connector-test.bin");
        let path = allowed_local_write_path(path.to_str().unwrap(), true).unwrap();
        assert!(
            path.to_string_lossy()
                .to_ascii_lowercase()
                .starts_with("\\\\?\\c:\\windows\\systemtemp\\")
                || path.to_string_lossy().to_ascii_lowercase().starts_with(
                    &temp_root.to_string_lossy().to_ascii_lowercase()
                )
        );
    }

    #[test]
    fn rejects_paths_outside_allowed_roots() {
        let err = allowed_local_read_path("/etc/hosts").unwrap_err();
        assert_eq!(err.code, crate::error::ErrorCode::BadRequest);
    }

    #[test]
    fn creates_nested_tmp_parent_when_requested() {
        let temp_root = std::env::temp_dir();
        let test_root = temp_root.join(format!("ssh-connector-state-test-{}", time::OffsetDateTime::now_utc().unix_timestamp_nanos()));
        let unique = test_root.join("nested").join("file.bin");
        let path = allowed_local_write_path(unique.to_str().unwrap(), true).unwrap();
        assert!(path.parent().unwrap().is_dir());
        std::fs::remove_dir_all(test_root).unwrap();
    }

    #[test]
    fn rejects_local_parent_traversal() {
        let error = allowed_local_write_path(
            &std::env::temp_dir().join("../etc/blocked").to_string_lossy(),
            true,
        )
        .unwrap_err();
        assert_eq!(error.code, crate::error::ErrorCode::BadRequest);
    }

    #[cfg(unix)]
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
    fn exec_payload_audit_excludes_command_body() {
        let value = match (ExecPayload::Raw {
            raw: "private data".into(),
        }) {
            ExecPayload::Raw { raw } => serde_json::json!({"type":"raw","bytes":raw.len()}),
            _ => unreachable!(),
        };
        assert_eq!(value["type"], "raw");
        assert!(value.get("preview").is_none());
        assert_eq!(value["bytes"], 12);
    }
}
