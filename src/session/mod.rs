//! Session manager: one-shot exec, persistent PTY sessions, and SFTP transfers.
//!
//! Quoting/encoding correctness (design doc §2) lives here:
//! - `ExecPayload::Argv` is escaped with POSIX single-quote rules so the AI
//!   never has to think about shell metacharacters.
//! - `ExecPayload::Script` is uploaded as a file via SFTP and run with the
//!   login shell, sidestepping quoting entirely for multi-line input.
//! - `ExecPayload::Raw` is the escape hatch; the caller owns all quoting.
//! - All byte streams are decoded as UTF-8 with lossy replacement and the
//!   `had_invalid_utf8` flag is surfaced so the AI knows when bytes were lost.

mod pty;

pub use pty::{PtyHandle, PtySession};

use crate::error::{ConnectorError, ErrorCode, Result};
use crate::ssh::{Connection, ConnectionPool};
use crate::types::{
    BecomeRootConfig, DirEntry, ExecPayload, ExecResult, ReadResult, ScreenSnapshot, SessionInfo,
    SessionKind,
};
use futures_util::{StreamExt, stream};
use russh::ChannelMsg;
use russh_sftp::client::SftpSession;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;

/// Escape one argument with POSIX single-quote rules: wrap in single quotes and
/// replace any embedded single quote with the `'\''` sequence.
pub fn posix_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Join an argv vector into a single safely-quoted command line.
pub fn quote_argv(argv: &[String]) -> Result<String> {
    if argv.is_empty() {
        return Err(ConnectorError::bad_request("argv must not be empty"));
    }
    Ok(argv
        .iter()
        .map(|a| posix_quote(a))
        .collect::<Vec<_>>()
        .join(" "))
}

/// Decode bytes as UTF-8, replacing invalid sequences. Returns (string, had_invalid).
fn decode_utf8(bytes: &[u8]) -> (String, bool) {
    match std::str::from_utf8(bytes) {
        Ok(s) => (s.to_string(), false),
        Err(_) => (String::from_utf8_lossy(bytes).into_owned(), true),
    }
}

/// Configuration knobs passed from the daemon for exec behaviour.
#[derive(Clone, Copy)]
pub struct ExecLimits {
    pub timeout: Duration,
    pub output_cap_bytes: usize,
}

/// Run a one-shot command on a fresh channel and collect its result.
pub async fn exec(
    conn: &Connection,
    payload: &ExecPayload,
    limits: ExecLimits,
) -> Result<ExecResult> {
    let command = match payload {
        ExecPayload::Argv { argv } => quote_argv(argv)?,
        ExecPayload::Raw { raw } => raw.clone(),
        ExecPayload::Script { script } => {
            return exec_script(conn, script, limits).await;
        }
    };
    exec_command_line(conn, &command, limits).await
}

async fn exec_command_line(
    conn: &Connection,
    command: &str,
    limits: ExecLimits,
) -> Result<ExecResult> {
    let start = std::time::Instant::now();
    let channel = conn.open_channel().await?;
    channel
        .exec(true, command.as_bytes())
        .await
        .map_err(|e| ConnectorError::internal(format!("exec: {e}")))?;

    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let mut exit_code: Option<i32> = None;
    let mut truncated = false;
    let mut timed_out = false;

    let mut channel = channel;
    let deadline = tokio::time::sleep(limits.timeout);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            _ = &mut deadline => {
                timed_out = true;
                let _ = channel.close().await;
                break;
            }
            msg = channel.wait() => {
                let Some(msg) = msg else { break };
                match msg {
                    ChannelMsg::Data { ref data } => {
                        if stdout.len() < limits.output_cap_bytes {
                            let room = limits.output_cap_bytes - stdout.len();
                            let take = room.min(data.len());
                            stdout.extend_from_slice(&data[..take]);
                            if take < data.len() { truncated = true; }
                        } else {
                            truncated = true;
                        }
                    }
                    ChannelMsg::ExtendedData { ref data, ext } => {
                        if ext == 1 {
                            if stderr.len() < limits.output_cap_bytes {
                                let room = limits.output_cap_bytes - stderr.len();
                                let take = room.min(data.len());
                                stderr.extend_from_slice(&data[..take]);
                                if take < data.len() { truncated = true; }
                            } else {
                                truncated = true;
                            }
                        }
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        exit_code = Some(exit_status as i32);
                    }
                    ChannelMsg::Eof | ChannelMsg::Close => {
                        // Keep draining until wait() returns None for a clean close,
                        // but Close means we can stop.
                    }
                    _ => {}
                }
            }
        }
    }

    let (stdout_s, inv1) = decode_utf8(&stdout);
    let (stderr_s, inv2) = decode_utf8(&stderr);
    Ok(ExecResult {
        stdout: stdout_s,
        stderr: stderr_s,
        exit_code,
        duration_ms: start.elapsed().as_millis() as u64,
        truncated,
        timed_out,
        had_invalid_utf8: inv1 || inv2,
    })
}

/// Upload a script via SFTP to a temp path and execute it with `sh`.
async fn exec_script(conn: &Connection, script: &str, limits: ExecLimits) -> Result<ExecResult> {
    let sftp = open_sftp(conn).await?;
    let remote_path = format!("/tmp/.ssh-connector-{}.sh", gen_token());
    sftp_write_file(&sftp, &remote_path, script.as_bytes())
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("upload script: {e}")))?;
    // Run then remove. Use sh explicitly; the path is single-quoted.
    let cmd = format!(
        "sh {0}; __rc=$?; rm -f {0}; exit $__rc",
        posix_quote(&remote_path)
    );
    let result = exec_command_line(conn, &cmd, limits).await;
    // Best-effort cleanup if exec failed before the inline rm.
    if result.is_err() {
        let _ = sftp.remove_file(remote_path.as_str()).await;
    }
    result
}

fn gen_token() -> String {
    let mut b = [0u8; 8];
    let _ = getrandom::fill(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Open an SFTP subsystem over a new channel on this connection.
pub async fn open_sftp(conn: &Connection) -> Result<SftpSession> {
    let channel = conn.open_channel().await?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("request sftp: {e}")))?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("sftp init: {e}")))?;
    // russh-sftp defaults each protocol response to 10 seconds. High-latency
    // large transfers can legitimately exceed that when several bounded reads
    // are in flight, so use the same order of magnitude as exec operations.
    sftp.set_timeout(120);
    Ok(sftp)
}

/// List a remote directory.
pub async fn sftp_list(conn: &Connection, path: &str) -> Result<Vec<DirEntry>> {
    let sftp = open_sftp(conn).await?;
    let rd = sftp
        .read_dir(path)
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("read_dir: {e}")))?;
    let mut out = Vec::new();
    for entry in rd {
        let meta = entry.metadata();
        out.push(DirEntry {
            name: entry.file_name(),
            size: meta.size.unwrap_or(0),
            mode: meta.permissions.unwrap_or(0),
            mtime: meta.mtime.unwrap_or(0) as u64,
            is_dir: meta.is_dir(),
        });
    }
    Ok(out)
}

/// Read a remote file fully (capped).
pub async fn sftp_get(conn: &Connection, path: &str) -> Result<Vec<u8>> {
    let sftp = open_sftp(conn).await?;
    sftp.read(path)
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("read: {e}")))
}

/// Write a remote file, creating or truncating it.
///
/// russh-sftp's `SftpSession::write` opens with `WRITE` only (no `CREATE`),
/// which fails with "No such file" on a new path. We open explicitly with
/// CREATE|TRUNCATE|WRITE and stream the bytes ourselves.
async fn sftp_write_file(sftp: &SftpSession, path: &str, data: &[u8]) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut file = sftp
        .create(path)
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("create: {e}")))?;
    file.write_all(data)
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("write: {e}")))?;
    file.shutdown()
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("flush: {e}")))?;
    Ok(())
}

/// Write a remote file (overwrites).
pub async fn sftp_put(conn: &Connection, path: &str, data: &[u8]) -> Result<()> {
    let sftp = open_sftp(conn).await?;
    let (parent, _) = remote_parent_and_name(path)?;
    ensure_remote_dirs(&sftp, &parent).await?;
    sftp_write_file(&sftp, path, data).await
}

#[derive(Debug, Clone)]
pub struct TransferReport {
    pub bytes: u64,
    pub sha256: String,
    pub verified: bool,
}

pub async fn sftp_download_file(
    conn: &Connection,
    remote_path: &str,
    local_path: &Path,
    overwrite: bool,
    chunk_size: usize,
    verify: bool,
) -> Result<TransferReport> {
    let sftp = open_sftp(conn).await?;
    let remote_size = sftp
        .metadata(remote_path)
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("stat remote: {e}")))?
        .size;
    let temp_path = local_temp_path(local_path)?;
    let mut local_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("create local: {e}")))?;

    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let transfer_result = async {
        let chunk_size = checked_chunk_size(chunk_size)?;
        if let Some(size) = remote_size {
            let ranges = remote_ranges(size, chunk_size);
            let mut chunks = stream::iter(ranges)
                .map(|(offset, len)| read_remote_range(&sftp, remote_path, offset, len))
                .buffered(REMOTE_READ_CONCURRENCY);
            while let Some(chunk) = chunks.next().await {
                let chunk = chunk?;
                local_file.write_all(&chunk).await.map_err(|e| {
                    ConnectorError::new(ErrorCode::SftpError, format!("write local: {e}"))
                })?;
                hasher.update(&chunk);
                bytes += chunk.len() as u64;
            }
        } else {
            let mut remote_file = sftp.open(remote_path).await.map_err(|e| {
                ConnectorError::new(ErrorCode::SftpError, format!("open remote: {e}"))
            })?;
            let mut buf = vec![0u8; chunk_size];
            loop {
                let n = remote_file.read(&mut buf).await.map_err(|e| {
                    ConnectorError::new(ErrorCode::SftpError, format!("read remote: {e}"))
                })?;
                if n == 0 {
                    break;
                }
                local_file.write_all(&buf[..n]).await.map_err(|e| {
                    ConnectorError::new(ErrorCode::SftpError, format!("write local: {e}"))
                })?;
                hasher.update(&buf[..n]);
                bytes += n as u64;
            }
        }
        local_file
            .sync_all()
            .await
            .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("sync local: {e}")))?;
        drop(local_file);

        if let Some(expected) = remote_size
            && expected != bytes
        {
            return Err(integrity_error(expected, bytes, "remote size"));
        }
        let sha256 = format!("{:x}", hasher.finalize());
        if verify {
            let (_, local_sha256) = hash_local_file(&temp_path, chunk_size).await?;
            let remote_sha256 = remote_sha256(conn, remote_path).await?;
            if local_sha256 != sha256 || remote_sha256 != sha256 {
                return Err(ConnectorError::new(
                    ErrorCode::TransferIntegrityFailed,
                    format!(
                        "download verification failed: received {sha256}, local {local_sha256}, remote {remote_sha256}"
                    ),
                ));
            }
        }
        commit_local_temp(&temp_path, local_path, overwrite).await?;
        Ok(TransferReport {
            bytes,
            sha256,
            verified: verify,
        })
    }
    .await;

    if transfer_result.is_err() {
        cleanup_local_temp(&temp_path).await;
    }
    transfer_result
}

async fn cleanup_local_temp(path: &Path) {
    let _ = tokio::fs::remove_file(path).await;
}

pub async fn sftp_upload_file(
    conn: &Connection,
    local_path: &Path,
    remote_path: &str,
    overwrite: bool,
    create_parent_dirs: bool,
    chunk_size: usize,
    verify: bool,
) -> Result<TransferReport> {
    let sftp = open_sftp(conn).await?;
    let (parent, name) = remote_parent_and_name(remote_path)?;
    if create_parent_dirs {
        ensure_remote_dirs(&sftp, &parent).await?;
    }
    let destination_exists = sftp.try_exists(remote_path).await.map_err(|e| {
        ConnectorError::new(
            ErrorCode::SftpError,
            format!("check remote destination: {e}"),
        )
    })?;
    if destination_exists && !overwrite {
        return Err(ConnectorError::bad_request(format!(
            "remote file already exists: {remote_path}; pass overwrite=true to replace it"
        )));
    }

    let mut local_file = tokio::fs::File::open(local_path)
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("open local: {e}")))?;
    let temp_path = remote_temp_path(&parent, &name, "part");
    let mut remote_file = sftp
        .create(&temp_path)
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("create remote: {e}")))?;

    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let transfer_result = async {
        let mut buf = vec![0u8; checked_chunk_size(chunk_size)?];
        loop {
            let n = local_file.read(&mut buf).await.map_err(|e| {
                ConnectorError::new(ErrorCode::SftpError, format!("read local: {e}"))
            })?;
            if n == 0 {
                break;
            }
            remote_file.write_all(&buf[..n]).await.map_err(|e| {
                ConnectorError::new(ErrorCode::SftpError, format!("write remote: {e}"))
            })?;
            hasher.update(&buf[..n]);
            bytes += n as u64;
        }
        remote_file.sync_all().await.map_err(|e| {
            ConnectorError::new(ErrorCode::SftpError, format!("sync remote: {e}"))
        })?;
        remote_file.shutdown().await.map_err(|e| {
            ConnectorError::new(ErrorCode::SftpError, format!("close remote: {e}"))
        })?;

        let sha256 = format!("{:x}", hasher.finalize());
        if verify {
            let remote_size = sftp
                .metadata(&temp_path)
                .await
                .map_err(|e| {
                    ConnectorError::new(ErrorCode::SftpError, format!("verify remote size: {e}"))
                })?
                .size
                .ok_or_else(|| {
                    ConnectorError::new(
                        ErrorCode::SftpError,
                        "remote server did not report file size for verification",
                    )
                })?;
            let remote_sha256 = remote_sha256(conn, &temp_path).await?;
            if remote_size != bytes || remote_sha256 != sha256 {
                return Err(ConnectorError::new(
                    ErrorCode::TransferIntegrityFailed,
                    format!(
                        "uploaded file verification failed: source {bytes} bytes/{sha256}, remote {remote_size} bytes/{remote_sha256}"
                    ),
                ));
            }
        }
        commit_remote_temp(&sftp, &temp_path, remote_path, destination_exists).await?;
        Ok(TransferReport {
            bytes,
            sha256,
            verified: verify,
        })
    }
    .await;

    if transfer_result.is_err() {
        let _ = sftp.remove_file(&temp_path).await;
    }
    transfer_result
}

const MIN_CHUNK_SIZE: usize = 64 * 1024;
const MAX_CHUNK_SIZE: usize = 8 * 1024 * 1024;
const REMOTE_READ_CONCURRENCY: usize = 8;

fn checked_chunk_size(chunk_size: usize) -> Result<usize> {
    if (MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        Ok(chunk_size)
    } else {
        Err(ConnectorError::bad_request(format!(
            "chunk_size_bytes must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE}"
        )))
    }
}

fn local_temp_path(destination: &Path) -> Result<PathBuf> {
    let parent = destination
        .parent()
        .ok_or_else(|| ConnectorError::bad_request("local destination has no parent directory"))?;
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            ConnectorError::bad_request("local destination must have a UTF-8 file name")
        })?;
    Ok(parent.join(format!(".{name}.ssh-connector-{}.part", gen_token())))
}

async fn commit_local_temp(temp: &Path, destination: &Path, overwrite: bool) -> Result<()> {
    if overwrite {
        tokio::fs::rename(temp, destination).await.map_err(|e| {
            ConnectorError::new(ErrorCode::SftpError, format!("commit local file: {e}"))
        })
    } else {
        tokio::fs::hard_link(temp, destination).await.map_err(|e| {
            ConnectorError::new(
                ErrorCode::SftpError,
                format!("commit local file without overwrite: {e}"),
            )
        })?;
        tokio::fs::remove_file(temp).await.map_err(|e| {
            ConnectorError::new(ErrorCode::SftpError, format!("remove local temp link: {e}"))
        })
    }
}

async fn hash_local_file(path: &Path, chunk_size: usize) -> Result<(u64, String)> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("verify local: {e}")))?;
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut buf = vec![0u8; checked_chunk_size(chunk_size)?];
    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("verify local: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        bytes += n as u64;
    }
    Ok((bytes, format!("{:x}", hasher.finalize())))
}

async fn remote_sha256(conn: &Connection, path: &str) -> Result<String> {
    let quoted = posix_quote(path);
    let command = format!(
        "if command -v sha256sum >/dev/null 2>&1; then sha256sum -- {quoted}; \
         elif command -v shasum >/dev/null 2>&1; then shasum -a 256 -- {quoted}; \
         else printf '%s\\n' 'no SHA-256 utility available' >&2; exit 127; fi"
    );
    let result = exec_command_line(
        conn,
        &command,
        ExecLimits {
            timeout: Duration::from_secs(15 * 60),
            output_cap_bytes: 4096,
        },
    )
    .await?;
    if result.timed_out {
        return Err(ConnectorError::new(
            ErrorCode::TransferIntegrityFailed,
            "remote SHA-256 verification timed out",
        ));
    }
    if result.exit_code != Some(0) {
        return Err(ConnectorError::new(
            ErrorCode::TransferIntegrityFailed,
            format!(
                "remote SHA-256 verification failed with exit {:?}: {}",
                result.exit_code,
                result.stderr.trim()
            ),
        ));
    }
    let digest = result
        .stdout
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ConnectorError::new(
            ErrorCode::TransferIntegrityFailed,
            "remote SHA-256 utility returned an invalid digest",
        ));
    }
    Ok(digest)
}

fn remote_ranges(size: u64, chunk_size: usize) -> Vec<(u64, usize)> {
    let mut ranges = Vec::new();
    let mut offset = 0u64;
    while offset < size {
        let len = (size - offset).min(chunk_size as u64) as usize;
        ranges.push((offset, len));
        offset += len as u64;
    }
    ranges
}

async fn read_remote_range(
    sftp: &SftpSession,
    path: &str,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>> {
    let mut file = sftp
        .open(path)
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("open remote: {e}")))?;
    file.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|e| ConnectorError::new(ErrorCode::SftpError, format!("seek remote: {e}")))?;
    let mut data = vec![0u8; len];
    file.read_exact(&mut data).await.map_err(|e| {
        ConnectorError::new(
            ErrorCode::SftpError,
            format!("read remote range at offset {offset}: {e}"),
        )
    })?;
    Ok(data)
}

fn remote_parent_and_name(path: &str) -> Result<(String, String)> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(ConnectorError::bad_request("remote path must name a file"));
    }
    let (parent, name) = match trimmed.rsplit_once('/') {
        Some(("", name)) => ("/", name),
        Some((parent, name)) => (parent, name),
        None => (".", trimmed),
    };
    if name.is_empty() || name == "." || name == ".." {
        return Err(ConnectorError::bad_request("remote path must name a file"));
    }
    Ok((parent.to_string(), name.to_string()))
}

fn remote_join(parent: &str, name: &str) -> String {
    match parent {
        "/" => format!("/{name}"),
        "." => name.to_string(),
        _ => format!("{parent}/{name}"),
    }
}

fn remote_temp_path(parent: &str, name: &str, suffix: &str) -> String {
    remote_join(
        parent,
        &format!(".{name}.ssh-connector-{}.{suffix}", gen_token()),
    )
}

async fn ensure_remote_dirs(sftp: &SftpSession, parent: &str) -> Result<()> {
    if parent == "." || parent == "/" || parent.is_empty() {
        return Ok(());
    }
    let absolute = parent.starts_with('/');
    let mut current = if absolute {
        "/".to_string()
    } else {
        String::new()
    };
    for component in parent.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            return Err(ConnectorError::bad_request(
                "remote parent creation does not accept '..' components",
            ));
        }
        current = if current.is_empty() || current == "/" {
            format!("{current}{component}")
        } else {
            format!("{current}/{component}")
        };
        let exists = sftp.try_exists(&current).await.map_err(|e| {
            ConnectorError::new(ErrorCode::SftpError, format!("check remote directory: {e}"))
        })?;
        if !exists {
            sftp.create_dir(&current).await.map_err(|e| {
                ConnectorError::new(
                    ErrorCode::SftpError,
                    format!("create remote directory {current}: {e}"),
                )
            })?;
        }
    }
    Ok(())
}

async fn commit_remote_temp(
    sftp: &SftpSession,
    temp_path: &str,
    destination: &str,
    destination_exists: bool,
) -> Result<()> {
    if !destination_exists {
        return sftp.rename(temp_path, destination).await.map_err(|e| {
            ConnectorError::new(ErrorCode::SftpError, format!("commit remote file: {e}"))
        });
    }

    let (parent, name) = remote_parent_and_name(destination)?;
    let backup_path = remote_temp_path(&parent, &name, "backup");
    sftp.rename(destination, &backup_path).await.map_err(|e| {
        ConnectorError::new(ErrorCode::SftpError, format!("stage remote overwrite: {e}"))
    })?;
    if let Err(error) = sftp.rename(temp_path, destination).await {
        let _ = sftp.rename(&backup_path, destination).await;
        return Err(ConnectorError::new(
            ErrorCode::SftpError,
            format!("commit remote overwrite: {error}"),
        ));
    }
    sftp.remove_file(&backup_path).await.map_err(|e| {
        ConnectorError::new(ErrorCode::SftpError, format!("remove remote backup: {e}"))
    })
}

fn integrity_error(expected: u64, actual: u64, source: &str) -> ConnectorError {
    ConnectorError::new(
        ErrorCode::TransferIntegrityFailed,
        format!("file size mismatch against {source}: expected {expected}, got {actual}"),
    )
}

/// Owns live PTY sessions and bridges exec/sftp through the connection pool.
pub struct SessionManager {
    pool: Arc<ConnectionPool>,
    limits: ExecLimits,
    pty_idle_ttl: Duration,
    ptys: Mutex<HashMap<String, PtyHandle>>,
}

impl SessionManager {
    pub fn new(pool: Arc<ConnectionPool>, limits: ExecLimits, pty_idle_ttl: Duration) -> Arc<Self> {
        let mgr = Arc::new(Self {
            pool,
            limits,
            pty_idle_ttl,
            ptys: Mutex::new(HashMap::new()),
        });
        mgr.clone().spawn_reaper();
        mgr
    }

    /// Periodically drop closed or idle-expired PTY sessions.
    fn spawn_reaper(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(15));
            loop {
                tick.tick().await;
                let ttl = self.pty_idle_ttl.as_secs();
                let mut dead = Vec::new();
                {
                    let map = self.ptys.lock().await;
                    for (id, h) in map.iter() {
                        let expired = ttl > 0 && h.idle_secs().await >= ttl;
                        if h.is_closed().await || expired {
                            dead.push(id.clone());
                        }
                    }
                }
                if !dead.is_empty() {
                    let mut map = self.ptys.lock().await;
                    for id in dead {
                        map.remove(&id);
                    }
                }
            }
        });
    }

    fn gen_session_id() -> String {
        format!("s-{}", gen_token())
    }

    /// Run a one-shot command on a host (connecting on demand).
    pub async fn exec(&self, host_id: &str, payload: &ExecPayload) -> Result<ExecResult> {
        let conn = self.pool.get_or_connect(host_id).await?;
        exec(&conn, payload, self.limits).await
    }

    /// Open a new persistent PTY session on a host.
    pub async fn open_pty(&self, host_id: &str, rows: u16, cols: u16) -> Result<SessionInfo> {
        let conn = self.pool.get_or_connect(host_id).await?;
        self.open_pty_on_connection(host_id, conn, rows, cols).await
    }

    /// Open a PTY on a runtime-only connection (for example a JumpServer target).
    pub async fn open_pty_on_config(
        &self,
        host_id: &str,
        cfg: &crate::types::HostConfig,
        rows: u16,
        cols: u16,
    ) -> Result<SessionInfo> {
        let conn = self.pool.get_or_connect_config(host_id, cfg).await?;
        self.open_pty_on_connection(host_id, conn, rows, cols).await
    }

    async fn open_pty_on_connection(
        &self,
        host_id: &str,
        conn: Arc<Connection>,
        rows: u16,
        cols: u16,
    ) -> Result<SessionInfo> {
        let id = Self::gen_session_id();
        let handle = PtySession::open(&conn, id.clone(), host_id.to_string(), rows, cols).await?;
        let info = self.info_for(&handle).await;
        self.ptys.lock().await.insert(id, handle);
        Ok(info)
    }

    /// Open a PTY session and automatically run post-login `su` escalation.
    pub async fn open_root_pty(
        &self,
        host_id: &str,
        rows: u16,
        cols: u16,
        become_root: Option<&BecomeRootConfig>,
    ) -> Result<SessionInfo> {
        let cfg = become_root.ok_or_else(|| {
            ConnectorError::bad_request(
                "become_root is not configured for this host; add become_root before using session_open_root",
            )
        })?;
        if !cfg.enabled {
            return Err(ConnectorError::bad_request(
                "become_root is disabled for this host",
            ));
        }
        let info = self.open_pty(host_id, rows, cols).await?;
        let handle = self.get_pty(&info.session_id).await?;
        if let Err(err) = run_become_root(&handle, cfg).await {
            let _ = self.close_pty(&info.session_id).await;
            return Err(err);
        }
        Ok(info)
    }

    async fn get_pty(&self, session_id: &str) -> Result<PtyHandle> {
        self.ptys
            .lock()
            .await
            .get(session_id)
            .cloned()
            .ok_or_else(|| ConnectorError::session_not_found(session_id))
    }

    pub async fn pty_send_text(&self, session_id: &str, text: &str) -> Result<()> {
        self.get_pty(session_id).await?.send_text(text).await
    }

    pub async fn pty_send_key(&self, session_id: &str, key: &crate::types::KeyName) -> Result<()> {
        let h = self.get_pty(session_id).await?;
        PtySession::send_key(&h, key).await
    }

    pub async fn pty_snapshot(&self, session_id: &str) -> Result<ScreenSnapshot> {
        Ok(self.get_pty(session_id).await?.snapshot().await)
    }

    pub async fn pty_read(&self, session_id: &str) -> Result<ReadResult> {
        Ok(self.get_pty(session_id).await?.read_new().await)
    }

    pub async fn pty_resize(&self, session_id: &str, rows: u16, cols: u16) -> Result<()> {
        self.get_pty(session_id).await?.resize(rows, cols).await
    }

    /// Subscribe to a session's raw byte stream (Web-UI takeover).
    pub async fn pty_subscribe(
        &self,
        session_id: &str,
    ) -> Result<tokio::sync::broadcast::Receiver<Vec<u8>>> {
        Ok(self.get_pty(session_id).await?.subscribe_raw())
    }

    pub async fn pty_input(&self, session_id: &str, bytes: Vec<u8>) -> Result<()> {
        self.get_pty(session_id).await?.input(bytes).await
    }

    pub async fn close_pty(&self, session_id: &str) -> Result<()> {
        let removed = self.ptys.lock().await.remove(session_id);
        match removed {
            // Dropping the handle drops its cmd_tx; once all senders are gone the
            // actor closes the channel. We send a final close intent by dropping.
            Some(_) => Ok(()),
            None => Err(ConnectorError::session_not_found(session_id)),
        }
    }

    pub async fn list_sessions(&self) -> Vec<SessionInfo> {
        let map = self.ptys.lock().await;
        let mut out = Vec::with_capacity(map.len());
        for h in map.values() {
            out.push(self.info_for(h).await);
        }
        out
    }

    async fn info_for(&self, h: &PtyHandle) -> SessionInfo {
        let (rows, cols) = h.dims().await;
        let ttl = self.pty_idle_ttl.as_secs();
        let idle_left = if ttl > 0 {
            Some(ttl.saturating_sub(h.idle_secs().await))
        } else {
            None
        };
        SessionInfo {
            session_id: h.session_id.clone(),
            host_id: h.host_id.clone(),
            kind: SessionKind::Pty,
            created_at: h.created_at.clone(),
            idle_ttl_left_secs: idle_left,
            rows,
            cols,
        }
    }

    // --- SFTP passthrough ---

    pub async fn sftp_list(&self, host_id: &str, path: &str) -> Result<Vec<DirEntry>> {
        let conn = self.pool.get_or_connect(host_id).await?;
        sftp_list(&conn, path).await
    }

    pub async fn sftp_get(&self, host_id: &str, path: &str) -> Result<Vec<u8>> {
        let conn = self.pool.get_or_connect(host_id).await?;
        sftp_get(&conn, path).await
    }

    pub async fn sftp_put(&self, host_id: &str, path: &str, data: &[u8]) -> Result<()> {
        let conn = self.pool.get_or_connect(host_id).await?;
        sftp_put(&conn, path, data).await
    }

    pub async fn sftp_download_file(
        &self,
        host_id: &str,
        remote_path: &str,
        local_path: &Path,
        overwrite: bool,
        chunk_size: usize,
        verify: bool,
    ) -> Result<TransferReport> {
        let conn = self.pool.get_or_connect(host_id).await?;
        sftp_download_file(
            &conn,
            remote_path,
            local_path,
            overwrite,
            chunk_size,
            verify,
        )
        .await
    }

    pub async fn sftp_upload_file(
        &self,
        host_id: &str,
        local_path: &Path,
        remote_path: &str,
        overwrite: bool,
        create_parent_dirs: bool,
        chunk_size: usize,
        verify: bool,
    ) -> Result<TransferReport> {
        let conn = self.pool.get_or_connect(host_id).await?;
        sftp_upload_file(
            &conn,
            local_path,
            remote_path,
            overwrite,
            create_parent_dirs,
            chunk_size,
            verify,
        )
        .await
    }
}

async fn run_become_root(handle: &PtyHandle, cfg: &BecomeRootConfig) -> Result<()> {
    let command = if cfg.command.trim().is_empty() {
        "su -"
    } else {
        cfg.command.trim()
    };
    handle.send_text(&format!("{command}\n")).await?;
    wait_for_password_prompt(handle, Duration::from_millis(cfg.prompt_timeout_ms)).await?;
    handle.send_text(&format!("{}\n", cfg.password)).await?;
    let timeout = Duration::from_millis(cfg.prompt_timeout_ms);
    wait_for_root_shell_ready(handle, timeout).await?;
    wait_until_root(handle, timeout).await?;
    Ok(())
}

async fn wait_for_password_prompt(handle: &PtyHandle, timeout: Duration) -> Result<()> {
    let start = std::time::Instant::now();
    loop {
        let out = handle.read_new().await;
        if looks_like_password_prompt(&out.data) {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err(ConnectorError::new(
                ErrorCode::AuthFailed,
                "timed out waiting for su password prompt",
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn looks_like_password_prompt(text: &str) -> bool {
    let t = text.to_lowercase();
    t.contains("password") || text.contains("密码") || text.contains("口令")
}

async fn wait_for_root_shell_ready(handle: &PtyHandle, timeout: Duration) -> Result<()> {
    let start = std::time::Instant::now();
    let mut seen = String::new();
    loop {
        let out = handle.read_new().await;
        seen.push_str(&out.data);
        if looks_like_su_failure(&seen) {
            return Err(ConnectorError::new(
                ErrorCode::AuthFailed,
                "su password was rejected",
            ));
        }
        if looks_like_root_prompt(&seen) {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err(ConnectorError::new(
                ErrorCode::AuthFailed,
                "timed out waiting for root shell prompt",
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_until_root(handle: &PtyHandle, timeout: Duration) -> Result<()> {
    const MARKER: &str = "__SSH_CONNECTOR_ROOT_CHECK__";
    handle
        .send_text(&format!("printf '{MARKER}%s\\n' \"$(id -u)\"\n"))
        .await?;
    let start = std::time::Instant::now();
    let mut seen = String::new();
    loop {
        let out = handle.read_new().await;
        seen.push_str(&out.data);
        if seen.contains(&format!("{MARKER}0")) {
            return Ok(());
        }
        if looks_like_su_failure(&seen) {
            return Err(ConnectorError::new(
                ErrorCode::AuthFailed,
                "su password was rejected",
            ));
        }
        if start.elapsed() >= timeout {
            return Err(ConnectorError::new(
                ErrorCode::AuthFailed,
                "timed out waiting for root shell verification",
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn looks_like_root_prompt(text: &str) -> bool {
    let stripped = strip_ansi(text);
    let tail = stripped
        .lines()
        .last()
        .unwrap_or(stripped.as_str())
        .trim_end();
    tail.ends_with("#") && (tail.contains("root@") || tail.starts_with('#') || tail.ends_with("~#"))
}

fn looks_like_su_failure(text: &str) -> bool {
    text.contains("Authentication failure")
        || text.contains("su: Authentication failure")
        || text.contains("认证失败")
        || text.contains("鉴定故障")
}

fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            while let Some(next) = chars.next() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_quote_plain() {
        assert_eq!(posix_quote("hello"), "'hello'");
    }

    #[test]
    fn posix_quote_with_single_quote() {
        // it's -> 'it'\''s'
        assert_eq!(posix_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn posix_quote_with_spaces_and_meta() {
        assert_eq!(posix_quote("a b; rm -rf /"), "'a b; rm -rf /'");
        assert_eq!(posix_quote("$(whoami)"), "'$(whoami)'");
        assert_eq!(posix_quote("`id`"), "'`id`'");
    }

    #[test]
    fn quote_argv_joins() {
        let argv = vec![
            "echo".to_string(),
            "hello world".to_string(),
            "a'b".to_string(),
        ];
        assert_eq!(quote_argv(&argv).unwrap(), "'echo' 'hello world' 'a'\\''b'");
    }

    #[test]
    fn quote_argv_empty_errs() {
        assert!(quote_argv(&[]).is_err());
    }

    #[test]
    fn decode_utf8_valid_and_invalid() {
        let (s, inv) = decode_utf8("héllo".as_bytes());
        assert_eq!(s, "héllo");
        assert!(!inv);
        let (s2, inv2) = decode_utf8(&[0xff, 0xfe, 0x41]);
        assert!(inv2);
        assert!(s2.contains('A'));
    }

    #[test]
    fn detects_password_prompts() {
        assert!(looks_like_password_prompt("Password: "));
        assert!(looks_like_password_prompt("root 密码："));
        assert!(looks_like_password_prompt("请输入口令:"));
        assert!(!looks_like_password_prompt("root@host:~# "));
    }

    #[test]
    fn remote_paths_keep_temporary_files_in_the_destination_directory() {
        assert_eq!(
            remote_parent_and_name("/var/lib/app/package.bin").unwrap(),
            ("/var/lib/app".into(), "package.bin".into())
        );
        let temp = remote_temp_path("/var/lib/app", "package.bin", "part");
        assert!(temp.starts_with("/var/lib/app/.package.bin.ssh-connector-"));
        assert!(temp.ends_with(".part"));
    }

    #[test]
    fn chunk_size_is_bounded() {
        assert!(checked_chunk_size(MIN_CHUNK_SIZE).is_ok());
        assert!(checked_chunk_size(MAX_CHUNK_SIZE).is_ok());
        assert_eq!(
            checked_chunk_size(MIN_CHUNK_SIZE - 1).unwrap_err().code,
            ErrorCode::BadRequest
        );
    }

    #[test]
    fn remote_ranges_cover_file_without_overlap() {
        assert_eq!(remote_ranges(10, 4), vec![(0, 4), (4, 4), (8, 2)]);
        assert!(remote_ranges(0, 4).is_empty());
    }

    #[tokio::test]
    async fn no_overwrite_commit_preserves_existing_destination_and_temp_cleanup_works() {
        let dir = std::env::temp_dir().join(format!("ssh-connector-commit-test-{}", gen_token()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let destination = dir.join("file.bin");
        let temp = dir.join(".file.bin.part");
        tokio::fs::write(&destination, b"old").await.unwrap();
        tokio::fs::write(&temp, b"new").await.unwrap();

        assert!(commit_local_temp(&temp, &destination, false).await.is_err());
        assert_eq!(tokio::fs::read(&destination).await.unwrap(), b"old");
        cleanup_local_temp(&temp).await;
        assert!(!temp.exists());
    }
}
