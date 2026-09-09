//! SSH connection layer: client handler, authentication (password / private key
//! / keyboard-interactive), multi-hop jump chains, host-key TOFU, and a
//! connection pool of one live transport per host.

#![allow(clippy::type_complexity)]

use crate::error::{ConnectorError, ErrorCode, Result};
use crate::types::{AuthMethod, HostConfig, HostStatus};
use crate::vault::Vault;
use russh::client::{self, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Per-connection client handler. Enforces host-key TOFU against the vault.
struct ClientHandler {
    vault: Arc<Vault>,
    /// host:port label this transport is connecting to (the final hop).
    host: String,
    port: u16,
}

impl client::Handler for ClientHandler {
    type Error = ConnectorError;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        let fp = server_public_key.fingerprint(HashAlg::Sha256).to_string();
        match self.vault.get_host_key(&self.host, self.port)? {
            Some(known) => {
                if known == fp {
                    Ok(true)
                } else {
                    Err(ConnectorError::new(
                        ErrorCode::HostKeyMismatch,
                        format!(
                            "host key for {}:{} changed (known {known}, got {fp}); refusing to connect",
                            self.host, self.port
                        ),
                    ))
                }
            }
            None => {
                // TOFU: record on first sight and accept.
                self.vault.record_host_key(&self.host, self.port, &fp)?;
                Ok(true)
            }
        }
    }
}

fn client_config(keepalive_secs: u64) -> Arc<client::Config> {
    let mut cfg = client::Config::default();
    // SFTP and interactive sessions exchange many small request/response
    // packets. Avoid delayed TCP writes on high-latency links.
    cfg.nodelay = true;
    if keepalive_secs > 0 {
        cfg.keepalive_interval = Some(std::time::Duration::from_secs(keepalive_secs));
    }
    Arc::new(cfg)
}

/// Parse a private key from PEM, decrypting with the passphrase if needed.
fn load_private_key(key_pem: &str, passphrase: Option<&str>) -> Result<PrivateKey> {
    let key = PrivateKey::from_openssh(key_pem).map_err(|e| {
        ConnectorError::new(
            ErrorCode::PrivateKeyInvalid,
            format!("private key could not be parsed: {e}"),
        )
    })?;
    if key.is_encrypted() {
        let pass = passphrase.ok_or_else(|| {
            ConnectorError::new(
                ErrorCode::PrivateKeyPassphraseRequired,
                "private key is encrypted but no passphrase given",
            )
        })?;
        key.decrypt(pass).map_err(|e| {
            ConnectorError::new(
                ErrorCode::PrivateKeyPassphraseInvalid,
                format!("private key passphrase was rejected: {e}"),
            )
        })
    } else {
        Ok(key)
    }
}

/// Run the configured authentication method against an open handle.
async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    auth: &AuthMethod,
) -> Result<()> {
    let ok = match auth {
        AuthMethod::Password { password } => handle
            .authenticate_password(user, password)
            .await
            .map_err(|e| auth_exchange_error("password", user, e))?
            .success(),
        AuthMethod::PrivateKey {
            key_pem,
            passphrase,
        } => {
            let key = load_private_key(key_pem, passphrase.as_deref())?;
            // Prefer SHA-256 for RSA; ignored for other key types.
            let kwh = PrivateKeyWithHashAlg::new(Arc::new(key), Some(HashAlg::Sha256));
            handle
                .authenticate_publickey(user, kwh)
                .await
                .map_err(|e| auth_exchange_error("private_key", user, e))?
                .success()
        }
        AuthMethod::KeyboardInteractive { answers } => {
            authenticate_keyboard_interactive(handle, user, answers).await?
        }
    };
    if ok {
        Ok(())
    } else {
        let code = match auth {
            AuthMethod::KeyboardInteractive { .. } => ErrorCode::KeyboardInteractiveFailed,
            _ => ErrorCode::AuthFailed,
        };
        Err(ConnectorError::new(
            code,
            format!("authentication failed for user {user}"),
        ))
    }
}

fn auth_exchange_error(
    auth_kind: &str,
    user: &str,
    error: impl std::fmt::Display,
) -> ConnectorError {
    let code = if auth_kind == "keyboard_interactive" {
        ErrorCode::KeyboardInteractiveFailed
    } else {
        ErrorCode::AuthFailed
    };
    ConnectorError::new(
        code,
        format!("{auth_kind} authentication exchange failed for user {user}: {error}"),
    )
}

async fn authenticate_keyboard_interactive(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    answers: &[String],
) -> Result<bool> {
    let mut resp = handle
        .authenticate_keyboard_interactive_start(user, None)
        .await
        .map_err(|e| auth_exchange_error("keyboard_interactive", user, e))?;
    let mut idx = 0usize;
    loop {
        match resp {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                // Answer each prompt from the configured answer list in order.
                let mut replies = Vec::with_capacity(prompts.len());
                for _ in &prompts {
                    let a = answers.get(idx).cloned().unwrap_or_default();
                    idx += 1;
                    replies.push(a);
                }
                resp = handle
                    .authenticate_keyboard_interactive_respond(replies)
                    .await
                    .map_err(|e| auth_exchange_error("keyboard_interactive", user, e))?;
            }
        }
    }
}

/// A live transport to a host (final hop authenticated), plus its config snapshot.
pub struct Connection {
    pub handle: Handle<ClientHandler>,
    pub host_id: String,
}

impl Connection {
    /// Open a new session channel for exec/pty/sftp.
    pub async fn open_channel(&self) -> Result<russh::Channel<client::Msg>> {
        self.handle
            .channel_open_session()
            .await
            .map_err(|e| ConnectorError::new(ErrorCode::Disconnected, format!("open channel: {e}")))
    }
}

/// Establish a transport to the final target, tunnelling through any jump hops.
///
/// For each hop we open a direct-tcpip channel on the previous handle to the
/// next hop's address, then run a fresh SSH client over that channel's stream
/// (`connect_stream`). The last hop is the real target.
async fn establish(
    vault: &Arc<Vault>,
    cfg: &HostConfig,
    keepalive_secs: u64,
) -> Result<Handle<ClientHandler>> {
    // Build the ordered list of (host, port, user, auth) ending at the target.
    let mut chain: Vec<(&str, u16, &str, &AuthMethod)> = Vec::new();
    for hop in &cfg.jump_hosts {
        chain.push((&hop.host, hop.port, &hop.user, &hop.auth));
    }
    chain.push((&cfg.host, cfg.port, &cfg.user, &cfg.auth));

    // First hop: direct TCP connect.
    let (first_host, first_port, first_user, first_auth) = chain[0];
    let handler = ClientHandler {
        vault: vault.clone(),
        host: first_host.to_string(),
        port: first_port,
    };
    let jump_count = cfg.jump_hosts.len();
    let mut handle = client::connect(
        client_config(keepalive_secs),
        (first_host, first_port),
        handler,
    )
    .await
    .map_err(|e| {
        map_chain_error(
            0,
            jump_count,
            first_host,
            first_port,
            classify_connect_error(e.into()),
        )
    })?;
    authenticate(&mut handle, first_user, first_auth)
        .await
        .map_err(|e| map_chain_error(0, jump_count, first_host, first_port, e))?;

    // Subsequent hops: tunnel through the previous handle.
    for (i, &(host, port, user, auth)) in chain.iter().enumerate().skip(1) {
        let channel = handle
            .channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0)
            .await
            .map_err(|e| {
                map_chain_error(i, jump_count, host, port, classify_connect_error(e.into()))
            })?;
        let handler = ClientHandler {
            vault: vault.clone(),
            host: host.to_string(),
            port,
        };
        let mut next = client::connect_stream(
            client_config(keepalive_secs),
            channel.into_stream(),
            handler,
        )
        .await
        .map_err(|e| map_chain_error(i, jump_count, host, port, classify_connect_error(e)))?;
        authenticate(&mut next, user, auth)
            .await
            .map_err(|e| map_chain_error(i, jump_count, host, port, e))?;
        handle = next;
    }

    Ok(handle)
}

fn classify_connect_error(error: ConnectorError) -> ConnectorError {
    match error.code {
        ErrorCode::HostKeyMismatch => error,
        ErrorCode::Internal => ConnectorError::new(ErrorCode::SshConnectFailed, error.message),
        _ => error,
    }
}

fn map_chain_error(
    hop_index: usize,
    jump_count: usize,
    host: &str,
    port: u16,
    error: ConnectorError,
) -> ConnectorError {
    let cause_code = error.code.as_str();
    let is_jump = hop_index < jump_count;
    let ctx = serde_json::json!({
        "hop_index": hop_index,
        "host": host,
        "port": port,
        "stage": if is_jump { "jump_host" } else { "final_target" },
        "cause_code": cause_code,
    });
    if is_jump {
        ConnectorError::new(
            ErrorCode::JumpFailedAtHop,
            format!("jump hop {hop_index} ({host}:{port}) failed: {error}"),
        )
        .with_context(ctx)
    } else {
        error.with_context(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_private_key_has_specific_code() {
        let error = load_private_key("not-a-private-key", None).unwrap_err();
        assert_eq!(error.code, ErrorCode::PrivateKeyInvalid);
    }

    #[test]
    fn first_jump_failure_is_not_misclassified_as_final_target() {
        let error = map_chain_error(
            0,
            1,
            "jump.example",
            22,
            ConnectorError::new(ErrorCode::AuthFailed, "rejected"),
        );
        assert_eq!(error.code, ErrorCode::JumpFailedAtHop);
        assert_eq!(error.context.as_ref().unwrap()["cause_code"], "auth_failed");
        assert_eq!(error.context.as_ref().unwrap()["stage"], "jump_host");
    }

    #[test]
    fn final_target_preserves_root_cause_after_jump() {
        let error = map_chain_error(
            1,
            1,
            "target.example",
            22,
            ConnectorError::new(ErrorCode::HostKeyMismatch, "changed"),
        );
        assert_eq!(error.code, ErrorCode::HostKeyMismatch);
        assert_eq!(error.context.as_ref().unwrap()["stage"], "final_target");
    }
}

/// Pool of live connections, one per host id.
pub struct ConnectionPool {
    vault: Arc<Vault>,
    keepalive_secs: u64,
    conns: Mutex<HashMap<String, Arc<Connection>>>,
}

impl ConnectionPool {
    pub fn new(vault: Arc<Vault>, keepalive_secs: u64) -> Self {
        Self {
            vault,
            keepalive_secs,
            conns: Mutex::new(HashMap::new()),
        }
    }

    /// Current status of a host's transport.
    pub async fn status(&self, host_id: &str) -> HostStatus {
        let guard = self.conns.lock().await;
        match guard.get(host_id) {
            Some(c) if !c.handle.is_closed() => HostStatus::Connected,
            _ => HostStatus::Disconnected,
        }
    }

    /// Connect (or reconnect) a persisted host. Replaces any existing dead handle.
    pub async fn connect(&self, host_id: &str) -> Result<()> {
        let cfg = self.vault.get_host_config(host_id)?;
        self.connect_config(host_id, &cfg).await
    }

    /// Connect a runtime-only target without persisting it in the vault.
    pub async fn connect_config(&self, host_id: &str, cfg: &HostConfig) -> Result<()> {
        let handle = establish(&self.vault, cfg, self.keepalive_secs).await?;
        let conn = Arc::new(Connection {
            handle,
            host_id: host_id.to_string(),
        });
        self.conns.lock().await.insert(host_id.to_string(), conn);
        Ok(())
    }

    /// Get or connect a runtime-only target.
    pub async fn get_or_connect_config(
        &self,
        host_id: &str,
        cfg: &HostConfig,
    ) -> Result<Arc<Connection>> {
        if let Ok(c) = self.get(host_id).await {
            return Ok(c);
        }
        self.connect_config(host_id, cfg).await?;
        self.get(host_id).await
    }

    /// Get a live connection, erroring if not connected/dropped. Does NOT
    /// auto-reconnect (design doc §4.3): callers must reconnect explicitly so
    /// stale session state is never silently assumed.
    pub async fn get(&self, host_id: &str) -> Result<Arc<Connection>> {
        let guard = self.conns.lock().await;
        match guard.get(host_id) {
            Some(c) if !c.handle.is_closed() => Ok(c.clone()),
            _ => Err(ConnectorError::disconnected(host_id)),
        }
    }

    /// Ensure a live connection exists, connecting on demand if absent/dead.
    pub async fn get_or_connect(&self, host_id: &str) -> Result<Arc<Connection>> {
        if let Ok(c) = self.get(host_id).await {
            return Ok(c);
        }
        self.connect(host_id).await?;
        self.get(host_id).await
    }

    /// Drop a host's transport (e.g. on host removal).
    pub async fn disconnect(&self, host_id: &str) {
        if let Some(c) = self.conns.lock().await.remove(host_id) {
            let _ = c
                .handle
                .disconnect(russh::Disconnect::ByApplication, "", "")
                .await;
        }
    }
}
