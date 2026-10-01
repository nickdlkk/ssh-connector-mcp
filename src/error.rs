//! Stable, structured error contract shared by every module.
//!
//! The `code` field is a stable string enum exposed over MCP and the Web API.
//! Callers (AI and humans) are expected to branch on `code`, never on the
//! human-readable `message`.

use serde::{Deserialize, Serialize};

/// Stable error codes. These strings are part of the external contract and must
/// not change without a version bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Vault has not been unlocked with the master password yet.
    VaultLocked,
    /// Master password was wrong / DEK could not be decrypted.
    VaultBadPassword,
    /// Vault is already initialized (cannot re-init without reset).
    VaultAlreadyInit,
    /// Requested host id does not exist.
    HostNotFound,
    /// SSH authentication failed at the final hop.
    AuthFailed,
    /// TCP/SSH transport establishment failed before authentication completed.
    SshConnectFailed,
    /// Private key input could not be parsed.
    PrivateKeyInvalid,
    /// An encrypted private key was supplied without a passphrase.
    PrivateKeyPassphraseRequired,
    /// The supplied private-key passphrase could not decrypt the key.
    PrivateKeyPassphraseInvalid,
    /// Keyboard-interactive authentication failed or the exchange was rejected.
    KeyboardInteractiveFailed,
    /// A jump-host hop failed; `context.hop_index` says which one.
    JumpFailedAtHop,
    /// Remote host key did not match the recorded TOFU fingerprint.
    HostKeyMismatch,
    /// No live transport for the host (never connected or dropped).
    Disconnected,
    /// Requested session id does not exist or already closed.
    SessionNotFound,
    /// PTY session is currently executing a bounded command.
    SessionBusy,
    /// Operation exceeded its deadline.
    Timeout,
    /// A field that is write-only for AI was requested for read.
    CredentialWriteOnly,
    /// Invalid argument shape (e.g. neither argv nor script given).
    BadRequest,
    /// SFTP-layer failure.
    SftpError,
    /// Source and destination bytes or SHA-256 digests did not match.
    TransferIntegrityFailed,
    /// Underlying I/O or protocol error not otherwise classified.
    Internal,
    /// JumpServer API returned a non-authentication error such as 404 or 5xx.
    JumpServerApiError,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::VaultLocked => "vault_locked",
            ErrorCode::VaultBadPassword => "vault_bad_password",
            ErrorCode::VaultAlreadyInit => "vault_already_init",
            ErrorCode::HostNotFound => "host_not_found",
            ErrorCode::AuthFailed => "auth_failed",
            ErrorCode::SshConnectFailed => "ssh_connect_failed",
            ErrorCode::PrivateKeyInvalid => "private_key_invalid",
            ErrorCode::PrivateKeyPassphraseRequired => "private_key_passphrase_required",
            ErrorCode::PrivateKeyPassphraseInvalid => "private_key_passphrase_invalid",
            ErrorCode::KeyboardInteractiveFailed => "keyboard_interactive_failed",
            ErrorCode::JumpFailedAtHop => "jump_failed_at_hop",
            ErrorCode::HostKeyMismatch => "host_key_mismatch",
            ErrorCode::Disconnected => "disconnected",
            ErrorCode::SessionNotFound => "session_not_found",
            ErrorCode::SessionBusy => "session_busy",
            ErrorCode::Timeout => "timeout",
            ErrorCode::CredentialWriteOnly => "credential_write_only",
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::SftpError => "sftp_error",
            ErrorCode::TransferIntegrityFailed => "transfer_integrity_failed",
            ErrorCode::Internal => "internal",
            ErrorCode::JumpServerApiError => "jumpserver_api_error",
        }
    }
}

/// The canonical error type returned across module boundaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorError {
    pub code: ErrorCode,
    pub message: String,
    /// Free-form structured context (e.g. `{"hop_index": 1, "host": "..."}`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

impl ConnectorError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            context: None,
        }
    }

    pub fn with_context(mut self, ctx: serde_json::Value) -> Self {
        self.context = Some(ctx);
        self
    }

    pub fn locked() -> Self {
        Self::new(
            ErrorCode::VaultLocked,
            "vault is locked; unlock with master password first",
        )
    }
    pub fn host_not_found(id: &str) -> Self {
        Self::new(ErrorCode::HostNotFound, format!("no host with id {id}"))
    }
    pub fn session_not_found(id: &str) -> Self {
        Self::new(
            ErrorCode::SessionNotFound,
            format!("no session with id {id}"),
        )
    }
    pub fn disconnected(id: &str) -> Self {
        Self::new(
            ErrorCode::Disconnected,
            format!("host {id} has no live transport"),
        )
    }
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::BadRequest, msg)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, msg)
    }
}

impl std::fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for ConnectorError {}

impl From<russh::Error> for ConnectorError {
    fn from(e: russh::Error) -> Self {
        ConnectorError::new(ErrorCode::Internal, format!("ssh: {e}"))
    }
}

impl From<std::io::Error> for ConnectorError {
    fn from(e: std::io::Error) -> Self {
        ConnectorError::new(ErrorCode::Internal, format!("io: {e}"))
    }
}

impl From<rusqlite::Error> for ConnectorError {
    fn from(e: rusqlite::Error) -> Self {
        ConnectorError::new(ErrorCode::Internal, format!("db: {e}"))
    }
}

pub type Result<T> = std::result::Result<T, ConnectorError>;
