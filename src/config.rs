//! Non-secret runtime configuration. Lives in `config.toml`; never holds
//! credentials.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpServerConfig {
    pub api_url: String,
    pub org_id: String,
    pub api_access_key_env: String,
    pub api_secret_key_env: String,
    pub ssh_username: String,
    /// Existing persisted host id whose JumpServer password is reused; no duplicate host is created.
    pub ssh_password_host_id: String,
    pub koko_host: String,
    #[serde(default = "default_koko_port")]
    pub koko_port: u16,
    #[serde(default)]
    pub verify_tls: bool,
}

fn default_koko_port() -> u16 { 32222 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Optional static JumpServer API provider. Credentials are referenced by env var names.
    #[serde(default)]
    pub jumpserver: Option<JumpServerConfig>,
    #[serde(default)]
    pub jumpserver_config_path: Option<PathBuf>,
    /// Web UI bind address. Forced to loopback by the daemon regardless.
    #[serde(default = "default_web_port")]
    pub web_port: u16,
    /// MCP HTTP bind port (loopback only).
    #[serde(default = "default_mcp_port")]
    pub mcp_port: u16,
    /// Default per-exec timeout in milliseconds.
    #[serde(default = "default_exec_timeout_ms")]
    pub exec_timeout_ms: u64,
    /// Per-stream output cap in bytes for exec.
    #[serde(default = "default_exec_output_cap")]
    pub exec_output_cap_bytes: usize,
    /// PTY idle TTL in seconds; 0 = never expire.
    #[serde(default = "default_pty_idle_ttl")]
    pub pty_idle_ttl_secs: u64,
    /// SSH keepalive interval in seconds.
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u64,
    /// Max concurrent exec channels per host.
    #[serde(default = "default_max_channels")]
    pub max_channels_per_host: usize,
}

fn default_web_port() -> u16 {
    7600
}
fn default_mcp_port() -> u16 {
    7601
}
fn default_exec_timeout_ms() -> u64 {
    120_000
}
fn default_exec_output_cap() -> usize {
    1024 * 1024
}
fn default_pty_idle_ttl() -> u64 {
    1800
}
fn default_keepalive() -> u64 {
    30
}
fn default_max_channels() -> usize {
    8
}

impl Default for Config {
    fn default() -> Self {
        Self {
            jumpserver: None,
            jumpserver_config_path: None,
            web_port: default_web_port(),
            mcp_port: default_mcp_port(),
            exec_timeout_ms: default_exec_timeout_ms(),
            exec_output_cap_bytes: default_exec_output_cap(),
            pty_idle_ttl_secs: default_pty_idle_ttl(),
            keepalive_secs: default_keepalive(),
            max_channels_per_host: default_max_channels(),
        }
    }
}

impl Config {
    /// Load from `data_dir/config.toml`, writing defaults if absent.
    pub fn load_or_init(data_dir: &Path) -> anyhow::Result<Config> {
        let path = data_dir.join("config.toml");
        if path.exists() {
            let text = std::fs::read_to_string(&path)?;
            Ok(toml::from_str(&text)?)
        } else {
            let cfg = Config::default();
            std::fs::write(&path, toml::to_string_pretty(&cfg)?)?;
            Ok(cfg)
        }
    }
}

/// Resolve the data directory: explicit override, else ~/.ssh-connector.
pub fn resolve_data_dir(override_dir: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    let dir = match override_dir {
        Some(d) => d,
        None => dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot determine home dir"))?
            .join(".ssh-connector"),
    };
    std::fs::create_dir_all(&dir)?;
    std::fs::create_dir_all(dir.join("audit"))?;
    std::fs::create_dir_all(dir.join("tmp"))?;
    Ok(dir)
}
