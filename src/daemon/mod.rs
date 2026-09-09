//! Daemon assembly: wire vault + state + transports, then serve.
//!
//! Two run modes share one `AppState`:
//! - default: bind a loopback HTTP server hosting the Web UI/API at `/` plus the
//!   MCP Streamable-HTTP endpoint at `/mcp`.
//! - `stdio_mcp`: speak MCP over stdio for editor integrations (no HTTP).
//!
//! Both binds are forced to 127.0.0.1 — this connector is never exposed off-box.

use crate::audit::AuditLog;
use crate::config::{self, Config};
use crate::state::AppState;
use crate::vault::Vault;
use std::io::BufRead;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

pub struct DaemonOptions {
    pub data_dir: Option<PathBuf>,
    pub master_password_env: Option<String>,
    pub master_password_stdin: bool,
    pub stdio_mcp: bool,
}

pub async fn run(opts: DaemonOptions) -> anyhow::Result<()> {
    let data_dir = config::resolve_data_dir(opts.data_dir.clone())?;
    let cfg = Config::load_or_init(&data_dir)?;
    let vault = Arc::new(Vault::open(&data_dir.join("vault.db"))?);
    let audit = Arc::new(AuditLog::new(data_dir.join("audit")));

    // Optional headless unlock. If the vault is uninitialized, unlock is skipped
    // and the Web UI drives first-run init.
    maybe_unlock(&vault, &opts)?;

    let local_token = generate_token();
    let state = AppState::new(vault, audit, cfg.clone(), local_token)?;

    if opts.stdio_mcp {
        // stdio MCP requires an already-unlocked vault (no interactive prompt).
        if !state.vault.is_unlocked() {
            anyhow::bail!(
                "stdio MCP mode requires the vault to be unlocked; pass --master-password-env or --master-password-stdin"
            );
        }
        return crate::mcp::serve_stdio(state).await;
    }

    serve_http(state, &cfg, &data_dir).await
}

fn maybe_unlock(vault: &Vault, opts: &DaemonOptions) -> anyhow::Result<()> {
    if !vault.is_initialized()? {
        return Ok(());
    }
    let pw = if let Some(var) = &opts.master_password_env {
        std::env::var(var).ok()
    } else if opts.master_password_stdin {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    } else {
        None
    };
    if let Some(pw) = pw {
        vault.unlock(&pw)?;
        tracing::info!("vault unlocked at startup");
    }
    Ok(())
}

async fn serve_http(state: Arc<AppState>, cfg: &Config, data_dir: &PathBuf) -> anyhow::Result<()> {
    let static_dir = resolve_static_dir(data_dir);
    let mcp_service = crate::mcp::build_http_service(state.clone());

    let app = crate::web::router(state, static_dir)
        .nest_service("/mcp", mcp_service)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, cfg.web_port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("listening on http://{addr}  (web UI + /mcp)");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Static assets ship next to the binary in prod, but during development they
/// live in `./static`. Prefer an explicit `data_dir/static`, then `./static`.
fn resolve_static_dir(data_dir: &PathBuf) -> PathBuf {
    let candidate = data_dir.join("static");
    if candidate.is_dir() {
        return candidate;
    }
    PathBuf::from("static")
}

fn generate_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("system RNG");
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in buf {
        let _ = write!(s, "{b:02x}");
    }
    s
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
