mod error;
mod types;

mod audit;
mod config;
mod daemon;
mod jumpserver;
mod mcp;
mod session;
mod ssh;
mod state;
mod term;
mod vault;
mod web;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "ssh-connector",
    version,
    about = "Cross-platform SSH maintenance connector: human-managed hosts, AI-driven sessions, credentials never exposed to AI"
)]
struct Cli {
    /// Run as the stdio MCP shim, forwarding to a running daemon over HTTP.
    #[arg(long)]
    mcp_stdio: bool,

    /// Data directory (vault, token, audit). Defaults to ~/.ssh-connector.
    #[arg(long)]
    data_dir: Option<std::path::PathBuf>,

    /// Master password source for headless unlock: read from this env var name.
    #[arg(long)]
    master_password_env: Option<String>,

    /// Read master password from stdin (one line) at startup (headless).
    #[arg(long)]
    master_password_stdin: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    daemon::run(daemon::DaemonOptions {
        data_dir: cli.data_dir,
        master_password_env: cli.master_password_env,
        master_password_stdin: cli.master_password_stdin,
        stdio_mcp: cli.mcp_stdio,
    })
    .await
}
