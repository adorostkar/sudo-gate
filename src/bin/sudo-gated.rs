use anyhow::{Context, Result};
use clap::Parser;
use sudo_gate::config::Config;

#[derive(Parser)]
#[command(name = "sudo-gated")]
#[command(about = "Root daemon that enforces Telegram approvals")]
struct Cli {
    /// Path to config JSON
    #[arg(long, default_value = "/etc/sudo-gate/config.json")]
    config: String,

    /// Unix socket path
    #[arg(long, default_value = "/run/sudo-gate/sock")]
    socket: String,
}

fn load_config(path: &str) -> Result<Config> {
    let cfg_text = std::fs::read_to_string(path).with_context(|| format!("read config: {path}"))?;
    let cfg: Config = serde_json::from_str(&cfg_text).context("parse config")?;
    cfg.validate()?;
    Ok(cfg)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = load_config(&cli.config)?;
    let d = sudo_gate::daemon::Daemon::new(cfg);
    d.serve(&cli.socket).await?;
    Ok(())
}
