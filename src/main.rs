mod config;
mod telegram;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use config::Config;
use telegram::Telegram;

#[derive(Parser)]
#[command(name = "sudo-gate")]
#[command(about = "Telegram-approved privilege gate (draft)")]
struct Cli {
    /// Path to config JSON (do not commit secrets)
    #[arg(long, default_value = "config.example.json")]
    config: String,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate config and Telegram connectivity
    Doctor,
}

fn load_config(path: &str) -> Result<Config> {
    let cfg_text = std::fs::read_to_string(path).with_context(|| format!("read config: {path}"))?;
    let cfg: Config = serde_json::from_str(&cfg_text).context("parse config")?;

    if cfg.telegram.allowed_user_id == 0 {
        anyhow::bail!("telegram.allowed_user_id must be set");
    }
    if cfg.security.hmac_secret_hex.len() < 32 {
        anyhow::bail!("security.hmac_secret_hex looks too short");
    }
    Ok(cfg)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = load_config(&cli.config)?;

    match cli.cmd {
        Command::Doctor => {
            let tg = Telegram::new(cfg.telegram.bot_token.clone());
            let me = tg.get_me().await?;
            println!(
                "sudo-gate: Telegram bot ok: id={} username={:?}",
                me.id, me.username
            );
            println!(
                "sudo-gate: policy.mode={} deny_rules={}",
                cfg.policy.mode,
                cfg.policy.deny.len()
            );
        }
    }

    Ok(())
}
