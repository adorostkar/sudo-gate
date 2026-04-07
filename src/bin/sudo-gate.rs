use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sudo_gate::config::Config;

#[derive(Parser)]
#[command(name = "sudo-gate")]
#[command(about = "Submit privileged command requests for approval")]
struct Cli {
    /// Path to config JSON (used only for doctor + optional defaults)
    #[arg(long, default_value = "/etc/sudo-gate/config.json")]
    config: String,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate config and Telegram connectivity
    Doctor,

    /// Submit a request to the daemon
    Request {
        #[arg(long)]
        reason: String,
        /// Command and args after `--`
        #[arg(last = true, required = true)]
        argv: Vec<String>,
        #[arg(long, default_value = "/run/sudo-gate/sock")]
        socket: String,
    },
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

    match cli.cmd {
        Command::Doctor => {
            let cfg = load_config(&cli.config)?;
            let tg = sudo_gate::telegram::Telegram::new(cfg.telegram.bot_token.clone());
            let me = tg.get_me().await?;
            println!(
                "sudo-gate: Telegram bot ok: id={} username={:?}",
                me.id, me.username
            );
            println!(
                "sudo-gate: policy.mode={} allow_rules={} deny_rules={} requester_allow_uids={}",
                cfg.policy.mode,
                cfg.policy.allow.len(),
                cfg.policy.deny.len(),
                cfg.security.requester_allow_uids.len(),
            );
        }
        Command::Request {
            reason,
            argv,
            socket,
        } => {
            let resp = sudo_gate::client::send_request(&socket, reason, argv).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }

    Ok(())
}
