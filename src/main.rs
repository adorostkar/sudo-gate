mod auth;
mod client;
mod config;
mod daemon;
mod ipc;
mod telegram;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use config::Config;
use telegram::{Telegram, TgInlineKeyboardButton, TgReplyMarkup};

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

    /// Send a test message with inline buttons (dev helper)
    TelegramTest,

    /// Start the root daemon (draft)
    Daemon {
        #[arg(long, default_value = "/run/sudo-gate/sock")]
        socket: String,
    },

    /// Submit a request to the daemon (draft)
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
        Command::TelegramTest => {
            let tg = Telegram::new(cfg.telegram.bot_token.clone());
            let chat_id = cfg
                .telegram
                .allowed_chat_id
                .unwrap_or(cfg.telegram.allowed_user_id);
            let markup = TgReplyMarkup {
                inline_keyboard: vec![vec![
                    TgInlineKeyboardButton {
                        text: "✅ APPROVE (test)".to_string(),
                        callback_data: "test:approve".to_string(),
                    },
                    TgInlineKeyboardButton {
                        text: "❌ DENY (test)".to_string(),
                        callback_data: "test:deny".to_string(),
                    },
                ]],
            };
            let msg = tg
                .send_message(
                    chat_id,
                    "sudo-gate test: if you see this, sendMessage works.",
                    Some(markup),
                )
                .await?;
            println!(
                "sent test message_id={} chat_id={}",
                msg.message_id, msg.chat.id
            );
        }
        Command::Daemon { socket } => {
            let d = daemon::Daemon::new(cfg);
            d.serve(&socket).await?;
        }
        Command::Request {
            reason,
            argv,
            socket,
        } => {
            let resp = client::send_request(&socket, reason, argv).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }

    Ok(())
}
