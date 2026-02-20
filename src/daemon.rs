use crate::config::Config;
use crate::ipc::{Request, Response};
use crate::telegram::{Telegram, TgInlineKeyboardButton, TgReplyMarkup};
use anyhow::{Context, Result};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

pub struct Daemon {
    cfg: Config,
    tg: Telegram,
}

#[derive(Debug, Clone)]
struct Pending {
    nonce: [u8; 32],
    cmd_hash_hex: String,
    expires_at: u64,
}

type PendingMap = Arc<Mutex<HashMap<String, Pending>>>;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

fn render_cmd(argv: &[String]) -> String {
    // Minimal shell-escaped rendering for display only.
    argv.iter()
        .map(|a| {
            if a.chars()
                .all(|c| c.is_ascii_alphanumeric() || "-._/:".contains(c))
            {
                a.clone()
            } else {
                format!("'{}'", a.replace('\\', "\\\\").replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

impl Daemon {
    pub fn new(cfg: Config) -> Self {
        let tg = Telegram::new(cfg.telegram.bot_token.clone());
        Self { cfg, tg }
    }

    pub async fn serve(self, socket_path: &str) -> Result<()> {
        // Ensure old socket removed
        let _ = std::fs::remove_file(socket_path);
        if let Some(parent) = std::path::Path::new(socket_path).parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create socket dir: {}", parent.display()))?;
        }

        let listener = UnixListener::bind(socket_path)
            .with_context(|| format!("bind unix socket: {socket_path}"))?;
        println!("sudo-gated: listening on {socket_path}");

        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));

        loop {
            let (stream, _addr) = listener.accept().await?;
            let cfg = self.cfg.clone();
            let tg = self.tg.clone();
            let pending = pending.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_client(cfg, tg, stream, pending).await {
                    eprintln!("client error: {e:#}");
                }
            });
        }
    }
}

async fn handle_client(
    cfg: Config,
    tg: Telegram,
    mut stream: UnixStream,
    pending: PendingMap,
) -> Result<()> {
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let req: Request = serde_json::from_slice(&buf).context("parse request")?;

    if req.reason.trim().is_empty() {
        let resp = Response {
            ok: false,
            message: "reason is required".to_string(),
            request_id: None,
        };
        stream.write_all(&serde_json::to_vec(&resp)?).await?;
        return Ok(());
    }
    if req.argv.is_empty() {
        let resp = Response {
            ok: false,
            message: "argv is required".to_string(),
            request_id: None,
        };
        stream.write_all(&serde_json::to_vec(&resp)?).await?;
        return Ok(());
    }

    // create pending request (in-memory)
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cmd_disp = render_cmd(&req.argv);
    let cmd_hash_hex = sha256_hex(&cmd_disp);

    let request_id = hex::encode(&nonce[..12]);
    let expires_at = now_unix() + cfg.security.request_ttl_seconds;

    {
        let mut map = pending.lock().await;
        map.insert(
            request_id.clone(),
            Pending {
                nonce,
                cmd_hash_hex: cmd_hash_hex.clone(),
                expires_at,
            },
        );
    }

    // Send telegram prompt (buttons not wired yet)
    let chat_id = cfg
        .telegram
        .allowed_chat_id
        .unwrap_or(cfg.telegram.allowed_user_id);
    let text = format!(
        "🔐 SUDO REQUEST (draft)\n\nReason: {}\nCommand: {}\nRequestId: {}\nExpires in: {}s",
        req.reason, cmd_disp, request_id, cfg.security.request_ttl_seconds
    );
    let markup = TgReplyMarkup {
        inline_keyboard: vec![vec![
            TgInlineKeyboardButton {
                text: "✅ APPROVE".to_string(),
                callback_data: format!("approve:{}:{}", request_id, cmd_hash_hex),
            },
            TgInlineKeyboardButton {
                text: "❌ DENY".to_string(),
                callback_data: format!("deny:{}:{}", request_id, cmd_hash_hex),
            },
        ]],
    };
    let _ = tg.send_message(chat_id, &text, Some(markup)).await;

    let resp = Response {
        ok: true,
        message: "request queued (awaiting approval)".to_string(),
        request_id: Some(request_id),
    };
    stream.write_all(&serde_json::to_vec(&resp)?).await?;
    Ok(())
}
