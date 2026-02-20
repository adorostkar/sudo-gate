use crate::auth::{decode_hmac_key, eq_ct, sign_trunc_hex};
use crate::config::Config;
use crate::ipc::{Request, Response};
use crate::policy::{evaluate, PolicyDecision};
use crate::telegram::{Telegram, TgInlineKeyboardButton, TgReplyMarkup, TgUpdate};
use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{oneshot, Mutex};
use tokio::time::sleep;

pub struct Daemon {
    cfg: Config,
    tg: Telegram,
}

#[derive(Debug)]
struct Pending {
    decision_tx: oneshot::Sender<bool>,
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

fn cb_data(key: &[u8], action: &str, request_id: &str, exp: u64) -> String {
    // Telegram callback_data limit is 64 bytes.
    // v1:<a|d>:<rid>:<exp>:<sig20>
    // Keep it compact: request_id is 16 hex chars, signature is 20 hex chars.
    let act = match action {
        "approve" => "a",
        "deny" => "d",
        _ => "x",
    };
    let msg = format!("v1:{act}:{request_id}:{exp}");
    let sig = sign_trunc_hex(key, msg.as_bytes(), 20);
    format!("{msg}:{sig}")
}

fn parse_cb(data: &str) -> Option<(String, String, u64, String)> {
    let parts: Vec<&str> = data.split(':').collect();
    if parts.len() != 5 {
        return None;
    }
    if parts[0] != "v1" {
        return None;
    }
    let act = parts[1].to_string();
    let request_id = parts[2].to_string();
    let exp: u64 = parts[3].parse().ok()?;
    let sig = parts[4].to_string();
    Some((act, request_id, exp, sig))
}

impl Daemon {
    pub fn new(cfg: Config) -> Self {
        let tg = Telegram::new(cfg.telegram.bot_token.clone());
        Self { cfg, tg }
    }

    pub async fn serve(self, socket_path: &str) -> Result<()> {
        let key = decode_hmac_key(&self.cfg.security.hmac_secret_hex)?;

        let _ = std::fs::remove_file(socket_path);
        if let Some(parent) = std::path::Path::new(socket_path).parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create socket dir: {}", parent.display()))?;
        }

        let listener = UnixListener::bind(socket_path)
            .with_context(|| format!("bind unix socket: {socket_path}"))?;
        println!("sudo-gated: listening on {socket_path}");

        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));

        // Telegram poll loop
        {
            let tg = self.tg.clone();
            let cfg = self.cfg.clone();
            let pending = pending.clone();
            let key = key.clone();
            tokio::spawn(async move {
                if let Err(e) = poll_telegram(cfg, tg, pending, &key).await {
                    eprintln!("telegram poll error: {e:#}");
                }
            });
        }

        loop {
            let (stream, _addr) = listener.accept().await?;
            let cfg = self.cfg.clone();
            let tg = self.tg.clone();
            let pending = pending.clone();
            let key = key.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_client(cfg, tg, stream, pending, &key).await {
                    eprintln!("client error: {e:#}");
                }
            });
        }
    }
}

async fn poll_telegram(cfg: Config, tg: Telegram, pending: PendingMap, key: &[u8]) -> Result<()> {
    let mut offset: Option<i64> = None;

    loop {
        let updates = tg.get_updates(offset, 20).await?;
        if let Some(last) = updates.last() {
            offset = Some(last.update_id + 1);
        }

        for u in updates {
            handle_update(&cfg, &tg, pending.clone(), key, u).await?;
        }

        sleep(Duration::from_millis(cfg.telegram.poll_interval_ms)).await;
    }
}

async fn handle_update(
    cfg: &Config,
    tg: &Telegram,
    pending: PendingMap,
    key: &[u8],
    u: TgUpdate,
) -> Result<()> {
    let Some(cb) = u.callback_query else {
        return Ok(());
    };

    if cb.from.id != cfg.telegram.allowed_user_id {
        let _ = tg
            .answer_callback_query(&cb.id, Some("not authorized"))
            .await;
        return Ok(());
    }

    if let Some(allowed_chat) = cfg.telegram.allowed_chat_id {
        let chat_id = cb.message.as_ref().map(|m| m.chat.id);
        if chat_id != Some(allowed_chat) {
            let _ = tg.answer_callback_query(&cb.id, Some("wrong chat")).await;
            return Ok(());
        }
    }

    let data = cb.data.unwrap_or_default();
    let Some((act, request_id, exp, sig)) = parse_cb(&data) else {
        let _ = tg.answer_callback_query(&cb.id, Some("bad data")).await;
        return Ok(());
    };

    let msg = format!("v1:{act}:{request_id}:{exp}");
    let expect = sign_trunc_hex(key, msg.as_bytes(), 20);
    if !eq_ct(&sig, &expect) {
        let _ = tg
            .answer_callback_query(&cb.id, Some("bad signature"))
            .await;
        return Ok(());
    }

    let now = now_unix();
    if now > exp {
        let _ = tg.answer_callback_query(&cb.id, Some("expired")).await;
        return Ok(());
    }

    let decision = match act.as_str() {
        "a" => true,
        "d" => false,
        _ => {
            let _ = tg.answer_callback_query(&cb.id, Some("bad action")).await;
            return Ok(());
        }
    };

    // Best-effort: remove inline buttons so the choice can't be clicked again.
    if let Some(msg) = cb.message.as_ref() {
        let _ = tg
            .edit_message_reply_markup(msg.chat.id, msg.message_id, None)
            .await;
    }

    let mut map = pending.lock().await;
    if let Some(p) = map.remove(&request_id) {
        let _ = p.decision_tx.send(decision);
        let _ = tg.answer_callback_query(&cb.id, Some("ok")).await;
    } else {
        let _ = tg
            .answer_callback_query(&cb.id, Some("unknown request"))
            .await;
    }

    Ok(())
}

async fn handle_client(
    cfg: Config,
    tg: Telegram,
    mut stream: UnixStream,
    pending: PendingMap,
    key: &[u8],
) -> Result<()> {
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let req: Request = serde_json::from_slice(&buf).context("parse request")?;

    if req.reason.trim().is_empty() {
        let resp = Response {
            ok: false,
            message: "reason is required".to_string(),
            request_id: None,
            approved: None,
            exit_code: None,
            stdout: None,
            stderr: None,
        };
        stream.write_all(&serde_json::to_vec(&resp)?).await?;
        return Ok(());
    }
    if req.argv.is_empty() {
        let resp = Response {
            ok: false,
            message: "argv is required".to_string(),
            request_id: None,
            approved: None,
            exit_code: None,
            stdout: None,
            stderr: None,
        };
        stream.write_all(&serde_json::to_vec(&resp)?).await?;
        return Ok(());
    }

    // Safety: never execute via shell.
    let cmd_disp = render_cmd(&req.argv);

    match evaluate(&cfg.policy, &req.argv) {
        PolicyDecision::Allow => {}
        PolicyDecision::Deny(why) => {
            let resp = Response {
                ok: false,
                message: why,
                request_id: None,
                approved: Some(false),
                exit_code: None,
                stdout: None,
                stderr: None,
            };
            stream.write_all(&serde_json::to_vec(&resp)?).await?;
            return Ok(());
        }
    }

    // create request id
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    // 16 hex chars (8 bytes) to keep Telegram callback_data under 64 bytes
    let request_id = hex::encode(&nonce[..8]);

    let exp = now_unix() + cfg.security.request_ttl_seconds;

    // Store decision channel
    let (tx, rx) = oneshot::channel::<bool>();
    {
        let mut map = pending.lock().await;
        map.insert(request_id.clone(), Pending { decision_tx: tx });
    }

    // Telegram prompt
    let chat_id = cfg
        .telegram
        .allowed_chat_id
        .unwrap_or(cfg.telegram.allowed_user_id);
    let cmd_hash = sha256_hex(&cmd_disp);
    let text = format!(
        "🔐 SUDO REQUEST\n\nReason: {}\nCommand: {}\nCmdHash: {}\n\nApprove? (expires in {}s)",
        req.reason,
        cmd_disp,
        &cmd_hash[..12],
        cfg.security.request_ttl_seconds
    );

    let approve = cb_data(key, "approve", &request_id, exp);
    let deny = cb_data(key, "deny", &request_id, exp);
    if approve.len() > 64 || deny.len() > 64 {
        return Err(anyhow!("callback_data too long"));
    }

    let markup = TgReplyMarkup {
        inline_keyboard: vec![vec![
            TgInlineKeyboardButton {
                text: "✅ APPROVE".to_string(),
                callback_data: approve,
            },
            TgInlineKeyboardButton {
                text: "❌ DENY".to_string(),
                callback_data: deny,
            },
        ]],
    };

    tg.send_message(chat_id, &text, Some(markup)).await?;

    // Wait for decision
    let decision = tokio::select! {
        d = rx => d.context("decision channel")?,
        _ = sleep(Duration::from_secs(cfg.security.request_ttl_seconds)) => false,
    };

    if !decision {
        let resp = Response {
            ok: true,
            message: "denied/timeout".to_string(),
            request_id: Some(request_id),
            approved: Some(false),
            exit_code: None,
            stdout: None,
            stderr: None,
        };
        stream.write_all(&serde_json::to_vec(&resp)?).await?;
        return Ok(());
    }

    // Execute (argv-only)
    let mut cmd = tokio::process::Command::new(&req.argv[0]);
    if req.argv.len() > 1 {
        cmd.args(&req.argv[1..]);
    }

    let out = cmd.output().await.context("exec command")?;
    let exit_code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    let resp = Response {
        ok: out.status.success(),
        message: if out.status.success() {
            "executed"
        } else {
            "executed (non-zero exit)"
        }
        .to_string(),
        request_id: Some(request_id),
        approved: Some(true),
        exit_code: Some(exit_code),
        stdout: Some(stdout),
        stderr: Some(stderr),
    };

    stream.write_all(&serde_json::to_vec(&resp)?).await?;
    Ok(())
}
