use crate::auth::{decode_hmac_key, eq_ct, sign_trunc_hex};
use crate::config::Config;
use crate::ipc::{Request, Response};
use crate::policy::{evaluate, PolicyDecision, RequestPolicyInput};
use crate::request::{
    canonicalize_command, validate_request_shape, validate_requester, NormalizedCommand,
    RequesterIdentity,
};
use crate::telegram::{Telegram, TgInlineKeyboardButton, TgReplyMarkup, TgUpdate};
use anyhow::{anyhow, Context, Result};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::{chown, Gid, Group, Uid, User};
use rand::RngCore;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{oneshot, Mutex};
use tokio::time::sleep;

fn sudo_gate_gid(group_name: &str) -> Result<Gid> {
    let group = Group::from_name(group_name)
        .context("lookup group")?
        .ok_or_else(|| anyhow!("group not found: {group_name}"))?;
    Ok(Gid::from_raw(group.gid.as_raw()))
}

fn set_dir_perms(dir_path: &std::path::Path, group_name: &str) -> Result<()> {
    let gid = sudo_gate_gid(group_name)?;
    chown(dir_path, Some(Uid::from_raw(0)), Some(gid)).context("chown dir")?;

    let mut perms = fs::metadata(dir_path).context("stat dir")?.permissions();
    perms.set_mode(0o750);
    fs::set_permissions(dir_path, perms).context("chmod dir")?;
    Ok(())
}

fn set_socket_perms(socket_path: &str, group_name: &str) -> Result<()> {
    let gid = sudo_gate_gid(group_name)?;
    chown(socket_path, Some(Uid::from_raw(0)), Some(gid)).context("chown socket")?;

    let mut perms = fs::metadata(socket_path)
        .context("stat socket")?
        .permissions();
    perms.set_mode(0o660);
    fs::set_permissions(socket_path, perms).context("chmod socket")?;
    Ok(())
}

fn prepare_socket_path(socket_path: &str) -> Result<()> {
    let path = Path::new(socket_path);
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("socket path must have a parent directory"))?;
    let expected_parent = Path::new("/run/sudo-gate");
    if parent != expected_parent {
        return Err(anyhow!(
            "socket path parent must be {}",
            expected_parent.display()
        ));
    }

    if path.exists() {
        let metadata = fs::symlink_metadata(path).context("stat existing socket path")?;
        if !metadata.file_type().is_socket() {
            return Err(anyhow!(
                "refusing to replace non-socket path: {}",
                path.display()
            ));
        }
        fs::remove_file(path)
            .with_context(|| format!("remove stale socket: {}", path.display()))?;
    }

    fs::create_dir_all(parent)
        .with_context(|| format!("create socket dir: {}", parent.display()))?;
    set_dir_perms(parent, "sudo-gate").context("set socket dir perms")?;
    Ok(())
}

pub struct Daemon {
    cfg: Config,
    tg: Telegram,
}

#[derive(Debug, Clone)]
struct PendingMetadata {
    requester: RequesterIdentity,
    reason: String,
    command: String,
    requested_at: u64,
}

#[derive(Debug)]
struct Pending {
    decision_tx: oneshot::Sender<bool>,
    metadata: PendingMetadata,
}

type PendingMap = Arc<Mutex<HashMap<String, Pending>>>;
type RateMap = Arc<Mutex<HashMap<u32, VecDeque<u64>>>>;

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

fn audit(event: &str, payload: serde_json::Value) {
    println!(
        "{}",
        json!({
            "event": event,
            "ts": now_unix(),
            "payload": payload,
        })
    );
}

fn cb_data(key: &[u8], action: &str, request_id: &str, exp: u64) -> String {
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
    if parts.len() != 5 || parts[0] != "v1" {
        return None;
    }

    Some((
        parts[1].to_string(),
        parts[2].to_string(),
        parts[3].parse().ok()?,
        parts[4].to_string(),
    ))
}

fn requester_from_stream(stream: &UnixStream) -> Result<RequesterIdentity> {
    let fd = unsafe { BorrowedFd::borrow_raw(stream.as_raw_fd()) };
    let creds = getsockopt(&fd, PeerCredentials).context("read peer credentials")?;
    let uid = creds.uid();
    let gid = creds.gid();
    let pid = creds.pid();
    let username = User::from_uid(Uid::from_raw(uid))
        .context("lookup peer uid")?
        .and_then(|u| u.name.into())
        .unwrap_or_else(|| uid.to_string());

    Ok(RequesterIdentity {
        uid,
        gid,
        pid,
        username,
    })
}

fn chat_id(cfg: &Config) -> i64 {
    cfg.telegram
        .allowed_chat_id
        .unwrap_or(cfg.telegram.allowed_user_id)
}

async fn send_response(stream: &mut UnixStream, resp: Response) -> Result<()> {
    stream.write_all(&serde_json::to_vec(&resp)?).await?;
    Ok(())
}

async fn reject(stream: &mut UnixStream, message: impl Into<String>) -> Result<()> {
    send_response(
        stream,
        Response {
            ok: false,
            message: message.into(),
            request_id: None,
            approved: None,
            exit_code: None,
            stdout: None,
            stderr: None,
        },
    )
    .await
}

async fn read_limited(stream: &mut UnixStream, max_bytes: usize) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if buf.len() + n > max_bytes {
            return Err(anyhow!(
                "request exceeds maximum size ({} bytes)",
                max_bytes
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

async fn read_stream_limited<R>(mut reader: R, max_bytes: usize) -> Result<(Vec<u8>, bool)>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut truncated = false;

    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            break;
        }

        if buf.len() >= max_bytes {
            truncated = true;
            continue;
        }

        let remaining = max_bytes - buf.len();
        let take = remaining.min(n);
        buf.extend_from_slice(&chunk[..take]);
        if take < n {
            truncated = true;
        }
    }

    Ok((buf, truncated))
}

async fn check_rate_limit(
    cfg: &Config,
    rates: &RateMap,
    requester: &RequesterIdentity,
) -> Result<()> {
    let now = now_unix();
    let cutoff = now.saturating_sub(cfg.security.per_uid_window_seconds);
    let mut rates = rates.lock().await;
    let entries = rates.entry(requester.uid).or_default();
    while matches!(entries.front(), Some(ts) if *ts <= cutoff) {
        entries.pop_front();
    }
    if entries.len() >= cfg.security.per_uid_max_requests {
        return Err(anyhow!("rate limit exceeded for uid {}", requester.uid));
    }
    entries.push_back(now);
    Ok(())
}

fn truncate_text(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    text.chars().take(max_chars).collect::<String>() + "\n…(truncated)…"
}

struct CommandRunResult {
    exit_code: i32,
    ok: bool,
    stdout: String,
    stderr: String,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

async fn run_command_limited(
    cfg: &Config,
    command: &NormalizedCommand,
) -> Result<CommandRunResult> {
    let mut cmd = tokio::process::Command::new(&command.exe);
    if command.argv.len() > 1 {
        cmd.args(&command.argv[1..]);
    }
    cmd.env_clear();
    cmd.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    cmd.env("LANG", "C.UTF-8");
    cmd.env("LC_ALL", "C.UTF-8");
    cmd.current_dir("/");
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.kill_on_drop(true);

    let mut child = cmd.spawn().context("spawn command")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("missing child stdout pipe"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("missing child stderr pipe"))?;

    let stdout_task = tokio::spawn(read_stream_limited(stdout, 8_000));
    let stderr_task = tokio::spawn(read_stream_limited(stderr, 8_000));

    let status = match tokio::time::timeout(
        Duration::from_secs(cfg.security.command_timeout_seconds),
        child.wait(),
    )
    .await
    {
        Ok(status) => status.context("wait for command")?,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            stdout_task.abort();
            stderr_task.abort();
            return Err(anyhow!(
                "execution timed out ({}s)",
                cfg.security.command_timeout_seconds
            ));
        }
    };

    let (stdout_bytes, stdout_truncated) = stdout_task.await.context("join stdout task")??;
    let (stderr_bytes, stderr_truncated) = stderr_task.await.context("join stderr task")??;

    let mut stdout = String::from_utf8_lossy(&stdout_bytes).to_string();
    let mut stderr = String::from_utf8_lossy(&stderr_bytes).to_string();
    if stdout_truncated {
        stdout.push_str("\n…(truncated)…");
    }
    if stderr_truncated {
        stderr.push_str("\n…(truncated)…");
    }

    Ok(CommandRunResult {
        exit_code: status.code().unwrap_or(-1),
        ok: status.success(),
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    })
}

fn telegram_result_text(
    cfg: &Config,
    request_id: &str,
    command: &str,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
) -> Option<String> {
    match cfg.telegram.result_mode.as_str() {
        "none" => None,
        "summary" => Some(format!(
            "✅ SUDO RESULT\n\nRequest: {}\nCommand: {}\nExit: {}\nStdout bytes: {}\nStderr bytes: {}",
            request_id,
            command,
            exit_code,
            stdout.len(),
            stderr.len()
        )),
        "truncated" => {
            let limit = cfg.telegram.result_max_chars;
            let body = format!(
                "✅ SUDO RESULT\n\nRequest: {}\nCommand: {}\nExit: {}\n\nSTDOUT:\n{}\n\nSTDERR:\n{}",
                request_id, command, exit_code, stdout, stderr
            );
            Some(truncate_text(&body, limit))
        }
        "full" => Some(format!(
            "✅ SUDO RESULT\n\nRequest: {}\nCommand: {}\nExit: {}\n\nSTDOUT:\n{}\n\nSTDERR:\n{}",
            request_id, command, exit_code, stdout, stderr
        )),
        _ => None,
    }
}

impl Daemon {
    pub fn new(cfg: Config) -> Self {
        let tg = Telegram::new(cfg.telegram.bot_token.clone());
        Self { cfg, tg }
    }

    pub async fn serve(self, socket_path: &str) -> Result<()> {
        let key = decode_hmac_key(&self.cfg.security.hmac_secret_hex)?;

        prepare_socket_path(socket_path)?;

        let listener = UnixListener::bind(socket_path)
            .with_context(|| format!("bind unix socket: {socket_path}"))?;
        set_socket_perms(socket_path, "sudo-gate").context("set socket ownership/mode")?;

        println!("sudo-gated: listening on {socket_path}");

        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let rates: RateMap = Arc::new(Mutex::new(HashMap::new()));

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
            let (stream, _) = listener.accept().await?;
            let cfg = self.cfg.clone();
            let tg = self.tg.clone();
            let pending = pending.clone();
            let rates = rates.clone();
            let key = key.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_client(cfg, tg, stream, pending, rates, &key).await {
                    eprintln!("client error: {e:#}");
                }
            });
        }
    }
}

async fn poll_telegram(cfg: Config, tg: Telegram, pending: PendingMap, key: &[u8]) -> Result<()> {
    let mut offset: Option<i64> = None;
    loop {
        match tg.get_updates(offset, 20).await {
            Ok(updates) => {
                if let Some(last) = updates.last() {
                    offset = Some(last.update_id + 1);
                }
                for update in updates {
                    if let Err(err) = handle_update(&cfg, &tg, pending.clone(), key, update).await {
                        eprintln!("telegram update handling error: {err:#}");
                    }
                }
            }
            Err(err) => {
                eprintln!("telegram polling error: {err:#}");
                sleep(Duration::from_secs(2)).await;
            }
        }
        sleep(Duration::from_millis(cfg.telegram.poll_interval_ms)).await;
    }
}

async fn handle_update(
    cfg: &Config,
    tg: &Telegram,
    pending: PendingMap,
    key: &[u8],
    update: TgUpdate,
) -> Result<()> {
    let Some(cb) = update.callback_query else {
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

    if now_unix() > exp {
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

    if let Some(msg) = cb.message.as_ref() {
        let _ = tg
            .edit_message_reply_markup(msg.chat.id, msg.message_id, None)
            .await;
    }

    let pending_request = {
        let mut map = pending.lock().await;
        map.remove(&request_id)
    };

    if let Some(pending_request) = pending_request {
        audit(
            "approval.resolved",
            json!({
                "request_id": request_id,
                "approved": decision,
                "approver_telegram_id": cb.from.id,
                "requester_uid": pending_request.metadata.requester.uid,
                "requester_gid": pending_request.metadata.requester.gid,
                "requester_user": pending_request.metadata.requester.username,
                "requester_pid": pending_request.metadata.requester.pid,
                "reason": pending_request.metadata.reason,
                "command": pending_request.metadata.command,
                "age_seconds": now_unix().saturating_sub(pending_request.metadata.requested_at),
            }),
        );
        let _ = pending_request.decision_tx.send(decision);
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
    rates: RateMap,
    key: &[u8],
) -> Result<()> {
    let requester = requester_from_stream(&stream)?;
    if let Err(err) = validate_requester(&requester, &cfg.security) {
        let message = err.to_string();
        audit(
            "request.rejected",
            json!({
                "requester_uid": requester.uid,
                "requester_gid": requester.gid,
                "requester_user": requester.username,
                "requester_pid": requester.pid,
                "reason": message,
            }),
        );
        reject(&mut stream, message).await?;
        return Ok(());
    }

    let buf = match tokio::time::timeout(
        Duration::from_secs(10),
        read_limited(&mut stream, cfg.security.max_request_bytes),
    )
    .await
    {
        Ok(Ok(buf)) => buf,
        Ok(Err(err)) => {
            let message = err.to_string();
            audit(
                "request.rejected",
                json!({
                    "requester_uid": requester.uid,
                    "requester_gid": requester.gid,
                    "requester_user": requester.username,
                    "requester_pid": requester.pid,
                    "reason": message,
                }),
            );
            reject(&mut stream, message).await?;
            return Ok(());
        }
        Err(_) => {
            let message = "request read timed out".to_string();
            audit(
                "request.rejected",
                json!({
                    "requester_uid": requester.uid,
                    "requester_gid": requester.gid,
                    "requester_user": requester.username,
                    "requester_pid": requester.pid,
                    "reason": message,
                }),
            );
            reject(&mut stream, message).await?;
            return Ok(());
        }
    };

    let req: Request = match serde_json::from_slice(&buf).context("parse request") {
        Ok(req) => req,
        Err(err) => {
            let message = err.to_string();
            audit(
                "request.rejected",
                json!({
                    "requester_uid": requester.uid,
                    "requester_gid": requester.gid,
                    "requester_user": requester.username,
                    "requester_pid": requester.pid,
                    "reason": message,
                }),
            );
            reject(&mut stream, message).await?;
            return Ok(());
        }
    };

    if let Err(err) = validate_request_shape(&req, &cfg.security) {
        let message = err.to_string();
        audit(
            "request.rejected",
            json!({
                "requester_uid": requester.uid,
                "requester_gid": requester.gid,
                "requester_user": requester.username,
                "requester_pid": requester.pid,
                "reason": message,
                "request_reason": req.reason,
            }),
        );
        reject(&mut stream, message).await?;
        return Ok(());
    }

    if let Err(err) = check_rate_limit(&cfg, &rates, &requester).await {
        let message = err.to_string();
        audit(
            "request.rejected",
            json!({
                "requester_uid": requester.uid,
                "requester_gid": requester.gid,
                "requester_user": requester.username,
                "requester_pid": requester.pid,
                "reason": message,
                "request_reason": req.reason,
            }),
        );
        reject(&mut stream, message).await?;
        return Ok(());
    }

    let normalized = match canonicalize_command(&req.argv) {
        Ok(cmd) => cmd,
        Err(err) => {
            let message = err.to_string();
            audit(
                "request.rejected",
                json!({
                    "requester_uid": requester.uid,
                    "requester_gid": requester.gid,
                    "requester_user": requester.username,
                    "requester_pid": requester.pid,
                    "reason": message,
                    "request_reason": req.reason,
                    "argv": req.argv,
                }),
            );
            reject(&mut stream, message).await?;
            return Ok(());
        }
    };

    let policy_input = RequestPolicyInput {
        exe: normalized.exe.clone(),
        argv: normalized.argv.clone(),
    };

    match evaluate(&cfg.policy, &policy_input) {
        PolicyDecision::Allow => {}
        PolicyDecision::Deny(why) => {
            audit(
                "policy.denied",
                json!({
                    "requester_uid": requester.uid,
                    "requester_gid": requester.gid,
                    "requester_user": requester.username,
                    "requester_pid": requester.pid,
                    "reason": req.reason,
                    "command": normalized.display,
                    "policy_message": why,
                }),
            );
            send_response(
                &mut stream,
                Response {
                    ok: false,
                    message: why,
                    request_id: None,
                    approved: Some(false),
                    exit_code: None,
                    stdout: None,
                    stderr: None,
                },
            )
            .await?;
            return Ok(());
        }
    }

    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let request_id = hex::encode(&nonce[..8]);
    let exp = now_unix() + cfg.security.request_ttl_seconds;

    let metadata = PendingMetadata {
        requester: requester.clone(),
        reason: req.reason.clone(),
        command: normalized.display.clone(),
        requested_at: now_unix(),
    };

    let (tx, rx) = oneshot::channel::<bool>();
    let pending_limit_reached = {
        let mut map = pending.lock().await;
        if map.len() >= cfg.security.max_pending_requests {
            true
        } else {
            map.insert(
                request_id.clone(),
                Pending {
                    decision_tx: tx,
                    metadata: metadata.clone(),
                },
            );
            false
        }
    };
    if pending_limit_reached {
        let message = "too many pending approval requests".to_string();
        audit(
            "request.rejected",
            json!({
                "requester_uid": requester.uid,
                "requester_gid": requester.gid,
                "requester_user": requester.username,
                "requester_pid": requester.pid,
                "reason": message,
                "request_reason": req.reason,
                "command": normalized.display,
            }),
        );
        reject(&mut stream, message).await?;
        return Ok(());
    }

    let cmd_hash = sha256_hex(&normalized.display);
    let prompt = format!(
        "🔐 SUDO REQUEST\n\nRequest: {}\nRequester: {} (uid {}, gid {}, pid {})\nReason: {}\nCommand: {}\nCmdHash: {}\n\nApprove? (expires in {}s)",
        request_id,
        requester.username,
        requester.uid,
        requester.gid,
        requester.pid,
        req.reason,
        normalized.display,
        &cmd_hash[..12],
        cfg.security.request_ttl_seconds
    );

    let approve = cb_data(key, "approve", &request_id, exp);
    let deny = cb_data(key, "deny", &request_id, exp);
    if approve.len() > 64 || deny.len() > 64 {
        let mut map = pending.lock().await;
        map.remove(&request_id);
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

    audit(
        "request.submitted",
        json!({
            "request_id": request_id,
            "requester_uid": requester.uid,
            "requester_gid": requester.gid,
            "requester_user": requester.username,
            "requester_pid": requester.pid,
            "reason": req.reason,
            "command": normalized.display,
        }),
    );

    if let Err(err) = tg.send_message(chat_id(&cfg), &prompt, Some(markup)).await {
        let mut map = pending.lock().await;
        map.remove(&request_id);
        return Err(err);
    }

    let decision = tokio::select! {
        decision = rx => decision.context("decision channel")?,
        _ = sleep(Duration::from_secs(cfg.security.request_ttl_seconds)) => false,
    };

    if !decision {
        let mut map = pending.lock().await;
        map.remove(&request_id);
        audit(
            "request.denied_or_timed_out",
            json!({
                "request_id": request_id,
                "requester_uid": requester.uid,
                "requester_gid": requester.gid,
                "requester_user": requester.username,
                "requester_pid": requester.pid,
                "reason": req.reason,
                "command": normalized.display,
            }),
        );
        send_response(
            &mut stream,
            Response {
                ok: true,
                message: "denied/timeout".to_string(),
                request_id: Some(request_id),
                approved: Some(false),
                exit_code: None,
                stdout: None,
                stderr: None,
            },
        )
        .await?;
        return Ok(());
    }

    let run = match run_command_limited(&cfg, &normalized).await {
        Ok(run) => run,
        Err(err) => {
            let message = err.to_string();
            audit(
                "command.timed_out",
                json!({
                    "request_id": request_id,
                    "requester_uid": requester.uid,
                    "requester_gid": requester.gid,
                    "requester_user": requester.username,
                    "requester_pid": requester.pid,
                    "command": normalized.display,
                    "timeout_seconds": cfg.security.command_timeout_seconds,
                }),
            );
            send_response(
                &mut stream,
                Response {
                    ok: false,
                    message,
                    request_id: Some(request_id),
                    approved: Some(true),
                    exit_code: None,
                    stdout: None,
                    stderr: None,
                },
            )
            .await?;
            return Ok(());
        }
    };

    audit(
        "command.executed",
        json!({
            "request_id": request_id,
            "requester_uid": requester.uid,
            "requester_gid": requester.gid,
            "requester_user": requester.username,
            "requester_pid": requester.pid,
            "command": normalized.display,
            "exit_code": run.exit_code,
            "ok": run.ok,
            "stdout_truncated": run.stdout_truncated,
            "stderr_truncated": run.stderr_truncated,
        }),
    );

    if let Some(text) = telegram_result_text(
        &cfg,
        &request_id,
        &normalized.display,
        run.exit_code,
        &run.stdout,
        &run.stderr,
    ) {
        let _ = tg.send_message(chat_id(&cfg), &text, None).await;
    }

    send_response(
        &mut stream,
        Response {
            ok: run.ok,
            message: if run.ok {
                "executed"
            } else {
                "executed (non-zero exit)"
            }
            .to_string(),
            request_id: Some(request_id),
            approved: Some(true),
            exit_code: Some(run.exit_code),
            stdout: Some(run.stdout),
            stderr: Some(run.stderr),
        },
    )
    .await?;

    Ok(())
}
