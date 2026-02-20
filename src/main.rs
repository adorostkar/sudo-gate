use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UnixDatagram;
use tokio::time::sleep;

// NOTE: This is an initial scaffold.
// It currently implements ONLY config loading + a Telegram connectivity smoke test.
// Next steps: daemon/client split, unix socket protocol, approval loop, exec.

#[derive(Debug, Clone, Deserialize)]
struct Config {
    telegram: TelegramConfig,
    security: SecurityConfig,
    policy: PolicyConfig,
}

#[derive(Debug, Clone, Deserialize)]
struct TelegramConfig {
    bot_token: String,
    allowed_user_id: i64,
    allowed_chat_id: Option<i64>,
    poll_interval_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct SecurityConfig {
    hmac_secret_hex: String,
    request_ttl_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct PolicyConfig {
    mode: String,
    deny: Vec<DenyRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct DenyRule {
    kind: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct TgGetMe {
    ok: bool,
    result: Option<TgUser>,
}

#[derive(Debug, Deserialize)]
struct TgUser {
    id: i64,
    username: Option<String>,
}

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

fn random_nonce_hex() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

#[tokio::main]
async fn main() -> Result<()> {
    let path = std::env::args().nth(1).unwrap_or_else(|| "config.example.json".to_string());
    let cfg_text = std::fs::read_to_string(&path).with_context(|| format!("read config: {path}"))?;
    let cfg: Config = serde_json::from_str(&cfg_text).context("parse config")?;

    // Basic sanity checks.
    if cfg.telegram.allowed_user_id == 0 {
        return Err(anyhow("telegram.allowed_user_id must be set"));
    }
    if cfg.security.hmac_secret_hex.len() < 32 {
        return Err(anyhow("security.hmac_secret_hex looks too short"));
    }

    // Telegram connectivity smoke test.
    let url = format!(
        "https://api.telegram.org/bot{}/getMe",
        cfg.telegram.bot_token
    );
    let client = reqwest::Client::new();
    let resp: TgGetMe = client.get(url).send().await?.json().await?;
    if !resp.ok {
        return Err(anyhow("telegram getMe failed"));
    }
    let bot = resp.result.context("missing bot result")?;

    // Print only non-sensitive info.
    println!("sudo-gate: Telegram bot ok: id={} username={:?}", bot.id, bot.username);
    println!("sudo-gate: policy.mode={} deny_rules={}", cfg.policy.mode, cfg.policy.deny.len());
    println!("sudo-gate: nonce_sample={} cmd_hash_sample={}", random_nonce_hex()[..12].to_string(), sha256_hex("id")[..12].to_string());
    println!("sudo-gate: now_unix={}", now_unix());

    Ok(())
}
