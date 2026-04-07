use anyhow::{bail, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub telegram: TelegramConfig,
    pub security: SecurityConfig,
    pub policy: PolicyConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TelegramConfig {
    pub bot_token: String,
    pub allowed_user_id: i64,
    pub allowed_chat_id: Option<i64>,
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    #[serde(default = "default_result_mode")]
    pub result_mode: String,
    #[serde(default = "default_result_max_chars")]
    pub result_max_chars: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    pub hmac_secret_hex: String,
    #[serde(default = "default_request_ttl_seconds")]
    pub request_ttl_seconds: u64,
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "default_max_reason_len")]
    pub max_reason_len: usize,
    #[serde(default = "default_max_arg_count")]
    pub max_arg_count: usize,
    #[serde(default = "default_max_arg_len")]
    pub max_arg_len: usize,
    #[serde(default = "default_max_pending_requests")]
    pub max_pending_requests: usize,
    #[serde(default = "default_per_uid_max_requests")]
    pub per_uid_max_requests: usize,
    #[serde(default = "default_per_uid_window_seconds")]
    pub per_uid_window_seconds: u64,
    #[serde(default = "default_command_timeout_seconds")]
    pub command_timeout_seconds: u64,
    #[serde(default)]
    pub requester_allow_uids: Vec<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    pub mode: String,
    #[serde(default)]
    pub allow: Vec<AllowRule>,
    #[serde(default)]
    pub deny: Vec<DenyRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AllowRule {
    pub exe: String,
    #[serde(default)]
    pub args_prefix: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DenyRule {
    pub kind: String,
    pub value: String,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.telegram.allowed_user_id == 0 {
            bail!("telegram.allowed_user_id must be set");
        }
        if self.security.hmac_secret_hex.len() < 32 {
            bail!("security.hmac_secret_hex looks too short");
        }
        match self.telegram.result_mode.as_str() {
            "none" | "summary" | "truncated" | "full" => {}
            other => bail!(
                "telegram.result_mode must be one of none|summary|truncated|full, got {other}"
            ),
        }
        if self.security.max_request_bytes == 0 {
            bail!("security.max_request_bytes must be > 0");
        }
        if self.security.max_reason_len == 0 {
            bail!("security.max_reason_len must be > 0");
        }
        if self.security.max_arg_count == 0 {
            bail!("security.max_arg_count must be > 0");
        }
        if self.security.max_arg_len == 0 {
            bail!("security.max_arg_len must be > 0");
        }
        if self.security.max_pending_requests == 0 {
            bail!("security.max_pending_requests must be > 0");
        }
        if self.security.per_uid_max_requests == 0 {
            bail!("security.per_uid_max_requests must be > 0");
        }
        if self.security.per_uid_window_seconds == 0 {
            bail!("security.per_uid_window_seconds must be > 0");
        }
        if self.security.command_timeout_seconds == 0 {
            bail!("security.command_timeout_seconds must be > 0");
        }
        if self.policy.mode != "allowlist" {
            bail!("policy.mode must be 'allowlist' so unknown modes fail closed");
        }
        if self.policy.allow.is_empty() {
            bail!("policy.allow must contain at least one explicit allow rule");
        }
        for rule in &self.policy.allow {
            if !rule.exe.starts_with('/') {
                bail!(
                    "policy allow rule exe must be an absolute path: {}",
                    rule.exe
                );
            }
        }
        for rule in &self.policy.deny {
            if rule.kind == "exe" && !rule.value.starts_with('/') {
                bail!(
                    "policy deny exe rule must use an absolute path: {}",
                    rule.value
                );
            }
        }
        Ok(())
    }
}

fn default_poll_interval_ms() -> u64 {
    1_500
}

fn default_result_mode() -> String {
    "summary".to_string()
}

fn default_result_max_chars() -> usize {
    1_200
}

fn default_request_ttl_seconds() -> u64 {
    90
}

fn default_max_request_bytes() -> usize {
    8 * 1024
}

fn default_max_reason_len() -> usize {
    200
}

fn default_max_arg_count() -> usize {
    16
}

fn default_max_arg_len() -> usize {
    512
}

fn default_max_pending_requests() -> usize {
    32
}

fn default_per_uid_max_requests() -> usize {
    5
}

fn default_per_uid_window_seconds() -> u64 {
    60
}

fn default_command_timeout_seconds() -> u64 {
    60
}
