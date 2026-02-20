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
    pub poll_interval_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    pub hmac_secret_hex: String,
    pub request_ttl_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    pub mode: String,
    pub deny: Vec<DenyRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DenyRule {
    pub kind: String,
    pub value: String,
}
