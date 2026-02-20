use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

#[derive(Clone)]
pub struct Telegram {
    client: reqwest::Client,
    token: String,
}

impl Telegram {
    pub fn new(token: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            token,
        }
    }

    fn api_url(&self, method: &str) -> String {
        format!("https://api.telegram.org/bot{}/{}", self.token, method)
    }

    pub async fn get_me(&self) -> Result<TgUser> {
        let url = self.api_url("getMe");
        let resp: TgGetMe = self.client.get(url).send().await?.json().await?;
        if !resp.ok {
            return Err(anyhow!("telegram getMe failed"));
        }
        resp.result.context("missing bot result")
    }
}

#[derive(Debug, Deserialize)]
struct TgGetMe {
    ok: bool,
    result: Option<TgUser>,
}

#[derive(Debug, Deserialize)]
pub struct TgUser {
    pub id: i64,
    pub username: Option<String>,
}
