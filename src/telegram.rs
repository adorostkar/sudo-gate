use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct Telegram {
    client: reqwest::Client,
    token: String,
}

impl Telegram {
    pub fn new(token: String) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("build telegram client");
        Self { client, token }
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

    pub async fn get_updates(
        &self,
        offset: Option<i64>,
        timeout_sec: u64,
    ) -> Result<Vec<TgUpdate>> {
        let url = self.api_url("getUpdates");
        let mut req = self.client.get(url).query(&[("timeout", timeout_sec)]);
        if let Some(o) = offset {
            req = req.query(&[("offset", o)]);
        }
        let resp: TgGetUpdates = req.send().await?.json().await?;
        if !resp.ok {
            return Err(anyhow!("telegram getUpdates failed"));
        }
        Ok(resp.result.unwrap_or_default())
    }

    pub async fn send_message(
        &self,
        chat_id: i64,
        text: &str,
        reply_markup: Option<TgReplyMarkup>,
    ) -> Result<TgMessage> {
        let url = self.api_url("sendMessage");
        let body = TgSendMessage {
            chat_id,
            text: text.to_string(),
            reply_markup,
        };
        let resp: TgSendMessageResp = self
            .client
            .post(url)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;
        if !resp.ok {
            return Err(anyhow!("telegram sendMessage failed"));
        }
        resp.result.context("missing message")
    }

    pub async fn answer_callback_query(
        &self,
        callback_query_id: &str,
        text: Option<&str>,
    ) -> Result<()> {
        let url = self.api_url("answerCallbackQuery");
        let body = TgAnswerCallback {
            callback_query_id: callback_query_id.to_string(),
            text: text.map(|s| s.to_string()),
            show_alert: Some(false),
        };
        let resp: TgOk = self
            .client
            .post(url)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;
        if !resp.ok {
            return Err(anyhow!("telegram answerCallbackQuery failed"));
        }
        Ok(())
    }

    pub async fn edit_message_reply_markup(
        &self,
        chat_id: i64,
        message_id: i64,
        reply_markup: Option<TgReplyMarkup>,
    ) -> Result<()> {
        let url = self.api_url("editMessageReplyMarkup");
        let body = TgEditMessageReplyMarkup {
            chat_id,
            message_id,
            reply_markup,
        };
        let resp: TgOk = self
            .client
            .post(url)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;
        if !resp.ok {
            return Err(anyhow!("telegram editMessageReplyMarkup failed"));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct TgGetMe {
    ok: bool,
    result: Option<TgUser>,
}

#[derive(Debug, Deserialize)]
struct TgGetUpdates {
    ok: bool,
    result: Option<Vec<TgUpdate>>,
}

#[derive(Debug, Deserialize)]
pub struct TgUser {
    pub id: i64,
    pub username: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TgUpdate {
    pub update_id: i64,
    pub message: Option<TgMessage>,
    pub callback_query: Option<TgCallbackQuery>,
}

#[derive(Debug, Deserialize)]
pub struct TgMessage {
    pub message_id: i64,
    pub chat: TgChat,
    pub from: Option<TgFrom>,
    pub text: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TgChat {
    pub id: i64,
}

#[derive(Debug, Deserialize)]
pub struct TgFrom {
    pub id: i64,
}

#[derive(Debug, Deserialize)]
pub struct TgCallbackQuery {
    pub id: String,
    pub from: TgFrom,
    pub message: Option<TgMessage>,
    pub data: Option<String>,
}

#[derive(Debug, Serialize)]
struct TgSendMessage {
    chat_id: i64,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_markup: Option<TgReplyMarkup>,
}

#[derive(Debug, Deserialize)]
struct TgSendMessageResp {
    ok: bool,
    result: Option<TgMessage>,
}

#[derive(Debug, Serialize)]
struct TgAnswerCallback {
    callback_query_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    show_alert: Option<bool>,
}

#[derive(Debug, Serialize)]
struct TgEditMessageReplyMarkup {
    chat_id: i64,
    message_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_markup: Option<TgReplyMarkup>,
}

#[derive(Debug, Deserialize)]
struct TgOk {
    ok: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TgReplyMarkup {
    pub inline_keyboard: Vec<Vec<TgInlineKeyboardButton>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TgInlineKeyboardButton {
    pub text: String,
    pub callback_data: String,
}
