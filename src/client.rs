use crate::ipc::{Request, Response};
use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub async fn send_request(
    socket_path: &str,
    reason: String,
    argv: Vec<String>,
) -> Result<Response> {
    let req = Request { reason, argv };
    let bytes = serde_json::to_vec(&req)?;

    let mut stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("connect socket: {socket_path}"))?;

    stream.write_all(&bytes).await?;
    stream.shutdown().await?;

    let mut resp_bytes = Vec::new();
    stream.read_to_end(&mut resp_bytes).await?;
    let resp: Response = serde_json::from_slice(&resp_bytes).context("parse response")?;
    Ok(resp)
}
