use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn decode_hmac_key(hex_str: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(hex_str).context("decode hmac_secret_hex")?;
    if bytes.len() < 16 {
        return Err(anyhow!("hmac key too short"));
    }
    Ok(bytes)
}

pub fn sign_trunc_hex(key: &[u8], msg: &[u8], trunc_hex_len: usize) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    let hex_all = hex::encode(out);
    hex_all.chars().take(trunc_hex_len).collect()
}

pub fn eq_ct(a: &str, b: &str) -> bool {
    // Constant-time-ish compare on bytes; good enough for this context.
    if a.len() != b.len() {
        return false;
    }
    let mut r: u8 = 0;
    for (x, y) in a.as_bytes().iter().zip(b.as_bytes().iter()) {
        r |= x ^ y;
    }
    r == 0
}
