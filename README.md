# sudo-gate (draft)

Root-privileged sudo approval gate with Telegram approvals.

## Status

Draft scaffold. Intended design:
- `sudo-gated` (daemon) runs as root, listens on Unix socket.
- `sudo-gate` (client) is executed by unprivileged user, submits a request.
- Daemon sends Telegram message (reason + exact command) with Approve/Deny inline buttons.
- Approval uses in-memory nonce + HMAC signature; single-use + short expiry.

## Config

Will live at `/etc/sudo-gate/config.json` (root-owned 0600) in production.

Fields:
- telegram.bot_token (secret)
- telegram.allowed_user_id (Ashkan)
- telegram.allowed_chat_id (optional)
- telegram.polling (offset, interval)
- policy.mode: `allow_all` for now
- policy.deny: empty for now

## Notes

Do NOT store secrets in git. Use the config file above.
