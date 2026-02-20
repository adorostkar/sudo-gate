# sudo-gate

A small **root daemon** that runs privileged commands only after you approve them in **Telegram**.

## What it does

- `sudo-gated` (daemon, runs as root)
  - listens on a Unix socket (default: `/run/sudo-gate/sock`)
  - sends an approval prompt to Telegram with **Approve/Deny** buttons
  - executes the requested command **only after approval** (argv-only, no shell)
  - edits the Telegram message to remove buttons after one click
  - sends a Telegram follow-up with the execution result

- `sudo-gate` (client, runs unprivileged)
  - submits a request with `--reason` and `-- <cmd args...>`

## Security model (honest)

- This is an **approval gate**, not magic: if the requesting user still has direct `sudo` (or can edit systemd/cron/sudoers), they can bypass it.
- Real safety requires OS hardening: run your automation under a non-sudo user and restrict write access to privileged control planes.

## Config

Production config is expected at:
- `/etc/sudo-gate/config.json` (root-owned `0600`)

Key fields:
- `telegram.bot_token` (secret)
- `telegram.allowed_user_id` (numeric Telegram user id allowed to approve)
- `telegram.allowed_chat_id` (optional extra guard)
- `security.hmac_secret_hex` (32 bytes hex recommended)
- `security.request_ttl_seconds` (approval timeout)
- `policy.mode`: `allow_all` for now (later: deny-by-default)
- `policy.deny`: empty array for now

See: `config.example.json`.

## Build

```bash
. "$HOME/.cargo/env"
cargo build --release
```

## Install + run

See `packaging/INSTALL.md`.

## Usage

Submit a request:

```bash
sudo-gate request --reason "restart nginx" -- systemctl restart nginx
```

Approve in Telegram.

Tip: this works well as a gate in front of any automation (CI runner, cron job, agent, scripts).
## Repo hygiene

- Never commit secrets.
- Use `/etc/sudo-gate/config.json` (or a local ignored config).
