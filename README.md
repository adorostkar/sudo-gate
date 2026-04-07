# sudo-gate

A small root daemon that runs privileged commands only after you approve them in Telegram.

## What it does

- `sudo-gated` (daemon, runs as root)
  - listens on a Unix socket under `/run/sudo-gate/` (default: `/run/sudo-gate/sock`)
  - reads requester identity from Unix socket peer credentials (uid/gid/pid)
  - validates request size and shape before prompting
  - enforces a fail-closed allowlist policy
  - sends an approval prompt to Telegram with Approve/Deny buttons
  - executes the approved command without a shell, with a minimal environment
  - emits structured audit events to stdout/journald
  - can send a result summary back to Telegram

- `sudo-gate` (client, runs unprivileged)
  - submits a request with `--reason` and `-- <cmd args...>`

## Security model

sudo-gate is a privilege broker, but only if the requester cannot bypass it.

Real safety requires all of the following:
- run automation under a dedicated non-sudo user
- keep `/etc/sudo-gate/config.json` root-owned and `0600`
- keep the socket group narrow (`sudo-gate`)
- preferably set `security.requester_allow_uids` to the exact requester uid(s)
- use `policy.mode = "allowlist"` with absolute executable paths and narrow arg prefixes

If the requester can still use direct sudo, or can edit systemd/cron/sudoers, this is only an approval wrapper.

## Main hardening features

- shell-free execution (`argv` only)
- Unix peer credential capture and auditing
- optional requester uid allowlist
- fail-closed allowlist policy
- absolute executable paths required
- request size, arg count, arg length, and pending request caps
- per-uid rate limiting
- timeout cleanup for stale requests
- configurable Telegram result leakage (`none|summary|truncated|full`)

## Config

Production config:
- `/etc/sudo-gate/config.json` (root-owned `0600`)

Important fields:
- `telegram.allowed_user_id` — Telegram user allowed to approve
- `telegram.allowed_chat_id` — optional extra chat guard
- `telegram.result_mode` — `none`, `summary`, `truncated`, or `full` (still bounded by daemon output capture limits)
- `security.requester_allow_uids` — optional explicit allowlist of local requester uids
- `security.max_request_bytes` — cap on inbound socket request size
- `security.max_pending_requests` — bound on simultaneous approvals
- `security.per_uid_max_requests` + `security.per_uid_window_seconds` — local rate limiting
- `policy.mode` — must be `allowlist`
- `policy.allow` — exact executable allow rules using absolute paths
- `policy.deny` — extra deny rules for defense in depth

See `config.example.json`.

## Build

```bash
. "$HOME/.cargo/env"
cargo build --release
```

## Install + run

Simplest path:

```bash
./packaging/install.sh
```

The installer can interactively:
- build and install binaries
- create the `sudo-gate` group
- add your automation user to that group
- install tmpfiles + systemd service
- generate `/etc/sudo-gate/config.json`
- start the daemon and run a doctor check

There is also a Telegram discovery helper:

```bash
python3 packaging/discover_telegram_ids.py --bot-token '123456:abc'
```

Ask the intended approver to send a fresh message to the bot first, then use the helper to discover candidate `allowed_user_id` and `allowed_chat_id` values.

For manual steps and non-interactive examples, see `packaging/INSTALL.md`.

## Usage

Submit a request:

```bash
sudo-gate request --reason "refresh apt metadata" -- /usr/bin/apt update
```

Approve in Telegram.

## Audit trail

The daemon prints structured JSON audit events to stdout, which systemd/journald can collect. Key events include:
- `request.submitted`
- `approval.resolved`
- `policy.denied`
- `command.executed`
- `command.timed_out`

## Current limitations

- Telegram approval is still a high-value root authorization factor
- the daemon does not yet do multi-party approval or second-factor confirmation
- policies are argv-prefix based, not a full DSL
- service hardening depends on what your allowlist needs to do

## Repo hygiene

- Never commit secrets
- Keep production config outside the repo
- Treat Telegram output as an exfiltration surface; prefer `summary` or `none`
