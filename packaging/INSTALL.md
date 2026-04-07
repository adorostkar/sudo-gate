# Install (manual steps)

This repo does not perform root changes automatically.

## 0) Create group + add your automation user

```bash
sudo groupadd --system sudo-gate 2>/dev/null || true
sudo usermod -aG sudo-gate <AUTOMATION_USER>
```

Use a dedicated automation user. Do not use your personal admin account.

## 1) Build

```bash
. "$HOME/.cargo/env"
cd /path/to/sudo-gate
cargo build --release
```

Artifacts:
- `target/release/sudo-gate`
- `target/release/sudo-gated`

## 2) Install binaries

```bash
sudo install -m 0755 target/release/sudo-gate  /usr/local/bin/sudo-gate
sudo install -m 0755 target/release/sudo-gated /usr/local/sbin/sudo-gated
```

## 3) Config (root-owned)

```bash
sudo mkdir -p /etc/sudo-gate
sudo cp config.example.json /etc/sudo-gate/config.json
sudo chmod 0600 /etc/sudo-gate/config.json
sudoedit /etc/sudo-gate/config.json
```

Recommended hardening in config:
- set `security.requester_allow_uids` to the exact automation uid(s)
- keep `telegram.result_mode` at `summary` or `none` unless you intentionally want more output copied to Telegram
- keep `policy.mode = "allowlist"`
- use absolute paths in `policy.allow`
- keep the allowlist narrow and task-specific

## 4) Runtime dirs + socket

The daemon requires its socket to live directly under `/run/sudo-gate/` and enforces:
- dir: `root:sudo-gate` mode `0750`
- socket: `root:sudo-gate` mode `0660`

Optional tmpfiles rule:

```bash
sudo tee /etc/tmpfiles.d/sudo-gate.conf >/dev/null <<'EOF'
d /run/sudo-gate 0750 root sudo-gate -
EOF
sudo systemd-tmpfiles --create /etc/tmpfiles.d/sudo-gate.conf
```

## 5) systemd

```bash
sudo cp packaging/sudo-gated.service /etc/systemd/system/sudo-gated.service
sudo systemctl daemon-reload
sudo systemctl enable --now sudo-gated
sudo systemctl status sudo-gated
```

Then inspect audit logs:

```bash
journalctl -u sudo-gated -f
```

## 6) Test

From the automation user:

```bash
sudo-gate request --reason "refresh apt cache" -- /usr/bin/apt update
```

Approve in Telegram and verify:
- Telegram prompt shows requester uid/gid/pid
- command runs only if it matches the allowlist
- audit logs appear in journald

## Hard-gate checklist

Minimum checklist for this to be a real gate:

- automation user has no direct sudo:
  ```bash
  sudo -l -U <AUTOMATION_USER>
  ```
- automation user cannot write to:
  - `/etc/sudoers.d/`
  - `/etc/systemd/system/`
  - `/etc/cron.*`
  - `/var/spool/cron/`
  - `/usr/local/sbin/sudo-gated`
  - `/usr/local/bin/sudo-gate`
  - `/etc/sudo-gate/config.json`
- only expected local users can open `/run/sudo-gate/sock`
- `policy.allow` contains only narrow commands you are comfortable approving

If any of those fail, sudo-gate is a convenience approval wrapper, not a strong privilege boundary.
