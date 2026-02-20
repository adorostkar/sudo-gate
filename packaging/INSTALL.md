# Install (manual steps)

This repo **does not** perform any root changes automatically.

## 0) Create group + add your automation user

```bash
sudo groupadd --system sudo-gate 2>/dev/null || true
sudo usermod -aG sudo-gate <AUTOMATION_USER>
```

Log out/in (or restart the service) so group membership applies.

## 1) Build

```bash
. "$HOME/.cargo/env"
cd /home/ashkan/.openclaw/workspace/sudo-gate
cargo build --release
```

Artifacts:
- `target/release/sudo-gate` (client)
- `target/release/sudo-gated` (daemon)

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

Why: config contains secrets (Telegram bot token + HMAC key) and should not be writable by the automation user.

## 4) Runtime dirs + socket

The daemon creates `/run/sudo-gate/` and also enforces:
- dir: `root:sudo-gate` mode `0750`
- socket: `root:sudo-gate` mode `0660`

If you want the directory created on boot before the service starts, add a tmpfiles rule:

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

## 6) Test

From the unprivileged user:

```bash
sudo-gate request --reason "test" -- id
```

Approve in Telegram and verify you get stdout/stderr/exit code.

## Next: make it a *real* gate (prevent bypass)

This project enforces approval **only if** the automation user cannot get root through other means.

Minimum checklist:

- Automation user should not have direct sudo:
  ```bash
  sudo -l -U <AUTOMATION_USER>
  ```
- Automation user must not be able to write to:
  - `/etc/sudoers.d/`
  - `/etc/systemd/system/`
  - `/etc/cron.*` and `/var/spool/cron/`

If `<AUTOMATION_USER>` is your personal admin user, consider creating a dedicated non-sudo user for automation.
