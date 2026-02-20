# Install (manual steps)

This repo **does not** perform any root changes automatically.

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

## 3) Config

```bash
sudo mkdir -p /etc/sudo-gate
sudo cp config.example.json /etc/sudo-gate/config.json
sudo chmod 0600 /etc/sudo-gate/config.json
sudoedit /etc/sudo-gate/config.json
```

## 4) Runtime dirs + socket

The daemon creates `/run/sudo-gate/` if needed. You may want to set ownership/permissions explicitly (later step).

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

## Next: hard gate

You still need sudoers/permissions so the agent cannot bypass the gate.
