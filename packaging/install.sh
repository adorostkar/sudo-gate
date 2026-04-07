#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

CONFIG_PATH="/etc/sudo-gate/config.json"
SERVICE_PATH="/etc/systemd/system/sudo-gated.service"
TMPFILES_PATH="/etc/tmpfiles.d/sudo-gate.conf"
SOCKET_PATH="/run/sudo-gate/sock"
INSTALL_CLIENT_PATH="/usr/local/bin/sudo-gate"
INSTALL_DAEMON_PATH="/usr/local/sbin/sudo-gated"
BACKUP_DIR="/var/backups/sudo-gate"
GROUP_NAME="sudo-gate"
RESULT_MODE="summary"
REQUEST_TTL_SECONDS="90"
POLL_INTERVAL_MS="1500"
MAX_REQUEST_BYTES="8192"
MAX_REASON_LEN="200"
MAX_ARG_COUNT="16"
MAX_ARG_LEN="512"
MAX_PENDING_REQUESTS="32"
PER_UID_MAX_REQUESTS="5"
PER_UID_WINDOW_SECONDS="60"
COMMAND_TIMEOUT_SECONDS="60"
NON_INTERACTIVE=0
DRY_RUN=0
BUILD_FIRST=1
BOT_TOKEN=""
ALLOWED_USER_ID=""
ALLOWED_CHAT_ID=""
AUTOMATION_USER=""
REQUESTER_UIDS=()
ALLOW_RULES=()

usage() {
  cat <<'EOF'
sudo-gate installer

Usage:
  packaging/install.sh [options]

Options:
  --bot-token TOKEN             Telegram bot token
  --allowed-user-id ID          Telegram user id allowed to approve
  --allowed-chat-id ID          Optional Telegram chat id
  --automation-user USER        Local automation user to add to sudo-gate group
  --requester-uid UID           Local requester uid allowed to use the socket (repeatable)
  --allow RULE                  Allow rule in the form /absolute/exe or /absolute/exe|arg1,arg2
                                Repeatable. Example:
                                --allow /usr/bin/apt|update
                                --allow /usr/bin/systemctl|restart,nginx
  --result-mode MODE            none|summary|truncated|full (default: summary)
  --config PATH                 Config destination (default: /etc/sudo-gate/config.json)
  --socket PATH                 Socket path (default: /run/sudo-gate/sock)
  --non-interactive             Fail instead of prompting for missing values
  --no-build                    Skip cargo build --release
  --dry-run                     Print actions without changing the system
  -h, --help                    Show this help

Examples:
  packaging/install.sh
  packaging/install.sh --non-interactive \
    --bot-token 123:abc \
    --allowed-user-id 123456 \
    --automation-user hermes \
    --requester-uid 1001 \
    --allow '/usr/bin/apt|update'

Telegram ID discovery helper:
  python3 packaging/discover_telegram_ids.py --bot-token 123:abc
EOF
}

log() {
  printf '[install] %s\n' "$*"
}

warn() {
  printf '[install][warn] %s\n' "$*" >&2
}

die() {
  printf '[install][error] %s\n' "$*" >&2
  exit 1
}

run() {
  if (( DRY_RUN )); then
    printf '[dry-run]'
    for arg in "$@"; do
      printf ' %q' "$arg"
    done
    printf '\n'
  else
    "$@"
  fi
}

as_root() {
  if (( EUID == 0 )); then
    run "$@"
  else
    run sudo "$@"
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

prompt() {
  local var_name="$1"
  local label="$2"
  local secret="${3:-0}"
  local default_value="${4:-}"
  local value=""

  if (( NON_INTERACTIVE )); then
    die "missing required value for $label in --non-interactive mode"
  fi

  if (( secret )); then
    read -r -s -p "$label${default_value:+ [$default_value]}: " value
    printf '\n'
  else
    read -r -p "$label${default_value:+ [$default_value]}: " value
  fi

  if [[ -z "$value" ]]; then
    value="$default_value"
  fi
  printf -v "$var_name" '%s' "$value"
}

prompt_optional() {
  local var_name="$1"
  local label="$2"
  local default_value="${3:-}"
  local value=""
  if (( NON_INTERACTIVE )); then
    printf -v "$var_name" '%s' "$default_value"
    return
  fi
  read -r -p "$label${default_value:+ [$default_value]}: " value
  if [[ -z "$value" ]]; then
    value="$default_value"
  fi
  printf -v "$var_name" '%s' "$value"
}

parse_allow_rule() {
  local raw="$1"
  local exe args_part
  if [[ "$raw" == *'|'* ]]; then
    exe="${raw%%|*}"
    args_part="${raw#*|}"
  else
    exe="$raw"
    args_part=""
  fi

  [[ "$exe" = /* ]] || die "allow rule executable must be an absolute path: $raw"

  if [[ -n "$args_part" ]]; then
    printf '%s|%s\n' "$exe" "$args_part"
  else
    printf '%s|\n' "$exe"
  fi
}

collect_allow_rules_interactive() {
  local line parsed
  if (( NON_INTERACTIVE )); then
    return
  fi

  if (( ${#ALLOW_RULES[@]} == 0 )); then
    log "Enter allow rules. Use /absolute/exe or /absolute/exe|arg1,arg2. Blank line to finish."
    while true; do
      read -r -p 'Allow rule: ' line
      [[ -z "$line" ]] && break
      parsed="$(parse_allow_rule "$line")"
      ALLOW_RULES+=("$parsed")
    done
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --bot-token)
        BOT_TOKEN="$2"; shift 2 ;;
      --allowed-user-id)
        ALLOWED_USER_ID="$2"; shift 2 ;;
      --allowed-chat-id)
        ALLOWED_CHAT_ID="$2"; shift 2 ;;
      --automation-user)
        AUTOMATION_USER="$2"; shift 2 ;;
      --requester-uid)
        REQUESTER_UIDS+=("$2"); shift 2 ;;
      --allow)
        ALLOW_RULES+=("$(parse_allow_rule "$2")"); shift 2 ;;
      --result-mode)
        RESULT_MODE="$2"; shift 2 ;;
      --config)
        CONFIG_PATH="$2"; shift 2 ;;
      --socket)
        SOCKET_PATH="$2"; shift 2 ;;
      --non-interactive)
        NON_INTERACTIVE=1; shift ;;
      --no-build)
        BUILD_FIRST=0; shift ;;
      --dry-run)
        DRY_RUN=1; shift ;;
      -h|--help)
        usage; exit 0 ;;
      *)
        die "unknown argument: $1" ;;
    esac
  done
}

validate_mode() {
  case "$RESULT_MODE" in
    none|summary|truncated|full) ;;
    *) die "invalid --result-mode: $RESULT_MODE" ;;
  esac
}

ensure_inputs() {
  [[ -n "$BOT_TOKEN" ]] || prompt BOT_TOKEN "Telegram bot token" 1
  [[ -n "$ALLOWED_USER_ID" ]] || prompt ALLOWED_USER_ID "Telegram allowed user id"
  prompt_optional ALLOWED_CHAT_ID "Telegram allowed chat id (optional)"
  prompt_optional AUTOMATION_USER "Automation user to add to sudo-gate group (optional)" "$AUTOMATION_USER"

  if [[ -n "$AUTOMATION_USER" ]] && (( ${#REQUESTER_UIDS[@]} == 0 )); then
    if id -u "$AUTOMATION_USER" >/dev/null 2>&1; then
      REQUESTER_UIDS+=("$(id -u "$AUTOMATION_USER")")
    else
      warn "automation user '$AUTOMATION_USER' does not exist yet; no requester uid auto-detected"
    fi
  fi

  collect_allow_rules_interactive
  if (( ${#ALLOW_RULES[@]} == 0 )); then
    die "at least one --allow rule is required"
  fi
}

backup_if_exists() {
  local path="$1"
  local name="$2"
  local stamp
  stamp="$(date +%Y%m%d-%H%M%S)"
  if (( DRY_RUN )); then
    return
  fi
  if [[ -e "$path" ]]; then
    as_root mkdir -p "$BACKUP_DIR"
    as_root cp -a "$path" "$BACKUP_DIR/${name}.${stamp}.bak"
  fi
}

write_tmpfiles() {
  local tmp
  tmp="$(mktemp)"
  cat > "$tmp" <<'EOF'
d /run/sudo-gate 0750 root sudo-gate -
EOF
  as_root install -m 0644 "$tmp" "$TMPFILES_PATH"
  rm -f "$tmp"
  as_root systemd-tmpfiles --create "$TMPFILES_PATH"
}

write_config() {
  local tmp requester_json allow_json chat_json
  tmp="$(mktemp)"

  if (( ${#REQUESTER_UIDS[@]} == 0 )); then
    requester_json='[]'
  else
    requester_json="$(printf '%s\n' "${REQUESTER_UIDS[@]}" | python3 -c 'import json,sys; vals=[int(x.strip()) for x in sys.stdin if x.strip()]; print(json.dumps(vals))')"
  fi

  allow_json="$(printf '%s\n' "${ALLOW_RULES[@]}" | python3 -c 'import json,sys
rules=[]
for line in sys.stdin:
    line=line.strip()
    if not line:
        continue
    exe,args=line.split("|",1)
    obj={"exe": exe}
    if args:
        obj["args_prefix"]=[part for part in args.split(",") if part]
    else:
        obj["args_prefix"]=None
    rules.append(obj)
print(json.dumps(rules))')"

  if [[ -n "$ALLOWED_CHAT_ID" ]]; then
    chat_json="$ALLOWED_CHAT_ID"
  else
    chat_json='null'
  fi

  BOT_TOKEN="$BOT_TOKEN" \
  ALLOWED_USER_ID="$ALLOWED_USER_ID" \
  ALLOWED_CHAT_JSON="$chat_json" \
  RESULT_MODE="$RESULT_MODE" \
  REQUEST_TTL_SECONDS="$REQUEST_TTL_SECONDS" \
  POLL_INTERVAL_MS="$POLL_INTERVAL_MS" \
  MAX_REQUEST_BYTES="$MAX_REQUEST_BYTES" \
  MAX_REASON_LEN="$MAX_REASON_LEN" \
  MAX_ARG_COUNT="$MAX_ARG_COUNT" \
  MAX_ARG_LEN="$MAX_ARG_LEN" \
  MAX_PENDING_REQUESTS="$MAX_PENDING_REQUESTS" \
  PER_UID_MAX_REQUESTS="$PER_UID_MAX_REQUESTS" \
  PER_UID_WINDOW_SECONDS="$PER_UID_WINDOW_SECONDS" \
  COMMAND_TIMEOUT_SECONDS="$COMMAND_TIMEOUT_SECONDS" \
  REQUESTER_UIDS_JSON="$requester_json" \
  ALLOW_JSON="$allow_json" \
  python3 - <<'PY' > "$tmp"
import json, os, secrets
cfg = {
  "telegram": {
    "bot_token": os.environ["BOT_TOKEN"],
    "allowed_user_id": int(os.environ["ALLOWED_USER_ID"]),
    "allowed_chat_id": json.loads(os.environ["ALLOWED_CHAT_JSON"]),
    "poll_interval_ms": int(os.environ["POLL_INTERVAL_MS"]),
    "result_mode": os.environ["RESULT_MODE"],
    "result_max_chars": 1200,
  },
  "security": {
    "hmac_secret_hex": secrets.token_hex(32),
    "request_ttl_seconds": int(os.environ["REQUEST_TTL_SECONDS"]),
    "max_request_bytes": int(os.environ["MAX_REQUEST_BYTES"]),
    "max_reason_len": int(os.environ["MAX_REASON_LEN"]),
    "max_arg_count": int(os.environ["MAX_ARG_COUNT"]),
    "max_arg_len": int(os.environ["MAX_ARG_LEN"]),
    "max_pending_requests": int(os.environ["MAX_PENDING_REQUESTS"]),
    "per_uid_max_requests": int(os.environ["PER_UID_MAX_REQUESTS"]),
    "per_uid_window_seconds": int(os.environ["PER_UID_WINDOW_SECONDS"]),
    "command_timeout_seconds": int(os.environ["COMMAND_TIMEOUT_SECONDS"]),
    "requester_allow_uids": json.loads(os.environ["REQUESTER_UIDS_JSON"]),
  },
  "policy": {
    "mode": "allowlist",
    "allow": json.loads(os.environ["ALLOW_JSON"]),
    "deny": [
      {"kind": "exe", "value": "/bin/sh"},
      {"kind": "exe", "value": "/bin/bash"},
      {"kind": "exe", "value": "/usr/bin/python3"},
      {"kind": "exe", "value": "/usr/bin/env"},
    ],
  },
}
print(json.dumps(cfg, indent=2))
PY

  as_root mkdir -p "$(dirname "$CONFIG_PATH")"
  backup_if_exists "$CONFIG_PATH" "config.json"
  as_root install -m 0600 "$tmp" "$CONFIG_PATH"
  rm -f "$tmp"
}

install_files() {
  local client_src daemon_src service_tmp
  client_src="$REPO_ROOT/target/release/sudo-gate"
  daemon_src="$REPO_ROOT/target/release/sudo-gated"
  [[ -x "$client_src" ]] || die "missing built client binary: $client_src"
  [[ -x "$daemon_src" ]] || die "missing built daemon binary: $daemon_src"

  backup_if_exists "$INSTALL_CLIENT_PATH" "sudo-gate"
  backup_if_exists "$INSTALL_DAEMON_PATH" "sudo-gated"
  backup_if_exists "$SERVICE_PATH" "sudo-gated.service"

  as_root install -m 0755 "$client_src" "$INSTALL_CLIENT_PATH"
  as_root install -m 0755 "$daemon_src" "$INSTALL_DAEMON_PATH"

  service_tmp="$(mktemp)"
  python3 - <<'PY' "$REPO_ROOT/packaging/sudo-gated.service" "$service_tmp" "$CONFIG_PATH" "$SOCKET_PATH"
from pathlib import Path
import sys
src = Path(sys.argv[1])
out = Path(sys.argv[2])
config = sys.argv[3]
socket = sys.argv[4]
text = src.read_text()
lines = []
for line in text.splitlines():
    if line.startswith('ExecStart='):
        line = f'ExecStart=/usr/local/sbin/sudo-gated --config {config} --socket {socket}'
    lines.append(line)
out.write_text('\n'.join(lines) + '\n')
PY
  as_root install -m 0644 "$service_tmp" "$SERVICE_PATH"
  rm -f "$service_tmp"
}

maybe_build() {
  if (( BUILD_FIRST )); then
    log "Building release binaries"
    (cd "$REPO_ROOT" && cargo build --release)
  fi
}

setup_group_and_user() {
  as_root groupadd --system "$GROUP_NAME" 2>/dev/null || true
  if [[ -n "$AUTOMATION_USER" ]]; then
    as_root usermod -aG "$GROUP_NAME" "$AUTOMATION_USER"
  fi
}

restart_service() {
  as_root systemctl daemon-reload
  as_root systemctl enable --now sudo-gated
  as_root systemctl restart sudo-gated
}

doctor_check() {
  log "Running doctor check as root"
  if (( DRY_RUN )); then
    printf '[dry-run] sudo %q --config %q doctor\n' "$INSTALL_CLIENT_PATH" "$CONFIG_PATH"
  elif (( EUID == 0 )); then
    "$INSTALL_CLIENT_PATH" --config "$CONFIG_PATH" doctor
  else
    sudo "$INSTALL_CLIENT_PATH" --config "$CONFIG_PATH" doctor
  fi
}

print_summary() {
  cat <<EOF

Install complete.

Config:   $CONFIG_PATH
Service:  $SERVICE_PATH
Socket:   $SOCKET_PATH
Client:   $INSTALL_CLIENT_PATH
Daemon:   $INSTALL_DAEMON_PATH

Next steps:
1) Confirm the bot can message you on Telegram
2) From an allowed requester account, run a test request like:
   sudo-gate request --reason "test" -- /usr/bin/id
3) Watch logs with:
   journalctl -u sudo-gated -f
EOF
}

parse_args "$@"
validate_mode
need_cmd cargo
need_cmd python3
need_cmd install
need_cmd systemctl
ensure_inputs
maybe_build
setup_group_and_user
write_tmpfiles
install_files
write_config
restart_service
doctor_check
print_summary
