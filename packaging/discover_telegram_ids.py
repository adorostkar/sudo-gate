#!/usr/bin/env python3
"""Discover Telegram user/chat IDs for sudo-gate setup.

Usage examples:
  python3 packaging/discover_telegram_ids.py --bot-token '123:abc'
  python3 packaging/discover_telegram_ids.py --bot-token '123:abc' --json

Ask the target approver to send a fresh message like /start to the bot first.
Then run this helper to inspect recent updates and extract candidate user/chat IDs.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request
from typing import Any


def api_get(token: str, method: str, **params: Any) -> dict[str, Any]:
    query = urllib.parse.urlencode(params)
    url = f"https://api.telegram.org/bot{token}/{method}"
    if query:
        url += f"?{query}"
    with urllib.request.urlopen(url, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not data.get("ok"):
        raise SystemExit(f"Telegram API {method} failed: {data}")
    return data


def collect_candidates(updates: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    users: dict[int, dict[str, Any]] = {}
    chats: dict[int, dict[str, Any]] = {}

    for update in updates:
        for key in ("message", "edited_message", "channel_post", "edited_channel_post"):
            msg = update.get(key)
            if not msg:
                continue

            chat = msg.get("chat") or {}
            chat_id = chat.get("id")
            if chat_id is not None:
                chats[int(chat_id)] = {
                    "chat_id": int(chat_id),
                    "type": chat.get("type"),
                    "title": chat.get("title"),
                    "username": chat.get("username"),
                    "first_name": chat.get("first_name"),
                    "last_name": chat.get("last_name"),
                }

            sender = msg.get("from") or msg.get("sender_chat") or {}
            user_id = sender.get("id")
            if user_id is not None:
                users[int(user_id)] = {
                    "user_id": int(user_id),
                    "username": sender.get("username"),
                    "first_name": sender.get("first_name"),
                    "last_name": sender.get("last_name"),
                    "is_bot": sender.get("is_bot"),
                }

        cb = update.get("callback_query")
        if cb:
            sender = cb.get("from") or {}
            user_id = sender.get("id")
            if user_id is not None:
                users[int(user_id)] = {
                    "user_id": int(user_id),
                    "username": sender.get("username"),
                    "first_name": sender.get("first_name"),
                    "last_name": sender.get("last_name"),
                    "is_bot": sender.get("is_bot"),
                }
            msg = cb.get("message") or {}
            chat = msg.get("chat") or {}
            chat_id = chat.get("id")
            if chat_id is not None:
                chats[int(chat_id)] = {
                    "chat_id": int(chat_id),
                    "type": chat.get("type"),
                    "title": chat.get("title"),
                    "username": chat.get("username"),
                    "first_name": chat.get("first_name"),
                    "last_name": chat.get("last_name"),
                }

    return list(users.values()), list(chats.values())


def main() -> int:
    parser = argparse.ArgumentParser(description="Discover Telegram user/chat IDs for sudo-gate")
    parser.add_argument("--bot-token", required=True, help="Telegram bot token")
    parser.add_argument("--limit", type=int, default=20, help="How many recent updates to inspect")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = parser.parse_args()

    me = api_get(args.bot_token, "getMe")["result"]
    updates = api_get(args.bot_token, "getUpdates", limit=args.limit, timeout=1).get("result", [])
    users, chats = collect_candidates(updates)

    payload = {
        "bot": {
            "id": me.get("id"),
            "username": me.get("username"),
            "first_name": me.get("first_name"),
        },
        "update_count": len(updates),
        "users": sorted(users, key=lambda x: x["user_id"]),
        "chats": sorted(chats, key=lambda x: x["chat_id"]),
    }

    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    print(f"Bot: @{payload['bot'].get('username')} (id={payload['bot'].get('id')})")
    print(f"Recent updates inspected: {payload['update_count']}")
    print()

    if not updates:
        print("No recent updates found.")
        print("Ask the intended approver to send a fresh message like /start to the bot, then re-run this helper.")
        return 0

    print("Candidate users:")
    if payload["users"]:
        for user in payload["users"]:
            label = user.get("username") or ""
            name = " ".join(part for part in [user.get("first_name"), user.get("last_name")] if part)
            extra = f" @{label}" if label else ""
            if name:
                extra += f" ({name})"
            print(f"- user_id={user['user_id']}{extra}")
    else:
        print("- none found")

    print()
    print("Candidate chats:")
    if payload["chats"]:
        for chat in payload["chats"]:
            label = chat.get("title") or chat.get("username") or chat.get("first_name") or ""
            ctype = chat.get("type") or "unknown"
            extra = f" {label}" if label else ""
            print(f"- chat_id={chat['chat_id']} type={ctype}{extra}")
    else:
        print("- none found")

    print()
    print("Recommended config mapping:")
    if payload["users"]:
        print(f"- telegram.allowed_user_id = {payload['users'][0]['user_id']}")
    if payload["chats"]:
        print(f"- telegram.allowed_chat_id = {payload['chats'][0]['chat_id']}")
    else:
        print("- telegram.allowed_chat_id = null  # direct-message approval only")

    return 0


if __name__ == "__main__":
    sys.exit(main())
