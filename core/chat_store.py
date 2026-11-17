"""chat_store.py - INFOSEC chat history, saved on this PC.

The dashboard saves every INFOSEC conversation (copilot panel, full page and scanner questions) through
POST /api/chats; the INFOSEC page lists them (GET /api/chats) and reopens one (GET /api/chats/<id>).

  * one JSON file per chat: <state-root>/infosec/chats/<id>.json (state root = data/ by default, which is
    git-ignored); nothing leaves the PC;
  * strict schema: whitelisted fields, capped sizes, chat ids from a fixed pattern (no path tricks);
  * token-like strings are masked before anything is written (ai_bridge.mask_secrets), the same second
    net the scan uses;
  * no delete route: removing saved chats is a file operation the user asks for in Claude Code chat,
    like every other deletion in this project.

Python 3 standard library only.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import secrets
import threading
from pathlib import Path

from ai_bridge import mask_secrets

CHAT_ID_RE = re.compile(r"^c[0-9a-z]{8,40}$")
MAX_MESSAGES = 200
MAX_TEXT = 20_000
MAX_TITLE = 120
MAX_SHORT = 200
MAX_CHATS = 2_000
MAX_LIST = 400
MAX_LIST_QUESTIONS = 30
MAX_FILE_BYTES = 6 * 1024 * 1024
ROLES = ("user", "assistant")
SOURCES = ("ai", "offline", "error")


class ChatError(Exception):
    """An error with an HTTP status and a short user-facing message."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _bad(message: str):
    raise ChatError(400, "bad_request", message)


def _now_ms() -> int:
    return int(_dt.datetime.now(_dt.timezone.utc).timestamp() * 1000)


def _ts(value, where: str) -> int:
    if value is None:
        return _now_ms()
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value < 10 ** 14:
        _bad(f"{where} must be a time in milliseconds.")
    return int(value)


def _text(value, where: str, limit: int, required: bool = False) -> str:
    if value is None:
        if required:
            _bad(f"{where} is required.")
        return ""
    if not isinstance(value, str):
        _bad(f"{where} must be text.")
    if len(value) > limit:
        _bad(f"{where} is too long.")
    return mask_secrets(value.replace("\x00", ""))


def validate_chat(body) -> dict:
    """Validate and normalise a chat posted by the dashboard. Raises ChatError(400) on bad input."""
    if not isinstance(body, dict):
        _bad("The chat must be a JSON object.")
    extra = set(body) - {"id", "title", "created", "updated", "messages"}
    if extra:
        _bad("Unknown chat field: " + sorted(extra)[0])
    cid = body.get("id")
    if not isinstance(cid, str) or not CHAT_ID_RE.match(cid):
        _bad("The chat id is invalid.")
    msgs = body.get("messages")
    if not isinstance(msgs, list) or len(msgs) > MAX_MESSAGES:
        _bad(f"messages must be a list of at most {MAX_MESSAGES} items.")
    out_msgs = []
    for i, m in enumerate(msgs):
        where = f"messages[{i}]"
        if not isinstance(m, dict) or m.get("role") not in ROLES:
            _bad(f"{where} needs role user or assistant.")
        extra = set(m) - {"role", "text", "ts", "source", "model", "costUsd", "about", "via", "error"}
        if extra:
            _bad(f"{where} has an unknown field: " + sorted(extra)[0])
        item = {"role": m["role"], "text": _text(m.get("text"), where + ".text", MAX_TEXT, required=True),
                "ts": _ts(m.get("ts"), where + ".ts")}
        if m.get("source") is not None:
            if m["source"] not in SOURCES:
                _bad(f"{where}.source is invalid.")
            item["source"] = m["source"]
        for key in ("model", "about", "via"):
            val = _text(m.get(key), f"{where}.{key}", MAX_SHORT)
            if val:
                item[key] = val
        if m.get("costUsd") is not None:
            cost = m["costUsd"]
            if isinstance(cost, bool) or not isinstance(cost, (int, float)) or not 0 <= cost < 100:
                _bad(f"{where}.costUsd is invalid.")
            item["costUsd"] = round(float(cost), 6)
        if m.get("error") is not None:
            if not isinstance(m["error"], bool):
                _bad(f"{where}.error must be true or false.")
            if m["error"]:
                item["error"] = True
        out_msgs.append(item)
    title = _text(body.get("title"), "title", MAX_TITLE).strip()
    if not title:
        first = next((m["text"] for m in out_msgs if m["role"] == "user"), "")
        title = " ".join(first.split())[:80] or "New chat"
    created = _ts(body.get("created"), "created")
    updated = _ts(body.get("updated"), "updated")
    return {"id": cid, "title": title, "created": created, "updated": max(updated, created), "messages": out_msgs}


def _write_json_atomic(path: Path, obj: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(obj, ensure_ascii=False, indent=1))
    os.replace(tmp, path)


def _read_json(path: Path):
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        with open(path, "r", encoding="utf-8-sig") as handle:
            return json.loads(handle.read())
    except (OSError, ValueError):
        return None


class ChatStore:
    """INFOSEC chats under <state_root>/infosec/chats, one JSON file each."""

    def __init__(self, state_root):
        self.dir = Path(state_root) / "infosec" / "chats"
        self._lock = threading.Lock()

    def _path(self, cid: str) -> Path:
        if not isinstance(cid, str) or not CHAT_ID_RE.match(cid):
            raise ChatError(404, "not_found", "No such chat.")
        return self.dir / f"{cid}.json"

    def save(self, body) -> dict:
        chat = validate_chat(body)
        path = self._path(chat["id"])
        with self._lock:
            if not path.exists() and self.dir.is_dir() and sum(1 for _ in self.dir.glob("c*.json")) >= MAX_CHATS:
                raise ChatError(507, "full", f"INFOSEC keeps at most {MAX_CHATS} saved chats.")
            _write_json_atomic(path, chat)
        return {"id": chat["id"], "title": chat["title"], "updated": chat["updated"], "count": len(chat["messages"])}

    def get(self, cid: str) -> dict:
        obj = _read_json(self._path(cid))
        if not isinstance(obj, dict) or obj.get("id") != cid:
            raise ChatError(404, "not_found", "No such chat.")
        return obj

    def list(self) -> list:
        """Newest first: id, title, times, message count and the user's questions (for the INFOSEC page)."""
        if not self.dir.is_dir():
            return []
        rows = []
        for path in self.dir.glob("c*.json"):
            if not CHAT_ID_RE.match(path.stem):
                continue
            obj = _read_json(path)
            if not isinstance(obj, dict) or obj.get("id") != path.stem:
                continue
            msgs = [m for m in obj.get("messages") or [] if isinstance(m, dict)]
            questions = [{"text": " ".join(str(m.get("text") or "").split())[:MAX_SHORT], "ts": m.get("ts"),
                          "about": m.get("about") or ""}
                         for m in msgs if m.get("role") == "user"][-MAX_LIST_QUESTIONS:]
            rows.append({"id": obj["id"], "title": obj.get("title") or "Chat", "created": obj.get("created"),
                         "updated": obj.get("updated"), "count": len(msgs), "questions": questions})
        rows.sort(key=lambda r: r.get("updated") or 0, reverse=True)
        return rows[:MAX_LIST]
