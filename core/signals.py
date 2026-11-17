"""signals.py - the dashboard -> Claude session signal bus (docs/ui-contract-v3.md section 1).

The dashboard server (server/serve.py) calls SignalStore.create() for POST /api/signal, and
SignalStore.list_recent() / session() for GET /api/signals and GET /api/session. The Claude
session side lives in tools/windows/watch-signals.ps1 (picks signals up), signal-status.ps1
(status updates), validate-delete.ps1 and execute-delete.ps1 (the only place that deletes).

Files (under the state root, normally <project>/data):
  signals/inbox/<id>.json     new signal, written here (atomically, via a dot-temp file)
  signals/status/<id>.json    {id, state, message, updatedAt}; first written here (queued)
  signals/archive/<id>.json   picked-up signals (moved by the watcher)
  session/heartbeat.json      {pid, startedAt, beatAt}, written by the watcher every 5 s

Validation is strict: an allowlist of signal types, exact payload keys per type (unknown keys
are rejected), module ids from an allowlist, at most 200 delete items with string paths of at
most 1024 characters, and no control or bidi characters in any string.

delete-request double confirmation: the request must carry typedConfirmation == "I confirm"
(exact, case-sensitive). A one-time code of 8 characters from CODE_ALPHABET is drawn with the
secrets module and returned to the browser ONCE, formatted XXXX-XXXX. Only codeSalt (32 hex)
and codeHash = PBKDF2-HMAC-SHA256(code, codeSalt, 600,000 iterations) (hex, code = the 8
characters without the dash) are written to disk. The code itself is never written, logged or returned by any other route.

Python 3 standard library only.
"""
from __future__ import annotations

import collections
import datetime as _dt
import hashlib
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path

SCHEMA = "bvs.signal/1"
SIGNAL_TYPES = ("run-admin", "run-github-check", "rerun-module", "fix-request", "delete-request", "refresh-report")
MODULE_IDS = tuple([f"S{n:02d}" for n in range(1, 14)] + ["G0", "G1", "G2", "H1", "H2"])
STATES = ("queued", "picked-up", "awaiting-chat-confirmation", "running", "done", "error", "cancelled", "expired")
CONFIRM_PHRASE = "I confirm"
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 8
MAX_DELETE_ITEMS = 200
MAX_PATH_CHARS = 1024
MAX_LABEL_CHARS = 300
MAX_MESSAGE_CHARS = 500
DELETE_METHODS = ("recycle", "holding", "uninstall", "tool", "setting")  # tool/setting are refused by the validator
EXPIRE_SECONDS = 60 * 60
SESSION_FRESH_SECONDS = 15
LIST_LIMIT = 30

ID_RE = re.compile(r"^(\d{8})-(\d{6})-(" + "|".join(re.escape(t) for t in SIGNAL_TYPES) + r")-([a-z0-9]{6})$")
SCAN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
ITEM_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
FINDING_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
# C0/C1 controls, zero-width and bidi override characters: never allowed in any signal string
_BAD_CHARS_RE = re.compile("[\x00-\x1f\x7f-\x9f​-‏ -‮⁦-⁩﻿]")
_RANDOM_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

_EMPTY_PAYLOAD_TYPES = ("run-admin", "run-github-check", "refresh-report")


class SignalError(Exception):
    """An error with an HTTP status and a short user-facing message (same shape as ai_bridge.AIError)."""

    def __init__(self, status: int, code: str, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.retry_after = retry_after


def _bad(message: str, code: str = "bad_request"):
    raise SignalError(400, code, message)


def utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def iso(ts: _dt.datetime) -> str:
    return ts.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value) -> _dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        out = _dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return out if out.tzinfo else out.replace(tzinfo=_dt.timezone.utc)


def clean_text(value, limit: int) -> str:
    """Display-safe text for status messages: controls/bidi removed, clipped."""
    text = _BAD_CHARS_RE.sub(" ", str(value or ""))
    return text if len(text) <= limit else text[: limit - 1] + "…"


# --- one-time code -------------------------------------------------------------------------------
def generate_code() -> str:
    """8 characters from CODE_ALPHABET (no 0/O/1/I/L), drawn with the secrets CSPRNG."""
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))


def format_code(code: str) -> str:
    return f"{code[:4]}-{code[4:]}"


def normalize_code(typed: str) -> str | None:
    """'I confirm k7q2-m9xp' / 'K7Q2-M9XP' / 'K7Q2M9XP' -> 'K7Q2M9XP'; None when malformed."""
    if not isinstance(typed, str):
        return None
    text = typed.strip()
    if text.startswith(CONFIRM_PHRASE):
        text = text[len(CONFIRM_PHRASE):]
    text = re.sub(r"[\s-]", "", text).upper()
    if len(text) != CODE_LENGTH or any(ch not in CODE_ALPHABET for ch in text):
        return None
    return text


CODE_KDF = "pbkdf2-sha256-600000"
CODE_KDF_ITERATIONS = 600_000


def hash_code(salt: str, code: str) -> str:
    """codeHash = PBKDF2-HMAC-SHA256(password=code, salt=salt, 600k iterations, 32 bytes) as hex.

    A slow KDF so the 40-bit one-time code cannot be brute-forced from the signal file in practice
    (plain sha256 would be crackable offline). execute-delete.ps1 computes the same with
    Rfc2898DeriveBytes.Pbkdf2.
    """
    return hashlib.pbkdf2_hmac("sha256", code.encode("utf-8"), salt.encode("utf-8"), CODE_KDF_ITERATIONS, 32).hex()


# --- validation ----------------------------------------------------------------------------------
def _check_keys(obj: dict, allowed: set, required: set, where: str):
    unknown = set(obj) - allowed
    if unknown:
        _bad(f"{where} has unknown field(s).")
    missing = required - set(obj)
    if missing:
        _bad(f"{where} is missing required field(s): {', '.join(sorted(missing))}.")


def _check_str(value, where: str, limit: int, allow_empty: bool = True) -> str:
    if not isinstance(value, str):
        _bad(f"{where} must be text.")
    if len(value) > limit:
        _bad(f"{where} is too long (at most {limit} characters).")
    if not allow_empty and not value.strip():
        _bad(f"{where} must not be empty.")
    if _BAD_CHARS_RE.search(value):
        _bad(f"{where} contains control or invisible characters.")
    return value


def _validate_delete_items(payload: dict) -> dict:
    _check_keys(payload, {"items"}, {"items"}, "payload")
    items = payload["items"]
    if not isinstance(items, list) or not items:
        _bad("payload.items must be a non-empty list.")
    if len(items) > MAX_DELETE_ITEMS:
        _bad(f"At most {MAX_DELETE_ITEMS} items per delete request.")
    clean, seen_ids, seen_paths = [], set(), set()
    for idx, item in enumerate(items):
        where = f"items[{idx}]"
        if not isinstance(item, dict):
            _bad(f"{where} must be an object.")
        _check_keys(item, {"id", "path", "bytes", "method", "label"}, {"id", "path", "method"}, where)
        iid = _check_str(item["id"], f"{where}.id", 128, allow_empty=False)
        if not ITEM_ID_RE.match(iid):
            _bad(f"{where}.id has an invalid format.")
        path = _check_str(item["path"], f"{where}.path", MAX_PATH_CHARS)
        method = item["method"]
        if method not in DELETE_METHODS:
            _bad(f"{where}.method is not allowed.")
        size = item.get("bytes")
        if size is not None and (isinstance(size, bool) or not isinstance(size, int) or size < 0 or size > 2 ** 62):
            _bad(f"{where}.bytes must be a whole number of bytes or null.")
        label = item.get("label")
        label = "" if label is None else _check_str(label, f"{where}.label", MAX_LABEL_CHARS)
        if iid in seen_ids:
            _bad(f"{where}.id is listed twice.")
        key = path.lower()
        if path and key in seen_paths:
            _bad(f"{where}.path is listed twice.")
        seen_ids.add(iid)
        if path:
            seen_paths.add(key)
        clean.append({"id": iid, "path": path, "bytes": size, "method": method, "label": label})
    return {"items": clean}


def validate_payload(stype: str, payload) -> dict:
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        _bad("payload must be an object.")
    if stype in _EMPTY_PAYLOAD_TYPES:
        if payload:
            _bad("This signal takes no payload fields.")
        return {}
    if stype == "rerun-module":
        _check_keys(payload, {"module"}, {"module"}, "payload")
        if payload["module"] not in MODULE_IDS:
            _bad("payload.module is not a known module id.")
        return {"module": payload["module"]}
    if stype == "fix-request":
        _check_keys(payload, {"findingId"}, {"findingId"}, "payload")
        fid = payload["findingId"]
        if not isinstance(fid, str) or not FINDING_ID_RE.match(fid):
            _bad("payload.findingId has an invalid format.")
        return {"findingId": fid}
    if stype == "delete-request":
        return _validate_delete_items(payload)
    _bad("Unknown signal type.")  # unreachable: the type is checked first
    return {}


def validate_signal(body, scan_id: str | None = None) -> dict:
    """Validate a POST /api/signal body. Returns {type, payload, typedConfirmation(bool)}.
    Raises SignalError(400) on anything unexpected."""
    if not isinstance(body, dict):
        _bad("The request must be a JSON object.")
    _check_keys(body, {"type", "payload", "typedConfirmation", "scanId"}, {"type"}, "The request")
    stype = body["type"]
    if not isinstance(stype, str) or stype not in SIGNAL_TYPES:
        _bad("Unknown signal type.")
    typed = body.get("typedConfirmation")
    if typed is not None and (not isinstance(typed, str) or len(typed) > 64):
        _bad("typedConfirmation must be short text.")
    scan = body.get("scanId")
    if scan is not None:
        if not isinstance(scan, str) or not SCAN_ID_RE.match(scan):
            _bad("scanId has an invalid format.")
        if scan_id and scan != scan_id:
            _bad("scanId does not match the scan this dashboard shows. Reload the page.")
    payload = validate_payload(stype, body.get("payload"))
    confirmed = typed == CONFIRM_PHRASE
    if stype == "delete-request" and not confirmed:
        _bad('Type exactly "I confirm" (capital I, no extra spaces) before sending a delete request.',
             code="confirmation_required")
    return {"type": stype, "payload": payload, "typedConfirmation": confirmed}


# --- rate limiting -------------------------------------------------------------------------------
class RateLimiter:
    """Sliding one-minute window. take() returns 0 when allowed, else the seconds to wait."""

    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self._lock = threading.Lock()
        self._recent = collections.deque()

    def take(self) -> int:
        now = time.monotonic()
        with self._lock:
            while self._recent and now - self._recent[0] > 60:
                self._recent.popleft()
            if len(self._recent) >= self.per_minute:
                return int(60 - (now - self._recent[0])) + 1
            self._recent.append(now)
            return 0


# --- store ---------------------------------------------------------------------------------------
def _write_json_atomic(path: Path, obj: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    data = json.dumps(obj, ensure_ascii=True, indent=1)
    with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(data)
    os.replace(tmp, path)


def _read_json(path: Path):
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            text = handle.read(1024 * 1024)
        return json.loads(text)
    except (OSError, ValueError):
        return None


class SignalStore:
    """Signal files under <state_root>/signals and the session heartbeat under <state_root>/session."""

    def __init__(self, state_root, scan_id: str | None = None):
        self.root = Path(state_root)
        self.scan_id = scan_id
        base = self.root / "signals"
        self.inbox = base / "inbox"
        self.status_dir = base / "status"
        self.archive = base / "archive"
        self.heartbeat = self.root / "session" / "heartbeat.json"
        self._lock = threading.Lock()

    # --- create ---------------------------------------------------------------------------------
    @staticmethod
    def new_id(stype: str, now: _dt.datetime | None = None) -> str:
        stamp = (now or utc_now()).astimezone().strftime("%Y%m%d-%H%M%S")
        rand = "".join(secrets.choice(_RANDOM_ALPHABET) for _ in range(6))
        return f"{stamp}-{stype}-{rand}"

    def create(self, request: dict) -> dict:
        """request = validate_signal() output. Returns {id, state:'queued', code?}. The code exists only in
        the returned dict: it is hashed with a fresh salt and never written anywhere."""
        now = utc_now()
        with self._lock:
            sid = self.new_id(request["type"], now)
            while (self.inbox / f"{sid}.json").exists() or (self.archive / f"{sid}.json").exists():
                sid = self.new_id(request["type"], now)
            signal = {
                "schema": SCHEMA, "id": sid, "type": request["type"], "createdAt": iso(now),
                "scanId": self.scan_id, "payload": request["payload"],
                "local": {"typedConfirmation": bool(request["typedConfirmation"]),
                          "at": iso(now) if request["typedConfirmation"] else None},
            }
            code = None
            if request["type"] == "delete-request":
                code = generate_code()
                salt = secrets.token_hex(16)
                signal["codeSalt"] = salt
                signal["codeHash"] = hash_code(salt, code)
                signal["codeKdf"] = CODE_KDF
            _write_json_atomic(self.inbox / f"{sid}.json", signal)
            self.write_status(sid, "queued", "Waiting for the Claude session to pick this up.")
        out = {"id": sid, "state": "queued"}
        if code:
            out["code"] = format_code(code)
        return out

    def write_status(self, sid: str, state: str, message: str):
        if not ID_RE.match(sid) or state not in STATES:
            raise ValueError("bad status")
        _write_json_atomic(self.status_dir / f"{sid}.json",
                           {"id": sid, "state": state, "message": clean_text(message, MAX_MESSAGE_CHARS),
                            "updatedAt": iso(utc_now())})

    # --- read -----------------------------------------------------------------------------------
    def _ids(self):
        found = {}
        for folder, where in ((self.archive, "archive"), (self.inbox, "inbox")):
            try:
                names = os.listdir(folder)
            except OSError:
                continue
            for name in names:
                if name.endswith(".json") and ID_RE.match(name[:-5]):
                    found[name[:-5]] = where
        return found

    @staticmethod
    def _summary(signal: dict) -> dict:
        payload = signal.get("payload") if isinstance(signal.get("payload"), dict) else {}
        stype = signal.get("type")
        if stype == "rerun-module":
            return {"module": payload.get("module")}
        if stype == "fix-request":
            return {"findingId": payload.get("findingId")}
        if stype == "delete-request":
            items = payload.get("items") if isinstance(payload.get("items"), list) else []
            total = sum(i.get("bytes") or 0 for i in items if isinstance(i, dict) and isinstance(i.get("bytes"), int))
            return {"items": len(items), "bytes": total}
        return {}

    def list_recent(self, limit: int = LIST_LIMIT) -> list:
        """The most recent signals with their state and message. Never codes, salts or hashes."""
        ids = self._ids()
        ordered = sorted(ids, key=lambda s: (ID_RE.match(s).group(1), ID_RE.match(s).group(2), s), reverse=True)
        now = utc_now()
        out = []
        for sid in ordered[:limit]:
            folder = self.archive if ids[sid] == "archive" else self.inbox
            signal = _read_json(folder / f"{sid}.json")
            if not isinstance(signal, dict) or signal.get("id") != sid:
                continue
            status = _read_json(self.status_dir / f"{sid}.json")
            status = status if isinstance(status, dict) and status.get("id") == sid else {}
            state = status.get("state") if status.get("state") in STATES else (
                "queued" if ids[sid] == "inbox" else "picked-up")
            message = clean_text(status.get("message") or "", MAX_MESSAGE_CHARS)
            created = parse_iso(signal.get("createdAt"))
            if state == "queued" and created and (now - created).total_seconds() > EXPIRE_SECONDS:
                state, message = "expired", "Nobody picked this up within 60 minutes. Send it again when Claude is listening."
            local = signal.get("local") if isinstance(signal.get("local"), dict) else {}
            out.append({
                "id": sid, "type": signal.get("type") if signal.get("type") in SIGNAL_TYPES else None,
                "createdAt": signal.get("createdAt"), "state": state, "message": message,
                "updatedAt": status.get("updatedAt") if isinstance(status.get("updatedAt"), str) else None,
                "confirmedInBrowser": local.get("typedConfirmation") is True,
                "summary": self._summary(signal),
            })
        return out

    def session(self) -> dict:
        beat = _read_json(self.heartbeat)
        beat = beat if isinstance(beat, dict) else {}
        beat_at = parse_iso(beat.get("beatAt"))
        connected = False
        if beat_at:
            age = (utc_now() - beat_at).total_seconds()
            connected = -5 <= age < SESSION_FRESH_SECONDS
        pid = beat.get("pid")
        return {"connected": connected, "beatAt": iso(beat_at) if beat_at else None,
                "pid": pid if isinstance(pid, int) and not isinstance(pid, bool) else None,
                "startedAt": beat.get("startedAt") if isinstance(beat.get("startedAt"), str) else None}
