"""Shared helpers for the baby-virus-scanner core tools.

Python 3 standard library only, cross-platform (Windows + Linux).
Everything here is read-only towards the system; the only writes go through
write_text_atomic(), which refuses to write outside the project folder.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"

SCAN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # 0 = most severe
CLASSES = ("compromise", "suspicious", "hardening", "hygiene", "info")
CHECK_STATUSES = ("ok", "partial", "skipped", "needs_admin", "needs_consent", "not_applicable", "error")
VERIFY_RESULTS = ("confirmed", "refuted", "inconclusive")
SAFETY_LEVELS = ("safe", "safe_after_check", "review", "use_tool", "do_not_touch")
METHODS = ("recycle", "holding", "tool", "uninstall", "setting", "none")
VERDICTS = ("COMPROMISED", "SUSPICIOUS", "HARDENING_NEEDED", "OK")


def utc_now_iso() -> str:
    now = _dt.datetime.now(_dt.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def read_text(path) -> str:
    """Read a text file written by any collector: UTF-8 (with or without BOM) or UTF-16."""
    raw = Path(path).read_bytes()
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def load_json(path):
    """Return (obj, None) or (None, error-message). Never raises for bad input files."""
    try:
        # NaN/Infinity are not valid JSON for the browser: map them to null on the way in.
        return json.loads(read_text(path), parse_constant=lambda _token: None), None
    except FileNotFoundError:
        return None, "missing"
    except (OSError, ValueError) as exc:  # json.JSONDecodeError is a ValueError
        return None, f"{type(exc).__name__}: {exc}"


def as_list(value):
    """PowerShell sometimes unwraps one-element arrays; normalise to a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def as_dict(value):
    return value if isinstance(value, dict) else {}


def to_int(value, default=None):
    if value is None or isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    try:
        text = str(value).strip()
        if not text:
            return default
        return int(float(text))
    except (TypeError, ValueError, OverflowError):
        return default


def lower_str(value, default=""):
    if value is None:
        return default
    return str(value).strip().lower()


def resolve_scan_dir(arg: str | None) -> Path:
    """--scan accepts a scan directory path or a scan ID under data/. Default: data/latest.txt."""
    if arg:
        candidate = Path(arg)
        if candidate.is_dir():
            return candidate.resolve()
        if SCAN_ID_RE.match(arg) and (DATA_DIR / arg).is_dir():
            return (DATA_DIR / arg).resolve()
        raise SystemExit(f"error: scan not found: {arg}")
    latest = DATA_DIR / "latest.txt"
    if not latest.is_file():
        raise SystemExit("error: no --scan given and data/latest.txt is missing")
    scan_id = read_text(latest).strip()
    if not SCAN_ID_RE.match(scan_id) or not (DATA_DIR / scan_id).is_dir():
        raise SystemExit(f"error: data/latest.txt points to a missing scan: {scan_id!r}")
    return (DATA_DIR / scan_id).resolve()


def dir_scan_id(scan_dir: Path) -> str:
    """The scan ID used in URLs and file paths: the scan folder's name."""
    name = Path(scan_dir).name
    return name if SCAN_ID_RE.match(name) else "scan"


def is_inside(child, parent) -> bool:
    child_real = os.path.normcase(os.path.realpath(str(child)))
    parent_real = os.path.normcase(os.path.realpath(str(parent)))
    try:
        return os.path.commonpath([child_real, parent_real]) == parent_real
    except ValueError:  # different drives on Windows
        return False


def write_text_atomic(path, text: str) -> Path:
    """Write UTF-8 (no BOM) atomically. Refuses to write outside the project folder."""
    target = Path(path)
    if not is_inside(target, ROOT):
        raise SystemExit(f"error: refusing to write outside the project folder: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    if not is_inside(target.parent, ROOT):  # re-check after mkdir (symlinked parents)
        raise SystemExit(f"error: refusing to write outside the project folder: {target}")
    tmp = target.with_name(f"{target.name}.tmp-{os.getpid()}")
    with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    os.replace(tmp, target)
    return target


def dump_json(obj, indent=None) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=indent, separators=None if indent else (",", ":"))
