"""agents_live.py - read-only list of the agentic coding tools running on this PC (GET /api/agents/live).

How it works:
  * one process listing via Windows PowerShell:
      Get-CimInstance Win32_Process | Select ProcessId,Name,CommandLine,CreationDate | ConvertTo-Json
    (falls back to `tasklist /FO CSV /NH`, which has names and PIDs only). Nothing is written,
    nothing is killed or changed. The result is cached for 5 seconds;
  * matches Claude Code (claude.exe, or node/bun running @anthropic-ai/claude-code), the Claude
    desktop app, Codex CLI, Gemini CLI, Aider, cursor-agent, Cursor, Windsurf and GitHub Copilot
    CLI. Electron helper processes (--type=...) are skipped so each app shows once per window
    process;
  * command lines never leave this module in full: only the executable's file name plus at most
    three flag NAMES (never their values, never flags that look secret: token/key/secret/pass/
    auth/cookie/...) are kept, and the result is passed through the secret maskers as well
    (ai_bridge.mask_secrets and the rules in config/secret-patterns.json).

Python 3 standard library only.
"""
from __future__ import annotations

import csv
import datetime as _dt
import io
import json
import os
import re
import subprocess
import sys
import threading
import time

sys.path.append(os.path.dirname(os.path.abspath(__file__)))  # appended, so the stdlib always wins
from ai_bridge import mask_secrets  # noqa: E402

CACHE_SECONDS = 5
TIMEOUT_S = 20
MAX_FLAGS = 3
PS_SCRIPT = ("Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine,"
             "@{n='CreationDate';e={if($_.CreationDate){$_.CreationDate.ToUniversalTime().ToString('o')}}} | "
             "ConvertTo-Json -Compress")

# exe file name (lower case) -> (kind, display name)
EXE_RULES = {
    "claude.exe": ("claude-code", "Claude Code"), "claude": ("claude-code", "Claude Code"),
    "codex.exe": ("codex", "Codex CLI"), "codex": ("codex", "Codex CLI"),
    "gemini.exe": ("gemini", "Gemini CLI"), "gemini": ("gemini", "Gemini CLI"),
    "aider.exe": ("aider", "Aider"), "aider": ("aider", "Aider"),
    "cursor-agent.exe": ("cursor-agent", "Cursor Agent"), "cursor-agent": ("cursor-agent", "Cursor Agent"),
    "cursor.exe": ("cursor", "Cursor"),
    "windsurf.exe": ("windsurf", "Windsurf"),
    "copilot.exe": ("copilot", "GitHub Copilot CLI"), "copilot": ("copilot", "GitHub Copilot CLI"),
}
# Script hosts whose command line tells which agent they run
SCRIPT_HOSTS = {"node.exe", "node", "bun.exe", "bun", "deno.exe", "python.exe", "python3.exe", "pythonw.exe",
                "py.exe", "gh.exe"}
SCRIPT_RULES = (
    (re.compile(r"(?i)@anthropic-ai[\\/]+claude-code|[\\/]claude-code[\\/]+cli\.m?js"), "claude-code", "Claude Code"),
    (re.compile(r"(?i)@openai[\\/]+codex|[\\/]codex[\\/]+bin[\\/]+codex"), "codex", "Codex CLI"),
    (re.compile(r"(?i)@google[\\/]+gemini-cli|[\\/]gemini-cli[\\/]"), "gemini", "Gemini CLI"),
    (re.compile(r"(?i)@github[\\/]+copilot|\bgh(?:\.exe)?\"?\s+copilot\b"), "copilot", "GitHub Copilot CLI"),
    (re.compile(r"(?i)cursor-agent"), "cursor-agent", "Cursor Agent"),
    (re.compile(r"(?i)(?:-m\s+aider\b|[\\/]aider(?:\.exe)?(?:\"|\s|$)|[\\/]aider[\\/])"), "aider", "Aider"),
)
ELECTRON_HELPER_RE = re.compile(r"(?i)\s--type=")
CLAUDE_DESKTOP_RE = re.compile(r"(?i)AnthropicClaude|[\\/]Claude[\\/]app-|WindowsApps[\\/]Claude")
FLAG_RE = re.compile(r"^--?[A-Za-z][A-Za-z0-9-]{0,39}$")
SECRET_FLAG_RE = re.compile(r"(?i)token|key|secret|pass|pwd|auth|cred|cookie|session|bearer|cert|private|sig")
NAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._ -]")
_TOKEN_RE = re.compile(r'"[^"]*"|\S+')


def _utc_iso(ts: float | None = None) -> str:
    return _dt.datetime.fromtimestamp(ts if ts is not None else time.time(), _dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def _parse_started(value) -> str | None:
    """ISO-8601 (from the calculated property) or the legacy '/Date(ms)/' form -> 'YYYY-MM-DDTHH:MM:SSZ'."""
    if not isinstance(value, str) or not value:
        return None
    m = re.match(r"^/Date\((\d+)\)/$", value)
    if m:
        return _utc_iso(int(m.group(1)) / 1000)
    text = value.strip()
    text = text[:-1] + "+00:00" if text.endswith("Z") else text
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)  # .NET writes 7 fractional digits
    try:
        ts = _dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if not ts.tzinfo:
        ts = ts.replace(tzinfo=_dt.timezone.utc)
    return ts.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def classify(name: str, cmdline: str | None):
    """Return (kind, display name) for an agentic tool process, or None."""
    exe = (name or "").strip().lower()
    cmd = cmdline or ""
    rule = EXE_RULES.get(exe)
    if rule:
        if cmd and ELECTRON_HELPER_RE.search(cmd):
            return None  # Electron renderer/GPU/utility helper of Cursor, Windsurf or the Claude desktop app
        if rule[0] == "claude-code" and CLAUDE_DESKTOP_RE.search(cmd):
            return ("claude-desktop", "Claude desktop app")
        return rule
    if exe in SCRIPT_HOSTS and cmd:
        for pattern, kind, display in SCRIPT_RULES:
            if pattern.search(cmd):
                return (kind, display)
    return None


_CONFIG_RULES = None
_CONFIG_LOCK = threading.Lock()


def _config_rules() -> list:
    """config/secret-patterns.json (the collectors' masking rules), compiled once with Python re."""
    global _CONFIG_RULES
    with _CONFIG_LOCK:
        if _CONFIG_RULES is None:
            rules = []
            path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config",
                                "secret-patterns.json")
            try:
                with open(path, "r", encoding="utf-8-sig") as handle:
                    cfg = json.load(handle)
                for rule in cfg.get("rules", []) if isinstance(cfg, dict) else []:
                    try:
                        rules.append((re.compile(rule["regex"]), int(rule.get("group") or 0)))
                    except (re.error, KeyError, TypeError, ValueError):
                        continue
            except (OSError, ValueError):
                pass
            _CONFIG_RULES = rules
        return _CONFIG_RULES


def mask_text(text: str) -> str:
    text = mask_secrets(text)
    for pattern, group in _config_rules():
        def repl(m, g=group):
            if g and m.group(g):
                return m.group(0).replace(m.group(g), "[masked]")
            return "[masked]"
        text = pattern.sub(repl, text)
    return text


def short_command(name: str, cmdline: str | None) -> str:
    """Executable file name plus at most three non-secret flag names. Values are never kept."""
    exe = NAME_SAFE_RE.sub("", os.path.basename((name or "").strip()))[:60] or "?"
    flags = []
    tokens = _TOKEN_RE.findall(cmdline or "")
    for token in tokens[1:]:
        flag = token.strip('"').split("=", 1)[0]
        if not FLAG_RE.match(flag) or SECRET_FLAG_RE.search(flag) or flag in flags:
            continue
        flags.append(flag)
        if len(flags) >= MAX_FLAGS:
            break
    return mask_text(" ".join([exe] + flags))


def parse_cim_json(text: str) -> list:
    data = json.loads(text) if text and text.strip() else []
    if isinstance(data, dict):
        data = [data]
    rows = []
    for proc in data if isinstance(data, list) else []:
        if not isinstance(proc, dict):
            continue
        pid = proc.get("ProcessId")
        if not isinstance(pid, int) or isinstance(pid, bool):
            continue
        rows.append({"pid": pid, "name": str(proc.get("Name") or ""), "cmd": proc.get("CommandLine"),
                     "started": _parse_started(proc.get("CreationDate"))})
    return rows


def parse_tasklist_csv(text: str) -> list:
    rows = []
    for rec in csv.reader(io.StringIO(text or "")):
        if len(rec) >= 2 and rec[1].strip().isdigit():
            rows.append({"pid": int(rec[1]), "name": rec[0], "cmd": None, "started": None})
    return rows


def build_items(rows: list) -> list:
    items = []
    for row in rows:
        hit = classify(row["name"], row["cmd"])
        if not hit:
            continue
        kind, display = hit
        items.append({"name": display, "kind": kind, "pid": row["pid"], "started": row["started"],
                      "exe": NAME_SAFE_RE.sub("", os.path.basename(row["name"]))[:60],
                      "command": short_command(row["name"], row["cmd"]),
                      "commandAvailable": bool(row["cmd"])})
    items.sort(key=lambda it: (it["kind"], it["started"] or "", it["pid"]))
    return items


def _no_window() -> dict:
    return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)} if os.name == "nt" else {}


def default_runner():
    """Return (rows, source). Read-only process listing; never raises."""
    if os.name != "nt":
        return [], "unsupported"
    for shell in ("powershell", "pwsh"):
        try:
            proc = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", PS_SCRIPT],
                                  capture_output=True, text=True, encoding="utf-8", errors="replace",
                                  timeout=TIMEOUT_S, shell=False, **_no_window())
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            try:
                return parse_cim_json(proc.stdout), "cim"
            except ValueError:
                continue
    try:
        proc = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=TIMEOUT_S, shell=False, **_no_window())
        if proc.returncode == 0:
            return parse_tasklist_csv(proc.stdout), "tasklist"
    except (OSError, subprocess.TimeoutExpired):
        pass
    return [], "error"


class LiveAgents:
    """Cached (5 s) list of running agentic tools. runner() -> (rows, source) is injectable for tests."""

    def __init__(self, runner=None, cache_seconds: float = CACHE_SECONDS):
        self.runner = runner or default_runner
        self.cache_seconds = cache_seconds
        self._lock = threading.Lock()
        self._cached = None
        self._stamp = 0.0

    def get(self) -> dict:
        with self._lock:
            now = time.monotonic()
            if self._cached is not None and now - self._stamp < self.cache_seconds:
                return self._cached
            try:
                rows, source = self.runner()
            except Exception:  # noqa: BLE001 - a listing failure must never break the dashboard
                rows, source = [], "error"
            items = build_items(rows)
            self._cached = {"items": items, "count": len(items), "source": source, "cachedAt": _utc_iso()}
            self._stamp = now
            return self._cached
