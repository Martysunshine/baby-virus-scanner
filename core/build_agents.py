#!/usr/bin/env python3
"""build_agents.py - build the "Agent map" data (docs/ui-contract-v3.md section 3).

Usage:
    python -I -B core/build_agents.py [--scan <scanDir | scanId>] [--ledger <file>] [--js <file>] [--quiet]

Reads
  * data/agents-ledger.json  - the main session's record of every AI helper (agent): role, module,
                               tokens, tool calls, duration, status, produced files, notes.
                               null = not measured. This script never invents a number.
  * the produced files       - line counts (how long a script each helper had to write)
  * the module envelopes     - <scan>/{security,storage,inventory,admin}/<module>.json:
                               run time (finished - started), findings and checks
  * <scan>/verify/*.json     - record counts for the verification helper
Writes
  * <scan>/agents.json       - schema bvs.agents/1; core/build_datajs.py exports it as dataset "agents"
  * --js <file> (optional)   - the same data as window.BVS.register("agents", ...) for test pages

Difficulty (contract section 3), measured from tokens / duration:
  extra-high: tokens >= 450k or duration >= 45 min | easy: tokens < 150k and duration < 10 min
  medium: tokens < 350k | hard: tokens < 450k
Without token data it is ESTIMATED from the script lines: < 500 easy, < 1500 medium, < 3000 hard,
otherwise extra-high. With neither, the helper stays ungraded (difficulty null, basis "unknown").

Python 3 standard library only. Read-only towards everything except the two output files, which
must be inside the project folder (bvs_common.write_text_atomic enforces that).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import sys
from pathlib import Path

sys.path.append(os.path.dirname(os.path.abspath(__file__)))  # appended, so the stdlib always wins
import bvs_common as C  # noqa: E402

SCHEMA = "bvs.agents/1"
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_+.-]{0,63}$")
MODULE_RE = re.compile(r"^[A-Z][A-Za-z0-9]{0,7}$")
PRODUCED_RE = re.compile(r"^(?P<path>[^()]+?)\s*(?:\((?P<note>[^()]{1,40})\))?$")
MAX_COUNT_BYTES = 8 * 1024 * 1024      # never line-count anything bigger (it would not be a script)
ENVELOPE_DIRS = ("security", "storage", "inventory", "admin")
VERIFY_DIR = "verify"

TOKENS_EASY, TOKENS_MEDIUM, TOKENS_HARD = 150_000, 350_000, 450_000
SEC_EASY, SEC_XHIGH = 10 * 60, 45 * 60
LINES_EASY, LINES_MEDIUM, LINES_HARD = 500, 1500, 3000

GRADES = ("easy", "medium", "hard", "extra-high")
LEGEND = [
    {"grade": "easy", "label": "Easy", "letter": "E", "color": "#2E9E5B",
     "rule": "Fewer than 150,000 tokens and under 10 minutes",
     "estimatedRule": "Script shorter than 500 lines",
     "plain": "A light job: quick to finish and little reading or writing for the AI."},
    {"grade": "medium", "label": "Medium", "letter": "M", "color": "#E8B400",
     "rule": "Fewer than 350,000 tokens",
     "estimatedRule": "Script of 500 to 1,499 lines",
     "plain": "A normal job: some research, one solid script."},
    {"grade": "hard", "label": "Hard", "letter": "H", "color": "#D63A3A",
     "rule": "Fewer than 450,000 tokens",
     "estimatedRule": "Script of 1,500 to 2,999 lines",
     "plain": "A heavy job: lots of reading, testing and fixing."},
    {"grade": "extra-high", "label": "Extra high", "letter": "X", "color": "#4B1D6B",
     "rule": "450,000 tokens or more, or 45 minutes or longer",
     "estimatedRule": "Script of 3,000 lines or more",
     "plain": "The heaviest jobs: close to what one AI session can hold."},
]
UNGRADED = {"grade": None, "label": "Not measured", "letter": "?", "color": "#98A1B5",
            "rule": "No token count and no script to measure",
            "plain": "The helper's usage was not recorded, so it is not graded."}

STATUS = {
    "done": ("Finished", "It did its job and reported back."),
    "resumed-done": ("Resumed, then finished",
                     "It stopped at the account usage limit, was resumed later and then finished."),
    "stopped-limit": ("Stopped by the usage limit",
                      "The account's usage limit stopped it. The main session took over what was left."),
    "replaced": ("Replaced", "It got stuck, so the main session did this job itself."),
}
KIND = {
    "explore": ("Explorer", "Looks around the PC and the project and reports what it finds."),
    "plan": ("Planner", "Reviews the plan and the design before anything is built."),
    "collector": ("Scan-script author", "Writes one security check script, tests it and runs it."),
    "verifier": ("Double-checker", "Re-checks findings to separate real problems from false alarms."),
    "storage": ("Storage & health author", "Writes the scripts that map disk space, programs and PC health."),
    "ui": ("Dashboard builder", "Builds the pages and tools you are looking at now."),
}
FILE_KIND = {".ps1": "script", ".psm1": "script", ".py": "script", ".js": "script", ".sh": "script",
             ".css": "code", ".html": "code", ".md": "doc", ".json": "config", ".tsv": "data"}
NOT_COUNTED = {
    "v1": "This file was rewritten later (dashboard v2), so its current length is not this helper's work.",
    "input": "This helper gave input to the file; it did not write it.",
}


# ----------------------------------------------------------------------------- small helpers

def clip(value, n=400):
    if value is None:
        return None
    text = str(value).strip()
    return text if len(text) <= n else text[: n - 1] + "\u2026"


def nonneg_int(value):
    v = C.to_int(value)
    return v if v is not None and v >= 0 else None


def fmt_int(n):
    return f"{n:,}"


def fmt_minutes(sec):
    if sec is None:
        return None
    if sec < 90:
        return f"{int(round(sec))} s"
    minutes = int(round(sec / 60))
    return f"{minutes // 60} h {minutes % 60} min" if minutes >= 60 else f"{minutes} min"


def count_lines(path: Path):
    """wc -l, plus a last line without a newline. None if missing, not a file or too big."""
    try:
        if not path.is_file() or path.is_symlink():
            return None
        if path.stat().st_size > MAX_COUNT_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if not raw:
        return 0
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        text = raw.decode("utf-16", errors="replace")
        return text.count("\n") + (0 if text.endswith("\n") else 1)
    return raw.count(b"\n") + (0 if raw.endswith(b"\n") else 1)


ISO_RE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d{1,9})?(Z|[+-]\d\d:\d\d)?$")


def parse_iso(value):
    """'2026-01-01T10:00:00.1234567Z' (.NET writes 7 fraction digits) -> epoch seconds, or None."""
    import datetime as dt
    if not isinstance(value, str):
        return None
    m = ISO_RE.match(value.strip())
    if not m:
        return None
    tz = m.group(3) or "Z"
    try:
        base = dt.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
        offset = dt.timezone.utc if tz == "Z" else dt.datetime.strptime(tz.replace(":", ""), "%z").tzinfo
    except ValueError:
        return None
    return base.replace(tzinfo=offset).timestamp() + (float("0" + m.group(2)) if m.group(2) else 0.0)


# ----------------------------------------------------------------------------- grading

def grade_measured(tokens, dur):
    """Return (grade, reason) from tokens / duration, or (None, None) when they cannot decide."""
    reasons = []
    if tokens is not None and tokens >= TOKENS_HARD:
        reasons.append(f"used {fmt_int(tokens)} tokens (450,000 or more)")
    if dur is not None and dur >= SEC_XHIGH:
        reasons.append(f"worked for {fmt_minutes(dur)} (45 minutes or more)")
    if reasons:
        return "extra-high", "Extra high because it " + " and ".join(reasons) + "."
    if tokens is None:
        return None, None
    if tokens < TOKENS_EASY and (dur is None or dur < SEC_EASY):
        return "easy", f"Easy because it used only {fmt_int(tokens)} tokens" + (
            f" and finished in {fmt_minutes(dur)}." if dur is not None else ".")
    if tokens < TOKENS_MEDIUM:
        if tokens < TOKENS_EASY:
            return "medium", (f"Medium: only {fmt_int(tokens)} tokens, but it worked for {fmt_minutes(dur)} "
                              "(10 minutes or more is at least Medium).")
        return "medium", f"Medium because it used {fmt_int(tokens)} tokens (150,000 to 349,999)."
    return "hard", f"Hard because it used {fmt_int(tokens)} tokens (350,000 to 449,999)."


def grade_lines(lines):
    if lines is None or lines <= 0:
        return None, None
    if lines < LINES_EASY:
        g, band = "easy", "under 500 lines"
    elif lines < LINES_MEDIUM:
        g, band = "medium", "500 to 1,499 lines"
    elif lines < LINES_HARD:
        g, band = "hard", "1,500 to 2,999 lines"
    else:
        g, band = "extra-high", "3,000 lines or more"
    label = next(x["label"] for x in LEGEND if x["grade"] == g)
    return g, (f"Estimated: its token use was not measured, so the length of the script it wrote decides. "
               f"{fmt_int(lines)} lines is {band}, which counts as {label}.")


# ----------------------------------------------------------------------------- inputs

def resolve_produced(entry: str, scan_dir: Path):
    """'dashboard/app.js (v1)' -> (Path or None, display path, note-key)."""
    m = PRODUCED_RE.match(entry.strip())
    if not m:
        return None, clip(entry, 200), None
    shown = m.group("path").strip()
    note = (m.group("note") or "").strip().lower() or None
    rel = shown.replace("<scan>", os.path.relpath(scan_dir, C.ROOT).replace(os.sep, "/"))
    if rel.startswith("/") or re.match(r"^[A-Za-z]:", rel) or ".." in rel.replace("\\", "/").split("/"):
        return None, clip(shown, 200), note
    target = (C.ROOT / rel).resolve()
    if not C.is_inside(target, C.ROOT):
        return None, clip(shown, 200), note
    return target, clip(shown, 200), note


def file_info(entry: str, scan_dir: Path):
    target, shown, note = resolve_produced(entry, scan_dir)
    ext = os.path.splitext(shown or "")[1].lower()
    kind = FILE_KIND.get(ext, "other")
    if kind == "config" and shown and shown.startswith("data/"):
        kind = "data"
    lines = count_lines(target) if target is not None else None
    counted = lines is not None and note not in NOT_COUNTED and kind in ("script", "code")
    info = {"path": shown, "kind": kind, "lines": lines, "exists": lines is not None, "counted": counted}
    if note:
        info["tag"] = note
    if note in NOT_COUNTED:
        info["note"] = NOT_COUNTED[note]
    elif lines is None:
        info["note"] = "File not found in the project, so its length is unknown."
    elif kind not in ("script", "code"):
        info["note"] = {"doc": "A written guide, not a script.", "config": "A settings file, not a script.",
                        "data": "A results file, not a script."}.get(kind, "Not a script.")
    return info


def find_envelope(scan_dir: Path, module: str):
    for sub in ENVELOPE_DIRS:
        path = scan_dir / sub / f"{module}.json"
        if path.is_file():
            return path
    return None


def envelope_info(scan_dir: Path, module_field):
    """Module 'S01' or 'G1+G2' -> combined run seconds / findings / checks, or None."""
    if not isinstance(module_field, str):
        return None
    parts = [p.strip() for p in module_field.split("+") if p.strip()]
    parts = [p for p in parts if MODULE_RE.match(p)]
    if not parts:
        return None
    out = {"modules": [], "runSec": None, "findings": None, "checks": None, "items": None, "checkStatus": {},
           "missing": []}
    for mod in parts:
        path = find_envelope(scan_dir, mod)
        if path is None:
            out["missing"].append(mod)
            continue
        env, err = C.load_json(path)
        if err or not isinstance(env, dict):
            out["missing"].append(mod)
            continue
        start, end = parse_iso(env.get("started")), parse_iso(env.get("finished"))
        run = round(end - start, 1) if start is not None and end is not None and end >= start else None
        findings = len(C.as_list(env.get("findings")))
        checks = C.as_list(env.get("checks"))
        # items the module listed (autostarts, junk folders, programs ...): the lists in its inventory
        items = sum(len(v) for v in C.as_dict(env.get("inventory")).values() if isinstance(v, list))
        status = {}
        for chk in checks:
            st = C.lower_str(C.as_dict(chk).get("status")) or "unknown"
            st = st if st in C.CHECK_STATUSES else "unknown"
            status[st] = status.get(st, 0) + 1
            out["checkStatus"][st] = out["checkStatus"].get(st, 0) + 1
        out["modules"].append({
            "module": mod, "file": os.path.relpath(path, C.ROOT).replace(os.sep, "/"),
            "started": clip(env.get("started"), 40), "finished": clip(env.get("finished"), 40),
            "runSec": run, "findings": findings, "checks": len(checks), "items": items, "checkStatus": status,
            "elevated": bool(env.get("elevated")),
        })
        if run is not None:
            out["runSec"] = round((out["runSec"] or 0) + run, 1)
        out["findings"] = (out["findings"] or 0) + findings
        out["checks"] = (out["checks"] or 0) + len(checks)
        out["items"] = (out["items"] or 0) + items
    return out if out["modules"] or out["missing"] else None


def verify_info(scan_dir: Path, produced):
    """Record counts for verification files listed in 'produced'."""
    out = None
    for f in produced:
        p = f.get("path") or ""
        if f"/{VERIFY_DIR}/" not in p or not p.endswith(".json"):
            continue
        target, _shown, _note = resolve_produced(p, scan_dir)
        if target is None or not target.is_file():
            continue
        doc, err = C.load_json(target)
        if err or not isinstance(doc, dict):
            continue
        records = C.as_list(doc.get("records"))
        res = {}
        for r in records:
            k = C.lower_str(C.as_dict(r).get("result")) or "unknown"
            res[k if k in C.VERIFY_RESULTS else "unknown"] = res.get(k if k in C.VERIFY_RESULTS else "unknown", 0) + 1
        out = out or {"records": 0, "results": {}}
        out["records"] += len(records)
        for k, v in res.items():
            out["results"][k] = out["results"].get(k, 0) + v
    return out


def short_label(agent_id: str, name: str, kind: str) -> str:
    if re.match(r"^(S\d\d|G\d?|H\d?|J|X\d|UI-[A-Z])$", agent_id):
        return agent_id
    base = re.sub(r"^(Explore|Plan|Verification):?\s*", "", name or "").strip()
    if kind == "verifier":
        return "Verify"
    if kind == "plan":
        return "Plan"
    if kind == "explore":
        words, out = base.split(), ""
        for w in words:  # "prior work" -> "Prior work", "environment baseline" -> "Environment"
            if out and len(out) + 1 + len(w) > 12:
                break
            out = f"{out} {w}".strip()
        return (out[:1].upper() + out[1:]) if out else agent_id
    return clip(name or agent_id, 18)


# ----------------------------------------------------------------------------- build

def build(scan_dir: Path, ledger_path: Path):
    ledger, err = C.load_json(ledger_path)
    if err or not isinstance(ledger, dict):
        raise SystemExit(f"error: cannot read the ledger {ledger_path}: {err or 'not an object'}")

    phases = []
    for i, ph in enumerate(C.as_list(ledger.get("phases"))):
        ph = C.as_dict(ph)
        pid = str(ph.get("id") or "")
        if not ID_RE.match(pid):
            continue
        phases.append({"id": pid, "label": clip(ph.get("label") or pid, 60),
                       "order": nonneg_int(ph.get("order")) or i + 1})
    phases.sort(key=lambda p: p["order"])
    phase_ids = {p["id"] for p in phases}

    agents, seen = [], set()
    for raw in C.as_list(ledger.get("agents")):
        raw = C.as_dict(raw)
        aid = str(raw.get("id") or "")
        if not ID_RE.match(aid) or aid in seen:
            continue
        seen.add(aid)
        kind = C.lower_str(raw.get("kind")) or "other"
        phase = str(raw.get("phase") or "")
        if phase not in phase_ids:
            phase = phases[0]["id"] if phases else "other"
        status = C.lower_str(raw.get("status")) or "unknown"
        tokens, tool_uses, dur = nonneg_int(raw.get("tokens")), nonneg_int(raw.get("toolUses")), nonneg_int(raw.get("durationSec"))
        module = raw.get("module") if isinstance(raw.get("module"), str) else None

        files = [file_info(str(p), scan_dir) for p in C.as_list(raw.get("produced")) if isinstance(p, str) and p.strip()]
        counted = [f for f in files if f["counted"]]
        script_lines = sum(f["lines"] for f in counted) if counted else None
        longest = max(counted, key=lambda f: f["lines"]) if counted else None

        grade, reason = grade_measured(tokens, dur)
        basis = "measured" if grade else None
        if not grade:
            grade, reason = grade_lines(script_lines)
            basis = "estimated" if grade else "unknown"
        if not grade:
            reason = ("Not graded: neither its token use nor a script it wrote was recorded. "
                      "The dashboard never guesses a number.")

        env = envelope_info(scan_dir, module)
        ver = verify_info(scan_dir, files) if kind == "verifier" else None
        st_label, st_plain = STATUS.get(status, (status.replace("-", " ").capitalize() or "Unknown", ""))
        kind_label, kind_plain = KIND.get(kind, (kind.capitalize(), ""))
        agents.append({
            "id": aid, "name": clip(raw.get("name") or aid, 80), "short": short_label(aid, str(raw.get("name") or ""), kind),
            "kind": kind, "kindLabel": kind_label, "role": kind_plain,
            "phase": phase, "module": clip(module, 20),
            "status": status, "statusLabel": st_label, "statusPlain": st_plain,
            "tokens": tokens, "toolUses": tool_uses, "durationSec": dur,
            "difficulty": grade, "difficultyBasis": basis, "difficultyReason": reason,
            "scriptLines": script_lines,
            "longestFile": {"path": longest["path"], "lines": longest["lines"]} if longest else None,
            "files": files,
            "runSec": env["runSec"] if env else None,
            "findings": env["findings"] if env else None,
            "checks": env["checks"] if env else None,
            "itemsListed": env["items"] if env else None,
            "checkStatus": env["checkStatus"] if env else None,
            "envelopes": env["modules"] if env else [],
            "envelopesMissing": env["missing"] if env else [],
            "verification": ver,
            "notes": clip(raw.get("notes"), 400) or None,
        })

    # ------------------------------------------------------------------ totals
    def ssum(values):
        vals = [v for v in values if v is not None]
        return sum(vals) if vals else None

    phase_out = []
    for ph in phases:
        members = [a for a in agents if a["phase"] == ph["id"]]
        measured = [a for a in members if a["tokens"] is not None]
        heavy = max(measured, key=lambda a: a["tokens"]) if measured else None
        by_grade = {g: sum(1 for a in members if a["difficulty"] == g) for g in GRADES}
        by_grade["unknown"] = sum(1 for a in members if not a["difficulty"])
        phase_out.append(dict(ph, **{
            "agents": len(members), "measuredAgents": len(measured),
            "tokens": ssum(a["tokens"] for a in members), "toolUses": ssum(a["toolUses"] for a in members),
            "durationSec": ssum(a["durationSec"] for a in members),
            "scriptLines": ssum(a["scriptLines"] for a in members),
            "findings": ssum(a["findings"] for a in members),
            "heaviest": heavy["id"] if heavy else None, "byDifficulty": by_grade,
            "agentIds": [a["id"] for a in members],
        }))

    measured = [a for a in agents if a["tokens"] is not None]
    scan_scripts = [f for a in agents for f in a["files"]
                    if f["counted"] and f["kind"] == "script" and (f["path"] or "").startswith("collectors/")]
    def longest_of(pairs):
        if not pairs:
            return None
        a, f = max(pairs, key=lambda af: af[1]["lines"])
        return {"agent": a["id"], "path": f["path"], "lines": f["lines"]}
    scan_pairs = [(a, f) for a in agents for f in a["files"]
                  if f["counted"] and f["kind"] == "script" and (f["path"] or "").startswith("collectors/")]
    all_pairs = [(a, f) for a in agents for f in a["files"] if f["counted"]]
    runs = [m["runSec"] for a in agents for m in a["envelopes"] if m["runSec"] is not None]
    by_grade = {g: {"measured": 0, "estimated": 0} for g in GRADES}
    for a in agents:
        if a["difficulty"]:
            by_grade[a["difficulty"]][a["difficultyBasis"]] += 1

    totals = {
        "agents": len(agents), "measuredAgents": len(measured), "unmeasuredAgents": len(agents) - len(measured),
        "tokens": ssum(a["tokens"] for a in agents), "toolUses": ssum(a["toolUses"] for a in agents),
        "durationSec": ssum(a["durationSec"] for a in agents),
        "scriptLines": ssum(a["scriptLines"] for a in agents),
        "findings": ssum(a["findings"] for a in agents), "checks": ssum(a["checks"] for a in agents),
        "longestScript": longest_of(scan_pairs),   # the longest scan script (collectors/)
        "longestFile": longest_of(all_pairs),       # the longest code file of any helper
        "scanScripts": len(scan_scripts),
        "typicalScanScriptLines": int(statistics.median(f["lines"] for f in scan_scripts)) if scan_scripts else None,
        "typicalRunSec": round(statistics.median(runs), 1) if runs else None,
        "longestRunSec": max(runs) if runs else None,
        "byDifficulty": by_grade,
        "ungraded": sum(1 for a in agents if not a["difficulty"]),
    }
    heaviest = [{"id": a["id"], "name": a["name"], "tokens": a["tokens"], "durationSec": a["durationSec"],
                 "difficulty": a["difficulty"]}
                for a in sorted(measured, key=lambda a: a["tokens"], reverse=True)[:5]]
    longest_scripts = [{"id": a["id"], "name": a["name"], "scriptLines": a["scriptLines"], "difficulty": a["difficulty"]}
                       for a in sorted((a for a in agents if a["scriptLines"]), key=lambda a: a["scriptLines"], reverse=True)[:5]]

    orch = C.as_dict(ledger.get("orchestrator"))
    return {
        "schema": SCHEMA,
        "generatedAt": C.utc_now_iso(),
        "scanId": C.dir_scan_id(scan_dir),
        "project": clip(ledger.get("project"), 80),
        "source": {"ledger": os.path.relpath(ledger_path, C.ROOT).replace(os.sep, "/"),
                   "ledgerSchema": clip(ledger.get("schema"), 40)},
        "orchestrator": {"id": "main", "name": clip(orch.get("name") or "Claude main session", 80),
                         "model": clip(orch.get("model"), 60), "role": clip(orch.get("role"), 300),
                         "tokens": nonneg_int(orch.get("tokens")), "durationSec": nonneg_int(orch.get("durationSec"))},
        "notes": [clip(n, 400) for n in C.as_list(ledger.get("notes")) if isinstance(n, str)],
        "legend": LEGEND, "ungraded": UNGRADED,
        "rules": {
            "measured": "Measured from the AI's own usage meter: tokens (how much text it read and wrote) and how long it worked.",
            "estimated": "When usage was not measured, the length of the script it wrote is used instead. These grades say 'estimated'.",
            "unknown": "Helpers with neither are shown in grey and are not graded.",
        },
        "phases": phase_out,
        "agents": agents,
        "totals": totals,
        "heaviest": heaviest,
        "longestScripts": longest_scripts,
    }


def js_literal(obj) -> str:
    text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return (text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build <scan>/agents.json for the dashboard's Agent map")
    parser.add_argument("--scan", help="scan directory or scan ID (default: data/latest.txt)")
    parser.add_argument("--ledger", help="agents ledger (default: data/agents-ledger.json)")
    parser.add_argument("--js", help="also write a window.BVS.register('agents', ...) script here (test pages)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    scan_dir = C.resolve_scan_dir(args.scan)
    ledger_path = Path(args.ledger).resolve() if args.ledger else C.DATA_DIR / "agents-ledger.json"
    data = build(scan_dir, ledger_path)
    out = C.write_text_atomic(scan_dir / "agents.json", json.dumps(data, ensure_ascii=False, indent=1) + "\n")
    if args.js:
        C.write_text_atomic(Path(args.js).resolve(), f'window.BVS.register("agents", {js_literal(data)});\n')
    if not args.quiet:
        t = data["totals"]
        print(f"agents.json -> {out}")
        print(f"  {t['agents']} helpers ({t['measuredAgents']} measured), tokens {fmt_int(t['tokens'] or 0)}, "
              f"helper time {fmt_minutes(t['durationSec']) or '-'}, findings {t['findings']}, checks {t['checks']}")
        print(f"  longest script: {t['longestScript']}")
        print(f"  typical scan script {t['typicalScanScriptLines']} lines, typical run {t['typicalRunSec']} s")
        for a in data["agents"]:
            print(f"  {a['id']:<14} {str(a['difficulty']):<11} {str(a['difficultyBasis']):<9} "
                  f"tok={a['tokens']} lines={a['scriptLines']} run={a['runSec']} findings={a['findings']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
