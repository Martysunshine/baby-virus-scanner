#!/usr/bin/env python3
"""aggregate.py - merge every envelope of one scan into <scanDir>/summary.json.

Usage:
    python -I -B src/core/aggregate.py [--scan <scanDir | scanId>] [--quiet]

Reads security/, admin/, storage/, inventory/ and verify/ envelopes (bvs.module/1), applies
verification records, scores findings from their reasons, builds coverage and computes the
verdict with the rubric in docs/schema.md. A verdict-override.json in the scan folder
({verdict, rationale, by}) is honoured and recorded as verdictSource "override"; the computed
verdict is kept next to it. AI agents must not write that file (see AGENTS.md).

Python 3 standard library only. Read-only, except for writing summary.json.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.append(os.path.dirname(os.path.abspath(__file__)))  # appended, so the stdlib always wins
import bvs_common as C  # noqa: E402

SCHEMA = "bvs.summary/1"
TOOL_VERSION = "0.1.0"

# docs/schema.md "Score" table. Collectors still choose their own severity.
REASON_POINTS = {
    "persistence": 3,
    "obfuscation": 3,
    "masquerading": 4,
    "invalid_signature": 4,
    "unsigned": 2,
    "user_writable": 2,
    "public_network": 2,
    "created_lt_30d": 1,
    "motw_unknown_host": 1,
    "random_name": 1,
}
INTEL_REASONS = {"intel_match", "av_match"}

AREAS = ("security", "admin", "storage", "inventory", "verify")
EXPECTED_SECURITY = [f"S{n:02d}" for n in range(1, 14)]
STORAGE_MODULES = ["G1", "G2", "H1", "H2"]

ID_KEYS = ("id", "findingId", "finding_id", "finding", "findingRef", "target", "targetId", "target_id", "ref")

VERDICT_MEANING = {
    "COMPROMISED": "A critical compromise finding was confirmed by an independent verifier. Stop: follow the "
                   "incident checklist from a clean device. Nothing is removed without the confirmation protocol.",
    "SUSPICIOUS": "At least one high or critical compromise/suspicious finding is neither refuted nor explained yet. "
                  "Answer the open questions first; the storage clean-up waits until they are resolved.",
    "HARDENING_NEEDED": "No sign of compromise. Some weaknesses are worth fixing (hardening list), including any "
                        "high-severity hardening items such as plaintext credentials.",
    "OK": "No sign of compromise and nothing above low severity.",
}

ACCOUNT_LINKS = [
    {"label": "GitHub security log", "url": "https://github.com/settings/security-log"},
    {"label": "GitHub sessions", "url": "https://github.com/settings/sessions"},
    {"label": "GitHub authorized OAuth apps", "url": "https://github.com/settings/applications"},
    {"label": "Google account security", "url": "https://myaccount.google.com/security"},
    {"label": "Microsoft account security", "url": "https://account.microsoft.com/security"},
    {"label": "Tailscale machines", "url": "https://login.tailscale.com/admin/machines"},
    {"label": "Claude account settings", "url": "https://claude.ai/settings"},
    {"label": "Anthropic Console API keys", "url": "https://console.anthropic.com/settings/keys"},
]


# ----------------------------------------------------------------------------- helpers

def norm_module(value, fallback="?"):
    text = str(value or "").strip()
    if not text:
        return fallback
    text = text.upper() if re.match(r"^[A-Za-z]\d+$", text) else text
    m = re.match(r"^S(\d)$", text)
    return f"S0{m.group(1)}" if m else text


def truthy(value):
    if isinstance(value, str):
        return value.strip().lower() not in ("", "0", "false", "no", "none", "null")
    return bool(value)


_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?)?\s*(Z|[+-]\d{2}:?\d{2})?$",
    re.IGNORECASE,
)
_MSDATE_RE = re.compile(r"^/Date\((-?\d+)([+-]\d{4})?\)/$")


def parse_time(value):
    """ISO-8601 (any fraction length), /Date(ms)/ or epoch seconds/ms -> epoch seconds (float) or None."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        return v / 1000.0 if v > 1e11 else v
    text = str(value).strip()
    if not text:
        return None
    if re.match(r"^-?\d+(\.\d+)?$", text):
        return parse_time(float(text))
    m = _MSDATE_RE.match(text)
    if m:
        return int(m.group(1)) / 1000.0
    m = _ISO_RE.match(text)
    if not m:
        return None
    year, month, day, hh, mm, ss, frac, tz = m.groups()
    try:
        dt = _dt.datetime(int(year), int(month), int(day), int(hh or 0), int(mm or 0), int(ss or 0),
                          int((frac or "0")[:6].ljust(6, "0")), tzinfo=_dt.timezone.utc)
    except ValueError:
        return None
    if tz and tz.upper() != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        offset = sign * (int(digits[:2]) * 3600 + int(digits[2:4]) * 60)
        dt = dt - _dt.timedelta(seconds=offset)
    return dt.timestamp()


def iso_date(epoch):
    if epoch is None:
        return None
    try:
        return _dt.datetime.fromtimestamp(epoch, _dt.timezone.utc).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return None


def norm_key(key):
    return re.sub(r"[^a-z0-9.]", "", str(key).lower())


def flatten(obj, prefix="", depth=0, out=None):
    """Flatten nested dicts into {"a.b.c": value}. Lists are kept as values."""
    if out is None:
        out = {}
    if isinstance(obj, dict) and depth < 4:
        for key, value in obj.items():
            flatten(value, f"{prefix}.{key}" if prefix else str(key), depth + 1, out)
    else:
        out[prefix] = obj
    return out


# ----------------------------------------------------------------------------- loading

def classify_json(obj):
    if isinstance(obj, dict) and (str(obj.get("schema", "")).startswith("bvs.module/") or "checks" in obj or "findings" in obj):
        return "envelope"
    return "other"


def load_envelopes(scan_dir: Path):
    envelopes, raw_verify, unrecognized, parse_errors = [], [], [], []
    for area in AREAS:
        folder = scan_dir / area
        if not folder.is_dir():
            continue
        for path in sorted(folder.glob("*.json")):
            if ".tmp" in path.name:
                continue
            rel = f"{area}/{path.name}"
            if area == "inventory" and path.name.lower() == "inventory-meta.json":
                continue
            obj, err = C.load_json(path)
            if err:
                parse_errors.append({"file": rel, "error": err})
                continue
            if classify_json(obj) == "envelope":
                envelopes.append(normalize_envelope(obj, area, path, rel))
            elif area == "verify":
                raw_verify.append({"file": rel, "data": obj})
            else:
                unrecognized.append({"file": rel, "reason": "not a bvs.module/1 envelope"})
    return envelopes, raw_verify, unrecognized, parse_errors


def normalize_envelope(obj, area, path: Path, rel):
    module = norm_module(obj.get("module"), fallback=path.stem)
    checks = []
    for c in C.as_list(obj.get("checks")):
        if not isinstance(c, dict):
            continue
        status = C.lower_str(c.get("status"), "ok")
        checks.append({
            "id": str(c.get("id") or c.get("check") or "?"),
            "description": str(c.get("description") or ""),
            "status": status if status in C.CHECK_STATUSES else "error",
            "statusRaw": None if status in C.CHECK_STATUSES else c.get("status"),
            "reason": c.get("reason"),
            "items": C.to_int(c.get("items"), 0),
            "ms": C.to_int(c.get("ms"), 0),
        })
    errors = []
    for e in C.as_list(obj.get("errors")):
        if isinstance(e, dict):
            errors.append({"check": e.get("check"), "error": str(e.get("error") or ""), "at": e.get("at")})
        elif e:
            errors.append({"check": None, "error": str(e), "at": None})
    return {
        "module": module,
        "area": C.lower_str(obj.get("area"), area) if area != "verify" else "verify",
        "folder": area,
        "file": rel,
        "schema": obj.get("schema"),
        "host": obj.get("host"),
        "platform": obj.get("platform"),
        "elevated": obj.get("elevated"),
        "started": obj.get("started"),
        "finished": obj.get("finished"),
        "checks": checks,
        "findings": [f for f in C.as_list(obj.get("findings")) if isinstance(f, dict)],
        "inventory": C.as_dict(obj.get("inventory")),
        "errors": errors,
        "raw": obj,
    }


# ----------------------------------------------------------------------------- findings

def normalize_finding(raw, env, index):
    f = dict(raw)
    f["id"] = str(raw.get("id") or f"{env['module']}-X{index:04d}")
    f["module"] = norm_module(raw.get("module"), fallback=env["module"])
    f["area"] = env["folder"]
    f["source"] = env["file"]
    sev = C.lower_str(raw.get("severity"), "info")
    if sev not in C.SEVERITIES:
        f["severityRaw"] = raw.get("severity")
        sev = "info"
    f["severity"] = sev
    cls = C.lower_str(raw.get("class"), "info")
    if cls not in C.CLASSES:
        f["classRaw"] = raw.get("class")
        cls = "info"
    f["class"] = cls
    conf = C.lower_str(raw.get("confidence"), "medium")
    f["confidence"] = conf if conf in ("high", "medium", "low") else "medium"
    f["check"] = str(raw.get("check") or "")
    f["title"] = str(raw.get("title") or f["check"] or f["id"])
    f["reasons"] = [str(r) for r in C.as_list(raw.get("reasons")) if r not in (None, "")]
    f["evidence"] = C.as_list(raw.get("evidence"))
    f["entities"] = C.as_dict(raw.get("entities"))
    f["mitre"] = [str(m) for m in C.as_list(raw.get("mitre")) if m]
    f["fp_notes"] = str(raw.get("fp_notes") or raw.get("fpNotes") or "")
    f["recommendation"] = str(raw.get("recommendation") or "")
    return f


def score_finding(f):
    reasons = {r.strip().lower() for r in f["reasons"]}
    points = {r: REASON_POINTS[r] for r in sorted(reasons) if r in REASON_POINTS}
    score = sum(points.values())
    intel = bool(reasons & INTEL_REASONS)
    if intel or score >= 8:
        band = "critical"
    elif score >= 5:
        band = "high"
    elif score >= 3:
        band = "medium"
    elif score >= 1:
        band = "low"
    else:
        band = "info"
    f["score"] = score
    f["scorePoints"] = points
    f["scoreSeverity"] = band
    f["intelMatch"] = intel


def iter_verification_records(obj, depth=0):
    """Yield dicts that look like verification records: {<id-ish>, result: confirmed|refuted|inconclusive}."""
    if depth > 16:
        return
    if isinstance(obj, dict):
        if C.lower_str(obj.get("result")) in C.VERIFY_RESULTS:
            yield obj
        nested = obj.get("verification")
        if isinstance(nested, dict) and C.lower_str(nested.get("result")) in C.VERIFY_RESULTS:
            rec = dict(nested)
            for key in ID_KEYS:
                if key in obj:
                    rec[key] = obj[key]
                    break
            yield rec
        for key, value in obj.items():
            if key != "verification" and isinstance(value, (dict, list)):
                yield from iter_verification_records(value, depth + 1)
    elif isinstance(obj, list):
        for value in obj:
            yield from iter_verification_records(value, depth + 1)


def normalize_record(rec, source, default_by=None, default_at=None):
    notes = None
    for key in ("notes", "note", "details", "detail", "rationale", "summary", "comment"):
        if rec.get(key):
            notes = str(rec.get(key))
            break
    return {
        "result": C.lower_str(rec.get("result")),
        "method": str(rec.get("method") or rec.get("how") or "") or None,
        "by": str(rec.get("by") or rec.get("verifier") or default_by or "") or None,
        "at": rec.get("at") or rec.get("verifiedAt") or default_at,
        "notes": notes,
        "explained": truthy(rec.get("explained")) or truthy(rec.get("benign")),
        "source": source,
    }


def record_target(rec, by_id, by_id_ci):
    for key in ID_KEYS:
        value = rec.get(key)
        if isinstance(value, str) and value:
            if value in by_id:
                return value
            hit = by_id_ci.get(value.lower())
            if hit:
                return hit
    return None


def combine_verification(records):
    if not records:
        return None
    results = {r["result"] for r in records}
    final = "confirmed" if "confirmed" in results else "refuted" if "refuted" in results else "inconclusive"
    chosen = [r for r in records if r["result"] == final]
    chosen.sort(key=lambda r: (parse_time(r.get("at")) or 0))
    best = dict(chosen[-1])
    best["result"] = final
    if len(results) > 1:
        best["disagreement"] = sorted(results)
    return best


def expected_state(f):
    """(explained, explainedBy, needsUserConfirmation) from the finding's expected match and verifier notes."""
    exp = f.get("expected")
    explained, by, needs_user = False, None, False

    def judge(entry):
        if isinstance(entry, dict) and entry:
            cancelled = False
            for key, value in entry.items():
                kl = key.lower()
                if (kl.startswith("cancel") or kl.startswith("invalidat") or kl in (
                        "invalid", "invalidifhit", "invalidifmatched", "invalidiftriggered", "invalidifmet")) and truthy(value):
                    cancelled = True
            if entry.get("valid") is False or entry.get("matched") is False or entry.get("match") is False:
                cancelled = True
            confirm = truthy(entry.get("confirmWithUser"))
            label = str(entry.get("id") or entry.get("name") or entry.get("reason") or "match")
            return (not cancelled and not confirm), label, (confirm and not cancelled)
        if isinstance(entry, str) and entry.strip():
            return True, entry.strip(), False
        if entry is True:
            return True, "match", False
        return False, None, False

    for entry in (exp if isinstance(exp, list) else [exp]):
        ok, label, confirm = judge(entry)
        if ok:
            explained, by = True, f"expected: {label}"
        if confirm:
            needs_user = True
    for rec in f.get("verifications") or []:
        if rec.get("explained") and rec.get("result") != "confirmed":
            explained, by = True, f"verifier: {rec.get('by') or '?'}"
    return explained, by, needs_user


def merge_findings(envelopes, raw_verify):
    primary = [e for e in envelopes if e["folder"] != "verify"]
    verifiers = [e for e in envelopes if e["folder"] == "verify"]
    findings, by_id = [], {}
    for env in primary:
        for i, raw in enumerate(env["findings"], 1):
            f = normalize_finding(raw, env, i)
            if f["id"] in by_id:  # colliding IDs from different files: keep both, disambiguate
                n = 2
                while f"{f['id']}#{n}" in by_id:
                    n += 1
                f["idOriginal"] = f["id"]
                f["id"] = f"{f['id']}#{n}"
            by_id[f["id"]] = f
            findings.append(f)
    # Verifier envelopes: findings that repeat an existing ID are verification sources only;
    # genuinely new findings (a verifier discovering something) are added.
    for env in verifiers:
        for i, raw in enumerate(env["findings"], 1):
            fid = str(raw.get("id") or "")
            if fid and fid in by_id:
                continue
            f = normalize_finding(raw, env, i)
            if f["id"] in by_id:
                continue
            by_id[f["id"]] = f
            findings.append(f)
    by_id_ci = {k.lower(): k for k in by_id}

    records = {fid: [] for fid in by_id}
    orphans = []
    for f in findings:
        own = f.get("verification")
        if isinstance(own, dict) and C.lower_str(own.get("result")) in C.VERIFY_RESULTS:
            records[f["id"]].append(normalize_record(own, f["source"]))
    sources = [(env["file"], env["raw"], env["module"], env.get("finished")) for env in verifiers]
    sources += [(rv["file"], rv["data"], None, None) for rv in raw_verify]
    for file, data, module, finished in sources:
        seen = set()
        for rec in iter_verification_records(data):
            target = record_target(rec, by_id, by_id_ci)
            norm = normalize_record(rec, file, default_by=module, default_at=finished)
            if target is None:
                orphans.append({"source": file, "ref": next((str(rec.get(k)) for k in ID_KEYS if rec.get(k)), None),
                                "result": norm["result"]})
                continue
            key = (target, norm["result"], norm["by"], str(norm["at"]))
            if key in seen:
                continue
            seen.add(key)
            records[target].append(norm)
    for f in findings:
        recs = records.get(f["id"]) or []
        if recs:
            f["verifications"] = recs
            f["verification"] = combine_verification(recs)
        else:
            f["verification"] = None
        score_finding(f)
        explained, by, needs_user = expected_state(f)
        f["explained"] = explained
        f["explainedBy"] = by
        f["needsUserConfirmation"] = needs_user
    return findings, orphans


def vresult(f):
    v = f.get("verification")
    return v.get("result") if isinstance(v, dict) else None


# ----------------------------------------------------------------------------- verdict

def counts_for(findings):
    by_sev = Counter(f["severity"] for f in findings)
    by_sev_active = Counter(f["severity"] for f in findings if vresult(f) != "refuted")
    by_class = Counter(f["class"] for f in findings)
    by_ver = Counter(vresult(f) or "unverified" for f in findings)
    by_module = {}
    for f in findings:
        m = by_module.setdefault(f["module"], {s: 0 for s in C.SEVERITIES} | {"total": 0, "refuted": 0, "maxScore": 0})
        m[f["severity"]] += 1
        m["total"] += 1
        m["maxScore"] = max(m["maxScore"], f["score"])
        if vresult(f) == "refuted":
            m["refuted"] += 1
    hc = [f for f in findings if f["severity"] in ("critical", "high")]
    return {
        "total": len(findings),
        "bySeverity": {s: by_sev.get(s, 0) for s in C.SEVERITIES},
        "bySeverityActive": {s: by_sev_active.get(s, 0) for s in C.SEVERITIES},
        "byClass": {c: by_class.get(c, 0) for c in C.CLASSES},
        "byVerification": {k: by_ver.get(k, 0) for k in ("confirmed", "refuted", "inconclusive", "unverified")},
        "byModule": dict(sorted(by_module.items())),
        "highCritical": len(hc),
        "highCriticalUnverified": sum(1 for f in hc if vresult(f) is None),
    }


def counts_toward_verdict(f):
    if f["severity"] == "info" or f["class"] == "info":
        return False
    if vresult(f) == "refuted":
        return False
    if f["area"] == "storage" and f["class"] == "hygiene":
        return False  # clean-up items are not security posture
    return True


def compute_verdict(findings):
    def label(f):
        v = vresult(f) or "unverified"
        return f"{f['id']} ({f['severity']} {f['class']}, verification: {v}) - {f['title']}"

    def capped(items, limit=12):
        out = [label(f) for f in items[:limit]]
        if len(items) > limit:
            out.append(f"... and {len(items) - limit} more")
        return out

    order = lambda f: (C.SEV_RANK[f["severity"]], -f["score"], f["id"])  # noqa: E731
    confirmed = sorted([f for f in findings if f["severity"] == "critical" and f["class"] == "compromise"
                        and vresult(f) == "confirmed"], key=order)
    considered = [f for f in findings if counts_toward_verdict(f)]
    # Only compromise/suspicious-class findings can make a machine SUSPICIOUS. A high-severity
    # *hardening* weakness (e.g. a plaintext token) is serious to fix, but it is not a sign of intrusion.
    intrusion_classes = ("compromise", "suspicious")
    open_hc = sorted([f for f in considered if f["severity"] in ("critical", "high") and f["class"] in intrusion_classes
                      and not f["explained"]], key=order)
    hardening_hc = [f for f in considered if f["severity"] in ("critical", "high") and f["class"] not in intrusion_classes
                    and not f["explained"]]
    medium = sorted(hardening_hc + [f for f in considered if f["severity"] == "medium" and not f["explained"]], key=order)
    low = [f for f in considered if f["severity"] == "low" and not f["explained"]]
    pending_crit = [f for f in findings if f["severity"] == "critical" and f["class"] == "compromise"
                    and vresult(f) in (None, "inconclusive")]
    reasons = []
    if confirmed:
        verdict, drivers = "COMPROMISED", confirmed
        reasons.append(f"{len(confirmed)} critical compromise finding(s) confirmed by a verifier:")
        reasons += capped(confirmed)
    elif open_hc:
        verdict, drivers = "SUSPICIOUS", open_hc
        reasons.append(f"{len(open_hc)} high/critical finding(s) are neither refuted nor explained:")
        reasons += capped(open_hc)
    elif medium:
        verdict, drivers = "HARDENING_NEEDED", medium
        reasons.append(f"No unrefuted high/critical compromise or suspicious findings. {len(medium)} hardening/medium item(s) remain "
                       f"({len(hardening_hc)} of them high-severity weaknesses; see the hardening list).")
    else:
        verdict, drivers = "OK", []
        reasons.append("No unrefuted finding above low severity." + (f" {len(low)} low-severity item(s) are listed for reference." if low else ""))
    if pending_crit and verdict != "COMPROMISED":
        reasons.append(f"{len(pending_crit)} critical compromise finding(s) still await a confirmed verification: "
                       + ", ".join(f["id"] for f in pending_crit[:10]))
    refuted_hc = [f for f in findings if f["severity"] in ("critical", "high") and vresult(f) == "refuted"]
    if refuted_hc:
        reasons.append(f"{len(refuted_hc)} high/critical finding(s) were refuted by a verifier and do not count.")
    explained_hc = [f for f in findings if f["severity"] in ("critical", "high") and f["explained"] and vresult(f) != "refuted"]
    if explained_hc:
        reasons.append(f"{len(explained_hc)} high/critical finding(s) are explained by known-good items or verifier notes.")
    return verdict, reasons, [f["id"] for f in drivers]


def compute_confidence(coverage, findings):
    totals = coverage["byStatus"]
    applicable = sum(totals.values()) - totals.get("not_applicable", 0)
    ok = totals.get("ok", 0) + 0.5 * totals.get("partial", 0)
    ratio = (ok / applicable) if applicable else 0.0
    hc = [f for f in findings if f["severity"] in ("critical", "high")]
    verified = (sum(1 for f in hc if vresult(f)) / len(hc)) if hc else 1.0
    missing = len(coverage["missingModules"]["security"])
    if ratio >= 0.9 and verified >= 1.0 and missing == 0:
        level = "high"
    elif ratio >= 0.7 and missing <= 2:
        level = "medium"
    else:
        level = "low"
    return {"level": level, "checkCoverage": round(ratio, 3), "highCriticalVerified": round(verified, 3),
            "missingSecurityModules": missing,
            "rule": "high: >=90% of applicable checks ok, every high/critical finding verified, no security module "
                    "missing; medium: >=70% ok and at most 2 modules missing; otherwise low."}


# ----------------------------------------------------------------------------- coverage

NAME_KEYS = ("log", "logname", "name", "channel", "source", "provider", "id", "key")


def _classify_time_key(key):
    k = norm_key(key)
    if k.startswith("oldest") or k.startswith("first") or k in ("from", "start", "since", "begin", "startutc", "fromutc"):
        return "from"
    if k.startswith("newest") or k.startswith("last") or k in ("to", "end", "until", "endutc", "toutc"):
        return "to"
    return None


def normalize_log_windows(value, module):
    items = []
    if isinstance(value, dict):
        keys = {norm_key(k) for k in value}
        if keys & set(NAME_KEYS) and any(_classify_time_key(k) for k in value):
            items = [value]
        else:
            for k, v in value.items():
                items.append(dict(v, log=v.get("log", k)) if isinstance(v, dict) else {"log": k, "value": v})
    elif isinstance(value, list):
        items = value
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        name, frm, to, events, extra = None, None, None, None, {}
        for k, v in it.items():
            nk = norm_key(k)
            kind = _classify_time_key(k)
            if name is None and nk in NAME_KEYS:
                name = v
            elif kind == "from" and frm is None:
                frm = v
            elif kind == "to" and to is None:
                to = v
            elif events is None and nk in ("events", "count", "records", "total", "eventcount", "recordcount"):
                events = v
            else:
                extra[k] = v
        f_epoch, t_epoch = parse_time(frm), parse_time(to)
        days = round((t_epoch - f_epoch) / 86400.0, 1) if f_epoch and t_epoch and t_epoch >= f_epoch else None
        out.append({"module": module, "log": None if name is None else str(name), "from": frm, "to": to,
                    "fromDate": iso_date(f_epoch), "toDate": iso_date(t_epoch), "days": days,
                    "events": events, "extra": extra})
    return out


def find_log_coverage(envelopes):
    windows = []
    for env in envelopes:
        for key, value in env["inventory"].items():
            if re.sub(r"[^a-z]", "", str(key).lower()) in ("logcoverage", "logwindows", "logcoveragewindows"):
                windows += normalize_log_windows(value, env["module"])
    return windows


INVENTORY_FACTS = {
    "volumeSize": ["volumesize", "volumebytes", "volumetotalbytes", "volumetotal", "volumecapacity", "volume.size",
                   "volume.sizebytes", "volume.totalbytes", "volume.total", "volume.capacity", "volume.bytes",
                   "totalsize", "disksize", "capacity", "size"],
    "volumeFree": ["volumefree", "volumefreebytes", "freebytes", "free", "volume.free", "volume.freebytes",
                   "volume.freespace", "freespace", "sizeremaining", "volume.sizeremaining"],
    "usedBytes": ["usedbytes", "volumeused", "volumeusedbytes", "used", "volume.used", "volume.usedbytes"],
    "scannedBytes": ["scannedbytes", "scanned.bytes", "bytesscanned", "totalbytesscanned", "scanned.totalbytes"],
    "scannedFiles": ["scannedfiles", "scanned.files", "filesscanned", "totalfiles"],
    "scannedDirs": ["scanneddirs", "scanned.dirs", "scanneddirectories", "scanned.directories", "dirsscanned", "totaldirs"],
    "inaccessibleDirs": ["inaccessibledirs", "inaccessibledircount", "inaccessibledirectories", "inaccessible",
                         "scanned.inaccessibledirs"],
    "cloudOnlyBytes": ["cloudonlybytes", "cloudonly", "cloud.bytes", "cloud.cloudonlybytes"],
    "durationSec": ["durationsec", "durationseconds", "duration", "elapsedsec", "elapsedseconds", "seconds"],
    "durationMs": ["durationms", "elapsedms"],
    "unaccountedBytes": ["unaccountedbytes", "unaccounted"],
}


def inventory_facts(scan_dir: Path):
    meta, err = C.load_json(scan_dir / "inventory" / "inventory-meta.json")
    present = (scan_dir / "inventory" / "dirs.tsv").is_file()
    if err and err != "missing":
        return {"present": present, "error": err, "facts": {}, "raw": []}
    if not isinstance(meta, dict):
        return {"present": present, "facts": {}, "raw": []}
    flat = flatten(meta)
    by_norm = {norm_key(k): v for k, v in flat.items()}
    by_last = {}
    for k, v in flat.items():
        by_last.setdefault(norm_key(k.split(".")[-1]), v)
    facts = {}
    for name, candidates in INVENTORY_FACTS.items():
        for cand in candidates:
            value = by_norm.get(cand.replace("_", ""))
            if value is None and "." not in cand:
                value = by_last.get(cand)
            if value is not None and not isinstance(value, (dict, list)):
                number = C.to_int(value)
                if number is not None:
                    facts[name] = number
                    break
    if "durationSec" not in facts and "durationMs" in facts:
        facts["durationSec"] = round(facts["durationMs"] / 1000)
    facts.pop("durationMs", None)
    if "usedBytes" not in facts and "volumeSize" in facts and "volumeFree" in facts:
        facts["usedBytes"] = facts["volumeSize"] - facts["volumeFree"]
    if "unaccountedBytes" not in facts and "usedBytes" in facts and "scannedBytes" in facts:
        facts["unaccountedBytes"] = facts["usedBytes"] - facts["scannedBytes"]
    raw = [{"key": k, "value": v if not isinstance(v, (dict, list)) else C.dump_json(v)[:500]} for k, v in flat.items()]
    return {"present": True, "facts": facts, "raw": raw[:200]}


def build_coverage(envelopes, unrecognized, parse_errors, orphans, scan_dir: Path, findings):
    modules, checks, errors = [], [], []
    totals = Counter()
    for env in envelopes:
        by_status = Counter(c["status"] for c in env["checks"])
        totals.update(by_status)
        modules.append({
            "module": env["module"], "area": env["folder"], "file": env["file"], "schema": env["schema"],
            "platform": env["platform"], "host": env["host"], "elevated": env["elevated"],
            "started": env["started"], "finished": env["finished"],
            "checks": len(env["checks"]), "byStatus": dict(by_status), "errors": len(env["errors"]),
            "findings": sum(1 for f in findings if f["source"] == env["file"]),
            "inventoryKeys": sorted(str(k) for k in env["inventory"].keys())[:60],
        })
        for c in env["checks"]:
            checks.append(dict(c, module=env["module"], area=env["folder"]))
        for e in env["errors"]:
            errors.append(dict(e, module=env["module"]))
    gaps = [c for c in checks if c["status"] not in ("ok", "not_applicable")]
    gap_order = {"error": 0, "needs_admin": 1, "needs_consent": 2, "skipped": 3, "partial": 4}
    gaps.sort(key=lambda c: (gap_order.get(c["status"], 9), c["module"], c["id"]))
    present = {(m["area"], m["module"]) for m in modules}
    present_modules = {m["module"] for m in modules}
    inv = inventory_facts(scan_dir)
    missing = {
        "security": [m for m in EXPECTED_SECURITY if m not in present_modules],
        "admin": [] if any(a == "admin" for a, _ in present) else ["admin checks"],
        "inventory": [] if inv.get("present") or any(a == "inventory" for a, _ in present) else ["G0 inventory"],
        "verify": [] if any(a == "verify" for a, _ in present) or (scan_dir / "verify").is_dir() and any(
            (scan_dir / "verify").glob("*.json")) else ["verifier records"],
        "storage": [m for m in STORAGE_MODULES if m not in present_modules],
    }
    return {
        "modules": modules,
        "checks": checks,
        "gaps": gaps,
        "byStatus": {s: totals.get(s, 0) for s in C.CHECK_STATUSES},
        "logWindows": find_log_coverage(envelopes),
        "missingModules": missing,
        "errors": errors,
        "unrecognizedFiles": unrecognized,
        "parseErrors": parse_errors,
        "orphanVerifications": orphans,
        "inventory": inv,
    }


# ----------------------------------------------------------------------------- tables for the report

def suspicious_files(findings):
    """Files named by compromise/suspicious or high/critical findings. Refuted ones are kept, marked, and sorted last."""
    rows = {}
    for f in findings:
        if not (f["class"] in ("compromise", "suspicious") or f["severity"] in ("critical", "high")):
            continue
        ents = [e for e in C.as_list(C.as_dict(f.get("entities")).get("files")) if isinstance(e, dict) and e.get("path")]
        if not ents:  # fall back to file evidence
            ents = [e for e in f["evidence"] if isinstance(e, dict) and e.get("path")
                    and C.lower_str(e.get("type")) in ("file", "")]
        for ent in ents:
            path = str(ent["path"])
            key = path.lower()
            motw = ent.get("motw") if isinstance(ent.get("motw"), dict) else {}
            facts = {"sig": ent.get("sig") or ent.get("signature"), "signer": ent.get("signer"),
                     "origin": motw.get("host") or motw.get("hostUrl") or motw.get("referrer"), "zone": motw.get("zone"),
                     "sha256": ent.get("sha256"), "size": C.to_int(ent.get("size")), "created": ent.get("created")}
            row = rows.setdefault(key, {"path": path, "findings": [], "reasons": [], "lead": None, **facts})
            row["findings"].append(f["id"])
            for r in f["reasons"]:
                if r not in row["reasons"]:
                    row["reasons"].append(r)
            for k, v in facts.items():
                if row.get(k) in (None, "") and v not in (None, ""):
                    row[k] = v
            # the "lead" finding decides severity/action: active beats refuted, then severity, then score
            rank = (vresult(f) == "refuted", C.SEV_RANK[f["severity"]], -f["score"])
            if row["lead"] is None or rank < row["lead"]:
                row["lead"] = rank
                row.update(severity=f["severity"], score=f["score"], action=f["recommendation"],
                           verification=vresult(f), title=f["title"])
    out = sorted(rows.values(), key=lambda r: (r["lead"], r["path"].lower()))
    for r in out:
        del r["lead"]
    return out


def hardening_list(findings):
    items = [f for f in findings if f["class"] == "hardening" and vresult(f) != "refuted"]
    items.sort(key=lambda f: (C.SEV_RANK[f["severity"]], -f["score"], f["id"]))
    return [{"id": f["id"], "module": f["module"], "severity": f["severity"], "title": f["title"],
             "recommendation": f["recommendation"]} for f in items]


def open_questions(findings):
    out = []
    for f in findings:
        if vresult(f) == "refuted":
            continue
        why = None
        if f["needsUserConfirmation"]:
            why = "Known-good item that must be confirmed by you"
        elif f["severity"] in ("critical", "high") and not f["explained"] and vresult(f) in (None, "inconclusive"):
            why = "High/critical finding without a confirmed or refuted verification"
        if why:
            out.append({"id": f["id"], "module": f["module"], "severity": f["severity"], "title": f["title"],
                        "why": why, "fp_notes": f["fp_notes"], "recommendation": f["recommendation"]})
    out.sort(key=lambda q: (C.SEV_RANK[q["severity"]], q["id"]))
    return out


def honest_limits(platform, log_windows):
    linux = str(platform or "").lower() == "linux"
    examples = [w for w in log_windows if w.get("log") and w.get("fromDate")]
    examples.sort(key=lambda w: w["fromDate"], reverse=True)
    if examples:
        sample = ", ".join(f"{w['log']} from {w['fromDate']}" for w in examples[:3])
        log_text = (f"Log history is limited ({sample}). Older activity cannot be reconstructed, and logs can be "
                    "cleared by an attacker.")
    else:
        log_text = ("Log history is limited: each log only reaches back so far (see the log windows above). Older "
                    "activity cannot be reconstructed, and logs can be cleared by an attacker.")
    return [
        {"id": "kernel", "title": "Kernel rootkits and firmware/UEFI implants",
         "text": "Every check runs in user mode on the live system. A kernel rootkit or a firmware/UEFI implant can "
                 "hide files, processes, registry keys and connections from it, so this scan cannot fully rule them out.",
         "escalation": ("If anything looks off, boot trusted live media and scan the disk offline (for example "
                        "ClamAV and rkhunter run from the live system)." if linux else
                        "If anything looks off, run your antivirus boot-time scan (for example Avast Boot-Time Scan "
                        "set to \"Ask\") or an offline scanner such as Microsoft Defender Offline.")},
        {"id": "router", "title": "The router's own configuration and firmware",
         "text": "The router was observed from the network only. Its configuration and firmware need its admin login.",
         "escalation": "Log in to the router and check: firmware version, admin password changed from the default, "
                       "remote administration off, DNS servers, port forwards and UPnP, DHCP clients, Wi-Fi security "
                       "(WPA2/WPA3) and WPS off."},
        {"id": "cloud", "title": "Cloud accounts without an API",
         "text": "GitHub security log and sessions, Google, Microsoft, the Tailscale admin console and Anthropic "
                 "cannot be fully inspected from this computer.",
         "escalation": "On each account's security page review active sessions and devices, recent sign-ins, "
                       "third-party app grants, tokens and keys, recovery email/phone and two-factor status.",
         "links": ACCOUNT_LINKS},
        {"id": "logs", "title": "Limited log history", "text": log_text,
         "escalation": "Treat the log windows as the period this scan can vouch for."},
        {"id": "absence", "title": "A missing event is not proof",
         "text": "User-mode checks cannot fully rule out a kernel rootkit or a router/firmware compromise, and the "
                 "absence of an event or artifact is not proof of a clean system."},
    ]


def storage_overview(envelopes):
    out = []
    for env in envelopes:
        if env["folder"] != "storage":
            continue
        keys = {}
        for key, value in env["inventory"].items():
            keys[str(key)] = len(value) if isinstance(value, list) else ("object" if isinstance(value, dict) else "value")
        out.append({"module": env["module"], "file": env["file"], "inventory": keys,
                    "findings": len(env["findings"]), "checks": len(env["checks"])})
    return out


# ----------------------------------------------------------------------------- main entry points

def load_override(scan_dir: Path):
    path = scan_dir / "verdict-override.json"
    if not path.is_file():
        return None, None
    obj, err = C.load_json(path)
    if err or not isinstance(obj, dict):
        return None, f"verdict-override.json ignored: {err or 'not an object'}"
    verdict = str(obj.get("verdict") or "").strip().upper().replace(" ", "_")
    if verdict == "HARDENING":
        verdict = "HARDENING_NEEDED"
    if verdict not in C.VERDICTS:
        return None, f"verdict-override.json ignored: unknown verdict {obj.get('verdict')!r}"
    return {"verdict": verdict, "rationale": str(obj.get("rationale") or ""), "by": str(obj.get("by") or ""),
            "at": obj.get("at")}, None


def build_summary(scan_dir: Path, override="auto"):
    """Build the summary dict (does not write). override: "auto" reads verdict-override.json, None disables,
    or pass a dict {verdict, rationale, by}."""
    scan_dir = Path(scan_dir)
    meta, _ = C.load_json(scan_dir / "scan-meta.json")
    meta = meta if isinstance(meta, dict) else {}
    envelopes, raw_verify, unrecognized, parse_errors = load_envelopes(scan_dir)
    findings, orphans = merge_findings(envelopes, raw_verify)
    findings.sort(key=lambda f: (C.SEV_RANK[f["severity"]], -f["score"], f["module"], f["id"]))
    coverage = build_coverage(envelopes, unrecognized, parse_errors, orphans, scan_dir, findings)
    verdict, reasons, drivers = compute_verdict(findings)
    warnings = []
    if override == "auto":
        ov, warn = load_override(scan_dir)
        if warn:
            warnings.append(warn)
    else:
        ov = override
    platform = meta.get("platform") or next((e["platform"] for e in envelopes if e.get("platform")), None)
    summary = {
        "schema": SCHEMA,
        "tool": "baby-virus-scanner",
        "toolVersion": TOOL_VERSION,
        "generatedAt": C.utc_now_iso(),
        "scanId": str(meta.get("scanId") or C.dir_scan_id(scan_dir)),
        "dirId": C.dir_scan_id(scan_dir),
        "host": meta.get("host") or next((e["host"] for e in envelopes if e.get("host")), None),
        "user": meta.get("user"),
        "platform": platform,
        "os": meta.get("os"),
        "elevated": meta.get("elevated"),
        "auditStartUtc": meta.get("auditStartUtc"),
        "verdict": ov["verdict"] if ov else verdict,
        "verdictSource": "override" if ov else "computed",
        "computedVerdict": verdict,
        "verdictMeaning": VERDICT_MEANING[ov["verdict"] if ov else verdict],
        "verdictReasons": reasons,
        "verdictDrivers": drivers,
        "override": ov,
        "rubric": {
            "COMPROMISED": "At least one critical compromise finding with verification.result = confirmed",
            "SUSPICIOUS": "At least one high or critical compromise/suspicious finding that is not refuted and not explained",
            "HARDENING_NEEDED": "Otherwise, at least one unrefuted, unexplained medium finding or high hardening/hygiene finding",
            "OK": "Nothing above low",
            "notes": "Info findings, refuted findings and storage hygiene items never drive the verdict.",
        },
        "counts": counts_for(findings),
        "score": {"max": max((f["score"] for f in findings), default=0),
                  "totalActive": sum(f["score"] for f in findings if vresult(f) != "refuted"),
                  "points": REASON_POINTS,
                  "bands": {"critical": ">=8 or intel_match/av_match", "high": "5-7", "medium": "3-4", "low": "1-2"}},
        "suspiciousFiles": suspicious_files(findings),
        "hardening": hardening_list(findings),
        "questions": open_questions(findings),
        "honestLimits": honest_limits(platform, coverage["logWindows"]),
        "storage": storage_overview(envelopes),
        "warnings": warnings,
        "coverage": coverage,
        "findings": findings,
    }
    summary["confidence"] = compute_confidence(coverage, findings)
    return summary


def write_summary(scan_dir: Path, summary) -> Path:
    return C.write_text_atomic(Path(scan_dir) / "summary.json", C.dump_json(summary, indent=1) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Aggregate one scan into summary.json")
    parser.add_argument("--scan", help="scan directory or scan ID (default: data/latest.txt)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    scan_dir = C.resolve_scan_dir(args.scan)
    summary = build_summary(scan_dir)
    path = write_summary(scan_dir, summary)
    if not args.quiet:
        cov = summary["coverage"]
        sev = summary["counts"]["bySeverityActive"]
        print(f"summary: {path}")
        print(f"verdict: {summary['verdict']} ({summary['verdictSource']}; computed {summary['computedVerdict']}; "
              f"confidence {summary['confidence']['level']})")
        print("active findings: " + ", ".join(f"{k}={v}" for k, v in sev.items()))
        print(f"envelopes: {len(cov['modules'])}, checks: {len(cov['checks'])}, gaps: {len(cov['gaps'])}, "
              f"missing security modules: {', '.join(cov['missingModules']['security']) or 'none'}")
        for w in summary["warnings"]:
            print(f"warning: {w}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
