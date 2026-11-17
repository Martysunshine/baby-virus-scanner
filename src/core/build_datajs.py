#!/usr/bin/env python3
"""build_datajs.py - write the dashboard data files for one scan.

Usage:
    python -I -B src/core/build_datajs.py [--scan <scanDir | scanId>] [--no-aggregate] [--quiet]

Writes <scanDir>/js/<name>.js files of the form
    window.BVS.register("<name>", <json>);
plus manifest.js. Loading data through <script> tags lets dashboard/index.html work from
file:// as well as from src/server/serve.py. Datasets: summary, findings, coverage and, when
present, storage, duplicates, programs, startup, registry, health and a treemap that is split
into lazily loaded chunks (one per top-level folder, deeper splits for very large subtrees).

Python 3 standard library only. Writes only inside the scan's js/ folder and data/latest.js.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from array import array
from pathlib import Path

sys.path.append(os.path.dirname(os.path.abspath(__file__)))  # appended, so the stdlib always wins
import bvs_common as C  # noqa: E402
import aggregate  # noqa: E402

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
TOP_CHILDREN = 200          # keep at least the top 200 children of every expanded folder
THRESHOLD_SHARE = 0.001     # ... and every node of at least 0.1% of used bytes
CHUNK_NODES = 20000         # split a subtree into its own file above this many nodes
MAX_ITEMS_PER_LIST = 20000  # hard cap per storage list (the table is virtualized, but stay sane)

SAFETY_CODE = {s: i for i, s in enumerate(C.SAFETY_LEVELS)}

# Storage inventory key -> dashboard tab. Keys are split into camelCase/snake tokens; the first tab
# (in this priority order) with a matching token wins; otherwise the module default applies.
TAB_PRIORITY = ("duplicates", "registry", "health", "startup", "big", "old", "programs", "junk")
TAB_TOKENS = {
    "duplicates": {"dup", "dups", "duplicate", "duplicates", "copies", "copy", "clone", "clones", "project",
                   "projects", "worktree", "worktrees"},
    "registry": {"registry", "reg", "apppaths", "apppath", "assoc", "associations", "association", "contextmenu",
                 "handlers", "shellext", "ghost", "ghosts", "orphan", "orphans", "orphaned", "wsc",
                 "securitycenter", "path", "env", "environment"},
    "health": {"health", "disk", "disks", "smart", "sfc", "dism", "ntfs", "whea", "reliability", "shortcut",
               "shortcuts", "lnk", "zero", "zerobyte", "partial", "incomplete", "mismatch", "mismatches", "corrupt",
               "damaged", "broken"},
    "startup": {"startup", "autorun", "autoruns", "autostart", "boot", "service", "services", "task", "tasks", "hog",
                "hogs", "cpu", "ram", "memory", "speed", "perf", "performance", "battery", "crash", "crashes"},
    "big": {"big", "large", "largest", "huge", "top", "biggest"},
    "old": {"old", "cold", "stale", "aged", "oldest", "unused"},
    "programs": {"program", "programs", "software", "installed", "apps", "app", "applications", "bloat",
                 "bloatware", "pup", "pups", "uninstall"},
    "junk": {"junk", "cache", "caches", "temp", "tmp", "category", "categories", "clean", "cleanup", "leftover",
             "leftovers", "installer", "installers", "dump", "dumps", "log", "logs", "trash", "recycle", "downloads"},
}
MODULE_DEFAULT_TAB = {"G1": "junk", "G2": "duplicates", "H1": "programs", "H2": "registry"}
TAB_DATASET = {"big": "storage", "old": "storage", "junk": "storage", "duplicates": "duplicates",
               "programs": "programs", "startup": "startup", "registry": "registry", "health": "health"}
DATASET_ORDER = ("storage", "duplicates", "programs", "startup", "registry", "health")

# Treemap "category" colouring folds free-form categories into three families (a treemap is an
# all-pairs form: only three categorical slots stay colour-blind safe), plus "other".
FAMILIES = [
    ("caches", "Caches & temp", re.compile(r"cache|temp|tmp|thumb|crash|dump|wer|prefetch|recycle|trash|shader|log")),
    ("dev", "Dev & build", re.compile(r"dev|node|npm|pnpm|yarn|pip|venv|conda|python|cargo|rust|gradle|maven|nuget|"
                                     r"docker|wsl|vm|virtual|sdk|build|toolchain|package|deps|git")),
    ("installers", "Installers & leftovers", re.compile(r"install|setup|download|leftover|old|update|backup|iso|msi|"
                                                        r"archive|driver")),
]

ITEM_KNOWN = {"id", "path", "kind", "bytes", "files", "newestUtc", "oldestUtc", "category", "purpose", "owner",
              "safety", "method", "how", "reversible", "flags", "gitRisk", "name", "displayName", "title", "size",
              "sizeBytes", "group", "groupSize", "label"}
MEMBER_KEYS = ("items", "files", "copies", "members", "paths", "duplicates", "locations")


# ----------------------------------------------------------------------------- output

def js_literal(obj) -> str:
    """JSON that is safe inside a classic <script>: escape <, >, &, U+2028 and U+2029."""
    text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), allow_nan=False, default=str)
    return (text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def write_dataset(js_dir: Path, name: str, obj) -> int:
    if not NAME_RE.match(name):
        raise ValueError(f"bad dataset name: {name!r}")
    text = f"window.BVS.register({js_literal(name)}, {js_literal(obj)});\n"
    C.write_text_atomic(js_dir / f"{name}.js", text)
    return len(text.encode("utf-8"))


def write_latest_pointer():
    latest = C.DATA_DIR / "latest.txt"
    if not latest.is_file():
        return None
    sid = C.read_text(latest).strip()
    if not C.SCAN_ID_RE.match(sid):
        return None
    C.write_text_atomic(C.DATA_DIR / "latest.js", f"window.BVS_LATEST = {js_literal(sid)};\n")
    return sid


# ----------------------------------------------------------------------------- small helpers

def iso_utc(value):
    epoch = aggregate.parse_time(value)
    if epoch is None:
        return None
    try:
        import datetime as _dt
        return _dt.datetime.fromtimestamp(epoch, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def tokens(key: str):
    parts = [p.lower() for p in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+", str(key))]
    joined = {a + b for a, b in zip(parts, parts[1:])}
    return set(parts) | joined


def tab_for(key: str, module: str) -> str:
    toks = tokens(key)
    for tab in TAB_PRIORITY:
        if toks & TAB_TOKENS[tab]:
            return tab
    return MODULE_DEFAULT_TAB.get(module, "junk")


def norm_safety(value):
    s = re.sub(r"[\s-]+", "_", C.lower_str(value))
    synonyms = {"safe_after_checking": "safe_after_check", "check": "safe_after_check", "usetool": "use_tool",
                "tool": "use_tool", "do_not_delete": "do_not_touch", "donottouch": "do_not_touch",
                "keep": "do_not_touch", "never": "do_not_touch", "system": "do_not_touch"}
    s = synonyms.get(s, s)
    return s if s in SAFETY_CODE else "review"


def norm_method(value, kind, safety):
    m = re.sub(r"[\s-]+", "_", C.lower_str(value))
    synonyms = {"recycle_bin": "recycle", "recyclebin": "recycle", "delete": "recycle", "uninstaller": "uninstall",
                "official_tool": "tool", "registry": "setting", "move": "holding"}
    m = synonyms.get(m, m)
    if safety == "do_not_touch":
        return "none"
    if safety == "use_tool" and m in ("", "recycle", "holding"):
        return "tool"
    if m and re.match(r"^[a-z_]{2,20}$", m):
        return m
    return {"program": "uninstall", "registry": "setting", "setting": "setting"}.get(kind, "recycle")


def basename(path: str) -> str:
    text = str(path or "").rstrip("\\/")
    return re.split(r"[\\/]", text)[-1] if text else ""


def path_key(path: str, case_insensitive: bool) -> str:
    text = str(path or "").rstrip("\\/")
    if len(text) == 2 and text[1] == ":":  # "C:" -> "C:\" root
        text += "\\"
    return text.casefold() if case_insensitive else text


def family_of(category: str):
    c = C.lower_str(category)
    for idx, (_fid, _label, rx) in enumerate(FAMILIES):
        if rx.search(c):
            return idx
    return len(FAMILIES)  # "other"


# ----------------------------------------------------------------------------- storage items

def expand_groups(entries):
    out = []
    for gi, entry in enumerate(entries, 1):
        if isinstance(entry, dict) and not entry.get("path"):
            members, member_key = None, None
            for key in MEMBER_KEYS:
                value = entry.get(key)
                if isinstance(value, list) and value:
                    members, member_key = value, key
                    break
            if members is not None:
                sha = entry.get("sha256") or entry.get("hash")
                gid = str(entry.get("group") or entry.get("groupId") or entry.get("id")
                          or (str(sha)[:12] if sha else f"group-{gi}"))
                info = {k: v for k, v in entry.items() if k not in (member_key, "id")}
                for member in members:
                    if isinstance(member, str):
                        member = {"path": member}
                    if not isinstance(member, dict):
                        continue
                    merged = {**info, **member}
                    merged["group"] = gid
                    merged["groupSize"] = len(members)
                    out.append(merged)
                continue
        out.append(entry)
    return out


def normalize_item(raw, module, key, n):
    if not isinstance(raw, dict):
        return None
    path = str(raw.get("path") or raw.get("fullPath") or raw.get("location") or "")
    kind = C.lower_str(raw.get("kind"), "")
    safety = norm_safety(raw.get("safety"))
    flags = raw.get("flags")
    if isinstance(flags, str):
        flags = [f.strip() for f in flags.split(",") if f.strip()]
    flags = [str(f) for f in C.as_list(flags) if f not in (None, "")]
    git = raw.get("gitRisk") if isinstance(raw.get("gitRisk"), dict) else None
    if git and any((C.to_int(v, 0) or 0) > 0 for v in git.values()) and "work_at_risk" not in flags:
        flags.append("work_at_risk")
    newest = None
    for k in ("newestUtc", "modifiedUtc", "lastWriteUtc", "modified", "lastModified", "lastUsed", "lastUsedUtc",
              "installDate"):
        if raw.get(k) not in (None, ""):
            newest = iso_utc(raw.get(k))
            if newest:
                break
    item_id = str(raw.get("id") or f"{module}-{re.sub(r'[^A-Za-z0-9]+', '', str(key))[:24] or 'item'}-{n:05d}")
    label = str(raw.get("name") or raw.get("displayName") or raw.get("title") or raw.get("label") or basename(path)
                or item_id)
    reversible = raw.get("reversible")
    item = {
        "id": item_id,
        "label": label,
        "path": path,
        "kind": kind or None,
        "bytes": C.to_int(raw.get("bytes", raw.get("size", raw.get("sizeBytes")))),
        "files": C.to_int(raw.get("files")),
        "newest": newest,
        "oldest": iso_utc(raw.get("oldestUtc")),
        "category": str(raw.get("category") or "") or None,
        "purpose": str(raw.get("purpose") or "") or None,
        "owner": str(raw.get("owner") or "") or None,
        "safety": safety,
        "safetyRaw": raw.get("safety") if norm_safety(raw.get("safety")) != C.lower_str(raw.get("safety")) else None,
        "method": norm_method(raw.get("method"), kind, safety),
        "how": str(raw.get("how") or "") or None,
        "reversible": reversible if isinstance(reversible, bool) else None,
        "flags": flags,
        "gitRisk": git,
        "group": str(raw.get("group")) if raw.get("group") is not None else None,
        "groupSize": C.to_int(raw.get("groupSize")),
        "module": module,
        "list": str(key),
        "tabs": [],
        "x": {k: v for k, v in raw.items() if k not in ITEM_KNOWN},
    }
    if item["safetyRaw"] is None:
        del item["safetyRaw"]
    return item


class ItemStore:
    def __init__(self, case_insensitive):
        self.case_insensitive = case_insensitive
        self.items = {}        # id -> item
        self.order = []
        self.facts = {name: [] for name in DATASET_ORDER}
        self.sources = {name: [] for name in DATASET_ORDER}
        self.warnings = []

    def add(self, item, tab):
        existing = self.items.get(item["id"])
        if existing is not None:
            if path_key(existing["path"], self.case_insensitive) == path_key(item["path"], self.case_insensitive):
                if tab not in existing["tabs"]:
                    existing["tabs"].append(tab)
                return
            n = 2
            while f"{item['id']}~{n}" in self.items:
                n += 1
            self.warnings.append(f"duplicate item id {item['id']} with a different path; renamed to {item['id']}~{n}")
            item["id"] = f"{item['id']}~{n}"
        item["tabs"] = [tab]
        self.items[item["id"]] = item
        self.order.append(item["id"])

    def tabs_present(self):
        present = set()
        for item in self.items.values():
            present.update(item["tabs"])
        return present


def collect_storage(envelopes, store: ItemStore):
    for env in envelopes:
        if env["folder"] != "storage":
            continue
        module = env["module"]
        for key, value in env["inventory"].items():
            tab = tab_for(key, module)
            dataset = TAB_DATASET[tab]
            entries = None
            if isinstance(value, list) and value and all(isinstance(v, (dict, str)) for v in value):
                if any(isinstance(v, dict) for v in value):
                    entries = value
            elif isinstance(value, dict) and isinstance(value.get("items"), list):
                entries = value["items"]
                rest = {k: v for k, v in value.items() if k != "items"}
                if rest:
                    store.facts[dataset].append({"module": module, "key": str(key), "value": rest})
            if entries is None:
                store.facts[dataset].append({"module": module, "key": str(key), "value": value})
                continue
            entries = expand_groups(entries)
            if len(entries) > MAX_ITEMS_PER_LIST:
                store.warnings.append(f"{module}.{key}: {len(entries)} entries, kept the first {MAX_ITEMS_PER_LIST}")
                entries = entries[:MAX_ITEMS_PER_LIST]
            count = 0
            for n, raw in enumerate(entries, 1):
                item = normalize_item(raw, module, key, n)
                if item is not None:
                    store.add(item, tab)
                    count += 1
            store.sources[dataset].append({"module": module, "key": str(key), "tab": tab, "count": count})


def read_tsv(path: Path):
    """Yield dicts keyed by lower-case header names. Extra tab-split fields are merged into 'path'."""
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as handle:
        header = [h.strip().lower() for h in handle.readline().rstrip("\r\n").split("\t")]
        width = len(header)
        path_idx = header.index("path") if "path" in header else None
        for line in handle:
            line = line.rstrip("\r\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) > width and path_idx is not None:
                extra = len(parts) - width
                parts[path_idx:path_idx + extra + 1] = ["\t".join(parts[path_idx:path_idx + extra + 1])]
            if len(parts) < width:
                parts += [""] * (width - len(parts))
            yield dict(zip(header, parts))


def files_tsv_fallback(scan_dir: Path, store: ItemStore, ref_epoch):
    """When G1 has not produced big/old/junk lists yet, derive unclassified ones from G0's files.tsv."""
    path = scan_dir / "inventory" / "files.tsv"
    present = store.tabs_present()
    if not path.is_file() or {"big", "old", "junk"} <= present:
        return 0
    large, partial = [], []
    for row in read_tsv(path):
        reason = C.lower_str(row.get("reason"))
        size = C.to_int(row.get("sizebytes"), 0) or 0
        if "large" in reason:
            large.append((size, row))
        if "partial" in reason:
            partial.append((size, row))
    large.sort(key=lambda t: -t[0])
    added = 0
    two_years = 2 * 365.25 * 86400
    for n, (size, row) in enumerate(large[:1000], 1):
        modified = aggregate.parse_time(row.get("modifiedutc"))
        tabs = []
        if "big" not in present:
            tabs.append("big")
        if "old" not in present and modified and ref_epoch and ref_epoch - modified > two_years:
            tabs.append("old")
        if not tabs:
            continue
        item = normalize_item({
            "id": f"g0-big-{n:05d}", "path": row.get("path"), "kind": "file", "bytes": size,
            "newestUtc": row.get("modifiedutc"), "category": "unclassified",
            "purpose": "Large file found by the inventory pass (G0). Not classified yet.",
            "safety": "review", "method": "recycle",
            "how": "Open the containing folder and identify the file before removing it.",
            "reversible": True, "ext": row.get("ext"), "allocBytes": C.to_int(row.get("allocbytes")),
        }, "G0", "files.tsv", n)
        for tab in tabs:
            store.add(dict(item, tabs=[]), tab)
        added += 1
    if "junk" not in present:
        for n, (size, row) in enumerate(sorted(partial, key=lambda t: -t[0])[:1000], 1):
            item = normalize_item({
                "id": f"g0-part-{n:05d}", "path": row.get("path"), "kind": "file", "bytes": size,
                "newestUtc": row.get("modifiedutc"), "category": "partial-download",
                "purpose": "Incomplete browser or tool download.",
                "safety": "safe_after_check", "method": "recycle",
                "how": "Make sure no download is still running (or resume it in the browser), then delete it.",
                "reversible": True,
            }, "G0", "files.tsv", n)
            store.add(item, "junk")
            added += 1
    if added:
        for ds in ("storage",):
            store.sources[ds].append({"module": "G0", "key": "files.tsv", "tab": "big/old/junk", "count": added,
                                      "note": "fallback: unclassified until G1 runs"})
    return added


def reclaimable_stats(items, case_insensitive):
    """Bytes in safe / safe_after_check items, nested paths counted once."""
    picked = []
    for it in items:
        if it["safety"] in ("safe", "safe_after_check") and it["bytes"] and it["path"]:
            picked.append((path_key(it["path"], case_insensitive), it["bytes"], it["safety"]))
    picked.sort(key=lambda t: t[0])
    total = {"safe": 0, "safe_after_check": 0}
    last = None
    for key, size, safety in picked:
        if last and (key == last or key.startswith(last.rstrip("\\/") + "\\") or key.startswith(last.rstrip("/") + "/")):
            continue
        total[safety] += size
        last = key
    return total


# ----------------------------------------------------------------------------- treemap

class DirTable:
    """dirs.tsv in compact parallel arrays (real scans have hundreds of thousands of rows)."""
    NUM = ("ownbytes", "ownfiles", "totalbytes", "totalfiles", "totaldirs", "newestwriteutc", "oldestwriteutc",
           "cold1ybytes", "cold2ybytes", "cold5ybytes", "cloudonlybytes", "cloudonlyfiles")

    def __init__(self, path: Path):
        self.paths, self.flags, self.raw_parent = [], [], []
        self.num = {k: array("q") for k in self.NUM}
        self.present = set()
        ids = {}
        for row in read_tsv(path):
            if not self.present:
                self.present = {k for k in row.keys()}
            idx = len(self.paths)
            rid = row.get("id", str(idx)).strip()
            ids[rid] = idx
            self.raw_parent.append(row.get("parent", "").strip())
            self.paths.append(row.get("path", ""))
            fl = row.get("flags", "").strip()
            self.flags.append(fl or None)
            for k in self.NUM:
                text = row.get(k, "")
                value = C.to_int(text, -1) if k not in ("newestwriteutc", "oldestwriteutc") else self._epoch(text)
                self.num[k].append(-1 if value is None else value)
        self.n = len(self.paths)
        self.parent = array("q", (ids.get(p, -1) if p not in ("", "-1") else -1 for p in self.raw_parent))
        for i in range(self.n):
            if self.parent[i] == i:
                self.parent[i] = -1
        del self.raw_parent
        # CSR children index
        order = sorted((i for i in range(self.n) if self.parent[i] >= 0), key=lambda i: self.parent[i])
        self.child_order = array("q", order)
        self.child_start = array("q", [0]) * (self.n + 1)
        counts = array("q", [0]) * self.n
        for i in order:
            counts[self.parent[i]] += 1
        acc = 0
        for i in range(self.n):
            self.child_start[i] = acc
            acc += counts[i]
        self.child_start[self.n] = acc

    @staticmethod
    def _epoch(text):
        if text is None or str(text).strip() == "":
            return -1
        value = aggregate.parse_time(text)
        return int(value) if value is not None else -1

    def children(self, i):
        return self.child_order[self.child_start[i]:self.child_start[i + 1]]

    def v(self, key, i):
        return self.num[key][i]


def age_bucket(table: DirTable, i, ref_epoch):
    total = table.v("totalbytes", i)
    if total <= 0:
        return -1
    c1, c2, c5 = table.v("cold1ybytes", i), table.v("cold2ybytes", i), table.v("cold5ybytes", i)
    if c1 >= 0 or c2 >= 0 or c5 >= 0:
        half = total / 2.0
        if c5 >= half:
            return 3
        if c2 >= half:
            return 2
        if c1 >= half:
            return 1
        return 0
    newest = table.v("newestwriteutc", i)
    if newest <= 0 or not ref_epoch:
        return -1
    years = (ref_epoch - newest) / (365.25 * 86400)
    return 3 if years >= 5 else 2 if years >= 2 else 1 if years >= 1 else 0


def build_treemap(scan_dir: Path, store: ItemStore, inv_facts, platform, ref_epoch):
    path = scan_dir / "inventory" / "dirs.tsv"
    if not path.is_file():
        return None, {}, ["inventory/dirs.tsv not found: no treemap"]
    warnings = []
    table = DirTable(path)
    if table.n == 0:
        return None, {}, ["inventory/dirs.tsv is empty"]
    case_insensitive = str(platform or "windows").lower() != "linux"
    sep = "/" if (str(platform or "").lower() == "linux" or table.paths[0].startswith("/")) else "\\"

    # classification of folders from storage items (dir items only)
    cats, cat_index, classify = [], {}, {}
    for item in store.items.values():
        if not item["path"] or item["kind"] not in (None, "dir", "folder", "directory"):
            continue
        key = path_key(item["path"], case_insensitive)
        safety = SAFETY_CODE[item["safety"]]
        cat = item["category"]
        ci = None
        if cat:
            if cat not in cat_index:
                cat_index[cat] = len(cats)
                cats.append(cat)
            ci = cat_index[cat]
        prev = classify.get(key)
        if prev:
            safety = max(safety, prev[0])  # the more cautious wins
            ci = prev[1] if prev[1] is not None else ci
        classify[key] = (safety, ci)

    roots = [i for i in range(table.n) if table.parent[i] < 0]
    total_root = sum(max(table.v("totalbytes", r), 0) for r in roots)
    used = inv_facts.get("usedBytes") or total_root
    threshold = max(1, int(used * THRESHOLD_SHARE))
    stats = {"nodes": 0, "matched": 0}

    def base(i, name):
        node = {"n": name, "b": max(table.v("totalbytes", i), 0)}
        tf, td = table.v("totalfiles", i), table.v("totaldirs", i)
        if tf >= 0:
            node["f"] = tf
        if td >= 0:
            node["d"] = td
        newest, oldest = table.v("newestwriteutc", i), table.v("oldestwriteutc", i)
        if newest > 0:
            node["t"] = newest
        if oldest > 0:
            node["o"] = oldest
        node["a"] = age_bucket(table, i, ref_epoch)
        cold = [table.v("cold1ybytes", i), table.v("cold2ybytes", i), table.v("cold5ybytes", i)]
        if any(c > 0 for c in cold):
            node["k3"] = [max(c, 0) for c in cold]
        cloud = table.v("cloudonlybytes", i)
        if cloud > 0:
            node["cl"] = cloud
        if table.flags[i]:
            node["fl"] = table.flags[i]
        hit = classify.get(path_key(table.paths[i], case_insensitive))
        if hit:
            node["s"] = hit[0]
            if hit[1] is not None:
                node["c"] = hit[1]
            stats["matched"] += 1
        stats["nodes"] += 1
        return node

    def name_of(i, parent_path):
        p = table.paths[i]
        if parent_path is not None:
            pp = parent_path
            if (p.casefold().startswith(pp.casefold()) if case_insensitive else p.startswith(pp)) and len(p) > len(pp):
                name = p[len(pp):].lstrip("\\/")
                if name:
                    return name
        return basename(p) or p

    def build(i, parent_path, depth):
        node = base(i, name_of(i, parent_path))
        kids = list(table.children(i))
        if depth > 0 and node["b"] < threshold:
            if kids:
                node["h"] = len(kids)
            return node
        kids.sort(key=lambda k: table.v("totalbytes", k), reverse=True)
        big = sum(1 for k in kids if table.v("totalbytes", k) >= threshold)
        keep = kids[:max(TOP_CHILDREN, big)]
        rest = kids[len(keep):]
        out = []
        my_path = table.paths[i]
        for k in keep:
            if table.v("totalbytes", k) >= threshold:
                out.append(build(k, my_path, depth + 1))
            else:
                leaf = base(k, name_of(k, my_path))
                n_kids = table.child_start[k + 1] - table.child_start[k]
                if n_kids:
                    leaf["h"] = n_kids
                out.append(leaf)
        own_b, own_f = table.v("ownbytes", i), table.v("ownfiles", i)
        if own_b > 0 or own_f > 0:
            out.append({"n": "(files in this folder)", "y": "f", "b": max(own_b, 0), "f": max(own_f, 0)})
        if rest:
            out.append({"n": f"({len(rest)} smaller items)", "y": "m", "m": len(rest),
                        "b": sum(max(table.v("totalbytes", k), 0) for k in rest),
                        "f": sum(max(table.v("totalfiles", k), 0) for k in rest)})
        out.sort(key=lambda c: c["b"], reverse=True)
        node["x"] = out
        return node

    if len(roots) == 1:
        root = build(roots[0], None, 0)
        root_path = table.paths[roots[0]]
    else:
        warnings.append(f"dirs.tsv has {len(roots)} roots; grouped under a synthetic root")
        root = {"n": "(all scanned roots)", "b": total_root, "a": -1,
                "x": sorted((build(r, None, 1) for r in roots), key=lambda c: c["b"], reverse=True)}
        root_path = ""

    # split into lazily loaded chunks: every top-level folder, plus any very large subtree
    chunks = {}
    counter = [0]

    def count(node):
        return 1 + sum(count(c) for c in node.get("x", ()))

    def preview(children):
        out = []
        for c in children:
            p = {k: v for k, v in c.items() if k not in ("x", "k")}
            if "x" in c or "k" in c:
                p["e"] = 1  # expandable once the chunk is loaded
            out.append(p)
        return out

    def split(node, depth):
        for child in node.get("x", ()):
            if "x" not in child:
                continue
            split(child, depth + 1)
            if depth == 0 or count(child) > CHUNK_NODES:
                counter[0] += 1
                name = f"treemap-{counter[0]:04d}"
                chunks[name] = {"x": child["x"]}
                child["k"] = name
                child["x"] = preview(child["x"])
                child["pv"] = 1

    split(root, 0)
    scanned = inv_facts.get("scannedBytes")
    meta = {
        "source": "inventory/dirs.tsv",
        "rootPath": root_path,
        "sep": sep,
        "caseInsensitive": case_insensitive,
        "rows": table.n,
        "nodes": stats["nodes"],
        "classifiedNodes": stats["matched"],
        "usedBytes": used,
        "treemapBytes": root["b"],
        "scannedBytes": scanned,
        "totalMatchesScanned": (scanned is None) or (scanned == root["b"]),
        "unaccountedBytes": inv_facts.get("unaccountedBytes"),
        "threshold": threshold,
        "thresholdRule": f"folders of at least {THRESHOLD_SHARE:.1%} of used bytes are broken down; every expanded "
                         f"folder shows its top {TOP_CHILDREN} children, the rest collapsed into '(n smaller items)'",
        "ageRef": int(ref_epoch) if ref_epoch else None,
        "ageBuckets": ["< 1 year", "1-2 years", "2-5 years", "> 5 years"],
        "safetyLevels": list(C.SAFETY_LEVELS),
        "cats": cats,
        "catFamily": [family_of(c) for c in cats],
        "families": [{"id": fid, "label": label} for fid, label, _ in FAMILIES] + [{"id": "other", "label": "Other classified"}],
        "chunks": len(chunks),
    }
    if scanned is not None and scanned != root["b"]:
        warnings.append(f"treemap total {root['b']} differs from inventory scannedBytes {scanned}")
    return {"meta": meta, "root": root}, chunks, warnings


# ----------------------------------------------------------------------------- main

def build(scan_dir: Path, run_aggregate=True, quiet=False):
    scan_dir = Path(scan_dir)
    if run_aggregate:
        summary = aggregate.build_summary(scan_dir)
        aggregate.write_summary(scan_dir, summary)
    else:
        summary, err = C.load_json(scan_dir / "summary.json")
        if err:
            raise SystemExit(f"error: summary.json: {err} (run without --no-aggregate)")
    platform = summary.get("platform") or "windows"
    case_insensitive = str(platform).lower() != "linux"
    ref_epoch = aggregate.parse_time(summary.get("auditStartUtc")) or aggregate.parse_time(summary.get("generatedAt"))
    js_dir = scan_dir / "js"
    written, warnings = {}, list(summary.get("warnings") or [])

    envelopes, _rv, _un, _pe = aggregate.load_envelopes(scan_dir)
    store = ItemStore(case_insensitive)
    collect_storage(envelopes, store)
    fallback = files_tsv_fallback(scan_dir, store, ref_epoch)
    warnings += store.warnings

    # summary / findings / coverage
    coverage = summary.get("coverage") or {}
    slim = {k: v for k, v in summary.items() if k not in ("findings", "coverage")}
    slim["coverage"] = {k: v for k, v in coverage.items() if k != "checks"}
    slim["coverage"]["checkCount"] = len(coverage.get("checks") or [])
    written["summary"] = write_dataset(js_dir, "summary", slim)
    written["findings"] = write_dataset(js_dir, "findings", {"items": summary.get("findings") or []})
    written["coverage"] = write_dataset(js_dir, "coverage", coverage)

    # guide: curated plain-English layer (headline, why, questions, fixes, stability, highlights)
    # optional curated/derived layers: guide (plain-English), agents (agent map, from src/core/build_agents.py)
    for layer in ("guide", "agents"):
        layer_path = scan_dir / f"{layer}.json"
        if layer_path.is_file():
            try:
                written[layer] = write_dataset(js_dir, layer, json.loads(layer_path.read_text(encoding="utf-8")))
            except (OSError, ValueError) as exc:
                warnings.append(f"{layer}.json not exported: {exc}")

    # storage datasets
    by_dataset = {name: [] for name in DATASET_ORDER}
    for item_id in store.order:
        item = store.items[item_id]
        datasets = {TAB_DATASET[t] for t in item["tabs"]}
        for ds in datasets:
            by_dataset[ds].append(item)
    storage_stats = {}
    for name in DATASET_ORDER:
        items = by_dataset[name]
        if not items and not store.facts[name]:
            continue
        stats = {"items": len(items), "bytes": sum(i["bytes"] or 0 for i in items),
                 "bySafety": {s: sum(1 for i in items if i["safety"] == s) for s in C.SAFETY_LEVELS},
                 "reclaimable": reclaimable_stats(items, case_insensitive)}
        storage_stats[name] = stats
        written[name] = write_dataset(js_dir, name, {"items": items, "facts": store.facts[name],
                                                     "sources": store.sources[name], "stats": stats})

    # treemap
    tm, chunks, tm_warn = build_treemap(scan_dir, store, (coverage.get("inventory") or {}).get("facts") or {},
                                        platform, ref_epoch)
    warnings += tm_warn
    lazy = {}
    if tm:
        written["treemap"] = write_dataset(js_dir, "treemap", tm)
        for name, chunk in chunks.items():
            lazy[name] = write_dataset(js_dir, name, chunk)

    manifest = {
        "schema": "bvs.datajs/1",
        "scanId": summary.get("scanId"),
        "dirId": C.dir_scan_id(scan_dir),
        "generatedAt": C.utc_now_iso(),
        "platform": platform,
        "datasets": [{"name": k, "file": f"{k}.js", "bytes": v} for k, v in written.items()],
        "lazy": [{"name": k, "file": f"{k}.js", "bytes": v} for k, v in lazy.items()],
        "storage": storage_stats,
        "fallbackItems": fallback,
        "warnings": warnings,
    }
    write_dataset(js_dir, "manifest", manifest)
    keep = {f"{k}.js" for k in list(written) + list(lazy) + ["manifest"]}
    removed = 0
    for old in js_dir.glob("*.js"):
        if old.name not in keep and NAME_RE.match(old.stem) and C.is_inside(old, js_dir):
            old.unlink()
            removed += 1
    latest = write_latest_pointer()
    if not quiet:
        print(f"datasets: {js_dir}")
        for k, v in written.items():
            print(f"  {k + '.js':<16} {v:>10,} bytes")
        if lazy:
            print(f"  treemap chunks: {len(lazy)} files, {sum(lazy.values()):,} bytes")
        if tm:
            m = tm["meta"]
            print(f"treemap: {m['rows']:,} dirs -> {m['nodes']:,} nodes; total {m['treemapBytes']:,} B; "
                  f"scanned {m['scannedBytes']}; matches: {m['totalMatchesScanned']}")
        print(f"verdict: {summary.get('verdict')} ({summary.get('verdictSource')})")
        if fallback:
            print(f"fallback items from files.tsv: {fallback}")
        if removed:
            print(f"removed {removed} stale data file(s)")
        if latest:
            print(f"data/latest.js -> {latest}")
        for w in warnings[:15]:
            print(f"warning: {w}")
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build dashboard data files for one scan")
    parser.add_argument("--scan", help="scan directory or scan ID (default: data/latest.txt)")
    parser.add_argument("--no-aggregate", action="store_true", help="use the existing summary.json")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    build(C.resolve_scan_dir(args.scan), run_aggregate=not args.no_aggregate, quiet=args.quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
