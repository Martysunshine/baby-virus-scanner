#!/usr/bin/env python3
"""Server safety tests (stdlib unittest). Starts its own server on a free port against the
synthetic fixture scan and stops it afterwards. The INFOSEC tests never call the real Claude:
the subprocess server runs with --no-ai, and the success path uses an in-process server whose
subprocess.run is mocked. Signal tests write only into a temporary --state-root, never into
the project's data/signals folder (a live Claude watcher may be listening there).

Run:  python -I -B tests/test_server.py
"""
import hashlib
import http.client
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "demo-scan"
STATIC_ALLOW = "GET, HEAD"
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (FIXTURE / "js" / "manifest.js").is_file():
            subprocess.run([sys.executable, "-I", "-B", str(ROOT / "core" / "build_datajs.py"), "--scan", str(FIXTURE),
                            "--quiet"], check=True)
        cls.state = tempfile.TemporaryDirectory(prefix="bvs-test-state-")
        cls.state_root = Path(cls.state.name)
        cls.proc = subprocess.Popen([sys.executable, "-I", "-B", str(ROOT / "server" / "serve.py"), "--scan", str(FIXTURE),
                                     "--port", "0", "--no-ai", "--state-root", cls.state.name],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        line = cls.proc.stdout.readline()
        if "http://127.0.0.1:" not in line:
            cls.proc.kill()
            raise RuntimeError(f"server did not start: {line!r}")
        cls.port = int(line.split("http://127.0.0.1:")[1].split("/")[0])

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        cls.proc.stdout.close()
        cls.state.cleanup()

    def request(self, method, path, host=None, body=None, headers=()):
        return raw_request(self.port, method, path, host=host, body=body, headers=headers)

    # --- required ----------------------------------------------------------------------------
    def test_get_root_200(self):
        resp, data = self.request("GET", "/")
        self.assertEqual(resp.status, 200)
        self.assertIn(b"<!doctype html>", data[:40].lower())

    def test_traversal_404(self):
        for path in ("/dashboard/../lib/windows/BVS.Common.psm1",
                     "/dashboard/%2e%2e/lib/windows/BVS.Common.psm1",
                     "/dashboard/%2E%2E%2Flib%2Fwindows%2FBVS.Common.psm1",
                     "/dashboard/..%5clib%5cwindows%5cBVS.Common.psm1",
                     "/data/demo-scan/js/../../scan-meta.json",
                     "/data/demo-scan/js/..%2f..%2fscan-meta.json",
                     "//etc/passwd", "/dashboard/", "/data/", "/dashboard/app.js::$DATA", "/dashboard/CON.js"):
            with self.subTest(path=path):
                resp, _ = self.request("GET", path)
                self.assertEqual(resp.status, 404)

    def test_post_405(self):
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            with self.subTest(method=method):
                resp, _ = self.request(method, "/", body=b"x=1")
                self.assertEqual(resp.status, 405)
                self.assertEqual(resp.getheader("Allow"), "GET, HEAD")

    def test_post_static_routes_still_405(self):
        """Only POST /api/ask exists; every other POST (and other methods on /api/ask) stays 405."""
        token = self.status()["token"]
        headers = self.ask_headers(token)
        for method, path in (("POST", "/"), ("POST", "/dashboard/app.js"), ("POST", "/data/latest.js"),
                             ("POST", "/data/demo-scan/js/summary.js"), ("POST", "/api/status"),
                             ("POST", "/api/ask?x=1"), ("POST", "/api/ask/"), ("POST", "/API/ASK"),
                             ("PUT", "/api/ask"), ("DELETE", "/api/ask"), ("OPTIONS", "/api/ask"),
                             ("POST", "/api/signals"), ("POST", "/api/session"), ("POST", "/api/agents/live"),
                             ("POST", "/api/signal/"), ("POST", "/api/signal?x=1"), ("PUT", "/api/signal"),
                             ("OPTIONS", "/api/signal"), ("POST", "/api/chats/"), ("POST", "/api/chats?x=1"),
                             ("PUT", "/api/chats"), ("POST", "/api/chats/cabcdefgh12"),
                             ("DELETE", "/api/chats/cabcdefgh12"), ("DELETE", "/api/chats")):
            with self.subTest(method=method, path=path):
                resp, _ = self.request(method, path, body=b'{"question":"x"}', headers=headers)
                self.assertEqual(resp.status, 405)
                self.assertEqual(resp.getheader("Allow"), STATIC_ALLOW)
        resp, _ = self.request("GET", "/api/ask")
        self.assertEqual((resp.status, resp.getheader("Allow")), (405, "POST"))
        resp, _ = self.request("GET", "/api/signal")
        self.assertEqual((resp.status, resp.getheader("Allow")), (405, "POST"))

    # --- INFOSEC API -------------------------------------------------------------------------
    def status(self):
        resp, data = self.request("GET", "/api/status")
        self.assertEqual(resp.status, 200)
        return json.loads(data)

    def ask_headers(self, token=None, origin=None, ctype="application/json", extra=(), consent="yes"):
        headers = [("Origin", origin or f"http://127.0.0.1:{self.port}")] if origin != "" else []
        if ctype:
            headers.append(("Content-Type", ctype))
        if token:
            headers.append(("X-BVS-Token", token))
        if consent is not None:
            headers.append(("X-BVS-AI-Consent", consent))
        return headers + list(extra)

    def ask(self, headers, body=None, host=None):
        if body is None:
            body = json.dumps({"question": "What is the verdict?", "context": {"view": "#/overview"}}).encode()
        return self.request("POST", "/api/ask", host=host, body=body, headers=headers)

    def test_status_json(self):
        resp, data = self.request("GET", "/api/status")
        self.assertEqual(resp.status, 200)
        self.assertTrue(resp.getheader("Content-Type").startswith("application/json"))
        self.assertIsNone(resp.getheader("Access-Control-Allow-Origin"))
        self.assertEqual(resp.getheader("Content-Security-Policy"), CSP)
        obj = json.loads(data)
        self.assertIs(obj["ai"], False)  # started with --no-ai
        self.assertEqual(obj["reason"], "disabled")
        self.assertGreaterEqual(len(obj["token"]), 32)
        self.assertEqual(obj["token"], self.status()["token"])  # stable for the server's lifetime

    def test_status_refuses_cross_origin(self):
        for headers in ([("Origin", "http://evil.example")], [("Origin", f"http://127.0.0.1:{self.port + 1}")],
                        [("Sec-Fetch-Site", "cross-site")], [("Sec-Fetch-Site", "same-site")]):
            with self.subTest(headers=headers):
                resp, data = self.request("GET", "/api/status", headers=headers)
                self.assertEqual(resp.status, 403)
                self.assertNotIn(b"token", data)
        resp, _ = self.request("GET", "/api/status", host="evil.example")
        self.assertEqual(resp.status, 403)

    def test_ask_without_or_with_wrong_token_403(self):
        for token in (None, "", "wrong", self.status()["token"] + "x"):
            with self.subTest(token=token):
                resp, data = self.ask(self.ask_headers(token))
                self.assertEqual(resp.status, 403)
                self.assertEqual(json.loads(data)["error"], "forbidden")

    def test_ask_wrong_origin_403(self):
        token = self.status()["token"]
        for origin in ("", "null", "http://evil.example", f"http://evil.example:{self.port}",
                       f"http://127.0.0.1:{self.port + 1}", f"https://127.0.0.1:{self.port}", "http://127.0.0.1",
                       f"http://localhost.evil.example:{self.port}"):
            with self.subTest(origin=origin):
                resp, _ = self.ask(self.ask_headers(token, origin=origin))
                self.assertEqual(resp.status, 403)
        resp, _ = self.ask(self.ask_headers(token, extra=[("Origin", "http://evil.example")]))  # two Origins
        self.assertEqual(resp.status, 403)

    def test_ask_bad_host_or_cross_site_403(self):
        token = self.status()["token"]
        resp, _ = self.ask(self.ask_headers(token), host="evil.example")
        self.assertEqual(resp.status, 403)
        for site in ("cross-site", "same-site"):
            with self.subTest(site=site):
                resp, _ = self.ask(self.ask_headers(token, extra=[("Sec-Fetch-Site", site)]))
                self.assertEqual(resp.status, 403)

    def test_ask_bad_content_type_415(self):
        token = self.status()["token"]
        for ctype in (None, "text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x",
                      "application/jsonx", "text/json"):
            with self.subTest(ctype=ctype):
                resp, data = self.ask(self.ask_headers(token, ctype=ctype))
                self.assertEqual(resp.status, 415)
                self.assertEqual(json.loads(data)["error"], "unsupported_media_type")

    def test_ask_oversize_413(self):
        token = self.status()["token"]
        big = json.dumps({"question": "x" * (64 * 1024 + 10)}).encode()
        resp, data = self.ask(self.ask_headers(token), body=big)
        self.assertEqual(resp.status, 413)
        self.assertEqual(json.loads(data)["error"], "too_large")

    def test_ask_bad_body_400(self):
        token = self.status()["token"]
        for body in (b"not json", b"\xff\xfe", b"[]", b'{"question": 5}', b'{"question": ""}',
                     b'{"question": "x", "preset": "rm -rf"}', b'{"question": "x", "context": []}',
                     b'{"question": "x", "context": {"entities": [{"type": "evil", "id": "1"}]}}',
                     b'{"question": "x", "context": {"history": [{"role": "system", "text": "hi"}]}}'):
            with self.subTest(body=body):
                resp, data = self.ask(self.ask_headers(token), body=body)
                self.assertEqual(resp.status, 400)
                self.assertEqual(json.loads(data)["error"], "bad_request")

    def test_ask_valid_but_ai_off_503(self):
        token = self.status()["token"]
        resp, data = self.ask(self.ask_headers(token, origin=f"http://localhost:{self.port}"),
                              host=f"localhost:{self.port}")
        self.assertEqual(resp.status, 503)
        self.assertEqual(json.loads(data)["error"], "ai_off")
        self.assertIsNone(resp.getheader("Access-Control-Allow-Origin"))

    def test_api_logs_no_prompt_text(self):
        token = self.status()["token"]
        marker = "ZZ-unique-marker-7f3a"
        self.ask(self.ask_headers(token), body=json.dumps({"question": marker}).encode())
        log = (ROOT / "logs" / "server.log").read_text(encoding="utf-8", errors="replace")
        self.assertIn("ai ask status=503", log)
        self.assertNotIn(marker, log)

    def test_bad_host_403(self):
        for host in ("evil.example", f"evil.example:{self.port}", "127.0.0.1", f"127.0.0.1:{self.port + 1}", ""):
            with self.subTest(host=host):
                resp, _ = self.request("GET", "/", host=host)
                self.assertEqual(resp.status, 403)

    def test_csp_and_hardening_headers(self):
        for path in ("/", "/dashboard/app.js", "/nope"):
            with self.subTest(path=path):
                resp, _ = self.request("GET", path)
                self.assertEqual(resp.getheader("Content-Security-Policy"), CSP)
                self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")
                self.assertEqual(resp.getheader("Referrer-Policy"), "no-referrer")
                self.assertEqual(resp.getheader("Cache-Control"), "no-store")
                self.assertIsNone(resp.getheader("Access-Control-Allow-Origin"))

    # --- AI consent (v3) ---------------------------------------------------------------------
    def test_ask_requires_consent_header(self):
        token = self.status()["token"]
        for consent in (None, "", "no", "true", "yes please"):
            with self.subTest(consent=consent):
                resp, data = self.ask(self.ask_headers(token, consent=consent))
                self.assertEqual(resp.status, 403)
                self.assertEqual(json.loads(data)["error"], "consent_required")
        resp, _ = self.ask(self.ask_headers(token, extra=[("X-BVS-AI-Consent", "yes")]))  # sent twice
        self.assertEqual(resp.status, 403)
        resp, data = self.ask(self.ask_headers(token, consent="yes"))
        self.assertEqual((resp.status, json.loads(data)["error"]), (503, "ai_off"))  # consent ok, AI switched off

    # --- signal bus (v3) ---------------------------------------------------------------------
    def signal_headers(self, token, origin=None, ctype="application/json", extra=()):
        return self.ask_headers(token, origin=origin, ctype=ctype, extra=extra, consent=None)

    def post_signal(self, body, headers=None, host=None):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        return self.request("POST", "/api/signal", host=host, body=raw,
                            headers=headers if headers is not None else self.signal_headers(self.status()["token"]))

    def api_get(self, path, token=None, extra=()):
        headers = ([("X-BVS-Token", token)] if token else []) + list(extra)
        return self.request("GET", path, headers=headers)

    @staticmethod
    def delete_body(n=2, typed="I confirm"):
        items = [{"id": f"g1-{i:05d}", "path": f"C:\\Users\\tester\\Downloads\\old-{i}.zip", "bytes": 1000 + i,
                  "method": "recycle", "label": f"old-{i}.zip"} for i in range(n)]
        body = {"type": "delete-request", "payload": {"items": items}}
        if typed is not None:
            body["typedConfirmation"] = typed
        return body

    def test_signal_auth_origin_token(self):
        token = self.status()["token"]
        body = {"type": "refresh-report", "payload": {}}
        inbox = self.state_root / "signals" / "inbox"
        before = set(inbox.glob("*")) if inbox.is_dir() else set()
        for headers in (self.signal_headers(None), self.signal_headers("wrong"), self.signal_headers(token + "x"),
                        self.signal_headers(token, origin=""), self.signal_headers(token, origin="http://evil.example"),
                        self.signal_headers(token, origin=f"http://127.0.0.1:{self.port + 1}"),
                        self.signal_headers(token, extra=[("Sec-Fetch-Site", "cross-site")]),
                        self.signal_headers(token, extra=[("Origin", "http://evil.example")])):
            with self.subTest(headers=headers):
                resp, data = self.post_signal(body, headers=headers)
                self.assertEqual(resp.status, 403)
                self.assertEqual(json.loads(data)["error"], "forbidden")
        resp, _ = self.post_signal(body, headers=self.signal_headers(token), host="evil.example")
        self.assertEqual(resp.status, 403)
        resp, data = self.post_signal(body, headers=self.signal_headers(token, ctype="text/plain"))
        self.assertEqual((resp.status, json.loads(data)["error"]), (415, "unsupported_media_type"))
        resp, data = self.post_signal(b"{" + b" " * (64 * 1024) + b"}", headers=self.signal_headers(token))
        self.assertEqual((resp.status, json.loads(data)["error"]), (413, "too_large"))
        resp, data = self.post_signal(b"not json", headers=self.signal_headers(token))
        self.assertEqual(resp.status, 400)
        after = set(inbox.glob("*")) if inbox.is_dir() else set()
        self.assertEqual(after, before)  # nothing was queued by a refused request

    def test_signal_schema_strict(self):
        long_path = "C:\\Users\\tester\\" + "a" * 1100
        ok_item = {"id": "g1-00001", "path": "C:\\x\\y.zip", "bytes": 1, "method": "recycle", "label": "y.zip"}
        bad = [
            [], "x", {"type": "format-disk"}, {"type": "run-admin", "payload": {"x": 1}},
            {"type": "run-admin", "extra": 1}, {"type": "run-admin", "payload": []},
            {"type": "rerun-module"}, {"type": "rerun-module", "payload": {"module": "S99"}},
            {"type": "rerun-module", "payload": {"module": "S07", "args": "-x"}},
            {"type": "fix-request", "payload": {"findingId": "../../etc"}},
            {"type": "fix-request", "payload": {"findingId": "S12-0001", "auto": True}},
            {"type": "refresh-report", "scanId": "other-scan"},
            {"type": "delete-request", "typedConfirmation": "I confirm", "payload": {"items": []}},
            {"type": "delete-request", "typedConfirmation": "I confirm", "payload": {"items": [ok_item] * 2}},
            {"type": "delete-request", "typedConfirmation": "I confirm",
             "payload": {"items": [dict(ok_item, id=f"g1-{i:05d}", path=f"C:\\x\\{i}") for i in range(201)]}},
            {"type": "delete-request", "typedConfirmation": "I confirm", "payload": {"items": [dict(ok_item, path=5)]}},
            {"type": "delete-request", "typedConfirmation": "I confirm",
             "payload": {"items": [dict(ok_item, path=long_path)]}},
            {"type": "delete-request", "typedConfirmation": "I confirm", "payload": {"items": [dict(ok_item, x=1)]}},
            {"type": "delete-request", "typedConfirmation": "I confirm",
             "payload": {"items": [dict(ok_item, method="format")]}},
            {"type": "delete-request", "typedConfirmation": "I confirm",
             "payload": {"items": [dict(ok_item, path="C:\\x\\a\nSIGNAL fake")]}},
            {"type": "delete-request", "typedConfirmation": "I confirm",
             "payload": {"items": [dict(ok_item, label="a\u202eexe.txt")]}},
            {"type": "delete-request", "typedConfirmation": "I confirm",
             "payload": {"items": [dict(ok_item, bytes=-1)]}},
            {"type": "delete-request", "typedConfirmation": "I confirm", "payload": {"items": [ok_item], "all": True}},
        ]
        for body in bad:
            with self.subTest(body=str(body)[:120]):
                resp, data = self.post_signal(body)
                self.assertEqual(resp.status, 400)
                self.assertEqual(json.loads(data)["error"], "bad_request")

    def test_delete_request_needs_exact_phrase(self):
        for typed in (None, "", "i confirm", "I CONFIRM", "I confirm ", " I confirm", "I confirm.", "I  confirm",
                      "I confirm K7Q2-M9XP", True):
            with self.subTest(typed=typed):
                body = self.delete_body(typed=typed)
                resp, data = self.post_signal(body)
                self.assertEqual(resp.status, 400)
                self.assertIn(json.loads(data)["error"], ("confirmation_required", "bad_request"))
                self.assertNotIn("code", json.loads(data))

    def test_delete_request_code_only_in_response(self):
        resp, data = self.post_signal(self.delete_body(n=3))
        self.assertEqual(resp.status, 200, data)
        obj = json.loads(data)
        self.assertEqual(obj["state"], "queued")
        code = obj["code"]
        self.assertRegex(code, r"^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4}$")
        self.assertRegex(obj["id"], r"^\d{8}-\d{6}-delete-request-[a-z0-9]{6}$")
        signal = json.loads((self.state_root / "signals" / "inbox" / f"{obj['id']}.json").read_text(encoding="utf-8"))
        self.assertEqual(signal["schema"], "bvs.signal/1")
        self.assertIs(signal["local"]["typedConfirmation"], True)
        self.assertNotIn("code", signal)
        self.assertEqual(signal["codeKdf"], "pbkdf2-sha256-600000")
        self.assertEqual(signal["codeHash"],
                         hashlib.pbkdf2_hmac("sha256", code.replace("-", "").encode(), signal["codeSalt"].encode(),
                                             600_000, 32).hex())
        self.assertEqual(len(signal["payload"]["items"]), 3)
        bare = code.replace("-", "")
        # the code is in no file: not in the signal/status files, not in the server log
        files = [p for p in self.state_root.rglob("*") if p.is_file()] + [ROOT / "logs" / "server.log"]
        for path in files:
            text = path.read_text(encoding="utf-8", errors="replace")
            self.assertNotIn(code, text, path)
            self.assertNotIn(bare, text, path)
        # and never in /api/signals
        resp, data = self.api_get("/api/signals", token=self.status()["token"])
        self.assertEqual(resp.status, 200)
        listing = json.loads(data)
        entry = next(s for s in listing["items"] if s["id"] == obj["id"])
        self.assertEqual((entry["state"], entry["type"], entry["summary"]["items"]), ("queued", "delete-request", 3))
        self.assertIs(entry["confirmedInBrowser"], True)
        for needle in (code, bare, signal["codeHash"], signal["codeSalt"], "codeHash", "codeSalt", '"code"'):
            self.assertNotIn(needle.encode(), data)
        self.assertLessEqual(len(listing["items"]), 30)

    def test_other_signals_queue_without_code(self):
        for body in ({"type": "run-admin"}, {"type": "run-github-check", "payload": {}},
                     {"type": "rerun-module", "payload": {"module": "S07"}},
                     {"type": "fix-request", "payload": {"findingId": "S12-0001"}},
                     {"type": "refresh-report", "payload": {}, "scanId": "demo-scan"}):
            with self.subTest(body=body):
                resp, data = self.post_signal(body)
                self.assertEqual(resp.status, 200, data)
                obj = json.loads(data)
                self.assertNotIn("code", obj)
                status = json.loads((self.state_root / "signals" / "status" / f"{obj['id']}.json").read_text())
                self.assertEqual(status["state"], "queued")

    def test_signal_get_routes_need_token(self):
        token = self.status()["token"]
        for path in ("/api/signals", "/api/session", "/api/agents/live"):
            with self.subTest(path=path):
                for tok, extra in ((None, ()), ("wrong", ()), (token, [("Origin", "http://evil.example")]),
                                   (token, [("Sec-Fetch-Site", "cross-site")])):
                    resp, data = self.api_get(path, token=tok, extra=extra)
                    self.assertEqual(resp.status, 403)
                    self.assertIsNone(resp.getheader("Access-Control-Allow-Origin"))
                resp, _ = self.request("GET", path, host="evil.example", headers=[("X-BVS-Token", token)])
                self.assertEqual(resp.status, 403)

    def test_session_heartbeat(self):
        token = self.status()["token"]
        beat = self.state_root / "session" / "heartbeat.json"
        beat.parent.mkdir(parents=True, exist_ok=True)
        if beat.exists():
            beat.unlink()
        resp, data = self.api_get("/api/session", token=token)
        self.assertEqual(resp.status, 200)
        self.assertIs(json.loads(data)["connected"], False)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        beat.write_text(json.dumps({"pid": 4242, "startedAt": now, "beatAt": now}), encoding="utf-8")
        obj = json.loads(self.api_get("/api/session", token=token)[1])
        self.assertEqual((obj["connected"], obj["pid"]), (True, 4242))
        old = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 60))
        beat.write_text(json.dumps({"pid": 4242, "startedAt": old, "beatAt": old}), encoding="utf-8")
        self.assertIs(json.loads(self.api_get("/api/session", token=token)[1])["connected"], False)

    def test_agents_live_route(self):
        resp, data = self.api_get("/api/agents/live", token=self.status()["token"])
        self.assertEqual(resp.status, 200)
        obj = json.loads(data)
        self.assertIsInstance(obj["items"], list)
        self.assertIn(obj["source"], ("cim", "tasklist", "unsupported", "error"))
        for item in obj["items"]:
            self.assertEqual(set(item), {"name", "kind", "pid", "started", "exe", "command", "commandAvailable"})
            self.assertLessEqual(len(item["command"].split()), 4)  # exe + at most 3 flag names

    # --- extras ------------------------------------------------------------------------------
    def test_static_allowlist_has_v3_files(self):
        serve = load_serve_module()
        self.assertIn("agents-view.js", serve.DASHBOARD_FILES)
        self.assertIn("agents.css", serve.DASHBOARD_FILES)
        for name in ("agents-view.js", "agents.css"):
            resp, _ = self.request("GET", f"/dashboard/{name}")
            self.assertEqual(resp.status, 200 if (ROOT / "dashboard" / name).is_file() else 404)

    def test_assets_route(self):
        """dashboard/assets: images only, one flat folder, same security headers as everything else."""
        resp, data = self.request("GET", "/dashboard/assets/logo-mark.svg")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Content-Type"), "image/svg+xml")
        self.assertEqual(resp.getheader("Content-Security-Policy"), CSP)
        self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.getheader("Cache-Control"), "no-store")
        self.assertIn(b"<svg", data[:200])
        resp, data = self.request("HEAD", "/dashboard/assets/logo.svg")
        self.assertEqual((resp.status, data), (200, b""))
        serve = load_serve_module()
        self.assertEqual((serve.CONTENT_TYPES[".png"], serve.CONTENT_TYPES[".webp"], serve.CONTENT_TYPES[".jpg"]),
                         ("image/png", "image/webp", "image/jpeg"))
        # optional AI art: served as image/png when present (a missing slot image is a plain 404 and the
        # dashboard keeps its built-in fallback)
        for name in ("logo-mark.png", "hero-shield.png", "storage-core.png", "agent-core.png", "bg-nebula.png"):
            with self.subTest(name=name):
                resp, data = self.request("GET", f"/dashboard/assets/{name}")
                if (ROOT / "dashboard" / "assets" / name).is_file():
                    self.assertEqual(resp.status, 200)
                    self.assertEqual(resp.getheader("Content-Type"), "image/png")
                    self.assertEqual(resp.getheader("Content-Security-Policy"), CSP)
                    self.assertTrue(data.startswith(b"\x89PNG\r\n\x1a\n"))
                else:
                    self.assertEqual(resp.status, 404)
        resp, _ = self.request("GET", "/dashboard/assets/hero-shield-missing.webp")
        self.assertEqual(resp.status, 404)

    def test_assets_traversal_404(self):
        for path in ("/dashboard/assets/../app.js", "/dashboard/assets/..%2fapp.js", "/dashboard/assets/%2e%2e/index.html",
                     "/dashboard/assets/..\\style.css", "/dashboard/assets/../../server/serve.py",
                     "/dashboard/assets/sub/logo.svg", "/dashboard/assets/", "/dashboard/assets",
                     "/dashboard/assets/.logo.svg", "/dashboard/assets/logo.svg/", "/dashboard/assets/logo.svg::$DATA",
                     "/dashboard/assets/CON.svg", "/dashboard/assets/nul.png", "/dashboard/assets//logo.svg",
                     "/dashboard/assets/C:logo.svg", "/dashboard/assets/logo%2esvg"):
            with self.subTest(path=path):
                resp, _ = self.request("GET", path)
                self.assertEqual(resp.status, 404)

    def test_assets_bad_extension_404(self):
        for path in ("/dashboard/assets/logo.svgz", "/dashboard/assets/logo.SVG", "/dashboard/assets/logo.html",
                     "/dashboard/assets/logo.js", "/dashboard/assets/logo.css", "/dashboard/assets/logo.gif",
                     "/dashboard/assets/logo.jpeg", "/dashboard/assets/logo.svg.js", "/dashboard/assets/logo.json",
                     "/dashboard/assets/logo", "/dashboard/assets/logo.mark.svg"):
            with self.subTest(path=path):
                resp, _ = self.request("GET", path)
                self.assertEqual(resp.status, 404)

    def test_localhost_head_and_data_routes(self):
        resp, data = self.request("HEAD", "/", host=f"localhost:{self.port}")
        self.assertEqual((resp.status, data), (200, b""))
        resp, data = self.request("GET", "/data/demo-scan/js/summary.js")
        self.assertEqual(resp.status, 200)
        self.assertTrue(data.startswith(b'window.BVS.register("summary"'))
        self.assertNotIn(b"<img", data)  # hostile names arrive escaped as <
        resp, data = self.request("GET", "/data/latest.js")
        self.assertEqual(data, b'window.BVS_LATEST = "demo-scan";\n')
        resp, _ = self.request("GET", "/data/other-scan/js/summary.js")
        self.assertEqual(resp.status, 404)

    def test_not_reachable_on_lan_address(self):
        try:
            addrs = {a for a in socket.gethostbyname_ex(socket.gethostname())[2] if not a.startswith("127.")}
        except OSError:
            addrs = set()
        if not addrs:
            self.skipTest("no non-loopback IPv4 address")
        for addr in addrs:
            with self.subTest(addr=addr):
                with self.assertRaises(OSError):
                    socket.create_connection((addr, self.port), timeout=2).close()


def raw_request(port, method, path, host=None, body=None, headers=()):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    if host != "":
        conn.putheader("Host", host or f"127.0.0.1:{port}")
    for key, value in headers:
        conn.putheader(key, value)
    if body is not None:
        conn.putheader("Content-Length", str(len(body)))
    conn.endheaders(body)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp, data


def load_serve_module():
    spec = importlib.util.spec_from_file_location("bvs_serve_under_test", ROOT / "server" / "serve.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InfosecSuccessPathTests(unittest.TestCase):
    """In-process server with subprocess.run mocked: proves the full POST /api/ask path and the exact,
    locked-down Claude command line without making a real AI call."""

    @classmethod
    def setUpClass(cls):
        cls.serve = load_serve_module()
        cls.bridge_mod = cls.serve.ai_bridge
        cls.sandbox = tempfile.TemporaryDirectory()
        cls.bridge = cls.bridge_mod.AIBridge(FIXTURE, claude_path=sys.executable, model="haiku",
                                             sandbox_dir=cls.sandbox.name)
        cls.server = cls.serve.DashboardServer(0, FIXTURE, "demo-scan", ai=cls.bridge)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.sandbox.cleanup()

    def setUp(self):
        self.bridge._recent.clear()

    def token(self):
        resp, data = raw_request(self.port, "GET", "/api/status")
        obj = json.loads(data)
        self.assertEqual(resp.status, 200)
        self.assertIs(obj["ai"], True)
        self.assertEqual(obj["model"], "haiku")
        return obj["token"]

    def post(self, payload, token=None):
        headers = [("Origin", f"http://127.0.0.1:{self.port}"), ("Content-Type", "application/json; charset=utf-8"),
                   ("X-BVS-Token", token or self.token()), ("Sec-Fetch-Site", "same-origin"),
                   ("X-BVS-AI-Consent", "yes")]
        return raw_request(self.port, "POST", "/api/ask", body=json.dumps(payload).encode(), headers=headers)

    @staticmethod
    def fake_completed(obj, code=0):
        return subprocess.CompletedProcess(args=[], returncode=code, stdout=json.dumps(obj), stderr="")

    def test_success_path_and_locked_down_command(self):
        secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        payload = {"question": "In one sentence, what is the verdict?", "preset": "eli5",
                   "context": {"view": "#/overview", "selectionText": "Verdict card " + secret,
                               "entities": [{"type": "tile", "id": "verdict", "label": "Verdict"}],
                               "history": [{"role": "user", "text": "hi"}, {"role": "assistant", "text": "hello"}]}}
        reply = {"type": "result", "subtype": "success", "is_error": False,
                 "result": "Your PC shows no sign of attack.", "total_cost_usd": 0.0123}
        with mock.patch.object(self.bridge_mod.subprocess, "run", return_value=self.fake_completed(reply)) as run:
            resp, data = self.post(payload)
        self.assertEqual(resp.status, 200, data)
        obj = json.loads(data)
        self.assertEqual(obj, {"text": "Your PC shows no sign of attack.", "source": "ai", "model": "haiku",
                               "costUsd": 0.0123})
        self.assertEqual(run.call_count, 1)
        args, kwargs = run.call_args
        cmd = args[0]
        self.assertEqual(cmd[0], os.path.abspath(sys.executable))
        self.assertEqual(cmd[cmd.index("--tools") + 1], "")
        for flag in ("-p", "--disable-slash-commands", "--no-session-persistence", "--strict-mcp-config"):
            self.assertIn(flag, cmd)
        self.assertEqual(cmd[cmd.index("--setting-sources") + 1], "user")
        self.assertEqual(cmd[cmd.index("--permission-mode") + 1], "dontAsk")
        self.assertEqual(cmd[cmd.index("--output-format") + 1], "json")
        self.assertEqual(cmd[cmd.index("--model") + 1], "haiku")
        self.assertIn("INFOSEC", cmd[cmd.index("--system-prompt") + 1])
        self.assertNotIn("--dangerously-skip-permissions", cmd)
        joined = " ".join(cmd)
        self.assertNotIn("In one sentence", joined)  # user text never on the command line
        self.assertNotIn("Verdict card", joined)
        prompt = kwargs["input"]
        self.assertIn("In one sentence, what is the verdict?", prompt)
        self.assertIn("<scan-data>", prompt)
        self.assertIn('"verdict":', prompt)
        self.assertIn("Verdict card", prompt)
        self.assertNotIn(secret, prompt)  # token-like strings are masked before leaving the PC
        self.assertLessEqual(len(prompt), 36_000)
        self.assertEqual(kwargs["cwd"], self.sandbox.name)
        self.assertEqual(kwargs["timeout"], 120)
        self.assertFalse(kwargs.get("shell"))
        self.assertNotIn("CLAUDECODE", kwargs["env"])

    def test_entities_pull_full_finding_json(self):
        fid = next(f["id"] for f in self.bridge.context.findings())
        reply = {"is_error": False, "result": "ok", "total_cost_usd": 0.001}
        with mock.patch.object(self.bridge_mod.subprocess, "run", return_value=self.fake_completed(reply)) as run:
            resp, _ = self.post({"question": "What is this?",
                                 "context": {"entities": [{"type": "finding", "id": fid}]}})
        self.assertEqual(resp.status, 200)
        self.assertIn(f"[finding {fid}]", run.call_args[1]["input"])

    def test_ai_error_and_timeout(self):
        with mock.patch.object(self.bridge_mod.subprocess, "run",
                               return_value=self.fake_completed({"is_error": True, "result": "Not logged in"}, 1)):
            resp, data = self.post({"question": "x"})
        self.assertEqual((resp.status, json.loads(data)["error"]), (502, "ai_failed"))
        with mock.patch.object(self.bridge_mod.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired(cmd="claude", timeout=120)):
            resp, data = self.post({"question": "x"})
        self.assertEqual((resp.status, json.loads(data)["error"]), (504, "timeout"))
        with mock.patch.object(self.bridge_mod.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 1, "garbage", "")):
            resp, data = self.post({"question": "x"})
        self.assertEqual(resp.status, 502)

    def test_rate_limit_and_busy_429(self):
        bridge = self.bridge_mod.AIBridge(FIXTURE, claude_path=sys.executable, rate_per_min=2,
                                          runner=lambda prompt, cmd: {"is_error": False, "result": "ok"})
        req = self.bridge_mod.validate_request({"question": "x"})
        bridge.ask(req)
        bridge.ask(req)
        with self.assertRaises(self.bridge_mod.AIError) as ctx:
            bridge.ask(req)
        self.assertEqual((ctx.exception.status, ctx.exception.code), (429, "rate_limited"))
        bridge._recent.clear()
        bridge._busy.acquire()
        try:
            with self.assertRaises(self.bridge_mod.AIError) as ctx:
                bridge.ask(req)
            self.assertEqual((ctx.exception.status, ctx.exception.code), (429, "busy"))
        finally:
            bridge._busy.release()
        # over HTTP: a 429 carries Retry-After
        self.bridge._recent.extend([time.monotonic()] * self.bridge.rate_per_min)
        resp, _ = self.post({"question": "x"})
        self.assertEqual(resp.status, 429)
        self.assertTrue(resp.getheader("Retry-After"))


class SignalInProcessTests(unittest.TestCase):
    """In-process server with a tiny signal rate limit and a fake process listing."""

    ROWS = [
        {"pid": 101, "name": "claude.exe", "started": "2026-10-20T10:00:00Z",
         "cmd": '"C:\\Users\\tester\\.local\\bin\\claude.exe" --resume abc --api-key sk-ant-' + "A" * 40 + " --model opus"},
        {"pid": 102, "name": "node.exe", "started": None,
         "cmd": "node C:\\Users\\tester\\AppData\\Roaming\\npm\\node_modules\\@anthropic-ai\\claude-code\\cli.js -p hi"},
        {"pid": 103, "name": "Cursor.exe", "started": None, "cmd": '"C:\\Cursor\\Cursor.exe" --type=renderer --x'},
        {"pid": 104, "name": "Cursor.exe", "started": None, "cmd": '"C:\\Cursor\\Cursor.exe"'},
        {"pid": 105, "name": "codex.exe", "started": None, "cmd": "codex.exe --token=ghp_" + "b" * 36 + " exec"},
        {"pid": 106, "name": "notepad.exe", "started": None, "cmd": "notepad.exe secret.txt"},
        {"pid": 107, "name": "python.exe", "started": None, "cmd": "python -m aider --model x"},
        {"pid": 108, "name": "node.exe", "started": None, "cmd": "node server.js"},
        {"pid": 109, "name": "claude.exe", "started": None,
         "cmd": '"C:\\Users\\tester\\AppData\\Local\\AnthropicClaude\\app-1.0\\claude.exe"'},
    ]

    @classmethod
    def setUpClass(cls):
        cls.serve = load_serve_module()
        cls.state = tempfile.TemporaryDirectory(prefix="bvs-test-state-")
        cls.calls = 0

        def runner():
            cls.calls += 1
            return [dict(r) for r in cls.ROWS], "cim"

        live = cls.serve.agents_live.LiveAgents(runner=runner)
        cls.server = cls.serve.DashboardServer(0, FIXTURE, "demo-scan", state_root=cls.state.name, live_agents=live,
                                               signal_rate_per_min=2)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.state.cleanup()

    def headers(self):
        return [("Origin", f"http://localhost:{self.port}"), ("Content-Type", "application/json"),
                ("X-BVS-Token", self.server.api_token), ("Sec-Fetch-Site", "same-origin")]

    def test_signal_rate_limit_429(self):
        body = json.dumps({"type": "refresh-report"}).encode()
        codes = [raw_request(self.port, "POST", "/api/signal", host=f"localhost:{self.port}", body=body,
                             headers=self.headers())[0] for _ in range(3)]
        self.assertEqual([c.status for c in codes], [200, 200, 429])
        self.assertTrue(codes[2].getheader("Retry-After"))

    def test_agents_live_masked_and_cached(self):
        hdr = [("X-BVS-Token", self.server.api_token)]
        before = self.calls
        resp, data = raw_request(self.port, "GET", "/api/agents/live", headers=hdr)
        raw_request(self.port, "GET", "/api/agents/live", headers=hdr)
        self.assertEqual(resp.status, 200)
        self.assertLessEqual(self.calls - before, 1)  # cached for 5 s
        obj = json.loads(data)
        by_pid = {it["pid"]: it for it in obj["items"]}
        self.assertEqual(set(by_pid), {101, 102, 104, 105, 107, 109})  # helpers, notepad, plain node skipped
        self.assertEqual(by_pid[101]["kind"], "claude-code")
        self.assertEqual(by_pid[101]["command"], "claude.exe --resume --model")  # no values, no --api-key
        self.assertEqual(by_pid[102]["kind"], "claude-code")
        self.assertEqual(by_pid[102]["command"], "node.exe -p")
        self.assertEqual(by_pid[104]["kind"], "cursor")
        self.assertEqual(by_pid[105]["command"], "codex.exe")
        self.assertEqual(by_pid[107]["kind"], "aider")
        self.assertEqual(by_pid[109]["kind"], "claude-desktop")
        for needle in (b"sk-ant", b"ghp_", b"tester", b"abc", b"secret.txt", b"cli.js"):
            self.assertNotIn(needle, data)


class FakeClaude:
    """Stands in for a streaming Claude Code process: records what is written to stdin and replays canned
    stream-json lines on stdout once the question has arrived."""

    def __init__(self, lines):
        self.lines = [json.dumps(x) + "\n" for x in lines]
        self.written = []
        self.ready = threading.Event()
        self.killed = False
        self.stdin = self
        self.stdout = self
        self.closed = False

    # stdin side
    def write(self, text):
        self.written.append(text)

    def flush(self):
        self.ready.set()

    def close(self):
        self.closed = True
        self.ready.set()

    # stdout side: yields lines only after the question was sent
    def __iter__(self):
        self.ready.wait(10)
        for line in self.lines:
            yield line

    def poll(self):
        return None if not self.killed and not self.closed else 0

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.killed = True


def stream_result(text, cost=0.002, pieces=None):
    events = [{"type": "system", "subtype": "init"}]
    for piece in (pieces or [text]):
        events.append({"type": "stream_event", "event": {"type": "content_block_delta",
                                                          "delta": {"type": "text_delta", "text": piece}}})
    events.append({"type": "result", "subtype": "success", "is_error": False, "result": text, "total_cost_usd": cost})
    return events


class InfosecStreamingTests(unittest.TestCase):
    """Streamed /api/ask (NDJSON) through an in-process server with a fake Claude process."""

    @classmethod
    def setUpClass(cls):
        cls.serve = load_serve_module()
        cls.bridge_mod = cls.serve.ai_bridge
        cls.sandbox = tempfile.TemporaryDirectory()
        cls.spawned = []
        cls.script = []

        def popen(cmd, **kwargs):
            proc = FakeClaude(cls.script.pop(0) if cls.script else stream_result("ok"))
            proc.cmd, proc.kwargs = cmd, kwargs
            cls.spawned.append(proc)
            return proc

        cls.bridge = cls.bridge_mod.AIBridge(FIXTURE, claude_path=sys.executable, model="haiku",
                                             sandbox_dir=cls.sandbox.name, popen=popen)
        cls.server = cls.serve.DashboardServer(0, FIXTURE, "demo-scan", ai=cls.bridge)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.bridge.close()
        cls.sandbox.cleanup()

    def setUp(self):
        self.bridge._recent.clear()
        self.bridge.warm.close()  # each test starts without a warm spare
        self.bridge.warm._closed = False
        del self.spawned[:]
        del self.script[:]

    def ask(self, payload, accept="application/x-ndjson"):
        resp, data = raw_request(self.port, "GET", "/api/status")
        token = json.loads(data)["token"]
        headers = [("Origin", f"http://127.0.0.1:{self.port}"), ("Content-Type", "application/json"),
                   ("X-BVS-Token", token), ("X-BVS-AI-Consent", "yes"), ("Accept", accept)]
        return raw_request(self.port, "POST", "/api/ask", body=json.dumps(payload).encode(), headers=headers)

    @staticmethod
    def events(data):
        return [json.loads(line) for line in data.decode("ascii").splitlines() if line.strip()]

    def test_stream_events_and_locked_down_command(self):
        secret = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"
        self.script.append(stream_result("Your PC shows no sign of attack.", pieces=["Your PC shows ", "no sign ", "of attack."]))
        resp, data = self.ask({"question": "Is my PC safe? " + secret, "context": {"view": "#/overview"}})
        self.assertEqual(resp.status, 200, data)
        self.assertTrue(resp.getheader("Content-Type").startswith("application/x-ndjson"))
        self.assertEqual(resp.getheader("Content-Security-Policy"), CSP)
        evs = self.events(data)
        self.assertEqual(evs[0]["type"], "status")
        self.assertEqual(evs[0]["stage"], "asking")
        self.assertIn({"type": "status", "stage": "writing"}, evs)
        streamed = "".join(e["text"] for e in evs if e["type"] == "delta")
        self.assertEqual(evs[-1]["type"], "done")
        self.assertEqual(evs[-1]["text"], "Your PC shows no sign of attack.")
        self.assertEqual(streamed, evs[-1]["text"])
        self.assertEqual(evs[-1]["costUsd"], 0.002)
        proc = self.spawned[0]
        cmd = proc.cmd
        self.assertEqual(cmd[cmd.index("--output-format") + 1], "stream-json")
        self.assertEqual(cmd[cmd.index("--input-format") + 1], "stream-json")
        self.assertIn("--include-partial-messages", cmd)
        self.assertEqual(cmd[cmd.index("--tools") + 1], "")
        self.assertEqual(json.loads(cmd[cmd.index("--settings") + 1]), {"alwaysThinkingEnabled": False})
        self.assertNotIn("Is my PC safe", " ".join(cmd))  # the question never goes on the command line
        self.assertEqual(proc.kwargs["env"].get("MAX_THINKING_TOKENS"), "0")
        self.assertNotIn("CLAUDECODE", proc.kwargs["env"])
        self.assertFalse(proc.kwargs.get("shell"))
        self.assertEqual(proc.kwargs["cwd"], self.sandbox.name)
        sent = json.loads("".join(proc.written))
        self.assertEqual(sent["type"], "user")
        self.assertIn("Is my PC safe?", sent["message"]["content"])
        self.assertNotIn(secret, sent["message"]["content"])  # masked before it leaves the PC
        self.assertTrue(proc.closed)  # one question per process

    def test_secret_in_answer_never_streams_unmasked(self):
        token = "ghp_" + "Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6J7k8"
        text = f"Your token {token} is exposed."
        self.script.append(stream_result(text, pieces=["Your token ", token[:10], token[10:], " is exposed."]))
        resp, data = self.ask({"question": "x"})
        self.assertEqual(resp.status, 200)
        self.assertNotIn(token[:12], data.decode("ascii"))
        self.assertNotIn(token, data.decode("ascii"))
        evs = self.events(data)
        self.assertEqual(evs[-1]["type"], "done")
        self.assertIn("is exposed.", evs[-1]["text"])

    def test_error_after_start_is_an_event(self):
        self.script.append([{"type": "system", "subtype": "init"},
                            {"type": "result", "subtype": "error", "is_error": True, "result": "Not logged in"}])
        resp, data = self.ask({"question": "x"})
        self.assertEqual(resp.status, 200)
        evs = self.events(data)
        self.assertEqual((evs[-1]["type"], evs[-1]["error"]), ("error", "ai_failed"))

    def test_process_that_dies_is_reported(self):
        self.script.append([{"type": "system", "subtype": "init"}])  # stdout ends without a result
        resp, data = self.ask({"question": "x"})
        evs = self.events(data)
        self.assertEqual((evs[-1]["type"], evs[-1]["error"]), ("error", "ai_failed"))

    def test_busy_and_rate_limit_before_start_are_plain_json(self):
        self.bridge._busy.acquire()
        try:
            resp, data = self.ask({"question": "x"})
        finally:
            self.bridge._busy.release()
        self.assertEqual(resp.status, 429)
        self.assertTrue(resp.getheader("Content-Type").startswith("application/json"))
        self.assertEqual(json.loads(data)["error"], "busy")

    def test_warm_spare_is_used_for_the_next_question(self):
        self.script.extend([stream_result("one"), stream_result("two")])
        resp, data = self.ask({"question": "first"})
        self.assertFalse(self.events(data)[0]["warm"])  # nothing was warm yet
        deadline = time.monotonic() + 5
        while len(self.spawned) < 2 and time.monotonic() < deadline:  # refill starts the next one
            time.sleep(0.02)
        self.assertEqual(len(self.spawned), 2)
        resp, data = self.ask({"question": "second"})
        evs = self.events(data)
        self.assertTrue(evs[0]["warm"])
        self.assertEqual(evs[-1]["text"], "two")
        self.assertIn("second", "".join(self.spawned[1].written))

    def test_json_answer_without_accept_header_still_works(self):
        reply = {"type": "result", "subtype": "success", "is_error": False, "result": "plain", "total_cost_usd": 0.001}
        with mock.patch.object(self.bridge_mod.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0, json.dumps(reply), "")):
            resp, data = self.ask({"question": "x"}, accept="application/json")
        self.assertEqual(resp.status, 200)
        self.assertEqual(json.loads(data)["text"], "plain")


class ChatHistoryTests(unittest.TestCase):
    """POST /api/chats, GET /api/chats and /api/chats/<id> against a temporary state root."""

    @classmethod
    def setUpClass(cls):
        cls.serve = load_serve_module()
        cls.state = tempfile.TemporaryDirectory(prefix="bvs-test-chats-")
        cls.server = cls.serve.DashboardServer(0, FIXTURE, "demo-scan", state_root=cls.state.name)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.state.cleanup()

    def token(self):
        _resp, data = raw_request(self.port, "GET", "/api/status")
        return json.loads(data)["token"]

    def post(self, obj, origin=True, token=None):
        headers = [("Content-Type", "application/json"), ("X-BVS-Token", token or self.token())]
        if origin:
            headers.append(("Origin", f"http://127.0.0.1:{self.port}"))
        return raw_request(self.port, "POST", "/api/chats", body=json.dumps(obj).encode(), headers=headers)

    def get(self, path, token=None):
        return raw_request(self.port, "GET", path, headers=[("X-BVS-Token", token or self.token())])

    def test_save_list_get_roundtrip(self):
        secret = "npm_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
        chat = {"id": "c" + "k3v9x2m1q8", "title": "", "created": 1760000000000, "updated": 1760000005000,
                "messages": [{"role": "user", "text": "What is my verdict? " + secret, "ts": 1760000000000,
                              "about": "Verdict", "via": "from the scanner"},
                             {"role": "assistant", "text": "No sign of attack.", "ts": 1760000004000, "source": "ai",
                              "model": "haiku", "costUsd": 0.0123}]}
        resp, data = self.post(chat)
        self.assertEqual(resp.status, 200, data)
        self.assertEqual(json.loads(data)["count"], 2)
        path = Path(self.state.name) / "infosec" / "chats" / "ck3v9x2m1q8.json"
        self.assertTrue(path.is_file())
        stored = path.read_text(encoding="utf-8")
        self.assertNotIn(secret, stored)  # masked before it is written
        resp, data = self.get("/api/chats")
        self.assertEqual(resp.status, 200)
        rows = json.loads(data)["items"]
        row = next(r for r in rows if r["id"] == "ck3v9x2m1q8")
        self.assertTrue(row["title"].startswith("What is my verdict?"))
        self.assertEqual(row["count"], 2)
        self.assertEqual(row["questions"][0]["about"], "Verdict")
        resp, data = self.get("/api/chats/ck3v9x2m1q8")
        self.assertEqual(resp.status, 200)
        full = json.loads(data)
        self.assertEqual(full["messages"][1]["text"], "No sign of attack.")
        self.assertEqual(full["messages"][0]["via"], "from the scanner")

    def test_bad_chats_are_refused(self):
        good = {"id": "cabcdefgh12", "messages": [{"role": "user", "text": "hi"}]}
        for bad in ({"id": "../../evil", "messages": []}, {"id": "Cabcdefgh12", "messages": []},
                    {"id": "cabcdefgh12", "messages": "x"}, dict(good, extra=1),
                    {"id": "cabcdefgh12", "messages": [{"role": "system", "text": "x"}]},
                    {"id": "cabcdefgh12", "messages": [{"role": "user", "text": "x", "html": "<b>"}]},
                    {"id": "cabcdefgh12", "messages": [{"role": "user", "text": "x" * 20001}]},
                    {"id": "cabcdefgh12", "messages": [{"role": "user", "text": "x"}] * 201}):
            with self.subTest(bad=str(bad)[:60]):
                resp, _ = self.post(bad)
                self.assertEqual(resp.status, 400)
        self.assertFalse((Path(self.state.name) / "evil.json").exists())

    def test_guards(self):
        good = {"id": "cguard00001", "messages": [{"role": "user", "text": "hi"}]}
        resp, _ = self.post(good, origin=False)
        self.assertEqual(resp.status, 403)
        resp, _ = self.post(good, token="wrong")
        self.assertEqual(resp.status, 403)
        resp, _ = raw_request(self.port, "GET", "/api/chats")  # no token
        self.assertEqual(resp.status, 403)
        resp, _ = self.get("/api/chats/cnotthere01")
        self.assertEqual(resp.status, 404)
        for path in ("/api/chats/../summary", "/api/chats/c..%2F..%2Fx", "/api/chats/cABCDEFGH12"):
            with self.subTest(path=path):
                resp, _ = self.get(path)
                self.assertEqual(resp.status, 404)


class PrivacyTests(unittest.TestCase):
    """core/ai_bridge.py redaction: user name, personal file names, evidence keys."""

    @classmethod
    def setUpClass(cls):
        cls.serve = load_serve_module()
        cls.ab = cls.serve.ai_bridge
        profile = "C:\\Users\\jdoe"
        cls.red = cls.ab.Redactor(profile=profile, usernames=["jdoe"],
                                  roots=[profile + "\\" + n for n in cls.ab.PERSONAL_FOLDER_NAMES])

    def test_user_name_and_profile(self):
        r = self.red
        self.assertEqual(r.redact_text("C:\\Users\\jdoe\\AppData\\Local\\x.log"), "C:\\Users\\<user>\\AppData\\Local\\x.log")
        self.assertEqual(r.redact_text("signed in as jdoe today"), "signed in as <user> today")
        self.assertEqual(r.redact_text("jdoesmith stays"), "jdoesmith stays")

    def test_personal_names(self):
        r = self.red
        self.assertEqual(r.redact_text("C:\\Users\\jdoe\\Documents\\Taxes\\2025 return.pdf"),
                         "C:\\Users\\<user>\\Documents\\[personal folder]\\[personal file .pdf]")
        self.assertEqual(r.redact_text("see C:\\Users\\jdoe\\Downloads\\setup.exe now"),
                         "see C:\\Users\\<user>\\Downloads\\[personal file .exe] now")
        self.assertEqual(r.redact_text("C:\\Users\\jdoe\\Desktop\\Old Stuff"),
                         "C:\\Users\\<user>\\Desktop\\[personal folder]")
        self.assertEqual(r.redact_text("C:\\Users\\jdoe\\Documents"), "C:\\Users\\<user>\\Documents")
        # a name the user typed in the question stays visible
        self.assertEqual(r.redact_text("C:\\Users\\jdoe\\Documents\\Taxes\\invoice.pdf", allow="Is invoice.pdf ok?"),
                         "C:\\Users\\<user>\\Documents\\[personal folder]\\invoice.pdf")

    def test_evidence_keys(self):
        obj = {"path": "C:\\Users\\jdoe\\Downloads\\miniToDo.zip", "label": "miniToDo.zip", "sha256": "ab" * 32,
               "evidence": [{"hostUrl": "https://cdn.example.com/a/b.zip?ex=1&hm=2#frag",
                             "command": '"C:\\Users\\jdoe\\tool.exe" --port 4040', "cmd": "node.exe x.js"}]}
        out = self.red.redact_obj(obj)
        self.assertNotIn("sha256", out)
        self.assertEqual(out["path"], "C:\\Users\\<user>\\Downloads\\[personal file .zip]")
        self.assertEqual(out["label"], "[personal file .zip]")
        ev = out["evidence"][0]
        self.assertEqual(ev["hostUrl"], "https://cdn.example.com/a/b.zip")
        self.assertEqual(ev["command"], "tool.exe [arguments removed]")
        self.assertEqual(ev["cmd"], "node.exe [arguments removed]")

    def test_prompt_is_redacted(self):
        bridge = self.ab.AIBridge(FIXTURE, enabled=False, redactor=self.red)
        item = {"id": "g1-00001", "path": "C:\\Users\\jdoe\\Documents\\Bank\\statement-march.pdf",
                "label": "statement-march.pdf", "sha256": "cd" * 32, "x": {"commandLine": "x.exe --secret-flag"}}
        req = self.ab.validate_request({"question": "Can I delete this?", "context": {
            "view": "#/storage/map?path=C%3A%5CUsers%5Cjdoe%5CDocuments%5CBank",
            "selectionText": "jdoe C:\\Users\\jdoe\\Pictures\\Family\\IMG_1.jpg",
            "entities": [{"type": "storageItem", "id": "g1-00001"}]}})
        with mock.patch.object(bridge.context, "entity", return_value=item):
            prompt = bridge.build_prompt(req)
        for leak in ("jdoe", "statement-march", "Bank", "Family", "IMG_1", "cd" * 32, "--secret-flag"):
            self.assertNotIn(leak, prompt)
        self.assertIn("[personal file .pdf]", prompt)
        self.assertIn("[personal file .jpg]", prompt)
        self.assertIn("<user>", prompt)
        req2 = self.ab.validate_request({"question": "Why is statement-march.pdf here?",
                                         "context": {"entities": [{"type": "storageItem", "id": "g1-00001"}]}})
        with mock.patch.object(bridge.context, "entity", return_value=item):
            prompt2 = bridge.build_prompt(req2)
        self.assertIn("statement-march.pdf", prompt2)  # the user typed it
        self.assertNotIn("Bank", prompt2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
