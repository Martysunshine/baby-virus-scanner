#!/usr/bin/env python3
"""serve.py - the read-only baby-virus-scanner dashboard server.

Usage:
    python -I -B server/serve.py [--scan <scanDir | scanId>] [--port 8777] [--open]
                                 [--no-ai] [--ai-model haiku] [--claude-path <claude.exe>]
                                 [--state-root <dir, default data/>]

Safety properties (see docs/playbooks/J-dashboard.md and docs/playbooks/K-signals.md):
  * binds to 127.0.0.1 only (port 8777, else the first free port in 8778-8800);
  * GET and HEAD only - every other method gets 405. The three exceptions are POST /api/ask
    (INFOSEC questions, never writes anything), POST /api/signal (dashboard -> Claude session
    signals; it only writes new files to <state-root>/signals/inbox and /status) and POST
    /api/chats (saves one INFOSEC chat as <state-root>/infosec/chats/<id>.json, core/chat_store.py);
  * the Host header must be 127.0.0.1:<port> or localhost:<port> (DNS-rebinding defence);
  * fixed routes only: "/", "/dashboard/<whitelisted file>", "/dashboard/assets/<name>.(svg|png|webp|jpg)"
    (logo and optional decorative images, one flat folder), "/data/latest.js",
    "/data/<scanId>/js/<name>.js", "/api/status", "/api/ask", "/api/signal", "/api/signals",
    "/api/session", "/api/agents/live", "/api/chats" and "/api/chats/<chatId>" (strict regexes,
    no percent-decoding, no directory listing);
  * resolved real paths must stay inside the allowed folders; symlinks/junctions are refused;
  * strict CSP and hardening headers on every response, no CORS.

INFOSEC API (core/ai_bridge.py runs the Claude Code CLI with no tools, prompt on stdin):
  * GET /api/status -> {ai, model, token}. The token is random per server start; other web
    sites cannot read it because there is no CORS and the Host header is checked;
  * POST /api/ask needs: the allowed Host, Origin exactly http://127.0.0.1:<port> or
    http://localhost:<port>, Sec-Fetch-Site (if sent) same-origin, the X-BVS-Token header,
    Content-Type application/json and a body of at most 64 KB (403/415/411/413/400 otherwise);
    one request at a time and about 20 per minute (429). Only metadata is logged, never text.
    It also needs X-BVS-AI-Consent: yes (403 consent_required otherwise). With
    Accept: application/x-ndjson the answer streams as one JSON event per line (status, delta,
    reset, then done or error); otherwise it comes back as one JSON object.

Chat history (core/chat_store.py): POST /api/chats has the same guards as /api/signal with a 5 MB
body limit and 120 saves per minute; GET /api/chats and /api/chats/<id> the same guards as
/api/signals. There is no delete route.

Signal API (core/signals.py, docs/ui-contract-v3.md section 1):
  * POST /api/signal: the same guards as /api/ask (Host, exact Origin, Sec-Fetch-Site, token,
    JSON, 64 KB), rate limits (20 signals and 120 attempts per minute) and a strict schema. A
    delete-request needs typedConfirmation "I confirm"; the response carries a one-time code
    that is never stored (only its salted hash) and never logged;
  * GET /api/signals, /api/session, /api/agents/live: the allowed Host, Origin (if sent) exactly
    this server, Sec-Fetch-Site (if sent) same-origin, the X-BVS-Token header and a rate limit
    (600 per minute). /api/signals never returns codes, salts or hashes; /api/agents/live is a
    read-only process listing with masked short command lines (core/agents_live.py).

Python 3 standard library only. Logs to logs/server.log.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import errno
import hmac
import http.server
import json
import os
import re
import secrets
import socket
import socketserver
import sys
import threading
import time
import webbrowser
from http import HTTPStatus
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = ROOT / "dashboard"
ASSETS_DIR = DASHBOARD_DIR / "assets"
DATA_DIR = ROOT / "data"
LOG_FILE = ROOT / "logs" / "server.log"

sys.path.append(str(ROOT / "core"))  # appended, so the stdlib always wins
import agents_live  # noqa: E402
import ai_bridge  # noqa: E402
import chat_store  # noqa: E402
import signals  # noqa: E402

BIND_ADDRESS = "127.0.0.1"
DEFAULT_PORT = 8777
FALLBACK_PORTS = range(8778, 8801)
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_API_BODY = 64 * 1024
MAX_CHAT_BODY = 5 * 1024 * 1024
SIGNAL_RATE_PER_MIN = 20       # signals written per minute
SIGNAL_ATTEMPTS_PER_MIN = 120  # authenticated POST /api/signal attempts per minute (valid or not)
CHAT_SAVES_PER_MIN = 120
API_GET_RATE_PER_MIN = 600
API_GET_ROUTES = ("/api/signals", "/api/session", "/api/agents/live", "/api/chats")
ROUTE_CHAT = re.compile(r"^/api/chats/(c[0-9a-z]{8,40})$")
NDJSON = "application/x-ndjson"

DASHBOARD_FILES = frozenset({
    "index.html", "style.css", "favicon.svg",
    "loader.js", "util.js", "vtable.js", "treemap.js", "basket.js", "app.js",
    # dashboard v2 (docs/ui-contract.md): storage map (UI-B) and INFOSEC / scanner (UI-C)
    "storage-view.js", "storage-treemap.js", "storage.css",
    "glossary.js", "infosec.js", "infosec.css", "scanner.js", "scanner.css",
    # dashboard v3 (docs/ui-contract-v3.md): agent map (M)
    "agents-view.js", "agents.css",
})
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".webp": "image/webp",
    ".jpg": "image/jpeg",
}
SCAN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
ROUTE_DASHBOARD = re.compile(r"^/dashboard/([A-Za-z0-9][A-Za-z0-9_-]{0,40}\.(?:html|js|css|svg))$")
# dashboard/assets: one flat folder of images only (logo, optional decorative art); no sub-folders, no dots in names
ROUTE_ASSETS = re.compile(r"^/dashboard/assets/([A-Za-z0-9][A-Za-z0-9_-]{0,63}\.(?:svg|png|webp|jpg))$")
ROUTE_DATA = re.compile(r"^/data/([A-Za-z0-9][A-Za-z0-9_-]{0,63})/js/([A-Za-z0-9][A-Za-z0-9_-]{0,63})\.js$")
WINDOWS_DEVICE_NAMES = re.compile(r"^(con|prn|aux|nul|com[0-9]|lpt[0-9]|conin\$|conout\$)$", re.IGNORECASE)

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
SECURITY_HEADERS = (
    ("Content-Security-Policy", CSP),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("X-Frame-Options", "DENY"),
    ("Permissions-Policy", "accelerometer=(), autoplay=(), bluetooth=(), camera=(), display-capture=(), "
                           "encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), "
                           "magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), "
                           "publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), "
                           "xr-spatial-tracking=(), clipboard-read=(), clipboard-write=(self)"),
)

_log_lock = threading.Lock()


def _printable(text, limit=300):
    out = []
    for ch in str(text)[:limit]:
        code = ord(ch)
        out.append(ch if 32 <= code < 127 else f"\\x{code:02x}" if code < 256 else f"\\u{code:04x}")
    return "".join(out)


def write_log(line: str):
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with _log_lock:
            LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(LOG_FILE, "a", encoding="utf-8", newline="\n") as handle:
                handle.write(f"{stamp} {line}\n")
    except OSError:
        pass  # logging must never break serving


def _is_link(path: str) -> bool:
    if os.path.islink(path):
        return True
    isjunction = getattr(os.path, "isjunction", None)  # Python 3.12+
    return bool(isjunction and isjunction(path))


def _inside(child_real: str, parent_real: str) -> bool:
    c, p = os.path.normcase(child_real), os.path.normcase(parent_real)
    try:
        return os.path.commonpath([c, p]) == p
    except ValueError:
        return False


class DashboardServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False  # SO_REUSEADDR would let another process share the port on Windows

    def __init__(self, port: int, scan_dir: Path, scan_id: str, ai=None, state_root=None, live_agents=None,
                 signal_rate_per_min: int = SIGNAL_RATE_PER_MIN):
        self.scan_dir = scan_dir
        self.scan_id = scan_id
        self.js_dir_real = os.path.realpath(str(scan_dir / "js"))
        self.dashboard_real = os.path.realpath(str(DASHBOARD_DIR))
        self.assets_real = os.path.realpath(str(ASSETS_DIR))
        self.ai =ai if ai is not None else ai_bridge.AIBridge(scan_dir, enabled=False)
        self.api_token = secrets.token_urlsafe(32)
        self.signals = signals.SignalStore(Path(state_root) if state_root else DATA_DIR, scan_id)
        self.chats = chat_store.ChatStore(Path(state_root) if state_root else DATA_DIR)
        self.live_agents = live_agents if live_agents is not None else agents_live.LiveAgents()
        self.signal_rate = signals.RateLimiter(signal_rate_per_min)
        self.signal_attempt_rate = signals.RateLimiter(SIGNAL_ATTEMPTS_PER_MIN)
        self.chat_rate = signals.RateLimiter(CHAT_SAVES_PER_MIN)
        self.api_get_rate = signals.RateLimiter(API_GET_RATE_PER_MIN)
        super().__init__((BIND_ADDRESS, port), DashboardHandler)

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):  # Windows: nobody else may bind this port while we hold it
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host  # skip HTTPServer's reverse-DNS lookup
        self.server_port = port


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "bvs-dashboard"
    sys_version = ""
    timeout = 20

    def version_string(self):
        return "bvs-dashboard"

    # --- request dispatch: GET/HEAD only, everything else 405 ------------------------------
    def handle_one_request(self):
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline, self.request_version, self.command = "", "", ""
                self.send_error(HTTPStatus.REQUEST_URI_TOO_LONG)
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            if not self.parse_request():
                return
            if self.command in ("GET", "HEAD"):
                self.handle_get()
            elif self.command == "POST" and self.path == "/api/ask":
                self.handle_ask()
            elif self.command == "POST" and self.path == "/api/signal":
                self.handle_signal()
            elif self.command == "POST" and self.path == "/api/chats":
                self.handle_chat_save()
            else:
                self._drain_body()
                self.respond(405, b"405 Method Not Allowed\n", extra=(("Allow", "GET, HEAD"),))
            self.wfile.flush()
        except (TimeoutError, socket.timeout) as exc:
            self.log_error("request timed out: %r", exc)
            self.close_connection = True
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            self.close_connection = True

    def _drain_body(self):
        """Read (and discard) a small request body so the 405 reply is not lost to a TCP reset."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if 0 < length <= 65536:
            try:
                self.rfile.read(length)
            except OSError:
                pass

    def handle_get(self):
        hosts = self.headers.get_all("Host") or []
        if len(hosts) != 1 or not self.host_allowed(hosts[0]):
            self.respond(403, b"403 Forbidden\n")
            return
        target = self.path
        if not target.startswith("/"):
            self.respond(404, b"404 Not Found\n")
            return
        path = target.split("?", 1)[0].split("#", 1)[0]
        if path == "/":
            self.serve_file(self.server.dashboard_real, "index.html")
            return
        if path == "/api/status":
            self.handle_status()
            return
        if path in ("/api/ask", "/api/signal"):
            self.respond(405, b"405 Method Not Allowed\n", extra=(("Allow", "POST"),))
            return
        if path in API_GET_ROUTES or ROUTE_CHAT.match(path):
            self.handle_api_get(path)
            return
        if path == "/data/latest.js":
            body = f'window.BVS_LATEST = "{self.server.scan_id}";\n'.encode("ascii")
            self.respond(200, body, CONTENT_TYPES[".js"])
            return
        m = ROUTE_DASHBOARD.match(path)
        if m and m.group(1) in DASHBOARD_FILES:
            self.serve_file(self.server.dashboard_real, m.group(1))
            return
        m = ROUTE_ASSETS.match(path)
        if m:  # serve_file re-checks: device names, links/junctions, real path directly inside dashboard/assets
            if _is_link(str(ASSETS_DIR)) or not _inside(self.server.assets_real, self.server.dashboard_real):
                self.respond(404, b"404 Not Found\n")
                return
            self.serve_file(self.server.assets_real, m.group(1))
            return
        m = ROUTE_DATA.match(path)
        if m and m.group(1) == self.server.scan_id:
            self.serve_file(self.server.js_dir_real, m.group(2) + ".js")
            return
        self.respond(404, b"404 Not Found\n")

    def host_allowed(self, host: str) -> bool:
        port = self.server.server_port
        host = host.strip()
        return host == f"127.0.0.1:{port}" or host.lower() == f"localhost:{port}"

    # --- INFOSEC API ------------------------------------------------------------------------
    def origin_allowed(self, origin: str) -> bool:
        port = self.server.server_port
        return origin in (f"http://127.0.0.1:{port}", f"http://localhost:{port}")

    def fetch_site_allowed(self) -> bool:
        """Sec-Fetch-Site (sent by modern browsers) must say the request came from this page."""
        sites = self.headers.get_all("Sec-Fetch-Site") or []
        return not sites or (len(sites) == 1 and sites[0].strip().lower() in ("same-origin", "none"))

    def respond_json(self, code: int, obj: dict, extra=()):
        body = json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        self.respond(code, body, "application/json; charset=utf-8", extra=extra)

    def handle_status(self):
        origins = self.headers.get_all("Origin") or []
        if len(origins) > 1 or (origins and not self.origin_allowed(origins[0].strip())) \
                or not self.fetch_site_allowed():
            self.respond_json(403, {"error": "forbidden", "message": "Forbidden"})
            return
        status = self.server.ai.status()
        status["token"] = self.server.api_token
        status["scan"] = self.server.scan_id
        self.respond_json(200, status)

    def handle_ask(self):
        started = time.monotonic()
        meta = {"status": 0}
        try:
            self._handle_ask(meta)
        finally:
            write_log("ai ask " + " ".join(f"{k}={_printable(v, 40)}" for k, v in meta.items())
                      + f" ms={int((time.monotonic() - started) * 1000)}")

    def _failer(self, meta: dict):
        def fail(code, err, message, drain=True, extra=()):
            meta["status"] = code
            meta["error"] = err
            if drain:
                self._drain_body()
            self.close_connection = True
            self.respond_json(code, {"error": err, "message": message}, extra=extra)
        return fail

    def token_ok(self) -> bool:
        tokens = self.headers.get_all("X-BVS-Token") or []
        return len(tokens) == 1 and hmac.compare_digest(tokens[0].strip().encode("utf-8", "replace"),
                                                        self.server.api_token.encode("ascii"))

    def _read_api_json(self, meta: dict, fail, require_consent: bool = False, max_body: int = MAX_API_BODY):
        """Shared guard for POST API routes: Host, exact Origin, Sec-Fetch-Site, X-BVS-Token, (consent),
        JSON content type, Content-Length <= max_body (64 KB by default), valid JSON. Returns (ok, body)."""
        hosts = self.headers.get_all("Host") or []
        if len(hosts) != 1 or not self.host_allowed(hosts[0]):
            fail(403, "forbidden", "Forbidden")
            return False, None
        origins = self.headers.get_all("Origin") or []
        if len(origins) != 1 or not self.origin_allowed(origins[0].strip()):
            fail(403, "forbidden", "Forbidden: bad origin")
            return False, None
        if not self.fetch_site_allowed():
            fail(403, "forbidden", "Forbidden: cross-site request")
            return False, None
        if not self.token_ok():
            fail(403, "forbidden", "Forbidden: missing or wrong token")
            return False, None
        if require_consent:
            consent = self.headers.get_all("X-BVS-AI-Consent") or []
            if len(consent) != 1 or consent[0].strip().lower() != "yes":
                fail(403, "consent_required", "Allow AI answers first: the dashboard asks once before INFOSEC "
                                              "sends anything to Claude.")
                return False, None
        ok, body = self._read_json_body(meta, fail, max_body)
        return ok, body

    def _read_json_body(self, meta: dict, fail, max_body: int = MAX_API_BODY):
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            fail(415, "unsupported_media_type", "Content-Type must be application/json")
            return False, None
        if self.headers.get("Transfer-Encoding"):
            fail(400, "bad_request", "Chunked bodies are not supported", drain=False)
            return False, None
        raw_len = self.headers.get_all("Content-Length") or []
        if len(raw_len) != 1:
            fail(411, "length_required", "Content-Length is required", drain=False)
            return False, None
        try:
            length = int(raw_len[0].strip())
        except ValueError:
            length = -1
        if length < 0:
            fail(400, "bad_request", "Bad Content-Length", drain=False)
            return False, None
        if length > max_body:
            if length <= 4 * MAX_API_BODY:  # read it so the client sees the 413 instead of a reset
                try:
                    self.rfile.read(length)
                except OSError:
                    pass
            fail(413, "too_large", f"Request body is larger than {max_body // 1024} KB", drain=False)
            return False, None
        try:
            raw = b""
            while len(raw) < length:  # large chat bodies arrive in several TCP segments
                chunk = self.rfile.read(length - len(raw))
                if not chunk:
                    break
                raw += chunk
        except OSError:
            fail(400, "bad_request", "Could not read the request body", drain=False)
            return False, None
        meta["bytes"] = len(raw)
        if len(raw) != length:
            fail(400, "bad_request", "Incomplete request body", drain=False)
            return False, None
        try:
            return True, json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            fail(400, "bad_request", "The body is not valid JSON", drain=False)
            return False, None

    def _handle_ask(self, meta: dict):
        fail = self._failer(meta)
        ok, body = self._read_api_json(meta, fail, require_consent=True)
        if not ok:
            return None
        try:
            request = ai_bridge.validate_request(body)
        except ai_bridge.AIError as exc:
            return fail(exc.status, exc.code, exc.message, drain=False)
        ctx = request["context"]
        meta.update(qlen=len(request["question"]), preset=request["preset"] or "-",
                    sel=len(ctx.get("selectionText") or ""), ents=len(ctx.get("entities") or []),
                    hist=len(ctx.get("history") or []))
        if NDJSON in (self.headers.get("Accept") or "").lower():
            return self._stream_ask(request, meta, fail)
        try:
            answer = self.server.ai.ask(request)
        except ai_bridge.AIError as exc:
            extra = (("Retry-After", str(exc.retry_after)),) if exc.retry_after else ()
            return fail(exc.status, exc.code, exc.message, drain=False, extra=extra)
        except Exception as exc:  # noqa: BLE001 - never leak a traceback to the page
            self.log_error("ai bridge failure: %s", type(exc).__name__)
            return fail(500, "internal", "INFOSEC hit an internal error", drain=False)
        meta["status"] = 200
        meta["alen"] = len(answer.get("text") or "")
        if "costUsd" in answer:
            meta["cost"] = answer["costUsd"]
        self.respond_json(200, answer)

    def _stream_ask(self, request: dict, meta: dict, fail):
        """Stream the answer as NDJSON (one JSON event per line). Problems found before the first byte
        (AI off, busy, rate limit) still get a normal JSON error with the right status code."""
        started = time.monotonic()
        state = {"open": False}
        meta["stream"] = 1

        def emit(event: dict):
            if not state["open"]:
                self.send_response(200)
                for key, value in SECURITY_HEADERS:
                    self.send_header(key, value)
                self.send_header("Content-Type", NDJSON + "; charset=utf-8")
                self.end_headers()  # HTTP/1.0 without Content-Length: the stream ends when the connection closes
                try:
                    self.connection.settimeout(None)
                except OSError:
                    pass
                state["open"] = True
            if event.get("type") == "delta" and "first_ms" not in meta:
                meta["first_ms"] = int((time.monotonic() - started) * 1000)
            self.wfile.write((json.dumps(event, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii"))
            self.wfile.flush()

        self.close_connection = True
        try:
            answer = self.server.ai.ask_stream(request, emit)
        except ai_bridge.AIError as exc:
            if not state["open"]:
                extra = (("Retry-After", str(exc.retry_after)),) if exc.retry_after else ()
                return fail(exc.status, exc.code, exc.message, drain=False, extra=extra)
            meta.update(status=exc.status, error=exc.code)
            emit({"type": "error", "error": exc.code, "message": exc.message})
            return None
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            meta.update(status=499, error="client_gone")
            raise
        except Exception as exc:  # noqa: BLE001 - never leak a traceback to the page
            self.log_error("ai bridge failure: %s", type(exc).__name__)
            if not state["open"]:
                return fail(500, "internal", "INFOSEC hit an internal error", drain=False)
            meta.update(status=500, error="internal")
            emit({"type": "error", "error": "internal", "message": "INFOSEC hit an internal error"})
            return None
        meta["status"] = 200
        meta["alen"] = len(answer.get("text") or "")
        if "costUsd" in answer:
            meta["cost"] = answer["costUsd"]
        emit(dict(answer, type="done"))
        return None

    # --- chat history (core/chat_store.py) ----------------------------------------------------
    def handle_chat_save(self):
        started = time.monotonic()
        meta = {"status": 0}
        try:
            fail = self._failer(meta)
            ok, body = self._read_api_json(meta, fail, max_body=MAX_CHAT_BODY)
            if not ok:
                return
            wait = self.server.chat_rate.take()
            if wait:
                fail(429, "rate_limited", f"Too many saves in a minute. Try again in {wait} s.", drain=False,
                     extra=(("Retry-After", str(wait)),))
                return
            try:
                result = self.server.chats.save(body)
            except chat_store.ChatError as exc:
                fail(exc.status, exc.code, exc.message, drain=False)
                return
            except OSError as exc:
                self.log_error("chat write failed: %s", type(exc).__name__)
                fail(500, "internal", "Could not save the chat.", drain=False)
                return
            meta.update(status=200, id=result["id"], count=result["count"])
            self.respond_json(200, result)
        finally:  # metadata only, never chat text
            write_log("chat save " + " ".join(f"{k}={_printable(v, 60)}" for k, v in meta.items())
                      + f" ms={int((time.monotonic() - started) * 1000)}")

    # --- signal bus (core/signals.py) -------------------------------------------------------
    def handle_signal(self):
        started = time.monotonic()
        meta = {"status": 0}
        try:
            self._handle_signal(meta)
        finally:  # metadata only: never the code, never paths
            write_log("signal post " + " ".join(f"{k}={_printable(v, 60)}" for k, v in meta.items())
                      + f" ms={int((time.monotonic() - started) * 1000)}")

    def _handle_signal(self, meta: dict):
        fail = self._failer(meta)
        ok, body = self._read_api_json(meta, fail)
        if not ok:
            return None
        def limited(limiter):
            wait = limiter.take()
            if wait:
                fail(429, "rate_limited", f"Too many requests in a minute. Try again in {wait} s.", drain=False,
                     extra=(("Retry-After", str(wait)),))
            return wait

        if limited(self.server.signal_attempt_rate):  # every authenticated attempt
            return None
        try:
            request = signals.validate_signal(body, self.server.scan_id)
        except signals.SignalError as exc:
            return fail(exc.status, exc.code, exc.message, drain=False)
        if limited(self.server.signal_rate):  # signals that would be written
            return None
        meta["type"] = request["type"]
        if request["type"] == "delete-request":
            meta["items"] = len(request["payload"]["items"])
        try:
            result = self.server.signals.create(request)
        except OSError as exc:
            self.log_error("signal write failed: %s", type(exc).__name__)
            return fail(500, "internal", "Could not write the signal file.", drain=False)
        meta["status"] = 200
        meta["id"] = result["id"]
        self.respond_json(200, result)
        return None

    def handle_api_get(self, path: str):
        origins = self.headers.get_all("Origin") or []
        if len(origins) > 1 or (origins and not self.origin_allowed(origins[0].strip())) \
                or not self.fetch_site_allowed():
            self.respond_json(403, {"error": "forbidden", "message": "Forbidden"})
            return
        if not self.token_ok():
            self.respond_json(403, {"error": "forbidden", "message": "Forbidden: missing or wrong token"})
            return
        wait = self.server.api_get_rate.take()
        if wait:
            self.respond_json(429, {"error": "rate_limited", "message": "Too many requests."},
                              extra=(("Retry-After", str(wait)),))
            return
        try:
            chat = ROUTE_CHAT.match(path)
            if path == "/api/signals":
                items = self.server.signals.list_recent()
                obj = {"items": items, "count": len(items)}
            elif path == "/api/session":
                obj = self.server.signals.session()
            elif path == "/api/chats":
                items = self.server.chats.list()
                obj = {"items": items, "count": len(items)}
            elif chat:
                obj = self.server.chats.get(chat.group(1))
            else:
                obj = self.server.live_agents.get()
        except chat_store.ChatError as exc:
            self.respond_json(exc.status, {"error": exc.code, "message": exc.message})
            return
        except Exception as exc:  # noqa: BLE001 - never leak a traceback to the page
            self.log_error("api get failure: %s", type(exc).__name__)
            self.respond_json(500, {"error": "internal", "message": "Internal error"})
            return
        self.respond_json(200, obj)

    def serve_file(self, base_real: str, name: str):
        stem = name.split(".", 1)[0]
        if WINDOWS_DEVICE_NAMES.match(stem) or "/" in name or "\\" in name or ":" in name:
            self.respond(404, b"404 Not Found\n")
            return
        candidate = os.path.join(base_real, name)
        if _is_link(candidate) or _is_link(base_real):
            self.respond(404, b"404 Not Found\n")
            return
        real = os.path.realpath(candidate)
        if (not _inside(real, base_real) or os.path.normcase(os.path.dirname(real)) != os.path.normcase(base_real)
                or not os.path.isfile(real)):
            self.respond(404, b"404 Not Found\n")
            return
        try:
            with open(real, "rb") as handle:
                body = handle.read(MAX_FILE_BYTES + 1)
        except OSError:
            self.respond(404, b"404 Not Found\n")
            return
        if len(body) > MAX_FILE_BYTES:
            self.respond(500, b"500 File too large\n")
            return
        ext = os.path.splitext(name)[1].lower()
        self.respond(200, body, CONTENT_TYPES.get(ext, "application/octet-stream"))

    # --- responses --------------------------------------------------------------------------
    def respond(self, code: int, body: bytes, content_type="text/plain; charset=utf-8", extra=()):
        self.send_response(code)
        for key, value in SECURITY_HEADERS:
            self.send_header(key, value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in extra:
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD" and body:
            # The 20 s timeout guards request *reading*. For the response, switch back to a blocking
            # socket and write in 64 KB chunks: on Windows a socket with a timeout is non-blocking
            # underneath, and large single writes were cut off (client reset after ~20 s) while a
            # network filter driver (antivirus web shield) was inspecting the stream.
            try:
                self.connection.settimeout(None)
            except OSError:
                pass
            view = memoryview(body)
            for start in range(0, len(view), 65536):
                self.wfile.write(view[start:start + 65536])

    def send_error(self, code, message=None, explain=None):
        try:
            phrase = HTTPStatus(code).phrase
        except ValueError:
            phrase = "Error"
        self.close_connection = True
        self.respond(int(code), f"{int(code)} {phrase}\n".encode("ascii"))

    # --- logging ----------------------------------------------------------------------------
    def log_request(self, code="-", size="-"):
        code = getattr(code, "value", code)
        host = self.headers.get("Host", "-") if getattr(self, "headers", None) else "-"
        write_log(f'{self.client_address[0]} "{_printable(getattr(self, "requestline", ""))}" {code} '
                  f'host={_printable(host, 80)}')

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        write_log(f"{self.client_address[0]} {_printable(format % args)}")


def resolve_scan_dir(arg):
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
    scan_id = latest.read_text(encoding="utf-8-sig").strip()
    if not SCAN_ID_RE.match(scan_id) or not (DATA_DIR / scan_id).is_dir():
        raise SystemExit(f"error: data/latest.txt points to a missing scan: {scan_id!r}")
    return (DATA_DIR / scan_id).resolve()


def bind(port: int, scan_dir: Path, scan_id: str, ai=None, state_root=None) -> DashboardServer:
    candidates = [port] + ([p for p in FALLBACK_PORTS] if port == DEFAULT_PORT else [])
    last_error = None
    for candidate in candidates:
        try:
            return DashboardServer(candidate, scan_dir, scan_id, ai=ai, state_root=state_root)
        except OSError as exc:
            last_error = exc
            if exc.errno in (errno.EADDRINUSE, errno.EACCES) or getattr(exc, "winerror", None) in (10048, 10013):
                continue
            raise
    raise SystemExit(f"error: no free port in {candidates[0]}-{candidates[-1]}: {last_error}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only baby-virus-scanner dashboard (127.0.0.1 only)")
    parser.add_argument("--scan", help="scan directory or scan ID (default: data/latest.txt)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="port (default 8777, falling back to 8778-8800; 0 = any free port)")
    parser.add_argument("--open", action="store_true", help="open the dashboard in the default browser")
    parser.add_argument("--no-ai", action="store_true",
                        help="switch off live INFOSEC answers (the dashboard then explains offline)")
    parser.add_argument("--ai-model", default=ai_bridge.DEFAULT_MODEL,
                        help=f"Claude model alias for INFOSEC (default {ai_bridge.DEFAULT_MODEL})")
    parser.add_argument("--claude-path", help="path to the Claude Code CLI (default: PATH, then ~/.local/bin)")
    parser.add_argument("--state-root", help="folder for signals/ and session/ (default: the project's data folder; "
                                             "tests use a temporary folder)")
    args = parser.parse_args(argv)
    if not ai_bridge.MODEL_RE.match(args.ai_model):
        raise SystemExit(f"error: unsupported --ai-model value: {args.ai_model!r}")
    state_root = None
    if args.state_root:
        state_root = Path(args.state_root).resolve()
        if not state_root.is_dir() or _is_link(str(state_root)):
            raise SystemExit(f"error: --state-root must be an existing, real folder: {args.state_root!r}")

    scan_dir = resolve_scan_dir(args.scan)
    if not _inside(os.path.realpath(str(scan_dir)), os.path.realpath(str(ROOT))):
        raise SystemExit("error: the scan folder must be inside the project folder")
    scan_id = scan_dir.name
    if not SCAN_ID_RE.match(scan_id):
        raise SystemExit(f"error: unsupported scan folder name: {scan_id!r}")
    if not (scan_dir / "js" / "manifest.js").is_file():
        print(f"warning: no dashboard data for {scan_id} yet. Run: python -I -B core/build_datajs.py --scan "
              f"\"{scan_dir}\"", file=sys.stderr)

    ai = ai_bridge.AIBridge(scan_dir, claude_path=args.claude_path, model=args.ai_model, enabled=not args.no_ai,
                            prewarm=True)
    server = bind(args.port, scan_dir, scan_id, ai=ai, state_root=state_root)
    url = f"http://127.0.0.1:{server.server_port}/"
    write_log(f"start pid={os.getpid()} url={url} scan={scan_id} ai={'on' if ai.enabled else ai.reason} "
              f"model={ai.model}")
    print(f"BVS dashboard (read-only) listening on {url} scan={scan_id}", flush=True)
    if ai.enabled:
        print(f"INFOSEC live answers: on (Claude {ai.model} via {ai.claude}; no tools, prompt via stdin)", flush=True)
    else:
        print(f"INFOSEC live answers: off ({ai.reason}); the dashboard explains offline", flush=True)
    print("Press Ctrl+C to stop.", flush=True)
    if args.open:
        threading.Timer(0.4, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        ai.close()
        write_log(f"stop pid={os.getpid()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
