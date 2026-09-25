#!/usr/bin/env python3
"""Small, bounded TLS config distributor. Never run this service as root.

TLS handshakes happen in workers, not in accept(). Slow headers have a total
request deadline. SIGHUP swaps the TLS context without dropping VPN sessions.
All upstream traffic is restricted to loopback; tokens are never logged.
"""
import base64
import binascii
from dataclasses import dataclass
import html
import http.server
import logging
import os
from pathlib import Path
import re
import signal
import socket
import socketserver
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request

LOG = logging.getLogger("aggsub")
TOKEN = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
MAX_BODY = 1024 * 1024


def read_file(root, relative):
    root = Path(root).resolve()
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ValueError("path outside distribution directory")
    with path.open("rb") as stream:
        data = stream.read(MAX_BODY + 1)
    if len(data) > MAX_BODY:
        raise ValueError("file too large")
    return data


def read_map(root):
    result = {}
    names = set()
    for line in read_file(root, "awg/submap.tsv").decode().splitlines():
        token, name = line.split("\t")
        if not TOKEN.fullmatch(token) or not NAME.fullmatch(name):
            raise ValueError("invalid distribution map")
        if token in result or name in names:
            raise ValueError("duplicate distribution identity")
        result[token] = name
        names.add(name)
    if not result:
        raise ValueError("empty distribution map")
    return result


def decode_subscription(raw):
    if len(raw) > MAX_BODY:
        raise ValueError("upstream response too large")
    stripped = raw.strip()
    if not stripped.startswith((b"vless://", b"vmess://", b"trojan://", b"ss://")):
        stripped = base64.b64decode(b"".join(stripped.split()), validate=True)
    lines = [line.strip() for line in stripped.decode("utf-8").splitlines() if line.strip()]
    if not lines or any(urllib.parse.urlsplit(line).scheme not in
                        {"vless", "vmess", "trojan", "ss"} for line in lines):
        raise ValueError("empty or invalid upstream subscription")
    return base64.b64encode(("\n".join(lines) + "\n").encode())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class Config:
    root: Path
    cert: str
    key: str
    host: str = "0.0.0.0"
    port: int = 2087
    sub_port: int = 2096
    sub_scheme: str = "http"
    sub_path: str = "/sub/"
    sub_ca: str = ""
    workers: int = 32
    handshake_timeout: float = 4.0
    request_timeout: float = 10.0

    def __post_init__(self):
        if not 0 <= self.port <= 65535 or not 1 <= self.sub_port <= 65535:
            raise ValueError("invalid port")
        if self.sub_scheme not in {"http", "https"}:
            raise ValueError("invalid subscription scheme")
        if not re.fullmatch(r"/[A-Za-z0-9_/-]*/", self.sub_path):
            raise ValueError("invalid subscription path")
        if not 1 <= self.workers <= 128:
            raise ValueError("invalid worker limit")

    def upstream(self, token):
        if not TOKEN.fullmatch(token):
            raise ValueError("invalid token")
        handlers = [urllib.request.ProxyHandler({}), NoRedirect()]
        if self.sub_scheme == "https":
            if not self.sub_ca:
                raise ValueError("HTTPS upstream requires a CA/certificate")
            ctx = ssl.create_default_context()
            ctx.load_verify_locations(self.sub_ca)
            ctx.check_hostname = False  # IP certificate, but connection is loopback only.
            ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        opener = urllib.request.build_opener(*handlers)
        url = f"{self.sub_scheme}://127.0.0.1:{self.sub_port}{self.sub_path}{token}"
        req = urllib.request.Request(url, headers={"User-Agent": "server-init/1", "Accept": "text/plain"})
        with opener.open(req, timeout=4) as response:
            return decode_subscription(response.read(MAX_BODY + 1))


def page(root, name, token):
    e = html.escape
    vless = read_file(root, f"dist/{name}.vless").decode().strip()
    vpn = read_file(root, f"dist/{name}.vpn").decode().strip()
    if not vless.startswith("vless://") or not vpn.startswith("vpn://"):
        raise ValueError("incomplete client exports")
    label = read_file(root, "awg/label").decode().strip()
    try:
        qr = base64.b64encode(read_file(root, f"dist/{name}-vless.png")).decode()
        qr_html = f'<img alt="VLESS QR" src="data:image/png;base64,{qr}">'
    except FileNotFoundError:
        qr_html = ""
    return f'''<!doctype html><html lang="ru"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN — {e(name)}</title><style>
body{{font:16px system-ui;background:#10131c;color:#eee;max-width:540px;margin:24px auto;padding:16px}}
section{{background:#1b2232;padding:20px;margin:18px 0;border-radius:16px}}
textarea{{box-sizing:border-box;width:100%;height:90px}}img{{display:block;width:280px;max-width:100%;margin:12px auto}}
a{{color:#a9cbff}}button{{padding:12px;margin:10px 0}}small{{color:#b0b9cc}}
</style><h1>VPN — {e(name)}</h1><small>Сервер {e(label)}. Ссылка содержит личные ключи: не пересылай её другим.</small>
<section><h2>AmneziaVPN</h2><p>Скопируй ключ → «+» → вставь ключ в приложение.</p>
<textarea id="a" readonly>{e(vpn)}</textarea><button onclick="copyKey('a',this)">Скопировать ключ</button>
<p><a href="/awg/{token}" download>Скачать конфигурацию .conf</a> · <a href="/vpn/{token}" download>Скачать ключ .vpn</a></p>
<a href="https://amnezia.org/downloads" rel="noreferrer">Скачать AmneziaVPN</a></section>
<section><h2>VLESS Reality / роутер</h2><p>Импортируй ссылку или QR в совместимый клиент.</p>{qr_html}
<textarea id="v" readonly>{e(vless)}</textarea><button onclick="copyKey('v',this)">Скопировать VLESS</button>
<p><a href="/sub/{token}">Адрес подписки</a> · <a href="https://hiddify.com/" rel="noreferrer">Hiddify</a></p></section>
<script>async function copyKey(id,b){{try{{await navigator.clipboard.writeText(document.getElementById(id).value);b.textContent='Скопировано ✓'}}catch(e){{b.textContent='Выдели и скопируй текст вручную'}}}}</script></html>'''.encode()


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "ConfigDistributor"
    sys_version = ""

    def log_message(self, *args):
        pass  # BaseHTTPRequestHandler otherwise logs bearer tokens in request URLs.

    def send(self, status, data=b"", kind="text/plain; charset=utf-8", filename=None):
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Connection", "close")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        if status == 503:
            self.send_header("Retry-After", "30")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def do_GET(self):
        cfg = self.server.cfg
        path = urllib.parse.urlsplit(self.path).path
        if path == "/healthz" and self.client_address[0] == "127.0.0.1":
            self.send(200, b"ok\n")
            return
        parts = path.split("/")
        if len(parts) != 3 or parts[1] not in {"p", "awg", "vpn", "sub"} or not TOKEN.fullmatch(parts[2]):
            self.send(404)
            return
        try:
            # Resolve one generation once, so an atomic publish cannot mix identities/files.
            root = cfg.root.resolve()
            name = read_map(root).get(parts[2])
            if name is None:
                self.send(404)
                return
            if parts[1] == "p":
                self.send(200, page(root, name, parts[2]), "text/html; charset=utf-8")
            elif parts[1] == "sub":
                self.send(200, cfg.upstream(parts[2]))
            else:
                relative = f"awg/clients/{name}.conf" if parts[1] == "awg" else f"dist/{name}.vpn"
                self.send(200, read_file(root, relative), filename=f"{name}.{parts[1] if parts[1] == 'vpn' else 'conf'}")
        except (OSError, ValueError, UnicodeError, binascii.Error):
            LOG.warning("configuration/upstream unavailable (%s)", parts[1])
            self.send(503, b"Configuration temporarily unavailable.\n")


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, cfg):
        self.cfg = cfg
        self.slots = threading.BoundedSemaphore(cfg.workers)
        self.reload_requested = threading.Event()
        self.context = self.new_context()
        super().__init__((cfg.host, cfg.port), Handler)

    def new_context(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        cert, key = Path(self.cfg.cert), Path(self.cfg.key)
        if cert.parent == key.parent:
            generation = cert.parent.resolve()
            cert, key = generation / cert.name, generation / key.name
        ctx.load_cert_chain(cert, key)
        return ctx

    def service_actions(self):
        if self.reload_requested.is_set():
            self.reload_requested.clear()
            try:
                self.context = self.new_context()
                LOG.info("TLS certificate reloaded")
            except (OSError, ssl.SSLError):
                LOG.error("TLS reload failed; keeping the previous working context")

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            self.shutdown_request(request)
            raise

    @staticmethod
    def abort_request(request):
        # HTTPServer.shutdown_request only half-closes writes. SHUT_RDWR is
        # necessary to interrupt a worker blocked reading trickled headers.
        try:
            request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        request.close()

    def process_request_thread(self, request, client_address):
        deadline = None
        try:
            request.settimeout(self.cfg.handshake_timeout)
            # Crucial: wrap accepted sockets INSIDE the bounded worker, never the listener.
            request = self.context.wrap_socket(request, server_side=True)
            request.settimeout(self.cfg.request_timeout)
            deadline = threading.Timer(self.cfg.request_timeout, self.abort_request, (request,))
            deadline.daemon = True
            deadline.start()
            self.finish_request(request, client_address)
        except (OSError, ValueError):
            pass  # Routine disconnect, TLS timeout or malformed request; do not log secrets.
        finally:
            if deadline:
                deadline.cancel()
            self.shutdown_request(request)
            self.slots.release()


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    cfg = Config(root=Path(os.getenv("AGG_DATA", "/var/lib/vpn-dist/current")),
                 cert=os.environ["AGG_CERT"], key=os.environ["AGG_KEY"],
                 port=int(os.getenv("AGG_PORT", "2087")),
                 sub_port=int(os.getenv("SUB_PORT", "2096")),
                 sub_scheme=os.getenv("SUB_SCHEME", "http"),
                 sub_path=os.getenv("SUB_PATH", "/sub/"), sub_ca=os.getenv("SUB_CA", ""))
    with Server(cfg) as server:
        signal.signal(signal.SIGHUP, lambda *_: server.reload_requested.set())
        LOG.info("config distributor listening on port %d", cfg.port)
        server.serve_forever(poll_interval=0.2)


if __name__ == "__main__":
    main()
