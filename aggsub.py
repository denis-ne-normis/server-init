#!/usr/bin/env python3
# Раздача персональных конфигов: /p/<subId> (страница: AWG-QR + VLESS), /awg/<subId>[/LABEL], /sub/<subId>.
# Запускается systemd-юнитом aggsub (env: AGG_PORT, SUB_PORT, AGG_CERT, AGG_KEY).
import http.server, ssl, urllib.request, base64, socketserver, os, html as HX
AGG_PORT = int(os.environ.get("AGG_PORT", "2087"))
SUB_PORT = os.environ.get("SUB_PORT", "2096")
SERVERS  = [("127.0.0.1:%s" % SUB_PORT, "")]      # один локальный сервер 3x-ui
CTX = ssl._create_unverified_context()
AWGDIR = "/root/vpn-setup/awg/clients"; AWGQR = "/root/vpn-setup/awg/qr"; DIST = "/root/vpn-setup/dist"

def submap():
    m = {}
    try:
        for line in open("/root/vpn-setup/awg/submap.tsv"):
            line = line.rstrip("\n")
            if "\t" in line:
                s, n = line.split("\t", 1); m[s] = n
    except Exception:
        pass
    return m

def b64img(p):
    try:
        return base64.b64encode(open(p, "rb").read()).decode()
    except Exception:
        return ""

def srvlabel():
    try:
        return open("/root/vpn-setup/awg/label").read().strip()
    except Exception:
        return ""

def ppage(name, sub):
    vless = ""
    try:
        vless = open(os.path.join(DIST, name + ".vless")).read().strip()
    except Exception:
        pass
    aqr = b64img(os.path.join(AWGQR, name + ".png")); vqr = b64img(os.path.join(DIST, name + "-vless.png")); e = HX.escape
    return """<!doctype html><html lang=ru><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>VPN %(n)s</title>
<style>
body{font-family:-apple-system,Roboto,Segoe UI,sans-serif;background:#0e1018;color:#eef;margin:0;padding:18px;text-align:center}
.w{max-width:540px;margin:0 auto}h1{font-size:22px;margin:6px 0 2px}.muted{color:#8b90a8;font-size:13px;margin-bottom:14px}
.card{background:#171a2b;border-radius:18px;padding:20px;margin:14px 0;box-shadow:0 8px 30px rgba(0,0,0,.35)}
.card h2{font-size:17px;margin:0 0 4px}.tag{display:inline-block;font-size:11px;padding:2px 8px;border-radius:20px;margin-bottom:10px}
.t1{background:#1f3a2a;color:#7fe0a0}.t2{background:#28304d;color:#9bb4ff}
img.qr{width:300px;max-width:92vw;background:#fff;padding:10px;border-radius:12px;image-rendering:pixelated;image-rendering:crisp-edges}
a.b{display:block;text-decoration:none;color:#fff;font-weight:600;padding:13px;border-radius:11px;margin:10px 0;font-size:16px}
.g{background:#2f9e5b}textarea{width:100%%;height:64px;border-radius:9px;border:1px solid #2a2f4a;background:#0e1018;color:#8b90a8;font-size:10px;padding:7px;box-sizing:border-box}
button.c{background:#2a2f4a;color:#fff;border:0;border-radius:9px;padding:10px 16px;margin-top:6px;font-size:14px}
ol{text-align:left;color:#c7cbe0;font-size:14px;line-height:1.55;padding-left:18px;margin:8px 0}
.store{font-size:12px;color:#8b90a8;margin-top:8px}.store a{color:#9bb4ff;margin:0 5px}
</style></head><body><div class=w>
<h1>VPN — %(n)s</h1><div class=muted>сервер <b>%(lbl)s</b> · твои личные конфиги, никому не пересылай</div>
<div class=card><span class="tag t1">ОСНОВНОЙ</span><h2>Amnezia (AmneziaWG)</h2>
<ol><li>Установи приложение <b>AmneziaVPN</b> (внизу ссылки).</li>
<li>В приложении: «+» → «QR-код», отсканируй код ниже. Или «Файл с настройками» → кнопка «Скачать конфиг».</li>
<li>Нажми «Подключиться».</li></ol>
%(aqr)s
<a class="b g" href="/awg/%(sub)s" download>Скачать конфиг Amnezia</a>
<div class=store><a href="https://play.google.com/store/apps/details?id=org.amnezia.vpn">Android</a> · <a href="https://apps.apple.com/app/id1600529900">iPhone</a> · <a href="https://amnezia.org/downloads">ПК</a></div></div>
<div class=card><span class="tag t2">РЕЗЕРВ / РОУТЕР</span><h2>Hiddify (VLESS Reality)</h2>
<ol><li>Установи <b>Hiddify</b> (внизу), включи Xray-core в настройках.</li>
<li>Отсканируй QR ниже («+» → «Сканировать») или скопируй ссылку → «Добавить из буфера». На роутер — эту ссылку в xkeen.</li>
<li>Подключайся.</li></ol>
%(vqr)s
<textarea id=v readonly>%(vless)s</textarea>
<button class=c onclick="navigator.clipboard.writeText(document.getElementById('v').value);this.textContent='Скопировано'">Скопировать VLESS</button>
<div class=store><a href="https://play.google.com/store/apps/details?id=app.hiddify.com">Android</a> · <a href="https://apps.apple.com/app/id6596777532">iPhone</a> · <a href="https://hiddify.com/">ПК</a></div></div>
</div></body></html>""" % {"n": e(name), "sub": e(sub), "vless": e(vless), "lbl": e(srvlabel() or "—"),
        "aqr": ('<img class=qr src="data:image/png;base64,%s">' % aqr) if aqr else "<i>нет QR</i>",
        "vqr": ('<img class=qr src="data:image/png;base64,%s">' % vqr) if vqr else "<i>нет QR</i>"}

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        parts = [x for x in self.path.split("?")[0].strip("/").split("/") if x]
        if len(parts) >= 2 and parts[0] == "sub":
            subid = parts[1]; lines = []
            for host, label in SERVERS:
                try:
                    raw = urllib.request.urlopen("https://%s/sub/%s" % (host, subid), context=CTX, timeout=6).read()
                    try: dec = base64.b64decode(raw).decode("utf-8", "ignore")
                    except Exception: dec = raw.decode("utf-8", "ignore")
                    for l in dec.splitlines():
                        l = l.strip()
                        if l and "://" in l:
                            if label: l = (l + "-" + label) if "#" in l else (l + "#" + label)
                            lines.append(l)
                except Exception: pass
            body = base64.b64encode(("\n".join(lines) + "\n").encode())
            self.send_response(200); self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Profile-Update-Interval", "12"); self.end_headers(); self.wfile.write(body)
        elif len(parts) >= 2 and parts[0] == "p":
            name = submap().get(parts[1])
            if name:
                out = ppage(name, parts[1]).encode("utf-8")
                self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out); return
            self.send_response(404); self.end_headers()
        elif len(parts) >= 2 and parts[0] == "awg":
            name = submap().get(parts[1])
            if name:
                p = os.path.join(AWGDIR, "%s.conf" % name)
                if os.path.isfile(p):
                    data = open(p, "rb").read()
                    self.send_response(200); self.send_header("Content-Type", "text/plain; charset=utf-8")
                    lbl = srvlabel(); fn = ("%s-%s" % (lbl, name)) if lbl else name
                    self.send_header("Content-Disposition", 'attachment; filename="%s.conf"' % fn)
                    self.end_headers(); self.wfile.write(data); return
            self.send_response(404); self.end_headers()
        else:
            self.send_response(404); self.end_headers()

class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

srv = S(("0.0.0.0", AGG_PORT), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.environ["AGG_CERT"], os.environ["AGG_KEY"])
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
