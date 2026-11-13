"""Real Xray: generated router JSON, REALITY/Vision handshake and HTTP traffic.

Only loopback listeners and temporary test keys. No user config or public target.
Usage: python3 tests/smoke_xkeen.py /path/to/xray [server-xray]
"""
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import provision
from test_reliability import fixture


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Echo(BaseHTTPRequestHandler):
    timeout = 2
    def log_message(self, *args):
        pass

    def do_GET(self):
        body = b'xkeen-reality-traffic-ok\n'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass  # REALITY can abort its decoy TLS connection; traffic is checked below.


def main():
    client_binary = Path(sys.argv[1]).resolve()
    server_binary = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else client_binary
    with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
        root = Path(temporary)
        cert, key = root / 'target.crt', root / 'target.key'
        provision.run(['openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '2',
                       '-keyout', key, '-out', cert, '-subj', '/CN=localhost.example.com',
                       '-addext', 'subjectAltName=DNS:localhost.example.com'])
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(cert, key)
        context.set_alpn_protocols(['h2', 'http/1.1'])
        target = QuietServer(('127.0.0.1', 0), Echo)
        target.socket = context.wrap_socket(target.socket, server_side=True, do_handshake_on_connect=False)
        http = QuietServer(('127.0.0.1', 0), Echo)
        for service in (target, http):
            threading.Thread(target=service.serve_forever, daemon=True).start()
            stack.callback(service.server_close)
            stack.callback(service.shutdown)
        result = provision.run([server_binary, 'x25519'])
        private, public = provision.parse_x25519(result.stdout, result.stderr)
        bundle = fixture()
        state = bundle['settings']
        state['VLESS_TRANSPORT'] = os.getenv('TEST_VLESS_TRANSPORT', 'tcp')
        state['XHTTP_PATH'] = '/smoke-profile'
        # Keep generated identities internally consistent; no test values printed.
        state.update(PANEL_HOST='127.0.0.1', VLESS_PORT=str(port()), SNI_DONOR='localhost.example.com',
                     REALITY_PRIVATE_KEY=private, REALITY_PUBLIC_KEY=public)
        server = {'log': {'loglevel': 'debug'}, 'inbounds': [{
            'listen': '127.0.0.1', 'port': int(state['VLESS_PORT']), 'protocol': 'vless',
            'settings': {'decryption': 'none', 'clients': [{'id': bundle['clients'][0]['uuid'], 'flow': 'xtls-rprx-vision'}]},
            'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {
                'target': f'127.0.0.1:{target.server_port}', 'serverNames': [state['SNI_DONOR']],
                'privateKey': private, 'shortIds': [state['REALITY_SHORT_ID']]}}
        }], 'outbounds': [{'protocol': 'freedom', 'settings': {
            # Only the disposable test server may proxy back to this local fixture.
            'finalRules': [{'action': 'allow', 'ip': ['127.0.0.1/32']}]}}]}
        if state['VLESS_TRANSPORT'] == 'xhttp':
            server['inbounds'][0]['settings']['clients'][0]['flow'] = ''
            server['inbounds'][0]['streamSettings'].update(network='xhttp', xhttpSettings={'mode': 'auto', 'path': state['XHTTP_PATH']})
        server_path = root / 'server.json'
        server_path.write_text(json.dumps(server))
        processes = []
        log = stack.enter_context((root / 'xray.log').open('w+'))

        def stop(process):
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

        def start(binary, config):
            provision.run([binary, 'run', '-test', '-config', config])
            process = subprocess.Popen([str(binary), 'run', '-config', str(config)], stdout=log, stderr=log)
            stack.callback(stop, process)
            processes.append(process)
            return process

        start(server_binary, server_path)
        for fp in ('chrome', 'firefox', 'safari'):
            state['REALITY_FINGERPRINT'] = fp
            provision.render(bundle, root, root / 'awg.conf', qr=False)
            exported = root / 'dist/test-client-04_outbounds.json'
            provision.run([client_binary, 'run', '-test', '-config', exported])
            client = json.loads(exported.read_text())
            socks_port = port()
            client.update(log={'loglevel': 'debug'}, inbounds=[{'listen': '127.0.0.1', 'port': socks_port,
                          'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': True}}])
            path = root / 'client.json'
            path.write_text(json.dumps(client))
            process = start(client_binary, path)
            for _ in range(10):
                if any(p.poll() is not None for p in processes):
                    raise RuntimeError('Xray exited before traffic check')
                result = subprocess.run(['curl', '--noproxy', '', '-fsS', '--max-time', '2', '--socks5-hostname',
                                         f'127.0.0.1:{socks_port}', f'http://127.0.0.1:{http.server_port}/'],
                                        capture_output=True, timeout=4)
                if result.returncode == 0 and result.stdout == b'xkeen-reality-traffic-ok\n':
                    break
                time.sleep(0.1)
            else:
                log.flush()
                log.seek(0)
                detail = log.read()
                for value in (private, public, bundle['clients'][0]['uuid'], state['REALITY_SHORT_ID']):
                    detail = detail.replace(value, '[test-identity]')
                print(detail[-4000:])
                raise RuntimeError(f'REALITY/Vision traffic failed for {fp}; no keys logged')
            print(f"PASS generated XKeen JSON + real {state['VLESS_TRANSPORT']}/REALITY HTTP traffic ({fp})")
            stop(process)
            processes.remove(process)


if __name__ == '__main__':
    main()
