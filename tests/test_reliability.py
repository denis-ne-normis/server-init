"""Regression suite: only temporary files, loopback sockets, and mocked host commands.
No test installs a VPN, changes the host firewall or calls a public VPN endpoint.
"""
import base64
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import aggsub
import provision
import vpnctl

TOKEN = "abcdefghijklmnopqrstuvwx"
OTHER = "zyxwvutsrqponmlkjihgfedcb"
KEYS = [base64.b64encode(bytes([i]) * 32).decode() for i in range(1, 6)]


def fixture():
    person = {"name": "test-client", "sub": TOKEN, "uuid": "12345678-1234-4234-9234-123456789012"}
    state = {"PANEL_PORT": "39000", "VLESS_PORT": "7443", "AWG_PORT": "39743", "SUB_PORT": "2096",
             "AGG_PORT": "2087", "AWG_SUBNET": "10.9.7", "PANEL_HOST": "203.0.113.10",
             "SNI_DONOR": "www.example.com", "CLIENTS_JSON": json.dumps([person]),
             "REALITY_PRIVATE_KEY": "test-only-private", "REALITY_PUBLIC_KEY": "test-only-public",
             "REALITY_SHORT_ID": "1234567890abcdef", "SRV_LABEL": "TEST", "AWG_MTU": "1376",
             "AWG_SRV_PRIV": KEYS[0], "BLOCK_SMTP": "1"}
    client = dict(person, private=KEYS[1], public=KEYS[3], psk=KEYS[4], ip="10.9.7.2")
    return {"schema": 1, "settings": state, "server_public": KEYS[2], "clients": [client]}


def make_cert(directory, stem):
    cert, key = Path(directory) / (stem + ".crt"), Path(directory) / (stem + ".key")
    subprocess.run(["openssl", "req", "-x509", "-nodes", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-days", "2", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=IP:127.0.0.1"], check=True, capture_output=True)
    return str(cert), str(key)


class StateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = fixture()

    def test_render_is_repeatable_without_new_keys(self):
        provision.render(self.bundle, self.root, self.root / "awg.conf", qr=False)
        before = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        with patch.object(provision, "run", side_effect=AssertionError("must not generate keys")):
            provision.render(self.bundle, self.root, self.root / "awg.conf", qr=False)
        after = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertEqual((self.root / "secrets.env").stat().st_mode & 0o777, 0o600)

    def test_awg_disk_consistency_and_mismatch(self):
        provision.render(self.bundle, self.root, self.root / "awg.conf", qr=False)
        public = lambda key: {KEYS[0]: KEYS[2], KEYS[1]: KEYS[3]}[key]
        vpnctl.verify_awg(self.bundle["settings"], self.root, self.root / "awg.conf", public)
        path = self.root / "awg/clients/test-client.conf"
        path.write_text(path.read_text().replace(KEYS[4], KEYS[0]))
        with self.assertRaisesRegex(ValueError, "PSK"):
            vpnctl.verify_awg(self.bundle["settings"], self.root, self.root / "awg.conf", public)

    def test_native_amnezia_format_contains_matching_config_and_mtu(self):
        provision.render(self.bundle, self.root, self.root / "awg.conf", qr=False)
        encoded = (self.root / "dist/test-client.vpn").read_text()[6:]
        packed = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        raw = zlib.decompress(packed[4:])
        self.assertEqual(struct.unpack(">I", packed[:4])[0], len(raw))
        outer = json.loads(raw)
        self.assertEqual(outer["defaultContainer"], "amnezia-awg2")
        last = json.loads(outer["containers"][0]["awg"]["last_config"])
        self.assertEqual(last["client_priv_key"], KEYS[1])
        self.assertIn("MTU = 1376", last["config"])
        self.assertIn("PersistentKeepalive = 25", last["config"])
        self.assertIn("$PRIMARY_DNS", last["config"])

    def test_existing_identity_state_refuses_regeneration(self):
        (self.root / "state.json").write_text("{}")
        with patch.object(provision, "ROOT", self.root), patch.object(provision, "AWG_CONF", self.root / "awg.conf"), patch.object(provision.os, "geteuid", return_value=0), patch.object(provision, "new_state") as generate:
            with self.assertRaisesRegex(ValueError, "existing identities"):
                provision.main()
            generate.assert_not_called()

    def test_existing_awg_config_without_secrets_also_blocks_regeneration(self):
        (self.root / "awg.conf").write_text("existing")
        with patch.object(provision, "ROOT", self.root), patch.object(provision, "AWG_CONF", self.root / "awg.conf"), patch.object(provision.os, "geteuid", return_value=0):
            with self.assertRaises(ValueError):
                provision.main()

    def test_legacy_shell_quoted_state_round_trip(self):
        provision.render(self.bundle, self.root, self.root / "awg.conf", qr=False)
        self.assertEqual(vpnctl.load_env(self.root / "secrets.env"), self.bundle["settings"])

    def test_legacy_state_is_parsed_not_executed(self):
        path = self.root / "evil.env"
        path.write_text("VALUE='$(touch /tmp/server-init-should-not-execute)'\n")
        self.assertEqual(vpnctl.load_env(path)["VALUE"], "$(touch /tmp/server-init-should-not-execute)")
        path.write_text("VALUE=ok; touch /tmp/server-init-should-not-execute\n")
        with self.assertRaises(ValueError):
            vpnctl.load_env(path)

    def test_duplicate_names_uuid_and_tokens_rejected(self):
        for key in ("name", "sub", "uuid"):
            state = dict(self.bundle["settings"])
            original = json.loads(state["CLIENTS_JSON"])[0]
            other = {"name": "another", "sub": OTHER, "uuid": "87654321-4321-4321-9321-210987654321"}
            other[key] = original[key]
            state["CLIENTS_JSON"] = json.dumps([original, other])
            with self.subTest(key=key), self.assertRaises(ValueError):
                vpnctl.validate_state(state)

    def test_port_conflict_and_invalid_input_rejected(self):
        for key, value in (("AGG_PORT", "39000"), ("VLESS_PORT", "99999"), ("AWG_SUBNET", "999.1.2"), ("PANEL_HOST", "example.org")):
            state = dict(self.bundle["settings"], **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                vpnctl.validate_state(state)

    def test_client_path_traversal_rejected(self):
        state = self.bundle["settings"]
        person = json.loads(state["CLIENTS_JSON"])[0]
        person["name"] = "../../etc/passwd"
        state["CLIENTS_JSON"] = json.dumps([person])
        with self.assertRaises(ValueError):
            vpnctl.validate_state(state)

    def test_distribution_cannot_escape_root_through_symlink(self):
        (self.root / "escape").symlink_to("/etc/passwd")
        with self.assertRaises(ValueError):
            aggsub.read_file(self.root, "escape")

    def test_firewall_preserves_custom_ssh_and_blocks_forwarded_smtp(self):
        text = vpnctl.firewall_text(self.bundle["settings"], "ens3", [2222, 22])
        self.assertIn("2222", text)
        self.assertNotIn("2096", text)  # local subscriptions do not need a public listener.
        self.assertIn('iifname "awg0" tcp dport { 25, 465, 587 } reject', text)
        self.assertIn("ip saddr 10.9.7.0/24", text)

    def test_firewall_interface_injection_rejected(self):
        with self.assertRaises(ValueError):
            vpnctl.firewall_text(self.bundle["settings"], 'eth0" accept', [22])


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certs = tempfile.TemporaryDirectory()
        cls.cert, cls.key = make_cert(cls.certs.name, "first")
        cls.cert2, cls.key2 = make_cert(cls.certs.name, "second")

    @classmethod
    def tearDownClass(cls):
        cls.certs.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        provision.render(fixture(), self.root, self.root / "awg.conf", qr=False)
        self.cfg = aggsub.Config(root=self.root, cert=self.cert, key=self.key, host="127.0.0.1", port=0,
                                 workers=4, handshake_timeout=0.5, request_timeout=0.5)
        self.server = aggsub.Server(self.cfg)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.temp.cleanup()

    def get(self, path):
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=ssl._create_unverified_context(), timeout=2)
        try:
            conn.request("GET", path)
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def test_page_and_private_downloads_still_work(self):
        for route in ("p", "awg", "vpn"):
            status, headers, data = self.get(f"/{route}/{TOKEN}")
            self.assertEqual(status, 200)
            self.assertTrue(data)
            self.assertEqual(headers["Cache-Control"], "no-store, max-age=0")
            self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(self.get("/healthz")[0], 200)

    def test_unknown_token_is_404_without_contacting_upstream(self):
        with patch.object(self.cfg, "upstream") as upstream:
            for route in ("p", "awg", "vpn", "sub"):
                self.assertEqual(self.get(f"/{route}/{OTHER}")[0], 404)
            upstream.assert_not_called()

    def test_encoded_traversal_and_extra_segments_rejected(self):
        for path in ("/awg/../../etc/passwd", "/p/%2e%2e", f"/sub/{TOKEN}/extra", f"/p/{TOKEN}/", "/p/x"):
            self.assertEqual(self.get(path)[0], 404)

    def test_missing_export_is_503_not_half_empty_page(self):
        (self.root / "dist/test-client.vpn").unlink()
        with self.assertLogs("aggsub", level="WARNING"):
            self.assertEqual(self.get(f"/p/{TOKEN}")[0], 503)

    def test_stalled_tls_handshake_does_not_block_other_clients(self):
        self.cfg.handshake_timeout = 3
        stalled = socket.create_connection(("127.0.0.1", self.port))
        try:
            time.sleep(0.05)
            before = time.monotonic()
            self.assertEqual(self.get(f"/p/{TOKEN}")[0], 200)
            self.assertLess(time.monotonic() - before, 1.5)
        finally:
            stalled.close()

    def test_worker_slots_released_after_handshake_timeout(self):
        connections = [socket.create_connection(("127.0.0.1", self.port)) for _ in range(4)]
        try:
            time.sleep(0.1)
            self.assertEqual(self.server.slots._value, 0)
            with self.assertRaises((OSError, ssl.SSLError, http.client.HTTPException)):
                self.get(f"/p/{TOKEN}")
            time.sleep(0.55)
            self.assertEqual(self.get(f"/p/{TOKEN}")[0], 200)
        finally:
            for connection in connections:
                connection.close()

    def test_slow_headers_have_total_deadline(self):
        conn = ssl._create_unverified_context().wrap_socket(socket.create_connection(("127.0.0.1", self.port)), server_hostname="localhost")
        conn.settimeout(1)
        started = time.monotonic()
        try:
            conn.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Slow: ")
            closed = False
            for _ in range(15):
                time.sleep(0.08)
                try:
                    conn.sendall(b"x")
                except OSError:
                    closed = True
                    break
            self.assertTrue(closed)
            self.assertLess(time.monotonic() - started, 1.3)
            self.assertEqual(self.get(f"/p/{TOKEN}")[0], 200)
        finally:
            conn.close()

    def test_tls_reload_swaps_certificate_without_restart(self):
        previous = self.server.context
        self.cfg.cert, self.cfg.key = self.cert2, self.key2
        self.server.reload_requested.set()
        self.server.service_actions()
        self.assertIsNot(previous, self.server.context)
        self.assertEqual(self.get(f"/p/{TOKEN}")[0], 200)

    def test_bad_certificate_reload_keeps_working_context(self):
        previous = self.server.context
        self.cfg.cert = str(self.root / "missing.pem")
        with self.assertLogs("aggsub", level="ERROR"):
            self.server.reload_requested.set()
            self.server.service_actions()
        self.assertIs(previous, self.server.context)
        self.assertEqual(self.get(f"/p/{TOKEN}")[0], 200)

    def test_actual_http_upstream_and_custom_port(self):
        payload = base64.b64encode(b"vless://test@127.0.0.1:7443\n")
        class Backend(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(payload)
        backend = ThreadingHTTPServer(("127.0.0.1", 0), Backend)
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        try:
            self.cfg.sub_port = backend.server_address[1]
            self.assertEqual(self.get(f"/sub/{TOKEN}")[2], payload)
        finally:
            backend.shutdown(); backend.server_close(); thread.join(2)

    def test_upstream_outage_is_503_and_logs_do_not_contain_token(self):
        with patch.object(self.cfg, "upstream", side_effect=OSError("backend unavailable")), self.assertLogs("aggsub", level="WARNING") as logs:
            status, _, data = self.get(f"/sub/{TOKEN}")
        self.assertEqual(status, 503)
        self.assertNotEqual(data, b"Cg==")
        self.assertNotIn(TOKEN, "\n".join(logs.output))

    def test_empty_or_invalid_subscription_is_rejected(self):
        for raw in (b"", b"Cg==", b"<html>error</html>", b"bm90IGEgc3Vic2NyaXB0aW9u"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                aggsub.decode_subscription(raw)

    def test_plain_and_base64_subscriptions(self):
        data = b"vless://test@127.0.0.1:7443\n"
        self.assertEqual(aggsub.decode_subscription(data), base64.b64encode(data))
        self.assertEqual(aggsub.decode_subscription(base64.b64encode(data)), base64.b64encode(data))


class HostSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.calls = []
        self.connection = "198.51.100.1 54321 203.0.113.10 2222"
        patcher = patch.object(vpnctl, "NFT_CONF", self.root / "persistent.nft")
        patcher.start()
        self.addCleanup(patcher.stop)

    def runner(self, args, **kwargs):
        args = [str(x) for x in args]
        self.calls.append(args)
        output = ""
        if args == ["ip", "-j", "address", "show"]:
            output = '[{"addr_info":[{"local":"203.0.113.10"},{"local":"127.0.0.1"}]}]'
        if args[:4] == ["ip", "-j", "-4", "route"]:
            output = '[{"dev":"ens3"}]'
        return SimpleNamespace(returncode=0, stdout=output)

    def apply(self):
        with patch.object(vpnctl, "FW", self.root), patch.object(vpnctl, "run", side_effect=self.runner), patch.dict(os.environ, SSH_CONNECTION=self.connection):
            vpnctl.firewall_apply(fixture()["settings"])
        return json.loads((self.root / "pending.json").read_text())

    def test_firewall_timer_is_armed_before_apply(self):
        self.apply()
        arm = next(i for i, args in enumerate(self.calls) if args[0] == "systemd-run")
        apply = next(i for i, args in enumerate(self.calls) if args[:3] == ["nft", "-f", str(self.root / "candidate.nft")])
        self.assertLess(arm, apply)
        self.assertTrue((self.root / "old.nft").exists())

    def test_failure_to_arm_timer_prevents_firewall_change(self):
        def runner(args, **kwargs):
            if args[0] == "systemd-run":
                raise RuntimeError("timer failed")
            return self.runner(args, **kwargs)
        with patch.object(vpnctl, "FW", self.root), patch.object(vpnctl, "run", side_effect=runner), patch.dict(os.environ, SSH_CONNECTION=self.connection):
            with self.assertRaises(RuntimeError):
                vpnctl.firewall_apply(fixture()["settings"])
        self.assertFalse((self.root / "pending.json").exists())
        self.assertFalse(any(args[:2] == ["nft", "-f"] for args in self.calls))

    def test_same_ssh_connection_cannot_confirm(self):
        pending = self.apply()
        with patch.object(vpnctl, "FW", self.root), patch.dict(os.environ, SSH_CONNECTION=self.connection):
            with self.assertRaises(ValueError):
                vpnctl.firewall_confirm(pending["token"])
        self.assertTrue((self.root / "pending.json").exists())

    def test_new_ssh_connection_can_persist_then_cancel_timer(self):
        pending = self.apply()
        writes = []
        with patch.object(vpnctl, "FW", self.root), patch.object(vpnctl, "run", side_effect=self.runner), patch.object(vpnctl, "atomic", side_effect=lambda *args: writes.append(args)), patch.dict(os.environ, SSH_CONNECTION=self.connection.replace("54321", "54322")):
            vpnctl.firewall_confirm(pending["token"])
        self.assertEqual(writes[0][0], self.root / "persistent.nft")
        self.assertFalse((self.root / "pending.json").exists())
        self.assertIn(["systemctl", "stop", pending["unit"] + ".timer"], self.calls)

    def test_rollback_restores_snapshot_not_unconditional_flush(self):
        pending = self.apply()
        self.calls.clear()
        with patch.object(vpnctl, "FW", self.root), patch.object(vpnctl, "run", side_effect=self.runner):
            vpnctl.firewall_rollback(pending["token"])
        self.assertEqual(self.calls, [["nft", "-f", str(self.root / "old.nft")]])
        self.assertFalse((self.root / "pending.json").exists())

    def test_stale_timer_cannot_rollback_new_transaction(self):
        self.apply()
        self.calls.clear()
        with patch.object(vpnctl, "FW", self.root), patch.object(vpnctl, "run", side_effect=self.runner):
            vpnctl.firewall_rollback("wrong-token")
        self.assertEqual(self.calls, [])
        self.assertTrue((self.root / "pending.json").exists())

    def test_recovery_does_not_restart_an_existing_interface(self):
        def runner(args, **kwargs):
            self.calls.append(args)
            return SimpleNamespace(returncode=0, stdout="active\n" if args[:2] == ["systemctl", "is-active"] else "")
        with patch.object(vpnctl, "run", side_effect=runner):
            vpnctl.recover()
        self.assertFalse(any("restart" in args for args in self.calls))
        self.assertFalse(any("latest-handshakes" in args for args in self.calls))

    def test_recovery_respects_intentional_stop(self):
        def runner(args, **kwargs):
            self.calls.append(args)
            return SimpleNamespace(returncode=0, stdout="inactive\n")
        with patch.object(vpnctl, "run", side_effect=runner):
            vpnctl.recover()
        self.assertFalse(any("restart" in args for args in self.calls))

    def test_recovery_starts_only_missing_configured_interface(self):
        conf = self.root / "awg.conf"; conf.write_text("configured")
        def runner(args, **kwargs):
            self.calls.append(args)
            return SimpleNamespace(returncode=1 if args[0] == "awg" else 0,
                                   stdout="active\n" if args[:2] == ["systemctl", "is-active"] else "")
        with patch.object(vpnctl, "AWG_CONF", conf), patch.object(vpnctl, "run", side_effect=runner):
            vpnctl.recover()
        self.assertIn(["systemctl", "restart", "awg-quick@awg0"], self.calls)
        self.assertFalse(any("genkey" in args for args in self.calls))


class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.settings = {"webCertFile": "/root/cert/le/fullchain.pem", "webKeyFile": "/root/cert/le/private.key"}
        self.calls = []

    def runner(self, args, **kwargs):
        self.calls.append(args)
        return SimpleNamespace(returncode=0, stdout="")

    def test_healthy_certificate_is_not_force_renewed(self):
        with patch.object(vpnctl, "db_settings", return_value=self.settings), patch.object(Path, "is_file", return_value=True), patch.object(vpnctl, "certificate_valid", return_value=True), patch.object(vpnctl, "ETC", self.root), patch.object(vpnctl, "run", side_effect=self.runner):
            vpnctl.cert_renew(fixture()["settings"])
        self.assertEqual(self.calls, [])

    def test_expiring_certificate_uses_short_profile_and_no_awg_restart(self):
        with patch.object(vpnctl, "db_settings", return_value=self.settings), patch.object(Path, "is_file", return_value=True), patch.object(vpnctl, "certificate_valid", return_value=False), patch.object(vpnctl, "deploy_certificate") as deploy, patch.object(vpnctl, "run", side_effect=self.runner):
            vpnctl.cert_renew(fixture()["settings"])
        issue = next(args for args in self.calls if "--issue" in args)
        self.assertIn("shortlived", issue)
        self.assertEqual(issue[issue.index("--days") + 1], "3")
        self.assertIn("--force", issue)
        self.assertEqual(self.calls[0][-1], "/bin/true")
        self.assertTrue(any("/usr/local/bin/vpnctl cert-deploy" in args for args in self.calls))
        self.assertFalse(any("awg-quick@awg0" in args for args in self.calls))
        deploy.assert_called_once_with(self.settings)

    def test_self_signed_certificate_is_not_silently_replaced(self):
        self.settings["webCertFile"] = "/root/cert/panel/cert.crt"
        with patch.object(vpnctl, "db_settings", return_value=self.settings), patch.object(vpnctl, "run", side_effect=self.runner):
            with self.assertRaises(ValueError):
                vpnctl.cert_renew(fixture()["settings"])
        self.assertEqual(self.calls, [])

    def test_failed_issuance_does_not_restart_services(self):
        def runner(args, **kwargs):
            self.calls.append(args)
            if "--issue" in args:
                raise RuntimeError("CA unavailable")
            return SimpleNamespace(returncode=0, stdout="")
        with patch.object(vpnctl, "db_settings", return_value=self.settings), patch.object(Path, "is_file", return_value=True), patch.object(vpnctl, "certificate_valid", return_value=False), patch.object(vpnctl, "run", side_effect=runner):
            with self.assertRaises(RuntimeError):
                vpnctl.cert_renew(fixture()["settings"])
        self.assertFalse(any(args[0] == "systemctl" for args in self.calls))


if __name__ == "__main__":
    unittest.main()
