"""Router exports, migration without rekeying, and installer choices."""
import contextlib
import copy
import io
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import provision
import reality_setup
import vpnctl
import xray_profile
from test_reliability import fixture, HTTPTests, TOKEN, OTHER


class RouterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = fixture()
        self.state = self.bundle['settings']
        provision.render(self.bundle, self.root, self.root / 'awg.conf', qr=False)
        self.path = self.root / 'dist/test-client-04_outbounds.json'

    def test_json_matches_link_and_inbound_for_each_fingerprint_and_port(self):
        for fp, port in (('chrome', '443'), ('firefox', '7443'), ('safari', '18443')):
            self.state.update(REALITY_FINGERPRINT=fp, VLESS_PORT=port)
            provision.render(self.bundle, self.root, self.root / 'awg.conf', qr=False)
            config = json.loads(self.path.read_text())
            self.assertEqual([x['tag'] for x in config['outbounds']], ['vless-reality', 'direct', 'block'])
            outbound = config['outbounds'][0]
            server = outbound['settings']['vnext'][0]
            self.assertEqual(server['port'], int(port))
            self.assertEqual(server['users'][0]['id'], self.bundle['clients'][0]['uuid'])
            inbound = json.loads((self.root / 'inbound.json').read_text())
            reality = json.loads(inbound['streamSettings'])['realitySettings']
            self.assertEqual(outbound['streamSettings']['realitySettings']['serverName'], reality['serverNames'][0])
            self.assertEqual(outbound['streamSettings']['realitySettings']['fingerprint'], fp)
            self.assertNotIn('privateKey', self.path.read_text())
            self.assertNotIn(self.state['AWG_SRV_PRIV'], self.path.read_text())
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
            with patch.object(vpnctl, 'ROOT', self.root):
                vpnctl.verify_exports(self.state)

    def test_legacy_repair_adds_only_router_file_preserving_old_fingerprint(self):
        link = self.root / 'dist/test-client.vless'
        link.write_text(link.read_text().replace('fp=chrome', 'fp=firefox').replace('&type=tcp', ''))
        self.path.unlink()
        before = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch.object(vpnctl, 'ROOT', self.root):
            vpnctl.verify_exports(self.state)
            self.assertFalse(self.path.exists())  # read-only preflight
            vpnctl.ensure_router_exports(self.state)
            vpnctl.ensure_router_exports(self.state)  # idempotent
            vpnctl.verify_exports(self.state)
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        self.assertEqual(json.loads(self.path.read_text())['outbounds'][0]['streamSettings']['realitySettings']['fingerprint'], 'firefox')

    def test_stale_or_symlink_router_file_is_not_overwritten(self):
        config = json.loads(self.path.read_text())
        config['outbounds'][0]['settings']['vnext'][0]['port'] = 1234
        self.path.write_text(json.dumps(config))
        with patch.object(vpnctl, 'ROOT', self.root):
            with self.assertRaisesRegex(ValueError, 'XKeen'):
                vpnctl.verify_exports(self.state)
            with self.assertRaisesRegex(ValueError, 'XKeen'):
                vpnctl.ensure_router_exports(self.state)
            self.path.unlink()
            self.path.symlink_to(self.root / 'missing.json')
            with self.assertRaisesRegex(ValueError, 'XKeen'):
                vpnctl.verify_exports(self.state)

    def test_unsupported_link_options_and_wrong_identities_fail_closed(self):
        link = (self.root / 'dist/test-client.vless').read_text()
        for invalid in (link.replace('type=tcp', 'type=xhttp'), link.replace('encryption=none', 'encryption=unsupported'),
                        link.replace('fp=chrome', 'fp=edge'), link.replace('security=reality', 'security=none'),
                        link.replace('sid=', 'sid=bad&sid='), link.replace('spx=', 'extra=1&spx='),
                        link.replace(':7443?', ':443?')):
            with self.subTest(link='redacted'), self.assertRaises(ValueError):
                xray_profile.xkeen_config(invalid, self.state, self.bundle['clients'][0])

    def test_multiple_clients_get_their_own_uuid(self):
        second = copy.deepcopy(self.bundle['clients'][0])
        second.update(name='second', sub=OTHER, uuid='22345678-1234-4234-9234-123456789012', ip='10.9.7.3')
        self.bundle['clients'].append(second)
        self.state['CLIENTS_JSON'] = json.dumps([{k: p[k] for k in ('name', 'uuid', 'sub')} for p in self.bundle['clients']])
        provision.render(self.bundle, self.root, self.root / 'awg.conf', qr=False)
        config = json.loads((self.root / 'dist/second-04_outbounds.json').read_text())
        self.assertEqual(config['outbounds'][0]['settings']['vnext'][0]['users'][0]['id'], second['uuid'])
        self.assertNotIn(self.bundle['clients'][0]['uuid'], json.dumps(config))


# Use the existing TLS fixture without importing another copy of its test class.
class RouterHTTPTests(unittest.TestCase):
    setUpClass = classmethod(HTTPTests.setUpClass.__func__)
    tearDownClass = classmethod(HTTPTests.tearDownClass.__func__)
    setUp = HTTPTests.setUp
    tearDown = HTTPTests.tearDown
    get = HTTPTests.get

    def test_authenticated_json_download_and_page(self):
        status, headers, data = self.get(f'/xkeen/{TOKEN}')
        self.assertEqual(status, 200)
        self.assertEqual(headers['Content-Disposition'], 'attachment; filename="04_outbounds.json"')
        self.assertEqual(headers['Content-Type'], 'application/json; charset=utf-8')
        self.assertIn('no-store', headers['Cache-Control'])
        self.assertEqual(json.loads(data), json.loads((self.root / 'dist/test-client-04_outbounds.json').read_text()))
        self.assertIn(f'/xkeen/{TOKEN}'.encode(), self.get(f'/p/{TOKEN}')[2])
        self.assertEqual(self.get(f'/xkeen/{OTHER}')[0], 404)
        self.assertEqual(self.get(f'/xkeen/{TOKEN}/04_outbounds.json')[0], 404)
        (self.root / 'dist/test-client-04_outbounds.json').unlink()
        with self.assertLogs('aggsub', level='WARNING'):
            self.assertEqual(self.get(f'/xkeen/{TOKEN}')[0], 503)


class ChoiceTests(unittest.TestCase):
    def choose(self, env, answers=None, check=None):
        with patch.object(reality_setup.socket, 'socket'), contextlib.redirect_stderr(io.StringIO()):
            return reality_setup.choose(env, answers is not None, iter(answers).__next__ if answers else input,
                                        check or (lambda host: (True, 10, 'OK')))

    def test_default_auto_uses_successful_fastest_candidate(self):
        results = {reality_setup.DONORS[0]: (False, 1, 'FAIL'), reality_setup.DONORS[1]: (True, 20, 'OK'), reality_setup.DONORS[2]: (True, 30, 'OK')}
        selected = self.choose({}, check=results.__getitem__)
        self.assertEqual(selected, {'SNI_DONOR': reality_setup.DONORS[1], 'VLESS_PORT': '443', 'REALITY_FINGERPRINT': 'chrome'})

    def test_menu_custom_and_presets(self):
        self.assertEqual(self.choose({}, ['4', 'target.example.com', '3', '18443', '2']),
                         {'SNI_DONOR': 'target.example.com', 'VLESS_PORT': '18443', 'REALITY_FINGERPRINT': 'firefox'})
        self.assertEqual(self.choose({}, ['3', '2', '1'])['VLESS_PORT'], '7443')
        custom = {'SNI_DONOR': 'other.example.com', 'VLESS_PORT': '9443', 'REALITY_FINGERPRINT': 'safari'}
        self.assertEqual(self.choose(custom, ['', '', '']), custom)

    def test_invalid_host_ports_and_failed_tls_stop_selection(self):
        for env in ({'SNI_DONOR': 'https://example.com'}, {'SNI_DONOR': 'bad..example.com'},
                    {'VLESS_PORT': '80'}, {'VLESS_PORT': '2096'}, {'VLESS_PORT': '0'}, {'VLESS_PORT': '65536'},
                    {'VLESS_PORT': 'abc'}, {'REALITY_FINGERPRINT': 'unsafe'}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                self.choose(env)
        with self.assertRaisesRegex(ValueError, 'нет подходящего'):
            self.choose({}, check=lambda host: (False, 0, 'FAIL'))

    def test_probe_checks_tls_h2_cert_and_redirects(self):
        tls = subprocess.CompletedProcess([], 0, 'New, TLSv1.3\nALPN protocol: h2\nVerify return code: 0 (ok)', '')
        head = subprocess.CompletedProcess([], 0, 'HTTP/1.1 200 OK\r\n', '')
        with patch.object(reality_setup.subprocess, 'run', side_effect=[tls, head]):
            self.assertTrue(reality_setup.probe('www.example.com')[0])
        for text in ('TLSv1.2\nALPN protocol: h2', 'TLSv1.3\nALPN protocol: http/1.1', 'TLSv1.3\nALPN protocol: h2\nVerify return code: 62'):
            with patch.object(reality_setup.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, text, '')):
                self.assertFalse(reality_setup.probe('www.example.com')[0])
        head.stdout = 'HTTP/1.1 301\r\nLocation: https://other.example.com/\r\n'
        with patch.object(reality_setup.subprocess, 'run', side_effect=[tls, head]):
            self.assertFalse(reality_setup.probe('www.example.com')[0])


del HTTPTests  # unittest discovery should not rerun the imported base suite.
