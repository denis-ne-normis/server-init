"""Certificate decisions and key-preserving TLS resume. Host commands are mocked here."""
import copy
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_reliability import fixture, make_cert
import bootstrap_tls as tls
import provision


class TLSBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'acme'
        self.home.mkdir()
        (self.home / 'acme.sh').touch()
        self.dest = self.root / 'deployed'
        self.log = self.root / 'private.log'
        self.calls = []

    def runner(self, args, **kwargs):
        self.calls.append(args)
        return SimpleNamespace(returncode=0, stdout='', stderr='')

    def ensure(self):
        tls.ensure_certificate('127.0.0.1', self.home, self.dest, self.log)

    def test_verified_cache_prevents_second_issuance(self):
        self.dest.mkdir()
        (self.dest / 'private.key').touch()
        with patch.object(tls, 'usable_pair', return_value=True), patch.object(tls.vpnctl, 'run', side_effect=self.runner):
            self.ensure()
        self.assertEqual(len(self.calls), 1)
        self.assertIn('--install-cert', self.calls[0])
        self.assertFalse(any('--issue' in call or '--force' in call for call in self.calls))

    def test_acme_skip_two_is_accepted_only_after_verification(self):
        self.dest.mkdir()
        (self.dest / 'private.key').touch()
        def runner(args, **kwargs):
            self.calls.append(args)
            return SimpleNamespace(returncode=2 if '--issue' in args else 0, stdout='Skip, Next renewal time', stderr='')
        with patch.object(tls, 'usable_pair', side_effect=[False, True, True]), patch.object(tls.vpnctl, 'run', side_effect=runner), patch.object(tls.socket, 'socket'):
            self.ensure()
        self.assertEqual(len(self.calls), 2)
        self.assertNotIn('--force', self.calls[0])

    def test_acme_skip_without_certificate_is_not_success(self):
        with patch.object(tls, 'usable_pair', return_value=False), patch.object(tls.vpnctl, 'run', return_value=SimpleNamespace(returncode=2, stdout='Skip', stderr='')), patch.object(tls.socket, 'socket'):
            with self.assertRaisesRegex(RuntimeError, 'verification failed'):
                self.ensure()

    def test_exit_zero_with_invalid_cert_is_not_success(self):
        with patch.object(tls, 'usable_pair', return_value=False), patch.object(tls.vpnctl, 'run', side_effect=self.runner), patch.object(tls.socket, 'socket'):
            with self.assertRaisesRegex(RuntimeError, 'verification failed'):
                self.ensure()
        self.assertFalse(any('--install-cert' in call for call in self.calls))

    def test_failure_reports_code_not_raw_secrets(self):
        result = SimpleNamespace(returncode=1, stdout='private-key-DONT-PRINT\nconnection refused', stderr='')
        with patch.object(tls, 'usable_pair', return_value=False), patch.object(tls.vpnctl, 'run', return_value=result), patch.object(tls.socket, 'socket'):
            with self.assertRaises(RuntimeError) as error:
                self.ensure()
        self.assertIn('ACME exit 1', str(error.exception))
        self.assertNotIn('private-key', str(error.exception))
        self.assertEqual(self.log.stat().st_mode & 0o777, 0o600)

    def test_busy_port_does_not_kill_any_service(self):
        with patch.object(tls, 'usable_pair', return_value=False), patch.object(tls.vpnctl, 'run') as run, patch.object(tls.socket, 'socket', side_effect=OSError):
            with self.assertRaisesRegex(RuntimeError, 'TCP 80'):
                self.ensure()
            run.assert_not_called()

    def test_real_certificate_key_ip_and_trust_checks(self):
        cert, key = make_cert(self.root, 'pair')
        cert2, key2 = make_cert(self.root, 'other')
        self.assertTrue(tls.usable_pair(cert, key, '127.0.0.1', cert, min_seconds=0))
        self.assertFalse(tls.usable_pair(cert, key2, '127.0.0.1', cert, min_seconds=0))
        self.assertFalse(tls.usable_pair(cert, key, '127.0.0.2', cert, min_seconds=0))
        self.assertFalse(tls.usable_pair(cert, key, '127.0.0.1', cert2, min_seconds=0))
        self.assertFalse(tls.usable_pair(cert, key, '127.0.0.1', cert, min_seconds=10 * 86400))


class ResumeTLS(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.exports = self.root / 'state'
        self.conf = self.root / 'awg.conf'
        self.db = self.root / 'panel.db'
        self.bundle = fixture()
        provision.render(self.bundle, self.exports, self.conf, qr=False)
        (self.exports / 'state.json').write_text(json.dumps(self.bundle))
        with sqlite3.connect(self.db) as db:
            db.execute('CREATE TABLE inbounds (id INTEGER)')
        p = patch.object(tls.vpnctl, 'verify_awg')
        p.start(); self.addCleanup(p.stop)
        p = patch.object(tls.vpnctl, 'run', return_value=SimpleNamespace(stdout=''))
        self.run = p.start(); self.addCleanup(p.stop)

    def check(self):
        return tls.check_resume(self.exports, self.conf, self.db)

    def test_resume_retains_every_saved_identity_byte(self):
        before = {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(self.check(), self.bundle['settings'])
        self.assertEqual(self.check(), self.bundle['settings'])
        after = {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(before, after)

    def test_any_inbound_blocks_resume(self):
        with sqlite3.connect(self.db) as db:
            db.execute('INSERT INTO inbounds VALUES (1)')
        with self.assertRaisesRegex(ValueError, 'inbound'):
            self.check()

    def test_live_interface_blocks_resume(self):
        self.run.return_value.stdout = 'awg0'
        with self.assertRaisesRegex(ValueError, 'live AWG'):
            self.check()

    def test_changed_export_blocks_resume(self):
        (self.exports / 'dist/test-client.vpn').write_text('different')
        with self.assertRaisesRegex(ValueError, 'exports'):
            self.check()

    def test_changed_state_blocks_resume(self):
        bundle = copy.deepcopy(self.bundle)
        bundle['settings']['VLESS_PORT'] = '4444'
        (self.exports / 'state.json').write_text(json.dumps(bundle))
        with self.assertRaisesRegex(ValueError, 'disagree'):
            self.check()

    def test_missing_inbound_payload_blocks_resume(self):
        (self.exports / 'inbound.json').unlink()
        with self.assertRaisesRegex(ValueError, 'exports'):
            self.check()

    def test_symlink_export_blocks_resume(self):
        p = self.exports / 'dist/test-client.vless'
        other = self.root / 'link'
        shutil.copyfile(p, other); p.unlink(); p.symlink_to(other)
        with self.assertRaisesRegex(ValueError, 'exports'):
            self.check()
