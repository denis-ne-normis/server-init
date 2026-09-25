"""Migration/certificate regressions added during the pre-merge review.
Host mutations are replaced; real file rendering, TLS pairs and parsing remain.
"""
import base64
import contextlib
import json
import os
from pathlib import Path
import shlex
import ssl
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zlib

import aggsub
import provision
import vpnctl
from test_reliability import fixture, make_cert, KEYS


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'state'
        self.source.mkdir()
        self.bundle = fixture()
        self.state = self.bundle['settings']
        self.conf = self.source / 'awg.conf'
        provision.render(self.bundle, self.source, self.conf, qr=False)
        self.cert, self.key = make_cert(self.root, 'panel')
        self.settings = {'webCertFile': self.cert, 'webKeyFile': self.key,
                         'subPort': '2096', 'subPath': '/sub/', 'subCertFile': '', 'subKeyFile': ''}
        self.commands = []
        self.units = {}
        self.real_atomic = vpnctl.atomic

    def public(self, private):
        return {KEYS[0]: KEYS[2], KEYS[1]: KEYS[3]}[private]

    def runner(self, args, **kwargs):
        args = list(map(str, args))
        self.commands.append(args)
        out = ''
        if args == ['awg', 'show', 'awg0', 'public-key']:
            out = KEYS[2]
        elif args == ['awg', 'show', 'awg0', 'listen-port']:
            out = '39743'
        elif args == ['awg', 'show', 'awg0', 'peers']:
            out = KEYS[3]
        return SimpleNamespace(returncode=0, stdout=out)

    def sandbox(self):
        stack = contextlib.ExitStack()
        for key, value in {'ROOT': self.source, 'AWG_CONF': self.conf,
                           'LIB': self.root / 'lib', 'DATA': self.root / 'data', 'ETC': self.root / 'etc'}.items():
            stack.enter_context(patch.object(vpnctl, key, value))
        stack.enter_context(patch.object(vpnctl, 'run', side_effect=self.runner))
        stack.enter_context(patch.object(vpnctl, 'pubkey', side_effect=self.public))
        # Existing function defaults bind production paths at import time.
        verify = vpnctl.verify_awg
        stack.enter_context(patch.object(vpnctl, 'verify_awg', side_effect=lambda s: verify(s, self.source, self.conf, self.public)))
        stack.enter_context(patch.object(vpnctl, 'db_settings', return_value=self.settings))
        stack.enter_context(patch.object(vpnctl.shutil, 'chown'))
        return stack

    def test_preflight_rejects_invalid_backend_before_any_mutation(self):
        for values in ({'subPort': '99999'}, {'subPath': '/bad path/'}, {'subEnable': 'false'},
                       {'subListen': '203.0.113.10'}, {'subKeyFile': 'without-cert'}):
            original = dict(self.settings)
            self.settings.update(values)
            with self.subTest(values=values), self.sandbox(), patch.object(vpnctl, 'backup') as backup, patch.object(vpnctl, 'publish') as publish:
                with self.assertRaises(ValueError):
                    vpnctl.repair(self.state)
                backup.assert_not_called()
                publish.assert_not_called()
                self.assertFalse(any(c[0] in {'systemctl', 'useradd'} for c in self.commands))
            self.settings.clear(); self.settings.update(original)

    def test_missing_export_is_rejected_before_backup_and_services(self):
        (self.source / 'dist/test-client.vpn').unlink()
        with self.sandbox(), patch.object(vpnctl, 'backup') as backup:
            with self.assertRaises(FileNotFoundError):
                vpnctl.repair(self.state)
            backup.assert_not_called()
            self.assertFalse(any(c[0] == 'systemctl' for c in self.commands))

    def test_valid_legacy_exports_pass_read_only_preflight(self):
        with self.sandbox():
            before = {p: p.read_bytes() for p in self.source.rglob('*') if p.is_file()}
            vpnctl.verify_exports(self.state)
            self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_stale_native_key_is_not_published_with_fresh_conf(self):
        path = self.source / 'dist/test-client.vpn'
        original = path.read_text()[6:]
        packed = base64.urlsafe_b64decode(original + '=' * (-len(original) % 4))
        outer = json.loads(zlib.decompress(packed[4:]))
        last = json.loads(outer['containers'][0]['awg']['last_config'])
        last['config'] = last['config'].replace(KEYS[1], KEYS[4])
        outer['containers'][0]['awg']['last_config'] = json.dumps(last)
        raw = json.dumps(outer).encode()
        path.write_text('vpn://' + base64.urlsafe_b64encode(len(raw).to_bytes(4, 'big') + zlib.compress(raw)).decode())
        with self.sandbox(), patch.object(vpnctl, 'backup') as backup:
            with self.assertRaisesRegex(ValueError, 'native Amnezia export differs'):
                vpnctl.repair(self.state)
            backup.assert_not_called()

    def test_stale_vless_key_rejected(self):
        path = self.source / 'dist/test-client.vless'
        path.write_text(path.read_text().replace('test-only-public', 'wrong-public'))
        with self.sandbox(), self.assertRaisesRegex(ValueError, 'VLESS export'):
            vpnctl.verify_exports(self.state)

    def test_native_decompression_is_bounded(self):
        raw = b' ' * (1024 * 1024 + 1)
        encoded = base64.urlsafe_b64encode(len(raw).to_bytes(4, 'big') + zlib.compress(raw))
        (self.source / 'dist/test-client.vpn').write_text('vpn://' + encoded.decode())
        with self.sandbox(), self.assertRaises(ValueError):
            vpnctl.verify_exports(self.state)

    def test_live_key_and_missing_peers_are_rejected_before_adoption(self):
        for key in ('public-key', 'peers'):
            def run(args, **kwargs):
                result = self.runner(args, **kwargs)
                if args[-1] == key:
                    result.stdout = 'mismatch'
                return result
            with self.subTest(key=key), self.sandbox(), patch.object(vpnctl, 'run', side_effect=run):
                with self.assertRaisesRegex(ValueError, 'live AWG'):
                    vpnctl.awg_start()
                self.assertFalse(any('up' in c or 'down' in c for c in self.commands))

    def test_expired_self_signed_rejected_before_backup(self):
        with self.sandbox(), patch.object(vpnctl, 'certificate_valid', return_value=False), patch.object(vpnctl, 'backup') as backup:
            with self.assertRaisesRegex(ValueError, 'expired certificate'):
                vpnctl.repair(self.state)
            backup.assert_not_called()

    def test_subscription_root_path_supported(self):
        self.settings['subPath'] = '/'
        with self.sandbox():
            self.assertEqual(vpnctl.subscription_environment(self.state, self.settings)['SUB_PATH'], '/')
        aggsub.Config(root=self.source, cert=self.cert, key=self.key, sub_path='/')

    def test_certificate_deploy_refreshes_upstream_trust_after_rotation(self):
        self.settings.update(subCertFile=self.cert, subKeyFile=self.key)
        with self.sandbox():
            vpnctl.deploy_certificate(self.settings)
            old = (vpnctl.ETC / 'sub-ca.pem').read_bytes()
            cert, key = make_cert(self.root, 'rotated')
            self.settings.update(webCertFile=cert, webKeyFile=key, subCertFile=cert, subKeyFile=key)
            vpnctl.deploy_certificate(self.settings)
            self.assertNotEqual(old, (vpnctl.ETC / 'sub-ca.pem').read_bytes())
            self.assertEqual(Path(cert).read_bytes(), (vpnctl.ETC / 'sub-ca.pem').read_bytes())
            self.assertEqual((vpnctl.ETC / 'sub-ca.pem').stat().st_mode & 0o777, 0o640)
            self.assertFalse(any('awg-quick@awg0' in c for c in self.commands))

    def test_healthy_legacy_certificate_hook_migrates_without_issuance(self):
        self.settings.update(webCertFile='/root/cert/le/fullchain.pem', webKeyFile='/root/cert/le/private.key')
        with self.sandbox():
            (vpnctl.ETC / 'tls').mkdir(parents=True)
            with patch.object(Path, 'is_file', return_value=True), patch.object(vpnctl, 'deploy_certificate'):
                vpnctl.cert_renew(self.state)
            self.assertTrue(any('--install-cert' in c and '/usr/local/bin/vpnctl cert-deploy' in c for c in self.commands))
            self.assertFalse(any('--issue' in c or '--force' in c for c in self.commands))

    def test_command_timeout_does_not_expose_arguments(self):
        with patch.object(subprocess, 'run', side_effect=subprocess.TimeoutExpired(['tool', 'secret-pass'], 1)):
            with self.assertRaises(RuntimeError) as error:
                vpnctl.run(['tool', 'secret-pass'])
        self.assertNotIn('secret-pass', str(error.exception))

    def test_repair_twice_preserves_identity_files_and_never_touches_firewall(self):
        before = {p: p.read_bytes() for p in self.source.rglob('*') if p.is_file()}
        snapshots = []
        def snapshot():
            snapshots.append(dict(before)); return self.root / 'private-backup.tar.gz'
        def atomic(path, text, mode=0o600):
            # Only the CLI launcher uses an absolute system path in this test.
            if str(path) == '/usr/local/bin/vpnctl':
                path = self.root / 'bin/vpnctl'
            self.real_atomic(path, text, mode)
        with self.sandbox(), patch.object(vpnctl, 'backup', side_effect=snapshot), patch.object(vpnctl, 'atomic', side_effect=atomic), patch.object(vpnctl, 'install_unit', side_effect=lambda n, s: self.units.update({n: s})), patch.object(vpnctl, 'wait_distribution') as wait:
            vpnctl.repair(self.state)
            vpnctl.repair(self.state)
            self.assertEqual(wait.call_count, 2)
            self.assertTrue((vpnctl.DATA / 'current/dist/test-client.vpn').exists())
            self.assertTrue((vpnctl.ETC / 'tls/cert.pem').exists())
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(vpnctl.ETC / 'tls/cert.pem', vpnctl.ETC / 'tls/key.pem')
        self.assertEqual(len(snapshots), 2)
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        self.assertFalse(any(c[0] in {'nft', 'apt-get', 'awg-quick'} for c in self.commands))
        self.assertFalse(any('genkey' in c or 'genpsk' in c for c in self.commands))
        self.assertIn('User=vpn-dist', self.units['aggsub.service'])
        self.assertIn('ExecStart=/usr/local/bin/vpnctl awg-start', self.units['awg-quick@awg0.service.d/server-init.conf'])

    def test_repair_readiness_failure_does_not_report_success(self):
        def atomic(path, text, mode=0o600):
            if str(path) == '/usr/local/bin/vpnctl': path = self.root / 'bin/vpnctl'
            self.real_atomic(path, text, mode)
        with self.sandbox(), patch.object(vpnctl, 'backup', return_value=self.root / 'backup.tar.gz'), patch.object(vpnctl, 'atomic', side_effect=atomic), patch.object(vpnctl, 'install_unit'), patch.object(vpnctl, 'wait_distribution', side_effect=RuntimeError('not ready')):
            with self.assertRaisesRegex(RuntimeError, 'not ready'):
                vpnctl.repair(self.state)


if __name__ == '__main__':
    unittest.main()
