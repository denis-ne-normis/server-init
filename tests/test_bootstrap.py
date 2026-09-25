"""Regressions for real Xray labels and the pre-identity bootstrap failure.
No package installs, public connections or changes to real server state.
"""
import base64
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import provision

PRIVATE, PUBLIC, HASH = [base64.urlsafe_b64encode(bytes([n]) * 32).decode().rstrip('=') for n in (1, 2, 3)]
MODERN = f'PrivateKey: {PRIVATE}\nPassword (PublicKey): {PUBLIC}\nHash32: {HASH}\n'


class XrayOutputTests(unittest.TestCase):
    def test_old_spaced_labels(self):
        self.assertEqual(provision.parse_x25519(f'Private key: {PRIVATE}\nPublic key: {PUBLIC}'), (PRIVATE, PUBLIC))

    def test_camel_case_labels(self):
        self.assertEqual(provision.parse_x25519(f'PrivateKey: {PRIVATE}\nPublicKey: {PUBLIC}'), (PRIVATE, PUBLIC))

    def test_password_label(self):
        self.assertEqual(provision.parse_x25519(f'PrivateKey: {PRIVATE}\nPassword: {PUBLIC}\nHash32: {HASH}'), (PRIVATE, PUBLIC))

    def test_v26_6_1_password_publickey_label(self):
        self.assertEqual(provision.parse_x25519(MODERN), (PRIVATE, PUBLIC))

    def test_stderr_whitespace_crlf(self):
        text = f' Private\tKey : {PRIVATE}\r\nPassword (Public Key): {PUBLIC}\r\n'
        self.assertEqual(provision.parse_x25519('', text), (PRIVATE, PUBLIC))

    def test_consistent_aliases_and_padding_are_normalized(self):
        self.assertEqual(provision.parse_x25519(MODERN, f'Public key: {PUBLIC}=\n'), (PRIVATE, PUBLIC))

    def test_hash32_is_never_used_as_public_key(self):
        with self.assertRaisesRegex(ValueError, 'missing private/public key'):
            provision.parse_x25519(f'PrivateKey: {PRIVATE}\nHash32: {HASH}')

    def test_conflicting_public_key_rejected(self):
        with self.assertRaisesRegex(ValueError, 'conflicting'):
            provision.parse_x25519(MODERN, f'PublicKey: {HASH}')

    def test_invalid_values_and_errors_do_not_echo_keys(self):
        for key in ('short-secret', 'A' * 44, PUBLIC[:-1] + '/', PUBLIC[:-1] + 'B'):
            with self.subTest(value_length=len(key)):
                with self.assertRaises(ValueError) as exc:
                    provision.parse_x25519(f'PrivateKey: {PRIVATE}\nPassword (PublicKey): {key}')
                self.assertNotIn(PRIVATE, str(exc.exception))
                self.assertNotIn(key, str(exc.exception))

    def test_actual_subprocess_stderr_capture(self):
        # Use the real run() wrapper, not a synthetic CompletedProcess only.
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'xray-test'
            binary.write_text(f'#!{sys.executable}\nimport sys\nsys.stderr.write({MODERN!r})\n')
            binary.chmod(0o700)
            result = provision.run([binary, 'x25519'])
            self.assertEqual(provision.parse_x25519(result.stdout, result.stderr), (PRIVATE, PUBLIC))

    def test_new_state_uses_parser_before_awg_generation(self):
        calls = []
        def runner(args, **kwargs):
            calls.append(args)
            output = MODERN if args == ['xray-test', 'x25519'] else base64.b64encode(bytes([4])*32).decode()+'\n'
            return SimpleNamespace(stdout=output, stderr='', returncode=0)
        env = {'PUBIP': '203.0.113.10', 'CLIENTS': 'one', 'PANEL_PORT': '39000'}
        with patch.object(provision, 'run', side_effect=runner):
            bundle = provision.new_state(env, 'xray-test')
        self.assertEqual(bundle['settings']['REALITY_PUBLIC_KEY'], PUBLIC)
        self.assertEqual(bundle['settings']['REALITY_PRIVATE_KEY'], PRIVATE)
        self.assertEqual(calls[0], ['xray-test', 'x25519'])

    def test_bad_output_cannot_reach_awg_generation(self):
        with patch.object(provision, 'run', return_value=SimpleNamespace(stdout='Hash32: '+HASH, stderr='')) as run:
            with self.assertRaises(ValueError):
                provision.new_state({'PUBIP': '203.0.113.10'}, 'xray-test')
            run.assert_called_once_with(['xray-test', 'x25519'])


class BootstrapResumeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'vpn-setup'
        self.root.mkdir()
        (self.root / 'xui-installer.sh').write_text('# downloaded installer\n')
        self.conf = self.base / 'awg0.conf'
        self.database = self.base / 'x-ui.db'
        with sqlite3.connect(self.database) as db:
            db.execute('CREATE TABLE inbounds (id INTEGER, enable INTEGER)')
        self.xui = self.base / 'x-ui'
        self.xui.write_text('#!/bin/sh\nexit 0\n')
        self.xui.chmod(0o700)
        self.patcher = patch.object(provision, 'run', return_value=SimpleNamespace(stdout='', stderr='', returncode=0))
        self.run = self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def check(self):
        provision.check_resume_before_identities(self.root, self.conf, self.database, self.xui)

    def snapshot(self):
        return {str(p.relative_to(self.base)):p.read_bytes() for p in self.base.rglob('*') if p.is_file()}

    def test_empty_panel_allows_resume_without_writes(self):
        before = self.snapshot()
        self.check()
        self.assertEqual(self.snapshot(), before)
        self.run.assert_called_once_with(['awg', 'show', 'interfaces'])

    def test_any_partial_identity_or_export_blocks_resume(self):
        for name in ('state.json', 'secrets.env', 'inbound.json', 'unrecognized.txt'):
            p = self.root / name
            p.touch()
            try:
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'resume refused'):
                    self.check()
            finally:
                p.unlink()
        self.run.assert_not_called()

    def test_export_directory_alone_blocks_resume(self):
        (self.root / 'dist').mkdir()
        with self.assertRaises(ValueError):
            self.check()

    def test_awg_configuration_blocks_resume(self):
        self.conf.write_text('already configured')
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.check()
        self.assertEqual(self.snapshot(), before)

    def test_any_inbound_even_disabled_blocks_resume(self):
        with sqlite3.connect(self.database) as db:
            db.execute('INSERT INTO inbounds VALUES (1,0)')
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'inbounds'):
            self.check()
        self.assertEqual(self.snapshot(), before)

    def test_missing_database_is_not_created(self):
        self.database.unlink()
        with self.assertRaises(ValueError):
            self.check()
        self.assertFalse(self.database.exists())

    def test_unknown_database_schema_blocks_resume(self):
        with sqlite3.connect(self.database) as db:
            db.execute('DROP TABLE inbounds')
        with self.assertRaisesRegex(ValueError, 'cannot verify'):
            self.check()

    def test_live_awg_interface_blocks_resume(self):
        self.run.return_value.stdout = 'awg0\n'
        with self.assertRaisesRegex(ValueError, 'live AWG'):
            self.check()

    def test_broken_symlink_is_not_treated_as_no_state(self):
        (self.root / 'state.json').symlink_to(self.base / 'missing')
        with self.assertRaises(ValueError):
            self.check()

    def test_resume_requires_installed_panel_executable(self):
        self.xui.chmod(0o600)
        with self.assertRaises(ValueError):
            self.check()

    def test_shell_has_explicit_opt_in_and_does_not_delete_state(self):
        script = (Path(__file__).resolve().parents[1] / 'install.sh').read_text()
        self.assertIn('--resume-before-identities', script)
        self.assertIn('"$HERE/provision.py" --check-resume-before-identities', script)
        self.assertIn('if [[ "$RESUME_BEFORE_IDENTITIES" == 0 ]]; then', script)
        self.assertNotIn('rm -rf', script)
        self.assertLess(script.index('--check-resume-before-identities'), script.index('apt-get update'))


if __name__ == '__main__':
    unittest.main()
