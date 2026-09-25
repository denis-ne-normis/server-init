"""Regression coverage for an explicit, reversible wire-profile migration."""
import base64
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import awg_profile as profile
import awg_upgrade as migration
import provision
import vpnctl as v
from test_reliability import fixture, KEYS


def upgraded():
    bundle = fixture()
    bundle['settings'].update(AWG_PROTOCOL='3.1', AWG_MTU='1280',
                               AWG_PARAMETERS=json.dumps(profile.new_profile(), sort_keys=True))
    return bundle


def nft_objects(state):
    def m(left, right):
        return {'match': {'op': '==', 'left': left, 'right': right}}
    src = m({'payload': {'protocol': 'ip', 'field': 'saddr'}},
            {'prefix': {'addr': '10.9.7.0', 'len': 24}})
    out = m({'meta': {'key': 'oifname'}}, 'ens3')
    inc = m({'meta': {'key': 'iifname'}}, 'awg0')
    return {'nftables': [
        {'chain': {'name': 'postrouting', 'type': 'nat', 'hook': 'postrouting'}},
        {'rule': {'chain': 'postrouting', 'expr': [src, out, {'masquerade': None}]}},
        {'rule': {'chain': 'forward', 'expr': [inc, out, src, {'accept': None}]}},
        {'rule': {'chain': 'input', 'expr': [m({'payload': {'protocol': 'udp', 'field': 'dport'}}, int(state['AWG_PORT'])), {'accept': None}]}},
    ]}


class ProfileTests(unittest.TestCase):
    def test_new_profile_retains_identity_keys(self):
        b = upgraded()
        self.assertEqual(b['clients'], fixture()['clients'])
        self.assertEqual(b['settings']['AWG_SRV_PRIV'], KEYS[0])
        self.assertEqual(profile.parameters(b['settings'], {})['S4'], '12')
        self.assertNotEqual(profile.new_profile()['HeaderProtectionKey'], profile.new_profile()['HeaderProtectionKey'])

    def test_legacy_remains_legacy(self):
        self.assertEqual(profile.parameters(fixture()['settings'], provision.OBFS), provision.OBFS)
        self.assertEqual(profile.keepalive(fixture()['settings']), '25')

    def test_validate_does_not_generate_random_key(self):
        s = upgraded()['settings']
        with patch.object(profile.secrets, 'token_bytes', side_effect=AssertionError):
            profile.parameters(s, {})

    def test_unsupported_version_rejected(self):
        with self.assertRaises(ValueError):
            profile.version({'AWG_PROTOCOL': 'latest'})

    def test_invalid_parameters_rejected_without_echoing_secret(self):
        for key, value in [('S4', '5'), ('H1', '10'), ('HeaderProtectionKey', 'private-secret'), ('I1', 'x\nPrivateKey = x')]:
            s = upgraded()['settings']; p = json.loads(s['AWG_PARAMETERS']); p[key] = value
            s['AWG_PARAMETERS'] = json.dumps(p)
            with self.subTest(key=key), self.assertRaises(ValueError) as ctx:
                profile.parameters(s, {})
            self.assertNotIn('private-secret', str(ctx.exception))

    def test_v3_export_matching_across_all_layers(self):
        with tempfile.TemporaryDirectory() as d:
            root, conf = migration.render_to(upgraded(), d)
            state = v.load_env(root / 'secrets.env')
            pub = lambda k: {KEYS[0]: KEYS[2], KEYS[1]: KEYS[3]}[k]
            v.verify_awg(state, root, conf, pub)
            with patch.object(v, 'ROOT', root):
                v.verify_exports(state)
            self.assertIn('PersistentKeepalive = 25-35', (root / 'awg/clients/test-client.conf').read_text())
            self.assertIn('MTU = 1280', conf.read_text())
            self.assertIn('HeaderProtectionKey', conf.read_text())
            migration.check_runtime(conf.read_text(), state)

    def test_mismatched_header_key_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            b = upgraded(); root, conf = migration.render_to(b, d)
            p = root / 'awg/clients/test-client.conf'
            p.write_text(p.read_text().replace(json.loads(b['settings']['AWG_PARAMETERS'])['HeaderProtectionKey'], KEYS[0]))
            with self.assertRaises(ValueError):
                v.verify_awg(b['settings'], root, conf, lambda k: {KEYS[0]: KEYS[2], KEYS[1]: KEYS[3]}[k])

    def test_kernel_dropping_parameters_rejected(self):
        with self.assertRaises(ValueError):
            migration.check_runtime('[Interface]\nS1 = 12\n', upgraded()['settings'])


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.nft = nft_objects(fixture()['settings'])
        self.bad_table = False
        self.conf = self.root / 'nftables.conf'; self.conf.write_text('configured')

    def runner(self, args, **kw):
        if args[0] == 'nft':
            return SimpleNamespace(returncode=int(self.bad_table), stdout=json.dumps(self.nft))
        return SimpleNamespace(returncode=0, stdout='1\n' if args[0] == 'sysctl' else '[{"dev":"ens3"}]')

    def check(self):
        with patch.object(v, 'run', side_effect=self.runner), patch.object(v, 'NFT_CONF', self.conf), patch.object(v, 'FW', self.root):
            return migration.network_issues(fixture()['settings'])

    def test_matching_nat_forward_and_udp_pass(self):
        self.assertEqual(self.check(), [])

    def test_missing_table_is_not_green_doctor(self):
        self.bad_table = True
        self.assertIn('missing', ' '.join(self.check()))

    def test_missing_nat_is_failure(self):
        self.nft['nftables'].pop(1)
        self.assertIn('masquerade', ' '.join(self.check()))

    def test_wrong_wan_is_failure(self):
        self.nft['nftables'][1]['rule']['expr'][1]['match']['right'] = 'wrong'
        self.assertIn('masquerade', ' '.join(self.check()))

    def test_pending_transaction_and_missing_persistence_reported(self):
        (self.root / 'pending.json').write_text('{}'); self.conf.unlink()
        self.assertEqual(len(self.check()), 2)

    def test_missing_forward_and_udp_are_reported(self):
        self.nft['nftables'] = self.nft['nftables'][:2]
        self.assertEqual(len(self.check()), 2)


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.root, self.conf = migration.render_to(fixture(), self.directory)
        self.old = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.old[self.conf] = self.conf.read_bytes()
        self.original = fixture()
        patches = [patch.object(v, 'ROOT', self.root), patch.object(v, 'AWG_CONF', self.conf),
                   patch.object(migration, 'BACKUPS', self.directory / 'backups'),
                   patch.object(migration, 'load_bundle', side_effect=lambda: json.loads((self.root / 'state.json').read_text())),
                   patch.object(migration, 'network_issues', return_value=[]), patch.object(migration, 'probe'),
                   patch.object(v, 'backup', return_value=self.directory / 'private-backup'),
                   patch.object(v, 'verify_awg'), patch.object(v, 'verify_live_awg'),
                   patch.object(v, 'verify_exports'), patch.object(v, 'publish'),
                   patch.object(migration, 'install_code'),
                   patch.object(v, 'run', side_effect=lambda *a, **kw: SimpleNamespace(returncode=0, stdout=self.conf.read_text())),
                   patch.object(migration, 'apply_runtime')]
        self.mocks = []
        for p in patches:
            self.mocks.append(p.start()); self.addCleanup(p.stop)

    def test_upgrade_twice_and_explicit_rollback_preserve_identities(self):
        migration.upgrade()
        first = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        migration.upgrade()
        self.assertEqual(first, {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
        now = json.loads((self.root / 'state.json').read_text())
        self.assertEqual(now['clients'], self.original['clients'])
        self.assertEqual((self.root / 'dist/test-client.vless').read_bytes(), self.old[self.root / 'dist/test-client.vless'])
        migration.rollback()
        for path, data in self.old.items():
            self.assertEqual(path.read_bytes(), data)

    def test_prepared_journal_blocks_noop_on_already_written_v3(self):
        migration.upgrade()
        journal = self.root / migration.JOURNAL
        data = json.loads(journal.read_text()); data['phase'] = 'prepared'
        journal.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'unfinished migration'):
            migration.upgrade()

    def test_runtime_failure_automatically_rolls_back(self):
        with patch.object(migration, 'apply_runtime', side_effect=[RuntimeError('apply fails'), None]):
            with self.assertRaisesRegex(RuntimeError, 'previous AWG profile restored'):
                migration.upgrade()
        for path, data in self.old.items():
            self.assertEqual(path.read_bytes(), data)

    def test_probe_failure_leaves_all_files_untouched(self):
        with patch.object(migration, 'probe', side_effect=RuntimeError('not supported')):
            with self.assertRaises(RuntimeError): migration.upgrade()
        for path, data in self.old.items(): self.assertEqual(path.read_bytes(), data)

    def test_network_failure_blocks_upgrade_before_probe(self):
        with patch.object(migration, 'network_issues', return_value=['NAT missing']), patch.object(migration, 'probe') as probe:
            with self.assertRaises(ValueError): migration.upgrade()
            probe.assert_not_called()

    def test_rollback_refuses_later_manual_changes(self):
        migration.upgrade()
        (self.root / 'awg/clients/test-client.conf').write_text('edited')
        with self.assertRaisesRegex(ValueError, 'files changed'):
            migration.rollback()


class ExternalSSHTests(unittest.TestCase):
    def test_self_ssh_and_loopback_are_not_external_confirmation(self):
        result = SimpleNamespace(stdout='[{"addr_info":[{"local":"203.0.113.10"}]}]')
        with patch.object(v, 'run', return_value=result):
            for source in ('127.0.0.1', '::1', '203.0.113.10'):
                with self.subTest(source=source), self.assertRaises(ValueError):
                    v.require_external_ssh(f'{source} 55555 203.0.113.10 22')
            v.require_external_ssh('198.51.100.1 55555 203.0.113.10 22')
