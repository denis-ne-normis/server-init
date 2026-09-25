#!/usr/bin/env python3
"""Explicit AWG 2 -> 3.1 migration. No package, firewall or Xray mutation.

Requires a consistent schema-1 server-init install and a 3.1-capable loaded
kernel/tools. Old client imports MUST be replaced after applying. Use rollback
from this checkout if the client has not been updated. Never print private data.
"""
import argparse
import copy
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import tempfile
import time

import awg_profile
import provision
import vpnctl as v

JOURNAL = 'awg-migration.json'
BACKUPS = Path('/root/vpn-backups')


def network_issues(state):
    """Check OUR managed live NAT/forward rules, not arbitrary third-party rulesets."""
    issues = []
    if (v.FW / 'pending.json').exists():
        issues.append('firewall confirmation still pending')
    if v.run(['sysctl', '-n', 'net.ipv4.ip_forward']).stdout.strip() != '1':
        issues.append('IPv4 forwarding disabled')
    route = json.loads(v.run(['ip', '-j', '-4', 'route', 'get', '1.1.1.1']).stdout)[0]
    wan = route['dev']
    result = v.run(['nft', '-j', 'list', 'table', 'inet', 'server_init'], check=False)
    if result.returncode:
        return issues + ['managed firewall/NAT missing (possibly rolled back); confirm firewall from an external SSH connection']
    objects = json.loads(result.stdout)['nftables']
    subnet = {'prefix': {'addr': state['AWG_SUBNET'] + '.0', 'len': 24}}
    def match(left, right):
        return {'match': {'op': '==', 'left': left, 'right': right}}
    src = match({'payload': {'protocol': 'ip', 'field': 'saddr'}}, subnet)
    out = match({'meta': {'key': 'oifname'}}, wan)
    incoming = match({'meta': {'key': 'iifname'}}, 'awg0')
    nat = False
    forwarding = False
    udp = False
    nat_hook = any(o.get('chain', {}).get('name') == 'postrouting' and
                   o['chain'].get('hook') == 'postrouting' and o['chain'].get('type') == 'nat' for o in objects)
    for obj in objects:
        rule = obj.get('rule', {})
        expr = rule.get('expr', [])
        # Match our exact generated predicates; do not claim arbitrary firewall analysis.
        clean = [e for e in expr if 'counter' not in e or len(e) != 1]
        if rule.get('chain') == 'postrouting' and nat_hook:
            nat |= clean == [src, out, {'masquerade': None}]
        if rule.get('chain') == 'forward':
            forwarding |= clean == [incoming, out, src, {'accept': None}]
        if rule.get('chain') == 'input':
            udp |= clean == [match({'payload': {'protocol': 'udp', 'field': 'dport'}}, int(state['AWG_PORT'])), {'accept': None}]
    if not nat:
        issues.append('expected AWG masquerade rule missing for active WAN')
    if not forwarding:
        issues.append('expected AWG forwarding rule missing for active WAN')
    if not udp:
        issues.append('expected AWG UDP input rule missing')
    if not v.NFT_CONF.is_file():
        issues.append('persistent firewall configuration missing')
    return issues


def render_to(bundle, directory):
    root, conf = Path(directory) / 'exports', Path(directory) / 'awg0.conf'
    provision.render(bundle, root=root, awg_conf=conf, qr=False)
    v.atomic(root / 'state.json', json.dumps(bundle, indent=2))
    return root, conf


def changed_files(bundle, root, conf):
    pairs = [(v.AWG_CONF, conf), (v.ROOT / 'state.json', root / 'state.json'),
             (v.ROOT / 'secrets.env', root / 'secrets.env')]
    for person in bundle['clients']:
        for relative in (f"awg/clients/{person['name']}.conf", f"dist/{person['name']}.vpn"):
            pairs.append((v.ROOT / relative, root / relative))
    return pairs


def load_bundle():
    for path in (v.ROOT, v.ROOT / 'state.json', v.ROOT / 'secrets.env', v.AWG_CONF):
        if path.is_symlink() or not path.exists():
            raise ValueError('migration requires intact schema-1 state, not a partial/legacy installation')
    bundle = json.loads((v.ROOT / 'state.json').read_text())
    state = v.validate_state(v.load_env(v.ROOT / 'secrets.env'))
    if bundle.get('schema') != 1 or bundle.get('settings') != state:
        raise ValueError('state.json and secrets.env disagree; migration refused')
    identities = [{k: c[k] for k in ('name', 'uuid', 'sub')} for c in bundle['clients']]
    if identities != v.people_from(state):
        raise ValueError('client identity list mismatch')
    # Re-render to a temporary tree to catch changed PSKs, addresses and exports.
    with tempfile.TemporaryDirectory() as temporary:
        root, conf = render_to(bundle, temporary)
        for live, expected in changed_files(bundle, root, conf):
            if live == v.ROOT / 'state.json':
                continue  # JSON formatting is not an identity.
            if live.is_symlink() or not live.resolve().is_relative_to(live.parent.resolve()) or live.read_bytes() != expected.read_bytes():
                raise ValueError('saved configs differ from state; no automatic overwrite permitted')
    v.verify_awg(state)
    v.verify_live_awg()
    v.verify_exports(state)
    return bundle


def stripped(conf):
    text = v.run(['awg-quick', 'strip', conf]).stdout
    # Older awg-tools rejects empty CPS lines. Empty fields have no wire effect.
    return '\n'.join(l for l in text.splitlines() if not l.strip() in {'I2 =', 'I3 =', 'I4 =', 'I5 ='}) + '\n'


def check_runtime(text, state):
    actual = v.config_sections(text)[0][1]
    expected = awg_profile.parameters(state, provision.OBFS)
    for key in awg_profile.MATCH_FIELDS:
        if key in expected and actual.get(key) != expected[key]:
            raise ValueError('AWG runtime did not retain expected profile parameters')


def probe(conf, state, temporary):
    file = Path(temporary) / 'probe.conf'
    v.atomic(file, stripped(conf))
    # No sockets/addresses/routes are created in the host namespace.
    result = v.run(['unshare', '--net', 'sh', '-ec',
                    'ip link add awg-probe type amneziawg; awg setconf awg-probe "$1"; awg showconf awg-probe',
                    'awg-probe', str(file)])
    check_runtime(result.stdout, state)


def apply_runtime(conf):
    # Recreate ONLY AWG: setconf would retain omitted 3.1 attributes on rollback.
    # No restart of x-ui, SSH, distribution, firewall or certificate services.
    v.run(['systemctl', 'restart', 'awg-quick@awg0'])




def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def restore(journal, strict=True):
    rows = journal['files']
    if strict:
        for row in rows:
            path = Path(row['target'])
            if path.is_symlink() or file_hash(path) not in {row['old_sha'], row['new_sha']}:
                raise ValueError('files changed since migration; automatic rollback refused')
    for row in rows:
        v.atomic(row['target'], Path(row['old']).read_text())
    apply_runtime(v.AWG_CONF)
    state = v.load_env(v.ROOT / 'secrets.env')
    v.verify_awg(state)
    v.verify_live_awg()
    v.publish(state)
    journal['phase'] = 'rolled-back'
    v.atomic(v.ROOT / JOURNAL, json.dumps(journal))


def rollback():
    path = v.ROOT / JOURNAL
    if not path.is_file():
        raise ValueError('no AWG migration journal to roll back')
    journal = json.loads(path.read_text())
    if journal['phase'] == 'rolled-back':
        print('AWG profile already rolled back; nothing changed.')
        return
    restore(journal)
    print('AWG profile rolled back. Previous client imports work again. VLESS/firewall untouched.')


def upgrade():
    journal_file = v.ROOT / JOURNAL
    if journal_file.exists() and json.loads(journal_file.read_text())['phase'] not in {'applied', 'rolled-back'}:
        raise ValueError('unfinished migration exists; run awg-rollback before retrying')
    bundle = load_bundle()
    state = bundle['settings']
    issues = network_issues(state)
    if issues:
        raise ValueError('; '.join(issues))
    if awg_profile.version(state) == '3.1':
        check_runtime(v.run(['awg', 'showconf', 'awg0']).stdout, state)
        print('AWG 3.1 already configured and NAT verified; no keys or files changed.')
        return
    journal_file = v.ROOT / JOURNAL
    if journal_file.exists() and json.loads(journal_file.read_text())['phase'] != 'rolled-back':
        raise ValueError('unfinished migration exists; run awg-rollback before retrying')
    new = copy.deepcopy(bundle)
    new['settings'].update(AWG_PROTOCOL='3.1', AWG_MTU='1280',
                           AWG_PARAMETERS=json.dumps(awg_profile.new_profile(), sort_keys=True))
    with tempfile.TemporaryDirectory(prefix='awg-prepare-') as temporary:
        root, conf = render_to(new, temporary)
        # Test actual installed tools + loaded kernel before touching saved data.
        probe(conf, new['settings'], temporary)
        archive = v.backup()
        print(f'Private backup: {archive}. Do not share it.', flush=True)
        directory = BACKUPS / ('awg-migration-' + str(time.time_ns()))
        directory.mkdir(mode=0o700, parents=True)
        rows = []
        for i, (target, source) in enumerate(changed_files(new, root, conf)):
            old = directory / f'{i}.old'
            staged = directory / f'{i}.new'
            v.atomic(old, target.read_text())
            v.atomic(staged, source.read_text())
            rows.append({'target': str(target), 'old': str(old), 'new': str(staged),
                         'old_sha': file_hash(old), 'new_sha': file_hash(staged)})
        journal = {'schema': 1, 'phase': 'prepared', 'files': rows}
        v.atomic(journal_file, json.dumps(journal))
        try:
            for row in rows:
                v.atomic(row['target'], Path(row['new']).read_text())
            apply_runtime(v.AWG_CONF)
            v.verify_awg(new['settings'])
            v.verify_live_awg()
            check_runtime(v.run(['awg', 'showconf', 'awg0']).stdout, new['settings'])
            v.verify_exports(new['settings'])
            v.publish(new['settings'])
            install_code()
            journal['phase'] = 'applied'
            v.atomic(journal_file, json.dumps(journal))
        except BaseException:
            try:
                restore(journal, strict=False)
            except BaseException:
                raise RuntimeError('migration AND automatic restore failed; use saved backup/awg-rollback') from None
            raise RuntimeError('migration failed; previous AWG profile restored, no VLESS/firewall changes') from None
    print('AWG 3.1 applied; keys, PSKs, addresses, UUIDs and personal links retained.')
    print('Re-import the NEW Amnezia profile from your existing personal page. Old imports cannot connect.')
    print('VLESS, certificates, firewall and package versions were NOT changed.')
    print('Rollback: python3 awg_upgrade.py rollback (from this checkout).')



def install_code():
    # Dependencies first, entry point last; never call repair (it can restart x-ui).
    source = Path(__file__).resolve().parent
    v.LIB.mkdir(mode=0o755, parents=True, exist_ok=True)
    for name in ('awg_profile.py', 'provision.py', 'awg_upgrade.py', 'vpnctl.py'):
        if (source / name).resolve() != (v.LIB / name).resolve():
            v.atomic(v.LIB / name, (source / name).read_text(), 0o644)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['apply', 'rollback', 'check'])
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('root required')
    os.umask(0o077)
    with open('/run/server-init.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command == 'check':
            bundle = load_bundle()
            issues = network_issues(bundle['settings'])
            if issues:
                raise ValueError('; '.join(issues))
            print('OK saved/runtime AWG identities, exports, managed NAT and forwarding.')
        elif args.command == 'apply':
            upgrade()
        else:
            rollback()


if __name__ == '__main__':
    def interrupted(*_):
        raise RuntimeError('migration interrupted')
    signal.signal(signal.SIGHUP, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f'ERROR: {exc}', file=__import__('sys').stderr)
        __import__('sys').exit(1)
