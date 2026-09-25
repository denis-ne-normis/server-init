#!/usr/bin/env python3
"""TLS bootstrap and narrow recovery after identities were already saved.

Never regenerate identities, delete state, force a CA order, or silently replace
failed public TLS with self-signed TLS. acme.sh exit 2 is a skip, not success:
only a verified certificate/key/IP/chain can make that path succeed.
"""
import argparse
import contextlib
import ipaddress
import json
import os
from pathlib import Path
import shlex
import socket
import sqlite3
import ssl
import subprocess
import tempfile

import provision
import vpnctl


def check_resume(root=None, conf=None, database=None):
    root = vpnctl.ROOT if root is None else Path(root)
    conf = vpnctl.AWG_CONF if conf is None else Path(conf)
    database = Path('/etc/x-ui/x-ui.db') if database is None else Path(database)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('missing bootstrap state directory')
    for path in (root / 'state.json', root / 'secrets.env', conf, database):
        if not path.is_file() or path.is_symlink():
            raise ValueError('resume requires intact saved state, AWG config and panel database')
    bundle = json.loads((root / 'state.json').read_text())
    state = vpnctl.validate_state(vpnctl.load_env(root / 'secrets.env'))
    if bundle.get('schema') != 1 or bundle.get('settings') != state:
        raise ValueError('state.json and secrets.env disagree; nothing changed')
    identities = [{k: p[k] for k in ('name', 'uuid', 'sub')} for p in bundle['clients']]
    if identities != vpnctl.people_from(state):
        raise ValueError('saved client identities disagree; nothing changed')
    # Compare a deterministic render to disk, without rewriting any saved file.
    with tempfile.TemporaryDirectory() as temporary:
        expected = Path(temporary) / 'exports'
        expected_conf = Path(temporary) / 'awg0.conf'
        provision.render(bundle, expected, expected_conf, qr=False)
        for file in expected.rglob('*'):
            if file.is_file():
                actual = root / file.relative_to(expected)
                if (actual.is_symlink() or not actual.resolve().is_relative_to(root.resolve())
                        or not actual.is_file() or actual.read_bytes() != file.read_bytes()):
                    raise ValueError('saved bootstrap exports changed or incomplete; nothing changed')
        if expected_conf.read_bytes() != conf.read_bytes():
            raise ValueError('saved AWG configuration differs from state; nothing changed')
    with contextlib.closing(sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True)) as db:
        if db.execute('SELECT COUNT(*) FROM inbounds').fetchone()[0]:
            raise ValueError('panel already has an inbound; TLS bootstrap resume refused')
    if vpnctl.run(['awg', 'show', 'interfaces']).stdout.strip():
        raise ValueError('live AWG interface exists; TLS bootstrap resume refused')
    vpnctl.verify_awg(state, root=root, conf=conf)
    return state


def usable_pair(cert, key, ip, ca_file=None, min_seconds=86400):
    """Check key match, remaining lifetime, IP SAN and a trusted server chain."""
    cert, key = Path(cert), Path(key)
    if not cert.is_file() or not key.is_file():
        return False
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        for args in (['openssl', 'x509', '-in', cert, '-noout', '-checkend', str(min_seconds)],
                     ['openssl', 'verify', '-purpose', 'sslserver', '-verify_ip', ip] +
                     (['-CAfile', ca_file] if ca_file else []) + ['-untrusted', cert, cert]):
            if vpnctl.run(args, check=False).returncode:
                return False
        return True
    except (OSError, ValueError, ssl.SSLError, RuntimeError):
        return False


def acme_reason(output):
    """Only fixed categories are returned; never print raw logs with secrets."""
    text = output.lower()
    if 'skip' in text or 'next renewal' in text:
        return 'ACME skipped issuance but no usable certificate was found'
    if 'rate' in text and ('limit' in text or 'too many' in text):
        return 'CA rate limit; respect its retry interval'
    if 'address already in use' in text or 'already used' in text:
        return 'HTTP-01 listener port is busy'
    if 'timeout' in text or 'timed out' in text or 'connection refused' in text:
        return 'CA or HTTP-01 connectivity failed'
    if 'resolve' in text or 'dns' in text:
        return 'DNS/network lookup failed'
    return 'ACME failed; inspect the private installation log for its exact error'


def ensure_certificate(ip, home=Path('/root/.acme.sh'), dest=Path('/root/cert/le'),
                       log=Path('/var/log/vpn-install.log'), server='letsencrypt', ca_file=None):
    ip = str(ipaddress.IPv4Address(ip))
    home, dest, log = Path(home), Path(dest), Path(log)
    acme = home / 'acme.sh'
    if not acme.is_file():
        raise ValueError('acme.sh is missing')
    cached = home / (ip + '_ecc')
    cert, key = cached / 'fullchain.cer', cached / (ip + '.key')
    # The upstream 3x-ui installer can ALREADY have issued this exact certificate.
    # Reuse it before --issue (which then returns 2). Do not force another order.
    reused = usable_pair(cert, key, ip, ca_file)
    base = [str(acme), '--home', str(home)]
    def call(arguments):
        result = vpnctl.run(base + arguments, check=False, timeout=300)
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open('a') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(result.stdout + result.stderr)
        return result
    if not reused:
        # Local bind is only a port-conflict test, NOT proof of Internet reachability.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(('0.0.0.0', 80))
        except OSError:
            raise RuntimeError('TCP 80 cannot be bound for HTTP-01; no service was stopped') from None
        args = ['--issue', '--server', server, '-d', ip, '--standalone', '--keylength', 'ec-256',
                '--certificate-profile', 'shortlived', '--days', '3']
        if ca_file:
            args += ['--ca-bundle', str(ca_file)]
        result = call(args)
        if result.returncode not in (0, 2):
            raise RuntimeError(f'ACME exit {result.returncode}: {acme_reason(result.stdout + result.stderr)}; log: {log}')
        if not usable_pair(cert, key, ip, ca_file):
            raise RuntimeError(f'ACME exit {result.returncode}: certificate/key/IP/trust verification failed; log: {log}')
    dest.mkdir(mode=0o700, parents=True, exist_ok=True)
    result = call(['--install-cert', '-d', ip, '--ecc', '--fullchain-file', str(dest / 'fullchain.pem'),
                   '--key-file', str(dest / 'private.key'), '--reloadcmd', '/bin/true'])
    if result.returncode or not usable_pair(dest / 'fullchain.pem', dest / 'private.key', ip, ca_file):
        raise RuntimeError(f'certificate deployment verification failed (exit {result.returncode}); log: {log}')
    (dest / 'private.key').chmod(0o600)
    print('OK verified existing IP certificate reused' if reused else 'OK IP certificate issued and verified')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['check-resume', 'safe-env', 'certificate'])
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('root required')
    os.umask(0o077)
    if args.command in {'check-resume', 'safe-env'}:
        state = check_resume()
        if args.command == 'safe-env':
            # No source/eval of arbitrary legacy input. This is newly shell-quoted data.
            print(''.join(f'{k}={shlex.quote(v)}\n' for k, v in state.items()), end='')
        else:
            print('OK saved bootstrap identities verified; resume will not regenerate them')
    else:
        state = vpnctl.validate_state(vpnctl.load_env(vpnctl.ROOT / 'secrets.env'))
        ensure_certificate(state['PANEL_HOST'])


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, sqlite3.Error, subprocess.TimeoutExpired):
        # Main errors below do not include commands or secrets; preserve actionable fixed messages.
        import sys
        error = sys.exc_info()[1]
        print(f'ERROR: {error}', file=sys.stderr)
        sys.exit(1)
