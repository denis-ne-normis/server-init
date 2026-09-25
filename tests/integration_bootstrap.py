#!/usr/bin/env python3
"""Destructive integration test: GitHub-hosted disposable runner ONLY.
Real ACME/Pebble, 3x-ui, Xray, AWG kernel, systemd. Never use on a user's VPS.
No production CA requests, credentials or source secrets are used/uploaded.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.request

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))
import bootstrap_tls
import provision
import vpnctl

TEMP = Path('/root/bootstrap-integration')
REPORT = SOURCE / 'integration-results.txt'
PRIVATE = TEMP / 'private.log'
children = []


def note(message):
    print(message, flush=True)
    with REPORT.open('a') as file:
        file.write(message + '\n')


def command(args, *, input=None, env=None, check=True, timeout=600):
    result = subprocess.run([str(a) for a in args], input=input, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            env=env, timeout=timeout)
    with PRIVATE.open('a') as file:
        file.write(result.stdout)
    if check and result.returncode:
        raise RuntimeError(f'{Path(str(args[0])).name} exited {result.returncode}')
    return result


def download(url, dest):
    command(['curl', '-fLSs', '--connect-timeout', '15', '--max-time', '180', '--retry', '2', url, '-o', dest])


def release(repo, tag, asset):
    meta = TEMP / 'release.json'
    download(f'https://api.github.com/repos/{repo}/releases/tags/{tag}', meta)
    info = next(a for a in json.loads(meta.read_text())['assets'] if a['name'] == asset)
    path = TEMP / asset
    download(info['browser_download_url'], path)
    digest = info.get('digest', '')
    if not digest.startswith('sha256:') or hashlib.sha256(path.read_bytes()).hexdigest() != digest[7:]:
        raise ValueError('release checksum mismatch or absent')
    return path


def snapshot():
    paths = [vpnctl.ROOT / 'state.json', vpnctl.ROOT / 'secrets.env', vpnctl.AWG_CONF]
    paths += [p for p in vpnctl.ROOT.rglob('*') if p.is_file() and p.suffix in {'.conf', '.vpn', '.vless'}]
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def redact_log():
    text = PRIVATE.read_text() if PRIVATE.exists() else ''
    if (vpnctl.ROOT / 'state.json').exists():
        bundle = json.loads((vpnctl.ROOT / 'state.json').read_text())
        fields = list(bundle['settings'].values())
        fields += [v for c in bundle['clients'] for v in c.values() if isinstance(v, str)]
        for value in sorted(fields, key=len, reverse=True):
            if len(value) >= 8:
                text = text.replace(value, '[redacted-test-value]')
    text = re.sub(r'(?m)^.*(?:PrivateKey|PresharedKey|Password|password|private.key|--token|Account key).*$','[redacted]',text)
    # No snapshots, keys, config files or private raw logs are uploaded.
    (SOURCE / 'integration-diagnostics.txt').write_text(text[-35000:])


def main():
    if (os.geteuid() != 0 or os.getenv('GITHUB_ACTIONS') != 'true'
            or os.getenv('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise SystemExit('REFUSED: disposable GitHub-hosted runner required')
    if vpnctl.ROOT.exists() or Path('/etc/x-ui/x-ui.db').exists():
        raise SystemExit('REFUSED: pre-existing VPN data')
    os.umask(0o077)
    TEMP.mkdir(mode=0o700)
    REPORT.write_text('')
    note('START isolated CI integration; no connection to user VPS')
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='l')
    command(['systemctl', 'stop', 'docker.service', 'docker.socket', 'nginx', 'apache2'], check=False)
    command(['apt-get', 'update'], env=env)
    command(['apt-get', 'install', '-y', 'python3', 'curl', 'jq', 'openssl', 'ca-certificates', 'socat', 'sqlite3',
             'qrencode', 'nftables', 'software-properties-common', 'iproute2', f'linux-headers-{os.uname().release}'], env=env)
    command(['add-apt-repository', '-y', 'ppa:amnezia/ppa'], env=env)
    command(['apt-get', 'update'], env=env)
    command(['apt-get', 'install', '-y', 'amneziawg', 'amneziawg-tools'], env=env)
    command(['modprobe', 'amneziawg'])
    note('PASS real AmneziaWG packages and running-kernel module')
    # Reset runner's Docker-created rules, never a persistent/user host firewall.
    command(['nft', 'flush', 'ruleset'])
    xui = release('MHSanaei/3x-ui', 'v3.2.8', 'x-ui-linux-amd64.tar.gz')
    command(['tar', '-xzf', xui, '-C', '/usr/local'])
    command(['chmod', '+x', '/usr/local/x-ui/x-ui'])
    for p in Path('/usr/local/x-ui/bin').glob('xray-linux-*'):
        p.chmod(0o755)
    Path('/etc/systemd/system/x-ui.service').write_text('[Unit]\nDescription=Integration 3x-ui\nAfter=network.target\n[Service]\nType=simple\nWorkingDirectory=/usr/local/x-ui\nExecStart=/usr/local/x-ui/x-ui\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n')
    command(['systemctl', 'daemon-reload'])
    command(['/usr/local/x-ui/x-ui', 'migrate'])
    # Use a real public egress IP as identity, but resolve it locally for Pebble HTTP-01.
    ip = command(['curl', '-fsS4', '--max-time', '20', 'https://api.ipify.org']).stdout.strip()
    command(['ip', 'addr', 'add', ip + '/32', 'dev', 'lo'])
    pebble = release('letsencrypt/pebble', 'v2.10.1', 'pebble-linux-amd64.tar.gz')
    command(['tar', '-xzf', pebble, '-C', TEMP])
    binary = next(p for p in TEMP.rglob('pebble') if p.is_file())
    binary.chmod(0o700)
    # Trusted test-only TLS for the local ACME API; never --insecure.
    cert, key = TEMP / 'api.crt', TEMP / 'api.key'
    command(['openssl', 'req', '-x509', '-nodes', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
             '-days', '3', '-keyout', key, '-out', cert, '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'])
    cfg = {'pebble': {'listenAddress':'127.0.0.1:14000', 'managementListenAddress':'127.0.0.1:15000',
        'certificate':str(cert), 'privateKey':str(key), 'httpPort':80, 'tlsPort':5001,
        'externalAccountBindingRequired':False, 'profiles':{'shortlived':{'description':'test','validityPeriod':576000}}}}
    (TEMP / 'pebble.json').write_text(json.dumps(cfg))
    output = PRIVATE.open('a')
    ca = subprocess.Popen([str(binary), '-config', str(TEMP / 'pebble.json')], stdout=output, stderr=output,
        env=dict(os.environ, PEBBLE_VA_NOSLEEP='1', PEBBLE_WFE_NONCEREJECT='0'))
    children.append(ca)
    ctx = ssl.create_default_context(cafile=str(cert))
    for _ in range(50):
        try:
            with urllib.request.urlopen('https://127.0.0.1:15000/roots/0',context=ctx,timeout=1) as r:
                root_cert = r.read()
            break
        except OSError:
            time.sleep(0.2)
    else:
        raise RuntimeError('Pebble API not ready')
    trust = Path('/usr/local/share/ca-certificates/integration-pebble.crt')
    trust.write_bytes(root_cert)
    command(['update-ca-certificates'])
    bundle_ca = TEMP / 'trust.pem'; bundle_ca.write_bytes(cert.read_bytes() + root_cert)
    home = Path('/root/.acme.sh'); home.mkdir(mode=0o700)
    download('https://raw.githubusercontent.com/acmesh-official/acme.sh/3.1.6/acme.sh', home / 'acme.sh')
    (home / 'acme.sh').chmod(0o700)
    # Real ACME order, real HTTP-01 fetch, real key/CSR/certificate; no mocked issuer.
    bootstrap_tls.ensure_certificate(ip, home=home, log=PRIVATE, server='https://127.0.0.1:14000/dir', ca_file=bundle_ca)
    note('PASS real acme.sh issuance through Pebble HTTP-01 with shortlived profile')
    args = [home / 'acme.sh', '--home', home, '--issue', '--server', 'https://127.0.0.1:14000/dir', '-d', ip,
            '--standalone', '--keylength', 'ec-256', '--certificate-profile', 'shortlived', '--days', '3', '--ca-bundle', bundle_ca]
    skipped = command(args, check=False)
    if skipped.returncode != 2:
        raise RuntimeError(f'expected actual acme.sh skip exit 2, got {skipped.returncode}')
    note('PASS reproduced original false failure: already-issued certificate returns exit 2')
    # Prepare exactly the user's point of interruption: identities saved, no inbound.
    env.update(PUBIP=ip, CLIENTS='integration', PANEL_PORT='39000', APPLY_FIREWALL='0', ENABLE_LE='1')
    command(['/usr/bin/python3', SOURCE / 'provision.py'], env=env)
    before = snapshot()
    result = command(['bash', SOURCE / 'install.sh', '--resume-from-tls'], env=env, check=False)
    if result.returncode:
        # Installer stdout does not contain credentials; log remains redacted on export.
        note('FAIL bootstrap stage: ' + result.stdout[-2000:])
        raise RuntimeError('real bootstrap continuation failed')
    if snapshot() != before:
        raise RuntimeError('bootstrap changed identity bytes')
    note('PASS complete TLS continuation: real panel API, AWG systemd, rootless HTTPS, subscriptions, Xray traffic probe')
    command(['/usr/local/bin/vpnctl', 'doctor'])
    command(['/usr/local/bin/vpnctl', 'repair'])
    if snapshot() != before:
        raise RuntimeError('repeat repair changed identities')
    note('PASS repeat repair and doctor with live services; identities unchanged')
    # Real AWG client in its own network namespace. UDP socket remains in root netns.
    bundle = json.loads((vpnctl.ROOT / 'state.json').read_text())
    client = bundle['clients'][0]
    command(['ip', 'netns', 'add', 'awg-integration'])
    command(['ip', 'link', 'add', 'awg-ci', 'type', 'amneziawg'])
    stripped = command(['awg-quick', 'strip', vpnctl.ROOT / 'awg/clients/integration.conf']).stdout
    stripped = '\n'.join(l for l in stripped.splitlines() if not re.match(r'I[2-5]\s*=\s*$',l)) + '\n'
    config = TEMP / 'awg-client.conf'; config.write_text(stripped)
    command(['awg', 'setconf', 'awg-ci', config])
    command(['ip', 'link', 'set', 'awg-ci', 'netns', 'awg-integration'])
    command(['ip', '-n', 'awg-integration', 'addr', 'add', client['ip'] + '/32', 'dev', 'awg-ci'])
    command(['ip', '-n', 'awg-integration', 'link', 'set', 'awg-ci', 'up'])
    command(['ip', '-n', 'awg-integration', 'route', 'add', '10.9.7.1/32', 'dev', 'awg-ci'])
    (TEMP / 'test.txt').write_text('awg-roundtrip-ok\n')
    http = subprocess.Popen(['/usr/bin/python3', '-m', 'http.server', '18080', '--bind', '10.9.7.1', '--directory', str(TEMP)], stdout=output, stderr=output)
    children.append(http)
    time.sleep(1)
    result = command(['ip','netns','exec','awg-integration','curl','-fsS','--retry','3','--max-time','15','http://10.9.7.1:18080/test.txt'])
    if result.stdout.strip() != 'awg-roundtrip-ok':
        raise RuntimeError('AWG data round trip failed')
    note('PASS real AWG client handshake and encrypted HTTP transfer in network namespace')
    command(['systemctl', 'restart', 'awg-quick@awg0', 'aggsub', 'x-ui'])
    time.sleep(3)
    command(['/usr/local/bin/vpnctl', 'doctor'])
    note('PASS service restart and post-restart health; no reboot or mobile-ISP test claimed')


if __name__ == '__main__':
    rc = 0
    try:
        main()
    except Exception as exc:
        note(f'FAIL {type(exc).__name__}: {exc}')
        rc = 1
    finally:
        if TEMP.is_dir():
            for child in children:
                child.terminate()
            redact_log()
            subprocess.run(['systemctl','stop','vpn-cert-renew.timer','vpn-awg-recover.timer','aggsub','awg-quick@awg0','x-ui'], capture_output=True)
            subprocess.run(['ip','netns','delete','awg-integration'], capture_output=True)
    sys.exit(rc)
