"""Called ONLY by the guarded disposable-runner integration harness.

AWG 2 -> 3.1 -> 2 -> 3.1, real kernel and Go peers, NAT/DNS/HTTPS.
No access to the user's server; no tests of censorship resistance are claimed.
"""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import zlib

GO_REF = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'


def exercise(t, original):
    if os.getenv('GITHUB_ACTIONS') != 'true' or os.getenv('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise RuntimeError('refusing to run outside disposable CI')
    import awg_upgrade
    import vpnctl as v
    run, note = t.command, t.note
    state = original['settings']
    wan = json.loads(run(['ip', '-j', '-4', 'route', 'get', '1.1.1.1']).stdout)[0]['dev']

    # Reproduce a clean install before firewall confirmation. The safe NAT must
    # survive a service restart without creating any inbound drop policy.
    run(['nft', 'flush', 'ruleset'])
    v.firewall_prime(state)
    assert run(['systemctl', 'is-enabled', '--quiet', 'vpn-awg-bootstrap-nat.service'], check=False).returncode == 0
    bootstrap = run(['nft', 'list', 'table', 'inet', 'server_init']).stdout
    assert 'masquerade' in bootstrap and 'policy drop' not in bootstrap
    run(['nft', 'flush', 'ruleset'])
    run(['systemctl', 'restart', 'vpn-awg-bootstrap-nat.service'])
    bootstrap = run(['nft', 'list', 'table', 'inet', 'server_init']).stdout
    assert 'masquerade' in bootstrap and 'policy drop' not in bootstrap
    note('PASS unconfirmed clean install keeps persistent AWG NAT without restricting inbound SSH')

    # Simulate confirmed firewall + reboot ordering: nftables restores the full
    # ruleset first, then the bootstrap service must detect the marker and no-op.
    rules = v.firewall_text(state, wan, [22])
    v.atomic(v.NFT_CONF, rules)
    run(['systemctl', 'enable', 'nftables'])
    run(['systemctl', 'restart', 'nftables'])
    run(['systemctl', 'restart', 'vpn-awg-bootstrap-nat.service'])
    assert awg_upgrade.network_issues(state) == []
    assert v.CONFIRMED_FIREWALL_MARKER in v.NFT_CONF.read_text()
    note('PASS confirmed firewall and NAT survive reboot-order service restarts without bootstrap clobber')
    run(['ip', 'netns', 'delete', 'awg-integration'])
    nft_before = run(['nft', 'list', 'ruleset']).stdout
    pid_before = run(['systemctl', 'show', 'x-ui', '-p', 'MainPID', '--value']).stdout
    links_before = {p: p.read_bytes() for p in v.ROOT.glob('dist/*.vless')}
    original_files = t.snapshot()
    run(['/usr/bin/python3', t.SOURCE / 'awg_upgrade.py', 'apply'])
    now = json.loads((v.ROOT / 'state.json').read_text())
    assert now['settings']['AWG_PROTOCOL'] == '3.1'
    assert now['clients'] == original['clients']
    assert now['settings']['AWG_SRV_PRIV'] == state['AWG_SRV_PRIV']
    assert {p: p.read_bytes() for p in links_before} == links_before
    assert run(['systemctl', 'show', 'x-ui', '-p', 'MainPID', '--value']).stdout == pid_before
    assert run(['nft', 'list', 'ruleset']).stdout == nft_before
    run(['/usr/local/bin/vpnctl', 'doctor'])
    note('PASS explicit AWG 2 -> 3.1 migration; VPN identities, Xray process and firewall unchanged')

    # Rollback must CLEAR new kernel attributes, not just omit them in setconf.
    run(['/usr/local/bin/vpnctl', 'awg-rollback'])
    assert t.snapshot() == original_files
    live = run(['awg', 'showconf', 'awg0']).stdout
    assert now['settings']['AWG_PARAMETERS'] not in live
    hp = next((l.partition('=')[2].strip() for l in live.splitlines() if l.startswith('HeaderProtectionKey')), '')
    assert hp in ('', base64.b64encode(bytes(32)).decode())
    run(['/usr/local/bin/vpnctl', 'awg-upgrade'])
    before_repeat = t.snapshot()
    run(['/usr/local/bin/vpnctl', 'awg-upgrade'])
    assert t.snapshot() == before_repeat
    note('PASS rollback restores old bytes and clears header protection; repeated upgrade is a no-op')

    # Exported native key, not a second independently hand-written config.
    encoded = (v.ROOT / 'dist/integration.vpn').read_text()[6:]
    packed = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
    native = json.loads(zlib.decompress(packed[4:]))
    protocol = native['containers'][0]['awg']
    assert protocol['protocol_version'] == '3.1'
    text = json.loads(protocol['last_config'])['config']
    text = text.replace('$PRIMARY_DNS', '1.1.1.1').replace('$SECONDARY_DNS', '8.8.8.8')
    raw_config = t.TEMP / 'native-client.conf'; v.atomic(raw_config, text)
    stripped = awg_upgrade.stripped(raw_config)
    config = t.TEMP / 'client-setconf.conf'; v.atomic(config, stripped)
    ip = original['clients'][0]['ip']
    public = state['PANEL_HOST']

    # Kernel client socket remains in root netns; tunnel routes live only in its netns.
    run(['ip', 'netns', 'add', 'awg-integration'])
    run(['ip', 'link', 'add', 'awg-ci', 'type', 'amneziawg'])
    run(['awg', 'setconf', 'awg-ci', config])
    run(['ip', 'link', 'set', 'awg-ci', 'netns', 'awg-integration'])
    run(['ip', '-n', 'awg-integration', 'addr', 'add', ip + '/32', 'dev', 'awg-ci'])
    run(['ip', '-n', 'awg-integration', 'link', 'set', 'awg-ci', 'mtu', '1280', 'up'])
    run(['ip', '-n', 'awg-integration', 'route', 'add', 'default', 'dev', 'awg-ci'])
    resolver = Path('/etc/netns/awg-integration/resolv.conf')
    resolver.parent.mkdir(parents=True, exist_ok=True)
    resolver.write_text('nameserver 1.1.1.1\nnameserver 8.8.8.8\n')
    result = run(['ip', 'netns', 'exec', 'awg-integration', 'curl', '-4fsS', '--max-time', '25', 'https://api.ipify.org'])
    assert result.stdout.strip() == public
    note('PASS AWG 3.1 native-export kernel client: DNS and Internet HTTPS through server NAT')

    # Doctor must diagnose the exact failure previously seen on the real VPS.
    run(['nft', 'delete', 'chain', 'inet', 'server_init', 'postrouting'])
    result = run(['/usr/local/bin/vpnctl', 'doctor'], check=False)
    assert result.returncode != 0 and 'masquerade' in result.stdout
    run(['nft', '-f', v.NFT_CONF])
    run(['/usr/local/bin/vpnctl', 'doctor'])
    note('PASS missing NAT is a failing diagnostic; restored NAT passes')
    run(['ip', 'netns', 'delete', 'awg-integration'])

    # Independent userspace implementation, used by mobile platforms.
    go = shutil.which('go')
    if not go:
        matches = sorted(Path('/opt/hostedtoolcache/go').glob('*/x64/bin/go'), reverse=True)
        go = str(matches[0]) if matches else '/usr/local/go/bin/go'
    src = t.TEMP / 'go-src'; src.mkdir()
    archive = t.TEMP / 'awg-go.tar.gz'
    t.download(f'https://codeload.github.com/amnezia-vpn/amneziawg-go/tar.gz/{GO_REF}', archive)
    run(['tar', '-xzf', archive, '--strip-components=1', '-C', src])
    binary = t.TEMP / 'amneziawg-go'
    run(['sh', '-ec', 'cd "$1"; exec "$2" build -trimpath -o "$3" .', 'build', src, go, binary],
        env=dict(os.environ, GOTOOLCHAIN='auto'), timeout=600)
    run(['ip', 'netns', 'add', 'awg-go-test'])
    run(['ip', 'link', 'add', 'go-host', 'type', 'veth', 'peer', 'name', 'go-uplink'])
    run(['ip', 'link', 'set', 'go-uplink', 'netns', 'awg-go-test'])
    run(['ip', 'addr', 'add', '198.18.13.1/30', 'dev', 'go-host'])
    run(['ip', 'link', 'set', 'go-host', 'up'])
    run(['ip', '-n', 'awg-go-test', 'addr', 'add', '198.18.13.2/30', 'dev', 'go-uplink'])
    run(['ip', '-n', 'awg-go-test', 'link', 'set', 'go-uplink', 'up'])
    run(['ip', '-n', 'awg-go-test', 'link', 'set', 'lo', 'up'])
    output = t.PRIVATE.open('a')
    proc = subprocess.Popen(['ip', 'netns', 'exec', 'awg-go-test', str(binary), '-f', 'awg-go'], stdout=output, stderr=output)
    t.children.append(proc)
    for _ in range(60):
        if run(['ip', '-n', 'awg-go-test', 'link', 'show', 'awg-go'], check=False).returncode == 0:
            break
        if proc.poll() is not None:
            raise RuntimeError('Go AWG process exited before readiness')
        time.sleep(.2)
    else:
        raise RuntimeError('Go AWG TUN did not appear')
    # Only transport Endpoint is adapted to the local test topology.
    v.atomic(config, stripped.replace(public + ':' + state['AWG_PORT'], '198.18.13.1:' + state['AWG_PORT']))
    run(['ip', 'netns', 'exec', 'awg-go-test', 'awg', 'setconf', 'awg-go', config])
    run(['ip', '-n', 'awg-go-test', 'addr', 'add', ip + '/32', 'dev', 'awg-go'])
    run(['ip', '-n', 'awg-go-test', 'link', 'set', 'awg-go', 'mtu', '1280', 'up'])
    run(['ip', '-n', 'awg-go-test', 'route', 'add', 'default', 'dev', 'awg-go'])
    resolver = Path('/etc/netns/awg-go-test/resolv.conf'); resolver.parent.mkdir(parents=True, exist_ok=True)
    resolver.write_text('nameserver 1.1.1.1\nnameserver 8.8.8.8\n')
    result = run(['ip', 'netns', 'exec', 'awg-go-test', 'curl', '-4fsS', '--max-time', '25', 'https://api.ipify.org'])
    assert result.stdout.strip() == public
    note('PASS independent AWG-Go v3 implementation with native export: kernel-server handshake, DNS and HTTPS/NAT')
    # Keep traffic flowing through one scheduled rekey; a first handshake alone
    # does not test the failure mode 'connects, then stops after some time'.
    peer = original['clients'][0]['public']
    def handshake():
        lines = run(['awg', 'show', 'awg0', 'latest-handshakes']).stdout.splitlines()
        return next(int(l.split()[1]) for l in lines if l.split()[0] == peer)
    first = handshake()
    assert first > 0
    deadline = time.monotonic() + 190
    while time.monotonic() < deadline:
        time.sleep(5)
        response = run(['ip', 'netns', 'exec', 'awg-go-test', 'curl', '-4fsS', '--max-time', '25', 'https://api.ipify.org'])
        assert response.stdout.strip() == public
        if handshake() > first:
            break
    else:
        raise RuntimeError('AWG-Go did not complete a scheduled rekey while transmitting')
    note('PASS AWG-Go continuous HTTPS traffic across an actual scheduled rekey')
    run(['/usr/local/bin/vpnctl', 'doctor'])
    assert run(['systemctl', 'show', 'x-ui', '-p', 'MainPID', '--value']).stdout == pid_before
    proc.terminate(); proc.wait(timeout=10)
    run(['ip', 'netns', 'delete', 'awg-go-test'])
    note('PASS final health; no mobile GUI, provider filtering, production CA or reboot claims')
