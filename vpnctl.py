#!/usr/bin/env python3
"""Conservative maintenance for server-init. repair never rewrites VPN identities.

Root-only writes; doctor is read-only. No shell evaluation of secrets.env.
Do not share backups: they contain private keys. Linux/systemd is required for
maintenance commands; pure parsers/renderers are covered by unit tests.
"""
import argparse
import awg_profile
import base64
import contextlib
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import urllib.parse
import zlib

ROOT = Path("/root/vpn-setup")
AWG_CONF = Path("/etc/amnezia/amneziawg/awg0.conf")
LIB = Path("/usr/local/lib/server-init")
DATA = Path("/var/lib/vpn-dist")
ETC = Path("/etc/vpn-dist")
FW = Path("/run/server-init-firewall")
NFT_CONF = Path("/etc/nftables.conf")
BOOTSTRAP_NAT = ETC / "bootstrap-nat.nft"
CONFIRMED_FIREWALL_MARKER = "# server-init confirmed firewall"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
TOKEN = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")


def run(args, *, data=None, check=True, timeout=60):
    try:
        result = subprocess.run([str(x) for x in args], input=data, text=True,
                                capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        # TimeoutExpired.__str__ includes argv, which may contain credentials.
        raise RuntimeError(f"{Path(str(args[0])).name} timed out; inspect local service logs") from None
    if check and result.returncode:
        # Commands/outputs may contain credentials. Never include them in diagnostics.
        raise RuntimeError(f"{Path(str(args[0])).name} failed (exit {result.returncode}); inspect local service logs")
    return result


def atomic(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".new-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def load_env(path):
    result = {}
    for line in Path(path).read_text().splitlines():
        parts = shlex.split(line, comments=True)
        if not parts:
            continue
        if len(parts) != 1 or "=" not in parts[0]:
            raise ValueError("invalid secrets.env; no shell commands are allowed")
        key, value = parts[0].split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in result:
            raise ValueError("invalid or duplicate environment key")
        result[key] = value
    return result


def people_from(state):
    people = json.loads(state["CLIENTS_JSON"])
    if not isinstance(people, list) or not 1 <= len(people) <= 253:
        raise ValueError("CLIENTS_JSON must contain 1..253 clients")
    seen = {key: set() for key in ("name", "sub", "uuid")}
    import uuid
    for person in people:
        if not NAME.fullmatch(person["name"]) or not TOKEN.fullmatch(person["sub"]):
            raise ValueError("invalid client name or subscription token")
        uuid.UUID(person["uuid"])
        for key in seen:
            if person[key] in seen[key]:
                raise ValueError("duplicate client identity")
            seen[key].add(person[key])
    return people


def validate_state(state):
    people_from(state)
    awg_profile.version(state)
    tcp = [int(state[key]) for key in ("PANEL_PORT", "VLESS_PORT", "SUB_PORT", "AGG_PORT")]
    if len(set(tcp)) != len(tcp) or any(not 1 <= p <= 65535 for p in tcp):
        raise ValueError("TCP ports must be distinct and between 1 and 65535")
    if int(state["AGG_PORT"]) < 1024:
        raise ValueError("rootless distribution needs AGG_PORT >= 1024; migrate a privileged port explicitly")
    if not 1 <= int(state["AWG_PORT"]) <= 65535:
        raise ValueError("invalid AWG port")
    ipaddress.IPv4Network(state["AWG_SUBNET"] + ".0/24")
    ipaddress.IPv4Address(state["PANEL_HOST"])
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", state["SNI_DONOR"]):
        raise ValueError("invalid Reality donor")
    return state


def config_sections(text):
    sections = []
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = {}
            sections.append((line[1:-1], current))
        elif current is not None and "=" in line:
            key, value = (part.strip() for part in line.split("=", 1))
            if key in current:
                raise ValueError("duplicate AWG field")
            current[key] = value
        else:
            raise ValueError("invalid AWG configuration")
    return sections


def key32(value):
    if len(base64.b64decode(value, validate=True)) != 32:
        raise ValueError("invalid AWG key")
    return value


def pubkey(private):
    return run(["awg", "pubkey"], data=key32(private) + "\n").stdout.strip()


def verify_awg(state, root=ROOT, conf=AWG_CONF, public=pubkey):
    sections = config_sections(Path(conf).read_text())
    if not sections or sections[0][0] != "Interface":
        raise ValueError("missing AWG interface")
    interface = sections[0][1]
    if interface.get("Address") != state["AWG_SUBNET"] + ".1/24" or interface.get("ListenPort") != state["AWG_PORT"]:
        raise ValueError("AWG metadata differs from state; refusing to rewrite it")
    server_public = public(interface["PrivateKey"])
    peers = {peer["PublicKey"]: peer for kind, peer in sections[1:] if kind == "Peer"}
    for person in people_from(state):
        client = config_sections((Path(root) / "awg/clients" / (person["name"] + ".conf")).read_text())
        if [kind for kind, _ in client] != ["Interface", "Peer"]:
            raise ValueError("invalid client config")
        local, remote = client[0][1], client[1][1]
        peer = peers.get(public(local["PrivateKey"]))
        if peer is None or remote.get("PublicKey") != server_public:
            raise ValueError("client/server key mismatch; re-import or restore correct config")
        if key32(remote["PresharedKey"]) != peer.get("PresharedKey") or local.get("Address") != peer.get("AllowedIPs"):
            raise ValueError("client PSK/address differs from server")
        for key in awg_profile.MATCH_FIELDS:
            if local.get(key, "") != interface.get(key, ""):
                raise ValueError("AWG obfuscation mismatch")


def verify_exports(state):
    """Check the exact bytes that will be published, before touching services."""
    from aggsub import read_file, read_map, page
    people = people_from(state)
    if read_map(ROOT) != {p["sub"]: p["name"] for p in people}:
        raise ValueError("distribution map differs from saved identities")
    for person in people:
        name = person["name"]
        page(ROOT, name, person["sub"])
        link = urllib.parse.urlsplit(read_file(ROOT, f"dist/{name}.vless").decode().strip())
        query = urllib.parse.parse_qs(link.query)
        expected = {"pbk": state["REALITY_PUBLIC_KEY"], "sid": state["REALITY_SHORT_ID"],
                    "sni": state["SNI_DONOR"], "security": "reality", "flow": "xtls-rprx-vision"}
        if (link.username != person["uuid"] or link.hostname != state["PANEL_HOST"]
                or link.port != int(state["VLESS_PORT"])
                or any(query.get(k) != [v] for k, v in expected.items())):
            raise ValueError("VLESS export differs from saved identities")
        encoded = read_file(ROOT, f"dist/{name}.vpn").decode().strip()[6:]
        packed = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        decoder = zlib.decompressobj()
        raw = decoder.decompress(packed[4:], 1024 * 1024 + 1)
        if (len(packed) < 5 or not decoder.eof or decoder.unused_data
                or len(raw) > 1024 * 1024 or int.from_bytes(packed[:4], "big") != len(raw)):
            raise ValueError("invalid native Amnezia export")
        outer = json.loads(raw)
        awg_meta = outer["containers"][0]["awg"]
        native = json.loads(awg_meta["last_config"])
        if awg_profile.version(state) == "3.1":
            if awg_meta.get("protocol_version") != "3.1":
                raise ValueError("native Amnezia protocol version differs from saved profile")
            import provision
            expected_profile = awg_profile.parameters(state, provision.OBFS)
            if any(awg_meta.get(k) != val or native.get(k) != val for k, val in expected_profile.items()):
                raise ValueError("native Amnezia profile metadata mismatch")
        disk = config_sections(read_file(ROOT, f"awg/clients/{name}.conf").decode())
        embedded = config_sections(native["config"])
        if [kind for kind, _ in embedded] != ["Interface", "Peer"]:
            raise ValueError("invalid embedded Amnezia configuration")
        # Legacy exports substitute DNS and may omit MTU; identity/route/obfs must agree.
        for part, fields in ((0, ("PrivateKey", "Address") + awg_profile.EXPORT_FIELDS),
                             (1, ("PublicKey", "PresharedKey", "Endpoint", "AllowedIPs"))):
            if any(embedded[part][1].get(key, "") != disk[part][1].get(key, "") for key in fields):
                raise ValueError("native Amnezia export differs from client config")
        if (native.get("client_priv_key") != disk[0][1]["PrivateKey"]
                or native.get("server_pub_key") != disk[1][1]["PublicKey"]
                or native.get("psk_key") != disk[1][1]["PresharedKey"]):
            raise ValueError("native Amnezia metadata differs from client config")


def subscription_environment(state, settings):
    """Validate the existing backend without silently changing panel settings."""
    sub_port = settings.get("subPort", "2096")
    if not 1 <= int(sub_port) <= 65535:
        raise ValueError("invalid actual subscription port")
    sub_path = settings.get("subPath", "/sub/")
    if not re.fullmatch(r"/(?:[A-Za-z0-9_-]+/)*", sub_path):
        raise ValueError("unsupported subscription path")
    if settings.get("subEnable", "true").lower() != "true":
        raise ValueError("3x-ui subscriptions are disabled; enable them explicitly before repair")
    if settings.get("subListen", "") not in {"", "0.0.0.0", "127.0.0.1", "::"}:
        raise ValueError("subscription listener must accept IPv4 loopback; configure it explicitly before repair")
    cert, key = settings.get("subCertFile", ""), settings.get("subKeyFile", "")
    if bool(cert) != bool(key):
        raise ValueError("subscription TLS needs both certificate and key")
    env = {"AGG_PORT": state["AGG_PORT"], "AGG_CERT": str(ETC / "tls/cert.pem"),
           "AGG_KEY": str(ETC / "tls/key.pem"), "SUB_PORT": sub_port,
           "SUB_SCHEME": "https" if cert else "http", "SUB_PATH": sub_path}
    if cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        if cert != settings.get("webCertFile") and not certificate_valid(cert):
            raise ValueError("separate subscription certificate expired; renew it before repair")
        env["SUB_CA"] = str(ETC / "sub-ca.pem")
    return env


def verify_live_awg():
    """Read-only check; never adopt a different runtime identity or missing peers."""
    expected = config_sections(AWG_CONF.read_text())
    interface = expected[0][1]
    actual = run(["awg", "show", "awg0", "public-key"]).stdout.strip()
    port = run(["awg", "show", "awg0", "listen-port"]).stdout.strip()
    peers = {peer["PublicKey"] for kind, peer in expected if kind == "Peer"}
    live = set(run(["awg", "show", "awg0", "peers"]).stdout.split())
    if actual != pubkey(interface["PrivateKey"]) or port != interface["ListenPort"] or peers != live:
        raise ValueError("live AWG key/port/peers differ from disk; restore consistent state explicitly")
    if interface.get("HeaderProtectionKey"):
        runtime = config_sections(run(["awg", "showconf", "awg0"]).stdout)[0][1]
        if any(runtime.get(k, "") != interface.get(k, "") for k in awg_profile.MATCH_FIELDS):
            raise ValueError("live AWG 3.1 parameters differ from saved config")


def wait_distribution(state, cert, timeout=12):
    context = ssl.create_default_context()
    context.load_verify_locations(cert)
    context.check_hostname = False  # The service is contacted over IPv4 loopback.
    context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPSHandler(context=context))
    end = time.monotonic() + timeout
    while True:
        try:
            with opener.open(f"https://127.0.0.1:{int(state['AGG_PORT'])}/healthz", timeout=2) as response:
                if response.status == 200 and response.read(16) == b"ok\n":
                    return
        except (OSError, ValueError, http.client.HTTPException):
            pass
        if time.monotonic() >= end:
            raise RuntimeError("distributor did not become ready; inspect journalctl -u aggsub; backup path was printed")
        time.sleep(0.2)


def db_settings():
    with sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True) as db:
        return dict(db.execute("SELECT key,value FROM settings"))


def backup():
    target = Path("/root/vpn-backups")
    target.mkdir(mode=0o700, exist_ok=True)
    name = target / (time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3) + ".tar.gz")
    paths = [ROOT, AWG_CONF, Path("/root/aggsub.py"), ETC, LIB, DATA,
             Path("/usr/local/bin/vpnctl"), Path("/root/.acme.sh"),
             Path("/etc/systemd/system/aggsub.service"),
             Path("/etc/systemd/system/awg-quick@awg0.service.d"),
             Path("/etc/nftables.conf"), Path("/root/cert")]
    paths += sorted(Path("/etc/systemd/system").glob("vpn-awg-recover.*"))
    paths += sorted(Path("/etc/systemd/system").glob("vpn-cert-renew.*"))
    with tempfile.TemporaryDirectory() as directory:
        db_copy = Path(directory) / "x-ui.db"
        if Path("/etc/x-ui/x-ui.db").exists():
            with sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True) as src, sqlite3.connect(db_copy) as dst:
                src.backup(dst)
        with tarfile.open(name, "w:gz") as archive:
            for path in paths:
                if path.exists():
                    archive.add(path, arcname=str(path).lstrip("/"))
            if db_copy.exists():
                archive.add(db_copy, arcname="etc/x-ui/x-ui.db")
    name.chmod(0o600)
    return name


def protected_dir(path):
    path.mkdir(parents=True, exist_ok=True)
    shutil.chown(path, user="root", group="vpn-dist")
    path.chmod(0o750)


def publish(state):
    from aggsub import read_map
    mapping = read_map(ROOT)
    if mapping != {p["sub"]: p["name"] for p in people_from(state)}:
        raise ValueError("distribution map differs from saved identities")
    protected_dir(DATA)
    protected_dir(DATA / "releases")
    generation = DATA / "releases" / (str(time.time_ns()) + "-" + secrets.token_hex(3))
    protected_dir(generation)
    files = ["awg/submap.tsv", "awg/label"]
    for name in mapping.values():
        files += [f"awg/clients/{name}.conf", f"dist/{name}.vless", f"dist/{name}.vpn"]
        if (ROOT / f"dist/{name}-vless.png").is_file():
            files.append(f"dist/{name}-vless.png")
    try:
        for relative in files:
            source = ROOT / relative
            if source.is_symlink() or not source.resolve().is_relative_to(ROOT.resolve()):
                raise ValueError("unexpected source symlink")
            dest = generation / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, dest)
        for directory, _, names in os.walk(generation):
            protected_dir(Path(directory))
            for name in names:
                path = Path(directory) / name
                shutil.chown(path, user="root", group="vpn-dist")
                path.chmod(0o640)
        from aggsub import page
        for token, name in mapping.items():
            page(generation, name, token)  # Fail before publication on incomplete exports.
        next_link = DATA / (".current-" + secrets.token_hex(4))
        next_link.symlink_to(generation)
        os.replace(next_link, DATA / "current")
    except Exception:
        shutil.rmtree(generation)
        raise
    # Keep a previous generation for in-flight reads; never remove the live one.
    old = sorted((p for p in (DATA / "releases").iterdir() if p.is_dir()), key=lambda p: p.name)
    for path in old[:-3]:
        if time.time() - path.stat().st_mtime > 60:
            shutil.rmtree(path)


def certificate_valid(cert, seconds=0):
    return run(["openssl", "x509", "-in", cert, "-noout", "-checkend", str(seconds)], check=False).returncode == 0


def deploy_certificate(settings):
    cert, key = settings["webCertFile"], settings["webKeyFile"]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)  # Validate the pair before publishing either file.
    if not certificate_valid(cert):
        raise ValueError("certificate expired; run vpnctl cert-renew before repair")
    protected_dir(ETC)
    sub_cert = settings.get("subCertFile", "")
    if sub_cert:
        # A one-time copy becomes stale when a self-signed certificate/issuer rotates.
        public_pem = Path(sub_cert).read_text()
        ssl.PEM_cert_to_DER_cert(public_pem.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----")
        atomic(ETC / "sub-ca.pem", public_pem, 0o640)
        shutil.chown(ETC / "sub-ca.pem", user="root", group="vpn-dist")
    generation = ETC / ("tls-" + str(time.time_ns()))
    protected_dir(generation)
    for source, name in ((cert, "cert.pem"), (key, "key.pem")):
        target = generation / name
        shutil.copyfile(source, target)
        shutil.chown(target, user="root", group="vpn-dist")
        target.chmod(0o640)
    link = ETC / (".tls-" + secrets.token_hex(3))
    link.symlink_to(generation)
    os.replace(link, ETC / "tls")
    for old in ETC.glob("tls-*"):
        if old.is_dir() and old != generation and time.time() - old.stat().st_mtime > 60:
            shutil.rmtree(old)
    if run(["systemctl", "is-active", "--quiet", "aggsub"], check=False).returncode == 0:
        run(["systemctl", "reload", "aggsub"], check=False)
    # Also cover renewals triggered by a legacy acme cron job, not just our timer.
    digest = hashlib.sha256(Path(cert).read_bytes()).hexdigest()
    stamp = ETC / "panel-cert.sha256"
    if not stamp.exists() or stamp.read_text() != digest:
        run(["systemctl", "try-restart", "x-ui"])
        atomic(stamp, digest)


def install_unit(name, content):
    atomic(Path("/etc/systemd/system") / name, content, 0o644)


def repair(state):
    validate_state(state)
    verify_awg(state)
    settings = db_settings()
    env = subscription_environment(state, settings)
    verify_exports(state)
    if run(["awg", "show", "awg0"], check=False).returncode == 0:
        verify_live_awg()
    # Validate the pair, but permit renewal of an expired LE certificate below.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(settings["webCertFile"], settings["webKeyFile"])
    if not certificate_valid(settings["webCertFile"]) and (
            "/cert/le/" not in settings["webCertFile"] or not Path("/root/.acme.sh/acme.sh").is_file()):
        raise ValueError("expired certificate cannot be renewed automatically; restore TLS before repair")
    saved = backup()
    print(f"Private backup: {saved}. Do not share this archive.", flush=True)
    if run(["id", "vpn-dist"], check=False).returncode:
        run(["useradd", "--system", "--user-group", "--no-create-home", "--shell", "/usr/sbin/nologin", "vpn-dist"])
    LIB.mkdir(mode=0o755, parents=True, exist_ok=True)
    LIB.chmod(0o755)  # The unprivileged distributor must be able to traverse this directory.
    for name in ("vpnctl.py", "aggsub.py", "provision.py", "awg_profile.py", "awg_upgrade.py"):
        source = Path(__file__).resolve().parent / name
        dest = LIB / name
        if source != dest:
            shutil.copyfile(source, dest)
        dest.chmod(0o644)
    atomic("/usr/local/bin/vpnctl", '#!/bin/sh\nexec /usr/bin/python3 /usr/local/lib/server-init/vpnctl.py "$@"\n', 0o755)
    publish(state)
    if not certificate_valid(settings["webCertFile"]):
        cert_renew(state)
    deploy_certificate(settings)
    atomic(ETC / "service.env", "".join(f"{k}={v}\n" for k, v in env.items()))
    install_unit("aggsub.service", """[Unit]
Description=Bounded VPN configuration distributor
After=network-online.target
Wants=network-online.target
[Service]
User=vpn-dist
Group=vpn-dist
EnvironmentFile=/etc/vpn-dist/service.env
ExecStart=/usr/bin/python3 /usr/local/lib/server-init/aggsub.py
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3
TimeoutStopSec=10
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
UMask=0077
TasksMax=96
MemoryMax=256M
LimitNOFILE=512
[Install]
WantedBy=multi-user.target
""")
    install_unit("awg-quick@awg0.service.d/server-init.conf", """[Service]
ExecStart=
ExecStart=/usr/local/bin/vpnctl awg-start
ExecStop=
ExecStop=/usr/local/bin/vpnctl awg-stop
""")
    install_unit("vpn-awg-recover.service", """[Unit]
Description=Recover only a missing AWG interface (never idle peers)
[Service]
Type=oneshot
ExecStart=/usr/local/bin/vpnctl recover
TimeoutStartSec=90
""")
    install_unit("vpn-awg-recover.timer", """[Unit]
Description=Check that the configured AWG interface exists
[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
[Install]
WantedBy=timers.target
""")
    install_unit("vpn-awg-bootstrap-nat.service", """[Unit]
Description=Keep AWG NAT available until restrictive firewall is confirmed
After=nftables.service network-online.target
Wants=network-online.target
Before=awg-quick@awg0.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/vpnctl firewall-prime-runtime
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
""")
    if "/cert/le/" in settings["webCertFile"]:
        install_unit("vpn-cert-renew.service", """[Unit]
Description=Renew short-lived IP certificate before expiry
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/vpnctl cert-renew
TimeoutStartSec=300
""")
        install_unit("vpn-cert-renew.timer", """[Unit]
Description=Check IP certificate expiry every six hours
[Timer]
OnBootSec=10min
OnUnitActiveSec=6h
RandomizedDelaySec=10min
[Install]
WantedBy=timers.target
""")
    run(["systemctl", "daemon-reload"])
    # A failed unit must be reset before adopting a live legacy interface.
    # Legacy installer started awg0 manually. Adopt the live interface without a down/up.
    run(["systemctl", "enable", "awg-quick@awg0", "aggsub"])
    run(["systemctl", "reset-failed", "awg-quick@awg0"], check=False)
    run(["systemctl", "start", "awg-quick@awg0"])
    run(["systemctl", "restart", "aggsub"])
    wait_distribution(state, settings["webCertFile"])
    run(["systemctl", "enable", "--now", "vpn-awg-recover.timer"])
    if "/cert/le/" in settings["webCertFile"]:
        run(["systemctl", "enable", "--now", "vpn-cert-renew.timer"])
        # Migrate a legacy restart hook immediately, not only after the next expiry.
        cert_renew(state)
    print(f"Repair applied. Backup: {saved}. VPN keys, peers and firewall were not changed.")


def awg_start():
    if run(["awg", "show", "awg0"], check=False).returncode == 0:
        verify_live_awg()
        return
    run(["awg-quick", "up", "awg0"])


def awg_stop():
    if run(["awg", "show", "awg0"], check=False).returncode == 0:
        run(["awg-quick", "down", "awg0"])


def recover():
    if run(["systemctl", "is-enabled", "--quiet", "awg-quick@awg0"], check=False).returncode:
        return  # Respect an administrator intentionally disabling the service.
    status = run(["systemctl", "is-active", "awg-quick@awg0"], check=False).stdout.strip()
    if status not in {"active", "failed"}:
        return  # Respect an intentional systemctl stop, even when still enabled.
    if run(["awg", "show", "awg0"], check=False).returncode and AWG_CONF.exists():
        run(["systemctl", "reset-failed", "awg-quick@awg0"], check=False)
        run(["systemctl", "restart", "awg-quick@awg0"])
        print("Recovered missing awg0 interface; no keys or peers were changed.")


def cert_renew(state):
    settings = db_settings()
    cert, key = settings.get("webCertFile", ""), settings.get("webKeyFile", "")
    if "/cert/le/" not in cert or not Path("/root/.acme.sh/acme.sh").is_file():
        raise ValueError("automatic renewal requires an existing acme.sh IP certificate")
    if certificate_valid(cert, 72 * 3600):
        if (ETC / "tls").exists():
            # --install-cert persists the hook even when --issue is unnecessary.
            run(["/root/.acme.sh/acme.sh", "--install-cert", "-d",
                 str(ipaddress.IPv4Address(state["PANEL_HOST"])), "--ecc", "--fullchain-file", cert,
                 "--key-file", key, "--reloadcmd", "/usr/local/bin/vpnctl cert-deploy"])
            deploy_certificate(settings)
        return
    # Inspect the actual certificate rather than trusting a stale 30-day ACME interval.
    # Pinning --days 3 also fixes the saved interval on a successful issuance.
    ip = str(ipaddress.IPv4Address(state["PANEL_HOST"]))
    acme = ["/root/.acme.sh/acme.sh"]
    # Retire the legacy hook BEFORE issuance, which can also run an install hook.
    run(acme + ["--install-cert", "-d", ip, "--ecc", "--fullchain-file", cert,
                "--key-file", key, "--reloadcmd", "/bin/true"], check=False)
    run(acme + ["--issue", "--server", "letsencrypt", "--standalone", "-d", ip,
                "--keylength", "ec-256", "--certificate-profile", "shortlived", "--days", "3", "--force"], timeout=240)
    # The old hook may exist in acme.sh's domain config; replace it with hot reload.
    run(acme + ["--install-cert", "-d", ip, "--ecc", "--fullchain-file", cert,
                "--key-file", key, "--reloadcmd", "/usr/local/bin/vpnctl cert-deploy"], timeout=60)
    deploy_certificate(settings)
    print("IP certificate renewed. AWG was not restarted; panel/VLESS may reconnect briefly.")


def firewall_bootstrap_text(state, wan):
    """Minimal persistent NAT. It never adds an input/forward drop policy."""
    validate_state(state)
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", wan):
        raise ValueError("invalid WAN interface")
    return f'''#!/usr/sbin/nft -f
# server-init bootstrap NAT: connectivity only, no inbound filtering.
table inet server_init {{
 chain postrouting {{
  type nat hook postrouting priority srcnat; policy accept;
  ip saddr {state['AWG_SUBNET']}.0/24 oifname "{wan}" masquerade
 }}
}}
'''


def firewall_prime_runtime():
    """Re-create bootstrap NAT at boot unless the restrictive firewall is confirmed."""
    if (FW / "pending.json").exists():
        return
    if NFT_CONF.is_file() and CONFIRMED_FIREWALL_MARKER in NFT_CONF.read_text():
        return
    if not BOOTSTRAP_NAT.is_file():
        raise ValueError("bootstrap NAT file missing")
    run(["nft", "delete", "table", "inet", "server_init"], check=False)
    run(["nft", "-f", BOOTSTRAP_NAT])


def firewall_prime(state):
    """Persist AWG NAT before the risky input firewall transaction."""
    if (FW / "pending.json").exists():
        raise ValueError("firewall confirmation/rollback already pending")
    if NFT_CONF.is_file() and CONFIRMED_FIREWALL_MARKER in NFT_CONF.read_text():
        print("Restrictive firewall already confirmed; bootstrap NAT is not needed.")
        return
    route = json.loads(run(["ip", "-j", "-4", "route", "get", "1.1.1.1"]).stdout)[0]
    text = firewall_bootstrap_text(state, route["dev"])
    atomic(BOOTSTRAP_NAT, text, 0o644)
    run(["nft", "-c", "-f", BOOTSTRAP_NAT])
    run(["systemctl", "enable", "vpn-awg-bootstrap-nat.service"])
    run(["systemctl", "restart", "vpn-awg-bootstrap-nat.service"])
    print("Persistent AWG bootstrap NAT enabled. It does not restrict inbound SSH or other ports.")


def firewall_text(state, wan, ssh_ports):
    validate_state(state)
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", wan):
        raise ValueError("invalid WAN interface")
    ports = sorted(set(int(p) for p in ssh_ports) | {80, int(state["PANEL_PORT"]), int(state["VLESS_PORT"]), int(state["AGG_PORT"])})
    if any(not 1 <= port <= 65535 for port in ports):
        raise ValueError("invalid listening port")
    smtp = 'tcp dport { 25, 465, 587 } reject with icmpx type admin-prohibited' if state.get("BLOCK_SMTP", "1") == "1" else ""
    return f'''#!/usr/sbin/nft -f
{CONFIRMED_FIREWALL_MARKER}
flush ruleset
# Dedicated VPN host only. Apply with a rollback timer, then confirm via NEW SSH.
table inet server_init {{
 chain input {{
  type filter hook input priority filter; policy drop;
  iifname "lo" accept
  ct state established,related accept
  ct state invalid drop
  meta l4proto {{ icmp, ipv6-icmp }} accept
  tcp dport {{ {', '.join(map(str, ports))} }} accept
  udp dport {state['AWG_PORT']} accept
 }}
 chain forward {{
  type filter hook forward priority filter; policy drop;
  {('iifname "awg0" ' + smtp) if smtp else ''}
  ct state established,related accept
  ct state invalid drop
  iifname "awg0" oifname "{wan}" ip saddr {state['AWG_SUBNET']}.0/24 accept
 }}
 chain output {{
  type filter hook output priority filter; policy accept;
  {smtp}
 }}
 chain postrouting {{
  type nat hook postrouting priority srcnat; policy accept;
  ip saddr {state['AWG_SUBNET']}.0/24 oifname "{wan}" masquerade
 }}
}}
'''


def require_external_ssh(connection):
    parts = connection.split()
    if len(parts) != 4:
        raise ValueError("use an external SSH connection from your computer")
    source = ipaddress.ip_address(parts[0])
    local = {ipaddress.ip_address(a["local"]) for interface in json.loads(
             run(["ip", "-j", "address", "show"]).stdout)
             for a in interface.get("addr_info", []) if "local" in a}
    if source.is_loopback or source.is_unspecified or source in local:
        raise ValueError("self-SSH is not an external connectivity test; open a terminal on YOUR COMPUTER")


def firewall_apply(state, replace=False):
    if (FW / "pending.json").exists():
        raise ValueError("firewall confirmation/rollback already pending")
    connection = os.getenv("SSH_CONNECTION", "")
    if len(connection.split()) != 4:
        raise ValueError("apply firewall over SSH so the active server port can be preserved")
    require_external_ssh(connection)
    live = run(["nft", "list", "ruleset"]).stdout
    if live.strip() and not replace:
        raise ValueError("existing firewall found; review it before explicit --replace-firewall")
    route = json.loads(run(["ip", "-j", "-4", "route", "get", "1.1.1.1"]).stdout)[0]
    ports = {int(connection.split()[3]), 22}
    for line in run(["ss", "-H", "-ltnp"]).stdout.splitlines():
        if '"sshd"' in line:
            ports.add(int(line.split()[3].rsplit(":", 1)[1]))
    FW.mkdir(mode=0o700, exist_ok=True)
    atomic(FW / "old.nft", "flush ruleset\n" + live)
    persistent_existed = NFT_CONF.exists()
    if persistent_existed:
        atomic(FW / "old.conf", NFT_CONF.read_text())
    atomic(FW / "candidate.nft", firewall_text(state, route["dev"], ports))
    run(["nft", "-c", "-f", FW / "candidate.nft"])
    token = secrets.token_hex(8)
    unit = "server-init-firewall-rollback-" + token
    atomic(FW / "pending.json", json.dumps({"connection": connection, "token": token, "unit": unit, "persistent_existed": persistent_existed}))
    try:
        run(["systemd-run", "--collect", "--unit=" + unit, "--on-active=180s",
             "--timer-property=RemainAfterElapse=no", "/usr/local/bin/vpnctl", "firewall-rollback", token])
    except Exception:
        (FW / "pending.json").unlink()
        raise
    try:
        run(["nft", "-f", FW / "candidate.nft"])
    except Exception:
        firewall_rollback()
        raise
    server_port = int(connection.split()[3])
    remote = (f'env SSH_CONNECTION="$SSH_CONNECTION" vpnctl firewall-confirm {token} '
              '&& vpnctl doctor && cat /root/vpn-handoff.md')
    print("Firewall hardening is TEMPORARY. AWG bootstrap NAT is already persistent.")
    print("ON YOUR COMPUTER, open a NEW terminal and run this single command:")
    print(f"ssh -p {server_port} -o ControlPath=none root@{state['PANEL_HOST']} {shlex.quote(remote)}")
    print("If you do nothing for 180 seconds, only the restrictive firewall rolls back; AWG NAT remains available.")


def firewall_rollback(token=""):
    if (FW / "pending.json").exists():
        pending = json.loads((FW / "pending.json").read_text())
        if token and not secrets.compare_digest(token, pending["token"]):
            return  # An old timer must not roll back a newer transaction.
        run(["nft", "-f", FW / "old.nft"])
        if pending.get("persistent_existed"):
            atomic(NFT_CONF, (FW / "old.conf").read_text())
        else:
            NFT_CONF.unlink(missing_ok=True)
        (FW / "pending.json").unlink()
        print("Previous live firewall restored; persistent config was never replaced.")


def firewall_confirm(token):
    pending = json.loads((FW / "pending.json").read_text())
    connection = os.getenv("SSH_CONNECTION", "")
    if not secrets.compare_digest(token, pending["token"]) or len(connection.split()) != 4 or connection == pending["connection"]:
        raise ValueError("confirmation must use the printed token from a NEW SSH connection")
    require_external_ssh(connection)
    run(["systemctl", "enable", "nftables"])
    atomic(NFT_CONF, (FW / "candidate.nft").read_text(), 0o600)
    (FW / "pending.json").unlink()
    run(["systemctl", "stop", pending["unit"] + ".timer"], check=False)
    print("Firewall confirmed and made persistent.")


def doctor(state, pre_firewall=False):
    errors = 0
    if (FW / "pending.json").exists():
        print("WARN firewall confirmation is pending; rules will roll back unless confirmed")
        errors += 1
    for service in ("x-ui", "awg-quick@awg0", "aggsub", "vpn-awg-recover.timer"):
        good = run(["systemctl", "is-active", "--quiet", service], check=False).returncode == 0
        print(f"{'OK' if good else 'FAIL'} service {service}")
        errors += not good
    try:
        verify_awg(state)
        verify_live_awg()
        print("OK saved AWG identities and live peer list match")
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f"FAIL AWG config consistency: {exc}")
        errors += 1
    handshakes = run(["awg", "show", "awg0", "latest-handshakes"], check=False)
    if not handshakes.returncode:
        times = [int(line.split()[1]) for line in handshakes.stdout.splitlines() if len(line.split()) == 2]
        recent = sum(t > 0 and time.time() - t < 180 for t in times)
        print(f"INFO AWG peers: {len(times)}, recent handshakes: {recent}. Idle peers are not failures.")
    forwarding = run(["sysctl", "-n", "net.ipv4.ip_forward"], check=False).stdout.strip() == "1"
    print(f"{'OK' if forwarding else 'FAIL'} IPv4 forwarding")
    errors += not forwarding
    settings = db_settings()
    cert = settings.get("webCertFile", "")
    good = bool(cert) and certificate_valid(cert)
    print(f"{'OK' if good else 'FAIL'} TLS certificate valid")
    errors += not good
    if good and not certificate_valid(cert, 48 * 3600):
        print("WARN TLS certificate expires in less than 48 hours")
        errors += 1
    if "/cert/le/" in cert:
        active = run(["systemctl", "is-active", "--quiet", "vpn-cert-renew.timer"], check=False).returncode == 0
        print(f"{'OK' if active else 'FAIL'} certificate renewal timer")
        errors += not active
    try:
        ctx = ssl.create_default_context()
        ctx.load_verify_locations(cert)
        ctx.check_hostname = False
        ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        token = people_from(state)[0]["sub"]
        for route in ("healthz", "p/" + token, "awg/" + token, "sub/" + token):
            url = f"https://127.0.0.1:{int(state['AGG_PORT'])}/{route}"
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
            try:
                with opener.open(url, timeout=8) as response:
                    content = response.read(1024 * 1024 + 1)
                    if not content:
                        raise ValueError("empty response")
                    if route.startswith("sub/"):
                        from aggsub import decode_subscription
                        decode_subscription(content)
                print(f"OK /{route.split('/')[0]} endpoint")
            except (OSError, ValueError, http.client.HTTPException):
                print(f"FAIL /{route.split('/')[0]} endpoint (details intentionally omit personal token)")
                errors += 1
    except (OSError, ValueError, ssl.SSLError):
        print("FAIL unable to verify distributor TLS")
        errors += 1
    from awg_upgrade import network_issues
    try:
        issues = network_issues(state)
        if pre_firewall:
            expected = {
                "expected AWG forwarding rule missing for active WAN",
                "expected AWG UDP input rule missing",
                "persistent firewall configuration missing",
            }
            unexpected = [issue for issue in issues if issue not in expected]
            primed = (BOOTSTRAP_NAT.is_file() and
                      run(["systemctl", "is-enabled", "--quiet", "vpn-awg-bootstrap-nat.service"],
                          check=False).returncode == 0)
            if primed and not unexpected:
                print("OK persistent AWG bootstrap NAT; restrictive input firewall is not confirmed yet")
            else:
                for issue in unexpected:
                    print(f"WARN {issue}")
                if not primed:
                    print("WARN persistent AWG bootstrap NAT is not enabled")
        else:
            for issue in issues:
                print(f"FAIL {issue}")
            if not issues:
                print("OK managed AWG NAT, forwarding and UDP input for active WAN")
            else:
                primed = (BOOTSTRAP_NAT.is_file() and
                          run(["systemctl", "is-enabled", "--quiet", "vpn-awg-bootstrap-nat.service"],
                              check=False).returncode == 0)
                if primed:
                    print("INFO AWG NAT fallback is persistent, but restrictive firewall hardening is not confirmed.")
                errors += 1
    except (OSError, ValueError, KeyError, RuntimeError):
        print(f"{'WARN' if pre_firewall else 'FAIL'} unable to inspect AWG NAT/firewall")
        if not pre_firewall:
            errors += 1
    print("INFO This is a local check, not a full VPN connection test from your ISP/mobile network.")
    return min(errors, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["repair", "doctor", "backup", "recover", "awg-start", "awg-stop", "cert-renew", "cert-deploy", "firewall-prime", "firewall-prime-runtime", "firewall-apply", "firewall-confirm", "firewall-rollback", "validate", "awg-upgrade", "awg-rollback"])
    parser.add_argument("token", nargs="?", default="")
    parser.add_argument("--replace-firewall", action="store_true")
    parser.add_argument("--pre-firewall", action="store_true", help="bootstrap-only: NAT not applied yet")
    args = parser.parse_args()
    os.umask(0o077)
    if os.geteuid() != 0:
        parser.error("run as root")
    # Nested systemd start/stop and acme deploy hooks must not reacquire parent locks.
    unlocked = {"doctor", "validate", "awg-start", "awg-stop", "cert-deploy", "firewall-prime-runtime"}
    lock = None
    if args.command not in unlocked:
        lock_path = "/run/server-init-firewall.lock" if args.command.startswith("firewall-") else "/run/server-init.lock"
        lock = open(lock_path, "a")
        try:
            flags = fcntl.LOCK_EX if args.command == "firewall-rollback" else fcntl.LOCK_EX | fcntl.LOCK_NB
            fcntl.flock(lock, flags)
        except BlockingIOError:
            if args.command == "recover":
                return 0
            raise RuntimeError("another installer/maintenance operation is active")
    if args.command in {"awg-upgrade", "awg-rollback"}:
        import awg_upgrade
        (awg_upgrade.upgrade if args.command == "awg-upgrade" else awg_upgrade.rollback)()
    elif args.command == "firewall-prime-runtime":
        firewall_prime_runtime()
    elif args.command == "awg-start":
        awg_start()
    elif args.command == "awg-stop":
        awg_stop()
    elif args.command == "firewall-rollback":
        firewall_rollback(args.token)
    elif args.command == "firewall-confirm":
        firewall_confirm(args.token)
    elif args.command == "recover":
        recover()
    elif args.command == "backup":
        print(backup())
    elif args.command == "cert-deploy":
        deploy_certificate(db_settings())
    else:
        state = validate_state(load_env(ROOT / "secrets.env"))
        if args.command == "repair":
            repair(state)
        elif args.command == "doctor":
            return doctor(state, args.pre_firewall)
        elif args.command == "cert-renew":
            cert_renew(state)
        elif args.command == "firewall-prime":
            firewall_prime(state)
        elif args.command == "firewall-apply":
            firewall_apply(state, args.replace_firewall)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, IndexError, RuntimeError, zlib.error, sqlite3.Error) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
