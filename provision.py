#!/usr/bin/env python3
"""Generate a NEW installation once. Existing state/keys are never overwritten.

Called by install.sh after dependencies are present. No package/network/service
operations. The complete identity state is saved before rendering live configs.
"""
import argparse
import base64
import contextlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import sqlite3
import struct
import sys
import uuid
import zlib

from vpnctl import ROOT, AWG_CONF, atomic, run, validate_state, NAME

OBFS = {"Jc": "5", "Jmin": "10", "Jmax": "50", "S1": "128", "S2": "96", "S3": "41", "S4": "5",
        "H1": "1710377591-1722398516", "H2": "1818569401-2116313076",
        "H3": "2127718891-2143330769", "H4": "2145494949-2146588297",
        "I1": "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>"}


def parse_x25519(stdout, stderr=""):
    """Accept documented Xray labels, never confuse Hash32 with the public key.

    v26.6.1 prints 'Password (PublicKey)'; older versions used 'Password' or
    'Public key'. Both streams are captured privately; errors never echo keys.
    """
    aliases = {"privatekey": "private", "publickey": "public",
               "password": "public", "password(publickey)": "public"}
    fields = {}
    for line in (stdout + "\n" + stderr).splitlines():
        label, separator, value = line.partition(":")
        field = aliases.get(re.sub(r"\s+", "", label).lower())
        if not separator or field is None:
            continue
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}=?", value):
            raise ValueError("invalid Xray X25519 key encoding")
        raw = base64.b64decode(value.rstrip("=") + "=", altchars=b"-_", validate=True)
        canonical = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        if len(raw) != 32 or canonical != value.rstrip("="):
            raise ValueError("invalid Xray X25519 key encoding")
        if field in fields and fields[field] != canonical:
            raise ValueError("conflicting Xray X25519 key fields")
        fields[field] = canonical
    if set(fields) != {"private", "public"}:
        raise ValueError("unrecognized Xray x25519 output: missing private/public key")
    return fields["private"], fields["public"]


def check_resume_before_identities(root=None, awg_conf=None, database=None, xui=None):
    """Read-only guard for the specific bootstrap failure before new_state saved.

    This is NOT a general reinstall/resume switch. Any identities, export files,
    live AWG interfaces or database inbounds block it. No files are deleted.
    Called while install.sh holds the maintenance lock.
    """
    root = ROOT if root is None else Path(root)
    awg_conf = AWG_CONF if awg_conf is None else Path(awg_conf)
    database = Path("/etc/x-ui/x-ui.db") if database is None else Path(database)
    xui = Path("/usr/local/x-ui/x-ui") if xui is None else Path(xui)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("resume requires the interrupted bootstrap directory")
    if awg_conf.exists() or awg_conf.is_symlink():
        raise ValueError("existing AWG configuration: resume refused")
    # In the reported failure the sole work file is the downloaded installer.
    # Even a partial state.json, exported config or dangling link must stop us.
    if any(p.name != "xui-installer.sh" or not p.is_file() or p.is_symlink()
           for p in root.iterdir()):
        raise ValueError("existing identity/export or unexpected work file: resume refused")
    if not database.is_file() or database.is_symlink() or not xui.is_file() or not os.access(xui, os.X_OK):
        raise ValueError("resume requires an installed 3x-ui binary and readable database")
    try:
        with contextlib.closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as db:
            if db.execute("SELECT COUNT(*) FROM inbounds").fetchone()[0] != 0:
                raise ValueError("existing 3x-ui inbounds: resume refused")
    except sqlite3.Error:
        raise ValueError("cannot verify empty 3x-ui database: resume refused") from None
    if run(["awg", "show", "interfaces"]).stdout.strip():
        raise ValueError("live AWG interface exists: resume refused")


def new_state(env, xray):
    result = run([xray, "x25519"])
    private, public = parse_x25519(result.stdout, result.stderr)
    supplied = env.get("CLIENTS_JSON", "")
    if supplied:
        people = json.loads(supplied)
    else:
        names = env.get("CLIENTS", "denis vlad liza parents router svyt").split()
        people = [{"name": n, "uuid": str(uuid.uuid4()), "sub": secrets.token_urlsafe(18)} for n in names]
    # Deliberately discard unexpected extra fields from cross-server CLIENTS_JSON.
    people = [{k: p[k] for k in ("name", "uuid", "sub")} for p in people]
    state = {"PANEL_PORT": env.get("PANEL_PORT", str(20000 + secrets.randbelow(40000))),
             "PANEL_USER": "admin_" + secrets.token_hex(4), "PANEL_PASS": secrets.token_urlsafe(32),
             "PANEL_PATH_RAW": secrets.token_hex(12), "SNI_DONOR": env.get("SNI_DONOR", "www.nvidia.com"),
             "VLESS_PORT": env.get("VLESS_PORT", "7443"), "AWG_PORT": env.get("AWG_PORT", "39743"),
             "AWG_SUBNET": env.get("AWG_SUBNET", "10.9.7"), "SUB_PORT": env.get("SUB_PORT", "2096"),
             "AGG_PORT": env.get("AGG_PORT", "2087"), "SRV_LABEL": env.get("SRV_LABEL", "S1"),
             "PANEL_HOST": env["PUBIP"], "BLOCK_SMTP": env.get("BLOCK_SMTP", "1"),
             "AWG_MTU": env.get("AWG_MTU", "1376"),
             "REALITY_PRIVATE_KEY": private, "REALITY_PUBLIC_KEY": public,
             "REALITY_SHORT_ID": secrets.token_hex(8), "CLIENTS_JSON": json.dumps(people, separators=(",", ":"))}
    state["PANEL_PATH"] = "/" + state["PANEL_PATH_RAW"] + "/"
    validate_state(state)
    if not NAME.fullmatch(state["SRV_LABEL"]) or not 1280 <= int(state["AWG_MTU"]) <= 1420:
        raise ValueError("invalid server label or AWG MTU (1280..1420)")
    state["AWG_SRV_PRIV"] = run(["awg", "genkey"]).stdout.strip()
    server_public = run(["awg", "pubkey"], data=state["AWG_SRV_PRIV"] + "\n").stdout.strip()
    clients = []
    for idx, person in enumerate(people, 2):
        private = run(["awg", "genkey"]).stdout.strip()
        clients.append({**person, "private": private,
                        "public": run(["awg", "pubkey"], data=private + "\n").stdout.strip(),
                        "psk": run(["awg", "genpsk"]).stdout.strip(),
                        "ip": state["AWG_SUBNET"] + "." + str(idx)})
    return {"schema": 1, "settings": state, "server_public": server_public, "clients": clients}


def amnezia_key(state, client, config, server_public):
    common = dict(OBFS, I2="", I3="", I4="", I5="")
    # Amnezia substitutes its DNS placeholders when importing the native key.
    native = config.replace("DNS = 1.1.1.1, 8.8.8.8", "DNS = $PRIMARY_DNS, $SECONDARY_DNS")
    last = dict(common, allowed_ips=["0.0.0.0/0", "::/0"], clientId=client["public"],
                client_ip=client["ip"], client_priv_key=client["private"], client_pub_key=client["public"],
                config=native, hostName=state["PANEL_HOST"], mtu=state["AWG_MTU"],
                persistent_keep_alive="25", port=int(state["AWG_PORT"]), psk_key=client["psk"], server_pub_key=server_public)
    awg = dict(common, last_config=json.dumps(last), port=state["AWG_PORT"], protocol_version="2",
               subnet_address=state["AWG_SUBNET"] + ".0", transport_proto="udp")
    outer = {"containers": [{"awg": awg, "container": "amnezia-awg2"}], "defaultContainer": "amnezia-awg2",
             "description": state["SRV_LABEL"] + "-" + client["name"], "dns1": "1.1.1.1", "dns2": "8.8.8.8", "hostName": state["PANEL_HOST"]}
    raw = json.dumps(outer, ensure_ascii=False).encode()
    return "vpn://" + base64.urlsafe_b64encode(struct.pack(">I", len(raw)) + zlib.compress(raw, 9)).decode().rstrip("=")


def render(bundle, root=ROOT, awg_conf=AWG_CONF, qr=True):
    state = bundle["settings"]
    validate_state(state)
    root = Path(root)
    obfs = "".join(f"{key} = {value}\n" for key, value in OBFS.items())
    server = (f"[Interface]\nAddress = {state['AWG_SUBNET']}.1/24\nListenPort = {state['AWG_PORT']}\n"
              f"PrivateKey = {state['AWG_SRV_PRIV']}\nMTU = {state['AWG_MTU']}\n" + obfs)
    for client in bundle["clients"]:
        server += f"\n[Peer]\nPublicKey = {client['public']}\nPresharedKey = {client['psk']}\nAllowedIPs = {client['ip']}/32\n"
        config = (f"[Interface]\nAddress = {client['ip']}/32\nDNS = 1.1.1.1, 8.8.8.8\n"
                  f"PrivateKey = {client['private']}\nMTU = {state['AWG_MTU']}\n" + obfs +
                  "I2 = \nI3 = \nI4 = \nI5 = \n\n[Peer]\n" +
                  f"PublicKey = {bundle['server_public']}\nPresharedKey = {client['psk']}\n"
                  f"AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {state['PANEL_HOST']}:{state['AWG_PORT']}\nPersistentKeepalive = 25\n")
        name = client["name"]
        atomic(root / f"awg/clients/{name}.conf", config)
        link = (f"vless://{client['uuid']}@{state['PANEL_HOST']}:{state['VLESS_PORT']}?encryption=none&flow=xtls-rprx-vision"
                f"&fp=chrome&pbk={state['REALITY_PUBLIC_KEY']}&security=reality&sid={state['REALITY_SHORT_ID']}"
                f"&sni={state['SNI_DONOR']}&spx=%2F#{state['SRV_LABEL']}-{name}")
        atomic(root / f"dist/{name}.vless", link)
        atomic(root / f"dist/{name}.vpn", amnezia_key(state, client, config, bundle["server_public"]))
        if qr:
            run(["qrencode", "-s", "8", "-m", "2", "-o", root / f"dist/{name}-vless.png"], data=link)
    atomic(awg_conf, server)
    atomic(root / "awg/submap.tsv", "".join(f"{p['sub']}\t{p['name']}\n" for p in bundle["clients"]))
    atomic(root / "awg/label", state["SRV_LABEL"])
    atomic(root / "secrets.env", "".join(f"{k}={shlex.quote(v)}\n" for k, v in state.items()))
    clients = [{"id": p["uuid"], "flow": "xtls-rprx-vision", "email": p["name"], "limitIp": 0,
                "totalGB": 0, "expiryTime": 0, "enable": True, "tgId": "", "subId": p["sub"], "comment": "", "reset": 0}
               for p in bundle["clients"]]
    reality = {"show": False, "target": state["SNI_DONOR"] + ":443", "xver": 0,
               "serverNames": [state["SNI_DONOR"]], "privateKey": state["REALITY_PRIVATE_KEY"],
               "shortIds": [state["REALITY_SHORT_ID"]], "settings": {"publicKey": state["REALITY_PUBLIC_KEY"], "fingerprint": "chrome", "spiderX": "/"}}
    inbound = {"enable": True, "remark": "VLESS-Reality-Vision", "listen": "", "port": int(state["VLESS_PORT"]),
               "protocol": "vless", "expiryTime": 0,
               "settings": json.dumps({"clients": clients, "decryption": "none", "fallbacks": []}),
               "streamSettings": json.dumps({"network": "tcp", "security": "reality", "realitySettings": reality,
                                              "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}}}),
               "sniffing": json.dumps({"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False, "routeOnly": False})}
    atomic(root / "inbound.json", json.dumps(inbound))


def main(argv=()):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-resume-before-identities", action="store_true")
    args = parser.parse_args(argv)
    os.umask(0o077)
    if os.geteuid() != 0:
        raise ValueError("root required")
    if args.check_resume_before_identities:
        check_resume_before_identities()
        print("OK: no saved VPN identities, exports, inbounds or live AWG interfaces; bootstrap can continue")
        return
    if (ROOT / "state.json").exists() or (ROOT / "secrets.env").exists() or AWG_CONF.exists():
        raise ValueError("existing identities detected; use repair, never regenerate keys implicitly")
    matches = list(Path("/usr/local/x-ui/bin").glob("xray-linux-*"))
    if len(matches) != 1:
        raise ValueError("expected exactly one Xray binary")
    bundle = new_state(os.environ, matches[0])
    ROOT.mkdir(mode=0o700, exist_ok=True)
    # Recovery source is committed before changing any live configuration.
    atomic(ROOT / "state.json", json.dumps(bundle, indent=2))
    render(bundle)


if __name__ == "__main__":
    main(sys.argv[1:])
