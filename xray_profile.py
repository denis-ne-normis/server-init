"""One VLESS/REALITY profile for share links and XKeen outbounds.

Keep the legacy Xray JSON aliases (tcp, vnext, publicKey): they also work on
current Xray and avoid requiring a new config schema on existing routers.
"""
import base64
import ipaddress
import re
import uuid
from urllib.parse import parse_qs, quote, urlencode, urlsplit

FINGERPRINTS = ("chrome", "firefox", "safari")


def donor_name(value):
    if not isinstance(value, str) or len(value) > 253:
        raise ValueError("invalid Reality donor hostname")
    labels = value.split(".")
    if len(labels) < 2 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", x) for x in labels):
        raise ValueError("Reality donor must be a DNS hostname, without scheme, port or path")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value.lower()
    raise ValueError("Reality donor must be a DNS hostname")


def fingerprint(state):
    value = state.get("REALITY_FINGERPRINT", "chrome")
    if value not in FINGERPRINTS:
        raise ValueError("Reality fingerprint must be chrome, firefox or safari")
    return value


def share_link(state, person):
    query = {"encryption": "none", "flow": "xtls-rprx-vision", "type": "tcp",
             "fp": fingerprint(state), "pbk": state["REALITY_PUBLIC_KEY"],
             "security": "reality", "sid": state["REALITY_SHORT_ID"],
             "sni": state["SNI_DONOR"], "spx": "/"}
    return (f"vless://{person['uuid']}@{state['PANEL_HOST']}:{state['VLESS_PORT']}?"
            + urlencode(query, quote_via=quote) + "#" + quote(state["SRV_LABEL"] + "-" + person["name"]))


def xkeen_config(link, state=None, person=None):
    """Only export the supported profile; never silently drop transport options."""
    url = urlsplit(link.strip())
    query = parse_qs(url.query, keep_blank_values=True, strict_parsing=True)
    allowed = {"encryption", "flow", "type", "fp", "pbk", "security", "sid", "sni", "spx", "headerType"}
    if set(query) - allowed or any(len(values) != 1 for values in query.values()):
        raise ValueError("unsupported or duplicate VLESS link options")
    q = {key: values[0] for key, values in query.items()}
    if (url.scheme != "vless" or url.password is not None or url.path not in ("", "/")
            or not url.hostname or not url.port or not url.username
            or q.get("type", "tcp") not in ("tcp", "raw")
            or q.get("headerType", "none") != "none"
            or q.get("encryption", "none") != "none" or q.get("security") != "reality"
            or q.get("flow") != "xtls-rprx-vision" or q.get("fp", "chrome") not in FINGERPRINTS):
        raise ValueError("XKeen export requires VLESS TCP + REALITY + Vision")
    uuid.UUID(url.username)
    donor_name(q.get("sni", ""))
    key = q.get("pbk", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", key):
        raise ValueError("invalid Reality public key")
    raw = base64.urlsafe_b64decode(key + "=")
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != key:
        raise ValueError("noncanonical Reality public key")
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}){1,8}", q.get("sid", "")):
        raise ValueError("invalid Reality short ID")
    if state is not None:
        expected = {"pbk": state["REALITY_PUBLIC_KEY"], "sid": state["REALITY_SHORT_ID"], "sni": state["SNI_DONOR"]}
        if (person is None or url.username != person["uuid"] or url.hostname != state["PANEL_HOST"]
                or url.port != int(state["VLESS_PORT"]) or any(q.get(k) != v for k, v in expected.items())
                or ("REALITY_FINGERPRINT" in state and q.get("fp", "chrome") != fingerprint(state))):
            raise ValueError("VLESS export differs from saved identities")
    return {"outbounds": [
        {"tag": "vless-reality", "protocol": "vless",
         "settings": {"vnext": [{"address": url.hostname, "port": url.port,
                                  "users": [{"id": url.username, "flow": "xtls-rprx-vision", "encryption": "none", "level": 0}]}]},
         "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
             "publicKey": key, "fingerprint": q.get("fp", "chrome"), "serverName": q["sni"],
             "shortId": q["sid"], "spiderX": q.get("spx", "/")}}},
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "block", "protocol": "blackhole"}
    ]}
