#!/usr/bin/env bash
# NEW dedicated Ubuntu VPN host only. Existing servers: python3 vpnctl.py repair.
# Run from a complete repository checkout, never a partial curl | bash download.
set -Eeuo pipefail
umask 077
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR=/root/vpn-setup
LOG=/var/log/vpn-install.log
fail() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }
RESUME_BEFORE_IDENTITIES=0
case "$*" in
  '') ;;
  --resume-before-identities) RESUME_BEFORE_IDENTITIES=1 ;;
  *) fail 'Usage: bash install.sh [--resume-before-identities]' ;;
esac
[[ $EUID -eq 0 ]] || fail 'Run as root.'
[[ -f "$HERE/vpnctl.py" && -f "$HERE/provision.py" && -f "$HERE/aggsub.py" ]] || fail 'Clone/download the COMPLETE repository and run bash install.sh there.'
exec 9>/run/server-init.lock
flock -n 9 || fail 'Another installer/maintenance operation is active.'
# Never mutate an existing or partially installed VPN, even when secrets.env is missing.
if [[ "$RESUME_BEFORE_IDENTITIES" == 1 ]]; then
  python3 "$HERE/provision.py" --check-resume-before-identities || fail 'Resume refused. Existing files were not changed.'
elif [[ -e "$WORKDIR/state.json" || -e "$WORKDIR/secrets.env" || -e /etc/amnezia/amneziawg/awg0.conf || -e /etc/x-ui/x-ui.db ]]; then
  fail "Existing installation detected. Nothing changed. Use: sudo python3 $HERE/vpnctl.py repair (see README for partial installations)."
fi
[[ ! -d /etc/pve ]] || fail 'Do not run on a Proxmox host.'
for service in docker podman kubelet nginx apache2; do
  if systemctl is-active --quiet "$service"; then fail "Existing service $service: use a separate, clean VPN VM."; fi
done
# shellcheck source=/dev/null
. /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" =~ ^(22\.04|24\.04)$ ]] || fail 'New installation currently supports Ubuntu 22.04/24.04 only; no Ubuntu PPA is injected into Debian.'
[[ $(uname -m) == x86_64 ]] || fail 'New installation currently supports amd64 only.'
[[ -n "${SSH_CONNECTION:-}" || "${APPLY_FIREWALL:-1}" == 0 ]] || fail 'Install over SSH, or explicitly set APPLY_FIREWALL=0 for an isolated test VM.'
if command -v nft >/dev/null && [[ -n "$(nft list ruleset)" ]]; then fail 'Existing nftables rules detected. Do not overwrite another firewall.'; fi
[[ -e "$LOG" ]] || touch "$LOG"
chmod 600 "$LOG"
trap 'printf "ERROR: installation stopped at line %s. Log: %s. Existing identity state is retained; do not delete it to retry.\n" "$LINENO" "$LOG" >&2' ERR
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
export SNI_DONOR="${SNI_DONOR:-www.nvidia.com}" VLESS_PORT="${VLESS_PORT:-7443}" SRV_LABEL="${SRV_LABEL:-S1}"
if [[ -t 0 ]]; then
  read -r -p "Reality donor [$SNI_DONOR]: " answer || answer=''
  SNI_DONOR="${answer:-$SNI_DONOR}"
  read -r -p "VLESS TCP port [$VLESS_PORT]: " answer || answer=''
  VLESS_PORT="${answer:-$VLESS_PORT}"
fi
XUI_VERSION="${XUI_VERSION:-v3.2.8}"
[[ "$XUI_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'Specify a release tag for XUI_VERSION; floating latest is not supported.'
if [[ "$RESUME_BEFORE_IDENTITIES" == 0 ]]; then
  step 'Install dependencies (no full apt upgrade or automatic reboot)'
  apt-get update >>"$LOG" 2>&1
  apt-get install -y python3 curl jq qrencode openssl ca-certificates nftables socat sqlite3 software-properties-common >>"$LOG" 2>&1
  step 'Install AmneziaWG for the running kernel'
  add-apt-repository -y ppa:amnezia/ppa >>"$LOG" 2>&1
  apt-get update >>"$LOG" 2>&1
  apt-get install -y "linux-headers-$(uname -r)" >>"$LOG" 2>&1
  apt-get install -y amneziawg amneziawg-tools >>"$LOG" 2>&1
  modprobe amneziawg
  command -v awg >/dev/null
  command -v awg-quick >/dev/null
  mkdir -p "$WORKDIR"
  chmod 700 "$WORKDIR"
  step "Install pinned 3x-ui $XUI_VERSION"
  curl -fLSs --connect-timeout 10 --max-time 120 --retry 2 "https://raw.githubusercontent.com/mhsanaei/3x-ui/$XUI_VERSION/install.sh" -o "$WORKDIR/xui-installer.sh"
  bash -n "$WORKDIR/xui-installer.sh"
  bash "$WORKDIR/xui-installer.sh" "$XUI_VERSION" </dev/null >>"$LOG" 2>&1
  [[ -x /usr/local/x-ui/x-ui ]] || fail '3x-ui binary missing.'
else
  step 'Continue bootstrap before identities (packages and 3x-ui are NOT reinstalled)'
  for tool in awg awg-quick curl jq qrencode openssl nft socat sqlite3; do
    command -v "$tool" >/dev/null || fail "Missing dependency $tool; bootstrap cannot continue."
  done
fi
export PUBIP="${PUBIP:-$(curl -fsS4 --connect-timeout 10 --max-time 20 https://api.ipify.org)}"
python3 -c 'import ipaddress,os; ipaddress.IPv4Address(os.environ["PUBIP"])'
step 'Persist all identities, then render configs (keys generated only on new installation)'
python3 "$HERE/provision.py"
# This is a freshly generated, safely shell-quoted file, not untrusted legacy input.
# shellcheck source=/dev/null
. "$WORKDIR/secrets.env"
step 'Enable forwarding and optional BBR'
cat > /etc/sysctl.d/99-vpn.conf <<'SYSCTL'
net.ipv4.ip_forward=1
net.ipv4.tcp_mtu_probing=1
SYSCTL
if modprobe tcp_bbr 2>/dev/null; then
  printf 'net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n' >> /etc/sysctl.d/99-vpn.conf
fi
sysctl -p /etc/sysctl.d/99-vpn.conf >>"$LOG" 2>&1
timedatectl set-ntp true || printf 'WARN: configure working time synchronization.\n'
step 'TLS certificate'
PANEL_CERT=/root/cert/panel/cert.crt
PANEL_KEY=/root/cert/panel/private.key
if [[ "${ENABLE_LE:-1}" == 1 ]]; then
  mkdir -p /root/.acme.sh /root/cert/le
  # Basic standalone issuance only needs acme.sh itself plus socat. systemd owns renewal.
  curl -fLSs --connect-timeout 10 --max-time 120 --retry 2 https://raw.githubusercontent.com/acmesh-official/acme.sh/3.1.6/acme.sh -o /root/.acme.sh/acme.sh
  chmod 700 /root/.acme.sh/acme.sh
  /root/.acme.sh/acme.sh --issue --server letsencrypt -d "$PANEL_HOST" --standalone --keylength ec-256 --certificate-profile shortlived --days 3 >>"$LOG" 2>&1 || fail 'IP certificate issuance failed. Check inbound port 80 and ACME log. Do not rerun the installer over existing state.'
  PANEL_CERT=/root/cert/le/fullchain.pem
  PANEL_KEY=/root/cert/le/private.key
  /root/.acme.sh/acme.sh --install-cert -d "$PANEL_HOST" --ecc --fullchain-file "$PANEL_CERT" --key-file "$PANEL_KEY" --reloadcmd /bin/true >>"$LOG" 2>&1
else
  mkdir -p /root/cert/panel
  openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 365 \
    -keyout "$PANEL_KEY" -out "$PANEL_CERT" -subj "/CN=$PANEL_HOST" -addext "subjectAltName=IP:$PANEL_HOST" >>"$LOG" 2>&1
  printf 'WARN: explicitly selected self-signed TLS; browsers will not trust it.\n'
fi
openssl x509 -in "$PANEL_CERT" -noout -checkend 0 >/dev/null
step 'Configure panel and loopback-only subscriptions'
XUIBIN=/usr/local/x-ui/x-ui
"$XUIBIN" setting -username "$PANEL_USER" -password "$PANEL_PASS" -port "$PANEL_PORT" -webBasePath "$PANEL_PATH_RAW" >>"$LOG" 2>&1
systemctl stop x-ui
PANEL_CERT="$PANEL_CERT" PANEL_KEY="$PANEL_KEY" SUB_PORT="$SUB_PORT" python3 - <<'PY'
import os, sqlite3
values = {"webCertFile":os.environ["PANEL_CERT"], "webKeyFile":os.environ["PANEL_KEY"],
          "subEnable":"true", "subListen":"127.0.0.1", "subPort":os.environ["SUB_PORT"],
          "subPath":"/sub/", "subCertFile":"", "subKeyFile":""}
with sqlite3.connect('/etc/x-ui/x-ui.db') as db:
    for key, value in values.items():
        db.execute('DELETE FROM settings WHERE key=?', (key,))
        db.execute('INSERT INTO settings (key,value) VALUES (?,?)', (key,value))
PY
systemctl enable --now x-ui >>"$LOG" 2>&1
BASE="https://127.0.0.1:${PANEL_PORT}${PANEL_PATH%/}"
ready=0
for _ in {1..30}; do
  if curl -fksS --max-time 2 "$BASE/" >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[[ "$ready" == 1 ]] || fail 'Panel did not become ready.'
CK="$WORKDIR/.cookies"
touch "$CK"; chmod 600 "$CK"
csrf=$(curl -fksS --max-time 10 -c "$CK" "$BASE/csrf-token" | jq -er '.obj')
jq -n --arg u "$PANEL_USER" --arg p "$PANEL_PASS" '{username:$u,password:$p}' |
  curl -fksS --max-time 15 -b "$CK" -c "$CK" -X POST "$BASE/login" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' --data-binary @- | jq -e '.success==true' >/dev/null
csrf=$(curl -fksS --max-time 10 -b "$CK" "$BASE/csrf-token" | jq -er '.obj')
curl -fksS --max-time 15 -b "$CK" -X POST "$BASE/panel/api/inbounds/add" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' --data-binary "@$WORKDIR/inbound.json" | jq -e '.success==true' >/dev/null
rm -f "$CK" "$WORKDIR/inbound.json"
step 'Install hardened distributor and systemd-managed AWG'
# vpnctl takes the same lock; all identity/config writes above are now complete.
flock -u 9
python3 "$HERE/vpnctl.py" repair
step 'Local health checks'
sleep 2
vpnctl doctor
step 'VLESS traffic probe (does NOT test an ISP/mobile route)'
python3 - <<'PY'
import json, socket
from pathlib import Path
from sys import path
path.insert(0,'/usr/local/lib/server-init')
from vpnctl import ROOT, load_env, atomic, run
state=load_env(ROOT/'secrets.env')
with socket.socket() as sock:
    sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
config={'log':{'loglevel':'error'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'udp':True}}],
'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':int(state['VLESS_PORT']),'users':[{'id':json.loads(state['CLIENTS_JSON'])[0]['uuid'],'encryption':'none','flow':'xtls-rprx-vision'}]}]},
'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'serverName':state['SNI_DONOR'],'publicKey':state['REALITY_PUBLIC_KEY'],'shortId':state['REALITY_SHORT_ID'],'fingerprint':'chrome','spiderX':'/'}}}]}
import subprocess,time
probe=ROOT/'.probe.json'; atomic(probe,json.dumps(config))
binary=next(Path('/usr/local/x-ui/bin').glob('xray-linux-*'))
process=subprocess.Popen([str(binary),'run','-c',str(probe)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
    time.sleep(2)
    if process.poll() is not None: raise SystemExit('VLESS probe failed to start')
    result=run(['curl','-fsS','--max-time','15','--socks5-hostname',f'127.0.0.1:{port}','https://api.ipify.org'])
    if result.stdout.strip()!=state['PANEL_HOST']: raise SystemExit('VLESS traffic probe failed')
finally:
    process.terminate()
    try: process.wait(timeout=5)
    except subprocess.TimeoutExpired: process.kill(); process.wait()
    probe.unlink(missing_ok=True)
print('OK VLESS local traffic probe')
PY
step 'Save handoff (private keys and logins are not printed into CI/public logs)'
python3 - <<'PY'
import json,sys
sys.path.insert(0,'/usr/local/lib/server-init')
from vpnctl import ROOT,load_env,atomic
s=load_env(ROOT/'secrets.env')
text=f"# VPN handoff\nPanel: https://{s['PANEL_HOST']}:{s['PANEL_PORT']}{s['PANEL_PATH']}\nLogin: {s['PANEL_USER']}\nPassword: {s['PANEL_PASS']}\n\n"
text+=''.join(f"{p['name']}: https://{s['PANEL_HOST']}:{s['AGG_PORT']}/p/{p['sub']}\n" for p in json.loads(s['CLIENTS_JSON']))
atomic('/root/vpn-handoff.md',text)
PY
if [[ "${APPLY_FIREWALL:-1}" == 1 ]]; then
  step 'Apply temporary firewall; confirmation from a NEW SSH connection is required'
  vpnctl firewall-apply --replace-firewall
  printf '\nVPN local tests passed. Firewall is NOT persistent until confirmation. Read /root/vpn-handoff.md for private access details.\n'
else
  printf '\nWARN: firewall explicitly skipped. This host is not hardened for public use.\n'
fi
