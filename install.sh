#!/usr/bin/env bash
#
# ════════════════════════════════════════════════════════════════════════════
#  One-click VPN installer (modern) — на чистом Ubuntu 24.04 / Debian 12, root.
#
#  Ставит за пару кликов, идемпотентно:
#    • apt upgrade + зависимости, BBR/тюнинг, синхронизация времени
#    • 3x-ui (пин Xray-core 26.x) + хардинг (рандом путь/порт/логин/пароль, HTTPS)
#    • VLESS + Reality + Vision (1 канал, роутеро-совместимый) на рабочем порту
#    • AmneziaWG 2.0 (современный, S3/S4+I1) + NAT — UDP-запас, не палится DPI
#    • N клиентов (по умолчанию 6) — у каждого VLESS + AWG, общий subId
#    • персональная страница раздачи на человека: /p/<subId> (QR + оба конфига)
#    • фаервол nftables (deny-by-default, SSH-safe, блок SMTP), self-test
#
#  Интерактивно спросит донора Reality и порт VLESS (можно задать через env).
#  Одинаковые клиенты на разных серверах: возьми CLIENTS_JSON из secrets.env
#  первого сервера и передай его при запуске на остальных.
#
#  Запуск:  bash <(curl -fsSL https://raw.githubusercontent.com/denis-ne-normis/server-init/main/install.sh)
# ════════════════════════════════════════════════════════════════════════════
set -Eeuo pipefail

# ───────────────────────────── CONFIG (env override) ──────────────────────────
XUI_VERSION="${XUI_VERSION:-v3.2.8}"          # пин панели (=> Xray-core 26.6.1). "" = latest
SNI_DONOR="${SNI_DONOR:-}"                     # донор Reality; пусто => спросит интерактивно
VLESS_PORT="${VLESS_PORT:-}"                   # порт VLESS; пусто => спросит интерактивно
SRV_LABEL="${SRV_LABEL:-}"                      # метка сервера (префикс в именах конфигов); пусто => спросит
PANEL_PORT="${PANEL_PORT:-}"                   # порт панели; пусто => случайный
CLIENTS="${CLIENTS:-denis vlad liza parents router svyt}"  # имена клиентов (без vless-main)
AWG_PORT="${AWG_PORT:-39743}"                  # UDP-порт AmneziaWG
AWG_SUBNET="${AWG_SUBNET:-10.9.7}"            # /24 подсеть AWG (сервер = .1)
SUB_PORT="${SUB_PORT:-2096}"                   # порт подписки 3x-ui
AGG_PORT="${AGG_PORT:-2087}"                   # порт раздачи (персональные страницы /p)
BLOCK_SMTP="${BLOCK_SMTP:-1}"                  # 1 = блокировать исходящий SMTP
CHECK_RUSSIA="${CHECK_RUSSIA:-1}"             # 1 = проверить доступность портов из РФ
ENABLE_LE="${ENABLE_LE:-1}"                     # 1 = валидный сертификат через sslip.io + Let's Encrypt (без предупреждений)
FORCE_REINSTALL="${FORCE_REINSTALL:-0}"
REPO_REF="${REPO_REF:-main}"                    # ветка/коммит репозитория для дозагрузки aggsub.py

# Отобранные рабочие варианты (проверено из РФ):
DONOR_CHOICES=(www.nvidia.com www.asus.com www.sony.com www.lg.com www.samsung.com)
PORT_CHOICES=(7443 8880 7444 7445)

# AmneziaWG 2.0 obfs (рабочий набор; одинаков на сервере и у клиентов):
AWG_JC=5; AWG_JMIN=10; AWG_JMAX=50; AWG_S1=128; AWG_S2=96; AWG_S3=41; AWG_S4=5
AWG_H1="1710377591-1722398516"; AWG_H2="1818569401-2116313076"
AWG_H3="2127718891-2143330769"; AWG_H4="2145494949-2146588297"
AWG_I1='<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>'

WORKDIR="/root/vpn-setup"; SECRETS="$WORKDIR/secrets.env"
AWGDIR="$WORKDIR/awg/clients"; AWGQR="$WORKDIR/awg/qr"; DIST="$WORKDIR/dist"
AWGCONF="/etc/amnezia/amneziawg/awg0.conf"
HANDOFF="/root/vpn-handoff.md"; LOG="/var/log/vpn-install.log"
INSTALL_SH="https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh"
SUB_PATH="/sub/"
# ────────────────────────────────────────────────────────────────────────────────

C_G='\033[0;32m'; C_Y='\033[0;33m'; C_R='\033[0;31m'; C_B='\033[0;34m'; C_N='\033[0m'
mkdir -p "$WORKDIR" "$AWGDIR" "$AWGQR" "$DIST"; chmod 700 "$WORKDIR"; : > "$LOG"
log()  { echo -e "$*" | tee -a "$LOG" >/dev/null; }
step() { echo -e "\n${C_B}━━▶ $*${C_N}" | tee -a "$LOG"; }
ok()   { echo -e "  ${C_G}✓${C_N} $*" | tee -a "$LOG"; }
warn() { echo -e "  ${C_Y}!${C_N} $*" | tee -a "$LOG"; }
die()  { echo -e "\n${C_R}✗ ОШИБКА: $*${C_N}\n  Лог: $LOG" | tee -a "$LOG"; exit 1; }
# shellcheck disable=SC2154
trap 'rc=$?; [ $rc -ne 0 ] && echo -e "\n${C_R}✗ Прервано на строке $LINENO (код $rc). Хвост лога:${C_N}" && tail -n 15 "$LOG"; exit $rc' ERR
require() { command -v "$1" >/dev/null 2>&1 || die "нет команды: $1"; }
ask_choice() { # $1=prompt  $2=varname  $3...=choices ; первый = дефолт
  local prompt="$1" var="$2"; shift 2; local choices=("$@") i sel
  if [ -t 0 ]; then
    echo -e "${C_B}$prompt${C_N}" >&2
    for i in "${!choices[@]}"; do echo "   $((i+1))) ${choices[$i]}" >&2; done
    read -r -p "   выбор [1-${#choices[@]}, Enter=1]: " sel </dev/tty || sel=""
    [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le "${#choices[@]}" ] && printf -v "$var" '%s' "${choices[$((sel-1))]}" || printf -v "$var" '%s' "${choices[0]}"
  else printf -v "$var" '%s' "${choices[0]}"; fi
}
ask_text() { # $1=prompt  $2=varname  $3=default
  local prompt="$1" var="$2" def="$3" v
  if [ -t 0 ]; then read -r -p "$(echo -e "${C_B}$prompt${C_N} [$def]: ")" v </dev/tty || v=""; printf -v "$var" '%s' "${v:-$def}"
  else printf -v "$var" '%s' "$def"; fi
}

# ───────────────────────────── 0. Pre-flight ─────────────────────────────
step "Pre-flight"
[ "$(id -u)" -eq 0 ] || die "запускать от root"
. /etc/os-release 2>/dev/null || die "не вижу /etc/os-release"
case "${ID:-}" in ubuntu|debian) ok "ОС: $PRETTY_NAME" ;; *) warn "ОС $PRETTY_NAME не тестировалась";; esac
[ "$(uname -m)" = "x86_64" ] || die "нужен amd64 (x86_64)"
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a

# ───────────────────────────── 1. Выбор донора и порта ─────────────────────────────
step "Параметры маскировки"
[ -n "$SNI_DONOR" ]  || ask_choice "Под какой сайт маскировать VLESS (Reality donor)?" SNI_DONOR "${DONOR_CHOICES[@]}"
[ -n "$VLESS_PORT" ] || ask_choice "Порт для VLESS (рабочие в РФ):" VLESS_PORT "${PORT_CHOICES[@]}"
[ -n "$SRV_LABEL" ] || ask_text "Метка сервера (префикс в именах конфигов, напр. DE/FI/NL)" SRV_LABEL "S1"
SRV_LABEL="$(printf '%s' "$SRV_LABEL" | tr -cd 'A-Za-z0-9._-')"; [ -n "$SRV_LABEL" ] || SRV_LABEL="S1"
ok "донор: $SNI_DONOR · порт VLESS: $VLESS_PORT · метка: $SRV_LABEL · порт AWG(UDP): $AWG_PORT"

# ───────────────────────────── 2. Зависимости ─────────────────────────────
step "Зависимости"
apt-get update -y >>"$LOG" 2>&1
apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade >>"$LOG" 2>&1
apt-get install -y curl wget jq qrencode openssl ca-certificates nftables socat dnsutils uuid-runtime software-properties-common sqlite3 >>"$LOG" 2>&1
for c in curl jq qrencode openssl nft; do require "$c"; done
ok "базовые зависимости установлены"
# AmneziaWG
step "Установка AmneziaWG (ядро + tools)"
if ! command -v awg >/dev/null 2>&1; then
  if [ "${ID:-}" = "ubuntu" ]; then add-apt-repository -y ppa:amnezia/ppa >>"$LOG" 2>&1
  else echo "deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu jammy main" >/etc/apt/sources.list.d/amnezia.list 2>/dev/null || true; fi
  apt-get update -y >>"$LOG" 2>&1
  apt-get install -y "linux-headers-$(uname -r)" >>"$LOG" 2>&1 || apt-get install -y linux-headers-generic >>"$LOG" 2>&1 || true
  apt-get install -y amneziawg amneziawg-tools >>"$LOG" 2>&1 || apt-get install -y amneziawg-dkms amneziawg-tools >>"$LOG" 2>&1 || die "не удалось поставить amneziawg (см. $LOG)"
fi
modprobe amneziawg 2>/dev/null || true
command -v awg >/dev/null 2>&1 || die "awg не установился"
ok "AmneziaWG: $(awg --version 2>/dev/null | head -1 || echo установлен)"
PUBIP="$(curl -fsS4 --max-time 10 https://api.ipify.org 2>/dev/null || true)"
[ -n "$PUBIP" ] || PUBIP="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' | head -1)"
[ -n "$PUBIP" ] || die "не определил публичный IP"
WANIF="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' | head -1)"; [ -n "$WANIF" ] || WANIF=eth0
ok "публичный IP: $PUBIP · внешний интерфейс: $WANIF"

# ───────────────────────────── 3. BBR + форвардинг + время ─────────────────────────────
step "Тюнинг (BBR), IP-forward, время"
cat > /etc/sysctl.d/99-vpn.conf <<'SYSCTL'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 1048576 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.core.netdev_max_backlog=16384
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.ip_forward=1
fs.file-max=1048576
SYSCTL
modprobe tcp_bbr 2>/dev/null || true; echo tcp_bbr > /etc/modules-load.d/bbr.conf
sysctl --system >>"$LOG" 2>&1
[ "$(sysctl -n net.ipv4.tcp_congestion_control)" = "bbr" ] && ok "BBR активен" || warn "BBR не подтвердился"
timedatectl set-ntp true 2>/dev/null || true; ok "NTP включён (критично для Reality)"

# ───────────────────────────── 4. 3x-ui ─────────────────────────────
step "Установка 3x-ui ($XUI_VERSION)"
if [ -x /usr/local/x-ui/x-ui ] && [ "$FORCE_REINSTALL" != "1" ]; then ok "3x-ui уже стоит — пропускаю"
else bash <(curl -Ls "$INSTALL_SH") ${XUI_VERSION:+"$XUI_VERSION"} < /dev/null >>"$LOG" 2>&1 || die "установщик 3x-ui упал (см. $LOG)"; ok "3x-ui установлена"; fi
XUIBIN=/usr/local/x-ui/x-ui
XRAYBIN="$(ls /usr/local/x-ui/bin/xray-linux-* 2>/dev/null | head -1)"; [ -x "$XRAYBIN" ] || die "не нашёл xray"
XRAY_VER="$("$XRAYBIN" -version 2>/dev/null | grep -oP 'Xray \K[0-9.]+' | head -1)"; ok "Xray-core: $XRAY_VER"

# ───────────────────────────── 5. Секреты + клиенты ─────────────────────────────
step "Секреты и клиенты"
gen_alnum() { local s; s="$(openssl rand -base64 "$1" | tr -dc 'A-Za-z0-9')"; printf '%s' "${s:0:$2}"; }
# shellcheck disable=SC1090
[ -f "$SECRETS" ] && { ok "переиспользую $SECRETS"; . "$SECRETS"; }
PANEL_USER="${PANEL_USER:-admin_$(gen_alnum 12 8)}"
PANEL_PASS="${PANEL_PASS:-$(gen_alnum 48 32)}"
PANEL_PATH_RAW="${PANEL_PATH_RAW:-$(gen_alnum 36 18)}"
[ -n "${PANEL_PORT:-}" ] || PANEL_PORT="$(shuf -i 20000-60000 -n1)"
if [ -z "${REALITY_PRIVATE_KEY:-}" ] || [ -z "${REALITY_PUBLIC_KEY:-}" ]; then
  KP="$("$XRAYBIN" x25519)"
  REALITY_PRIVATE_KEY="$(echo "$KP" | grep -iE 'private' | awk -F: '{print $2}' | tr -d ' ')"
  REALITY_PUBLIC_KEY="$(echo "$KP"  | grep -iE 'public|password' | awk -F: '{print $2}' | tr -d ' ' | head -1)"
fi
REALITY_SHORT_ID="${REALITY_SHORT_ID:-$(openssl rand -hex 8)}"
# PEOPLE: [{name,uuid,sub}] — общий subId на человека (одинаковый на всех серверах через CLIENTS_JSON)
PEOPLE="${CLIENTS_JSON:-[]}"
[ "$(echo "$PEOPLE" | jq 'length')" -gt 0 ] && CLIENTS="$(echo "$PEOPLE" | jq -r '[.[].name]|join(" ")')"
for name in $CLIENTS; do
  echo "$PEOPLE" | jq -e --arg n "$name" 'any(.[]?; .name==$n)' >/dev/null 2>&1 || \
    PEOPLE="$(echo "$PEOPLE" | jq -c --arg n "$name" --arg u "$("$XRAYBIN" uuid)" --arg s "$(gen_alnum 24 16)" '. + [{name:$n,uuid:$u,sub:$s}]')"
done
NP="$(echo "$PEOPLE" | jq 'length')"
CLIENTS_J="$(echo "$PEOPLE" | jq -c '[.[]|{id:.uuid,flow:"xtls-rprx-vision",email:.name,limitIp:0,totalGB:0,expiryTime:0,enable:true,tgId:"",subId:.sub,comment:"",reset:0}]')"
ok "клиентов: $NP ($(echo "$PEOPLE" | jq -r '[.[].name]|join(", ")'))"

# ───────────────────────────── 6. Хардинг панели ─────────────────────────────
step "Хардинг панели + HTTPS"
XUI_DB="/etc/x-ui/x-ui.db"
"$XUIBIN" setting -username "$PANEL_USER" -password "$PANEL_PASS" -port "$PANEL_PORT" -webBasePath "$PANEL_PATH_RAW" >>"$LOG" 2>&1
# Валидный сертификат без своего домена: sslip.io (резолвит IP) + Let's Encrypt (acme.sh, standalone порт 80).
LE_HOST="${PUBIP//./-}.sslip.io"; PANEL_HOST="$PUBIP"; PANEL_CERT=""; PANEL_KEY=""
if [ "$ENABLE_LE" = "1" ] && getent hosts "$LE_HOST" >/dev/null 2>&1; then
  [ -f /root/.acme.sh/acme.sh ] || curl -s https://get.acme.sh | sh -s email="admin@$LE_HOST" >>"$LOG" 2>&1
  ACME=/root/.acme.sh/acme.sh
  [ -f "$ACME" ] && "$ACME" --set-default-ca --server letsencrypt >>"$LOG" 2>&1 || true
  if [ -f "$ACME" ] && { [ -d "/root/.acme.sh/${LE_HOST}_ecc" ] || "$ACME" --issue -d "$LE_HOST" --standalone --keylength ec-256 >>"$LOG" 2>&1; }; then
    mkdir -p /root/cert/le
    "$ACME" --install-cert -d "$LE_HOST" --ecc --fullchain-file /root/cert/le/fullchain.pem --key-file /root/cert/le/private.key \
      --reloadcmd "systemctl restart x-ui; systemctl restart aggsub 2>/dev/null || true" >>"$LOG" 2>&1
    PANEL_CERT=/root/cert/le/fullchain.pem; PANEL_KEY=/root/cert/le/private.key; PANEL_HOST="$LE_HOST"
    ok "Let's Encrypt сертификат для $LE_HOST — открывается без предупреждений"
  else warn "LE не выпустился (порт 80 закрыт/занят?) — ставлю self-signed"; fi
fi
if [ -z "$PANEL_CERT" ]; then
  mkdir -p /root/cert/panel
  openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 \
    -keyout /root/cert/panel/private.key -out /root/cert/panel/cert.crt \
    -subj "/CN=$PUBIP" -addext "subjectAltName=IP:$PUBIP" >>"$LOG" 2>&1
  PANEL_CERT=/root/cert/panel/cert.crt; PANEL_KEY=/root/cert/panel/private.key
  ok "self-signed сертификат (браузер предупредит 1 раз — это норма)"
fi
# В 3x-ui 3.2.8 CLI -webCert НЕ работает → пишем webCertFile/webKeyFile напрямую в БД.
systemctl stop x-ui 2>/dev/null || true
sqlite3 "$XUI_DB" "DELETE FROM settings WHERE key IN ('webCertFile','webKeyFile'); INSERT INTO settings (key,value) VALUES ('webCertFile','$PANEL_CERT'),('webKeyFile','$PANEL_KEY');"
systemctl enable x-ui >>"$LOG" 2>&1 || true; systemctl restart x-ui; sleep 2
PANEL_PORT="$("$XUIBIN" setting -show 2>/dev/null | grep -i '^port' | awk '{print $2}')"
PANEL_PATH="$("$XUIBIN" setting -show 2>/dev/null | grep -i 'webBasePath' | awk '{print $2}')"
BASE="https://127.0.0.1:${PANEL_PORT}${PANEL_PATH%/}"
for i in $(seq 1 20); do [ "$(curl -sk -m4 -o /dev/null -w '%{http_code}' "$BASE/" 2>/dev/null)" = "200" ] && break; sleep 1; [ "$i" = "20" ] && die "панель не поднялась"; done
ok "панель отвечает: порт $PANEL_PORT"

# ───────────────────────────── 7. API + VLESS+Reality+Vision ─────────────────────────────
CK="$WORKDIR/.cookies"; : > "$CK"; chmod 600 "$CK"
api_login() { local c; c=$(curl -sk -c "$CK" "$BASE/csrf-token" | jq -r '.obj // empty')
  curl -sk -b "$CK" -c "$CK" -X POST "$BASE/login" -H "X-CSRF-Token: $c" -H 'Content-Type: application/json' \
    -d "$(jq -cn --arg u "$PANEL_USER" --arg p "$PANEL_PASS" '{username:$u,password:$p}')" | jq -e '.success==true' >/dev/null; }
api_post() { local c; c=$(curl -sk -b "$CK" "$BASE/csrf-token" | jq -r '.obj // empty')
  curl -sk -b "$CK" -X POST "$BASE$1" -H "X-CSRF-Token: $c" -H 'Content-Type: application/json' -d "$2"; }
api_get()  { curl -sk -b "$CK" "$BASE$1"; }
step "VLESS + Reality + Vision (TCP/$VLESS_PORT, донор $SNI_DONOR)"
api_login || die "не залогинился в панель API"
echo Q | openssl s_client -connect "${SNI_DONOR}:443" -servername "$SNI_DONOR" -alpn h2 2>/dev/null | grep -q 'Verify return code: 0' \
  && ok "донор $SNI_DONOR валиден (TLS ok)" || warn "донор $SNI_DONOR не прошёл быстрый TLS-чек"
# ВАЖНО: панель использует поле target (не dest) — иначе XHTTP/новые сборки не цепляются
REALITY_JSON="$(jq -cn --arg priv "$REALITY_PRIVATE_KEY" --arg pub "$REALITY_PUBLIC_KEY" --arg sid "$REALITY_SHORT_ID" --arg donor "$SNI_DONOR" \
  '{show:false,target:($donor+":443"),xver:0,serverNames:[$donor],privateKey:$priv,shortIds:[$sid],settings:{publicKey:$pub,fingerprint:"chrome",spiderX:"/"}}')"
SNIFF="$(jq -cn '{enabled:true,destOverride:["http","tls","quic"],metadataOnly:false,routeOnly:false}')"
if api_get "/panel/api/inbounds/list" | jq -e '.obj[]?|select(.remark=="VLESS-Reality-Vision")' >/dev/null 2>&1; then ok "VLESS-инбаунд уже есть — пропускаю"; else
  S=$(jq -cn --argjson cl "$CLIENTS_J" '{clients:$cl,decryption:"none",fallbacks:[]}')
  ST=$(jq -cn --argjson reality "$REALITY_JSON" '{network:"tcp",security:"reality",realitySettings:$reality,tcpSettings:{acceptProxyProtocol:false,header:{type:"none"}}}')
  BODY=$(jq -cn --arg s "$S" --arg st "$ST" --arg sn "$SNIFF" --argjson port "$VLESS_PORT" '{enable:true,remark:"VLESS-Reality-Vision",listen:"",port:$port,protocol:"vless",expiryTime:0,settings:$s,streamSettings:$st,sniffing:$sn}')
  R=$(api_post "/panel/api/inbounds/add" "$BODY"); echo "$R" | jq -e '.success==true' >/dev/null || die "VLESS не создан: $(echo "$R" | jq -r '.msg // .')"
  ok "VLESS создан со всеми клиентами"
fi

# ───────────────────────────── 8. AmneziaWG 2.0 ─────────────────────────────
step "AmneziaWG 2.0 ($AWG_SUBNET.0/24, UDP/$AWG_PORT)"
mkdir -p "$(dirname "$AWGCONF")"
# серверный приватник
AWG_SRV_PRIV="${AWG_SRV_PRIV:-$(awg genkey)}"
AWG_SRV_PUB="$(printf '%s' "$AWG_SRV_PRIV" | awg pubkey)"
OBFS="Jc = $AWG_JC\nJmin = $AWG_JMIN\nJmax = $AWG_JMAX\nS1 = $AWG_S1\nS2 = $AWG_S2\nS3 = $AWG_S3\nS4 = $AWG_S4\nH1 = $AWG_H1\nH2 = $AWG_H2\nH3 = $AWG_H3\nH4 = $AWG_H4\nI1 = $AWG_I1"
# server [Interface] (I1 only — старый awg-quick не любит пустые I2-5)
{ printf '[Interface]\nAddress = %s.1/24\nListenPort = %s\nPrivateKey = %s\n' "$AWG_SUBNET" "$AWG_PORT" "$AWG_SRV_PRIV"; printf '%b\n' "$OBFS"; } > "$AWGCONF"
# клиентские obfs (с пустыми I2-5 — приложение Amnezia их принимает)
OBFS_CLI="${OBFS}\nI2 = \nI3 = \nI4 = \nI5 = "
idx=2
echo "$PEOPLE" | jq -r '.[].name' | while read -r nm; do
  cpriv=$(awg genkey); cpub=$(printf '%s' "$cpriv" | awg pubkey); psk=$(awg genpsk); cip="$AWG_SUBNET.$idx"
  # добавить пир на сервер
  { printf '\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n' "$cpub" "$psk" "$cip"; } >> "$AWGCONF"
  # клиентский .conf (современный 2.0)
  { printf '[Interface]\nAddress = %s/32\nDNS = 1.1.1.1, 8.8.8.8\nPrivateKey = %s\n' "$cip" "$cpriv"; printf '%b\n' "$OBFS_CLI";
    printf '\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %s:%s\nPersistentKeepalive = 25\n' "$AWG_SRV_PUB" "$psk" "$PUBIP" "$AWG_PORT"; } > "$AWGDIR/${nm}.conf"
  qrencode -r "$AWGDIR/${nm}.conf" -s 10 -m 2 -o "$AWGQR/${nm}.png" 2>/dev/null || true
  idx=$((idx+1))
done
chmod 600 "$AWGCONF"
systemctl enable awg-quick@awg0 >>"$LOG" 2>&1 || true
awg-quick down awg0 2>/dev/null || true
awg-quick up awg0 >>"$LOG" 2>&1 || die "awg0 не поднялся (см. $LOG)"
ok "AmneziaWG поднят: $(awg show awg0 | grep -c peer:) пиров"

# ───────────────────────────── 9. Фаервол + NAT ─────────────────────────────
step "Фаервол nftables + NAT для AWG"
SMTP_RULE=""; [ "$BLOCK_SMTP" = "1" ] && SMTP_RULE='tcp dport { 25, 465, 587 } reject with icmp type admin-prohibited'
cat > /etc/nftables.conf <<NFT
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iif "lo" accept
        ct state established,related accept
        ct state invalid drop
        ip protocol icmp accept
        ip6 nexthdr ipv6-icmp accept
        tcp dport 22 accept
        tcp dport 80 accept
        tcp dport $PANEL_PORT accept
        tcp dport $VLESS_PORT accept
        tcp dport $SUB_PORT accept
        tcp dport $AGG_PORT accept
        udp dport $AWG_PORT accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        iifname "awg0" accept
        oifname "awg0" ct state established,related accept
    }
    chain output {
        type filter hook output priority filter; policy accept;
        $SMTP_RULE
    }
}
table inet nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr $AWG_SUBNET.0/24 oifname "$WANIF" masquerade
    }
}
NFT
nft -c -f /etc/nftables.conf >>"$LOG" 2>&1 || die "ошибка синтаксиса nftables"
nohup bash -c 'sleep 90; nft flush ruleset' >/dev/null 2>&1 & RB=$!
nft -f /etc/nftables.conf; systemctl enable nftables >>"$LOG" 2>&1 || true; kill "$RB" 2>/dev/null || true
ok "фаервол применён (22, $PANEL_PORT, $VLESS_PORT, $SUB_PORT, $AGG_PORT/tcp, $AWG_PORT/udp)"

# ───────────────────────────── 10. Раздача: aggsub.py (/sub /awg /p) ─────────────────────────────
step "Сервис раздачи (персональные страницы /p)"
printf '%s' "$PEOPLE" | jq -r '.[]|"\(.sub)\t\(.name)"' > "$WORKDIR/awg/submap.tsv"
printf '%s' "$SRV_LABEL" > "$WORKDIR/awg/label"
# VLESS-ссылки + QR на человека (с префиксом сервера в названии)
echo "$PEOPLE" | jq -r '.[]|"\(.name) \(.uuid)"' | while read -r nm uid; do
  link="vless://${uid}@${PUBIP}:${VLESS_PORT}?encryption=none&flow=xtls-rprx-vision&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&security=reality&sid=${REALITY_SHORT_ID}&sni=${SNI_DONOR}&spx=%2F#${SRV_LABEL}-${nm}"
  printf '%s' "$link" > "$DIST/${nm}.vless"; qrencode -s 10 -m 2 -o "$DIST/${nm}-vless.png" "$link" 2>/dev/null || true
done
curl -fsSL "https://raw.githubusercontent.com/denis-ne-normis/server-init/${REPO_REF}/aggsub.py" -o /root/aggsub.py 2>/dev/null || cp "$WORKDIR/aggsub.py" /root/aggsub.py 2>/dev/null || true
if [ ! -f /root/aggsub.py ]; then warn "aggsub.py не найден в репозитории — страницы /p будут недоступны (см. README)"; else
  cat > /etc/systemd/system/aggsub.service <<UNIT
[Unit]
Description=VPN personal-config distributor
After=network.target
[Service]
Environment=AGG_CERT=$PANEL_CERT
Environment=AGG_KEY=$PANEL_KEY
Environment=AGG_PORT=$AGG_PORT
ExecStart=/usr/bin/python3 /root/aggsub.py
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload; systemctl enable aggsub >>"$LOG" 2>&1 || true; systemctl restart aggsub; sleep 1
  systemctl is-active --quiet aggsub && ok "раздача активна на :$AGG_PORT" || warn "aggsub не поднялся"
fi

# ───────────────────────────── 11. Self-test ─────────────────────────────
step "Self-test"
systemctl is-active --quiet x-ui && ok "x-ui активен" || warn "x-ui не активен"
ss -tlnp | grep -q ":$VLESS_PORT " && ok "TCP :$VLESS_PORT слушается" || warn "нет TCP :$VLESS_PORT"
ss -ulnp | grep -q ":$AWG_PORT " && ok "UDP :$AWG_PORT слушается" || warn "нет UDP :$AWG_PORT"
# VLESS прогон трафика (первый клиент)
U1="$(echo "$PEOPLE" | jq -r '.[0].uuid')"
cat > "$WORKDIR/.probe.json" <<PJ
{"log":{"loglevel":"error"},"inbounds":[{"listen":"127.0.0.1","port":10991,"protocol":"socks","settings":{"udp":true}}],
"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"$PUBIP","port":$VLESS_PORT,"users":[{"id":"$U1","encryption":"none","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"$SNI_DONOR","publicKey":"$REALITY_PUBLIC_KEY","shortId":"$REALITY_SHORT_ID","fingerprint":"chrome","spiderX":"/"}}}]}
PJ
"$XRAYBIN" run -c "$WORKDIR/.probe.json" >/dev/null 2>&1 & PP=$!; sleep 5
[ "$(curl -s --max-time 12 --socks5-hostname 127.0.0.1:10991 https://api.ipify.org 2>/dev/null)" = "$PUBIP" ] && ok "VLESS прогон трафика OK" || warn "VLESS прогон не прошёл"
kill "$PP" 2>/dev/null || true; rm -f "$WORKDIR/.probe.json"
if [ "$CHECK_RUSSIA" = "1" ]; then
  { rid=$(curl -s -m10 -H "Accept: application/json" "https://check-host.net/check-tcp?host=${PUBIP}:$VLESS_PORT&node=ru1.node.check-host.net&node=msk.node.check-host.net" | jq -r '.request_id // empty')
    if [ -n "$rid" ]; then sleep 12; echo "  доступ из РФ (порт $VLESS_PORT):"
      curl -s -m10 -H "Accept: application/json" "https://check-host.net/check-result/$rid" | jq -r 'to_entries[]|"      \(.key|split(".")[0]): \(if .value==null then "wait" elif (.value[0].error) then "BLOCK" elif (.value[0].time) then "OK \((.value[0].time*1000)|floor)ms" else "?" end)"' || true
    fi; } || true
fi

# ───────────────────────────── 12. Секреты + handoff ─────────────────────────────
step "Сохранение секретов и памятки"
umask 077
cat > "$SECRETS" <<EOF
PANEL_PORT=$PANEL_PORT
PANEL_PATH=$PANEL_PATH
PANEL_PATH_RAW=$PANEL_PATH_RAW
PANEL_USER=$PANEL_USER
PANEL_PASS=$PANEL_PASS
SNI_DONOR=$SNI_DONOR
VLESS_PORT=$VLESS_PORT
SRV_LABEL=$SRV_LABEL
REALITY_PRIVATE_KEY=$REALITY_PRIVATE_KEY
REALITY_PUBLIC_KEY=$REALITY_PUBLIC_KEY
REALITY_SHORT_ID=$REALITY_SHORT_ID
AWG_PORT=$AWG_PORT
AWG_SUBNET=$AWG_SUBNET
AWG_SRV_PRIV=$AWG_SRV_PRIV
SUB_PORT=$SUB_PORT
AGG_PORT=$AGG_PORT
PANEL_HOST=$PANEL_HOST
CLIENTS_JSON='$PEOPLE'
EOF
chmod 600 "$SECRETS"
{
  echo "# VPN handoff ($PUBIP)"; echo
  echo "Панель:  https://$PANEL_HOST:$PANEL_PORT$PANEL_PATH"; echo "Логин:   $PANEL_USER"; echo "Пароль:  $PANEL_PASS"; echo
  echo "VLESS: Reality+Vision TCP/$VLESS_PORT, донор $SNI_DONOR (Xray $XRAY_VER)"
  echo "AmneziaWG 2.0: UDP/$AWG_PORT, подсеть $AWG_SUBNET.0/24"
  echo "Персональные страницы (QR + оба конфига):"
  echo "$PEOPLE" | jq -r --arg ip "$PANEL_HOST" --arg ap "$AGG_PORT" '.[]|"  \(.name): https://\($ip):\($ap)/p/\(.sub)"'
} > "$HANDOFF"; chmod 600 "$HANDOFF"
ok "сохранено: $SECRETS · $HANDOFF"

# ───────────────────────────── 13. Итог ─────────────────────────────
echo -e "\n${C_G}════════════════════════════════════════════════════════════════${C_N}"
echo -e "${C_G}  ГОТОВО. VLESS+Reality+Vision и AmneziaWG 2.0 развёрнуты ($NP клиентов).${C_N}"
echo -e "${C_G}════════════════════════════════════════════════════════════════${C_N}"
echo -e "\n${C_B}━━ Панель 3x-ui ━━${C_N}"
echo -e "  URL:    https://$PANEL_HOST:$PANEL_PORT$PANEL_PATH"
echo -e "  Логин:  $PANEL_USER"
echo -e "  Пароль: $PANEL_PASS"
echo -e "\n${C_B}━━ Ссылки для пересылки (перешли каждому ЕГО ссылку) ━━${C_N}"
echo -e "  ${C_Y}одна ссылка = страница с настройкой Amnezia (AWG) + Hiddify/роутер (VLESS), с QR${C_N}"
echo "$PEOPLE" | jq -r --arg ip "$PANEL_HOST" --arg ap "$AGG_PORT" '.[]|"   • \(.name):  https://\($ip):\($ap)/p/\(.sub)"'
echo -e "\n${C_Y}Все ссылки и доступы сохранены в памятке: $HANDOFF${C_N}"
echo -e "${C_Y}Секреты: $SECRETS · Те же клиенты на другом сервере: запусти с CLIENTS_JSON из $SECRETS${C_N}\n"
