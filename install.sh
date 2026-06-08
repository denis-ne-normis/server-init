#!/usr/bin/env bash
#
# ════════════════════════════════════════════════════════════════════════════
#  One-click VPN installer — 3x-ui + двойной VLESS+Reality (XHTTP + TCP/Vision)
#  Чистый Ubuntu 24.04 / Debian 12 (amd64), root.
#
#  Делает с нуля, идемпотентно:
#    • apt update/upgrade + зависимости
#    • BBR + сетевой тюнинг, синхронизация времени
#    • панель 3x-ui (фикс. версия = Xray-core 26.6.1)
#    • хардинг: случайный путь/порт/логин/пароль, HTTPS (LE для IP или self-signed)
#    • Канал A: VLESS + XHTTP + Reality (TCP/443) — основной, стелс
#    • Канал B: VLESS + Reality + TCP + Vision (TCP/8443) — резерв, максимальная
#               совместимость (роутеры, старые клиенты); стабилен после рестартов
#    • фаервол nftables (deny-by-default, SSH-safe, блок исходящего SMTP)
#    • самопроверка: реальный прогон трафика через ОБА канала
#    • выдаёт в консоль доступ к панели + готовые ссылки/QR (первый клиент создан)
#
#  Почему не Hysteria2: встроенный в Xray hy2-inbound нестабилен (баг #5921 —
#  перестаёт отвечать после рестарта Xray). Два VLESS+Reality канала на разных
#  транспортах/портах дают надёжное резервирование без этого бага.
#
#  Запуск:  bash <(curl -fsSL https://raw.githubusercontent.com/denis-ne-normis/server-init/main/install.sh)
#  Повторный запуск безопасен (переиспользует ранее сгенерированные секреты).
# ════════════════════════════════════════════════════════════════════════════
set -Eeuo pipefail

# ───────────────────────────── CONFIG (можно править) ──────────────────────────
XUI_VERSION="${XUI_VERSION:-v3.2.8}"          # пин панели (=> Xray-core 26.6.1). "" = latest
SNI_DONOR="${SNI_DONOR:-www.microsoft.com}"   # донор Reality (TLS1.3+H2+X25519, глобальный CDN, без RU PoP)
VLESS_PORT="${VLESS_PORT:-443}"               # Канал A: VLESS+XHTTP+Reality (TCP)
VISION_PORT="${VISION_PORT:-8443}"            # Канал B: VLESS+Reality+TCP+Vision
PANEL_PORT="${PANEL_PORT:-}"                    # порт панели; пусто => случайный
FIRST_CLIENT="${FIRST_CLIENT:-client-1}"       # имя первого клиента (создаётся в обоих каналах)
ENABLE_BACKUP="${ENABLE_BACKUP:-1}"            # 1 = поднять резервный канал B (Vision)
BLOCK_SMTP="${BLOCK_SMTP:-1}"                   # 1 = блокировать исходящий SMTP (анти-абуз)
FORCE_REINSTALL="${FORCE_REINSTALL:-0}"        # 1 = переустановить панель, даже если уже стоит

WORKDIR="/root/vpn-setup"
SECRETS="$WORKDIR/secrets.env"
HANDOFF="/root/vpn-handoff.md"
LOG="/var/log/vpn-install.log"
XRAY_FLOOR_MAJOR=26
INSTALL_SH="https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh"
# ────────────────────────────────────────────────────────────────────────────────

C_G='\033[0;32m'; C_Y='\033[0;33m'; C_R='\033[0;31m'; C_B='\033[0;34m'; C_N='\033[0m'
mkdir -p "$WORKDIR"; chmod 700 "$WORKDIR"; : > "$LOG"
log()  { echo -e "$*" | tee -a "$LOG" >/dev/null; }
step() { echo -e "\n${C_B}━━▶ $*${C_N}" | tee -a "$LOG"; }
ok()   { echo -e "  ${C_G}✓${C_N} $*" | tee -a "$LOG"; }
warn() { echo -e "  ${C_Y}!${C_N} $*" | tee -a "$LOG"; }
die()  { echo -e "\n${C_R}✗ ОШИБКА: $*${C_N}\n  Лог: $LOG" | tee -a "$LOG"; exit 1; }
# shellcheck disable=SC2154  # rc присваивается внутри самой trap-строки
trap 'rc=$?; [ $rc -ne 0 ] && echo -e "\n${C_R}✗ Прервано на строке $LINENO (код $rc). Последние строки лога:${C_N}" && tail -n 15 "$LOG"; exit $rc' ERR

require() { command -v "$1" >/dev/null 2>&1 || die "нет команды: $1"; }

# ───────────────────────────── 0. Pre-flight ─────────────────────────────
step "Pre-flight"
[ "$(id -u)" -eq 0 ] || die "запускать от root"
. /etc/os-release 2>/dev/null || die "не вижу /etc/os-release"
case "${ID:-}" in ubuntu|debian) ok "ОС: $PRETTY_NAME" ;; *) warn "ОС $PRETTY_NAME не тестировалась (ожидается Ubuntu/Debian)";; esac
[ "$(uname -m)" = "x86_64" ] || die "нужен amd64 (x86_64), у вас $(uname -m)"
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a

# ───────────────────────────── 1. Зависимости ─────────────────────────────
step "Установка зависимостей"
apt-get update -y >>"$LOG" 2>&1
apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade >>"$LOG" 2>&1
apt-get install -y curl wget jq qrencode openssl ca-certificates nftables socat dnsutils uuid-runtime >>"$LOG" 2>&1
for c in curl jq qrencode openssl nft; do require "$c"; done
ok "зависимости установлены"

PUBIP="$(curl -fsS4 --max-time 10 https://api.ipify.org 2>/dev/null || true)"
[ -n "$PUBIP" ] || PUBIP="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' | head -1)"
[ -n "$PUBIP" ] || die "не определил публичный IP"
ok "публичный IP: $PUBIP"

# ───────────────────────────── 2. BBR + тюнинг + время ─────────────────────────────
step "Сетевой тюнинг (BBR) и время"
cat > /etc/sysctl.d/99-vpn.conf <<'SYSCTL'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.rmem_default=1048576
net.core.wmem_default=1048576
net.ipv4.tcp_rmem=4096 1048576 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.core.netdev_max_backlog=16384
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_notsent_lowat=131072
fs.file-max=1048576
SYSCTL
modprobe tcp_bbr 2>/dev/null || true
echo tcp_bbr > /etc/modules-load.d/bbr.conf
sysctl --system >>"$LOG" 2>&1
[ "$(sysctl -n net.ipv4.tcp_congestion_control)" = "bbr" ] && ok "BBR активен ($(sysctl -n net.core.default_qdisc) qdisc)" || warn "BBR не подтвердился"
timedatectl set-ntp true 2>/dev/null || true
ok "NTP включён"

# ───────────────────────────── 3. Установка 3x-ui ─────────────────────────────
step "Установка панели 3x-ui ($XUI_VERSION)"
if [ -x /usr/local/x-ui/x-ui ] && [ "$FORCE_REINSTALL" != "1" ]; then
  ok "3x-ui уже установлена — пропускаю установку (FORCE_REINSTALL=1 чтобы переставить)"
else
  if [ -n "$XUI_VERSION" ]; then
    bash <(curl -Ls "$INSTALL_SH") "$XUI_VERSION" < /dev/null >>"$LOG" 2>&1 || die "установщик 3x-ui завершился с ошибкой (см. $LOG)"
  else
    bash <(curl -Ls "$INSTALL_SH") < /dev/null >>"$LOG" 2>&1 || die "установщик 3x-ui завершился с ошибкой (см. $LOG)"
  fi
  ok "3x-ui установлена"
fi
XUIBIN=/usr/local/x-ui/x-ui
XRAYBIN="$(ls /usr/local/x-ui/bin/xray-linux-* 2>/dev/null | head -1)"; [ -x "$XRAYBIN" ] || die "не нашёл бинарь xray"
XRAY_VER="$("$XRAYBIN" -version 2>/dev/null | grep -oP 'Xray \K[0-9.]+' | head -1)"
ok "Xray-core: $XRAY_VER"
[ "${XRAY_VER%%.*}" -ge "$XRAY_FLOOR_MAJOR" ] 2>/dev/null || warn "Xray-core < $XRAY_FLOOR_MAJOR.x — возможны проблемы с XHTTP"

# ───────────────────────────── 4. Секреты ─────────────────────────────
step "Секреты"
gen_alnum() { local s; s="$(openssl rand -base64 "$1" | tr -dc 'A-Za-z0-9')"; printf '%s' "${s:0:$2}"; }
if [ -f "$SECRETS" ]; then
  ok "найден $SECRETS — переиспользую существующие секреты (идемпотентность)"
  # shellcheck disable=SC1090
  . "$SECRETS"
fi
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
VLESS_UUID="${VLESS_UUID:-$("$XRAYBIN" uuid)}"
VLESS_PATH="${VLESS_PATH:-/api/v1/$(openssl rand -hex 4)}"
ok "секреты готовы"

# ───────────────────────────── 5. Хардинг панели ─────────────────────────────
step "Хардинг панели (путь/порт/логин/пароль/HTTPS)"
"$XUIBIN" setting -username "$PANEL_USER" -password "$PANEL_PASS" -port "$PANEL_PORT" -webBasePath "$PANEL_PATH_RAW" >>"$LOG" 2>&1
CERT_LINE="$("$XUIBIN" setting -getCert 2>/dev/null || true)"
PANEL_CERT="$(echo "$CERT_LINE" | grep -i 'cert:' | awk '{print $2}')"
PANEL_KEY="$(echo  "$CERT_LINE" | grep -i 'key:'  | awk '{print $2}')"
if [ -z "$PANEL_CERT" ] || [ ! -f "$PANEL_CERT" ] || [ -z "$PANEL_KEY" ] || [ ! -f "$PANEL_KEY" ]; then
  warn "сертификата панели нет — генерирую self-signed"
  mkdir -p /root/cert/panel
  openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 \
    -keyout /root/cert/panel/private.key -out /root/cert/panel/cert.crt \
    -subj "/CN=$PUBIP" -addext "subjectAltName=IP:$PUBIP" >>"$LOG" 2>&1
  "$XUIBIN" setting -webCert /root/cert/panel/cert.crt -webCertKey /root/cert/panel/private.key >>"$LOG" 2>&1
  ok "self-signed сертификат панели подключён"
else
  ok "сертификат панели: $PANEL_CERT (оставляю как есть)"
fi
systemctl enable x-ui >>"$LOG" 2>&1 || true
systemctl restart x-ui
sleep 2
PANEL_PORT="$("$XUIBIN" setting -show 2>/dev/null | grep -i '^port' | awk '{print $2}')"
PANEL_PATH="$("$XUIBIN" setting -show 2>/dev/null | grep -i 'webBasePath' | awk '{print $2}')"
[ -n "$PANEL_PORT" ] && [ -n "$PANEL_PATH" ] || die "не прочитал настройки панели"
BASE="https://127.0.0.1:${PANEL_PORT}${PANEL_PATH%/}"
for i in $(seq 1 20); do
  [ "$(curl -sk -m4 -o /dev/null -w '%{http_code}' "$BASE/" 2>/dev/null)" = "200" ] && break
  sleep 1; [ "$i" = "20" ] && die "панель не поднялась за 20с"
done
ok "панель отвечает: порт $PANEL_PORT путь $PANEL_PATH"

# ───────────────────────────── 6. API-хелперы (cookie + CSRF) ─────────────────────────────
CK="$WORKDIR/.cookies"; : > "$CK"; chmod 600 "$CK"
api_login() {
  local c; c=$(curl -sk -c "$CK" "$BASE/csrf-token" | jq -r '.obj // empty')
  curl -sk -b "$CK" -c "$CK" -X POST "$BASE/login" -H "X-CSRF-Token: $c" -H 'Content-Type: application/json' \
    -d "$(jq -cn --arg u "$PANEL_USER" --arg p "$PANEL_PASS" '{username:$u,password:$p}')" | jq -e '.success==true' >/dev/null
}
api_post() { local c; c=$(curl -sk -b "$CK" "$BASE/csrf-token" | jq -r '.obj // empty')
  curl -sk -b "$CK" -X POST "$BASE$1" -H "X-CSRF-Token: $c" -H 'Content-Type: application/json' -d "$2"; }
api_get()  { curl -sk -b "$CK" "$BASE$1"; }
inbound_exists() { api_get "/panel/api/inbounds/list" | jq -e --arg r "$1" '.obj[]?|select(.remark==$r)' >/dev/null 2>&1; }

step "Авторизация в панели (API)"
api_login || die "не удалось залогиниться в панель API"
ok "API-сессия установлена"

# общий realitySettings для обоих каналов
REALITY_JSON="$(jq -cn --arg priv "$REALITY_PRIVATE_KEY" --arg pub "$REALITY_PUBLIC_KEY" --arg sid "$REALITY_SHORT_ID" --arg donor "$SNI_DONOR" \
  '{show:false,dest:($donor+":443"),xver:0,serverNames:[$donor],privateKey:$priv,shortIds:["",$sid],settings:{publicKey:$pub,fingerprint:"chrome",spiderX:"/"}}')"

# ───────────────────────────── 7. Канал A: VLESS+XHTTP+Reality ─────────────────────────────
step "Канал A — VLESS + XHTTP + Reality (TCP/$VLESS_PORT)"
echo Q | openssl s_client -connect "${SNI_DONOR}:443" -servername "$SNI_DONOR" -alpn h2 2>/dev/null \
  | grep -q 'Verify return code: 0' && ok "донор $SNI_DONOR валиден (TLS ok)" || warn "донор $SNI_DONOR не прошёл быстрый TLS-чек"
if inbound_exists "VLESS-XHTTP-Reality"; then
  ok "канал A уже есть — пропускаю"
else
  S=$(jq -cn --arg id "$VLESS_UUID" --arg em "$FIRST_CLIENT" '{clients:[{id:$id,flow:"",email:$em,enable:true,limitIp:0,totalGB:0,expiryTime:0,tgId:"",subId:"sub1"}],decryption:"none",fallbacks:[]}')
  ST=$(jq -cn --arg path "$VLESS_PATH" --argjson reality "$REALITY_JSON" \
    '{network:"xhttp",security:"reality",xhttpSettings:{host:"",path:$path,mode:"auto"},realitySettings:$reality}')
  SN=$(jq -cn '{enabled:true,destOverride:["http","tls","quic"],metadataOnly:false,routeOnly:false}')
  BODY=$(jq -cn --arg s "$S" --arg st "$ST" --arg sn "$SN" --argjson port "$VLESS_PORT" \
    '{enable:true,remark:"VLESS-XHTTP-Reality",listen:"",port:$port,protocol:"vless",expiryTime:0,settings:$s,streamSettings:$st,sniffing:$sn}')
  R=$(api_post "/panel/api/inbounds/add" "$BODY"); echo "$R" | jq -e '.success==true' >/dev/null || die "канал A не создан: $(echo "$R" | jq -r '.msg // .')"
  ok "канал A создан (клиент: $FIRST_CLIENT)"
fi

# ───────────────────────────── 8. Канал B: VLESS+Reality+TCP+Vision ─────────────────────────────
if [ "$ENABLE_BACKUP" = "1" ]; then
  step "Канал B — VLESS + Reality + TCP + Vision (TCP/$VISION_PORT) — надёжный резерв"
  if inbound_exists "VLESS-TCP-Reality-Vision"; then
    ok "канал B уже есть — пропускаю"
  else
    S=$(jq -cn --arg id "$VLESS_UUID" --arg em "$FIRST_CLIENT" '{clients:[{id:$id,flow:"xtls-rprx-vision",email:($em+"-tcp"),enable:true,limitIp:0,totalGB:0,expiryTime:0,tgId:"",subId:"sub1tcp"}],decryption:"none",fallbacks:[]}')
    ST=$(jq -cn --argjson reality "$REALITY_JSON" \
      '{network:"tcp",security:"reality",realitySettings:$reality,tcpSettings:{acceptProxyProtocol:false,header:{type:"none"}}}')
    SN=$(jq -cn '{enabled:true,destOverride:["http","tls","quic"],metadataOnly:false,routeOnly:false}')
    BODY=$(jq -cn --arg s "$S" --arg st "$ST" --arg sn "$SN" --argjson port "$VISION_PORT" \
      '{enable:true,remark:"VLESS-TCP-Reality-Vision",listen:"",port:$port,protocol:"vless",expiryTime:0,settings:$s,streamSettings:$st,sniffing:$sn}')
    R=$(api_post "/panel/api/inbounds/add" "$BODY"); echo "$R" | jq -e '.success==true' >/dev/null || die "канал B не создан: $(echo "$R" | jq -r '.msg // .')"
    ok "канал B создан (тот же клиент, flow=vision)"
  fi
else
  warn "резервный канал B отключён (ENABLE_BACKUP=0)"
fi

# ───────────────────────────── 9. Фаервол (nftables) ─────────────────────────────
step "Фаервол nftables (deny-by-default, SSH-safe)"
SMTP_RULE=""; [ "$BLOCK_SMTP" = "1" ] && SMTP_RULE='tcp dport { 25, 465, 587 } reject with icmp type admin-prohibited'
BACKUP_RULE=""; [ "$ENABLE_BACKUP" = "1" ] && BACKUP_RULE="tcp dport $VISION_PORT accept"
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
        tcp dport $PANEL_PORT accept
        tcp dport $VLESS_PORT accept
        $BACKUP_RULE
    }
    chain forward { type filter hook forward priority filter; policy drop; }
    chain output {
        type filter hook output priority filter; policy accept;
        $SMTP_RULE
    }
}
NFT
nft -c -f /etc/nftables.conf >>"$LOG" 2>&1 || die "ошибка синтаксиса nftables"
nohup bash -c 'sleep 90; nft flush ruleset' >/dev/null 2>&1 &
RB=$!
nft -f /etc/nftables.conf
systemctl enable nftables >>"$LOG" 2>&1 || true
kill "$RB" 2>/dev/null || true
ok "фаервол применён и включён в автозагрузку"

# ───────────────────────────── 10. Проверки ─────────────────────────────
step "Проверки работоспособности"
systemctl is-active --quiet x-ui && ok "сервис x-ui активен" || die "x-ui не активен"
ss -tlnp | grep -q ":$VLESS_PORT " && ok "TCP :$VLESS_PORT слушается (канал A)" || die "нет TCP :$VLESS_PORT"
[ "$ENABLE_BACKUP" = "1" ] && { ss -tlnp | grep -q ":$VISION_PORT " && ok "TCP :$VISION_PORT слушается (канал B)" || warn "нет TCP :$VISION_PORT"; }
if curl -s --max-time 12 --resolve "$SNI_DONOR:443:$PUBIP" "https://$SNI_DONOR/" -o /dev/null -w '%{http_code}' 2>/dev/null | grep -qE '^[23]'; then
  ok "Reality маскировка работает (зонд видит настоящий $SNI_DONOR)"
else warn "быстрый Reality-зонд не подтвердился (не критично)"; fi
# сквозной прогон через каналы
selftest() { # $1=label $2=port $3=flow $4=network $5=extra(xhttp path or empty)
  local cfg="$WORKDIR/.st.json"
  if [ "$4" = "xhttp" ]; then
    jq -n --arg u "$VLESS_UUID" --arg path "$VLESS_PATH" --arg pub "$REALITY_PUBLIC_KEY" --arg sid "$REALITY_SHORT_ID" --arg d "$SNI_DONOR" --argjson p "$2" \
      '{log:{loglevel:"error"},inbounds:[{tag:"s",listen:"127.0.0.1",port:10991,protocol:"socks",settings:{udp:true}}],outbounds:[{protocol:"vless",settings:{vnext:[{address:"'"$PUBIP"'",port:$p,users:[{id:$u,encryption:"none",flow:""}]}]},streamSettings:{network:"xhttp",security:"reality",xhttpSettings:{host:"",path:$path,mode:"auto"},realitySettings:{serverName:$d,publicKey:$pub,shortId:$sid,fingerprint:"chrome",spiderX:"/"}}}]}' > "$cfg"
  else
    jq -n --arg u "$VLESS_UUID" --arg pub "$REALITY_PUBLIC_KEY" --arg sid "$REALITY_SHORT_ID" --arg d "$SNI_DONOR" --argjson p "$2" \
      '{log:{loglevel:"error"},inbounds:[{tag:"s",listen:"127.0.0.1",port:10991,protocol:"socks",settings:{udp:true}}],outbounds:[{protocol:"vless",settings:{vnext:[{address:"'"$PUBIP"'",port:$p,users:[{id:$u,encryption:"none",flow:"xtls-rprx-vision"}]}]},streamSettings:{network:"tcp",security:"reality",realitySettings:{serverName:$d,publicKey:$pub,shortId:$sid,fingerprint:"chrome",spiderX:"/"}}}]}' > "$cfg"
  fi
  "$XRAYBIN" run -c "$cfg" >/dev/null 2>&1 & local p=$!; sleep 5
  local got; got="$(curl -s --max-time 15 --socks5-hostname 127.0.0.1:10991 https://api.ipify.org 2>/dev/null || true)"
  kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; rm -f "$cfg"
  [ "$got" = "$PUBIP" ] && ok "сквозной тест [$1] пройден (трафик вышел через сервер)" || warn "сквозной тест [$1] вернул: '${got:-пусто}'"
}
selftest "Канал A XHTTP/$VLESS_PORT" "$VLESS_PORT" "" "xhttp"
[ "$ENABLE_BACKUP" = "1" ] && selftest "Канал B Vision/$VISION_PORT" "$VISION_PORT" "vision" "tcp"

# ───────────────────────────── 11. Ссылки, QR, секреты, handoff ─────────────────────────────
step "Генерация ссылок, QR и памятки"
PANEL_URL="https://$PUBIP:$PANEL_PORT$PANEL_PATH"
PATH_ENC="$(jq -rn --arg v "$VLESS_PATH" '$v|@uri')"
LINK_A="vless://${VLESS_UUID}@${PUBIP}:${VLESS_PORT}?type=xhttp&path=${PATH_ENC}&mode=auto&security=reality&encryption=none&pbk=${REALITY_PUBLIC_KEY}&fp=chrome&sni=${SNI_DONOR}&sid=${REALITY_SHORT_ID}&spx=%2F#${FIRST_CLIENT}-XHTTP"
LINK_B=""
[ "$ENABLE_BACKUP" = "1" ] && LINK_B="vless://${VLESS_UUID}@${PUBIP}:${VISION_PORT}?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&pbk=${REALITY_PUBLIC_KEY}&fp=chrome&sni=${SNI_DONOR}&sid=${REALITY_SHORT_ID}&spx=%2F#${FIRST_CLIENT}-Vision"

umask 077
cat > "$SECRETS" <<EOF
# ===== Панель =====
PANEL_PORT=$PANEL_PORT
PANEL_PATH=$PANEL_PATH
PANEL_PATH_RAW=$PANEL_PATH_RAW
PANEL_USER=$PANEL_USER
PANEL_PASS=$PANEL_PASS
# ===== Reality (общий для обоих каналов) =====
SNI_DONOR=$SNI_DONOR
REALITY_PRIVATE_KEY=$REALITY_PRIVATE_KEY
REALITY_PUBLIC_KEY=$REALITY_PUBLIC_KEY
REALITY_SHORT_ID=$REALITY_SHORT_ID
VLESS_UUID=$VLESS_UUID
VLESS_PATH=$VLESS_PATH
VLESS_PORT=$VLESS_PORT
VISION_PORT=$VISION_PORT
LINK_A='$LINK_A'
LINK_B='$LINK_B'
EOF
qrencode -o "$WORKDIR/channelA_qr.png" -s 6 -m 2 "$LINK_A" 2>/dev/null || true
[ -n "$LINK_B" ] && qrencode -o "$WORKDIR/channelB_qr.png" -s 6 -m 2 "$LINK_B" 2>/dev/null || true

cat > "$HANDOFF" <<EOF
# VPN handoff ($PUBIP)

Панель:  $PANEL_URL
Логин:   $PANEL_USER
Пароль:  $PANEL_PASS
Xray-core: $XRAY_VER · 3x-ui: $XUI_VERSION · донор: $SNI_DONOR

## Канал A — VLESS+XHTTP+Reality (основной, TCP/$VLESS_PORT)
$LINK_A

## Канал B — VLESS+Reality+TCP+Vision (резерв, TCP/$VISION_PORT)
$LINK_B

Требования к клиенту: ядро Xray >= 26.x; fp=chrome обязателен (уже в ссылках).
Резервный канал B (Vision) совместим почти со всеми клиентами/роутерами.
Все секреты: $SECRETS  · QR: $WORKDIR/*.png
EOF
chmod 600 "$SECRETS" "$HANDOFF"
ok "сохранено: $HANDOFF и $SECRETS"

# ───────────────────────────── 12. Итог ─────────────────────────────
echo -e "\n${C_G}════════════════════════════════════════════════════════════════${C_N}"
echo -e "${C_G}  ГОТОВО. VPN развёрнут и проверен (2 канала VLESS+Reality).${C_N}"
echo -e "${C_G}════════════════════════════════════════════════════════════════${C_N}"
echo -e "${C_B}Панель:${C_N}  $PANEL_URL"
echo -e "${C_B}Логин:${C_N}   $PANEL_USER"
echo -e "${C_B}Пароль:${C_N}  $PANEL_PASS"
echo -e "\n${C_B}Канал A (основной, XHTTP/$VLESS_PORT):${C_N}\n$LINK_A"
[ -n "$LINK_B" ] && echo -e "\n${C_B}Канал B (резерв, Vision/$VISION_PORT):${C_N}\n$LINK_B"
echo -e "\n${C_B}QR основного канала:${C_N}"
qrencode -t ANSIUTF8 "$LINK_A"
echo -e "${C_Y}Памятка: $HANDOFF · Версии: Xray $XRAY_VER · 3x-ui $XUI_VERSION${C_N}\n"
