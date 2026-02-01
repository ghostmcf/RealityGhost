#!/usr/bin/env bash
# RealityGhost v3.6.1 – Dual-Mode (XHTTP/TCP) with stealth HTTPS subscription
#
# FIXED/FEATURES:
# (1) Correct XHTTP schema: streamSettings.xhttpSettings.path
# (2) Build links correctly for each transport:
#     - XHTTP: type=xhttp&mode=packet-up&path=/...
#     - TCP : type=tcp
# (3) CRITICAL: Do NOT write pbk in server realitySettings (client-side only).
# (4) UUID change updates only main client (clients[0].id). Guest stays intact.
# (5) Switch transport from Manage menu (TCP <-> XHTTP), persist in /etc/ghost_transport
# (6) Safer tempfiles; no "local" outside functions.
# (7) SAFE ROTATE (default): rotate fingerprint + APPEND shortId (keep last N), NO key/path change unless opted-in.
#     - ROTATE_KEYS=1 realityghost manual-rotate  (hard rotate keys => old clients WILL drop)
#     - ROTATE_PATH=1 realityghost manual-rotate  (hard rotate path (xhttp) => old clients WILL drop)

set -euo pipefail
export TZ="Asia/Tehran"

### Paths ###
XRAY_DIR=/usr/local/xray
SCRIPT_DIR=$XRAY_DIR/scripts
SUB_DIR=$XRAY_DIR/sub
CONFIG_FILE=$XRAY_DIR/config.json
STATE_FILE=$SCRIPT_DIR/state.json
PUBKEY_FILE=$SCRIPT_DIR/pubkey
GHOST_CONF=/etc/ghost.conf
UUID_FILE=$SCRIPT_DIR/uuid
NGINX_SITE=/etc/nginx/sites-available/ghost_https.conf
TRANSPORT_FILE=/etc/ghost_transport   # persist mode here
XRAYVER="26.1.31"
### IDs ###
UUID="9f416f94-9c90-4e5a-9ab4-dde5e147f7c3"
EXTRA_UUID="0cd3e743-f8dd-4b10-82f8-f6c35e17f182"  # fixed guest subscription

### Defaults ###
DOH_SERVER="https://dns.google/dns-query"
SERVER_IP="91.107.158.133"
DEFAULT_TRANSPORT="tcp"  # xhttp|tcp
XHTTP_HOST_DEFAULT="www.gstatic.com"
# ajax.googleapis.com
# fonts.gstatic.com
# www.gstatic.com


log(){ echo "[$(date +%H:%M:%S)] $*"; }
err(){ echo "ERROR: $*" >&2; }
ask(){ read -r -p "$1" _v; echo "${_v}"; }
tmpfile(){ mktemp "${TMPDIR:-/tmp}/ghost.XXXXXX"; }

domain=""
[[ -f $GHOST_CONF ]] && domain=$(<"$GHOST_CONF") || true
[[ -f $UUID_FILE ]] && UUID=$(<"$UUID_FILE") || true

get_transport(){
  local tr=""
  if [[ -f "$TRANSPORT_FILE" ]]; then
    tr=$(<"$TRANSPORT_FILE" 2>/dev/null || true)
    if [[ "$tr" == "tcp" || "$tr" == "xhttp" ]]; then
      echo "$tr"; return 0
    fi
  fi
  echo "$DEFAULT_TRANSPORT"
}
set_transport(){
  local t="${1:-}"
  [[ "$t" != "tcp" && "$t" != "xhttp" ]] && { err "Invalid transport: $t"; return 1; }
  echo "$t" > "$TRANSPORT_FILE"
  log "Transport set to: Dual Mode , XHTTP and TCP Both enabled"
}

# ────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────

health_check() {
  log "→ Running health check (XRAY${1:+ + NGINX})"

  # --- XRAY config ---
  if ! xray_test_config; then
    err "HealthCheck: xray config invalid"
    return 1
  fi

  # --- XHTTP path ---
  local path
  path="$(get_xhttp_path)"

  if [[ -z "$path" ]]; then
    err "HealthCheck: xhttp path missing in config"
    return 1
  fi

  log "✔ XHTTP path detected → /$path"

  # --- nginx (ONLY if requested) ---
  if [[ "${1:-}" == "nginx" ]]; then
    if ! command -v nginx >/dev/null 2>&1; then
      err "HealthCheck: nginx not installed"
      return 1
    fi

    if ! nginx -t >/dev/null 2>&1; then
      err "HealthCheck: nginx config invalid"
      return 1
    fi

    if ! systemctl is-active --quiet nginx; then
      err "HealthCheck: nginx not running"
      return 1
    fi

    log "✔ NGINX is running"
  fi

  log "✔ Health check PASSED"
  return 0
}




xray_bin(){
  if [[ -x "$XRAY_DIR/xray" ]]; then echo "$XRAY_DIR/xray"; return 0; fi
  command -v xray 2>/dev/null || true
}

xray_test_config(){
  local bin; bin=$(xray_bin)
  [[ -z "${bin:-}" ]] && { err "Xray binary not found"; return 1; }
  "$bin" -test -config "$CONFIG_FILE" >/dev/null 2>&1
}

xray_gen_keys(){
  local bin out priv pub

  bin=$(xray_bin)
  [[ -z "$bin" ]] && { err "Xray binary not found"; return 1; }

  out=$("$bin" x25519 2>/dev/null)

  priv=$(awk -F': ' '/PrivateKey:/ {print $2}' <<<"$out")
  pub=$(awk -F': ' '/Password:/   {print $2}' <<<"$out")

  [[ -n "$priv" && -n "$pub" ]] || {
    err "x25519 output unparsable"
    echo "$out" >&2
    return 1
  }

  echo "$priv $pub"
}


detect_ip(){
  log "IP detection started …"
  local ip=""
  if command -v curl >/dev/null 2>&1; then
    ip=$(curl -sf https://api.ipify.org || curl -sf https://ifconfig.me || true)
  fi
  if [[ -n "${ip:-}" ]]; then SERVER_IP=$ip; echo "$ip"; return 0; fi
  read -r -p "Auto-detect IP failed. Enter server public IP: " ip
  [[ -n "${ip:-}" ]] && { SERVER_IP=$ip; echo "$ip"; return 0; }
  err "No IP provided"; return 1
}


ensure_config_file() {
  mkdir -p "$(dirname "$CONFIG_FILE")"

  if [[ ! -f "$CONFIG_FILE" ]]; then
    log "config.json not found, creating base config …"
    cat >"$CONFIG_FILE" <<'EOF'
{
  "log": { "loglevel": "warning" },
  "inbounds": [],
  "outbounds": [{ "protocol": "freedom", "settings": {} }]
}
EOF
  fi

  # 🔴 normalize structure safely
  local tmp
  tmp=$(mktemp /tmp/ghost.XXXXXX)

  # اگر فایل خراب بود، اول JSON رو بازنویسی می‌کنیم
  if ! jq empty "$CONFIG_FILE" 2>/dev/null; then
    log "⚠️ Warning: config.json corrupted, resetting base structure …"
    cat >"$CONFIG_FILE" <<'EOF'
{
  "log": { "loglevel": "warning" },
  "inbounds": [],
  "outbounds": [{ "protocol": "freedom", "settings": {} }]
}
EOF
  fi

  jq '
    .inbounds = (.inbounds // [])
    | if (.inbounds | length) == 0 then
        .inbounds = [{
          "listen": "127.0.0.1",
          "port": 8444,
          "protocol": "vless",
          "settings": { "clients": [], "decryption": "none" },
          "streamSettings": { "network": "tcp", "security": "reality", "realitySettings": {}, "tlsSettings": {} },
          "tag": "RealityVLESS"
        }]
      else .
      end
  ' "$CONFIG_FILE" >"$tmp" && mv "$tmp" "$CONFIG_FILE"

  log "✅ Config normalized"
}

save_xhttp_path() {
  local p="$1"
  local tmp

  [[ -z "$p" ]] && { err "save_xhttp_path: empty path"; return 1; }

  ensure_config_file

  tmp=$(tmpfile)
  jq --arg v "/$p" '
    .inbounds |= map(
      if .streamSettings.network == "xhttp" then
        .streamSettings.xhttpSettings = {
          "path": $v,
          "mode": "packet-up"
        }
      else .
      end
    )
  ' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"

  log "XHTTP path saved → /$p"
  return 0
}


get_xhttp_path() {
  jq -r '
    .inbounds[]
    | select(.streamSettings.network=="xhttp")
    | .streamSettings.xhttpSettings.path // empty
  ' "$CONFIG_FILE" 2>/dev/null | head -n1 | sed 's|^/||'
}





# ────────────────────────────────────────────────────────────────
# Kernel tuning
# ────────────────────────────────────────────────────────────────

tune_kernel(){
  log "Applying kernel net tuning (BBR/fastopen/buffers) …"
  cat >/etc/sysctl.d/99-ghost.conf <<'SYS'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.core.rmem_max=25000000
net.core.wmem_max=25000000
net.ipv4.tcp_rmem=4096 87380 25000000
net.ipv4.tcp_wmem=4096 65536 25000000
SYS
  sysctl --system || true
}

remove_kernel_tuning(){
  rm -f /etc/sysctl.d/99-ghost.conf || true
  sysctl --system || true
  log "Kernel tuning removed"
}

# ────────────────────────────────────────────────────────────────
# Xray config writer (Dual mode)
# ────────────────────────────────────────────────────────────────

rand_hex() {
  hexdump -n "$1" -e '"/%02X"' /dev/urandom | tr -d '/'
}


write_config() {
  log "Writing Xray config …"

  mkdir -p /var/log/xray "$XRAY_DIR" "$SCRIPT_DIR" "$SUB_DIR"
  ensure_config_file

  # ===== Reality keypair =====
  local keys PRIV PUB
  keys=$(xray_gen_keys) || { err "Reality keygen failed"; return 1; }
  PRIV=$(awk '{print $1}' <<<"$keys")
  PUB=$(awk '{print $2}' <<<"$keys")
  echo "$PUB" > "$PUBKEY_FILE"   # only for subscriptions

  # ===== Shared params =====
  local SID FP PATH_X
  SID="$(rand_hex 8)"
  FP="$(shuf -e chrome edge firefox safari -n1)"

  # ---- stable XHTTP path (CRITICAL) ----
  PATH_X="$(get_xhttp_path)"
  if [[ -z "$PATH_X" ]]; then
    PATH_X="$(rand_hex 8)"
  fi

  # ===== Stream settings: TCP Reality =====
  local STREAM_TCP
  STREAM_TCP=$(cat <<EOF
{
  "network": "tcp",
  "security": "reality",
  "realitySettings": {
    "xver": 0,
    "show": false,
    "dest": "google.com:443",
    "serverNames": [
      "google.com",
      "www.gstatic.com",
      "fonts.gstatic.com"
    ],
    "privateKey": "$PRIV",
    "shortIds": ["$SID"]
  },
  "tlsSettings": {
    "fingerprint": "$FP",
    "alpn": ["h2","http/1.1"],
    "enablePQTls": true
  }
}
EOF
)

  # ===== Stream settings: XHTTP Reality (nginx-backed) =====
  local STREAM_XHTTP
  STREAM_XHTTP=$(cat <<EOF
{
  "network": "xhttp",
  "security": "reality",
  "realitySettings": {
    "xver": 0,
    "show": false,
    "dest": "google.com:443",
    "serverNames": [
      "google.com",
      "www.gstatic.com",
      "fonts.gstatic.com"
    ],
    "privateKey": "$PRIV",
    "shortIds": ["$SID"]
  },
  "xhttpSettings": {
    "path": "/$PATH_X",
    "mode": "packet-up"
  },
  "tlsSettings": {
    "fingerprint": "$FP",
    "alpn": ["h2"],
    "enablePQTls": true
  }
}
EOF
)

  # ===== Write final config =====
  cat > "$CONFIG_FILE" <<EOF
{
  "log": {
    "access": "/dev/null",
    "error": "/var/log/xray/err.log",
    "loglevel": "warning"
  },

  "inbounds": [
    {
      "tag": "reality-tcp",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "$UUID", "flow": "" }
        ],
        "decryption": "none"
      },
      "streamSettings": $STREAM_TCP
    },
    {
      "tag": "reality-xhttp",
      "listen": "127.0.0.1",
      "port": 8444,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "$UUID", "flow": "" }
        ],
        "decryption": "none"
      },
      "streamSettings": $STREAM_XHTTP
    }
  ],

  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" }
  ]
}
EOF

  log "✅ Xray config written:"
  log "   - Reality TCP : 0.0.0.0:443"
  log "   - Reality XHTTP (nginx) : 127.0.0.1:8444"
  log "   - XHTTP path : /$PATH_X"
}


write_xray_service(){
  log "Writing systemd unit for Xray …"
  cat > /etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray Reality Service
After=network.target

[Service]
ExecStart=/usr/local/xray/xray run -config /usr/local/xray/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable xray
}

# ────────────────────────────────────────────────────────────────
# Ensure config has essentials for current transport
# ────────────────────────────────────────────────────────────────

ensure_keys_sid_and_path() {
  ensure_config_file

  local sid priv pub keys tmp
  local path

  #
  # ===== Reality keypair (shared for ALL inbounds) =====
  #
  priv=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey // empty' "$CONFIG_FILE")

  if [[ -z "$priv" || ! -s "$PUBKEY_FILE" ]]; then
    log "Reality keys missing → regenerating"

    keys=$(xray_gen_keys) || return 1
    priv=$(awk '{print $1}' <<<"$keys")
    pub=$(awk '{print $2}' <<<"$keys")
    echo "$pub" > "$PUBKEY_FILE"

    tmp=$(tmpfile)
    jq --arg pk "$priv" '
      .inbounds[].streamSettings.realitySettings.privateKey = $pk
      | del(.inbounds[].streamSettings.realitySettings.pbk)
    ' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
  fi

  #
  # ===== ShortID (shared) =====
  #
  sid=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0] // empty' "$CONFIG_FILE")

  if [[ -z "$sid" ]]; then
    sid="$(rand_hex 8)"
    tmp=$(tmpfile)
    jq --arg s "$sid" '
      .inbounds[].streamSettings.realitySettings.shortIds = [ $s ]
    ' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
  fi

  #
  # ===== Reality dest + serverNames (fake CDN) =====
  #
  tmp=$(tmpfile)
  jq '
    .inbounds[].streamSettings.realitySettings.dest = "google.com:443"
    | .inbounds[].streamSettings.realitySettings.serverNames = [
        "google.com",
        "www.gstatic.com",
        "fonts.gstatic.com"
      ]
  ' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"

  #
  # ===== Ensure XHTTP PATH exists (STATE, not config) =====
  #
  path="$(get_xhttp_path)"
  if [[ -z "$path" ]]; then
    path="$(rand_hex 8)"
    save_xhttp_path "$path"
    log "Generated new XHTTP path: /$path"
  fi

  return 0
}





# ────────────────────────────────────────────────────────────────
# Subscription builders (respect transport)
# ────────────────────────────────────────────────────────────────



build_vless_uri_tcp() {
  local u="$1" sni="$2" tag="$3"
  local IP SID FP PB uri

  IP="$SERVER_IP"

  SID=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0] // empty' "$CONFIG_FILE")
  FP=$(jq -r  '.inbounds[0].streamSettings.tlsSettings.fingerprint // empty' "$CONFIG_FILE")
  PB=$(<"$PUBKEY_FILE")

  [[ -z "$PB"  ]] && { err "Empty publicKey file"; return 1; }
  [[ -z "$SID" ]] && { err "Empty shortId"; return 1; }

  # fallback safety
  [[ -z "$FP" ]] && FP="chrome"

  uri="vless://$u@$IP:443?encryption=none&security=reality"
  uri+="&type=tcp"
  uri+="&sni=$sni"
  uri+="&host=$sni"
  uri+="&fp=$FP"
  uri+="&alpn=h2,http/1.1"
  uri+="&pbk=$PB"
  uri+="&sid=$SID"
  uri+="#${tag}-TCP"

  echo "$uri"
}


build_vless_uri_xhttp() {
  local u="$1" sni="$2" tag="$3"
  local IP SID FP PB path uri host

  IP="$SERVER_IP"

  # 🔐 HTTP Host MUST match nginx + cert
  host="$domain"

  SID=$(jq -r '.inbounds[].streamSettings.realitySettings.shortIds[0] // empty' "$CONFIG_FILE" | head -n1)
  FP=$(jq -r  '.inbounds[].streamSettings.tlsSettings.fingerprint // empty' "$CONFIG_FILE" | head -n1)
  PB=$(<"$PUBKEY_FILE")
  path=$(get_xhttp_path)

  [[ -z "$PB"   ]] && { err "Empty publicKey file"; return 1; }
  [[ -z "$SID"  ]] && { err "Empty shortId"; return 1; }
  [[ -z "$path" ]] && { err "Empty xhttp path"; return 1; }

  uri="vless://$u@$IP:443?encryption=none&security=reality"
  uri+="&type=xhttp"
  uri+="&mode=packet-up"
  uri+="&path=/$path"

  # 👇 critical for nginx + DPI
  uri+="&host=$sni"

  # 👇 Reality camouflage
  uri+="&sni=$sni"
  uri+="&fp=$FP"

  # safer than forcing h2 everywhere
  uri+="&alpn=h2,http/1.1"

  uri+="&pbk=$PB"
  uri+="&sid=$SID"
  uri+="#${tag}-XHTTP"

  echo "$uri"
}




generate_one_subscription() {
  local U="$1" PREFIX="$2"
  local RAW_FILE URL
  ensure_keys_sid_and_path || return 1

  RAW_FILE="$SUB_DIR/$U.raw"
  : > "$RAW_FILE"

  local -a SNIS=(google.com www.gstatic.com fonts.gstatic.com)

  for i in {0..2}; do
    local sni tag
    sni="${SNIS[i]}"
    if (( i == 0 )); then
      tag="${PREFIX}"
    else
      tag="${PREFIX}-Backup${i}"
    fi

    echo "# $tag | TCP | SNI=$sni" >>"$RAW_FILE"
    build_vless_uri_tcp   "$U" "$sni" "$tag" >>"$RAW_FILE"
    echo >>"$RAW_FILE"

    echo "# $tag | XHTTP | SNI=$sni" >>"$RAW_FILE"
    build_vless_uri_xhttp "$U" "$sni" "$tag" >>"$RAW_FILE"
    echo >>"$RAW_FILE"
  done

  base64 --wrap=0 "$RAW_FILE" > "$SUB_DIR/$U"
  URL="https://$domain/$U"
  log "Subscription URL: $URL"
}



generate_subscription(){
  log "→ Regenerating subscriptions (transport=$(get_transport)) …"
  mkdir -p "$SUB_DIR"

  generate_one_subscription "$UUID" "RealityGhost"
  # generate_one_subscription "$EXTRA_UUID" "Guest"

  if command -v qrencode >/dev/null 2>&1; then
    echo
    log "QR (Main): https://$domain/$UUID"
    qrencode -t ANSIUTF8 "https://$domain/$UUID" || true
    echo
    # log "QR (Guest): https://$domain/$EXTRA_UUID"
    # qrencode -t ANSIUTF8 "https://$domain/$EXTRA_UUID" || true
  fi

  log "✔ Subscriptions regenerated"
  echo "iOS:      Use Shadowrocket https://apps.apple.com/us/app/shadowrocket/id932747118"
  # qrencode -t ANSIUTF8 "https://apps.apple.com/us/app/shadowrocket/id932747118" || true
  echo "iOS:      Use Streisand https://apps.apple.com/us/app/streisand/id6450534064"
  # qrencode -t ANSIUTF8 "https://apps.apple.com/us/app/streisand/id6450534064" || true
  echo "Android:  Use v2rayNG https://github.com/2dust/v2rayNG/releases/download/1.10.32/v2rayNG_1.10.32_universal.apk"
  # qrencode -t ANSIUTF8 "https://github.com/2dust/v2rayNG/releases/download/1.10.32/v2rayNG_1.10.32_universal.apk" || true
  echo "Windows:  Use v2rayN https://github.com/2dust/v2rayN/releases/download/7.17.1/v2rayN-windows-64.zip"
}

# ────────────────────────────────────────────────────────────────
# NGINX (unchanged idea)
# ────────────────────────────────────────────────────────────────

write_nginx() {
  log "Installing & configuring NGINX …"

  # --- پاک کردن کانفیگ قدیمی ---
  rm -f /etc/nginx/sites-enabled/ghost_https.conf
  rm -f /etc/nginx/sites-available/ghost_https.conf
  mkdir -p "$SUB_DIR" /var/www/ghost_web

  # --- صفحه پیش‌فرض ---
  cat > /var/www/ghost_web/index.html <<'HTML'
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Welcome</title></head>
<body><h1>It works.</h1></body>
</html>
HTML

  # --- نصب nginx و certbot plugin ---
  if ! command -v nginx >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y nginx python3-certbot-nginx || {
      err "Failed to install NGINX or Certbot plugin"
      return 1
    }
  else
    apt-get install -y python3-certbot-nginx || true
  fi

  # --- توقف nginx قبل از تغییر کانفیگ ---
  systemctl stop nginx || true

  # --- TLS cert ---
  if ! certbot certonly --nginx -d "$domain" --non-interactive --agree-tos -m "$help_email"; then
    err "Certbot failed. Trying webroot fallback…"
    if [[ -f "/etc/letsencrypt/live/$domain/fullchain.pem" ]]; then
      log "Using existing certificate for $domain."
    else
      certbot certonly --webroot -w /var/www/ghost_web -d "$domain" --non-interactive --agree-tos -m "$help_email" || {
        err "Certbot webroot also failed. TLS not configured."
      }
    fi
  fi

  # --- ساخت کانفیگ جدید nginx ---
  cat > /etc/nginx/sites-available/ghost_https.conf <<EOF
server {
    listen 443 ssl http2;
    server_name $domain;

    ssl_certificate     /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    # ---- subscriptions ----
    location = /$UUID {
        alias $SUB_DIR/$UUID;
        default_type text/plain;
        add_header Content-Type text/plain;
        add_header Cache-Control "no-store";
    }

    

    # ---- Reality XHTTP ----
    location / {
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;

        proxy_pass http://127.0.0.1:8444;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
EOF

  ln -sf /etc/nginx/sites-available/ghost_https.conf /etc/nginx/sites-enabled/ghost_https.conf

  # --- minimal nginx.conf ---
  cat > /etc/nginx/nginx.conf <<'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 4096;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    sendfile      on;
    keepalive_timeout 65;

    access_log off;
    error_log /var/log/nginx/error.log warn;

    include /etc/nginx/sites-enabled/*.conf;
}
EOF

  # --- بررسی پورت 443 ---
  if ss -tuln | grep -q ':443'; then
    log "Port 443 busy. Attempting to stop conflicting service…"
    fuser -k 443/tcp || true
  fi

  # --- تست و ریستارت nginx ---
  if nginx -t; then
    systemctl restart nginx || {
      err "NGINX failed to start. Check journalctl -xeu nginx.service"
      return 1
    }
    log "✅ NGINX ready on :443 (TLS + Subscription + XHTTP)"
  else
    err "NGINX config test failed"
    return 1
  fi
}



update_nginx_uuid() {
  if [[ -z "$NGINX_SITE" || ! -f "$NGINX_SITE" ]]; then
    err "NGINX_SITE not set or file does not exist"
    return 1
  fi

  sed -i "s|location = /[a-f0-9-]\+ {|location = /$UUID {|" "$NGINX_SITE"

  nginx -t && systemctl reload nginx
  log "✅ Updated subscription UUIDs (XHTTP untouched)"
}



# ────────────────────────────────────────────────────────────────
# SAFE Rotate (manual)
# ────────────────────────────────────────────────────────────────

manual_rotate_all() {
  clear
  log "→ Manual rotation (dual-inbound SAFE) …"
  log "→ SAFE MODE: keys/path are NOT rotated unless ROTATE_KEYS=1 / ROTATE_PATH=1"

  ensure_config_file
  local tmp bak old_fp new_fp newsid keepN
  keepN=6

  # ── Backup for rollback
  bak=$(tmpfile)
  cp -f "$CONFIG_FILE" "$bak"

  # ── 1) Fingerprint rotate (ALL inbounds)
  old_fp=$(jq -r '
    .inbounds[].streamSettings.tlsSettings.fingerprint // empty
  ' "$CONFIG_FILE" | head -n1)

  while :; do
    new_fp=$(shuf -e chrome edge firefox safari -n1)
    [[ -n "$new_fp" && "$new_fp" != "$old_fp" ]] && break
  done

  tmp=$(tmpfile)
  jq --arg fp "$new_fp" '
    .inbounds |= map(
      .streamSettings.tlsSettings.fingerprint = $fp
    )
  ' "$CONFIG_FILE" >"$tmp" && mv "$tmp" "$CONFIG_FILE"

  log "Rotated Fingerprint → $new_fp"

  # ── 2) ShortId append (shared, keep last N)
  newsid=$(rand_hex 8)
  tmp=$(tmpfile)
  jq --arg s "$newsid" --argjson n "$keepN" '
    .inbounds |= map(
      .streamSettings.realitySettings.shortIds =
        (([ $s ] + (.streamSettings.realitySettings.shortIds // []))[:$n])
    )
  ' "$CONFIG_FILE" >"$tmp" && mv "$tmp" "$CONFIG_FILE"

  log "Appended ShortID → $newsid (keep $keepN)"

  # ── 3) HARD rotate: Reality keys (ALL inbounds)
  if [[ "${ROTATE_KEYS:-0}" == "1" ]]; then
    log "HARD ROTATE: rotating Reality keys (clients WILL drop)"
    local keys priv pub
    keys=$(xray_gen_keys) || {
      err "Keygen failed"; cp -f "$bak" "$CONFIG_FILE"; return 1;
    }
    priv=$(cut -d' ' -f1 <<<"$keys")
    pub=$(cut -d' ' -f2 <<<"$keys")
    echo "$pub" > "$PUBKEY_FILE"

    tmp=$(tmpfile)
    jq --arg pk "$priv" '
      .inbounds |= map(
        .streamSettings.realitySettings.privateKey = $pk
        | del(.streamSettings.realitySettings.pbk)
      )
    ' "$CONFIG_FILE" >"$tmp" && mv "$tmp" "$CONFIG_FILE"

    log "Rotated Reality keys"
  fi

  # ── 4) HARD rotate: xHTTP path (ONLY xhttp inbounds)
  if [[ "${ROTATE_PATH:-0}" == "1" ]]; then
    local p
    p=$(rand_hex 8)
    tmp=$(tmpfile)
    jq --arg v "/$p" '
      .inbounds |= map(
        if .streamSettings.network == "xhttp" then
          .streamSettings.xhttpSettings.path = $v
          | .streamSettings.xhttpSettings.mode = "packet-up"
        else .
        end
      )
    ' "$CONFIG_FILE" >"$tmp" && mv "$tmp" "$CONFIG_FILE"

    log "Rotated xHTTP path → /$p"
  fi

  # ── 5) Ensure consistency
  ensure_keys_sid_and_path || {
    err "ensure failed"; cp -f "$bak" "$CONFIG_FILE"; return 1;
  }

  # ── 6) Validate & restart
  if ! xray_test_config; then
    err "Config invalid → rollback"
    cp -f "$bak" "$CONFIG_FILE"
    return 1
  fi

  systemctl restart xray
  systemctl restart nginx

  generate_subscription

  log "✔ Rotation complete (dual-inbound SAFE)."
}


# ────────────────────────────────────────────────────────────────
# Transport switch (core feature)
# ────────────────────────────────────────────────────────────────

switch_transport() {
  local cur next

  cur=$(get_transport)
  if [[ "$cur" == "xhttp" ]]; then
    next="tcp"
  else
    next="xhttp"
  fi

  log "Switching transport (LINK MODE): $cur → $next"

  #  preference 
  set_transport "$next"

  #path / sid 
  ensure_keys_sid_and_path

  #  regenerate subscription
  generate_subscription

  log "✅ Transport switched to $next (no server restart, no config change)"
}

# ────────────────────────────────────────────────────────────────
# Install / Manage / Uninstall
# ────────────────────────────────────────────────────────────────
show_banner() {
cat <<'EOF'
  *****  *****  *****  *****  *****  *****  *****  *****  *****  ***** 
 *     **     **     **     **     **     **     **     **     **     *
*  *****  *****  *****  *****  *****  *****  *****  *****  *****  ***** 
*  *              *        *         *      *         *         *    *
*  *  *****  *****  *****  *****  *****  *****  *****  *****  *****  *
*  *  *         *      *      *      *         *         *      *     *
*  *  *****  *****  *****  *****  *****  *****  *****  *****  *****  *
 *     **     **     **     **     **     **     **     **     **     *
  *****  *****  *****  *****  *****  *****  *****  *****  *****  ***** 

                 R E A L I T Y G H O S T
EOF
}

install(){
  clear
  show_banner
  echo
  log "=== RealityGhost v3.7.0 Install (Dual-Mode) ==="
  # while true; do
  #     domain=$(ask "Subscription Domain: ")
  #     [[ -n "$domain" ]] && break
  #     echo "⚠ Domain cannot be empty. Please enter a valid domain."
  # done

  # # Email
  # while true; do
  #     help_email=$(ask "Email for Let's Encrypt: ")
  #     [[ -n "$help_email" ]] && break
  #     echo "⚠ Email cannot be empty. Please enter a valid email."
  # done
  domain="api4.mindescape.co"
  help_email="help@mindescape.co"
  echo "$domain" > "$GHOST_CONF"
  echo "$domain"

  local t
  set_transport "$DEFAULT_TRANSPORT"
  log "Link preference set to: $DEFAULT_TRANSPORT (server runs TCP + XHTTP)"

  read -r -p "Generate new UUID? (Y/n): " yn
  yn=${yn:-Y}
  if [[ "$yn" =~ ^[Yy]$ ]]; then
      UUID="$(uuidgen)"
      log "Generated new UUID → $UUID"
  fi

  echo "UUID=$UUID"

  # apt-get update -y
  # apt-get install -y curl unzip jq openssl ufw qrencode vnstat uuid-runtime nginx libnginx-mod-stream certbot xxd python3

  mkdir -p "$SCRIPT_DIR" "$SUB_DIR"
  echo "$UUID" > "$UUID_FILE"

  detect_ip || true

  local SSH_PORT
  SSH_PORT=$(ss -tnlp 2>/dev/null | awk '/sshd/ && /LISTEN/ {print $4}' | sed 's/.*://;q')
  [[ -z "${SSH_PORT:-}" ]] && SSH_PORT=22
  ufw allow "${SSH_PORT}/tcp" || true
  ufw allow 80/tcp && ufw allow 443/tcp && ufw --force enable || true
#   ver=$(curl -s https://api.github.com/repos/XTLS/xray-core/releases/latest | jq -r .tag_name | sed 's/^v//')  
  curl -L -o /tmp/x.zip "https://github.com/XTLS/xray-core/releases/download/v${XRAYVER}/Xray-linux-64.zip"
  mkdir -p "$XRAY_DIR" && unzip -oq /tmp/x.zip -d "$XRAY_DIR" && chmod +x "$XRAY_DIR/xray"
  log "Ensuring config file …"
  ensure_config_file
  log "Writing config file …"
  write_config
  systemctl restart xray
  sleep 1
  log "Writing Xray Service …"
  write_xray_service

  log "Writing Nginx …"
  write_nginx
  log "Updating Nginx UUID …"
  update_nginx_uuid

  tune_kernel || true
  ensure_keys_sid_and_path
  systemctl restart xray
  systemctl restart nginx

  health_check || { err "Refusing to generate broken subscription"; return 1; }
  generate_subscription

  echo "0 5 */3 * * root /usr/local/bin/realityghost manual-rotate" > /etc/cron.d/ghost
  ln -sf "$(realpath "$0")" /usr/local/bin/realityghost
  chmod +x /usr/local/bin/realityghost || true
  chmod +x "$(realpath "$0")" || true

  log "=== Install complete. Run 'realityghost manage' ==="
}

manage(){
  [[ $EUID -eq 0 ]] || { err "Run as root"; exit 1; }
  clear
  while true; do
    local cur
    show_banner
    cur=$(get_transport)
    cat <<EOF

RealityGhost Manager (transport=$cur)
Xray version: $XRAYVER
------------------------------
1) Show current URI (base64-decoded)
2) Show subscription links (with QR)
3) Regenerate subscription
4) Manual rotate (SAFE)
5) Update server IP (subs only)
6) Change DoH server
7) Change UUID (MAIN only)
8) Switch Transport (TCP <-> XHTTP)
9) Restart Xray
10) Reload Xray config
11) Show bandwidth stats
12) Show Xray logs
13) Uninstall
0) Exit
EOF

    read -r -p "Choice: " ch
    clear
    case ${ch:-} in
      1) [[ -f "$SUB_DIR/$UUID" ]] && base64 -d <"$SUB_DIR/$UUID" || err "No subscription file" ;;
      2)
         echo "https://$domain/$UUID"
        #  echo "https://$domain/$EXTRA_UUID"
         if command -v qrencode >/dev/null 2>&1; then
           echo; log "QR (Main):";  qrencode -t ANSIUTF8 "https://$domain/$UUID"  || true
          #  echo; log "QR (Guest):"; qrencode -t ANSIUTF8 "https://$domain/$EXTRA_UUID" || true
         fi
      ;;
      3) generate_subscription ;;
      4) manual_rotate_all ;;
      5)
        local newip
        newip=$(ask "New public IP (blank=auto-detect): ")
        [[ -z "$newip" ]] && newip=$(curl -sf https://api.ipify.org || curl -sf https://ifconfig.me || true)
        if [[ -n "$newip" ]]; then
          SERVER_IP="$newip"; log "SERVER_IP set to $SERVER_IP"
          generate_subscription
          systemctl restart nginx
        else
          err "Could not detect/set IP"
        fi
      ;;
      6)
        local newdoh tmp
        newdoh=$(ask "New DoH URL: ")
        [[ -z "$newdoh" ]] && { err "Empty DoH URL"; continue; }
        cp "$CONFIG_FILE" "/tmp/config.bak.$$" || true
        tmp=$(tmpfile)
        jq --arg d "$newdoh" '.dns.servers=[ $d, "1.1.1.1", "8.8.8.8" ]' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
        if xray_test_config; then
          systemctl restart xray; log "DoH updated"
        else
          err "Invalid config; reverting."
          mv "/tmp/config.bak.$$" "$CONFIG_FILE"
        fi
      ;;
      7)
        local newu tmp
        read -r -p "New UUID (36-hex): " newu
        if [[ $newu =~ ^[0-9A-Za-z-]{36}$ ]]; then
          UUID=$newu; echo "$UUID" > "$UUID_FILE"
          tmp=$(tmpfile)
          jq --arg u "$UUID" '.inbounds[0].settings.clients[0].id=$u' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
          if xray_test_config; then
            update_nginx_uuid
            generate_subscription
            systemctl restart xray
            systemctl restart nginx
            log "UUID updated (main only)"
          else
            err "Invalid config after UUID change"
          fi
        else
          err "Invalid UUID"
        fi
      ;;
      8) switch_transport ;;
      9) systemctl restart xray; log "Xray restarted" ;;
      10) systemctl reload xray || systemctl restart xray; log "Xray reloaded" ;;
      11) vnstat -d | tail -n1 || true ;;
      12) journalctl -u xray -n 80 --no-pager || true ;;
      13) uninstall ;;
      0) exit 0 ;;
      *) err "Invalid choice" ;;
    esac
  done
}

uninstall(){
  log "Uninstalling RealityGhost …"
  systemctl stop xray nginx || true
  systemctl disable xray || true

  ufw delete allow 80/tcp || true
  ufw delete allow 443/tcp || true

  remove_kernel_tuning || true

  rm -rf "$XRAY_DIR" "$SCRIPT_DIR" "$SUB_DIR" 2>/dev/null || true
  rm -f  "$PUBKEY_FILE" "$UUID_FILE" "$STATE_FILE" "$GHOST_CONF" "$TRANSPORT_FILE" 2>/dev/null || true
  rm -f  "$NGINX_SITE" /etc/nginx/sites-enabled/ghost_https.conf 2>/dev/null || true
  rm -f  /etc/cron.d/ghost /usr/local/bin/realityghost 2>/dev/null || true

  rm -f /etc/systemd/system/xray.service 2>/dev/null || true
  systemctl daemon-reload || true

  if nginx -t 2>/dev/null; then systemctl restart nginx || true; else systemctl stop nginx || true; fi
  log "Uninstalled."
}

case "${1:-}" in
  install) install;;
  manage) manage;;
  manual-rotate) manual_rotate_all;;
  uninstall) uninstall;;
  *) echo "Usage: $0 {install|manage|manual-rotate|uninstall}"; exit 1;;
esac
