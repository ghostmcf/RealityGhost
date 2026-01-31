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

### IDs ###
UUID="9f416f94-9c90-4e5a-9ab4-dde5e147f7c3"
EXTRA_UUID="0cd3e743-f8dd-4b10-82f8-f6c35e17f182"  # fixed guest subscription

### Defaults ###
DOH_SERVER="https://dns.google/dns-query"
SERVER_IP="91.107.158.133"
DEFAULT_TRANSPORT="xhttp"  # xhttp|tcp

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
  log "Transport set to: $t"
}

# ────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────

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
  local out bin attempt priv pub
  bin=$(xray_bin) || true
  [[ -z "${bin:-}" ]] && { err "Xray binary not found for keygen"; return 1; }

  for attempt in {1..8}; do
    out=$("$bin" x25519 2>&1 || true)
    priv=$(awk -F': *' 'tolower($0) ~ /private/ { gsub(/\r/,"",$2); print $2; exit }' <<<"$out")
    pub=$(awk  -F': *' 'tolower($0) ~ /public/  { gsub(/\r/,"",$2); print $2; exit }' <<<"$out")

    if [[ -z "${priv:-}" || -z "${pub:-}" ]]; then
      mapfile -t _k < <(grep -Eo '[A-Za-z0-9+/=]{40,90}' <<<"$out" | tail -n2)
      priv=${_k[0]:-}; pub=${_k[1]:-}
    fi

    if [[ -n "${priv:-}" && -n "${pub:-}" && "$priv" != "$pub" ]]; then
      echo "$priv $pub"; return 0
    fi
    sleep 0.2
  done

  err "Keygen failed (priv/pub parse bug)"
  return 1
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

get_xhttp_path(){
  jq -r '.inbounds[0].streamSettings.xhttpSettings.path // empty' "$CONFIG_FILE" 2>/dev/null | sed 's#^/##'
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

write_config(){
  log "Writing Xray config …"
  mkdir -p /var/log/xray "$XRAY_DIR" "$SCRIPT_DIR" "$SUB_DIR"

  local keys PRIV PUB
  keys=$(xray_gen_keys) || { err "Failed keygen"; exit 1; }
  PRIV=$(cut -d' ' -f1 <<<"$keys")
  PUB=$(cut -d' ' -f2 <<<"$keys")
  echo "$PUB" > "$PUBKEY_FILE"   # subscriptions only

  local SID FP PATH_X TRANSPORT STREAM_SETTINGS tmp
  SID=$(openssl rand -hex 8)
  FP=$(shuf -e chrome edge firefox safari -n1)
  TRANSPORT=$(get_transport)

  PATH_X="$(get_xhttp_path)"
  [[ -z "$PATH_X" ]] && PATH_X="$(openssl rand -hex 8)"

  if [[ "$TRANSPORT" == "xhttp" ]]; then
    STREAM_SETTINGS=$(cat <<EOF
{
  "network": "xhttp",
  "security": "reality",
  "realitySettings": {
    "xver": 0,
    "show": false,
    "dest": "google.com:443",
    "serverNames": ["google.com","www.gstatic.com","fonts.gstatic.com"],
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
  else
    STREAM_SETTINGS=$(cat <<EOF
{
  "network": "tcp",
  "security": "reality",
  "realitySettings": {
    "xver": 0,
    "show": false,
    "dest": "google.com:443",
    "serverNames": ["google.com","www.gstatic.com","fonts.gstatic.com"],
    "privateKey": "$PRIV",
    "shortIds": ["$SID"]
  },
  "tlsSettings": {
    "fingerprint": "$FP",
    "alpn": ["h2"],
    "enablePQTls": true
  }
}
EOF
)
  fi

  cat > "$CONFIG_FILE" <<EOF
{
  "log": {"access": "/dev/null", "error": "/var/log/xray/err.log", "loglevel": "warning"},
  "dns": {"servers": ["$DOH_SERVER","1.1.1.1","8.8.8.8"]},
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 8444,
      "protocol": "vless",
      "settings": {
        "clients": [
          {"id": "$UUID", "flow": ""},
          {"id": "$EXTRA_UUID", "flow": ""}
        ],
        "decryption": "none"
      },
      "streamSettings": $STREAM_SETTINGS,
      "tag": "RealityVLESS"
    }
  ],
  "outbounds": [
    {"protocol": "freedom", "settings": {}, "tag": "direct"},
    {"protocol": "blackhole", "settings": {"response": {"type":"http"}}, "tag": "blocked"}
  ]
}
EOF

  tmp=$(tmpfile)
  jq 'del(.inbounds[0].streamSettings.realitySettings.pbk)' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
  log "Xray config written (transport=$(get_transport)) → $CONFIG_FILE"
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

ensure_keys_sid_and_path(){
  local sid pk keys priv pub tmp dest tr path

  tr=$(get_transport)
  sid=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0] // empty' "$CONFIG_FILE" 2>/dev/null || true)
  pk=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey // empty' "$CONFIG_FILE" 2>/dev/null || true)

  if [[ -z "${pk:-}" || ! -s "$PUBKEY_FILE" ]]; then
    log "Reality keys missing/invalid → regenerating …"
    keys=$(xray_gen_keys) || { err "Keygen failed"; return 1; }
    priv=$(cut -d' ' -f1 <<<"$keys")
    pub=$(cut -d' ' -f2 <<<"$keys")
    echo "$pub" > "$PUBKEY_FILE"

    tmp=$(tmpfile)
    jq --arg pk "$priv" '
      .inbounds[0].streamSettings.realitySettings.privateKey=$pk
      | del(.inbounds[0].streamSettings.realitySettings.pbk)
    ' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
  fi

  if [[ -z "${sid:-}" ]]; then
    log "shortId missing → creating one …"
    sid=$(openssl rand -hex 8)
    tmp=$(tmpfile)
    jq --arg s "$sid" '.inbounds[0].streamSettings.realitySettings.shortIds=[ $s ]' \
      "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
  fi

  dest=$(jq -r '.inbounds[0].streamSettings.realitySettings.dest // empty' "$CONFIG_FILE" 2>/dev/null || true)
  if [[ -z "$dest" ]]; then
    tmp=$(tmpfile)
    jq '
      .inbounds[0].streamSettings.realitySettings.dest="google.com:443"
      | .inbounds[0].streamSettings.realitySettings.serverNames=["google.com","www.gstatic.com","fonts.gstatic.com"]
    ' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
  fi

  if [[ "$tr" == "xhttp" ]]; then
    path=$(get_xhttp_path)
    if [[ -z "${path:-}" ]]; then
      log "xhttp path missing → creating one …"
      path="$(openssl rand -hex 8)"
      tmp=$(tmpfile)
      jq --arg p "/$path" '
        .inbounds[0].streamSettings.xhttpSettings.path=$p
        | .inbounds[0].streamSettings.xhttpSettings.mode="packet-up"
      ' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
    fi
  else
    tmp=$(tmpfile)
    jq 'del(.inbounds[0].streamSettings.xhttpSettings)' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
  fi

  tmp=$(tmpfile)
  jq 'del(.inbounds[0].streamSettings.realitySettings.pbk)' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
  return 0
}

# ────────────────────────────────────────────────────────────────
# Subscription builders (respect transport)
# ────────────────────────────────────────────────────────────────

build_vless_uri(){
  local u="$1" sni="$2" tag="$3"
  local IP SID FP PB tr path uri

  tr=$(get_transport)
  IP=$SERVER_IP
  SID=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0] // empty' "$CONFIG_FILE")
  FP=$(jq -r  '.inbounds[0].streamSettings.tlsSettings.fingerprint // empty' "$CONFIG_FILE")
  PB=$(<"$PUBKEY_FILE")
  path=$(get_xhttp_path)

  [[ -z "$PB" ]] && { err "Empty publicKey file"; return 1; }
  [[ -z "$SID" ]] && { err "Empty shortId"; return 1; }

  uri="vless://$u@$IP:443?encryption=none&security=reality"
  if [[ "$tr" == "xhttp" ]]; then
    [[ -z "$path" ]] && { err "Empty xhttp path"; return 1; }
    uri+="&type=xhttp&mode=packet-up&path=/$path"
  else
    uri+="&type=tcp"
  fi
  uri+="&sni=$sni&fp=$FP&alpn=h2&pbk=$PB&sid=$SID#${tag}"
  echo "$uri"
}

generate_one_subscription(){
  local U="$1" PREFIX="$2"
  local RAW_FILE URL
  ensure_keys_sid_and_path || return 1

  RAW_FILE="$SUB_DIR/$U.raw"; : > "$RAW_FILE"
  local -a SNIS=(google.com www.gstatic.com fonts.gstatic.com)

  for i in {0..2}; do
    local sni tag uri
    sni="${SNIS[i]}"
    if (( i == 0 )); then tag="${PREFIX}"; else tag="${PREFIX}-Backup${i}"; fi
    uri=$(build_vless_uri "$U" "$sni" "$tag")
    echo "# $tag (transport=$(get_transport), SNI=$sni)" >>"$RAW_FILE"
    echo "$uri" >>"$RAW_FILE"
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
  generate_one_subscription "$EXTRA_UUID" "Guest"

  if command -v qrencode >/dev/null 2>&1; then
    echo
    log "QR (Main): https://$domain/$UUID"
    qrencode -t ANSIUTF8 "https://$domain/$UUID" || true
    echo
    log "QR (Guest): https://$domain/$EXTRA_UUID"
    qrencode -t ANSIUTF8 "https://$domain/$EXTRA_UUID" || true
  fi

  log "✔ Subscriptions regenerated"
}

# ────────────────────────────────────────────────────────────────
# NGINX (unchanged idea)
# ────────────────────────────────────────────────────────────────

write_nginx(){
  log "Installing & configuring NGINX …"
  rm -f /etc/nginx/sites-enabled/default || true
  mkdir -p "$SUB_DIR" /var/www/ghost_web
  echo '<!doctype html><html><head><meta charset="utf-8"><title>Welcome</title></head><body><h1>It works.</h1></body></html>' > /var/www/ghost_web/index.html

  systemctl stop nginx || true

  if ! certbot certonly --standalone -d "$domain" --non-interactive --agree-tos -m "$help_email"; then
    err "Certbot failed."
    [[ -f "/etc/letsencrypt/live/$domain/fullchain.pem" ]] || { err "No certificate present. Aborting."; return 1; }
    log "Using existing certificate for $domain."
  fi

  [[ -f "/etc/letsencrypt/live/$domain/fullchain.pem" ]] || { err "Certificate missing. Aborting."; return 1; }

  cat > "$NGINX_SITE" <<EOF
server {
    listen 127.0.0.1:8443 ssl http2;
    server_name $domain;
    ssl_certificate     /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;

    location = /$UUID { alias $SUB_DIR/$UUID; default_type text/plain; add_header Content-Disposition ""; }
    location = /$EXTRA_UUID { alias $SUB_DIR/$EXTRA_UUID; default_type text/plain; add_header Content-Disposition ""; }

    location / { root /var/www/ghost_web; index index.html; }
}
EOF
  ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/ghost_https.conf

  cat > /etc/nginx/nginx.conf <<'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

load_module /usr/lib/nginx/modules/ngx_stream_module.so;

events { worker_connections 4096; }

http {
    include       /etc/nginx/mime.types;
    default_type  text/html;
    sendfile      on;
    keepalive_timeout 65;
    include /etc/nginx/sites-enabled/*.conf;
}

stream {
    map $ssl_preread_server_name $backend {
        ~^google\.com$           xray;
        ~^www\.gstatic\.com$    xray;
        ~^fonts\.gstatic\.com$  xray;
        default                  subscribe;
    }
    upstream subscribe { server 127.0.0.1:8443; }
    upstream xray      { server 127.0.0.1:8444; }
    server {
        listen 443 reuseport backlog=8192;
        proxy_connect_timeout 10s;
        proxy_timeout 300s;
        ssl_preread on;
        proxy_pass $backend;
    }
}
EOF

  nginx -t && systemctl restart nginx
  log "NGINX configured"
}

update_nginx_uuid(){
  cat > "$NGINX_SITE" <<EOF
server {
    listen 127.0.0.1:8443 ssl http2;
    server_name $domain;
    ssl_certificate     /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;

    location = /$UUID { alias $SUB_DIR/$UUID; default_type text/plain; add_header Content-Disposition ""; }
    location = /$EXTRA_UUID { alias $SUB_DIR/$EXTRA_UUID; default_type text/plain; add_header Content-Disposition ""; }

    location / { root /var/www/ghost_web; index index.html; }
}
EOF
  ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/ghost_https.conf
  nginx -t && systemctl restart nginx
  log "✅ Updated NGINX → UUID=$UUID | EXTRA_UUID=$EXTRA_UUID"
}

# ────────────────────────────────────────────────────────────────
# SAFE Rotate (manual)
# ────────────────────────────────────────────────────────────────

manual_rotate_all(){
  clear
  log "→ Manual rotation (transport=$(get_transport)) …"
  log "→ SAFE MODE: keys/path are NOT rotated unless ROTATE_KEYS=1 / ROTATE_PATH=1"

  local tmp old_fp new_fp newsid keepN
  keepN=6

  # Backup for rollback
  local bak
  bak=$(tmpfile)
  cp -f "$CONFIG_FILE" "$bak"

  # 1) Fingerprint rotate (safe)
  old_fp=$(jq -r '.inbounds[0].streamSettings.tlsSettings.fingerprint' "$CONFIG_FILE")
  while :; do
    new_fp=$(shuf -e chrome edge firefox safari -n1)
    [[ -n "$new_fp" && "$new_fp" != "$old_fp" ]] && break
  done
  tmp=$(tmpfile)
  jq --arg p "$new_fp" '.inbounds[0].streamSettings.tlsSettings.fingerprint=$p' \
     "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
  log "Rotated Fingerprint → $new_fp"

  # 2) ShortId: APPEND (keep last N)  ✅ مهم‌ترین اصلاح
  newsid=$(openssl rand -hex 8)
  tmp=$(tmpfile)
  jq --arg s "$newsid" --argjson n "$keepN" '
    .inbounds[0].streamSettings.realitySettings.shortIds =
      ([ $s ] + (.inbounds[0].streamSettings.realitySettings.shortIds // []))
      | unique
      | .[0:$n]
  ' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
  log "Appended ShortID → $newsid (kept up to $keepN)"

  # 3) Keys rotate only if explicitly requested (HARD)
  if [[ "${ROTATE_KEYS:-0}" == "1" ]]; then
    log "HARD ROTATE: rotating Reality keys (old clients WILL drop)"
    local keys priv pub
    keys=$(xray_gen_keys) || { err "Keygen failed"; cp -f "$bak" "$CONFIG_FILE"; return 1; }
    priv=$(cut -d' ' -f1 <<<"$keys")
    pub=$(cut -d' ' -f2 <<<"$keys")

    tmp=$(tmpfile)
    jq --arg pk "$priv" '
      .inbounds[0].streamSettings.realitySettings.privateKey=$pk
      | del(.inbounds[0].streamSettings.realitySettings.pbk)
    ' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
    echo "$pub" > "$PUBKEY_FILE"
    log "Rotated Reality keys → public key updated"
  fi

  # 4) XHTTP path rotate only if explicitly requested (HARD) and only in xhttp
  if [[ "$(get_transport)" == "xhttp" && "${ROTATE_PATH:-0}" == "1" ]]; then
    log "HARD ROTATE: rotating xHTTP path (old clients WILL drop)"
    local p
    p=$(openssl rand -hex 8)
    tmp=$(tmpfile)
    jq --arg v "/$p" '
      .inbounds[0].streamSettings.xhttpSettings.path=$v
      | .inbounds[0].streamSettings.xhttpSettings.mode="packet-up"
    ' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
    log "Rotated xHTTP path → /$p"
  fi

  # Ensure consistency & remove pbk
  ensure_keys_sid_and_path || { err "ensure failed"; cp -f "$bak" "$CONFIG_FILE"; return 1; }

  # Validate BEFORE restart, rollback if invalid
  if ! xray_test_config; then
    err "Config invalid after rotation → rollback"
    cp -f "$bak" "$CONFIG_FILE"
    return 1
  fi

  # Restart services
  systemctl restart xray
  systemctl restart nginx

  # Rebuild subscriptions (now reflect new fp/sid, and keys/path if hard-rotated)
  generate_subscription

  mkdir -p "$SCRIPT_DIR"
  jq -n --arg ts "$(date -Is)" \
        --arg tr "$(get_transport)" \
        --arg fp "$new_fp" \
        --arg sid_new "$newsid" \
        --arg sid_active "$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$CONFIG_FILE")" \
        --arg pb "$(cat "$PUBKEY_FILE" 2>/dev/null || true)" \
        --arg path "$(get_xhttp_path)" \
        --arg rotate_keys "${ROTATE_KEYS:-0}" \
        --arg rotate_path "${ROTATE_PATH:-0}" '
        {rotated_at:$ts, transport:$tr, fp:$fp, sid_added:$sid_new, sid_active:$sid_active,
         pbk:$pb, xhttp_path:$path, rotate_keys:$rotate_keys, rotate_path:$rotate_path}
  ' > "$STATE_FILE"

  log "Rotation complete (SAFE)."
}

# ────────────────────────────────────────────────────────────────
# Transport switch (core feature)
# ────────────────────────────────────────────────────────────────

switch_transport(){
  local cur next tmp path
  cur=$(get_transport)
  if [[ "$cur" == "xhttp" ]]; then next="tcp"; else next="xhttp"; fi

  log "Switching transport: $cur → $next"
  set_transport "$next"

  if [[ "$next" == "tcp" ]]; then
    tmp=$(tmpfile)
    jq '
      .inbounds[0].streamSettings.network="tcp"
      | del(.inbounds[0].streamSettings.xhttpSettings)
    ' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
  else
    path=$(get_xhttp_path)
    [[ -z "$path" ]] && path=$(openssl rand -hex 8)
    tmp=$(tmpfile)
    jq --arg p "/$path" '
      .inbounds[0].streamSettings.network="xhttp"
      | .inbounds[0].streamSettings.xhttpSettings.path=$p
      | .inbounds[0].streamSettings.xhttpSettings.mode="packet-up"
    ' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
  fi

  ensure_keys_sid_and_path
  xray_test_config || { err "Config invalid after switching transport"; return 1; }

  systemctl restart xray
  systemctl restart nginx
  generate_subscription
  log "✅ Switched transport to $next"
}

# ────────────────────────────────────────────────────────────────
# Install / Manage / Uninstall
# ────────────────────────────────────────────────────────────────

install(){
  log "=== RealityGhost v3.6.1 Install (Dual-Mode) ==="
  domain=$(ask "Domain (default api4.mindescape.co): ") && domain=${domain:-api4.mindescape.co}
  help_email=$(ask "Email for Let's Encrypt (default help@mindescape.co): ") && help_email=${help_email:-help@mindescape.co}
  echo "$domain" > "$GHOST_CONF"

  local t
  t=$(ask "Transport (xhttp/tcp) [default: $DEFAULT_TRANSPORT]: ")
  t=${t:-$DEFAULT_TRANSPORT}
  [[ "$t" != "xhttp" && "$t" != "tcp" ]] && t="$DEFAULT_TRANSPORT"
  set_transport "$t"

  read -r -p "Generate new UUID? (y/N): " yn
  if [[ "${yn:-N}" =~ ^[Yy]$ ]]; then UUID="$(uuidgen)"; log "Generated new UUID → $UUID"; fi

  apt-get update -y
  apt-get install -y curl unzip jq openssl ufw qrencode vnstat uuid-runtime nginx libnginx-mod-stream certbot xxd python3

  mkdir -p "$SCRIPT_DIR" "$SUB_DIR"
  echo "$UUID" > "$UUID_FILE"

  detect_ip || true

  local SSH_PORT
  SSH_PORT=$(ss -tnlp 2>/dev/null | awk '/sshd/ && /LISTEN/ {print $4}' | sed 's/.*://;q')
  [[ -z "${SSH_PORT:-}" ]] && SSH_PORT=22
  ufw allow "${SSH_PORT}/tcp" || true
  ufw allow 80/tcp && ufw allow 443/tcp && ufw --force enable || true

  local ver
  ver=$(curl -s https://api.github.com/repos/XTLS/xray-core/releases/latest | jq -r .tag_name | sed 's/^v//')
  curl -L -o /tmp/x.zip "https://github.com/XTLS/xray-core/releases/download/v${ver}/Xray-linux-64.zip"
  mkdir -p "$XRAY_DIR" && unzip -oq /tmp/x.zip -d "$XRAY_DIR" && chmod +x "$XRAY_DIR/xray"

  write_config
  write_xray_service
  write_nginx
  update_nginx_uuid

  tune_kernel || true
  ensure_keys_sid_and_path
  systemctl restart xray
  systemctl restart nginx
  generate_subscription

  echo "0 5 */3 * * root /usr/local/bin/realityghost manual-rotate" > /etc/cron.d/ghost
  ln -sf "$(realpath "$0")" /usr/local/bin/realityghost
  chmod +x /usr/local/bin/realityghost || true
  chmod +x "$(realpath "$0")" || true

  log "=== Install complete. Run 'realityghost manage' ==="
}

manage(){
  [[ $EUID -eq 0 ]] || { err "Run as root"; exit 1; }

  while true; do
    local cur
    cur=$(get_transport)
    cat <<EOF

RealityGhost Manager (transport=$cur)
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
         echo "https://$domain/$EXTRA_UUID"
         if command -v qrencode >/dev/null 2>&1; then
           echo; log "QR (Main):";  qrencode -t ANSIUTF8 "https://$domain/$UUID"  || true
           echo; log "QR (Guest):"; qrencode -t ANSIUTF8 "https://$domain/$EXTRA_UUID" || true
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
