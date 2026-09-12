#!/usr/bin/env bash
#
# AmneziaWG Panel - one-line installer
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/rima0222/Am_wg3/main/install.sh | sudo bash
#
set -euo pipefail

REPO_URL="${AWG_PANEL_REPO_URL:-https://github.com/rima0222/Am_wg3.git}"
INSTALL_DIR="/opt/awg-panel"
ETC_DIR="/etc/awg-panel"
WG_ETC_DIR="/etc/amnezia/amneziawg"
IFACE="awg0"
CONF_PATH="${WG_ETC_DIR}/${IFACE}.conf"

# ---------- helpers ----------
log()  { echo "[+] $*"; }
warn() { echo "[!] $*"; }
err()  { echo "[x] $*" >&2; }

ask() {
  # ask "question text" "default value"
  local prompt="$1" default="${2:-}" answer
  if [ -n "$default" ]; then
    printf '\n>> %s\n   (press Enter to keep default) [%s]: ' "$prompt" "$default" > /dev/tty
  else
    printf '\n>> %s: ' "$prompt" > /dev/tty
  fi
  IFS= read -r answer < /dev/tty
  echo "${answer:-$default}"
}

ask_secret() {
  local prompt="$1" answer
  printf '\n>> %s: ' "$prompt" > /dev/tty
  IFS= read -rs answer < /dev/tty
  echo "" > /dev/tty
  echo "$answer"
}

random_hex() { openssl rand -hex "${1:-16}"; }
random_int() { shuf -i "$1-$2" -n 1; }

if [ "$(id -u)" -ne 0 ]; then
  err "This script must be run as root (sudo bash install.sh)"
  exit 1
fi

if ! grep -qi ubuntu /etc/os-release; then
  warn "This script was tested on Ubuntu; it may not work on other distros."
fi

log "Starting AmneziaWG Panel installation..."

# ---------- 1. settings ----------
log "Detecting public IP (max 5s per attempt)..."
PUBLIC_IP="$(curl -s -4 --max-time 5 https://api.ipify.org || true)"
if [ -z "$PUBLIC_IP" ]; then
  PUBLIC_IP="$(curl -s -4 --max-time 5 https://ifconfig.me || true)"
fi
if [ -z "$PUBLIC_IP" ]; then
  warn "Could not auto-detect public IP; you'll need to enter it manually."
fi

SERVER_ENDPOINT="$(ask 'Server IP or domain that clients will connect to' "${PUBLIC_IP}")"
echo "   -> using: ${SERVER_ENDPOINT}" > /dev/tty
WG_PORT="$(ask 'WireGuard UDP port (pick an unusual one to avoid collisions)' "$(random_int 20000 60000)")"
echo "   -> using: ${WG_PORT}" > /dev/tty
PANEL_PORT="$(ask 'Web panel port' "8787")"
echo "   -> using: ${PANEL_PORT}" > /dev/tty
ADMIN_USER="$(ask 'Panel admin username' "admin")"
echo "   -> using: ${ADMIN_USER}" > /dev/tty
ADMIN_PASS="$(ask_secret 'Panel admin password')"
if [ -z "$ADMIN_PASS" ]; then
  ADMIN_PASS="$(random_hex 8)"
  warn "Password was empty; generated a random one: ${ADMIN_PASS}"
fi

# ---------- 2. dependencies ----------
log "Installing prerequisites..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y software-properties-common python3-launchpadlib gnupg2 \
  linux-headers-"$(uname -r)" python3-venv python3-pip qrencode iptables \
  curl openssl git unzip

log "Adding the AmneziaWG PPA..."
add-apt-repository -y ppa:amnezia/ppa
apt-get update -y

log "Installing AmneziaWG..."
apt-get install -y amneziawg amneziawg-tools

if ! command -v awg >/dev/null 2>&1; then
  err "amneziawg-tools installation failed. Make sure kernel headers match the running kernel."
  exit 1
fi

# ---------- 3. IP forwarding + tuning ----------
log "Enabling IP forwarding and tuning for many concurrent users..."
cat > /etc/sysctl.d/99-awg-panel.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
net.core.netdev_max_backlog = 4096
net.netfilter.nf_conntrack_max = 262144
net.ipv4.udp_mem = 65536 131072 262144
EOF
sysctl --system >/dev/null

# ---------- 4. detect outbound interface(s) ----------
DEFAULT_IFACE="$(ip route show default | awk '/default/ {print $5; exit}')"
if [ -z "$DEFAULT_IFACE" ]; then
  err "Could not detect the default network interface."
  exit 1
fi
log "Outbound network interface (IPv4): ${DEFAULT_IFACE}"

ENABLE_IPV6=0
DEFAULT_IFACE6=""
if ip -6 route show default 2>/dev/null | grep -q default; then
  DEFAULT_IFACE6="$(ip -6 route show default | awk '/default/ {print $5; exit}')"
  if [ -n "$DEFAULT_IFACE6" ]; then
    ENABLE_IPV6=1
    log "Native IPv6 uplink detected (${DEFAULT_IFACE6}) - enabling dual-stack for clients."
  fi
fi
if [ "$ENABLE_IPV6" = "0" ]; then
  log "No IPv6 uplink detected - clients will be IPv4-only (this is normal on most VPS providers)."
fi

# ---------- 5. server keys + anti-DPI obfuscation params ----------
log "Generating keys and anti-DPI obfuscation parameters..."
mkdir -p "$WG_ETC_DIR"
chmod 700 "$WG_ETC_DIR"
SERVER_PRIVATE_KEY="$(awg genkey)"
SERVER_PUBLIC_KEY="$(echo "$SERVER_PRIVATE_KEY" | awg pubkey)"

gen_unique_h() {
  local vals=()
  while [ "${#vals[@]}" -lt 4 ]; do
    local v
    v="$(random_int 100000 2000000000)"
    if [[ ! " ${vals[*]:-} " =~ " ${v} " ]]; then
      vals+=("$v")
    fi
  done
  echo "${vals[@]}"
}
read -r H1 H2 H3 H4 <<< "$(gen_unique_h)"
JC="$(random_int 3 10)"
JMIN="40"
JMAX="$(random_int 200 900)"
S1="$(random_int 15 60)"
S2="$(random_int 15 60)"

AWG_SUBNET="10.29.29.0/24"
AWG_ADDRESS="10.29.29.1/24"
AWG_SUBNET6="fd42:29:29::/64"
AWG_ADDRESS6="fd42:29:29::1/64"
AWG_DNS="1.1.1.1, 8.8.8.8"
CLIENT_MTU="1280"

if [ "$ENABLE_IPV6" = "1" ]; then
  ADDRESS_LINE="${AWG_ADDRESS}, ${AWG_ADDRESS6}"
else
  ADDRESS_LINE="${AWG_ADDRESS}"
fi

IPV6_POSTUP=""
IPV6_POSTDOWN=""
if [ "$ENABLE_IPV6" = "1" ]; then
  IPV6_POSTUP="PostUp = ip6tables -t nat -A POSTROUTING -s ${AWG_SUBNET6} -o ${DEFAULT_IFACE6} -j MASQUERADE
PostUp = ip6tables -A FORWARD -i ${IFACE} -j ACCEPT
PostUp = ip6tables -A FORWARD -o ${IFACE} -j ACCEPT"
  IPV6_POSTDOWN="PostDown = ip6tables -t nat -D POSTROUTING -s ${AWG_SUBNET6} -o ${DEFAULT_IFACE6} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${IFACE} -j ACCEPT
PostDown = ip6tables -D FORWARD -o ${IFACE} -j ACCEPT"
fi

# ---------- 6. server interface config ----------
log "Writing ${CONF_PATH} ..."
cat > "$CONF_PATH" <<EOF
[Interface]
PrivateKey = ${SERVER_PRIVATE_KEY}
Address = ${ADDRESS_LINE}
ListenPort = ${WG_PORT}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
S1 = ${S1}
S2 = ${S2}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}

PostUp = iptables -t nat -A POSTROUTING -s ${AWG_SUBNET} -o ${DEFAULT_IFACE} -j MASQUERADE
PostUp = iptables -A FORWARD -i ${IFACE} -j ACCEPT
PostUp = iptables -A FORWARD -o ${IFACE} -j ACCEPT
PostUp = iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
${IPV6_POSTUP}
PostDown = iptables -t nat -D POSTROUTING -s ${AWG_SUBNET} -o ${DEFAULT_IFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${IFACE} -j ACCEPT
PostDown = iptables -D FORWARD -o ${IFACE} -j ACCEPT
PostDown = iptables -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
${IPV6_POSTDOWN}
EOF
chmod 600 "$CONF_PATH"

# ---------- 7. bring up the tunnel ----------
log "Starting the ${IFACE} tunnel..."
systemctl enable --now "awg-quick@${IFACE}" || {
  err "Failed to bring up the tunnel. Check logs with:"
  echo "journalctl -u awg-quick@${IFACE} -n 50 --no-pager"
  exit 1
}

# ---------- 8. deploy panel files ----------
log "Deploying panel to ${INSTALL_DIR}..."
SRC_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ]; then
  SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
fi
mkdir -p "$INSTALL_DIR"
if [ -n "$SRC_DIR" ] && [ -d "${SRC_DIR}/panel" ]; then
  log "Using local copy at ${SRC_DIR}"
  cp -r "${SRC_DIR}/panel/"* "$INSTALL_DIR/"
else
  # script was run standalone (curl | bash) - clone the full repo instead
  log "Cloning ${REPO_URL} ..."
  TMP_CLONE="$(mktemp -d)"
  git clone --depth 1 "$REPO_URL" "$TMP_CLONE"
  cp -r "${TMP_CLONE}/panel/"* "$INSTALL_DIR/"
  rm -rf "$TMP_CLONE"
fi

log "Creating Python virtual environment and installing dependencies..."
python3 -m venv "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install --upgrade pip -q
"${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" -q

# ---------- 9. panel config + admin password hash ----------
log "Writing panel configuration..."
mkdir -p "$ETC_DIR"
chmod 700 "$ETC_DIR"

log "Generating a self-signed TLS certificate for the panel (protects the admin login in transit)..."
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout "${ETC_DIR}/key.pem" \
  -out "${ETC_DIR}/cert.pem" \
  -days 3650 \
  -subj "/CN=${SERVER_ENDPOINT}" >/dev/null 2>&1
chmod 600 "${ETC_DIR}/key.pem"
chmod 644 "${ETC_DIR}/cert.pem"

PASSWORD_HASH="$("${INSTALL_DIR}/venv/bin/python3" - "$ADMIN_PASS" <<'PYEOF'
import sys, hashlib, os
password = sys.argv[1]
salt = os.urandom(16).hex()
digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000)
print(f"{salt}${digest.hex()}")
PYEOF
)"

JWT_SECRET="$(random_hex 32)"

cat > "${ETC_DIR}/panel.env" <<EOF
AWG_INTERFACE=${IFACE}
AWG_CONF_PATH=${CONF_PATH}
AWG_SUBNET=${AWG_SUBNET}
AWG_ADDRESS=${AWG_ADDRESS}
AWG_ENABLE_IPV6=${ENABLE_IPV6}
AWG_SUBNET6=${AWG_SUBNET6}
AWG_ADDRESS6=${AWG_ADDRESS6}
AWG_ENDPOINT=${SERVER_ENDPOINT}
AWG_PORT=${WG_PORT}
AWG_SERVER_PUBLIC_KEY=${SERVER_PUBLIC_KEY}
AWG_DNS=${AWG_DNS}
AWG_JC=${JC}
AWG_JMIN=${JMIN}
AWG_JMAX=${JMAX}
AWG_S1=${S1}
AWG_S2=${S2}
AWG_H1=${H1}
AWG_H2=${H2}
AWG_H3=${H3}
AWG_H4=${H4}
AWG_CLIENT_MTU=${CLIENT_MTU}
PANEL_DB_PATH=${ETC_DIR}/panel.db
PANEL_JWT_SECRET=${JWT_SECRET}
PANEL_PORT=${PANEL_PORT}
PANEL_ADMIN_USER=${ADMIN_USER}
PANEL_ADMIN_PASSWORD_HASH=${PASSWORD_HASH}
PANEL_STATS_INTERVAL=2
PANEL_ONLINE_THRESHOLD=150
EOF
chmod 600 "${ETC_DIR}/panel.env"

# ---------- 10. systemd service ----------
log "Installing the panel service..."
if [ -f "${SRC_DIR}/systemd/awg-panel.service" ]; then
  cp "${SRC_DIR}/systemd/awg-panel.service" /etc/systemd/system/awg-panel.service
else
  cat > /etc/systemd/system/awg-panel.service <<EOF
[Unit]
Description=AmneziaWG Management Panel
After=network.target awg-quick@${IFACE}.service
Wants=awg-quick@${IFACE}.service

[Service]
Type=simple
EnvironmentFile=${ETC_DIR}/panel.env
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port \${PANEL_PORT} --app-dir ${INSTALL_DIR} --ssl-keyfile ${ETC_DIR}/key.pem --ssl-certfile ${ETC_DIR}/cert.pem
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
systemctl enable --now awg-panel

# ---------- 11. firewall ----------
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow "${WG_PORT}/udp" >/dev/null
  ufw allow "${PANEL_PORT}/tcp" >/dev/null
fi

echo ""
echo "=================================================================="
echo "Installation complete."
echo "=================================================================="
echo "Panel:            https://${SERVER_ENDPOINT}:${PANEL_PORT}"
echo "User portal:      https://${SERVER_ENDPOINT}:${PANEL_PORT}/portal"
echo "Admin username:   ${ADMIN_USER}"
echo "Admin password:   ${ADMIN_PASS}"
echo "------------------------------------------------------------------"
echo "NOTE: the panel uses a self-signed TLS certificate (to keep your"
echo "login password from being sent in plaintext). Your browser will"
echo "show a security warning on first visit - this is expected; click"
echo "'Advanced > Proceed' to continue. Do this once before using /portal"
echo "from another site (e.g. GitHub Pages), or its requests will fail."
echo "Interface: ${IFACE}   Port: ${WG_PORT}"
if [ "$ENABLE_IPV6" = "1" ]; then
  echo "IPv6:      enabled (${AWG_SUBNET6})"
else
  echo "IPv6:      not available on this server (IPv4-only)"
fi
echo "Tunnel status:  awg show ${IFACE}"
echo "Panel logs:     journalctl -u awg-panel -f"
echo ""
echo "Migrating from another server? Restore your JSON backup from the"
echo "panel's Backup menu after logging in, then update the Endpoint IP"
echo "in each client config (or have users re-fetch it from /portal)."
echo "=================================================================="
