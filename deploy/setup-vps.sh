#!/usr/bin/env bash
# Provision a fresh Ubuntu 22.04+/Debian 12+ VPS as the KVN WireGuard server + API host.
# Run as root from a checkout of the repo:   sudo bash deploy/setup-vps.sh
# Env: DOMAIN=vpn.example.com (optional; enables HTTPS via Caddy)  SSH_PORT=22  WG_PORT=51820
#      VPN_SUBNET=10.8.0.0/24  SKIP_SSH_HARDENING=1
# Idempotent: existing WireGuard keys / secrets are never overwritten.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$(dirname "$HERE")"
SSH_PORT="${SSH_PORT:-22}"; WG_PORT="${WG_PORT:-51820}"; VPN_SUBNET="${VPN_SUBNET:-10.8.0.0/24}"
SERVER_ADDR="${VPN_SUBNET%.*}.1/${VPN_SUBNET#*/}"        # 10.8.0.1/24
WAN_IF="${WAN_IF:-$(ip -4 route show default | awk '{print $5; exit}')}"
[ -n "$WAN_IF" ] || { echo "cannot detect WAN interface, set WAN_IF"; exit 1; }
PUBLIC_IP="$(curl -4fsS --max-time 5 https://api.ipify.org || true)"

echo "==> packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard wireguard-tools nftables fail2ban unattended-upgrades curl ca-certificates rsync openssl
if ! command -v node >/dev/null || [ "$(node -p 'process.versions.node.split(".")[0]')" -lt 22 ]; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y -qq nodejs
fi

echo "==> WireGuard (wg0, $SERVER_ADDR, udp/$WG_PORT)"
install -d -m 700 /etc/wireguard
if [ ! -f /etc/wireguard/wg0.conf ]; then
  umask 077
  wg genkey > /etc/wireguard/server.key           # server PRIVATE key: root-only, never read by the API
  wg pubkey < /etc/wireguard/server.key > /etc/wireguard/server.pub
  cat > /etc/wireguard/wg0.conf <<CONF
[Interface]
Address = $SERVER_ADDR
ListenPort = $WG_PORT
PrivateKey = $(cat /etc/wireguard/server.key)
# No [Peer] blocks and no SaveConfig: peers are owned by the API, which re-adds them
# (reconcile) after every restart of this interface.
CONF
fi
chmod 600 /etc/wireguard/wg0.conf /etc/wireguard/server.key
systemctl enable --now wg-quick@wg0

echo "==> kernel forwarding"
cat > /etc/sysctl.d/99-kvn.conf <<CONF
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.tcp_syncookies = 1
CONF
sysctl --system >/dev/null

echo "==> firewall (nftables), WAN=$WAN_IF"
sed -e "s#@WAN_IF@#$WAN_IF#g" -e "s#@SSH_PORT@#$SSH_PORT#g" -e "s#@WG_PORT@#$WG_PORT#g" -e "s#@VPN_SUBNET@#$VPN_SUBNET#g" \
  "$HERE/nftables.conf.tpl" > /etc/nftables.conf
nft -c -f /etc/nftables.conf                       # validate before applying
nft -f /etc/nftables.conf
systemctl enable nftables

echo "==> fail2ban (sshd)"
cat > /etc/fail2ban/jail.d/kvn-sshd.conf <<CONF
[sshd]
enabled = true
port = $SSH_PORT
maxretry = 4
findtime = 10m
bantime = 1h
CONF
systemctl enable --now fail2ban && systemctl restart fail2ban

echo "==> SSH hardening"
if [ "${SKIP_SSH_HARDENING:-0}" = 1 ]; then
  echo "skipped (SKIP_SSH_HARDENING=1)"
elif ! find /root/.ssh /home/*/.ssh -name authorized_keys -size +0 2>/dev/null | grep -q .; then
  # Refuse to disable password login if nobody could log in afterwards.
  echo "!! no authorized_keys found: SSH hardening NOT applied. Add your key, then re-run." >&2
else
  install -m 644 "$HERE/sshd-hardening.conf" /etc/ssh/sshd_config.d/99-kvn-hardening.conf
  if sshd -t; then systemctl reload ssh 2>/dev/null || systemctl reload sshd; echo "applied"
  else rm -f /etc/ssh/sshd_config.d/99-kvn-hardening.conf; echo "!! sshd -t failed, reverted" >&2; fi
fi

echo "==> application"
id kvn >/dev/null 2>&1 || useradd --system --home /opt/kvn --shell /usr/sbin/nologin kvn
install -d -o root -g root /opt/kvn
rsync -a --delete --exclude node_modules --exclude data --exclude .git "$SRC/backend" "$SRC/frontend" /opt/kvn/
(cd /opt/kvn/backend && npm ci --omit=dev --silent)
chown -R root:root /opt/kvn
install -d -m 700 -o kvn -g kvn /var/lib/kvn
install -d -m 755 /etc/kvn
if [ ! -f /etc/kvn/kvn.env ]; then
  umask 077
  cat > /etc/kvn/kvn.env <<CONF
NODE_ENV=production
PORT=3000
TRUST_PROXY=1
JWT_SECRET=$(openssl rand -base64 48 | tr -d '\n')
DATA_ENCRYPTION_KEY=$(openssl rand -base64 32)
DB_PATH=/var/lib/kvn/kvn.sqlite
# Stage 1: fake payments. Remove both lines once the real provider is connected.
PAYMENT_PROVIDER=mock
ALLOW_MOCK_PAYMENTS=true
WG_APPLY_MODE=wg
WG_INTERFACE=wg0
WG_SUBNET=$VPN_SUBNET
WG_ENDPOINT=${DOMAIN:-${PUBLIC_IP:-CHANGE_ME}}:$WG_PORT
WG_SERVER_PUBLIC_KEY=$(cat /etc/wireguard/server.pub)
WG_SERVER_REGION=EU
FRONTEND_URL=https://${DOMAIN:-CHANGE_ME}
CONF
  chmod 600 /etc/kvn/kvn.env
fi
install -m 644 "$HERE/kvn.service" /etc/systemd/system/kvn.service
systemctl daemon-reload
systemctl enable --now kvn
systemctl restart kvn

if [ -n "${DOMAIN:-}" ]; then
  echo "==> Caddy (HTTPS for $DOMAIN)"
  apt-get install -y -qq caddy
  printf '%s {\n  encode gzip\n  reverse_proxy 127.0.0.1:3000\n}\n' "$DOMAIN" > /etc/caddy/Caddyfile
  systemctl reload caddy || systemctl restart caddy
fi

echo
echo "Done. Server public key: $(cat /etc/wireguard/server.pub)"
echo "Endpoint in configs:     ${DOMAIN:-$PUBLIC_IP}:$WG_PORT"
echo "Check:  wg show wg0 | systemctl status kvn | curl -s localhost:3000/api/health"
