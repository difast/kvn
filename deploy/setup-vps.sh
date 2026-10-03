#!/usr/bin/env bash
# Provision a fresh Ubuntu 22.04+/Debian 12+ VPS as the KVN WireGuard server + API host.
# Run as root from a checkout of the repo:   sudo bash deploy/setup-vps.sh
# Env: DOMAIN=vpn.example.com (optional; enables HTTPS via Caddy)  SSH_PORT=22  WG_PORT=51820
#      VPN_SUBNET=10.8.0.0/24  SKIP_SSH_HARDENING=1
#      XRAY_PORT=8443 (VLESS+Reality, tcp)  REALITY_DEST=host:443 (default: auto-picked from this server by pick-reality-dest.sh)
# Idempotent: existing WireGuard keys / secrets are never overwritten.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$(dirname "$HERE")"
SSH_PORT="${SSH_PORT:-22}"; WG_PORT="${WG_PORT:-51820}"; VPN_SUBNET="${VPN_SUBNET:-10.8.0.0/24}"
XRAY_PORT="${XRAY_PORT:-8443}"; REALITY_DEST="${REALITY_DEST:-}"
SERVER_ADDR="${VPN_SUBNET%.*}.1/${VPN_SUBNET#*/}"        # 10.8.0.1/24
WAN_IF="${WAN_IF:-$(ip -4 route show default | awk '{print $5; exit}')}"
[ -n "$WAN_IF" ] || { echo "cannot detect WAN interface, set WAN_IF"; exit 1; }
PUBLIC_IP="$(curl -4fsS --max-time 5 https://api.ipify.org || true)"

echo "==> packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard wireguard-tools nftables fail2ban unattended-upgrades curl ca-certificates rsync openssl python3
if ! command -v node >/dev/null || [ "$(node -p 'process.versions.node.split(".")[0]')" -lt 22 ]; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y -qq nodejs
fi

echo "==> WireGuard (wg0, $SERVER_ADDR, udp/$WG_PORT)"
install -d -m 700 /etc/wireguard
if [ ! -f /etc/wireguard/wg0.conf ]; then
  (umask 077
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
  )
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

# Layout: with a DOMAIN the website and VLESS share tcp/443 ("self-steal": Xray owns :443 and passes ordinary visitors to
# Caddy on 127.0.0.1:8444). An already-installed server keeps whatever layout its Xray config has (see move-to-443.sh).
XRAY_DIR=/usr/local/etc/xray
SELF_STEAL=0
if [ -n "${DOMAIN:-}" ]; then
  if [ -f "$XRAY_DIR/config.json" ]; then
    [ "$(python3 -c "import json;print([i['port'] for i in json.load(open('$XRAY_DIR/config.json'))['inbounds'] if i.get('tag')=='vless-in'][0])" 2>/dev/null)" = 443 ] && SELF_STEAL=1
  else
    SELF_STEAL=1
  fi
fi
if [ "$SELF_STEAL" = 1 ]; then XRAY_PORT=443; REALITY_DEST=127.0.0.1:8444; REALITY_SNI="$DOMAIN"; fi

echo "==> firewall (nftables), WAN=$WAN_IF"
sed -e "s#@WAN_IF@#$WAN_IF#g" -e "s#@SSH_PORT@#$SSH_PORT#g" -e "s#@WG_PORT@#$WG_PORT#g" -e "s#@XRAY_PORT@#$XRAY_PORT#g" -e "s#@VPN_SUBNET@#$VPN_SUBNET#g" \
  "$HERE/nftables.conf.tpl" > /etc/nftables.conf
nft -c -f /etc/nftables.conf                       # validate before applying
nft -f /etc/nftables.conf
systemctl enable nftables

if [ -n "${DOMAIN:-}" ]; then
  echo "==> Caddy (HTTPS for $DOMAIN, self-steal layout: $SELF_STEAL)"
  apt-get install -y -qq caddy
  if [ "$SELF_STEAL" = 1 ]; then
    sed "s#@DOMAIN@#$DOMAIN#g" "$HERE/Caddyfile.selfsteal.tpl" > /etc/caddy/Caddyfile
  else
    printf '%s {\n  encode gzip\n  reverse_proxy 127.0.0.1:3000\n}\n' "$DOMAIN" > /etc/caddy/Caddyfile
  fi
  systemctl reload caddy || systemctl restart caddy
fi

echo "==> Xray (VLESS + Reality on tcp/$XRAY_PORT)"
if ! command -v xray >/dev/null; then
  curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o /tmp/xray-install.sh
  bash /tmp/xray-install.sh install
  rm -f /tmp/xray-install.sh
fi
install -d -m 755 "$XRAY_DIR"
if [ ! -f "$XRAY_DIR/reality.pub" ]; then
  # Reality imitates a real TLS 1.3 + h2 site; one with a big certificate chain breaks it (www.microsoft.com sent 8 KB here).
  if [ -z "$REALITY_DEST" ]; then
    REALITY_DEST="$(bash "$HERE/pick-reality-dest.sh" --best 2>/dev/null)" || REALITY_DEST="www.apple.com:443"
    echo "Reality dest picked: $REALITY_DEST"
  fi
  [ "$SELF_STEAL" = 1 ] || REALITY_SNI="${REALITY_DEST%:*}"
  KEYS="$(xray x25519)"
  # Output labels differ between Xray versions ("Public key:" / "Password (PublicKey):").
  R_PRIV="$(printf '%s\n' "$KEYS" | sed -n 's/^PrivateKey: *//p;s/^Private key: *//p' | head -1)"
  R_PUB="$(printf '%s\n' "$KEYS" | sed -n 's/^Password (PublicKey): *//p;s/^PublicKey: *//p;s/^Public key: *//p' | head -1)"
  [ -n "$R_PRIV" ] && [ -n "$R_PUB" ] || { echo "cannot parse 'xray x25519' output" >&2; exit 1; }
  R_SID="$(openssl rand -hex 8)"
  (umask 077
   sed -e "s#@XRAY_PORT@#$XRAY_PORT#g" -e "s#@REALITY_DEST@#$REALITY_DEST#g" -e "s#@REALITY_SNI@#$REALITY_SNI#g" \
       -e "s#@REALITY_PRIVATE_KEY@#$R_PRIV#g" -e "s#@REALITY_SHORT_ID@#$R_SID#g" "$HERE/xray-config.json.tpl" > "$XRAY_DIR/config.json"
   printf '%s' "$R_PUB" > "$XRAY_DIR/reality.pub"; printf '%s' "$R_SID" > "$XRAY_DIR/reality.sid")
  chmod 644 "$XRAY_DIR/reality.pub" "$XRAY_DIR/reality.sid"
fi
xray run -test -c "$XRAY_DIR/config.json" >/dev/null
# The config holds the Reality private key: readable by the xray service user only.
XRAY_USER="$(systemctl show -p User --value xray 2>/dev/null)"; XRAY_USER="${XRAY_USER:-nobody}"
chown "root:$(id -gn "$XRAY_USER")" "$XRAY_DIR/config.json"; chmod 640 "$XRAY_DIR/config.json"
if ! runuser -u "$XRAY_USER" -- test -r "$XRAY_DIR/config.json"; then
  echo "!! $XRAY_USER cannot read the config; falling back to mode 644" >&2; chmod 644 "$XRAY_DIR/config.json"
fi
systemctl enable xray >/dev/null 2>&1; systemctl restart xray

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
chmod -R u=rwX,go=rX /opt/kvn   # readable by the unprivileged 'kvn' user
install -d -m 700 -o kvn -g kvn /var/lib/kvn
install -d -m 755 /etc/kvn
if [ ! -f /etc/kvn/kvn.env ]; then
  (umask 077
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
  )
  chmod 600 /etc/kvn/kvn.env
fi
if ! grep -q '^XRAY_APPLY_MODE=' /etc/kvn/kvn.env; then
  cat >> /etc/kvn/kvn.env <<CONF
XRAY_APPLY_MODE=xray
XRAY_BIN=/usr/local/bin/xray
XRAY_PORT=$XRAY_PORT
XRAY_HOST=${PUBLIC_IP:-$DOMAIN}
XRAY_SNI=${REALITY_SNI:-www.apple.com}
XRAY_SHORT_ID=$(cat "$XRAY_DIR/reality.sid")
XRAY_REALITY_PUBLIC_KEY=$(cat "$XRAY_DIR/reality.pub")
CONF
fi
install -m 644 "$HERE/kvn.service" /etc/systemd/system/kvn.service
systemctl daemon-reload
systemctl enable --now kvn
systemctl restart kvn

echo
echo "Done. Server public key: $(cat /etc/wireguard/server.pub)"
echo "Endpoint in configs:     ${DOMAIN:-$PUBLIC_IP}:$WG_PORT"
echo "VLESS+Reality: tcp/$XRAY_PORT, public key $(cat "$XRAY_DIR/reality.pub"), short id $(cat "$XRAY_DIR/reality.sid")"
echo "Check:  wg show wg0 ; systemctl status kvn xray ; curl -s localhost:3000/api/health"
