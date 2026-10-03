#!/usr/bin/env bash
# Moves VLESS+Reality from tcp/8443 to tcp/443 on an already installed server (self-steal layout):
#   Xray listens on public :443 and uses the local Caddy (127.0.0.1:8444, real certificate for DOMAIN) as Reality "dest";
#   ordinary visitors are passed through to the website, so https://DOMAIN keeps working on the normal port.
# Automatic rollback if the website does not answer on :443 afterwards.
#   usage (root):  bash deploy/move-to-443.sh DOMAIN          e.g. 5-129-219-98.nip.io
# Env (tests): CFG KVN_ENV CADDYFILE NO_RESTART=1
set -uo pipefail
DOMAIN="${1:?usage: $0 DOMAIN}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CFG="${CFG:-/usr/local/etc/xray/config.json}"; KVN_ENV="${KVN_ENV:-/etc/kvn/kvn.env}"; CADDYFILE="${CADDYFILE:-/etc/caddy/Caddyfile}"
[ -n "${NO_RESTART:-}" ] || [ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
case "$DOMAIN" in *[!a-zA-Z0-9.-]*|"") echo "bad domain: $DOMAIN"; exit 2;; esac

BK="$(mktemp -d /root/kvn-move443-XXXXXX 2>/dev/null || mktemp -d)"
cp -p "$CFG" "$BK/xray.json"; cp -p "$KVN_ENV" "$BK/kvn.env"; [ -f "$CADDYFILE" ] && cp -p "$CADDYFILE" "$BK/Caddyfile"
echo "backup: $BK"

rollback() {
  echo "!! rolling back"
  cp -p "$BK/xray.json" "$CFG"; cp -p "$BK/kvn.env" "$KVN_ENV"; [ -f "$BK/Caddyfile" ] && cp -p "$BK/Caddyfile" "$CADDYFILE"
  if [ -z "${NO_RESTART:-}" ]; then systemctl stop xray; systemctl restart caddy; systemctl start xray; systemctl restart kvn; fi
  echo "rolled back to the previous setup (VLESS on 8443, website on 443)."; exit 1
}

# 1. new files
sed "s#@DOMAIN@#$DOMAIN#g" "$HERE/Caddyfile.selfsteal.tpl" > "$CADDYFILE.new"
python3 - "$CFG" "$DOMAIN" <<'PY' || { rm -f "$CADDYFILE.new"; exit 1; }
import json, sys
p, domain = sys.argv[1], sys.argv[2]
c = json.load(open(p))
for i in c['inbounds']:
    if i.get('tag') == 'vless-in':
        i['port'] = 443
        r = i['streamSettings']['realitySettings']; r['dest'] = '127.0.0.1:8444'; r['serverNames'] = [domain]
json.dump(c, open(p, 'w'), indent=2)
PY
mv "$CADDYFILE.new" "$CADDYFILE"
for kv in "XRAY_PORT=443" "XRAY_SNI=$DOMAIN"; do k="${kv%%=*}"
  if grep -q "^$k=" "$KVN_ENV"; then sed -i "s#^$k=.*#$kv#" "$KVN_ENV"; else echo "$kv" >> "$KVN_ENV"; fi; done
echo "files updated: xray port 443, dest 127.0.0.1:8444, serverNames [$DOMAIN]; Caddy on 127.0.0.1:8444"
[ -z "${NO_RESTART:-}" ] || { echo "(NO_RESTART: not restarting)"; exit 0; }

command -v caddy >/dev/null && { caddy validate --config "$CADDYFILE" --adapter caddyfile >/dev/null 2>&1 || { echo "!! Caddyfile invalid"; rollback; }; }
xray run -test -c "$CFG" >/dev/null 2>&1 || { echo "!! xray config invalid"; rollback; }

# 2. switch over (Caddy must release :443 before Xray takes it)
systemctl stop xray
systemctl restart caddy || rollback
systemctl start xray || rollback
systemctl restart kvn

# 3. verify through the public port path: Xray(:443) -> Caddy(:8444) -> API
ok=0
for _ in $(seq 20); do
  [ "$(curl -s -m 5 -o /dev/null -w '%{http_code}' --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/api/health")" = 200 ] && { ok=1; break; }; sleep 2
done
[ "$ok" = 1 ] || { echo "!! website does not answer on :443"; rollback; }
echo "OK: https://$DOMAIN works on :443 through Xray; Reality is on :443 too."
echo "Now: wait ~30s, copy the VLESS link from the website AGAIN (port and sni changed), delete the old entry in Happ and add the new one."
echo "Check:  ss -tlnp | grep -E ':(443|8444) '"
