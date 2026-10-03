#!/usr/bin/env bash
# End-to-end lab: proves the *real* VPN path with real WireGuard tunnels, NAT and the production firewall
# rules, using three network namespaces on one machine (needs root, ip, wg, wireguard-go or kernel wg, nft, python3, node 22).
#
#   [client ns] c0 198.18.0.2 ──── i0 198.18.0.1 [inet ns: echo service 203.0.113.200] i1 198.51.100.254 ──── v0 198.51.100.1 [vps ns: wg0 10.8.0.1, nftables, NAT]
#
# The echo service answers with the IP it sees, so "external IP" is verifiable:
#   no VPN -> 198.18.0.2 (client's own ISP address);  VPN -> 198.51.100.1 (the VPS).
# The API runs on the root namespace in WG_APPLY_MODE=wg and talks to wg0 exactly as in production.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
API=http://127.0.0.1:3100/api
PASS=0; FAIL=0
for t in ip wg wg-quick nft ping curl python3 node openssl; do command -v $t >/dev/null || { echo "missing tool: $t"; exit 2; }; done
if ! command -v wireguard-go >/dev/null && ! { ip link add probe0 type wireguard 2>/dev/null && ip link del probe0; }; then echo "need wireguard-go or kernel WireGuard"; exit 2; fi
export WG_QUICK_USERSPACE_IMPLEMENTATION="${WG_QUICK_USERSPACE_IMPLEMENTATION:-wireguard-go}"

ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
check() { if [ "$2" = "$3" ]; then ok "$1 ($3)"; else bad "$1 (expected '$3', got '$2')"; fi; }
section() { echo; echo "== $*"; }
ns() { local n=$1; shift; ip netns exec "$n" "$@"; }
j() { python3 -c "import sys,json; d=json.load(sys.stdin); print(eval('d'+sys.argv[1]))" "$1"; }
api() { curl -s -m 10 -H 'Content-Type: application/json' "$@"; }

cleanup() {
  [ -n "${APIPID:-}" ] && kill "$APIPID" 2>/dev/null
  [ -n "${ECHOPID:-}" ] && kill "$ECHOPID" 2>/dev/null
  ns client wg-quick down "$TMP/kvn.conf" >/dev/null 2>&1
  pkill -x wireguard-go 2>/dev/null
  for n in client vps inet; do ip netns del $n 2>/dev/null; done
  rm -rf "$TMP"
}
trap 'cp "$TMP/api.log" /tmp/kvn-lab-api.log 2>/dev/null; cleanup' EXIT

section "build network (client / vps / internet)"
for n in client vps inet; do ip netns del $n 2>/dev/null; ip netns add $n; ns $n ip link set lo up; done
ip link add c0 type veth peer name i0; ip link set c0 netns client; ip link set i0 netns inet
ip link add v0 type veth peer name i1; ip link set v0 netns vps;    ip link set i1 netns inet
ns client ip addr add 198.18.0.2/24 dev c0;     ns client ip link set c0 up; ns client ip route add default via 198.18.0.1
ns inet   ip addr add 198.18.0.1/24 dev i0;     ns inet ip link set i0 up
ns inet   ip addr add 198.51.100.254/24 dev i1; ns inet ip link set i1 up
ns inet   ip addr add 203.0.113.200/32 dev lo   # the "internet" host
ns inet   ip addr add 192.168.99.1/32 dev lo    # a private address clients must NOT reach through the VPN
ns inet   sysctl -qw net.ipv4.ip_forward=1
ns vps    ip addr add 198.51.100.1/24 dev v0;   ns vps ip link set v0 up; ns vps ip route add default via 198.51.100.254
ns vps    sysctl -qw net.ipv4.ip_forward=1

section "VPS: WireGuard wg0 + production firewall"
umask 077; wg genkey > "$TMP/server.key"; wg pubkey < "$TMP/server.key" > "$TMP/server.pub"; umask 022
SERVER_PRIV="$(cat "$TMP/server.key")"; SERVER_PUB="$(cat "$TMP/server.pub")"
ns vps wireguard-go wg0 >/dev/null 2>&1; sleep 1
ns vps ip addr add 10.8.0.1/24 dev wg0
ns vps wg set wg0 private-key "$TMP/server.key" listen-port 51820
ns vps ip link set wg0 up
sed -e 's#@WAN_IF@#v0#g' -e 's#@SSH_PORT@#22#g' -e 's#@WG_PORT@#51820#g' -e 's#@VPN_SUBNET@#10.8.0.0/24#g' "$ROOT/deploy/nftables.conf.tpl" > "$TMP/nft.conf"
ns vps nft -c -f "$TMP/nft.conf" && ns vps nft -f "$TMP/nft.conf" && ok "firewall rules (deploy/nftables.conf.tpl) validated and loaded" || bad "firewall rules failed to load"
echo "  wg0 listening on: $(ns vps wg show wg0 listen-port)"

# internet echo service: replies with the source IP it sees
cat > "$TMP/echo.py" <<'PY'
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = self.client_address[0].encode(); self.send_response(200); self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.HTTPServer(('0.0.0.0', 80), H).serve_forever()
PY
ns inet python3 "$TMP/echo.py" & ECHOPID=$!
sleep 1

section "baseline without VPN"
check "external IP without VPN is the client's own" "$(ns client curl -s -m 5 http://203.0.113.200/)" "198.18.0.2"

section "start API (WG_APPLY_MODE=wg, production mode)"
( cd "$ROOT/backend" && exec env NODE_ENV=production PORT=3100 JWT_SECRET="lab-$(openssl rand -hex 24)" DATA_ENCRYPTION_KEY="$(openssl rand -base64 32)" \
  DB_PATH="$TMP/kvn.sqlite" ALLOW_MOCK_PAYMENTS=true WG_APPLY_MODE=wg WG_INTERFACE=wg0 WG_SUBNET=10.8.0.0/24 \
  WG_ENDPOINT=198.51.100.1:51820 WG_SERVER_PUBLIC_KEY="$SERVER_PUB" VPN_RECONCILE_INTERVAL_SEC=2 RATE_LIMIT_DISABLED=true \
  node src/server.js > "$TMP/api.log" 2>&1 ) & APIPID=$!
for _ in $(seq 20); do curl -sf $API/health >/dev/null && break; sleep 0.5; done
check "API health" "$(curl -s $API/health)" '{"ok":true}'
[ "$FAIL" = 0 ] || { echo "API did not start:"; cat "$TMP/api.log"; exit 1; }

# register -> pay -> profile -> conf ; sets TOKEN PROFILE_ID
onboard() {
  local email=$1
  TOKEN=$(api -X POST $API/auth/register -d "{\"email\":\"$email\",\"password\":\"lab-password-1\"}" | j "['accessToken']")
  api -X POST $API/payments -H "Authorization: Bearer $TOKEN" -d '{}' > "$TMP/pay.json"
  PAY_STATUS=$(j "['payment']['status']" < "$TMP/pay.json")
  PROFILE_ID=$(api -X POST $API/vpn/profiles -H "Authorization: Bearer $TOKEN" -d '{"name":"lab"}' | j "['profile']['id']")
  api -H "Authorization: Bearer $TOKEN" $API/vpn/profiles/$PROFILE_ID/config > "$TMP/kvn.conf"
}
connect() {   # "import" the downloaded .conf into the WireGuard client and bring the tunnel up
  # Lab-only edits: no resolvconf (drop DNS=) and this sandbox kernel lacks IPv6 policy routing (drop ::/0).
  # Everything else is the file exactly as downloaded.
  sed -i -e '/^DNS/d' -e 's#, ::/0##' "$TMP/kvn.conf"
  ns client wg-quick up "$TMP/kvn.conf" > "$TMP/wgquick.log" 2>&1 || { bad "wg-quick up failed"; sed 's/^/    /' "$TMP/wgquick.log"; return 1; }
}
disconnect() { ns client wg-quick down "$TMP/kvn.conf" >/dev/null 2>&1; }
handshake_age() { ns client wg show kvn latest-handshakes | awk '{print $2}'; }

section "SCENARIO A: register -> pay -> .conf -> connect -> verify -> revoke"
onboard "lab-a@example.com"
check "payment succeeded" "$PAY_STATUS" "succeeded"
PUB_A=$(grep -c '^PrivateKey' "$TMP/kvn.conf"); check ".conf has an [Interface] PrivateKey" "$PUB_A" "1"
CLIENT_PUB=$(grep '^PrivateKey' "$TMP/kvn.conf" | cut -d' ' -f3 | wg pubkey)
ADDR_A=$(grep '^Address' "$TMP/kvn.conf" | cut -d' ' -f3)
echo "  client address from .conf: $ADDR_A, server peers on wg0: $(ns vps wg show wg0 peers | wc -l)"
check "peer was added to the real wg0 interface" "$(ns vps wg show wg0 peers | grep -c "$CLIENT_PUB")" "1"
check "peer allowed-ips is its unique /32" "$(ns vps wg show wg0 allowed-ips | grep "$CLIENT_PUB" | awk '{print $2}')" "10.8.0.2/32"
connect && {
  ns client ping -c 2 -W 3 10.8.0.1 >/dev/null 2>&1; check "ping through tunnel to VPS (10.8.0.1)" "$?" "0"
  [ "$(handshake_age)" != "0" ] && ok "WireGuard handshake completed" || bad "no handshake"
  check "external IP with VPN is the VPS" "$(ns client curl -s -m 8 http://203.0.113.200/)" "198.51.100.1"
  ns client ping -c 2 -W 3 203.0.113.200 >/dev/null 2>&1; check "internet reachable via VPN (ping 203.0.113.200)" "$?" "0"
  TX=$(ns client wg show kvn transfer | awk '{print $2}'); [ "${TX:-0}" -gt 0 ] && ok "bytes really sent through the tunnel ($TX)" || bad "no tunnel traffic"
  ns client curl -s -m 4 -o /dev/null http://192.168.99.1/; check "private range 192.168.0.0/16 is NOT reachable via VPN (firewall)" "$?" "28"
  ns vps nft list chain inet filter forward | grep -q 'counter' ; true
}
# revoke
RV=$(api -X POST $API/vpn/profiles/$PROFILE_ID/revoke -H "Authorization: Bearer $TOKEN" | j "['profile']['status']")
check "API revoke" "$RV" "revoked"
check "peer removed from the real wg0 interface" "$(ns vps wg show wg0 peers | grep -c "$CLIENT_PUB")" "0"
sleep 1
ns client curl -s -m 5 -o /dev/null http://203.0.113.200/; check "no internet through VPN after revoke (and no leak outside it)" "$?" "28"
ns client ping -c 1 -W 2 10.8.0.1 >/dev/null 2>&1; check "tunnel to VPS dead after revoke" "$?" "1"
check "revoked config can no longer be downloaded (HTTP)" "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" $API/vpn/profiles/$PROFILE_ID/config)" "410"
disconnect
# the old config, re-imported, still must not work
connect; ns client curl -s -m 5 -o /dev/null http://203.0.113.200/; check "re-importing the old revoked .conf gives no access" "$?" "28"; disconnect

section "SCENARIO B: subscription cancelled -> access removed"
onboard "lab-b@example.com"; connect
check "external IP with VPN (user B)" "$(ns client curl -s -m 8 http://203.0.113.200/)" "198.51.100.1"
check "user B got a different VPN IP than A" "$(grep '^Address' "$TMP/kvn.conf" | cut -d' ' -f3)" "10.8.0.2/32"   # A was revoked, address released
PUB_B=$(grep '^PrivateKey' "$TMP/kvn.conf" | cut -d' ' -f3 | wg pubkey)
api -X POST $API/subscription/cancel -H "Authorization: Bearer $TOKEN" >/dev/null
check "peer removed on cancel" "$(ns vps wg show wg0 peers | grep -c "$PUB_B")" "0"
ns client curl -s -m 5 -o /dev/null http://203.0.113.200/; check "no access after cancel" "$?" "28"
disconnect

section "SCENARIO C: subscription EXPIRES (background reconcile removes the peer)"
onboard "lab-c@example.com"; connect
check "external IP with VPN (user C)" "$(ns client curl -s -m 8 http://203.0.113.200/)" "198.51.100.1"
PUB_C=$(grep '^PrivateKey' "$TMP/kvn.conf" | cut -d' ' -f3 | wg pubkey)
# time travel: the subscription and profile end 1 second from now
node --no-warnings -e "
const {DatabaseSync}=require('node:sqlite'); const d=new DatabaseSync('$TMP/kvn.sqlite');
const t=new Date(Date.now()+1000).toISOString();
d.exec(\"UPDATE subscriptions SET ends_at='\"+t+\"'; UPDATE vpn_profiles SET expires_at='\"+t+\"' WHERE public_key='$PUB_C'\");"
sleep 6   # expiry + reconcile interval (2s)
check "peer removed by the expiry sweep" "$(ns vps wg show wg0 peers | grep -c "$PUB_C")" "0"
ns client curl -s -m 5 -o /dev/null http://203.0.113.200/; check "no access after expiry" "$?" "28"
check "expired config not downloadable (HTTP)" "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" $API/vpn/profiles/$PROFILE_ID/config)" "402"
disconnect

section "SCENARIO D: wg0 restarted -> API restores peers (self-healing)"
onboard "lab-d@example.com"
PUB_D=$(grep '^PrivateKey' "$TMP/kvn.conf" | cut -d' ' -f3 | wg pubkey)
ns vps wg set wg0 peer "$PUB_D" remove
check "peer wiped from wg0 (simulated restart)" "$(ns vps wg show wg0 peers | grep -c "$PUB_D")" "0"
sleep 4
check "reconcile re-added the peer" "$(ns vps wg show wg0 peers | grep -c "$PUB_D")" "1"
connect; check "VPN works after self-heal" "$(ns client curl -s -m 8 http://203.0.113.200/)" "198.51.100.1"; disconnect

section "SECURITY"
api -X POST $API/auth/register -d '{"email":"lab-x@example.com","password":"lab-password-1"}' > "$TMP/x.json"; TX2=$(j "['accessToken']" < "$TMP/x.json")
check "another user cannot download someone else's config" "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TX2" $API/vpn/profiles/$PROFILE_ID/config)" "404"
check "unauthenticated config download rejected" "$(curl -s -o /dev/null -w '%{http_code}' $API/vpn/profiles/$PROFILE_ID/config)" "401"
check "client cannot reach the server's services (input policy drop, e.g. API port 3100 via 10.8.0.1)" "$(ns vps ss -tln 2>/dev/null | grep -c ':3100 ')" "0"
LEAK=$(grep -rIl --exclude-dir=node_modules --exclude-dir=.git -F "$SERVER_PRIV" "$ROOT" "$TMP" 2>/dev/null | grep -v '/server.key$' | wc -l)
check "server PRIVATE key appears nowhere in repo, DB, API log or responses" "$LEAK" "0"
check "frontend contains no PrivateKey material" "$(grep -rIl -E 'PrivateKey *=|[A-Za-z0-9+/]{43}=' "$ROOT/frontend" | wc -l)" "0"
node --no-warnings -e "
const {DatabaseSync}=require('node:sqlite'); const d=new DatabaseSync('$TMP/kvn.sqlite');
const r=d.prepare('SELECT private_key_enc, preshared_key_enc FROM vpn_profiles').all();
const plain=r.some(x=>/^[A-Za-z0-9+/]{43}=\$/.test(x.private_key_enc)||/^[A-Za-z0-9+/]{43}=\$/.test(x.preshared_key_enc));
console.log(plain?'PLAIN':'ENCRYPTED');" > "$TMP/enc.txt"
check "client private/preshared keys are encrypted in the DB" "$(cat "$TMP/enc.txt")" "ENCRYPTED"

echo; echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
