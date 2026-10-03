#!/usr/bin/env bash
# Verifies the "self-steal" layout used when VLESS+Reality shares public tcp/443 with the website, with REAL Caddy and Xray:
#   Xray :443 (Reality, dest = Caddy 127.0.0.1:8444)  ->  website for ordinary visitors, VLESS for valid clients.
# Needs root, xray (+geoip.dat in XRAY_LOCATION_ASSET), caddy, openssl, curl, python3. Uses ports 80, 443, 3000, 8444, 8099.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export XRAY_LOCATION_ASSET="${XRAY_LOCATION_ASSET:-/usr/local/share/xray}"
T="$(mktemp -d)"; DOMAIN=lab.example; PASS=0; FAIL=0; PIDS=()
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
check() { if [ "$2" = "$3" ]; then ok "$1 ($3)"; else bad "$1 (expected '$3', got '$2')"; fi; }
trap 'kill "${PIDS[@]}" 2>/dev/null' EXIT
for t in xray caddy openssl curl python3; do command -v $t >/dev/null || { echo "missing tool: $t"; exit 2; }; done
ip addr add 93.184.216.34/32 dev lo 2>/dev/null   # the "internet" host

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$T/k" -out "$T/c" -subj "/CN=$DOMAIN" -days 2 >/dev/null 2>&1
cat > "$T/srv.py" <<'PY'
import http.server, socketserver, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = sys.argv[3].encode(); self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    def server_bind(self):  # HTTPServer.server_bind does a reverse-DNS lookup that hangs offline
        socketserver.TCPServer.server_bind(self); self.server_port = self.server_address[1]
S((sys.argv[1], int(sys.argv[2])), H).serve_forever()
PY
python3 "$T/srv.py" 127.0.0.1 3000 '{"ok":true}' & PIDS+=($!)
python3 "$T/srv.py" 93.184.216.34 8099 93.184.216.34 & PIDS+=($!)

# Caddy: the repo's real template, plus a local certificate (no ACME offline)
sed -e "s#@DOMAIN@#$DOMAIN#g" -e "s#bind 127.0.0.1#bind 127.0.0.1\n\ttls $T/c $T/k#" -e 's#^{#{\n\tadmin off#' "$ROOT/deploy/Caddyfile.selfsteal.tpl" > "$T/Caddyfile"
caddy validate --config "$T/Caddyfile" --adapter caddyfile >/dev/null 2>&1 && ok "Caddyfile.selfsteal.tpl is valid for Caddy" || bad "Caddyfile invalid"
caddy run --config "$T/Caddyfile" --adapter caddyfile > "$T/caddy.log" 2>&1 & PIDS+=($!)

KEYS="$(xray x25519)"; PRIV="$(echo "$KEYS" | sed -n 's/^PrivateKey: *//p')"; PUB="$(echo "$KEYS" | sed -n 's/^Password (PublicKey): *//p')"
sed -e 's#@XRAY_PORT@#443#g' -e 's#@REALITY_DEST@#127.0.0.1:8444#g' -e "s#@REALITY_SNI@#$DOMAIN#g" -e "s#@REALITY_PRIVATE_KEY@#$PRIV#g" -e 's#@REALITY_SHORT_ID@#0123456789abcdef#g' \
  "$ROOT/deploy/xray-config.json.tpl" > "$T/xray.json"
xray run -c "$T/xray.json" > "$T/xray.log" 2>&1 & PIDS+=($!)
sleep 3
echo '{"inbounds":[{"tag":"vless-in","port":443,"protocol":"vless","settings":{"decryption":"none","clients":[{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","email":"t@kvn","flow":"xtls-rprx-vision"}]}}]}' > "$T/u.json"
xray api adu --server=127.0.0.1:10085 "$T/u.json" | grep -q "Added 1" && ok "user added to the running Xray" || bad "adu failed"

H() { curl -sk --noproxy '*' -m 8 --resolve "$DOMAIN:443:127.0.0.1" "$@"; }
check "ordinary visitor gets the website through :443 (Xray -> Caddy -> API)" "$(H "https://$DOMAIN/api/health")" '{"ok":true}'
check "...over HTTP/2" "$(H -o /dev/null -w '%{http_version}' --http2 "https://$DOMAIN/")" "2"
check "HTTP redirects to the real public HTTPS port (no :8444 leak)" "$(curl -s --noproxy '*' -m 5 -o /dev/null -w '%{redirect_url}' -H "Host: $DOMAIN" http://127.0.0.1/)" "https://$DOMAIN/"

client() { # $1=shortId  $2=socks port
  python3 - "$PUB" "$1" "$2" "$T/cl$2.json" "$DOMAIN" <<'PY'
import json, sys
json.dump({"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":int(sys.argv[3]),"protocol":"socks","settings":{"udp":False}}],
"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":443,"users":[{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","encryption":"none","flow":"xtls-rprx-vision"}]}]},
"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":sys.argv[5],"fingerprint":"ios","publicKey":sys.argv[1],"shortId":sys.argv[2]}}}]}, open(sys.argv[4],'w'))
PY
  xray run -c "$T/cl$2.json" >/dev/null 2>&1 & PIDS+=($!); sleep 1.5
}
client 0123456789abcdef 10896
check "valid VLESS client works on the SAME port 443" "$(env -u no_proxy -u NO_PROXY curl -s -m 8 --socks5-hostname 127.0.0.1:10896 http://93.184.216.34:8099/)" "93.184.216.34"
client ffffffffffffffff 10895
check "client with a wrong shortId gets nothing" "$(env -u no_proxy -u NO_PROXY curl -s -m 6 --socks5-hostname 127.0.0.1:10895 http://93.184.216.34:8099/)" ""
echo; echo "RESULT: $PASS passed, $FAIL failed"; [ "$FAIL" = 0 ]
