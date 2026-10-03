#!/usr/bin/env bash
# Runs a real Xray *client* on this machine with the given vless:// link and tries to reach the internet through it.
# It tells you whether the VLESS+Reality server itself works, independent of any phone / mobile network / app.
#   usage: bash deploy/selftest-vless.sh 'vless://UUID@HOST:PORT?...'
# Env: TEST_URL (default https://api.ipify.org), SPEED_URL (default 20 MB from speed.cloudflare.com)
set -uo pipefail
LINK="${1:-}"; [ -n "$LINK" ] || { echo "usage: $0 'vless://...'"; exit 2; }
for t in xray python3 curl; do command -v "$t" >/dev/null || { echo "missing tool: $t"; exit 2; }; done
TEST_URL="${TEST_URL:-https://api.ipify.org}"
SPEED_URL="${SPEED_URL:-https://speed.cloudflare.com/__down?bytes=20000000}"
PORT=10899
TMP="$(mktemp -d)"; XPID=""
trap '[ -n "$XPID" ] && kill "$XPID" 2>/dev/null; rm -rf "$TMP"' EXIT

python3 - "$LINK" "$TMP/client.json" "$PORT" <<'PY' || { echo "FAIL: cannot parse the link"; exit 2; }
import sys, json
from urllib.parse import urlparse, parse_qs
u = urlparse(sys.argv[1].strip()); q = {k: v[0] for k, v in parse_qs(u.query).items()}
assert u.scheme == 'vless' and q.get('security') == 'reality', 'not a vless+reality link'
raw = sys.argv[1]
if '[' in raw or '](' in raw or ' ' in raw.strip() or not all(k in q for k in ('sni', 'fp', 'pbk', 'sid')):
    print("FAIL: the link is corrupted (chat/markdown turned part of it into a [text](url) link or cut it).")
    print("      Copy it again with the 'Copy' button in the website cabinet, not from a chat message.")
    sys.exit(2)
print(f"link: host={u.hostname} port={u.port} sni={q['sni']} fp={q['fp']} flow={q.get('flow')} (uuid hidden)")
json.dump({"log": {"loglevel": "info"},
  "inbounds": [{"listen": "127.0.0.1", "port": int(sys.argv[3]), "protocol": "socks", "settings": {"udp": False}}],
  "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": u.hostname, "port": u.port, "users": [
      {"id": u.username, "encryption": "none", "flow": q.get('flow', '')}]}]},
    "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
      "serverName": q['sni'], "fingerprint": q['fp'], "publicKey": q['pbk'], "shortId": q['sid']}}}]}, open(sys.argv[2], 'w'))
PY

xray run -c "$TMP/client.json" > "$TMP/xray.log" 2>&1 & XPID=$!
sleep 2
if ! kill -0 "$XPID" 2>/dev/null; then echo "FAIL: xray client did not start:"; cat "$TMP/xray.log"; exit 1; fi

via() { env -u no_proxy -u NO_PROXY curl -s --socks5-hostname "127.0.0.1:$PORT" "$@"; }
FAILS=0

echo "== 1. connect + exit IP (should be this server's public IP)"
IP="$(via -m 20 "$TEST_URL")"; RC=$?
if [ $RC -eq 0 ] && [ -n "$IP" ]; then echo "PASS  reached the internet through VLESS, exit address: $IP"; else
  echo "FAIL  no connection through VLESS (curl exit $RC)"; FAILS=$((FAILS+1)); echo "--- client log:"; tail -5 "$TMP/xray.log"; fi

echo "== 2. connection setup time (6 new connections; each one is a full Reality handshake)"
for i in 1 2 3 4 5 6; do
  via -m 15 -o /dev/null -w "   #$i  connect %{time_connect}s  first-byte %{time_starttransfer}s  total %{time_total}s  http %{http_code}\n" "$TEST_URL" || { echo "   #$i  FAILED"; FAILS=$((FAILS+1)); }
done

echo "== 3. download speed through VLESS"
SP="$(via -m 40 -o /dev/null -w '%{speed_download}' "$SPEED_URL")"; RC=$?
if [ $RC -eq 0 ]; then echo "PASS  $(python3 -c "print(f'{float(\"$SP\")*8/1e6:.1f} Mbit/s')")"; else echo "FAIL  download failed (curl exit $RC)"; FAILS=$((FAILS+1)); fi

if [ "$FAILS" != 0 ]; then echo; echo "--- client log (errors):"; grep -iE "fail|error|reality|handshake|timeout|refused|dial" "$TMP/xray.log" | sort | uniq -c | sort -rn | head -6 | cut -c1-300; fi
echo; if [ "$FAILS" = 0 ]; then echo "RESULT: the VLESS server works. If your phone is slow, the cause is the phone's network path or the app, not the server."
else echo "RESULT: $FAILS check(s) failed: the problem is on the server side (see above)."; fi
[ "$FAILS" = 0 ]
