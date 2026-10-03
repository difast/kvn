#!/usr/bin/env bash
# Temporarily turns on Reality's debug output ("show"), runs the self-test once, prints the Reality log lines,
# then restores the config. Run as root on the VPS:   bash deploy/reality-debug.sh 'vless://...'
set -uo pipefail
LINK="${1:-}"; [ -n "$LINK" ] || { echo "usage: $0 'vless://...'"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
CFG=/usr/local/etc/xray/config.json
BAK="$(mktemp)"; cp -p "$CFG" "$BAK"
trap 'cp -p "$BAK" "$CFG"; rm -f "$BAK"; systemctl restart xray; echo "(config restored, xray restarted; the API re-adds users within ~30s)"' EXIT

python3 - "$CFG" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
for i in c['inbounds']:
    if i.get('tag') == 'vless-in': i['streamSettings']['realitySettings']['show'] = True
json.dump(c, open(sys.argv[1], 'w'), indent=2)
PY
systemctl restart xray
echo "waiting for the API to re-add users into Xray (up to 70s)..."
for _ in $(seq 35); do
  [ "$(xray api inbounduser --server=127.0.0.1:10085 -tag=vless-in 2>/dev/null | grep -c '"email"')" -ge 1 ] && break; sleep 2
done
echo "users in xray: $(xray api inbounduser --server=127.0.0.1:10085 -tag=vless-in 2>/dev/null | grep -c '"email"')"
START="$(date '+%Y-%m-%d %H:%M:%S')"
bash "$HERE/selftest-vless.sh" "$LINK" 2>&1 | grep -E "PASS|FAIL|RESULT" | head -4
echo; echo "===== Reality log (auth keys removed) ====="
journalctl -u xray --since "$START" --no-pager 2>/dev/null | grep -i "reality" | grep -viE "authkey" | cut -c1-330 | head -25
