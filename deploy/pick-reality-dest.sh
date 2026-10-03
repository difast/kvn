#!/usr/bin/env bash
# Checks candidate "dest" sites for Reality FROM THIS SERVER: must speak TLS 1.3 + h2 and send a SMALL certificate chain.
# A large chain (e.g. www.microsoft.com sent an 8273-byte Certificate message) makes Reality fail with
# "handshake did not complete successfully".
#   bash deploy/pick-reality-dest.sh                 # table of candidates
#   bash deploy/pick-reality-dest.sh --best          # print only the best host:443 (used by setup-vps.sh)
#   bash deploy/pick-reality-dest.sh --apply HOST    # switch this server to HOST (edits xray + kvn config, restarts)
# Env: CANDIDATES="host[:port] ..."  CFG=/usr/local/etc/xray/config.json  KVN_ENV=/etc/kvn/kvn.env  NO_RESTART=1
set -uo pipefail
CFG="${CFG:-/usr/local/etc/xray/config.json}"; KVN_ENV="${KVN_ENV:-/etc/kvn/kvn.env}"
CANDIDATES="${CANDIDATES:-www.apple.com www.cloudflare.com dl.google.com addons.mozilla.org www.amazon.com www.samsung.com www.nvidia.com www.oracle.com gateway.icloud.com www.microsoft.com}"
MAX_CHAIN=5000   # bytes of DER certificates we accept (microsoft's 8273 failed)

probe() { # prints: tls alpn chain_bytes   (empty chain = unreachable)
  local host="${1%%:*}" port="${1##*:}"; [ "$port" = "$1" ] && port=443
  local out; out="$(timeout 8 openssl s_client -connect "$host:$port" -servername "$host" -tls1_3 -alpn h2 -showcerts </dev/null 2>/dev/null)" || true
  local tls alpn chain
  tls="$(printf '%s\n' "$out" | sed -n 's/^ *Protocol *: *//p;s/^New, *\(TLSv[0-9.]*\).*/\1/p' | head -1)"
  alpn="$(printf '%s\n' "$out" | sed -n 's/^ALPN protocol: *//p' | head -1)"
  chain="$(printf '%s\n' "$out" | awk '/BEGIN CERTIFICATE/{f=1;next}/END CERTIFICATE/{f=0;next}f{n+=length($0)}END{print int(n*3/4)}')"
  echo "${tls:-?} ${alpn:-none} ${chain:-0}"
}

if [ "${1:-}" = "--apply" ]; then
  HOST="${2:?usage: --apply HOST}"; HOST="${HOST%%:*}"
  [ "$(id -u)" = 0 ] || [ -n "${NO_RESTART:-}" ] || { echo "run as root"; exit 1; }
  python3 - "$CFG" "$HOST" <<'PY'
import json, sys
p, host = sys.argv[1], sys.argv[2]
c = json.load(open(p))
for i in c['inbounds']:
    if i.get('tag') == 'vless-in':
        r = i['streamSettings']['realitySettings']; r['dest'] = f'{host}:443'; r['serverNames'] = [host]
json.dump(c, open(p, 'w'), indent=2)
print(f'xray config: dest={host}:443, serverNames=[{host}]')
PY
  if grep -q '^XRAY_SNI=' "$KVN_ENV"; then sed -i "s#^XRAY_SNI=.*#XRAY_SNI=$HOST#" "$KVN_ENV"; else echo "XRAY_SNI=$HOST" >> "$KVN_ENV"; fi
  echo "kvn.env: XRAY_SNI=$HOST"
  if [ -z "${NO_RESTART:-}" ]; then systemctl restart xray kvn; echo "restarted xray and kvn. Copy the VLESS link from the website AGAIN (the SNI changed) and re-import it."; fi
  exit 0
fi

BEST=""; BESTSZ=999999
[ "${1:-}" = "--best" ] || printf '%-26s %-8s %-6s %-12s %s\n' HOST TLS ALPN CHAIN-BYTES VERDICT
for c in $CANDIDATES; do
  read -r tls alpn chain < <(probe "$c")
  verdict="no"; [ "$tls" = "TLSv1.3" ] && [ "$alpn" = "h2" ] && [ "$chain" -gt 0 ] && [ "$chain" -le "$MAX_CHAIN" ] && verdict="OK"
  [ "${1:-}" = "--best" ] || printf '%-26s %-8s %-6s %-12s %s\n' "$c" "$tls" "$alpn" "$chain" "$verdict"
  if [ "$verdict" = OK ] && [ "$chain" -lt "$BESTSZ" ]; then BEST="$c"; BESTSZ="$chain"; fi
done
if [ "${1:-}" = "--best" ]; then [ -n "$BEST" ] && echo "${BEST%%:*}:443"; [ -n "$BEST" ]; exit $?; fi
echo; if [ -n "$BEST" ]; then echo "Best: $BEST (chain $BESTSZ bytes). Apply with:  bash deploy/pick-reality-dest.sh --apply ${BEST%%:*}"
else echo "No suitable candidate. Try other hosts via CANDIDATES=\"...\"."; fi
