#!/usr/sbin/nft -f
# Firewall for the KVN VPS. Placeholders (@...@) are rendered by setup-vps.sh.
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    ct state invalid drop
    iifname "lo" accept

    ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 10/second accept
    meta l4proto ipv6-icmp accept

    # SSH: per-source-IP throttle on new connections (on top of fail2ban).
    tcp dport @SSH_PORT@ ct state new meter ssh4 { ip saddr limit rate 6/minute burst 10 packets } accept
    tcp dport @SSH_PORT@ ct state new meter ssh6 { ip6 saddr limit rate 6/minute burst 10 packets } accept

    udp dport @WG_PORT@ accept      # WireGuard
    tcp dport { 80, 443 } accept    # web + API behind Caddy (HTTPS)
    # Everything else, including WireGuard clients talking to the server itself: dropped.
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    ct state invalid drop
    # Clients may not reach private/link-local ranges (cloud metadata 169.254.169.254, provider LAN).
    iifname "wg0" ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } drop
    # wg0 -> wg0 (client-to-client) is not allowed: there is no rule for it, policy drop applies.
    iifname "wg0" oifname "@WAN_IF@" tcp flags syn tcp option maxseg size set rt mtu
    iifname "wg0" oifname "@WAN_IF@" accept
  }

  chain output { type filter hook output priority 0; policy accept; }
}

table ip nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "@WAN_IF@" ip saddr @VPN_SUBNET@ masquerade
  }
}
