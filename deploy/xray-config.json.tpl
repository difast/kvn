{
  "log": { "loglevel": "warning", "access": "none" },
  "api": { "tag": "api", "services": ["HandlerService", "StatsService"] },
  "inbounds": [
    {
      "tag": "api-in",
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" }
    },
    {
      "tag": "vless-in",
      "listen": "0.0.0.0",
      "port": @XRAY_PORT@,
      "protocol": "vless",
      "settings": { "clients": [], "decryption": "none" },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "@REALITY_DEST@",
          "serverNames": ["@REALITY_SNI@"],
          "privateKey": "@REALITY_PRIVATE_KEY@",
          "shortIds": ["@REALITY_SHORT_ID@"]
        }
      }
    }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "rules": [
      { "type": "field", "inboundTag": ["api-in"], "outboundTag": "api" },
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" }
    ]
  }
}
