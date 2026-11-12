#!/bin/bash
set -euo pipefail
BASE="$(cd "$(dirname "$0")" && pwd)"
NAME="${1:-}"
if [ -z "$NAME" ]; then
  PS3="Choose proxy number: "
  select NAME in http https socks4 socks4a socks5 shadowsocks vmess vless trojan hysteria2 tuic vless-tls; do
    if [ -n "$NAME" ]; then break; fi
  done
fi
case "$NAME" in http|https|socks4|socks4a|socks5|shadowsocks|vmess|vless|trojan|hysteria2|tuic|vless-tls) ;;
*) echo 'Usage: use.sh http|https|socks4|socks4a|socks5|shadowsocks|vmess|vless|trojan|hysteria2|tuic|vless-tls'; exit 2;; esac
"$HOME/.local/bin/claudeguard" set-proxy < "$BASE/profiles/$NAME.json"
"$HOME/.local/bin/claudeguard" use-proxy
