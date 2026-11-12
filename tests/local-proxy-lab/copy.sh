#!/bin/bash
set -euo pipefail
BASE="$(cd "$(dirname "$0")" && pwd)"
NAME="${1:-}"
case "$NAME" in http|https|socks4|socks4a|socks5|shadowsocks|vmess|vless|trojan|hysteria2|tuic|vless-tls) ;;
*) echo 'Specify a profile name, e.g. socks5'; exit 2;; esac
/usr/bin/pbcopy < "$BASE/profiles/$NAME.json"
echo "Profile copied. Paste into Configure Proxy."
