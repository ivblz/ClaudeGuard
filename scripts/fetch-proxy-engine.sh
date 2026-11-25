#!/bin/bash
set -euo pipefail
DEST="${1:?output directory}"; ARCH="${2:-$(uname -m)}"
case "$ARCH" in
 arm64) SUM=0d8c7f5ed5d587b0f1a5e9772a708ec3bfa4ac4c9329604b01d8d9c2ba406838;;
 x86_64|amd64) ARCH=amd64; SUM=eae86b9b033bba50b7c44ab719e4bfac0aca05efd28483390ed3aa510f32db25;;
 *) exit 2;;
esac
mkdir -p "$DEST"
WORK=$(mktemp -d)
STAGED=''
trap 'rm -rf "$WORK"; [ -z "$STAGED" ] || rm -f "$STAGED"' EXIT
NAME="sing-box-1.14.4-darwin-$ARCH"
curl --fail --location --proto '=https' --tlsv1.2 "https://github.com/SagerNet/sing-box/releases/download/v1.14.4/$NAME.tar.gz" -o "$WORK/engine.tar.gz"
printf '%s  %s\n' "$SUM" "$WORK/engine.tar.gz" | shasum -a 256 -c -
tar -xzf "$WORK/engine.tar.gz" -C "$WORK"
# Never overwrite an executed Mach-O inode (macOS caches its code signature).
STAGED=$(mktemp "$DEST/.sing-box.XXXXXX")
cp "$WORK/$NAME/sing-box" "$STAGED"
chmod 755 "$STAGED"
mv -f "$STAGED" "$DEST/sing-box"
STAGED=''
codesign --force --sign - "$DEST/sing-box"
codesign --verify --strict "$DEST/sing-box"
case "$ARCH:$(uname -m)" in
 arm64:arm64|amd64:x86_64) "$DEST/sing-box" version >/dev/null;;
esac

cat > "$DEST/PROXY-ENGINE-NOTICE.txt" <<'NOTICE'
sing-box 1.14.4 — SagerNet / nekohasekai, GPL-3.0-or-later.
Official binaries: https://github.com/SagerNet/sing-box/releases/tag/v1.14.4
Corresponding source: https://github.com/SagerNet/sing-box/tree/v1.14.4
Source archive: https://github.com/SagerNet/sing-box/archive/refs/tags/v1.14.4.tar.gz
License: https://github.com/SagerNet/sing-box/blob/v1.14.4/LICENSE
The upstream license also restricts derivative works from using the name or
implying association with sing-box without prior consent; see SING_BOX_LICENSE.
ClaudeGuard preserves the engine code and applies a local code signature for macOS.
NOTICE
