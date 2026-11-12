#!/bin/bash
# Build release assets without installing or changing the running firewall.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
VERSION="${1:-2.0.0}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Usage: ./build.sh [2.0.0]' >&2; exit 1; }
[ "$(uname -s)" = Darwin ] || { echo 'Build ClaudeGuard on macOS.' >&2; exit 1; }
for tool in xcrun pkgbuild productbuild codesign iconutil sips; do
    command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 1; }
done
/usr/bin/python3 -I -c 'import sys; assert sys.version_info >= (3, 9)' || {
    echo 'Install Xcode Command Line Tools first: xcode-select --install' >&2; exit 1;
}
WORK="$(mktemp -d "${TMPDIR:-/tmp}/claudeguard-pkg.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
SDK="$(xcrun --show-sdk-path)"
PAYLOAD="$WORK/root"
APP="$PAYLOAD/Applications/ClaudeGuard.app"
HELPER="$PAYLOAD/Library/Application Support/ClaudeGuard"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$HELPER/Runtime/bin" "$WORK/modules"
for arch in arm64 x86_64; do
    bash "$ROOT/scripts/fetch-proxy-engine.sh" "$WORK/engine-$arch" "$arch"
    echo "Building $arch (macOS 14+)…"
    xcrun clang -O2 -Wall -Wextra -Werror -isysroot "$SDK" -target "$arch-apple-macos14.0" \
        "$ROOT/src/hosts_helper.c" -o "$WORK/hosts-helper-$arch"
    xcrun clang -O2 -Wall -Wextra -Werror -isysroot "$SDK" -target "$arch-apple-macos14.0" \
        "$ROOT/src/pf_anchor.c" -o "$WORK/pf-anchor-$arch"
    xcrun swiftc -O -sdk "$SDK" -target "$arch-apple-macos14.0" -module-cache-path "$WORK/modules" \
        "$ROOT/src/main.swift" "$ROOT/src/ModeSegmentedControl.swift" -o "$WORK/ClaudeGuardMenuBar-$arch"
done
for name in hosts-helper pf-anchor ClaudeGuardMenuBar; do
    xcrun lipo -create "$WORK/$name-arm64" "$WORK/$name-x86_64" -output "$WORK/$name"
done
cp "$WORK/ClaudeGuardMenuBar" "$APP/Contents/MacOS/"
cp "$WORK/engine-arm64/PROXY-ENGINE-NOTICE.txt" "$HELPER/"
xcrun lipo -create "$WORK/engine-arm64/sing-box" "$WORK/engine-x86_64/sing-box" -output "$HELPER/sing-box"
cp "$ROOT/src/proxy_config.py" "$ROOT/src/proxy_service.py" "$ROOT/src/trace_timing.py" "$HELPER/"
cp "$WORK/hosts-helper" "$WORK/pf-anchor" "$ROOT/src/pf_controller.py" "$HELPER/"
/usr/bin/rsync -a --exclude '__pycache__' --exclude '*.pyc' --exclude '.DS_Store' "$ROOT/src/" "$HELPER/Runtime/src/"
cp "$ROOT/bin/claudeguard" "$HELPER/Runtime/bin/"
cp "$ROOT/uninstall.sh" "$ROOT/packaging/setup_user.py" "$HELPER/Runtime/"
cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$HELPER/"
cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$HELPER/Runtime/"
cp "$ROOT/src/vendor/SING_BOX_LICENSE" "$HELPER/SING_BOX_LICENSE"
mkdir -p "$WORK/AppIcon.iconset"
for pair in '16:icon_16x16' '32:icon_16x16@2x' '32:icon_32x32' '64:icon_32x32@2x' \
    '128:icon_128x128' '256:icon_128x128@2x' '256:icon_256x256' '512:icon_256x256@2x' \
    '512:icon_512x512' '1024:icon_512x512@2x'; do
    sips -z "${pair%%:*}" "${pair%%:*}" "$ROOT/assets/AppIcon.png" \
        --out "$WORK/AppIcon.iconset/${pair#*:}.png" >/dev/null
done
iconutil -c icns "$WORK/AppIcon.iconset" -o "$APP/Contents/Resources/AppIcon.icns"
/usr/bin/python3 - "$APP" "$VERSION" "$WORK/components.plist" <<'PY'
import plistlib, sys
from pathlib import Path
app, version, components = sys.argv[1:]
with (Path(app) / 'Contents/Info.plist').open('wb') as f:
    plistlib.dump(dict(CFBundleExecutable='ClaudeGuardMenuBar', CFBundleIconFile='AppIcon',
        CFBundleIdentifier='com.claudeguard.app', CFBundleName='ClaudeGuard',
        CFBundlePackageType='APPL', CFBundleShortVersionString=version,
        CFBundleVersion=version, LSMinimumSystemVersion='14.0', LSUIElement=True), f)
with open(components, 'wb') as f:
    plistlib.dump([dict(RootRelativeBundlePath='Applications/ClaudeGuard.app',
        BundleIsRelocatable=False, BundleIsVersionChecked=True,
        BundleHasStrictIdentifier=True, BundleOverwriteAction='upgrade')], f)
PY
find "$PAYLOAD" -type d -exec chmod 755 {} +
find "$PAYLOAD" -type f -exec chmod 644 {} +
chmod 755 "$HELPER/sing-box" "$APP/Contents/MacOS/ClaudeGuardMenuBar" "$HELPER/hosts-helper" "$HELPER/pf-anchor" \
    "$HELPER/Runtime/bin/claudeguard" "$HELPER/Runtime/uninstall.sh" \
    "$HELPER/Runtime/src/cli_wrapper.py" "$HELPER/Runtime/src/app_launcher.py" "$HELPER/Runtime/src/helper.py"
IDENTITY="${CLAUDEGUARD_APP_SIGN_IDENTITY:--}"
for binary in "$HELPER/sing-box" "$HELPER/hosts-helper" "$HELPER/pf-anchor" "$APP"; do
    codesign --force --options runtime --sign "$IDENTITY" "$binary"
done
mkdir "$WORK/scripts"
for script in preinstall postinstall configure.py; do
    cp "$ROOT/packaging/scripts/$script" "$WORK/scripts/"
done
chmod 755 "$WORK/scripts/preinstall" "$WORK/scripts/postinstall"
pkgbuild --root "$PAYLOAD" --component-plist "$WORK/components.plist" \
    --scripts "$WORK/scripts" --identifier com.claudeguard.installer \
    --version "$VERSION" --install-location / --ownership recommended "$WORK/component.pkg"
cat > "$WORK/Distribution.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>ClaudeGuard $VERSION</title>
  <options customize="never" require-scripts="true" hostArchitectures="arm64,x86_64"/>
  <domains enable_localSystem="true" enable_currentUserHome="false" enable_anywhere="false"/>
  <allowed-os-versions><os-version min="14.0"/></allowed-os-versions>
  <welcome file="Welcome.html" mime-type="text/html"/>
  <conclusion file="Conclusion.html" mime-type="text/html"/>
  <choices-outline><line choice="default"/></choices-outline>
  <choice id="default" visible="false"><pkg-ref id="com.claudeguard.installer"/></choice>
  <pkg-ref id="com.claudeguard.installer" version="$VERSION" onConclusion="none">component.pkg</pkg-ref>
</installer-gui-script>
EOF
OUTPUT="$ROOT/ClaudeGuard.pkg"
set -- productbuild --distribution "$WORK/Distribution.xml" --resources "$ROOT/packaging/resources" \
    --package-path "$WORK"
if [ -n "${CLAUDEGUARD_INSTALLER_SIGN_IDENTITY:-}" ]; then
    set -- "$@" --sign "$CLAUDEGUARD_INSTALLER_SIGN_IDENTITY"
fi
"$@" "$WORK/ClaudeGuard.pkg"
# Replace an older build only once the new package has completed successfully.
mv -f "$WORK/ClaudeGuard.pkg" "$OUTPUT"
echo "Built $OUTPUT"
