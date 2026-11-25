#!/usr/bin/env bash

PLIST_PATH="$HOME/Library/LaunchAgents/com.claudeguard.daemon.plist"
SUDOERS_FILE="/etc/sudoers.d/claudeguard"
INSTALL_DIR="$HOME/.local/share/ClaudeGuard"
CONFIG_DIR="$HOME/.config/claudeguard"
# Real claude path recorded at install time (avoids hardcoding a version).
REAL_CLAUDE_TARGET=$(python3 -c "
import json, os
path = os.path.expanduser('~/.config/claudeguard/config.json')
try:
    with open(path) as f:
        print(json.load(f).get('real_claude_cli_path', ''))
except Exception:
    print('')
" 2>/dev/null)

echo "=================================================="
echo " 🛑 Uninstalling ClaudeGuard (Clean Reset)"
echo "=================================================="

# 1. Unload and delete LaunchAgent
echo "--> Unloading LaunchAgent..."
if [ -f "$PLIST_PATH" ]; then
    launchctl unload "$PLIST_PATH" 2>/dev/null || true
fi

# 2. Terminate running background processes
echo "--> Stopping running processes..."
pkill -f "ClaudeGuardMenuBar" 2>/dev/null || true

# 2b. Remove only our PF anchor and enable reference. Never disable global PF.
echo "--> Removing root network helper (LaunchDaemon)..."
HELPER_PLIST="/Library/LaunchDaemons/com.claudeguard.helper.plist"
HELPER_SYS_DIR="/Library/Application Support/ClaudeGuard"
sudo launchctl bootout system "$HELPER_PLIST" 2>/dev/null || sudo launchctl unload "$HELPER_PLIST" 2>/dev/null || true
# Prefer this checkout's backend: this also safely migrates legacy installs
# whose old helper had no scoped cleanup command. A failure must leave the
# backend/token available for retry rather than silently orphan firewall rules.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PF_BACKEND="$SCRIPT_DIR/src/pf_controller.py"
[ -f "$PF_BACKEND" ] || PF_BACKEND="$HELPER_SYS_DIR/pf_controller.py"
if [ ! -f "$PF_BACKEND" ]; then
    echo "Cannot safely clean PF: pf_controller.py is missing. Use a complete ClaudeGuard checkout."
    exit 1
fi
sudo mkdir -p "$HELPER_SYS_DIR" || exit 1
if ! sudo /usr/bin/python3 -I "$PF_BACKEND" --unblock; then
    echo "PF cleanup failed; installation files and token were kept. Resolve the reported error and retry."
    exit 1
fi
# 3. Restore /etc/hosts file
echo "--> Restoring /etc/hosts and DNS settings..."
HOSTS_TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/claudeguard-uninstall.XXXXXX") || exit 1
trap 'rm -rf -- "$HOSTS_TMP_DIR"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if ! python3 - "$HOSTS_TMP_DIR/hosts" <<'PYTHON'
import os, sys
HOSTS_PATH = '/etc/hosts'
with open(HOSTS_PATH, 'r') as f:
    content = f.read()
for header, footer in [
    ('# BEGIN CLAUDEGUARD BLOCKS\n', '# END CLAUDEGUARD BLOCKS\n'),
    ('# BEGIN CLAUDEGUARD UPDATE BLOCKS\n', '# END CLAUDEGUARD UPDATE BLOCKS\n')
]:
    while header in content:
        start = content.index(header)
        end = content.find(footer, start + len(header))
        if end < 0:
            raise ValueError('Unterminated ClaudeGuard hosts block; refusing to rewrite hosts')
        content = content[:start] + content[end + len(footer):]
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as f:
    f.write(content)
PYTHON
then
    echo "Hosts cleanup failed; installation files were kept. Resolve the error and retry." >&2
    exit 1
fi
if ! sudo cp "$HOSTS_TMP_DIR/hosts" /etc/hosts; then
    echo "Cannot restore /etc/hosts; installation files were kept. Resolve the error and retry." >&2
    exit 1
fi
# Flush DNS
dscacheutil -flushcache || { echo "DNS cache flush failed; retry uninstall." >&2; exit 1; }
sudo killall -HUP mDNSResponder || { echo "DNS reload failed; retry uninstall." >&2; exit 1; }
rm -f "$PLIST_PATH" || exit 1
sudo rm -f "$HELPER_PLIST" || exit 1
sudo rm -rf "$HELPER_SYS_DIR" || exit 1

# 4. Unlock auto-update folders
# Globbed: a stale literal bundle id silently unlocks nothing and would leave the
# update dirs frozen forever.
echo "--> Unlocking filesystem auto-update locks..."
for target in "$HOME/Library/Caches/"com.anthropic.claude*.ShipIt \
              "$HOME/Library/Application Support/Claude/app-update.yml"; do
    [ -e "$target" ] || continue
    chflags -R nouchg "$target" 2>/dev/null || true
    if [ -d "$target" ]; then
        chmod -R 755 "$target" 2>/dev/null || true
    else
        chmod 644 "$target" 2>/dev/null || true
    fi
done

# 5. Un-hook 'claude' and restore the real binary
echo "--> Restoring original 'claude' CLI binary..."
rm -f "$HOME/.local/bin/claudeguard"
rm -f "/usr/local/bin/claudeguard" 2>/dev/null || true

# Only shims that are actually ours: a blanket rm would delete a real install
# sitting at the same path (the native installer owns ~/.local/bin/claude).
for link in "$HOME/.local/bin/claude" "/usr/local/bin/claude" "/opt/homebrew/bin/claude"; do
    [ -L "$link" ] || continue
    case "$(python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "$link" 2>/dev/null)" in
        *cli_wrapper.py) rm -f "$link" && echo "    Removed ClaudeGuard shim: $link" ;;
    esac
done

# Put the real binary back where its own installer would have put it.
if [ -n "$REAL_CLAUDE_TARGET" ] && [ -f "$REAL_CLAUDE_TARGET" ]; then
    case "$REAL_CLAUDE_TARGET" in
        /opt/homebrew/*) RESTORE_DIR="/opt/homebrew/bin" ;;
        /usr/local/*)    RESTORE_DIR="/usr/local/bin" ;;
        *)               RESTORE_DIR="$HOME/.local/bin" ;;
    esac
    if [ -e "$RESTORE_DIR/claude" ] || [ -L "$RESTORE_DIR/claude" ]; then
        echo "    Existing claude command left unchanged."
    elif [ ! -d "$RESTORE_DIR" ] || [ ! -w "$RESTORE_DIR" ]; then
        echo "Error: Cannot restore the claude command: destination directory is missing or not writable." >&2
        exit 1
    elif ln -s "$REAL_CLAUDE_TARGET" "$RESTORE_DIR/claude"; then
        echo "    Restored $RESTORE_DIR/claude -> $REAL_CLAUDE_TARGET"
    else
        echo "Error: Could not restore the claude command. Resolve the error and retry uninstall." >&2
        exit 1
    fi
else
    echo "    Saved Claude CLI binary is unavailable; command restoration skipped."
fi

# Remove the shared application and any legacy installer-created user link.
sudo rm -rf "/Applications/ClaudeGuard.app"
if [ -L "$HOME/Applications/ClaudeGuard.app" ]; then
    if [ "$(readlink "$HOME/Applications/ClaudeGuard.app")" = "$INSTALL_DIR/ClaudeGuard.app" ]; then
        rm "$HOME/Applications/ClaudeGuard.app"
    fi
fi

# 6. Remove installed files and configs
echo "--> Cleaning configuration and installation files..."
rm -rf "$INSTALL_DIR"
rm -rf "$CONFIG_DIR"
sudo rm -f "$SUDOERS_FILE" 2>/dev/null || true

echo ""
echo "=================================================="
echo " ✨ ClaudeGuard completely uninstalled!"
echo " System restored to clean state."
echo "=================================================="
