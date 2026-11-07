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
    rm -f "$PLIST_PATH"
    echo "    Removed LaunchAgent: $PLIST_PATH"
fi

# 2. Terminate running background processes
echo "--> Stopping running processes..."
pkill -f "ClaudeGuardMenuBar" 2>/dev/null || true
pkill -f "ClaudeGuard" 2>/dev/null || true

# 2b. Remove the root network-helper LaunchDaemon + its binary, and disable pf
echo "--> Removing root network helper (LaunchDaemon)..."
HELPER_PLIST="/Library/LaunchDaemons/com.claudeguard.helper.plist"
HELPER_SYS_DIR="/Library/Application Support/ClaudeGuard"
sudo launchctl bootout system "$HELPER_PLIST" 2>/dev/null || sudo launchctl unload "$HELPER_PLIST" 2>/dev/null || true
sudo rm -f "$HELPER_PLIST" 2>/dev/null || true
sudo rm -rf "$HELPER_SYS_DIR" 2>/dev/null || true
sudo /sbin/pfctl -d 2>/dev/null || true
sudo /sbin/pfctl -F states 2>/dev/null || true

# 3. Restore /etc/hosts file
echo "--> Restoring /etc/hosts and DNS settings..."
python3 -c "
import os, subprocess
HOSTS_PATH = '/etc/hosts'
if os.path.exists(HOSTS_PATH):
    try:
        with open(HOSTS_PATH, 'r') as f: content = f.read()
        for header, footer in [
            ('# BEGIN CLAUDEGUARD BLOCKS\n', '# END CLAUDEGUARD BLOCKS\n'),
            ('# BEGIN CLAUDEGUARD UPDATE BLOCKS\n', '# END CLAUDEGUARD UPDATE BLOCKS\n')
        ]:
            while header in content and footer in content:
                start = content.find(header)
                end = content.find(footer) + len(footer)
                content = content[:start] + content[end:]
        tmp = '/tmp/claudeguard_clean_hosts.tmp'
        with open(tmp, 'w') as f: f.write(content)
        cmd = f'sudo cp {tmp} {HOSTS_PATH} && rm -f {tmp}'
        subprocess.run(cmd, shell=True, capture_output=True)
    except: pass
" 2>/dev/null || true

# Flush DNS
dscacheutil -flushcache 2>/dev/null || true
sudo killall -HUP mDNSResponder 2>/dev/null || true

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
    if [ -d "$RESTORE_DIR" ] && [ -w "$RESTORE_DIR" ] && [ ! -e "$RESTORE_DIR/claude" ]; then
        ln -sf "$REAL_CLAUDE_TARGET" "$RESTORE_DIR/claude"
        echo "    Restored $RESTORE_DIR/claude -> $REAL_CLAUDE_TARGET"
    fi
else
    echo "    ⚠️  Could not determine the original claude CLI path; nothing restored."
    echo "       Reinstall Claude Code (e.g. 'brew reinstall --cask claude-code') if 'claude' now points nowhere."
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
