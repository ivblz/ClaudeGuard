#!/usr/bin/env python3
import sys
import os
import subprocess

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")))

from src.config import ConfigManager
from src.brain import get_verdict
from src.integrity import discover_desktop_app
from src.network_guard import sync_hosts_file

def launch_claude_desktop():
    config = ConfigManager()

    if not config.protection_enabled:
        open_real_app(config)
        return

    if config.config.get("connection_mode", "vpn") == "vpn" and not config.allowed_ips:
        show_mac_alert(
            "ClaudeGuard Protection 🚫",
            "Access to Claude Desktop blocked.\n\nReason: No allowed VPN IPs configured in whitelist.\n\nUse 'claudeguard add-ip <IP>' to configure."
        )
        sys.exit(1)

    # Fail closed — only "allowed" launches; "blocked"/"offline" both refuse.
    verdict, ip, err = get_verdict(config, timeout=2.0)

    if verdict != "allowed":
        if verdict == "offline":
            show_mac_alert(
                "ClaudeGuard Protection 🚫",
                "Access to Claude Desktop BLOCKED.\n\nNo internet connection — your IP can't be verified.\n\nExecution cancelled to prevent region ban."
            )
        else:
            ip_str = ip if ip else "Unknown"
            err_msg = f"\nError: {err}" if err else ""
            show_mac_alert(
                "ClaudeGuard Protection 🚫",
                f"Access to Claude Desktop BLOCKED.\n\nCurrent Public IP: {ip_str}\nStatus: NOT IN ALLOWED VPN WHITELIST{err_msg}\n\nExecution cancelled to prevent region ban."
            )
        sys.exit(1)

    # IP is valid! Unblock domain and start app
    ok, message = (True, "") if config.config.get("connection_mode") == "proxy" else sync_hosts_file(block_claude_domains=False, config=config)
    if not ok:
        print(message, file=sys.stderr)
        show_mac_alert("ClaudeGuard Error", "Network protection could not be updated. See the helper logs.")
        sys.exit(1)
    open_real_app(config)

def open_real_app(config):
    # Re-discover if the recorded location is stale (app moved or reinstalled).
    app_path = config.real_claude_app
    if not os.path.exists(app_path):
        app_path = discover_desktop_app(config)
        if app_path:
            config.config["real_claude_app_path"] = app_path
            config.save_config()

    if app_path and os.path.exists(app_path):
        subprocess.run(["open", "-a", app_path], check=False)
    else:
        show_mac_alert("ClaudeGuard Error", "Claude Desktop app not found. Run 'claudeguard doctor'.")

def show_mac_alert(title, message):
    script = 'on run argv\n    display alert (item 1 of argv) message (item 2 of argv) as critical\nend run'
    subprocess.run(["osascript", "-e", script, "--", title, message], check=False)

if __name__ == "__main__":
    launch_claude_desktop()
