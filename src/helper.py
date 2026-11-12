#!/usr/bin/env python3
import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")))

from src.config import ConfigManager
from src.integrity import repair
from src.network_guard import sync_hosts_file

def main():
    if len(sys.argv) < 2:
        return
    cmd = sys.argv[1]
    config = ConfigManager()
    from src import trace_timing as trace
    trace.configure(config.config, os.path.dirname(config.path) if hasattr(config, "path") else None)

    if cmd == "proxy_save":
        from src.proxy import save_profile
        try:
            # Persist only. The daemon enforces the new configuration asynchronously.
            # Waiting for DNS/root acknowledgement here freezes the settings window.
            save_profile(config, sys.stdin.read(65537))
        except json.JSONDecodeError:
            print("Invalid JSON. Paste one complete outbound object.", file=sys.stderr)
            sys.exit(1)
        except ValueError as error:
            print(str(error), file=sys.stderr)
            sys.exit(1)
        except Exception:
            print("Could not save proxy settings. Check the profile and configuration file permissions.", file=sys.stderr)
            sys.exit(1)
    elif cmd == "proxy_check":
        from src.proxy import prepare, probe, profile_id
        import time
        from pathlib import Path
        result = {"profile_id": profile_id(config), "ok": False, "ip": "", "error": "Proxy is disconnected", "prepared": False}
        # A queued proxy check may start after the user has already selected
        # VPN. Do not wait for a stopped proxy or apply its failure policy.
        if config.config.get("connection_mode") != "proxy":
            result["error"] = "Connection mode changed"
            print(json.dumps(result), flush=True)
            return
        try:
            if not config.config.get("proxy_profile"):
                raise ValueError("Proxy is not configured")
            if not config.config.get("proxy_enabled", True):
                raise ValueError("Proxy is disconnected")
            cache = Path(config.path).parent / "proxy-health.json"
            try:
                previous = json.loads(cache.read_text())
            except (OSError, ValueError):
                previous = {}
            if previous.get("profile") != profile_id(config) or time.time() - previous.get("prepared_at", 0) > 60:
                ip = prepare(config)
                result["prepared"] = True
                cache.write_text(json.dumps({"profile": profile_id(config), "prepared_at": time.time()}))
            else:
                try:
                    ip = probe()
                except Exception:
                    ip = prepare(config)
                    result["prepared"] = True
            result.update(ok=True, ip=ip, error="")
        except Exception as error:
            result["error"] = str(error)
            current = ConfigManager()
            if (current.config.get("connection_mode") != "proxy"
                    or profile_id(current) != profile_id(config)):
                result["error"] = "Connection settings changed"
                print(json.dumps(result), flush=True)
                return
            # A failed startup/probe must still install ordinary blocking, even
            # when the proxy profile itself is invalid or conflicts with a VPN.
            import copy
            denied = copy.copy(config)
            denied.config = dict(config.config, proxy_enabled=False)
            ok, message = sync_hosts_file(True, denied)
            if not ok:
                result["error"] += "; " + message
        print(json.dumps(result), flush=True)
    elif cmd == "sync_hosts":
        block_claude = sys.argv[2].lower() == "true" if len(sys.argv) > 2 else False
        ok, message = sync_hosts_file(block_claude_domains=block_claude, config=config)
        if not ok:
            print(message, file=sys.stderr, flush=True)
            sys.exit(1)

    elif cmd == "integrity":
        # Called by the daemon on a timer; logs only real changes so the normal
        # case stays quiet.
        report = repair(config)
        for change in report["changed"]:
            print(f"[ClaudeGuard] repaired: {change}", flush=True)

if __name__ == "__main__":
    main()
