#!/usr/bin/env python3
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")))

from src.config import ConfigManager
from src.integrity import repair
from src.network_guard import sync_hosts_file

def main():
    if len(sys.argv) < 2:
        return
    cmd = sys.argv[1]
    config = ConfigManager()

    if cmd == "sync_hosts":
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
