<div align="center">

# 🛡️ ClaudeGuard

**A VPN-whitelist guard for Claude on macOS.**

Blocks the **Claude Desktop** app, the **Claude Code CLI** (`claude`) and every Claude/Anthropic domain (`claude.ai`, `claude.com`, `anthropic.com` and all their subdomains) whenever your public IP is not on your VPN whitelist - so you never touch Claude from the wrong region by accident.

**English** · [Русский](README.ru.md)

<br>

<img src="photos/vpn_ok.png" width="190" alt="Protected (VPN OK)">
<img src="photos/blocked.png" width="190" alt="Blocked">
<img src="photos/disable.png" width="190" alt="Protection Disabled">
<img src="photos/offline.png" width="190" alt="Offline (no connection)">
<br>

<img src="photos/ip_whitelist.png" width="350" alt="IP Whitelist">
<img src="photos/add_model.png" width="350" alt="Default Model">

</div>

---

## Why

If your account is region-sensitive, a single request from the wrong IP can get your account flagged.
ClaudeGuard solves that: every launch and every running session is checked against your whitelist of allowed IPs, and access is cut the instant you fall off it.

## Features

- 🔐 **IP whitelist** - Claude opens **only** when your public IP matches one of your VPN nodes.
- ⏱ **Instant pre-flight check** - launching `claude` or `Claude.app` verifies the public IP in < 0.5s (STUN over UDP). Not whitelisted → blocked before anything connects.
- 🧠 **One brain, one verdict** - a background daemon publishes the decision to a state file; the CLI, the app launcher and the menu bar all read the same verdict, so nothing can disagree.
- 🚀 **Autostart at login** via `LaunchAgent`.
- 🟢 **Menu bar UI** - live status (🟢 protected / 🔴 blocked / ⚪ offline / 🟡 off), toggles, one-click whitelist.
- 🤖 **Default model override** - pin a model for every `claude` session (e.g. `claude-opus-4-8`) from the menu bar; the CLI wrapper injects `--model` automatically so you don't have to type it each time.

## Install

The installer compiles the native binaries (Swift + C) **on your machine**. Locally-compiled binaries
carry no quarantine flag, so **Gatekeeper never blocks them** - no Apple Developer account, no code-signing,
no notarization, no Homebrew. The only requirement is Xcode Command Line Tools (the installer offers to
install them if missing).

Two ways to install - both give the exact same result.

**Option 1 - one line** (downloads and builds from GitHub):

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/ivblz/ClaudeGuard/main/install.sh)"
```

**Option 2 - from a local copy** (a cloned or downloaded repo; never touches GitHub):

```bash
./install.sh
```

Either way it compiles for your architecture (Apple Silicon or Intel), installs the menu bar daemon at login,
and wraps the `claude` command. It asks for your password once (`sudo` is needed to edit `/etc/hosts` and pf)
and offers to whitelist your current IP - accept **only if you are on your VPN right now.**

**Uninstall:**

```bash
./uninstall.sh
```

The app is installed at `/Applications/ClaudeGuard.app`. Supporting Python files live in `~/.local/share/ClaudeGuard`, and settings in `~/.config/claudeguard`.

## CLI

After install the `claudeguard` command is available:

| Command | What it does |
|---|---|
| `claudeguard status` | Current status, IP and whitelist |
| `claudeguard add-ip <ip>` | Add an IP or CIDR to the whitelist |
| `claudeguard remove-ip <ip>` | Remove an IP from the whitelist |
| `claudeguard list-ips` | List whitelisted IPs |
| `claudeguard enable-protection` / `disable-protection` | Turn protection on / off |
| `claudeguard set-model <model>` | Set the default model (e.g. `claude-opus-4-8`) |
| `claudeguard enable-model` / `disable-model` | Turn the model override on / off |
| `claudeguard launch-desktop` | Launch Claude Desktop with a pre-flight check |
| `claudeguard start` / `stop` | Start / stop the menu bar daemon |
| `claudeguard doctor` | Check every hook is still attached, and re-attach it |
| `claudeguard set-cli-path <path>` | Point at the real `claude` binary if auto-detect misses it |

### Surviving Claude reinstalls

Reinstalling Claude Code puts the real `claude` binary back over ClaudeGuard's shim,
and updating it deletes the version-stamped path the shim hands off to - so the guard
would silently detach while the menu bar still showed 🟢. The same applies to Claude
Desktop, whose bundle id and update directories have been renamed before.

ClaudeGuard therefore discovers those locations instead of hard-coding them, and
re-attaches whatever came loose: the daemon self-heals **every 60s**, the `claude`
wrapper re-hooks on each run, and `/etc/hosts` is re-applied whenever something
external edits it. Run `claudeguard doctor` to see the state of every hook (and fix
it immediately) at any time.

## How it works

1. **STUN-first IP detection** - the public IP is resolved via a single UDP STUN round-trip (tens of ms), falling back to HTTP echo services on networks that block UDP.
2. **The brain** (`src/brain.py`) turns that IP into one verdict - `allowed` / `blocked` / `offline` - and it **fails closed**: only a confirmed `allowed` lets Claude run.
3. **Single source of truth** - the menu bar daemon writes its verdict to `~/.config/claudeguard/state.json` on every check. The CLI wrapper and app launcher read it (instant), and fall back to their own check only if the daemon is down.
4. **Enforcement** - the whole Claude/Anthropic domain family (~175 hosts across 5 apex domains) is blocked via `/etc/hosts` + a pf firewall rule (TCP + UDP/QUIC); the desktop app is force-quit with an alert; a running `claude` session is killed the moment the IP leaves the whitelist.

> **Scope:** this is accidental-leak protection for your own machine, not a defense against a malicious admin. The truly unbypassable layer (a Network Extension content filter) requires a paid Apple Developer account; the on-device approach here is the free ceiling and covers accidental leaks well.

### Coexisting with other PF users

Rules and the address table live in the private `com.claudeguard` anchor.
ClaudeGuard acquires its own PF enable token (`-E`) and releases only that token (`-X`)
on unblock/uninstall. It never globally disables PF or flushes all connection states.
Existing TCP/QUIC states are removed only for blocked destination IPs. Built-in domains
are restricted to Anthropic's dedicated ranges; explicitly added custom domains may use
shared IPs, so blocking those addresses affects all connections to them.

Upgrade with `./install.sh`; updating user-side Python alone does not update the root-owned
backend. The installer starts the user daemon only after installing the matching root helper.
The native `pf-anchor` helper inserts/removes only ClaudeGuard's labelled root call,
using ticket-checked single-rule operations. It also works when Internet Sharing replaces
the default `com.apple/*` entry with its own anchors. No root ruleset reload is used.
The exact legacy ClaudeGuard ruleset is migrated; ambiguous mixed legacy/foreign rules
are rejected rather than rewritten. The private macOS PF ABI is checked by reading rules
before mutation; an incompatible kernel produces an error without a global-reload fallback.

The menu retains its original four IP/protection states. Enforcement errors are logged,
retried and propagated to launch checks, without an extra menu state. Active blocks are
refreshed every 60 seconds. Hosts blocking remains in place on PF failure. Logs:
`/tmp/claudeguard.err` and `/tmp/claudeguard-helper.err`.

Run isolated tests without touching the system firewall:
`python3 -B -m unittest discover -s tests -v`.
Native tests: `clang -Wall -Wextra -Werror tests/test_pf_anchor.c -o /tmp/test-pf-anchor && /tmp/test-pf-anchor`.
`tests/live_pf_check.py` is a separate opt-in root test that temporarily blocks one Claude IP
and verifies TCP recovery and preservation of Internet Sharing/NAT/reference state.

## Project structure

```
src/
  brain.py          The single decision core (reads the daemon verdict; STUN fallback)
  ip_checker.py     Public-IP detection: STUN over UDP, then HTTP
  config.py         Config at ~/.config/claudeguard/config.json
  network_guard.py  /etc/hosts + pf firewall block/unblock
  integrity.py      Finds Claude's real paths; re-attaches hooks after a reinstall
  cli_wrapper.py    Pre-flight interceptor for the `claude` command
  app_launcher.py   Pre-flight interceptor for Claude.app
  main.swift        Native menu bar daemon (AppKit): monitoring, alerts, state file
  hosts_helper.c    Root helper run by a LaunchDaemon (no sudoers, no setuid); writes /etc/hosts + pf
  pf_controller.py  Root-owned backend: private PF anchor/token, request acknowledgements, hosts merge
  pf_anchor.c       Ticket-checked insertion/removal of only our labelled root anchor call
bin/claudeguard     Management CLI
assets/AppIcon.png  App icon
install.sh          Compiles natively on-device and installs everything
uninstall.sh        Clean removal, restores the original `claude`
```

## License

MIT - see [LICENSE](LICENSE). The extracted Apple PF ABI definitions in `src/vendor/pf_abi.h`
retain their upstream notices and [Apple Public Source License](src/vendor/APPLE_LICENSE).
