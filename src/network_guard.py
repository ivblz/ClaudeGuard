import ipaddress
import fcntl
import json
import os
import socket
import subprocess
import sys
import time
import uuid
from src import trace_timing as trace
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

HOSTS_PATH = "/etc/hosts"
BLOCK_HEADER = "# BEGIN CLAUDEGUARD BLOCKS\n"
BLOCK_FOOTER = "# END CLAUDEGUARD BLOCKS\n"

# Legacy markers are retained only to remove blocks from older installations.
UPDATE_HEADER = "# BEGIN CLAUDEGUARD UPDATE BLOCKS\n"
UPDATE_FOOTER = "# END CLAUDEGUARD UPDATE BLOCKS\n"

# The user daemon has no root, and we no longer use sudo/sudoers. Instead it
# stages the desired /etc/hosts + pf rule under this private dir and pokes a
# trigger file; a root LaunchDaemon (com.claudeguard.helper) watches the trigger
# and applies the vetted files. See hosts_helper.c and install.sh.
CONFIG_DIR = os.path.expanduser("~/.config/claudeguard")
PENDING_DIR = os.path.join(CONFIG_DIR, "pending")
PENDING_HOSTS = os.path.join(PENDING_DIR, "hosts.tmp")
PF_RULE_PATH = os.path.join(PENDING_DIR, "pf.rule")
REQUEST_FILE = os.path.join(PENDING_DIR, "request")
STATUS_FILE = "/Library/Application Support/ClaudeGuard/network-status.json"
ROOT_HELPER = "/Library/Application Support/ClaudeGuard/hosts-helper"

APEX_DOMAINS = [
    "claude.com",
    "claude.ai",
    "claude.usercontent.com",
    "anthropic.com",
    "anthropic.ai"
]

SUBDOMAIN_PREFIXES = [
    "", "www", "app", "api", "auth", "stats", "cdn", "assets",
    "console", "docs", "support", "feedback", "desktop-app-updates",
    "a-api", "a-cdn", "code", "status", "blog", "research", "events",
    "login", "register", "portal", "admin", "internal", "v1", "v2", "v3",
    "ws", "gateway", "proxy", "assets-proxy", "account", "settings", "billing"
]

KNOWN_RESOLVED_DOMAINS = [
    "claude.com", "www.claude.com", "console.claude.com", "docs.claude.com", "support.claude.com", "code.claude.com", "status.claude.com", "app.claude.com", "api.claude.com", "auth.claude.com",
    "claude.ai", "www.claude.ai", "app.claude.ai", "assets.claude.ai", "console.claude.ai", "a-cdn.claude.ai", "status.claude.ai", "api.claude.ai", "auth.claude.ai",
    "claude.usercontent.com", "www.claude.usercontent.com", "app.claude.usercontent.com",
    "anthropic.com", "www.anthropic.com", "api.anthropic.com", "assets.anthropic.com", "console.anthropic.com", "docs.anthropic.com", "support.anthropic.com", "feedback.anthropic.com", "desktop-app-updates.anthropic.com", "a-api.anthropic.com", "a-cdn.anthropic.com", "status.anthropic.com", "events.anthropic.com", "portal.anthropic.com", "assets-proxy.anthropic.com", "billing.anthropic.com",
    "anthropic.ai", "www.anthropic.ai", "app.anthropic.ai", "api.anthropic.ai", "auth.anthropic.ai"
]

# External resolvers used to find the *real* server IPs. dig queries them
# directly and never consults /etc/hosts, so it still works after we've poisoned
# the hosts file with 0.0.0.0 entries.
EXTERNAL_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

# Anthropic's own address ranges. pf only ever blocks IPs inside these, so an
# auxiliary page hosted on a shared CDN (e.g. the status page on CloudFront, the
# trust page on Cloudflare) never drags unrelated sites down with it. Every
# account-critical domain (claude.ai, app/api/console/auth/login.*) lives here.
ANTHROPIC_NETS = [
    ipaddress.ip_network("160.79.104.0/24"),
    ipaddress.ip_network("2607:6bc0::/32"),
]

# Fallback for when external DNS is unreachable, so pf still has something to drop.
FALLBACK_IPS = ["160.79.104.10", "2607:6bc0::10"]

# Small set of domains that actually exist and share Anthropic's dedicated IPs.
# pf blocks by IP, so resolving these is enough to discover every address the
# whole domain family sits on — no need to query dozens of subdomains, most of
# which are NXDOMAIN and just slow the block down.
PF_RESOLVE_DOMAINS = [
    "claude.ai", "www.claude.ai", "app.claude.ai", "api.claude.ai", "auth.claude.ai",
    "claude.com", "www.claude.com", "app.claude.com", "api.claude.com", "console.claude.com",
    "anthropic.com", "www.anthropic.com", "api.anthropic.com", "console.anthropic.com",
]

def _is_ip(text):
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, text)
            return True
        except OSError:
            pass
    return False

def _in_anthropic_range(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in ANTHROPIC_NETS)

def _dig(resolver, record_type, domain):
    """Returns (query_succeeded, ips). query_succeeded is False only when the
    resolver itself failed (timeout/unreachable) — an NXDOMAIN is a *successful*
    query with an empty answer, and must not trigger a pointless retry."""
    dig_bin = "/usr/bin/dig" if os.path.exists("/usr/bin/dig") else "dig"
    try:
        res = subprocess.run(
            [dig_bin, f"@{resolver}", "+short", "+time=1", "+tries=1", record_type, domain],
            capture_output=True, text=True, timeout=1.05
        )
    except Exception:
        return False, []
    if res.returncode != 0:
        return False, []
    ips = []
    for line in res.stdout.splitlines():
        line = line.strip()
        # +short can emit CNAME lines (trailing dot) — keep only literal IPs.
        if line and not line.endswith(".") and _is_ip(line):
            ips.append(line)
    return True, ips

DNS_DEADLINE = 2.5


def _resolve_live(domains):
    deadline = time.monotonic() + DNS_DEADLINE
    answers = {host: set() for host in domains}
    timings = {} if trace.enabled else None
    started = time.monotonic() if trace.enabled else None
    pool = ThreadPoolExecutor(max_workers=32)
    pending = {pool.submit(_dig, EXTERNAL_RESOLVERS[0], record, host): (host, record, 0)
               for host in domains for record in ("A", "AAAA")}
    try:
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            done, _ = wait(pending, timeout=remaining, return_when=FIRST_COMPLETED)
            if not done:
                break
            for future in done:
                host, record, resolver = pending.pop(future)
                ok, ips = future.result()
                if ok:
                    answers[host].update(ips)
                elif resolver + 1 < len(EXTERNAL_RESOLVERS) and time.monotonic() < deadline:
                    pending[pool.submit(_dig, EXTERNAL_RESOLVERS[resolver + 1], record, host)] = (host, record, resolver + 1)
                if timings is not None:
                    timings[host] = time.monotonic() - started
    finally:
        for future in pending:
            future.cancel()
        # Running dig processes have their own 1.05s timeout; don't join them
        # here and accidentally extend the overall switching deadline.
        pool.shutdown(wait=False)
    if timings:
        host = max(timings, key=timings.get)
        trace.emit("dns.claude.slowest." + trace.host_label(host), timings[host] * 1000)
    return answers


@trace.stage("dns.claude.total")
def resolve_ips(domains):
    domains = set(domains)
    if not domains:
        return set()
    answers = _resolve_live(domains)
    return {ip for found in answers.values() for ip in found}


def resolve_domain_ips(domains):
    """The pf target set: Anthropic-owned IPs only (never a shared CDN), plus a
    fallback so a DNS outage can't leave pf with an empty table."""
    ips = {ip for ip in resolve_ips(domains) if _in_anthropic_range(ip)}
    ips.update(FALLBACK_IPS)
    return sorted(ips)

def generate_all_subdomains():
    domains = set(KNOWN_RESOLVED_DOMAINS)
    for apex in APEX_DOMAINS:
        domains.add(apex)
        for sub in SUBDOMAIN_PREFIXES:
            if sub:
                domains.add(f"{sub}.{apex}")
    return sorted(list(domains))

def sync_hosts_file(block_claude_domains, config):
    # Keep the staged hosts/rule/request triple consistent until acknowledged.
    trace.configure(config.config, CONFIG_DIR)
    _ensure_pending()
    with open(os.path.join(PENDING_DIR, "sync.lock"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _sync_hosts_file(block_claude_domains, config)


def _sync_hosts_file(block_claude_domains, config):
    """Block/unblock all Claude & Anthropic subdomains via /etc/hosts and pf
    (TCP + UDP QUIC)."""
    try:
        if not os.path.exists(HOSTS_PATH):
            return False, "File /etc/hosts does not exist"

        with open(HOSTS_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        content = remove_section(content, BLOCK_HEADER, BLOCK_FOOTER)
        content = remove_section(content, UPDATE_HEADER, UPDATE_FOOTER)

        all_blocked = sorted(list(set(generate_all_subdomains() + config.config.get("blocked_domains", []))))

        vpn_mode = (config.config.get("connection_mode", "vpn") == "vpn"
                    and getattr(config, "protection_enabled", False))
        new_blocks = ""
        # VPN denial lives in PF. Poisoned DNS can outlive hosts cleanup in browsers.
        if block_claude_domains and not vpn_mode:
            new_blocks += BLOCK_HEADER
            for domain in all_blocked:
                new_blocks += f"0.0.0.0\t{domain}\n"
                new_blocks += f"127.0.0.1\t{domain}\n"
                new_blocks += f"::1\t{domain}\n"
            new_blocks += BLOCK_FOOTER

        final_content = content.rstrip() + "\n\n" + new_blocks if new_blocks else content.rstrip() + "\n"

        _ensure_pending()

        # pf rule blocks TCP + UDP (UDP covers HTTP/3 QUIC) to the real server
        # IPs. Using literal IPs (not domain names) is essential: pfctl would
        # otherwise resolve the names through the just-poisoned /etc/hosts and
        # build a table full of 0.0.0.0. Resolving via external DNS also means
        # the block holds even when the browser uses DoH and skips /etc/hosts.
        proxy_mode = (config.config.get("connection_mode") == "proxy" and config.protection_enabled
                      and config.config.get("proxy_enabled", True) and bool(config.config.get("proxy_profile")))
        _atomic_write(os.path.join(PENDING_DIR, "vpn.json"), json.dumps({
            "allow": not block_claude_domains,
            "allowed_ips": config.config.get("allowed_ips", []),
        }) if vpn_mode else "null")
        if block_claude_domains or proxy_mode or vpn_mode:
            # User-added custom domains are explicit intent — block whatever they
            # resolve to, no Anthropic-range filter.
            managed = set(generate_all_subdomains())
            custom = [domain for domain in config.config.get("blocked_domains", [])
                      if domain not in managed]
            if proxy_mode:
                from src.proxy_config import validate, DEDICATED
                profile = validate(config.config.get("proxy_profile"))
                # Resolve the union once; the PF target set already includes all
                # proxy routes, so a separate owned-range lookup is redundant.
                routing_ips = resolve_ips(sorted(set(KNOWN_RESOLVED_DOMAINS + PF_RESOLVE_DOMAINS
                                                     + config.config.get("blocked_domains", []))))
                if not routing_ips:
                    raise RuntimeError("Cannot resolve Claude routes; proxy remains blocked")
                ip_set = set(routing_ips)
                ip_set.update(FALLBACK_IPS)
                ip_set.update(DEDICATED)
                request = {"profile": profile, "addresses": sorted(routing_ips),
                           "domains": sorted(set(APEX_DOMAINS + all_blocked))}
                _atomic_write(os.path.join(PENDING_DIR, "proxy.json"), json.dumps(request))
            elif vpn_mode:
                # Keep the dedicated IPv4/IPv6 ranges covered even on DNS failure.
                ip_set = {str(net) for net in ANTHROPIC_NETS}
                ip_set.update(resolve_ips(KNOWN_RESOLVED_DOMAINS + custom))
                _atomic_write(os.path.join(PENDING_DIR, "proxy.json"), "null")
            else:
                if config.config.get("connection_mode") == "proxy" and not config.config.get("proxy_profile"):
                    # No proxy to probe. Dedicated ranges give immediate fail-closed
                    # coverage without waiting on external DNS after profile removal.
                    ip_set = {str(net) for net in ANTHROPIC_NETS}
                else:
                    ip_set = set(resolve_domain_ips(PF_RESOLVE_DOMAINS))
                if custom:
                    ip_set.update(resolve_ips(custom))
                _atomic_write(os.path.join(PENDING_DIR, "proxy.json"), "null")
            table_body = " ".join(sorted(ip_set))
            pf_content = (
                f"table <claude_guard> persist {{ {table_body} }}\n"
                f"block drop out quick {'on ! utun199 ' if proxy_mode else ''}proto {{ tcp, udp }} to <claude_guard>{' user != 0' if proxy_mode else ''}\n"
            )
            _atomic_write(PF_RULE_PATH, pf_content)
        else:
            _atomic_write(os.path.join(PENDING_DIR, "proxy.json"), "null")
            if os.path.exists(PF_RULE_PATH):
                try:
                    os.remove(PF_RULE_PATH)
                except Exception:
                    pass

        write_hosts(final_content)

        return True, "Hosts and PF synced successfully"
    except Exception as e:
        return False, f"Failed to sync hosts: {e}"

def remove_section(text, header, footer):
    while header in text and footer in text:
        start = text.find(header)
        end = text.find(footer) + len(footer)
        text = text[:start] + text[end:]
    return text

def _ensure_pending():
    """The private staging dir the root helper reads from. 0700 + user-owned is
    what lets the helper trust its contents (it applies only files owned by the
    config dir's owner)."""
    os.makedirs(PENDING_DIR, mode=0o700, exist_ok=True)
    os.chmod(PENDING_DIR, 0o700)
    for name in ("proxy.json", "proxy.json.new"):
        path = os.path.join(PENDING_DIR, name)
        if os.path.exists(path):
            os.chmod(path, 0o600)

def _atomic_write(path, content):
    tmp = path + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

@trace.stage("helper.root.apply")
def _apply_as_root():
    """Use the same root-owned backend in both execution paths."""
    subprocess.run([ROOT_HELPER, CONFIG_DIR], check=True, timeout=60)

@trace.stage("macos.confirmation.poll_100ms_deadline_30s")
def write_hosts(content):
    """Stage the desired /etc/hosts and signal the root helper to apply it.

    No sudo, no sudoers: the LaunchDaemon com.claudeguard.helper watches the
    trigger file and runs as root. When we already are root we just apply
    directly."""
    _ensure_pending()
    _atomic_write(PENDING_HOSTS, content)

    # Poke the trigger. Written in place (not renamed) so launchd's kqueue watch
    # on this exact file survives across pokes.
    request_id = uuid.uuid4().hex
    if trace.enabled:
        # Reserved UUID version nibble carries opt-in diagnostics to launchd.
        # Keep the same 32-hex nonce protocol; no sidecar I/O when disabled.
        request_id = request_id[:12] + "f" + request_id[13:]
    with open(REQUEST_FILE, "w", encoding="utf-8") as f:
        f.write(request_id)
        f.flush()
        os.fsync(f.fileno())

    if os.geteuid() == 0:
        _apply_as_root()

    # hosts markers alone cannot confirm PF success. Allow launchd throttling.
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with open(STATUS_FILE, encoding="utf-8") as f:
                status = json.load(f)
                if status.get("request") == request_id:
                    if not status.get("ok"):
                        raise RuntimeError(status.get("error", "Network helper failed"))
                    return
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    raise RuntimeError("Network helper did not acknowledge the request within 30s")
