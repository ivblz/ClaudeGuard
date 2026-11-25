"""Privileged network backend. Installed root-owned and run with python3 -I.

Only our anchor, enable reference, hosts section and destination states belong
to us. Never disable PF, reload pf.conf, or flush the global state table.
"""
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

# Isolated Python excludes the script directory; add only this root-owned directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import trace_timing as trace

SYSTEM_DIR = Path("/Library/Application Support/ClaudeGuard")
ANCHOR = "com.claudeguard"
PREVIOUS_ANCHOR = "com.apple/000.ClaudeGuard"
TABLE = "claude_guard"
HEADER = "# BEGIN CLAUDEGUARD BLOCKS\n"
FOOTER = "# END CLAUDEGUARD BLOCKS\n"
LEGACY_HEADER = "# BEGIN CLAUDEGUARD UPDATE BLOCKS\n"
LEGACY_FOOTER = "# END CLAUDEGUARD UPDATE BLOCKS\n"
HOSTS_PATH = Path("/etc/hosts")


class PFError(RuntimeError):
    pass


def atomic_json(path, data, mode=0o600):
    temporary = path.with_suffix(".new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w") as stream:
        os.fchmod(stream.fileno(), mode)
        json.dump(data, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def trusted_read(path, owner, optional=False):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if optional:
            return None
        raise
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_size > 1024 * 1024:
            raise PFError("Untrusted staged file: " + str(path))
        return stream.read(1024 * 1024 + 1)


def parse_rule(text):
    """Accept data, not arbitrary user-supplied pfctl directives."""
    match = re.fullmatch(
        r"table <claude_guard> persist \{ ([^{}\n]+) \}\n"
        r"block drop out quick (?:on ! utun199 )?proto \{ tcp, udp \} to <claude_guard>(?: user != 0)?\n", text)
    if not match:
        raise PFError("Invalid ClaudeGuard PF rule")
    addresses = sorted({ip if ip in {"160.79.104.0/24", "2607:6bc0::/32"} else str(ipaddress.ip_address(ip)) for ip in match[1].split()})
    if not addresses:
        raise PFError("Empty block table")
    return addresses


def make_rule(addresses, proxy=False):
    return ("table <claude_guard> persist { " + " ".join(addresses) + " }\n"
            "block drop out quick " + ("on ! utun199 " if proxy else "") + "proto { tcp, udp } to <claude_guard>" + (" user != 0" if proxy else "") + "\n")


def make_vpn_rule(addresses, interface):
    if not isinstance(interface, str) or not re.fullmatch(r"utun[0-9]{1,4}", interface) or interface == "utun199":
        raise PFError("Unverified VPN interface")
    # Bind states to the tunnel: a surviving connection cannot migrate to en0.
    # IPv6 has no separate whitelist proof yet, so it remains blocked.
    return ("table <claude_guard> persist { " + " ".join(addresses) + " }\n"
            "pass out quick on " + interface + " inet proto { tcp, udp } to <claude_guard> keep state (if-bound)\n"
            "block drop out quick proto { tcp, udp } to <claude_guard>\n")


def verified_vpn_interface(allowed):
    if not isinstance(allowed, list) or not allowed or len(allowed) > 1024:
        raise PFError("VPN whitelist is empty or invalid")
    networks = [ipaddress.ip_network(value, strict=False) for value in allowed]
    def route():
        result = subprocess.run(['/sbin/route', '-n', 'get', '160.79.104.10'],
                                capture_output=True, text=True, timeout=3, check=True)
        match = re.search(r'^\s*interface:\s*(utun[0-9]{1,4})\s*$', result.stdout, re.M)
        if not match or match[1] == 'utun199':
            raise PFError("Claude route is not through a VPN tunnel")
        return match[1]
    interface = route()
    # No ambient proxy variables or curlrc; the proof must use this interface.
    for endpoint in ('https://api.ipify.org', 'https://checkip.amazonaws.com'):
        try:
            result = subprocess.run(['/usr/bin/curl', '-q', '--fail', '--silent',
                                     '--ipv4', '--interface', interface, '--proxy', '', '--noproxy', '*',
                                     '--max-time', '3', '--max-filesize', '128', endpoint],
                                    capture_output=True, text=True, timeout=4, check=True,
                                    env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})
            address = ipaddress.ip_address(result.stdout.strip())
            if not any(address in network for network in networks):
                raise PFError("VPN exit IP is not whitelisted")
            if route() != interface:
                raise PFError("VPN route changed during verification")
            return interface
        except (subprocess.SubprocessError, ValueError):
            continue
    raise PFError("VPN tunnel could not be verified; traffic remains blocked")


def strip_section(text, header, footer):
    while header in text:
        start = text.index(header)
        end = text.find(footer, start + len(header))
        if end < 0:
            raise PFError("Incomplete ClaudeGuard hosts section")
        text = text[:start] + text[end + len(footer):]
    return text


def merge_hosts(current, staged):
    """Keep other tools' latest edits, rather than copying a stale hosts file."""
    clean = strip_section(current, HEADER, FOOTER)
    clean = strip_section(clean, LEGACY_HEADER, LEGACY_FOOTER)
    block = ""
    if HEADER in staged:
        start = staged.index(HEADER) + len(HEADER)
        end = staged.find(FOOTER, start)
        if end < 0:
            raise PFError("Incomplete staged hosts section")
        body = staged[start:end]
        for line in body.splitlines():
            if not re.fullmatch(r"(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+[A-Za-z0-9_.-]+", line):
                raise PFError("Invalid staged hosts entry")
        block = HEADER + body + FOOTER
    return clean.rstrip() + ("\n\n" + block if block else "\n")


class PFController:
    def __init__(self, directory=SYSTEM_DIR, runner=subprocess.run):
        self.directory = Path(directory)
        self.token_path = self.directory / "pf-token.json"
        self.runner = runner

    @trace.stage("pf.helper.call")
    def pf(self, *args, input=None):
        result = self.runner(["/sbin/pfctl", *args], input=input,
                             capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise PFError("pfctl " + " ".join(args) + ": " + result.stderr.strip())
        return result.stdout + result.stderr if args == ("-E",) else result.stdout

    def root_rules(self):
        return self.pf("-sr").strip()

    @staticmethod
    def legacy_only(rules):
        # Exact old pfctl -sr output, never substring-based deletion of foreign
        # rules. pfctl expands the tcp/udp list into two filter rules.
        expected = {"block drop out quick proto " + proto + " from any to <claude_guard>"
                    for proto in ("tcp", "udp")}
        return set(rules.splitlines()) == expected and len(rules.splitlines()) == 2

    def ensure_attachment(self):
        rules = self.root_rules()
        legacy = self.legacy_only(rules)
        if "<claude_guard>" in rules and not legacy:
            raise PFError("Mixed legacy ClaudeGuard and foreign root rules; migration requires review")
        # Internet Sharing can leave only its own root anchor, without the
        # default com.apple/* wildcard. Insert OUR direct anchor call with a
        # ticket-checked ioctl; never replay or replace any foreign root rule.
        self.anchor("ensure")
        if legacy:
            self.anchor("migrate-legacy")
            self.pf("-t", TABLE, "-T", "kill")

    @trace.stage("pf.anchor.helper.call")
    def anchor(self, operation):
        result = self.runner([str(self.directory / "pf-anchor"), operation],
                             capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise PFError("pf-anchor " + operation + ": " + result.stderr.strip())

    def clear_anchor(self, name):
        self.pf("-a", name, "-F", "rules")
        self.pf("-a", name, "-F", "Tables")

    def read_token(self):
        try:
            token = json.loads(self.token_path.read_text())["token"]
        except FileNotFoundError:
            return None
        if not isinstance(token, str) or not re.fullmatch(r"[0-9]+", token):
            raise PFError("Invalid saved PF enable token")
        return token

    def token_is_live(self, token):
        # References are lost on reboot or an external pfctl -d. Match a full
        # numeric field, never a token substring or another process's PID.
        refs = self.pf("-s", "References")
        for line in refs.splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[0].isdigit() and fields[2] == token:
                return True
        return False

    def enable(self):
        token = self.read_token()
        if token and self.token_is_live(token):
            return
        output = self.pf("-E")
        match = re.search(r"Token\s*:\s*(\d+)", output)
        if not match:
            raise PFError("pfctl did not return an enable token")
        token = match[1]
        try:
            atomic_json(self.token_path, {"token": token})
        except Exception:
            self.pf("-X", token)
            raise

    @trace.stage("pf.apply.block")
    def block(self, addresses, proxy=False, kill_states=True, vpn_interface=None):
        # Stage first, so migrating the legacy root rules switches directly to
        # an already populated anchor, without an unprotected interval.
        self.pf("-a", ANCHOR, "-f", "-", input=make_vpn_rule(addresses, vpn_interface) if vpn_interface else make_rule(addresses, proxy=proxy))
        self.ensure_attachment()
        self.enable()
        # Upgrade from the first scoped implementation. It had no private
        # root call; only its child rules/table belong to us.
        self.clear_anchor(PREVIOUS_ANCHOR)
        # States bypass subsequent rule evaluation. Remove only connections to
        # the destinations being blocked; leave every other connection intact.
        for address in addresses if kill_states else []:
            network = "::/0" if ipaddress.ip_network(address, strict=False).version == 6 else "0.0.0.0/0"
            self.pf("-k", network, "-k", address)

    @trace.stage("pf.apply.unblock")
    def unblock(self):
        rules = self.root_rules()
        if "<claude_guard>" in rules:
            # A legacy install may be disabled before its first block request.
            if not self.legacy_only(rules):
                raise PFError("Mixed legacy ClaudeGuard and foreign root rules; migration requires review")
            self.ensure_attachment()
        self.clear_anchor(ANCHOR)
        self.anchor("remove")
        self.clear_anchor(PREVIOUS_ANCHOR)
        token = self.read_token()
        if token:
            if self.token_is_live(token):
                self.pf("-X", token)
            self.token_path.unlink()


@trace.stage("hosts.apply")
def apply_hosts(staged):
    merged = merge_hosts(HOSTS_PATH.read_text(), staged)
    # /etc/hosts must keep its existing inode (system services watch it).
    with HOSTS_PATH.open("w") as stream:
        stream.write(merged)
        stream.flush()
        os.fsync(stream.fileno())
    for command in (["/usr/bin/dscacheutil", "-flushcache"],
                    ["/usr/bin/killall", "-HUP", "mDNSResponder"]):
        started = trace.begin() if trace.enabled else None
        try:
            subprocess.run(command, capture_output=True, timeout=10, check=True)
        finally:
            if trace.enabled:
                trace.end(started, "hosts.helper." + ("flushcache" if command[0].endswith("dscacheutil") else "mdns_hup"), "completed")


def apply_request(config_dir, controller):
    directory = Path(config_dir)
    owner = directory.stat().st_uid
    pending = directory / "pending"
    request = trusted_read(pending / "request", owner).strip()
    if not re.fullmatch(r"[0-9a-f]{32}", request):
        raise PFError("Invalid request ID")
    # UUID4 requests normally have version nibble 4. The diagnostics-only
    # version f propagates opt-in through launchd without another file read.
    trace.configure({"trace": request[12] == "f"}, directory)
    status = {"request": request, "ok": False}
    proxy = None
    vpn = None
    addresses = []
    hosts = ""
    rule = None
    blocked = False
    denial_installed = False
    try:
        hosts = trusted_read(pending / "hosts.tmp", owner)
        rule = trusted_read(pending / "pf.rule", owner, optional=True)
        blocked = rule is not None
        raw_proxy = trusted_read(pending / "proxy.json", owner, optional=True)
        proxy = json.loads(raw_proxy) if raw_proxy else None
        raw_vpn = trusted_read(pending / "vpn.json", owner, optional=True)
        vpn = json.loads(raw_vpn) if raw_vpn else None
        if vpn is not None:
            addresses = parse_rule(rule)
            if proxy is not None or not isinstance(vpn, dict) or type(vpn.get("allow")) is not bool:
                raise PFError("Invalid VPN guard request")
            try:
                previous = json.loads((controller.directory / "network-status.json").read_text())
            except (OSError, ValueError):
                previous = {}
            previous_interface = previous.get("vpn_interface") if previous.get("ok") else None
            # Retain a previously verified tunnel while rechecking it; startup,
            # mode changes and denied requests get an unconditional block first.
            retain = previous_interface if vpn["allow"] else None
            old_addresses = addresses
            if previous.get("vpn_addresses"):
                # Keep previously protected destinations covered while cached
                # application DNS/active connections may still use them.
                old_addresses = parse_rule(make_rule(previous.get("vpn_addresses", addresses)))
                addresses = sorted(set(addresses) | set(old_addresses))
            status["vpn_addresses"] = addresses
            controller.block(addresses, vpn_interface=retain, kill_states=not bool(retain))
            if retain:
                for address in set(addresses) - set(old_addresses):
                    family = "::/0" if ipaddress.ip_network(address, strict=False).version == 6 else "0.0.0.0/0"
                    controller.pf("-k", family, "-k", address)
            # Remove legacy DNS poisoning only after the PF guard is installed.
            # Accept older staged VPN requests too, but never write their blocks.
            apply_hosts(strip_section(hosts, HEADER, FOOTER))
            if raw_proxy and previous.get("proxy", True):
                from proxy_service import stop
                stop()
            if vpn["allow"]:
                interface = verified_vpn_interface(vpn.get("allowed_ips"))
                # A new tunnel must not inherit floating states from an old path.
                controller.block(addresses, vpn_interface=interface,
                                 kill_states=interface != previous_interface)
                status.update(ok=True, blocked=False, proxy=False, vpn_interface=interface, vpn_addresses=addresses)
            else:
                status.update(ok=True, blocked=True, proxy=False)
            atomic_json(controller.directory / "network-status.json", status, mode=0o644)
            return
        if proxy is not None:
            from proxy_service import ensure
            # Install the direct-traffic kill switch before starting the tunnel.
            try:
                previous = json.loads((controller.directory / "network-status.json").read_text())
            except (OSError, ValueError):
                previous = {}
            controller.block(parse_rule(rule), proxy=True, kill_states=not previous.get("proxy", False))
            ensure(proxy)
        elif raw_proxy:
            from proxy_service import stop
            if blocked:
                controller.block(parse_rule(rule))
                denial_installed = True
            stop()
        if proxy is None and blocked != (HEADER in hosts):
            raise PFError("Inconsistent staged hosts and PF request")
        addresses = parse_rule(rule) if blocked else []
        if blocked:
            if proxy is not None:
                controller.block(addresses, proxy=True, kill_states=False)
            elif not denial_installed:
                controller.block(addresses)
            # Only configured proxy requests carry the complete resolved route set.
            apply_hosts(strip_section(hosts, HEADER, FOOTER) if proxy is not None else hosts)
        else:
            controller.unblock()
            apply_hosts(hosts)
        status.update(ok=True, blocked=blocked, proxy=proxy is not None)
    except Exception as error:
        if vpn is not None and addresses:
            try:
                controller.block(addresses)
            except Exception:
                pass
        # A failed proxy must get a full deny rule: no TUN or root exemption.
        # Keep the hosts fallback only when PF cannot confirm that denial.
        pf_denial_confirmed = False
        try:
            if vpn is None and blocked:
                controller.block(parse_rule(rule))
                pf_denial_confirmed = True
                apply_hosts(strip_section(hosts, HEADER, FOOTER) if proxy is not None else hosts)
        except Exception:
            if not pf_denial_confirmed and isinstance(proxy, dict):
                domains = proxy.get("domains", [])
                if domains and all(isinstance(d, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", d) for d in domains):
                    denial = HEADER + ''.join("0.0.0.0\t" + d + "\n::1\t" + d + "\n" for d in domains) + FOOTER
                    try:
                        apply_hosts(denial)
                    except Exception:
                        pass
            elif not pf_denial_confirmed and HEADER in hosts:
                try:
                    apply_hosts(hosts)
                except Exception:
                    pass
        status["error"] = str(error)
    atomic_json(controller.directory / "network-status.json", status, mode=0o644)
    if not status["ok"]:
        raise PFError(status["error"])


def main():
    if os.geteuid() != 0:
        raise PFError("The network helper must run as root")
    if len(sys.argv) != 2:
        raise PFError("usage: pf_controller.py <config-dir> | --unblock")
    # The installer creates this root-owned directory. All helper invocations,
    # including uninstall and direct-root operation, share one lock.
    with (SYSTEM_DIR / "network.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        controller = PFController()
        if sys.argv[1] == "--unblock":
            from proxy_service import stop
            stop()
            controller.unblock()
        else:
            apply_request(sys.argv[1], controller)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("ClaudeGuard network helper: " + str(error), file=sys.stderr)
        sys.exit(1)
