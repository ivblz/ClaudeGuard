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
        r"block drop out quick proto \{ tcp, udp \} to <claude_guard>\n", text)
    if not match:
        raise PFError("Invalid ClaudeGuard PF rule")
    addresses = sorted({str(ipaddress.ip_address(ip)) for ip in match[1].split()})
    if not addresses:
        raise PFError("Empty block table")
    return addresses


def make_rule(addresses):
    return ("table <claude_guard> persist { " + " ".join(addresses) + " }\n"
            "block drop out quick proto { tcp, udp } to <claude_guard>\n")


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

    def block(self, addresses):
        # Stage first, so migrating the legacy root rules switches directly to
        # an already populated anchor, without an unprotected interval.
        self.pf("-a", ANCHOR, "-f", "-", input=make_rule(addresses))
        self.ensure_attachment()
        self.enable()
        # Upgrade from the first scoped implementation. It had no private
        # root call; only its child rules/table belong to us.
        self.clear_anchor(PREVIOUS_ANCHOR)
        # States bypass subsequent rule evaluation. Remove only connections to
        # the destinations being blocked; leave every other connection intact.
        for address in addresses:
            network = "::/0" if ipaddress.ip_address(address).version == 6 else "0.0.0.0/0"
            self.pf("-k", network, "-k", address)

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


def apply_hosts(staged):
    merged = merge_hosts(HOSTS_PATH.read_text(), staged)
    # /etc/hosts must keep its existing inode (system services watch it).
    with HOSTS_PATH.open("w") as stream:
        stream.write(merged)
        stream.flush()
        os.fsync(stream.fileno())
    for command in (["/usr/bin/dscacheutil", "-flushcache"],
                    ["/usr/bin/killall", "-HUP", "mDNSResponder"]):
        subprocess.run(command, capture_output=True, timeout=10, check=True)


def apply_request(config_dir, controller):
    directory = Path(config_dir)
    owner = directory.stat().st_uid
    pending = directory / "pending"
    request = trusted_read(pending / "request", owner).strip()
    if not re.fullmatch(r"[0-9a-f]{32}", request):
        raise PFError("Invalid request ID")
    status = {"request": request, "ok": False}
    try:
        hosts = trusted_read(pending / "hosts.tmp", owner)
        rule = trusted_read(pending / "pf.rule", owner, optional=True)
        blocked = rule is not None
        if blocked != (HEADER in hosts):
            raise PFError("Inconsistent staged hosts and PF request")
        addresses = parse_rule(rule) if blocked else []
        if blocked:
            # Retain hosts protection even if PF rejects a custom configuration.
            apply_hosts(hosts)
            controller.block(addresses)
        else:
            controller.unblock()
            apply_hosts(hosts)
        status.update(ok=True, blocked=blocked)
    except Exception as error:
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
            controller.unblock()
        else:
            apply_request(sys.argv[1], controller)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("ClaudeGuard network helper: " + str(error), file=sys.stderr)
        sys.exit(1)
