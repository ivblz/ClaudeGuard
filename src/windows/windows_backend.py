"""Windows Firewall protection and the managed sing-box loopback proxy."""

import base64
import ctypes
from concurrent.futures import ALL_COMPLETED, FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
import hashlib
import http.client
import ipaddress
import json
import ntpath
import os
from pathlib import Path
from queue import Empty, Queue
import re
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

from src.windows.windows_config import CONFIG_PATH, DEFAULT_CONFIG, ConfigManager, validate_whitelist_entry
from src.ip_checker import is_ip_allowed
from src.proxy_config import DEDICATED, PORT, validate
from src.windows.windows_platform import CREATE_NO_WINDOW, api, run_system, system_directory
from src.windows.windows_process_guard import WindowsProcessGuard


LOOPBACK = '127.0.0.1'
PROXY_URL = f'http://{LOOPBACK}:{PORT}'
DNS_DEADLINE = 4
DNS_CACHE_LIMIT = 2048
CHECK_INTERVAL = 3
PROCESS_POLICY_KEYS = ('connection_mode', 'protection_enabled', 'allowed_ips', 'blocked_domains',
                       'proxy_enabled', 'proxy_profile', 'real_claude_app_path', 'real_claude_cli_path')
RULE_GROUP = 'ClaudeGuard (managed)'
RULE_PREFIX = 'ClaudeGuard-750df9b7-'
KNOWN_DOMAINS = frozenset(DEFAULT_CONFIG['blocked_domains']) | {
    'anthropic.ai', 'www.anthropic.ai', 'app.anthropic.ai', 'api.anthropic.ai',
    'auth.anthropic.ai', 'api.claude.ai', 'auth.claude.ai', 'console.claude.ai',
    'console.claude.com', 'code.claude.com', 'desktop-app-updates.anthropic.com',
}
DOMAIN = re.compile(r'(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
                    r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z', re.I | re.ASCII)


class WindowsGuardError(RuntimeError):
    """An actionable error safe to display without exposing proxy credentials."""


def _powershell(script, payload=None, *, message, timeout=40):
    if sys.platform != 'win32':
        raise WindowsGuardError('Windows protection requires Windows 10 or 11.')
    source = ("$ErrorActionPreference = 'Stop'\n"
              "$ProgressPreference = 'SilentlyContinue'\n"
              "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)\n"
              "$inputData = [Console]::In.ReadToEnd() | ConvertFrom-Json\n"
              + script)
    encoded = base64.b64encode(source.encode('utf-16-le')).decode('ascii')
    try:
        result = run_system(
            [r'WindowsPowerShell\v1.0\powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
             '-EncodedCommand', encoded],
            input=json.dumps(payload), encoding='utf-8', errors='replace', timeout=timeout,
        )
        if result.returncode:
            raise WindowsGuardError(message)
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise WindowsGuardError(message) from error


_FIREWALL = r'''
function Get-OwnedRules {
    Get-NetFirewallRule -PolicyStore PersistentStore -Name ($inputData.prefix + '*') |
        Where-Object { $_.Name -match $inputData.pattern -and $_.Group -eq $inputData.group }
}

function Normalize-Address([string]$value) {
    if ($value -eq 'Any') { return 'Any' }
    if ($value -match '-') {
        $first, $last = $value.Split('-')
        return ([string][Net.IPAddress]::Parse($first) + '-' + [Net.IPAddress]::Parse($last))
    }
    $address, $mask = $value.Split('/')
    $ip = [Net.IPAddress]::Parse($address)
    if ($null -eq $mask) { return [string]$ip }
    $width = 8 * $ip.GetAddressBytes().Length
    if ($mask -match '^[0-9]+$') { $bits = [int]$mask }
    else {
        $bits = 0
        foreach ($octet in [Net.IPAddress]::Parse($mask).GetAddressBytes()) {
            $bits += [Convert]::ToString($octet, 2).Replace('0', '').Length
        }
    }
    if ($bits -eq $width) { return [string]$ip }
    return ([string]$ip + '/' + $bits)
}

function Compare-FirewallAddresses($actual, $expected) {
    $actualValues = @($actual | ForEach-Object { Normalize-Address $_ } | Sort-Object -Unique)
    $expectedValues = @($expected | ForEach-Object { Normalize-Address $_ } | Sort-Object -Unique)
    return (($actualValues -join ',') -eq ($expectedValues -join ','))
}

if ($inputData.remove) {
    Get-OwnedRules | Remove-NetFirewallRule
    if (@(Get-OwnedRules).Count -ne 0) { throw 'ClaudeGuard rules remain' }
    return
}

$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
if ($profiles.Count -ne 3 -or @($profiles | Where-Object {
        $_.Enabled -ne 'True' -or $_.AllowLocalFirewallRules -eq 'False'
    }).Count -ne 0) { throw 'Firewall profiles must enforce local policy' }

$owned = @(Get-OwnedRules)
foreach ($spec in $inputData.rules) {
    $rule = @($owned | Where-Object Name -eq $spec.name)
    if ($rule.Count -eq 0) {
        if ($inputData.recentlyVerified) { $inputData.recentlyVerified = $false }
        $application = @{}
        if ($spec.program) { $application.Program = $spec.program }
        New-NetFirewallRule -PolicyStore PersistentStore -Name $spec.name -DisplayName $spec.display `
            -Group $inputData.group -Direction Outbound -Action Block -Enabled True -Profile Any `
            -LocalAddress @($spec.local) -RemoteAddress @($spec.remote) @application | Out-Null
    }
}

$activeRules = @{}
if ($inputData.rules.Count) {
    foreach ($entry in Get-NetFirewallRule -PolicyStore ActiveStore -Name @($inputData.rules.name)) {
        if ($activeRules.ContainsKey($entry.Name)) { throw 'Duplicate active rule' }
        $activeRules[$entry.Name] = $entry
    }
}
# NetSecurity batches a pipeline of associated rules. Results can arrive
# out of order, so join each filter to its active rule by InstanceID.
$filters = @{}
foreach ($type in 'Address', 'Port', 'Application', 'Service', 'Interface', 'InterfaceType', 'Security') {
    $index = @{}
    $cmd = 'Get-NetFirewall' + $type + 'Filter'
    if ($inputData.recentlyVerified) { break }
    foreach ($item in @($activeRules.Values | & $cmd)) {
        if (!$item.InstanceID -or $index.ContainsKey($item.InstanceID)) {
            throw 'Missing or duplicate firewall filter identity'
        }
        $index[$item.InstanceID] = $item
    }
    $filters[$type] = $index
}
foreach ($spec in $inputData.rules) {
    $active = @($activeRules[$spec.name])
    if ($active.Count -ne 1 -or $active[0].Group -ne $inputData.group `
        -or $active[0].Enabled -ne 'True' -or $active[0].Action -ne 'Block' `
        -or $active[0].Direction -ne 'Outbound' -or $active[0].Profile -ne 'Any' `
        -or $active[0].PrimaryStatus -ne 'OK') { throw 'ClaudeGuard rule is not active' }
    if ($inputData.recentlyVerified) { continue }
    $rule = $active[0]
    $id = $rule.InstanceID
    foreach ($index in $filters.Values) {
        if (!$index.ContainsKey($id)) { throw 'An active firewall filter is missing' }
    }
    $address = $filters.Address[$id]
    $port = $filters.Port[$id]
    $app = $filters.Application[$id]
    $service = $filters.Service[$id]
    $interface = $filters.Interface[$id]
    $interfaceType = $filters.InterfaceType[$id]
    $security = $filters.Security[$id]
    $program = if ($spec.program) { $spec.program } else { 'Any' }
    $actualProgram = ([string]$app.Program).Replace('/', '\')
    if (!(Compare-FirewallAddresses $address.LocalAddress $spec.local) `
        -or !(Compare-FirewallAddresses $address.RemoteAddress $spec.remote) `
        -or $port.Protocol -ne 'Any' -or $port.LocalPort -ne 'Any' -or $port.RemotePort -ne 'Any' `
        -or $port.IcmpType -ne 'Any' -or $port.DynamicTarget -ne 'Any' `
        -or ![StringComparer]::OrdinalIgnoreCase.Equals($actualProgram, $program) `
        -or $app.Package -or $service.Service -ne 'Any' `
        -or ($interface.InterfaceAlias -join ',') -ne 'Any' `
        -or ($interfaceType.InterfaceType -join ',') -ne 'Any' `
        -or $security.Authentication -ne 'NotRequired' -or $security.Encryption -ne 'NotRequired' `
        -or $security.LocalUser -ne 'Any' -or $security.RemoteUser -ne 'Any' `
        -or $security.RemoteMachine -ne 'Any' -or $security.OverrideBlockRules -ne $false) {
        throw 'ClaudeGuard rule has unexpected filters'
    }
}

# Create and verify the replacement rules before removing any older protection.
if (!$inputData.preserveOlder) {
    $keep = @($inputData.rules | ForEach-Object { $_.name })
    $obsolete = @($owned | Where-Object { $_.Name -notin $keep })
    if ($obsolete.Count -ne 0) {
        $obsolete | Remove-NetFirewallRule
        if (@(Get-OwnedRules | Where-Object { $_.Name -notin $keep }).Count -ne 0) {
            throw 'Previous ClaudeGuard rules remain'
        }
    }
}
'''


def _address_complement(value):
    """Windows Firewall source ranges that cover every address except value."""
    address = ipaddress.ip_address(value)
    first = type(address)(0)
    last = type(address)(2 ** address.max_prefixlen - 1)
    ranges = []
    if address > first:
        ranges.append(str(first) if address == first + 1 else f'{first}-{address - 1}')
    if address < last:
        ranges.append(str(last) if address == last - 1 else f'{address + 1}-{last}')
    return ranges


def _rule_spec(family, local, remote, *, program=None):
    scope = [family, local, remote]
    if program is not None:
        scope.append(program)
    fingerprint = hashlib.sha256(json.dumps(scope).encode()).hexdigest()[:24]
    display = 'app protection' if program is not None else 'outbound protection'
    spec = {'name': f'{RULE_PREFIX}{family}-{fingerprint}',
            'display': f'ClaudeGuard {display} (IPv{family})',
            'local': local, 'remote': remote}
    if program is not None:
        spec['program'] = program
    return spec


def _rule_specs(targets, sources):
    rules = []
    networks = [ipaddress.ip_network(value) for value in targets]
    for family in (4, 6):
        remote = sorted({str(network.network_address) if network.num_addresses == 1 else str(network)
                         for network in ipaddress.collapse_addresses(
                             network for network in networks if network.version == family)})
        local = _address_complement(sources[family]) if family in sources else ['Any']
        rules.append(_rule_spec(family, local, remote))
    return rules


def _program_rule_specs(programs, sources, proxy):
    programs = sorted({ntpath.normcase(ntpath.normpath(program)) for program in programs})
    # Each remote scope must match only its own address family, including when
    # a VPN check can verify one family and the other remains blocked.
    destinations = {
        4: ['0.0.0.0/1', '128.0.0.0/1'],
        6: ['::/1', '8000::/1'],
    }
    if proxy:
        destinations = {
            4: ['0.0.0.0-126.255.255.255', '128.0.0.0-255.255.255.255'],
            6: ['::', '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'],
        }
    rules = []
    for family, remote in destinations.items():
        local = _address_complement(sources[family]) if not proxy and family in sources else ['Any']
        rules.extend(_rule_spec(family, local, remote, program=program) for program in programs)
    return rules


class WindowsFirewall:
    def __init__(self):
        self._confirmed = None
        self._staged = None
        self._audit_after = 0

    def apply(self, targets, sources, *, preserve_older=False, programs=(), proxy=False, stage_proxy=False):
        rules = [*_rule_specs(targets, sources), *_program_rule_specs(programs, sources, proxy)]
        names = tuple(rule['name'] for rule in rules)
        if not preserve_older and names == self._confirmed and time.monotonic() < self._audit_after:
            return
        recently_verified = names == self._staged and time.monotonic() < self._audit_after
        self._confirmed = self._staged = None
        if stage_proxy and programs:
            # Install and verify the loopback-only policy under the full block.
            # TLS verification must succeed before the full block can be removed.
            candidate = _program_rule_specs(programs, {}, True)
            final_names = tuple(rule['name'] for rule in [*rules[:2], *candidate])
            self._run(rules=[*rules, *candidate], preserve_older=True)
            self._staged = final_names
            self._audit_after = time.monotonic() + 15
            return
        self._run(rules=rules, preserve_older=preserve_older, recently_verified=recently_verified)
        if not preserve_older:
            self._confirmed = names
            if not recently_verified:
                self._audit_after = time.monotonic() + 15

    def remove(self):
        self._confirmed = self._staged = None
        self._run(remove=True)

    def _run(self, *, rules=None, remove=False, preserve_older=False, recently_verified=False):
        _powershell(_FIREWALL, {
            'rules': rules, 'remove': remove, 'group': RULE_GROUP, 'preserveOlder': preserve_older,
            'recentlyVerified': recently_verified, 'prefix': RULE_PREFIX, 'pattern': '^' + re.escape(RULE_PREFIX) + '[46]-[0-9a-f]{24}$',
        }, message=('Could not remove ClaudeGuard firewall rules. Run ClaudeGuard as Administrator.'
                    if remove else 'Could not confirm Windows Firewall protection. Run as Administrator '
                    'and enable Windows Firewall and local firewall rules for every profile.'))


_STRONG_HOST = r'''
$interfaces = @(Get-NetIPInterface -PolicyStore ActiveStore)
$families = @(
    foreach ($family in 4, 6) {
        $group = @($interfaces | Where-Object AddressFamily -eq ('IPv' + $family))
        if ($group.Count -ne 0 -and !($group | Where-Object WeakHostSend -ne 'Disabled')) {
            $family
        }
    }
)
ConvertTo-Json -Compress -InputObject $families
'''


def _strong_host_families():
    result = _powershell(_STRONG_HOST, message='Could not verify Windows interface routing settings.')
    eligible = json.loads(result)
    return {family for family in (4, 6) if family in eligible}


_PRIVATE_ACL = r'''
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
foreach ($path in $inputData.paths) {
    $item = Get-Item -LiteralPath $path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'ClaudeGuard path is a reparse point'
    }
    $acl = $item.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRuleSpecific($rule) }
    foreach ($principal in @($user, $system, $administrators)) {
        $inherit = if ($item.PSIsContainer) { 'ContainerInherit, ObjectInherit' } else { 'None' }
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $principal, 'FullControl', $inherit, 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    $item.SetAccessControl($acl)
}
'''


def _private_paths(paths):
    _powershell(_PRIVATE_ACL, {'paths': [str(path) for path in paths]},
                message='Could not secure the Windows configuration and proxy runtime files.')


def _public_exit(family):
    """Return (remote public exit, local source) from a direct, verified TLS connection."""
    address_family = socket.AF_INET if family == 4 else socket.AF_INET6
    host = 'api.ipify.org' if family == 4 else 'api6.ipify.org'
    context = ssl.create_default_context()
    try:
        endpoints = socket.getaddrinfo(host, 443, address_family, socket.SOCK_STREAM)
    except OSError:
        return None
    for af, kind, protocol, _, sockaddr in endpoints[:2]:
        try:
            with socket.socket(af, kind, protocol) as raw:
                raw.settimeout(2.0)
                raw.connect(sockaddr)
                local = ipaddress.ip_address(raw.getsockname()[0].split('%')[0])
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    tls.sendall((f'GET / HTTP/1.1\r\nHost: {host}\r\n'
                                 'Connection: close\r\nUser-Agent: ClaudeGuard\r\n\r\n').encode('ascii'))
                    with http.client.HTTPResponse(tls) as response:
                        response.begin()
                        if response.status == 200:
                            public = ipaddress.ip_address(response.read(64).decode('ascii').strip())
                            if public.version == family and public.is_global and not local.is_loopback:
                                return str(public), str(local)
        except (OSError, ValueError, http.client.HTTPException):
            continue
    return None


class _DnsRecord(ctypes.Structure):
    pass


_DnsRecordPtr = ctypes.POINTER(_DnsRecord)
_DnsRecord._fields_ = [
    ('next', _DnsRecordPtr), ('name', ctypes.c_void_p), ('kind', ctypes.c_uint16),
    ('length', ctypes.c_uint16), ('flags', ctypes.c_uint32), ('ttl', ctypes.c_uint32),
    ('reserved', ctypes.c_uint32), ('data', ctypes.c_ubyte * 16),
]


def _resolve(host):
    query = api('dnsapi', 'DnsQuery_W', ctypes.c_long, ctypes.c_wchar_p, ctypes.c_uint16,
                ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(_DnsRecordPtr), ctypes.c_void_p)
    free = api('dnsapi', 'DnsFree', None, ctypes.c_void_p, ctypes.c_int)
    addresses = set()
    for kind, size in ((1, 4), (28, 16)):
        head = _DnsRecordPtr()
        try:
            # Use the configured DNS servers without resolver cache, NetBIOS,
            # suffix search or link-local multicast for these public FQDNs.
            options = 0x8 | 0x80 | 0x800 | 0x1000
            # TCP avoids dropped UDP negative answers on filtered networks.
            status = query(host + '.', kind, options | 0x2, None, ctypes.byref(head), None)
            if status not in (0, 9003, 9501):
                if head:
                    free(head, 1)
                    head = _DnsRecordPtr()
                status = query(host + '.', kind, options, None, ctypes.byref(head), None)
            if status == 9003:  # NXDOMAIN applies to every record type.
                return addresses
            if status == 9501:  # NOERROR without records of this type.
                continue
            if status:
                return None
            cursor = head
            while cursor:
                record = cursor.contents
                if record.kind == kind and record.length == size and record.flags & 3 == 1:
                    address = ipaddress.ip_address(bytes(record.data[:size]))
                    if address.is_global and not address.is_multicast and not getattr(address, 'ipv4_mapped', None):
                        addresses.add(str(address))
                cursor = record.next
        finally:
            if head:
                free(head, 1)  # DnsFreeRecordList
    return addresses


class _NetworkChecks:
    def __init__(self, max_workers):
        self.max_workers = max_workers
        self.jobs = Queue()
        self.workers = 0
        self.pending = {}

    def _worker(self):
        while (job := self.jobs.get()) is not None:
            future, function, value = job
            if future.set_running_or_notify_cancel():
                try:
                    future.set_result(function(value))
                except BaseException as error:
                    future.set_exception(error)

    def run(self, function, values, timeout, *, enough=None):
        jobs = {}
        self.pending = {key: future for key, future in self.pending.items() if not future.done()}
        for value in values:
            key = (function, value)
            if key in self.pending:
                continue  # A pending result belongs to an earlier check.
            if key not in self.pending:
                future = self.pending[key] = Future()
                self.jobs.put((future, function, value))
            jobs[self.pending[key]] = value
        # Windows name resolution can outlast the caller's deadline. Daemon
        # workers let the process exit even if a system lookup never returns.
        while self.workers < min(self.max_workers, len(self.pending)):
            threading.Thread(target=self._worker, daemon=True).start()
            self.workers += 1
        deadline = time.monotonic() + timeout
        results = {}
        waiting = set(jobs)
        while waiting:
            done, waiting = wait(waiting, timeout=max(0, deadline - time.monotonic()),
                                 return_when=FIRST_COMPLETED if enough else ALL_COMPLETED)
            results.update((jobs[future], future.result()) for future in done)
            if not done or time.monotonic() >= deadline or (enough and enough(results)):
                break
        for future in waiting:
            future.cancel()
        # Remove canceled queued jobs even if every worker is still in a lookup.
        while True:
            try:
                self.jobs.get_nowait()
            except Empty:
                break
        return results

    def close(self):
        for _ in range(self.workers):
            self.jobs.put(None)


def _proxy_config(profile):
    outbound = validate(profile)
    outbound['tag'] = 'proxy'
    return {
        'log': {'disabled': True},
        'dns': {'servers': [{'type': 'local', 'tag': 'local'}]},
        'inbounds': [{'type': 'mixed', 'tag': 'claudeguard', 'listen': LOOPBACK, 'listen_port': PORT}],
        'outbounds': [outbound],
        'route': {'default_domain_resolver': 'local', 'final': 'proxy'},
    }


def _engine_path(explicit=None):
    if getattr(sys, 'frozen', False):
        candidate = Path(sys.executable).resolve().with_name('sing-box.exe')
    else:
        selected = explicit or os.environ.get('CLAUDEGUARD_SING_BOX')
        candidate = (Path(selected).expanduser().resolve() if selected else
                     Path(__file__).resolve().parents[2] / 'bin' / 'sing-box.exe')
        if selected and not candidate.is_file():
            raise WindowsGuardError('The configured sing-box executable does not exist.')
    if candidate.is_file():
        return candidate
    raise WindowsGuardError('sing-box.exe is missing from the ClaudeGuard installation.')


def _proxy_exit():
    # CONNECT explicitly to the local listener, independently of system and
    # environment proxy settings. TLS authenticates the exit check endpoint.
    connection = http.client.HTTPSConnection(LOOPBACK, PORT, timeout=4)
    try:
        connection.set_tunnel('api.ipify.org', 443)
        connection.request('GET', '/', headers={'User-Agent': 'ClaudeGuard', 'Connection': 'close'})
        with connection.getresponse() as response:
            data = response.read(64).decode('ascii').strip() if response.status == 200 else ''
            ip = ipaddress.ip_address(data)
            if ip.is_global:
                return str(ip)
    except (OSError, http.client.HTTPException, ValueError):
        pass
    finally:
        connection.close()
    raise WindowsGuardError('The configured proxy did not pass the HTTPS exit check.')


def _is_proxy_owner(process):
    if process.poll() is not None:
        return False
    dword = ctypes.c_uint32
    get_table = api("iphlpapi", "GetExtendedTcpTable", dword, ctypes.c_void_p,
                    ctypes.POINTER(dword), ctypes.c_int, dword, dword, dword)
    size = dword(4096)
    for _ in range(3):
        table = ctypes.create_string_buffer(size.value)
        # TCP_TABLE_OWNER_PID_LISTENER contains IPv4 listeners and their PIDs.
        result = get_table(table, ctypes.byref(size), False, socket.AF_INET, 3, 0)
        if result == 122:  # ERROR_INSUFFICIENT_BUFFER
            continue
        if result:
            raise WindowsGuardError('Could not verify ownership of the local proxy port.')
        count, = struct.unpack_from('<I', table)
        row = struct.Struct('<I4sIIII')
        owners = []
        for index in range(count):
            _, address, port, _, _, pid = row.unpack_from(table, 4 + index * row.size)
            if address == socket.inet_aton(LOOPBACK) and port & 0xffff == socket.htons(PORT):
                owners.append(pid)
        return owners == [process.pid]
    raise WindowsGuardError('Could not read a stable TCP listener table.')


def _atomic_json(path, value):
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.runtime-', suffix='.json')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, separators=(',', ':'))
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _engine_job(process):
    """Keep sing-box tied to ClaudeGuard, including a forced ClaudeGuard exit."""
    import ctypes
    from ctypes import wintypes

    class JobLimits(ctypes.Structure):
        _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64),
                    ('flags', wintypes.DWORD), ('min_memory', ctypes.c_size_t),
                    ('max_memory', ctypes.c_size_t), ('active_processes', wintypes.DWORD),
                    ('affinity', ctypes.c_size_t), ('priority', wintypes.DWORD),
                    ('scheduling', wintypes.DWORD)]

    class ExtendedJobLimits(ctypes.Structure):
        _fields_ = [('limits', JobLimits), ('io', ctypes.c_uint64 * 6),
                    ('process_memory', ctypes.c_size_t), ('job_memory', ctypes.c_size_t),
                    ('peak_process_memory', ctypes.c_size_t), ('peak_job_memory', ctypes.c_size_t)]

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                wintypes.LPVOID, wintypes.DWORD]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL

    job = kernel.CreateJobObjectW(None, None)
    if job:
        limits = ExtendedJobLimits()
        limits.limits.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        # Popen already holds a Windows process handle. Reopening the process
        # by PID could attach a different process if the original exits.
        if kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            if kernel.AssignProcessToJobObject(job, int(process._handle)):
                def close():
                    if not kernel.CloseHandle(job):
                        raise ctypes.WinError(ctypes.get_last_error())
                return close
        kernel.CloseHandle(job)
    raise WindowsGuardError('Could not attach sing-box to the ClaudeGuard process lifetime.')


class WindowsGuard:
    """Synchronize the saved configuration and expose a status snapshot to the tray."""

    def __init__(self, config_path=None, engine_path=None, *, process_guard=None):
        self.config_path = Path(config_path or CONFIG_PATH).expanduser().absolute()
        self.runtime = self.config_path.parent / 'windows-runtime'
        self.engine_path = engine_path
        self._firewall = WindowsFirewall()
        self._operation = threading.RLock()
        self._process_guard = WindowsProcessGuard() if process_guard is None else process_guard
        self._process_state_lock = threading.Lock()
        self._process_scan_lock = threading.Lock()
        self._process_generation = 0
        self._process_suspended = False
        self._process_verdict = None
        self._block_episode = 0
        self._desktop_closed = self._cli_closed = 0
        self._process_error = None
        self._runtime_ready = False
        self._targets = set(DEDICATED)
        self._programs = ()
        self._programs_ready = False
        self._domains = set(KNOWN_DOMAINS)
        self._dns_cache = {}
        self._dns_checks = _NetworkChecks(16)
        self._resolver = ThreadPoolExecutor(max_workers=1)
        self._ip_checks = _NetworkChecks(2)
        self._process = None
        self._close_job = None
        self._profile = None
        self._protection_enabled = False
        self._mode = 'vpn'
        self._policy_key = None
        self._closed = False
        self._publish('checking')

    def status(self):
        return self._status.copy()

    @staticmethod
    def _process_policy(settings):
        return json.dumps({key: settings.get(key, DEFAULT_CONFIG[key]) for key in PROCESS_POLICY_KEYS},
                          sort_keys=True)

    def _update_status(self):
        errors = (self._network_status['error'], self._process_error)
        self._status = {
            **self._network_status,
            'error': ' '.join(filter(None, errors)) or None,
            'protected': self._network_status['protected'] and self._process_error is None,
            'block_episode': self._process_verdict[1] if self._process_verdict else None,
            'desktop_closed': self._desktop_closed,
            'cli_closed': self._cli_closed,
            'process_enforcement_error': self._process_error,
        }

    def _set_process_verdict(self, policy):
        if self._process_verdict and self._process_verdict[0] == policy:
            return
        if policy is not None:
            self._block_episode += 1
        self._process_verdict = (policy, self._block_episode) if policy is not None else None
        self._desktop_closed = self._cli_closed = 0
        self._process_error = None

    def invalidate_process_verdict(self):
        """Suspend process enforcement before a settings write or quit."""
        with self._process_state_lock:
            self._process_generation += 1
            self._process_suspended = True
            self._set_process_verdict(None)
            self._update_status()

    def resume_process_verdict(self):
        """Allow a new network check to authorize process enforcement."""
        with self._process_state_lock:
            self._process_generation += 1
            self._process_suspended = False

    def _clear_process_verdict(self):
        with self._process_state_lock:
            self._set_process_verdict(None)
            self._update_status()

    def _process_verdict_is_current(self, verdict):
        if self._process_verdict is not verdict:
            return False
        try:
            settings = json.loads(self.config_path.read_text(encoding='utf-8'))
            if not isinstance(settings, dict) or self._process_policy(settings) != verdict[0]:
                return False
        except (OSError, ValueError):
            return False
        return self._process_verdict is verdict

    def enforce_processes(self):
        """Reapply the current confirmed block to newly started Claude processes."""
        verdict = self._process_verdict
        if verdict is None or not self._process_scan_lock.acquire(blocking=False):
            return self.status()
        try:
            def current():
                return self._process_verdict_is_current(verdict)

            if not current():
                return self.status()
            try:
                report = self._process_guard.enforce(json.loads(verdict[0]), self.status(), should_enforce=current)
                desktop_closed, cli_closed, error = report.desktop_closed, report.cli_closed, report.error
            except (OSError, RuntimeError, subprocess.SubprocessError):
                desktop_closed = cli_closed = 0
                error = 'Could not verify that Claude processes were closed.'
            with self._process_state_lock:
                if self._process_verdict is verdict:
                    self._desktop_closed += desktop_closed
                    self._cli_closed += cli_closed
                    self._process_error = error
                    self._update_status()
        finally:
            self._process_scan_lock.release()
        return self.status()

    def _publish(self, state, *, protected=False, ip=None, error=None, proxy_url=None, families=(),
                 process_context=None):
        with self._process_state_lock:
            self._network_status = {
                'mode': self._mode, 'state': state, 'ip': ip, 'error': error,
                'protection_enabled': self._protection_enabled, 'protected': protected,
                'proxy_url': proxy_url, 'check_interval': CHECK_INTERVAL, 'verified_families': tuple(families),
            }
            policy = None
            if state == 'blocked' and self._protection_enabled and process_context and not self._process_suspended:
                generation, settings = process_context
                if generation == self._process_generation:
                    policy = self._process_policy(settings)
            self._set_process_verdict(policy)
            self._update_status()
        return self.status()

    def _prepare_runtime(self):
        if self._runtime_ready:
            return
        for path in (self.runtime, *self.runtime.parents):
            try:
                attributes = getattr(path.stat(follow_symlinks=False), 'st_file_attributes', 0)
                if attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    raise WindowsGuardError('ClaudeGuard cannot store settings through a Windows reparse point.')
            except FileNotFoundError:
                continue
        self.runtime.mkdir(parents=True, exist_ok=True)
        owned = [self.runtime]
        if self.config_path == Path(CONFIG_PATH).absolute():
            owned.insert(0, self.config_path.parent)
            if self.config_path.exists():
                owned.append(self.config_path)
        cache_file = self.runtime / 'dns.json'
        if cache_file.exists():
            owned.append(cache_file)
        _private_paths(owned)
        # Remove interrupted writes owned by the runtime directory.
        for path in self.runtime.glob('.runtime-*.json'):
            path.unlink()
        try:
            data = json.loads(cache_file.read_text(encoding='utf-8'))
            if isinstance(data, dict):
                for host, addresses in data.items():
                    if DOMAIN.fullmatch(host) and isinstance(addresses, list):
                        self._dns_cache[host] = self._valid_addresses(addresses)
        except (OSError, ValueError):
            pass
        self._set_targets()
        self._runtime_ready = True

    def prepare(self):
        """Create the private configuration and runtime directories before opening the UI."""
        with self._operation:
            self._prepare_runtime()

    @staticmethod
    def _valid_addresses(values):
        addresses = set()
        for value in values:
            try:
                address = ipaddress.ip_address(value)
                if address.is_global and not address.is_multicast and not getattr(address, 'ipv4_mapped', None):
                    addresses.add(str(address))
            except (TypeError, ValueError):
                continue
        return addresses

    def _read_domains(self, configured):
        if not isinstance(configured, list) or len(configured) > 256:
            raise WindowsGuardError('Configure up to 256 protected domains.')
        domains = set(KNOWN_DOMAINS)
        for value in configured:
            if not isinstance(value, str) or not DOMAIN.fullmatch(value.rstrip('.')):
                raise WindowsGuardError('A protected domain is invalid.')
            domains.add(value.rstrip('.').lower())
        return domains

    def _set_targets(self):
        targets = set(DEDICATED)
        for host in self._domains:
            targets.update(self._dns_cache.get(host, ()))
        if len(targets) > DNS_CACHE_LIMIT:
            raise WindowsGuardError('Too many resolved protected addresses.')
        self._targets = targets

    def _refresh_targets(self, resolved):
        new_cache = {host: self._dns_cache.get(host, set()) | resolved.get(host, set())
                     for host in self._domains}
        if sum(len(addresses) for addresses in new_cache.values()) > DNS_CACHE_LIMIT:
            # Do not discard addresses to make room for a new answer. Keep the
            # last complete snapshot and require the blocked state on overflow.
            raise WindowsGuardError('Too many resolved protected addresses.')
        self._dns_cache = new_cache
        previous = self._targets
        self._set_targets()
        if self._targets == previous:
            return False
        _atomic_json(self.runtime / 'dns.json', {host: sorted(values) for host, values in new_cache.items()})
        return True

    def _stop_proxy(self):
        self._profile = None
        try:
            if self._close_job:
                self._close_job()
                self._close_job = None
            elif self._process is not None and self._process.poll() is None:
                self._process.terminate()
            if self._process is not None:
                self._process.wait(timeout=5)
                self._process = None
        except (OSError, subprocess.SubprocessError) as error:
            raise WindowsGuardError('Could not stop the local sing-box process.') from error

    def _start_proxy(self, profile):
        self._stop_proxy()
        executable = _engine_path(self.engine_path)
        data = json.dumps(_proxy_config(profile)).encode('utf-8')
        if len(data) > 262144:
            raise WindowsGuardError('The configured proxy profile is too large.')
        system = system_directory()
        environment = {'SystemRoot': str(system.parent), 'WINDIR': str(system.parent), 'PATH': str(system)}
        try:
            self._process = subprocess.Popen(
                [str(executable), 'run', '-c', 'stdin'], cwd=executable.parent, env=environment,
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=CREATE_NO_WINDOW,
            )
            self._close_job = _engine_job(self._process)
            # Feed the validated config directly. No intermediate plaintext
            # profile is left behind or editable before the engine reads it.
            with self._process.stdin as pipe:
                pipe.write(data)
            self._profile = profile
        except OSError as error:
            raise WindowsGuardError('Could not start sing-box.exe.') from error

    def _proxy_address(self, settings):
        profile = validate(settings['proxy_profile'])
        started = profile != self._profile or self._process is None or self._process.poll() is not None
        if started:
            self._start_proxy(profile)
        deadline = time.monotonic() + 3
        while not _is_proxy_owner(self._process):
            if not started or self._process.poll() is not None or time.monotonic() >= deadline:
                raise WindowsGuardError('sing-box could not open the local proxy port.')
            time.sleep(0.05)
        address = _proxy_exit()
        if self._process.poll() is not None:
            raise WindowsGuardError('The local sing-box process stopped unexpectedly.')
        return address

    def _vpn_verdict(self, whitelist):
        trusted_families = {ipaddress.ip_network(entry, strict=False).version for entry in whitelist}

        def enough(results):
            return any(results.values()) and trusted_families.issubset(results)

        observed = self._ip_checks.run(_public_exit, (4, 6), 3, enough=enough)
        exits = {family: result for family, result in observed.items() if result}
        if not exits:
            return 'offline', None, {}, 'The public exit could not be verified.'
        matches = {family: result for family, result in exits.items() if is_ip_allowed(result[0], whitelist)}
        eligible = _strong_host_families() if matches else set()
        verified = {family: result for family, result in matches.items() if family in eligible}
        if verified:
            sources = {family: result[1] for family, result in verified.items()}
            return 'allowed', verified[min(verified)][0], sources, None
        error = ('Add a trusted public IP or CIDR to allow the VPN route.' if not whitelist else
                 'No public exit was verified for an eligible Windows network route.')
        return 'blocked', exits[min(exits)][0], {}, error

    def _apply_firewall(self, sources, **options):
        if self._programs:
            options['programs'] = self._programs
        self._firewall.apply(self._targets, sources, **options)

    def _recover(self, error, decision, ip, process_context, untested_whitelist):
        self._policy_key = None
        if not self._protection_enabled:
            return self._publish('error', error='Could not disable Windows protection.')

        public_error = (str(error) if isinstance(error, (WindowsGuardError, ValueError)) else
                        'ClaudeGuard could not read or apply the Windows settings.')
        firewall_inputs_ready = self._runtime_ready and self._programs_ready
        protected = firewall_inputs_ready
        try:
            self._stop_proxy()
        except (OSError, WindowsGuardError):
            public_error = 'Could not confirm the local proxy stopped.'
            protected = False
        try:
            self._apply_firewall({}, preserve_older=not firewall_inputs_ready)
        except (OSError, WindowsGuardError) as firewall_error:
            public_error = (str(firewall_error) if isinstance(firewall_error, WindowsGuardError) else
                            'Could not confirm Windows protection.')
            protected = False

        if untested_whitelist is not None:
            try:
                decision, ip, _, _ = self._vpn_verdict(untested_whitelist)
            except (OSError, subprocess.SubprocessError, WindowsGuardError, TypeError, ValueError):
                pass
        if decision == 'blocked' or (decision == 'offline' and protected):
            return self._publish(decision, protected=protected, ip=ip, error=public_error,
                                 process_context=process_context)
        return self._publish('error', error=public_error, ip=ip)

    def tick(self, *, enforce_processes=True):
        """Check the connection and optionally enforce the result in this caller."""
        status = self._check_connection()
        if enforce_processes and status['block_episode'] is not None:
            return self.enforce_processes()
        return status

    def _check_connection(self):
        with self._operation:
            if self._closed:
                return self.status()
            self._protection_enabled = True
            with self._process_state_lock:
                generation = self._process_generation
            process_context = None
            untested_whitelist = None
            decision = ip = None
            try:
                self._prepare_runtime()
                settings = ConfigManager(self.config_path).config
                self._mode = 'proxy' if settings.get('connection_mode') == 'proxy' else 'vpn'
                self._protection_enabled = settings.get('protection_enabled') is not False
                if not self._protection_enabled:
                    return self.disable()
                process_context = generation, settings
                if self._mode == 'proxy':
                    decision = 'blocked'
                self._programs_ready = False
                self._programs = tuple(self._process_guard.approved_program_paths(settings))
                self._programs_ready = True

                whitelist = ()
                if self._mode == 'vpn':
                    untested_whitelist = ()
                    configured = settings.get('allowed_ips', [])
                    if not isinstance(configured, list) or not all(isinstance(ip, str) for ip in configured):
                        raise WindowsGuardError('The VPN whitelist is invalid.')
                    whitelist = untested_whitelist = tuple(validate_whitelist_entry(ip) for ip in configured)

                domains = self._read_domains(settings.get('blocked_domains', []))
                self._domains = domains
                self._set_targets()
                proxy_policy = None
                if self._mode == 'proxy':
                    proxy_policy = (settings.get('proxy_enabled'), settings.get('proxy_profile'))
                policy_key = (self._mode, frozenset(domains), whitelist, self._programs, proxy_policy)
                proxy_verified = (self._mode == 'proxy' and self._network_status['state'] == 'allowed'
                                  and self._process is not None and self._process.poll() is None)
                blanket_applied = (policy_key != self._policy_key
                                   or (self._mode == 'proxy' and not proxy_verified))
                stage = (self._mode == 'proxy' and settings.get('proxy_enabled') is True
                         and bool(settings.get('proxy_profile')) and bool(self._programs))
                blanket_options = {'stage_proxy': True} if stage else {}
                answers = self._resolver.submit(self._dns_checks.run, _resolve, sorted(domains), DNS_DEADLINE)
                try:
                    if blanket_applied:
                        self._apply_firewall({}, **blanket_options)
                finally:
                    resolved = answers.result()
                valid = {host: ips for host, ips in resolved.items() if ips is not None}
                refreshed_targets = self._refresh_targets(valid)
                if valid.keys() != domains:
                    decision, untested_whitelist = 'offline', None
                    raise WindowsGuardError('DNS verification did not complete for all protected domains.')
                if self._mode == 'vpn':
                    self._stop_proxy()
                if refreshed_targets and (self._mode != 'proxy' or blanket_applied):
                    self._apply_firewall({}, **blanket_options)
                    blanket_applied = True
                self._policy_key = policy_key

                if self._mode == 'proxy':
                    if settings.get('proxy_enabled') is not True or not settings.get('proxy_profile'):
                        self._stop_proxy()
                        return self._publish('blocked', protected=True, error='Configure and enable a proxy to connect.',
                                             process_context=process_context)
                    ip = self._proxy_address(settings)
                    self._clear_process_verdict()
                    if self._programs or not blanket_applied or refreshed_targets:
                        self._apply_firewall({}, proxy=True)
                    return self._publish('allowed', protected=True, ip=ip, proxy_url=PROXY_URL)

                untested_whitelist = None
                decision, ip, sources, error = self._vpn_verdict(whitelist)
                if decision != 'blocked':
                    self._clear_process_verdict()
                if sources or not blanket_applied:
                    self._apply_firewall(sources)
                return self._publish(decision, protected=True, ip=ip, error=error, families=sorted(sources),
                                     process_context=process_context)
            except (OSError, subprocess.SubprocessError, WindowsGuardError, TypeError, ValueError) as error:
                return self._recover(error, decision, ip, process_context, untested_whitelist)

    def disable(self):
        """Stop this guard's proxy and remove its machine-wide firewall rules."""
        with self._operation:
            self._clear_process_verdict()
            self._stop_proxy()
            self._firewall.remove()
            self._policy_key = None
            self._protection_enabled = False
            return self._publish('disabled')

    def close(self):
        """Leave protected destinations and approved apps blocked, then close the local proxy."""
        self.invalidate_process_verdict()
        with self._operation:
            if self._closed:
                return
            try:
                if self._protection_enabled:
                    self._apply_firewall({}, preserve_older=(self._mode == 'proxy' or not (self._runtime_ready and self._programs_ready)))
                    self._publish('blocked', protected=True)
            finally:
                self._closed = True
                self._resolver.shutdown(wait=True)
                self._dns_checks.close()
                self._ip_checks.close()
                self._stop_proxy()
