"""Root-owned sing-box lifecycle. Called under the network helper's lock."""
import hashlib
import ipaddress
import json
import plistlib
import socket
import subprocess
import time
from pathlib import Path

import trace_timing as trace

from proxy_config import engine_config, INTERFACE, PORT

ROOT = Path('/Library/Application Support/ClaudeGuard')
PLIST = Path('/Library/LaunchDaemons/com.claudeguard.proxy.plist')
LABEL = 'system/com.claudeguard.proxy'

@trace.stage("macos.command.timeout_20s")
def run(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, timeout=20, check=check)

@trace.stage("engine.stop")
@trace.stage("routes.teardown.engine_owned")
def stop():
    stopped = run('/bin/launchctl', 'bootout', LABEL, check=False)
    if stopped.returncode and run('/bin/launchctl', 'print', LABEL, check=False).returncode == 0:
        raise RuntimeError('Could not stop ClaudeGuard proxy service; firewall protection retained')
    polling = trace.begin() if trace.enabled else None
    deadline = time.monotonic() + 5
    while run('/bin/launchctl', 'print', LABEL, check=False).returncode == 0:
        if time.monotonic() >= deadline:
            raise RuntimeError('Proxy service is still stopping; retry shortly')
        time.sleep(0.1)
    if trace.enabled:
        trace.end(polling, "macos.stop.poll_100ms_deadline_5s")
    PLIST.unlink(missing_ok=True)
    (ROOT / 'proxy-fingerprint').unlink(missing_ok=True)

def route_conflicts(output, requested):
    fields = {}
    for line in output.splitlines():
        if ':' in line:
            key, value = line.strip().split(':', 1)
            fields[key] = value.strip()
    destination = fields.get('destination', '')
    flags = fields.get('flags', '')
    if destination in {'', 'default'} or 'WASCLONED' in flags or fields.get('interface') == INTERFACE:
        return False
    try:
        if '/' in destination:
            existing = ipaddress.ip_network(destination, strict=False)
        else:
            if ':' not in destination:
                destination += '.0' * (4 - len(destination.split('.')))
            address = ipaddress.ip_address(destination)
            mask = fields.get('mask')
            prefix = address.max_prefixlen
            if mask and mask != 'default':
                bits = bin(int(ipaddress.ip_address(mask)))[2:].zfill(address.max_prefixlen)
                if '01' in bits:
                    raise ValueError('Non-contiguous route mask')
                prefix = bits.count('1')
            existing = ipaddress.ip_network(str(address) + '/' + str(prefix), strict=False)
        return existing == ipaddress.ip_network(requested)
    except ValueError:
        raise RuntimeError('Could not inspect an existing route safely')


@trace.stage("engine.ensure")
def ensure(request):
    addresses = [str(ipaddress.ip_address(a)) for a in request['addresses']]
    config = engine_config(request['profile'], addresses, request['domains'])
    content = json.dumps(config, sort_keys=True)
    fingerprint = hashlib.sha256(content.encode()).hexdigest()
    stamp = ROOT / 'proxy-fingerprint'
    status = run('/bin/launchctl', 'print', LABEL, check=False)
    if stamp.exists() and stamp.read_text() == fingerprint and 'state = running' in status.stdout:
        return
    if status.returncode != 0:
        interface = run('/sbin/ifconfig', INTERFACE, check=False)
        if interface.returncode == 0:
            raise RuntimeError('Proxy interface is occupied by another application')
    if status.returncode != 0:
        # A default/broader VPN route remains installed beneath our more-specific
        # routes. Refuse only an exact route collision, not the VPN transport.
        for network in config['inbounds'][0]['route_address']:
            destination = str(ipaddress.ip_network(network).network_address)
            family = ['-inet6'] if ':' in destination else []
            route = run('/sbin/route', '-n', 'get', *family, destination, check=False)
            if route_conflicts(route.stdout, network):
                raise RuntimeError('An existing route overlaps a ClaudeGuard route exactly; it was left unchanged')
    binary = ROOT / 'sing-box' 
    if not binary.is_file():
        raise RuntimeError('Proxy engine is missing; reinstall ClaudeGuard')
    candidate = ROOT / 'proxy-next.json'
    candidate.touch(mode=0o600, exist_ok=True)
    candidate.chmod(0o600)
    candidate.write_text(content)
    checked = run(str(binary), 'check', '-c', str(candidate), check=False)
    if checked.returncode < 0:
        raise RuntimeError('Proxy engine was terminated by macOS; reinstall ClaudeGuard to repair the executable')
    if checked.returncode:
        raise RuntimeError('Proxy profile rejected by sing-box; check protocol settings')
    stop()
    with socket.socket() as listener:
        # Match the engine's reuse policy: TIME_WAIT is not another listener.
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(('127.0.0.1', PORT))
        except OSError as error:
            raise RuntimeError('Local proxy port is occupied by another application') from error
    candidate.replace(ROOT / 'proxy.json')
    body = {'Label': 'com.claudeguard.proxy',
            'ProgramArguments': [str(binary), 'run', '-c', str(ROOT / 'proxy.json')],
            'RunAtLoad': True, 'KeepAlive': True, 'ThrottleInterval': 5,
            'StandardOutPath': str(ROOT / 'proxy.log'), 'StandardErrorPath': str(ROOT / 'proxy.log')}
    log = ROOT / 'proxy.log'
    log.touch(mode=0o600, exist_ok=True)
    log.chmod(0o600)
    with PLIST.open('wb') as stream:
        plistlib.dump(body, stream)
    PLIST.chmod(0o644)
    timing = trace.begin() if trace.enabled else None
    started = run('/bin/launchctl', 'bootstrap', 'system', str(PLIST), check=False)
    if trace.enabled:
        trace.end(timing, "engine.start.bootstrap", "ok" if not started.returncode else "error")
        trace.end(timing, "routes.setup.engine_owned.submitted", "ok" if not started.returncode else "error")
    if started.returncode:
        loaded = run('/bin/launchctl', 'print', LABEL, check=False)
        if loaded.returncode or 'state = running' not in loaded.stdout or str(ROOT / 'proxy.json') not in loaded.stdout:
            raise RuntimeError('Proxy service could not start; check the engine log')
    stamp.write_text(fingerprint)
