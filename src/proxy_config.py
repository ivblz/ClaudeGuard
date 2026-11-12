"""Validated proxy profiles. Shared by the UI bridge and root-owned backend."""
import base64
import ipaddress
import json
import re
from urllib.parse import urlsplit, unquote

PORT = 17943
INTERFACE = 'utun199'
DEDICATED = ['160.79.104.0/24', '2607:6bc0::/32']
TYPES = {'http', 'socks', 'shadowsocks', 'vmess', 'vless', 'trojan', 'hysteria2', 'tuic'}
# No arbitrary config, file paths, detours, listeners, executable hooks or TLS bypass.
FIELDS = {'type', 'server', 'server_port', 'username', 'password', 'version',
          'method', 'uuid', 'security', 'alter_id', 'flow', 'tls', 'transport',
          'congestion_control'}

def validate(profile):
    if profile is None:
        raise ValueError('Proxy is not configured. Choose Configure Proxy…')
    if not isinstance(profile, dict):
        raise ValueError('Expected one proxy JSON object, not a full configuration or list')
    if set(profile) - FIELDS:
        raise ValueError('This JSON contains unsupported fields. Paste one outbound object without tag')
    p = dict(profile)
    if p.get('type') not in TYPES:
        raise ValueError('Unsupported proxy protocol')
    host = p.get('server', '')
    if not isinstance(host, str) or not host or len(host) > 253 or not re.fullmatch(r'[A-Za-z0-9.:_-]+', host):
        raise ValueError('Invalid proxy server')
    port = p.get('server_port')
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Invalid proxy port')
    if host.lower() in {'localhost', '127.0.0.1', '::1'} and port == PORT:
        raise ValueError('Proxy upstream cannot point back to ClaudeGuard')
    for key, value in p.items():
        if key not in {'server_port', 'alter_id', 'tls', 'transport'} and (not isinstance(value, str) or len(value) > 4096):
            raise ValueError('Invalid proxy field: ' + key)
    if 'tls' in p:
        tls = p['tls']
        if not isinstance(tls, dict) or set(tls) - {'enabled', 'server_name', 'alpn', 'utls', 'reality', 'certificate'}:
            raise ValueError('Unsupported TLS settings (certificate verification is required)')
        if 'certificate' in tls:
            certificates = tls['certificate']
            if (not isinstance(certificates, list) or not certificates
                    or not all(isinstance(line, str) for line in certificates)
                    or sum(len(line) for line in certificates) > 65536
                    or '-----BEGIN CERTIFICATE-----' not in '\n'.join(certificates)):
                raise ValueError('Invalid inline CA certificate')
        if tls.get('enabled') is not True:
            raise ValueError('TLS must be enabled when configured')
        if 'server_name' in tls and (not isinstance(tls['server_name'], str) or not re.fullmatch(r'[A-Za-z0-9.-]+', tls['server_name'])):
            raise ValueError('Invalid TLS server name')
        if 'alpn' in tls and (not isinstance(tls['alpn'], list) or not all(isinstance(x, str) for x in tls['alpn'])):
            raise ValueError('Invalid ALPN')
        for key, fields in [('utls', {'enabled', 'fingerprint'}), ('reality', {'enabled', 'public_key', 'short_id'})]:
            if key in tls and (not isinstance(tls[key], dict) or set(tls[key]) - fields):
                raise ValueError('Invalid ' + key)
    if 'transport' in p:
        t = p['transport']
        if not isinstance(t, dict) or set(t) - {'type', 'path', 'headers', 'service_name', 'host'}:
            raise ValueError('Unsupported transport settings')
        if t.get('type') not in {'ws', 'http', 'httpupgrade', 'grpc'}:
            raise ValueError('Unsupported transport')
    return p

def parse_profile(text):
    text = text.strip()
    if not text:
        raise ValueError("Enter a proxy URL or outbound JSON profile")
    if text.startswith('{'):
        return validate(json.loads(text))
    u = urlsplit(text)
    scheme = u.scheme.lower()
    if scheme not in {'http', 'https', 'socks4', 'socks4a', 'socks5', 'socks5h', 'trojan', 'vless', 'ss'}:
        raise ValueError('Use HTTP(S)/SOCKS URL or a sing-box outbound JSON profile')
    if u.query or (u.path and u.path != '/'):
        raise ValueError('For transport/TLS options import a sing-box outbound JSON profile')
    p = {'type': scheme, 'server': u.hostname, 'server_port': u.port or (443 if scheme == 'https' else 1080 if scheme.startswith('socks') else 80)}
    if scheme.startswith('socks'):
        p.update(type='socks', version='4a' if scheme == 'socks4a' else '4' if scheme == 'socks4' else '5')
    if scheme in {'http', 'https'}:
        p['type'] = 'http'
    if scheme in {'https', 'trojan'}:
        p['tls'] = {'enabled': True, 'server_name': u.hostname}
    if u.username is not None:
        if scheme == 'vless':
            p['uuid'] = unquote(u.username)
        elif scheme == 'trojan':
            p['password'] = unquote(u.username)
        elif scheme == 'ss':
            credentials = unquote(u.username)
            if u.password is None:
                credentials = base64.urlsafe_b64decode(credentials + '=' * (-len(credentials) % 4)).decode()
                method, password = credentials.split(':', 1)
            else:
                method, password = credentials, unquote(u.password)
            p.update(type='shadowsocks', method=method, password=password)
        else:
            p['username'] = unquote(u.username)
            if u.password is not None:
                p['password'] = unquote(u.password)
    return validate(p)

def engine_config(profile, addresses, domains):
    outbound = validate(profile)
    outbound['tag'] = 'proxy'
    routes = sorted(set(DEDICATED + [str(ipaddress.ip_network(a, strict=False)) for a in addresses]))
    if len(routes) > 2048:
        raise ValueError('Too many proxy routes')
    if not domains or len(domains) > 1024 or not all(isinstance(d, str) and re.fullmatch(r'[a-zA-Z0-9_.-]+', d) for d in domains):
        raise ValueError('Invalid proxy domains')
    return {
        'log': {'level': 'error', 'timestamp': True},
        'dns': {'servers': [{'type': 'local', 'tag': 'local'}]},
        'inbounds': [
            {'type': 'tun', 'tag': 'tun', 'interface_name': INTERFACE,
             'address': ['172.31.255.249/30', 'fdfe:cdab:199::1/126'],
             'auto_route': True, 'route_address': routes, 'stack': 'system', 'mtu': 1500},
            {'type': 'mixed', 'tag': 'cli', 'listen': '127.0.0.1', 'listen_port': PORT}],
        'outbounds': [outbound, {'type': 'direct', 'tag': 'direct'}],
        'route': {'auto_detect_interface': True, 'default_domain_resolver': 'local',
                  # Reject QUIC before sniff establishes a UDP session. After
                  # sniff, reject only closes the session and the browser may
                  # wait for retransmission timeouts instead of receiving ICMP.
                  # Restrict this early rule to Anthropic-owned ranges so other
                  # sites on a shared CDN retain their normal UDP behaviour.
                  'rules': [{'ip_cidr': DEDICATED, 'network': 'udp',
                             'action': 'reject', 'method': 'default', 'no_drop': True},
                            {'action': 'sniff'},
                            {'inbound': 'cli', 'action': 'route', 'outbound': 'proxy'},
                            {'domain_suffix': domains, 'network': 'udp',
                             'action': 'reject', 'method': 'default', 'no_drop': True},
                            {'domain_suffix': domains, 'action': 'route', 'outbound': 'proxy'},
                            {'ip_cidr': DEDICATED, 'action': 'route', 'outbound': 'proxy'},
                            {'domain_regex': ['.+'], 'action': 'route', 'outbound': 'direct'},
                            {'action': 'reject'}],
                  'final': 'direct'}}
