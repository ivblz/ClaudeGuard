#!/usr/bin/env python3
"""Admin-only isolated TUN smoke test; routes only documentation/test addresses."""
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import tempfile
import threading
import time

ENGINE = '/tmp/cg-proxy-engine/sing-box'
IFACE = 'utun198'

def run(*args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, timeout=15, **kwargs)

class Upstream(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline()
        while self.rfile.readline() not in (b'\r\n', b'\n', b''):
            pass
        if not line.startswith(b'CONNECT '): return
        self.wfile.write(b'HTTP/1.1 200 Connection Established\r\n\r\n'); self.wfile.flush()
        self.rfile.readline()
        while self.rfile.readline() not in (b'\r\n', b'\n', b''):
            pass
        self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ntun-test')

assert os.geteuid() == 0, 'Administrator privileges required'
assert run('/sbin/ifconfig', IFACE).returncode != 0, 'Test interface already in use'
before = run('/sbin/route', '-n', 'get', 'default').stdout
server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Upstream)
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    with tempfile.TemporaryDirectory(prefix='cg-tun-test-') as directory:
        path = Path(directory)
        cfg = {
            'log': {'level': 'debug'},
            'inbounds': [{'type': 'tun', 'tag': 'tun', 'interface_name': IFACE,
                          'address': ['172.31.255.245/30'], 'auto_route': True,
                          'route_address': ['198.18.199.1/32'], 'stack': 'system'}],
            'outbounds': [{'type': 'http', 'tag': 'proxy', 'server': '127.0.0.1',
                           'server_port': server.server_address[1]}],
            'route': {'auto_detect_interface': True, 'final': 'proxy'}}
        (path / 'config.json').write_text(json.dumps(cfg))
        with (path / 'log').open('w') as log:
            proc = subprocess.Popen([ENGINE, 'run', '-c', str(path / 'config.json')], stdout=log, stderr=log)
            try:
                for _ in range(50):
                    if proc.poll() is not None:
                        raise RuntimeError((path / 'log').read_text())
                    if IFACE in run('/sbin/route', '-n', 'get', '198.18.199.1').stdout: break
                    time.sleep(.1)
                result = run('/usr/bin/curl', '-q', '--silent', '--fail', '--max-time', '5', '--noproxy', '*', 'http://198.18.199.1/')
                assert result.stdout == 'tun-test', (result.stderr, (path / 'log').read_text())
                assert before == run('/sbin/route', '-n', 'get', 'default').stdout, 'Default route changed'
                print('PASS: scoped TUN transports HTTP through upstream; default route unchanged')
            finally:
                proc.terminate(); proc.wait(timeout=10)
        assert IFACE not in run('/sbin/route', '-n', 'get', '198.18.199.1').stdout, 'Test route not cleaned up'
        print('PASS: owned TUN route removed after shutdown')
        result = run('/sbin/pfctl', '-nf', '/tmp/cg-proxy-pf.conf')
        assert result.returncode == 0, result.stderr
        print('PASS: PF kill-switch syntax accepted (no rules installed)')
finally:
    server.shutdown(); server.server_close()
