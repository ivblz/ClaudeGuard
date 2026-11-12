"""Optional real sing-box integration: CLAUDEGUARD_TEST_ENGINE=/path/sing-box."""
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest
from src.proxy_config import engine_config, parse_profile

ENGINE = os.environ.get('CLAUDEGUARD_TEST_ENGINE')


class Upstream(socketserver.StreamRequestHandler):
    def handle(self):
        request = self.rfile.readline().decode()
        while self.rfile.readline() not in (b'\r\n', b'\n', b''):
            pass
        self.server.requests.append(request)
        if self.server.refuse:
            self.wfile.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n')
            return
        self.wfile.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        self.wfile.flush()
        # The origin is simulated inside the proxy; success is impossible without this hop.
        self.rfile.readline()
        while self.rfile.readline() not in (b'\r\n', b'\n', b''):
            pass
        self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\nvia-test-proxy!')


@unittest.skipUnless(ENGINE, 'Set CLAUDEGUARD_TEST_ENGINE for real engine integration')
class EngineTests(unittest.TestCase):
    def test_proxy_hop_and_failure_have_no_direct_fallback(self):
        server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Upstream)
        server.requests = []
        server.refuse = False
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                cfg = engine_config(parse_profile('http://127.0.0.1:' + str(server.server_address[1])), [], ['claude.ai'])
                cfg['inbounds'] = [cfg['inbounds'][1]]
                with socket.socket() as probe:
                    probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
                cfg['inbounds'][0]['listen_port'] = port
                path = Path(directory) / 'config.json'; path.write_text(json.dumps(cfg))
                subprocess.run([ENGINE, 'check', '-c', str(path)], check=True, capture_output=True)
                with open(Path(directory) / 'log', 'w') as log:
                    process = subprocess.Popen([ENGINE, 'run', '-c', str(path)], stdout=log, stderr=log)
                    try:
                        for _ in range(50):
                            try:
                                with socket.create_connection(('127.0.0.1', port), timeout=.1): break
                            except OSError: time.sleep(.1)
                        command = ['/usr/bin/curl', '-q', '--silent', '--fail', '--max-time', '3',
                                   '--proxy', 'http://127.0.0.1:' + str(port), '--noproxy', '',
                                   'http://origin.invalid/']
                        result = subprocess.run(command, capture_output=True, text=True)
                        self.assertEqual(result.stdout, 'via-test-proxy!')
                        self.assertTrue(any('origin.invalid:80' in r for r in server.requests))
                        server.refuse = True
                        failed = subprocess.run(command, capture_output=True, text=True)
                        self.assertNotEqual(failed.returncode, 0)
                        self.assertNotIn('via-test-proxy!', failed.stdout)
                    finally:
                        process.terminate(); process.wait(timeout=5)
        finally:
            server.shutdown(); server.server_close()
