"""Exercise the packaged Windows proxy engine with loopback-only servers."""
from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from src.proxy_config import parse_profile
from src.windows.windows_backend import _proxy_config
from test_proxy_engine import Upstream


ENGINE = os.environ.get("CLAUDEGUARD_TEST_ENGINE")
LOOPBACK = "127.0.0.1"


@contextmanager
def serve(handler):
    with socketserver.ThreadingTCPServer((LOOPBACK, 0), handler) as server:
        server.daemon_threads = True
        server.requests = []
        server.refuse = False
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server, server.server_address[1]
        finally:
            server.shutdown()
            thread.join()


class Origin(socketserver.StreamRequestHandler):
    def handle(self):
        self.server.requests.append(self.rfile.readline())
        self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndirect")


def request(proxy_port, origin_port):
    connection = http.client.HTTPConnection(LOOPBACK, proxy_port, timeout=3)
    try:
        connection.set_tunnel(LOOPBACK, origin_port)
        connection.request("GET", "/")
        with connection.getresponse() as response:
            return response.read()
    finally:
        connection.close()


@unittest.skipUnless(sys.platform == "win32" and ENGINE, "Set CLAUDEGUARD_TEST_ENGINE to packaged sing-box.exe")
class WindowsEngineTests(unittest.TestCase):
    def test_proxy_hop_and_refusal_never_connect_directly_to_reachable_origin(self):
        with serve(Upstream) as (upstream, upstream_port), serve(Origin) as (origin, origin_port):
            with tempfile.TemporaryDirectory() as directory:
                config = _proxy_config(parse_profile(f"http://{LOOPBACK}:{upstream_port}"))
                with socket.socket() as available:
                    available.bind((LOOPBACK, 0))
                    port = available.getsockname()[1]
                config["inbounds"][0]["listen_port"] = port
                path = Path(directory) / "config.json"
                path.write_text(json.dumps(config), encoding="utf-8")
                subprocess.run([ENGINE, "check", "-c", str(path)], check=True, capture_output=True, timeout=10)

                with subprocess.Popen([ENGINE, "run", "-c", str(path)], stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL) as process:
                    try:
                        deadline = time.monotonic() + 5
                        while time.monotonic() < deadline and process.poll() is None:
                            try:
                                with socket.create_connection((LOOPBACK, port), timeout=0.1):
                                    break
                            except OSError:
                                time.sleep(0.05)
                        else:
                            self.fail("sing-box did not open its loopback listener")

                        self.assertEqual(request(port, origin_port), b"via-test-proxy!")
                        upstream.refuse = True
                        with self.assertRaises((OSError, http.client.HTTPException)):
                            request(port, origin_port)
                        target = f"CONNECT {LOOPBACK}:{origin_port} "
                        self.assertEqual(len([line for line in upstream.requests if line.startswith(target)]), 2)
                        self.assertEqual(origin.requests, [])
                    finally:
                        process.terminate()
                        process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
