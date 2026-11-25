#!/usr/bin/env python3
"""Opt-in QUIC fallback regression against installed ClaudeGuard in Proxy mode.

A throwaway local sing-box client generates a synthetic QUIC Initial. ClaudeGuard
must promptly refuse it with ICMP, rather than leave HTTP/3 clients retrying.
No account credentials, settings changes or Desktop app are used.
"""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import uuid

ENGINE = '/Library/Application Support/ClaudeGuard/sing-box'


def quic_initial():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind(('127.0.0.1', 0))
        receiver.settimeout(4)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        config = {
            'log': {'level': 'error'},
            'inbounds': [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': port}],
            'outbounds': [{
                'type': 'tuic', 'server': '127.0.0.1',
                'server_port': receiver.getsockname()[1],
                'uuid': str(uuid.uuid4()), 'password': 'synthetic-test',
                'tls': {'enabled': True, 'server_name': 'assets-proxy.anthropic.com',
                        'alpn': ['h3']},
            }],
        }
        with tempfile.TemporaryDirectory(prefix='cg-quic-') as directory:
            path = Path(directory) / 'config.json'
            path.write_text(json.dumps(config))
            path.chmod(0o600)
            process = subprocess.Popen([ENGINE, 'run', '-c', str(path)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(30):
                    try:
                        connection = socket.create_connection(('127.0.0.1', port), timeout=.1)
                        break
                    except OSError:
                        if process.poll() is not None:
                            raise RuntimeError('Synthetic QUIC client could not start')
                        time.sleep(.1)
                else:
                    raise RuntimeError('Synthetic QUIC client startup timed out')
                with connection:
                    connection.sendall(b'CONNECT origin.invalid:443 HTTP/1.1\r\n'
                                       b'Host: origin.invalid:443\r\n\r\n')
                    packet, _ = receiver.recvfrom(65535)
                    return packet
            finally:
                process.terminate()
                process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', help='Run against installed ClaudeGuard')
    if not parser.parse_args().run:
        parser.error('Explicit opt-in required: --run')
    state = json.loads((Path.home() / '.config/claudeguard/state.json').read_text())
    if (state.get('mode') != 'proxy' or not state.get('protection_enabled')
            or state.get('state') != 'allowed' or time.time() - state.get('updated_at', 0) > 90):
        raise SystemExit('Requires a fresh Proxy OK verdict with Protection enabled')
    packet = quic_initial()
    print('Synthetic QUIC Initial:', len(packet), 'bytes', flush=True)
    for _ in range(3):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.settimeout(2)
            probe.connect(('160.79.104.10', 443))
            started = time.monotonic()
            try:
                probe.send(packet)
                probe.recv(256)
            except ConnectionRefusedError:
                elapsed = time.monotonic() - started
                if elapsed > .5:
                    raise SystemExit('FAIL: UDP refusal exceeded 500ms')
                print('PASS: QUIC refused in', round(elapsed * 1000, 1), 'ms', flush=True)
            except OSError as error:
                raise SystemExit('FAIL: no prompt ICMP refusal: ' + str(error)) from error
            else:
                raise SystemExit('FAIL: unexpected UDP reply; packet was not rejected')


if __name__ == '__main__':
    main()
