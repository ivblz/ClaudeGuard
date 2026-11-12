#!/usr/bin/env python3
"""Opt-in root smoke test. Temporarily block a single dedicated Claude IP.

No config/whitelist/hosts edits. Refuse to run over an existing ClaudeGuard
block. Hold the installed helper lock; always remove our test rules/reference.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.pf_controller import PFController, ANCHOR, PREVIOUS_ANCHOR, SYSTEM_DIR

TARGET = "160.79.104.10"
REPORT = Path("/tmp/claudeguard-pf-live-report.json")


def pf(*args):
    result = subprocess.run(["/sbin/pfctl", *args], capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return result.stdout


def foreign_root(text):
    return '\n'.join(line for line in text.splitlines()
                     if not line.startswith('anchor "' + ANCHOR + '"'))


def refs():
    return {parts[2] for line in pf('-s', 'References').splitlines()
            if len(parts := line.split()) >= 3 and parts[0].isdigit()}


def reachable():
    try:
        with socket.create_connection((TARGET, 443), timeout=3):
            return True
    except OSError:
        return False


def snapshot():
    return {
        'root': foreign_root(pf('-sr')),
        'nat': pf('-sn'),
        'sharing_filter': pf('-a', 'com.apple.internet-sharing', '-sr'),
        'sharing_nat': pf('-a', 'com.apple.internet-sharing', '-sn'),
        'enabled': pf('-si').splitlines()[0].split(' for ')[0],
    }


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Run this opt-in test with sudo')
    report = {'ok': False}
    try:
        with (SYSTEM_DIR / 'network.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            for name in (ANCHOR, PREVIOUS_ANCHOR):
                if pf('-a', name, '-sr').strip():
                    raise RuntimeError('Existing ClaudeGuard block; test refused without changing it')
            if 'anchor "' + ANCHOR + '"' in pf('-sr'):
                raise RuntimeError('Existing ClaudeGuard root call; test refused')
            before = snapshot()
            before_refs = refs()
            report['before'] = before
            report['reachable_before'] = reachable()
            if not report['reachable_before']:
                raise RuntimeError('Test IP is not reachable before blocking; no firewall changes made')
            directory = tempfile.mkdtemp(prefix='claudeguard-pf-test-')
            report['recovery_directory'] = directory
            shutil.copy2('/tmp/claudeguard-pf-anchor', Path(directory) / 'pf-anchor')
            controller = PFController(directory)
            sentinel = None
            started = False
            try:
                # A separate reference stands in for an unrelated service.
                result = subprocess.run(['/sbin/pfctl', '-E'], capture_output=True,
                                        text=True, check=True, timeout=15)
                match = re.search(r'Token\s*:\s*(\d+)', result.stdout + result.stderr)
                if not match:
                    raise RuntimeError('No sentinel enable token returned')
                sentinel = match[1]
                report['test_reference'] = sentinel
                started = True
                controller.block([TARGET])
                report['during'] = snapshot()
                report['reachable_blocked'] = reachable()
                report['table'] = pf('-a', ANCHOR, '-t', 'claude_guard', '-T', 'show')
                assert TARGET in report['table'], 'Target missing from private table'
                assert not report['reachable_blocked'], 'TCP still reachable through block'
                for key in ('root', 'nat', 'sharing_filter', 'sharing_nat'):
                    assert report['during'][key] == before[key], 'Foreign rules changed: ' + key
                controller.unblock()
                report['sentinel_preserved'] = sentinel in refs()
                assert report['sentinel_preserved'], 'Foreign enable reference lost'
                report['reachable_after'] = reachable()
                assert report['reachable_after'], 'TCP did not recover after unblock'
            finally:
                # Clean our rules even after a failed assertion/connection.
                try:
                    if started:
                        controller.unblock()
                finally:
                    if sentinel:
                        pf('-X', sentinel)
                        report.pop('test_reference', None)
            report['after'] = snapshot()
            assert report['after'] == before, 'PF root/NAT/Sharing/enable status did not return to baseline'
            assert refs() == before_refs, 'Enable references differ after cleanup'
            shutil.rmtree(directory)
            report.pop('recovery_directory', None)
            report['ok'] = True
    except Exception as error:
        report['error'] = str(error)
    finally:
        with tempfile.NamedTemporaryFile(mode='w', prefix='claudeguard-pf-report-', dir='/tmp', delete=False) as stream:
            json.dump(report, stream, indent=2)
            name = stream.name
        if os.environ.get('SUDO_UID'):
            os.chown(name, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))
        os.replace(name, REPORT)
        print(json.dumps(report, indent=2))
        print('Report:', REPORT)
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
