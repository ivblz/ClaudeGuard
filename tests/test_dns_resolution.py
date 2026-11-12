import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from src import network_guard as guard


class DNSResolutionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.config = patch.object(guard, 'CONFIG_DIR', self.directory.name)
        self.config.start()

    def tearDown(self):
        self.config.stop()
        self.directory.cleanup()

    def test_matches_old_sequential_answers_and_fallback(self):
        calls = []
        def resolver(server, record, host):
            calls.append((server, record, host))
            if host == 'failed.example':
                return False, []
            if host == 'empty.example':
                return True, []
            if record == 'AAAA' and server == guard.EXTERNAL_RESOLVERS[0]:
                return False, []
            return True, ['192.0.2.1' if record == 'A' else '2001:db8::1']
        hosts = ['ok.example', 'empty.example', 'failed.example']
        expected = set()
        for host in hosts:
            for record in ('A', 'AAAA'):
                for server in guard.EXTERNAL_RESOLVERS:
                    ok, ips = resolver(server, record, host)
                    if ok:
                        expected.update(ips)
                        break
        calls.clear()
        with patch.object(guard, '_dig', side_effect=resolver):
            self.assertEqual(guard.resolve_ips(hosts), expected)
        self.assertFalse(any(server != guard.EXTERNAL_RESOLVERS[0] and host == 'empty.example'
                             for server, record, host in calls))
    def test_every_call_resolves_live_and_ignores_existing_cache(self):
        cache = Path(self.directory.name) / 'dns_cache.json'
        original = json.dumps({'old.example': {'ips': ['192.0.2.99'], 'timestamp': time.time()}})
        cache.write_text(original)
        with patch.object(guard, '_dig', return_value=(True, ['192.0.2.1'])) as query:
            self.assertEqual(guard.resolve_ips(['old.example']), {'192.0.2.1'})
            self.assertEqual(guard.resolve_ips(['old.example']), {'192.0.2.1'})
            self.assertEqual(query.call_count, 4)
        with patch.object(guard, '_dig', return_value=(False, [])):
            self.assertEqual(guard.resolve_ips(['old.example']), set())
        self.assertEqual(cache.read_text(), original)

    def test_deadline_does_not_join_slow_queries(self):
        def slow(*args):
            time.sleep(0.12)
            return True, ['192.0.2.1']
        with patch.object(guard, 'DNS_DEADLINE', 0.02), patch.object(guard, '_dig', side_effect=slow):
            start = time.monotonic()
            self.assertEqual(guard.resolve_ips(['slow.example']), set())
            self.assertLess(time.monotonic() - start, 0.1)
        time.sleep(0.13)
