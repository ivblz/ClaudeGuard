"""Regression coverage for removal of the separate auto-update block."""
import tempfile
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src import network_guard as guard
from src import brain
from src.config import DEFAULT_CONFIG


class NetworkGuardTests(unittest.TestCase):
    def test_empty_proxy_blocks_without_dns_and_stops_engine(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hosts = root / 'hosts'
            hosts.write_text('127.0.0.1 localhost\n')
            config = SimpleNamespace(protection_enabled=True, config={
                'connection_mode': 'proxy', 'proxy_profile': None,
            })
            with patch.object(guard, 'HOSTS_PATH', str(hosts)), \
                    patch.object(guard, 'PENDING_DIR', str(root)), \
                    patch.object(guard, 'PF_RULE_PATH', str(root / 'pf.rule')), \
                    patch.object(guard, 'resolve_domain_ips') as owned, \
                    patch.object(guard, 'resolve_ips') as resolve, \
                    patch.object(guard, 'write_hosts') as write:
                ok, message = guard.sync_hosts_file(True, config)
            self.assertTrue(ok, message)
            owned.assert_not_called()
            resolve.assert_not_called()
            self.assertIn('160.79.104.0/24', (root / 'pf.rule').read_text())
            self.assertIn('2607:6bc0::/32', (root / 'pf.rule').read_text())
            self.assertNotIn('user != 0', (root / 'pf.rule').read_text())
            self.assertEqual((root / 'proxy.json').read_text(), 'null')
            self.assertIn(guard.BLOCK_HEADER, write.call_args.args[0])

    def test_proxy_resolves_routes_once_without_a_second_pf_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hosts = root / 'hosts'
            hosts.write_text('127.0.0.1 localhost\n')
            config = SimpleNamespace(protection_enabled=True, config={
                'connection_mode': 'proxy', 'blocked_domains': ['custom.example'],
                'proxy_profile': {'type': 'http', 'server': 'localhost', 'server_port': 3128},
            })
            with patch.object(guard, 'HOSTS_PATH', str(hosts)), \
                    patch.object(guard, 'PENDING_DIR', str(root)), \
                    patch.object(guard, 'PF_RULE_PATH', str(root / 'pf.rule')), \
                    patch.object(guard, 'resolve_domain_ips') as owned, \
                    patch.object(guard, 'resolve_ips', return_value={'192.0.2.1'}) as resolve, \
                    patch.object(guard, 'write_hosts'):
                ok, message = guard.sync_hosts_file(False, config)
            self.assertTrue(ok, message)
            owned.assert_not_called()
            self.assertEqual(resolve.call_count, 1)
            self.assertTrue(set(guard.PF_RESOLVE_DOMAINS + ['custom.example'])
                            .issubset(resolve.call_args.args[0]))
            rule = (root / 'pf.rule').read_text()
            self.assertIn('192.0.2.1', rule)
            self.assertIn('160.79.104.0/24', rule)

    def test_default_domains_do_not_bypass_the_dedicated_ip_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hosts = root / 'hosts'
            hosts.write_text('127.0.0.1 localhost\n')
            config = SimpleNamespace(config={
                'blocked_domains': DEFAULT_CONFIG['blocked_domains'] + ['custom.example'],
            })
            with patch.object(guard, 'HOSTS_PATH', str(hosts)), \
                 patch.object(guard, 'PENDING_DIR', str(root)), \
                 patch.object(guard, 'PF_RULE_PATH', str(root / 'pf.rule')), \
                 patch.object(guard, 'resolve_domain_ips', return_value=['160.79.104.10']), \
                 patch.object(guard, 'resolve_ips', return_value={'192.0.2.1'}) as custom, \
                 patch.object(guard, 'write_hosts'):
                ok, message = guard.sync_hosts_file(True, config)
            self.assertTrue(ok, message)
            custom.assert_called_once_with(['custom.example'])
            self.assertIn('192.0.2.1', (root / 'pf.rule').read_text())

    def test_legacy_blocks_removed_without_losing_hosts_or_ip_protection(self):
        for blocked in (False, True):
            with self.subTest(blocked=blocked), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                hosts = root / 'hosts'
                hosts.write_text('127.0.0.1 localhost\n' + guard.UPDATE_HEADER
                                 + '0.0.0.0 desktop-app-updates.anthropic.com\n'
                                 + guard.UPDATE_FOOTER)
                config = SimpleNamespace(config={
                    'block_auto_updates': True,
                    'update_domains': ['legacy-update.example'],
                    'blocked_domains': [],
                })
                with patch.object(guard, 'HOSTS_PATH', str(hosts)), \
                     patch.object(guard, 'PENDING_DIR', str(root)), \
                     patch.object(guard, 'PF_RULE_PATH', str(root / 'pf.rule')), \
                     patch.object(guard, '_ensure_pending'), \
                     patch.object(guard, 'resolve_domain_ips', return_value=['160.79.104.10']), \
                     patch.object(guard, 'write_hosts') as write:
                    ok, message = guard.sync_hosts_file(blocked, config)
                self.assertTrue(ok, message)
                content = write.call_args.args[0]
                self.assertIn('127.0.0.1 localhost', content)
                self.assertNotIn(guard.UPDATE_HEADER, content)
                self.assertNotIn('legacy-update.example', content)
                self.assertEqual(guard.BLOCK_HEADER in content, blocked)
                self.assertEqual((root / 'pf.rule').exists(), blocked)
                if blocked:
                    self.assertIn('proto { tcp, udp }', (root / 'pf.rule').read_text())


class AcknowledgementTests(unittest.TestCase):
    def run_request(self, status):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = root / 'status.json'
            result.write_text(json.dumps(status))
            with patch.object(guard, 'PENDING_DIR', str(root)), \
                 patch.object(guard, 'PENDING_HOSTS', str(root / 'hosts.tmp')), \
                 patch.object(guard, 'REQUEST_FILE', str(root / 'request')), \
                 patch.object(guard, 'STATUS_FILE', str(result)), \
                 patch.object(guard.os, 'geteuid', return_value=501), \
                 patch.object(guard.uuid, 'uuid4', return_value=SimpleNamespace(hex='a' * 32)), \
                 patch.object(guard.time, 'monotonic', side_effect=[0, 0, 31]), \
                 patch.object(guard.time, 'sleep'):
                guard.write_hosts('127.0.0.1 localhost\n')

    def test_matching_success_is_accepted(self):
        self.run_request({'request': 'a' * 32, 'ok': True})

    def test_stale_success_is_not_accepted(self):
        with self.assertRaisesRegex(RuntimeError, 'did not acknowledge'):
            self.run_request({'request': 'b' * 32, 'ok': True})

    def test_matching_error_is_propagated(self):
        with self.assertRaisesRegex(RuntimeError, 'PF refused'):
            self.run_request({'request': 'a' * 32, 'ok': False, 'error': 'PF refused'})

    def test_root_path_invokes_the_same_backend_without_shell_commands(self):
        with patch.object(guard.subprocess, 'run') as run:
            guard._apply_as_root()
        run.assert_called_once_with([guard.ROOT_HELPER, guard.CONFIG_DIR], check=True, timeout=60)

    def test_error_never_allows_launch_and_still_terminates_blocked_sessions(self):
        config = SimpleNamespace(protection_enabled=True, config={})
        for state, expected in [('allowed', 'offline'), ('blocked', 'blocked')]:
            with self.subTest(state=state), patch.object(brain, 'read_daemon_state', return_value={
                'state': state, 'ip': '192.0.2.1', 'enforcement_error': 'PF refused',
            }):
                self.assertEqual(brain.get_verdict(config), (expected, '192.0.2.1', 'PF refused'))


if __name__ == '__main__':
    unittest.main()
