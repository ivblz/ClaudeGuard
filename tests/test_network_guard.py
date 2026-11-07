"""Regression coverage for removal of the separate auto-update block."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src import network_guard as guard


class NetworkGuardTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
