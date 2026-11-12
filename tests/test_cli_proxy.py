"""CLI launch gate regressions: proxy launches must not reconfigure the tunnel."""
import contextlib
import io
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from src import cli_wrapper

class CLIProxyTests(unittest.TestCase):
    def config(self):
        return SimpleNamespace(protection_enabled=True, allowed_ips=[], config={'connection_mode':'proxy'})

    def test_verified_proxy_launch_does_not_restart_engine(self):
        with patch.object(cli_wrapper, 'ConfigManager', return_value=self.config()), \
             patch.object(cli_wrapper.signal, 'signal'), \
             patch.object(cli_wrapper, 'get_verdict', return_value=('allowed','192.0.2.1',None)), \
             patch.object(cli_wrapper, 'repair_cli'), \
             patch.object(cli_wrapper, 'sync_hosts_file') as sync, \
             patch.object(cli_wrapper, 'run_real_claude') as launch:
            cli_wrapper.main()
            launch.assert_called_once()
            sync.assert_not_called()

    def test_unverified_proxy_blocks_with_proxy_instructions(self):
        error = io.StringIO()
        with patch.object(cli_wrapper, 'ConfigManager', return_value=self.config()), \
             patch.object(cli_wrapper.signal, 'signal'), \
             patch.object(cli_wrapper, 'get_verdict', return_value=('blocked',None,'Proxy unavailable')), \
             patch.object(cli_wrapper, 'force_restore_terminal'), \
             patch.object(cli_wrapper, 'run_real_claude') as launch, contextlib.redirect_stderr(error):
            with self.assertRaises(SystemExit) as caught:
                cli_wrapper.main()
            self.assertEqual(caught.exception.code,1)
            launch.assert_not_called()
        self.assertIn('Proxy unavailable', error.getvalue())
        self.assertIn('Configure Proxy', error.getvalue())
        self.assertEqual(len(error.getvalue().splitlines()), 1)
        self.assertNotIn('add-ip',error.getvalue())

if __name__ == '__main__':
    unittest.main()
