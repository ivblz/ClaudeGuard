"""Obsolete proxy checks must not stall or block the newly selected VPN mode."""
import contextlib
import io
import json
from pathlib import Path
import runpy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from src import proxy
from src import network_guard

HELPER = str(Path(__file__).resolve().parents[1] / 'src/helper.py')


class HelperModeTests(unittest.TestCase):
    def test_profile_removal_save_does_not_wait_for_network(self):
        config = SimpleNamespace(config={'connection_mode': 'proxy'}, protection_enabled=True)
        with patch('src.config.ConfigManager', return_value=config), \
                patch.object(proxy, 'save_profile', return_value=None) as save, \
                patch.object(network_guard, 'sync_hosts_file') as sync, \
                patch('sys.stdin', io.StringIO('')), patch('sys.argv', [HELPER, 'proxy_save']):
            runpy.run_path(HELPER, run_name='__main__')
        save.assert_called_once_with(config, '')
        sync.assert_not_called()

    def test_empty_profile_check_blocks_without_probing_old_listener(self):
        config = SimpleNamespace(config={'connection_mode': 'proxy', 'proxy_profile': None})
        out = io.StringIO()
        with patch('src.config.ConfigManager', return_value=config), \
                patch.object(proxy, 'prepare') as prepare, patch.object(proxy, 'probe') as probe, \
                patch.object(network_guard, 'sync_hosts_file', return_value=(True, '')) as sync, \
                patch('sys.argv', [HELPER, 'proxy_check']), contextlib.redirect_stdout(out):
            runpy.run_path(HELPER, run_name='__main__')
        self.assertFalse(json.loads(out.getvalue())['ok'])
        prepare.assert_not_called()
        probe.assert_not_called()
        self.assertTrue(sync.call_args.args[0])

    def test_proxy_check_after_vpn_selection_does_no_network_work(self):
        config = SimpleNamespace(config={'connection_mode': 'vpn'})
        out = io.StringIO()
        with patch('src.config.ConfigManager', return_value=config), \
                patch.object(proxy, 'prepare') as prepare, patch.object(proxy, 'probe') as probe, \
                patch.object(network_guard, 'sync_hosts_file') as sync, \
                patch('sys.argv', [HELPER, 'proxy_check']), contextlib.redirect_stdout(out):
            runpy.run_path(HELPER, run_name='__main__')
        self.assertFalse(json.loads(out.getvalue())['ok'])
        prepare.assert_not_called()
        probe.assert_not_called()
        sync.assert_not_called()

    def test_failed_old_check_does_not_block_new_vpn(self):
        old = SimpleNamespace(config={'connection_mode': 'proxy', 'proxy_profile': None},
                              path='/nonexistent/claudeguard/config.json')
        current = SimpleNamespace(config={'connection_mode': 'vpn'})
        out = io.StringIO()
        with patch('src.config.ConfigManager', side_effect=[old, current]), \
                patch.object(proxy, 'prepare', side_effect=RuntimeError('Old connection failed')), \
                patch.object(network_guard, 'sync_hosts_file') as sync, \
                patch('sys.argv', [HELPER, 'proxy_check']), contextlib.redirect_stdout(out):
            runpy.run_path(HELPER, run_name='__main__')
        self.assertEqual(json.loads(out.getvalue())['error'], 'Connection settings changed')
        sync.assert_not_called()
