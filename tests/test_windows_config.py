"""Shared configuration persistence on Windows and POSIX; no user files touched."""
import json
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.windows.windows_config import ConfigManager, DEFAULT_CONFIG


class ConfigPersistenceTests(unittest.TestCase):
    def test_macos_paths_defaults_and_private_file_mode_are_preserved(self):
        # Exercise the macOS branch without claiming a real macOS integration run.
        spec = importlib.util.spec_from_file_location(
            'config_macos_regression', Path(__file__).resolve().parents[1] / 'src/config.py')
        module = importlib.util.module_from_spec(spec)
        with patch('sys.platform', 'darwin'):
            spec.loader.exec_module(module)
            self.assertEqual(module.CONFIG_DIR, os.path.expanduser('~/.config/claudeguard'))
            self.assertEqual(module.DEFAULT_CONFIG['real_claude_cli_path'], '/opt/homebrew/bin/claude')
            self.assertEqual(module.DEFAULT_CONFIG['real_claude_app_path'], '/Applications/Claude.app')
            with tempfile.TemporaryDirectory() as directory:
                with patch.object(module.os, 'fchmod', create=True) as chmod:
                    manager = module.ConfigManager(str(Path(directory) / 'config.json'))
                    manager.add_ip('192.0.2.1')
                    self.assertTrue(chmod.called)
                    self.assertTrue(all(call.args[1] == 0o600 for call in chmod.call_args_list))
                    self.assertEqual(module.ConfigManager(manager.path).allowed_ips, ['192.0.2.1'])

    def test_new_configs_do_not_share_mutable_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            first = ConfigManager(str(Path(directory) / 'one.json'))
            first.add_ip('192.0.2.1')
            second = ConfigManager(str(Path(directory) / 'two.json'))
            self.assertEqual(second.allowed_ips, [])
            self.assertEqual(DEFAULT_CONFIG['allowed_ips'], [])

    def test_failed_replace_preserves_complete_previous_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            manager = ConfigManager(str(path))
            before = path.read_bytes()
            manager.config['default_model'] = 'new-value'
            with patch('src.windows.windows_config.os.replace', side_effect=OSError('locked')):
                with self.assertRaises(OSError):
                    manager.save_config()
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(list(Path(directory).glob('*.tmp')), [])

    def test_unicode_round_trip_and_defaults_for_old_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            path.write_text(json.dumps({'real_claude_app_path': 'C:/Программы/Claude.exe'}), encoding='utf-8')
            manager = ConfigManager(str(path))
            manager.save_config()
            loaded = ConfigManager(str(path))
            self.assertEqual(loaded.real_claude_app, 'C:/Программы/Claude.exe')
            self.assertTrue(loaded.protection_enabled)


if __name__ == '__main__':
    unittest.main()
