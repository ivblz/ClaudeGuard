import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from src.config import ConfigManager, validate_whitelist_entry


class WhitelistValidationTests(unittest.TestCase):
    def test_addresses_and_prefixes(self):
        for value in ('192.0.2.1', '192.0.2.1/24', '0.0.0.0/0',
                      '2001:db8::1', '2001:db8::1/64', '::/0', '::1/128'):
            self.assertEqual(validate_whitelist_entry(' ' + value + ' '), value)
        for value in ('', 'example.com', '999.1.1.1', '127.1', '01.2.3.4',
                      '192.0.2.1/33', '::1/129', '::1/-1', '::1/',
                      '::1/1/2', 'fe80::1%en0', '192.0.2.1/255.255.255.0'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_whitelist_entry(value)

    def test_invalid_updates_leave_file_and_memory_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            config = ConfigManager(str(path))
            config.allowed_ips = ['192.0.2.1']
            original = path.read_bytes()
            with self.assertRaises(ValueError):
                config.add_ip('not-an-ip')
            with self.assertRaises(ValueError):
                config.allowed_ips = ['2001:db8::1', 'invalid']
            self.assertEqual(config.allowed_ips, ['192.0.2.1'])
            self.assertEqual(path.read_bytes(), original)
            config.allowed_ips = []
            self.assertEqual(config.allowed_ips, [])

    def test_cli_invalid_input_reports_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            config = ConfigManager(str(Path(directory) / '.config/claudeguard/config.json'))
            original = Path(config.path).read_bytes()
            result = subprocess.run(
                [sys.executable, '-B', str(Path(__file__).resolve().parents[1] / 'bin/claudeguard'),
                 'add-ip', 'not-an-ip'], env={**os.environ, 'HOME': directory},
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('Invalid IP/CIDR', result.stderr)
            self.assertNotIn('Traceback', result.stderr)
            self.assertEqual(Path(config.path).read_bytes(), original)
