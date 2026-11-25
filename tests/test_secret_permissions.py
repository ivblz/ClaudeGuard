"""Permission regressions; only temporary directories, no system helpers."""
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.config import ConfigManager
from src import network_guard


class SecretPermissionsTests(unittest.TestCase):
    def test_installer_migration_preserves_private_permissions(self):
        script = (Path(__file__).resolve().parents[1] / 'install.sh').read_text()
        migration = script.split('python3 - "$CONFIG_DIR/config.json" <<\'PYTHON\'\n', 1)[1].split('\nPYTHON', 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'config.json'
            path.write_text('{"proxy_profile":{"password":"synthetic"}}')
            previous = os.umask(0)
            try:
                with patch.object(sys, 'argv', ['migration', str(path)]):
                    exec(compile(migration, 'install.sh migration', 'exec'), {})
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(json.loads(path.read_text())['proxy_profile']['password'], 'synthetic')
            finally:
                os.umask(previous)

    def test_config_creation_and_existing_permissions_ignore_umask(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'config' / 'config.json'
            previous = os.umask(0)
            try:
                manager = ConfigManager(str(path))
                manager.config['proxy_profile'] = {'password': 'synthetic-test-secret'}
                manager.save_config()
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
                path.chmod(0o644)
                path.parent.chmod(0o755)
                loaded = ConfigManager(str(path))
                self.assertEqual(loaded.config, manager.config)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            finally:
                os.umask(previous)

    def test_pending_restricts_existing_and_atomic_temporary_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'pending'
            directory.mkdir(mode=0o755)
            path = directory / 'proxy.json'
            staged = directory / 'proxy.json.new'
            path.write_text('{}')
            staged.write_text('{}')
            path.chmod(0o644)
            staged.chmod(0o644)
            previous = os.umask(0)
            try:
                with patch.object(network_guard, 'PENDING_DIR', str(directory)):
                    network_guard._ensure_pending()
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o600)
                replace = os.replace
                def checked_replace(source, destination):
                    self.assertEqual(stat.S_IMODE(os.stat(source).st_mode), 0o600)
                    replace(source, destination)
                with patch.object(network_guard.os, 'replace', side_effect=checked_replace):
                    network_guard._atomic_write(str(path), json.dumps({'password': 'synthetic'}))
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            finally:
                os.umask(previous)
