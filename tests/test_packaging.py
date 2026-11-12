"""Exercise installer orchestration without touching launchd or the firewall."""
import importlib.util
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pkg_configure', ROOT / 'packaging/scripts/configure.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class PackagingTests(unittest.TestCase):
    def test_user_setup_preserves_whitelist_and_can_run_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / 'home'
            runtime = Path(tmp) / 'Runtime'
            runtime.mkdir()
            shutil.copy2(ROOT / 'packaging/setup_user.py', runtime / 'setup_user.py')
            (runtime / 'src').mkdir()
            shutil.copy2(ROOT / 'src/config.py', runtime / 'src/config.py')
            (runtime / 'src/integrity.py').write_text('def repair(config): return {}\n')
            (runtime / 'bin').mkdir()
            (runtime / 'bin/claudeguard').touch()
            (runtime / 'uninstall.sh').touch()
            for name in ('LICENSE', 'NOTICE'):
                shutil.copy2(ROOT / name, runtime / name)
            config = home / '.config/claudeguard/config.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps({'allowed_ips': ['192.0.2.1'],
                'protection_enabled': False, 'block_auto_updates': True}))
            for _ in range(2):
                subprocess.run([sys.executable, '-I', str(runtime / 'setup_user.py')],
                               env={**os.environ, 'HOME': str(home)}, check=True, capture_output=True)
            saved = json.loads(config.read_text())
            self.assertEqual(saved['allowed_ips'], ['192.0.2.1'])
            self.assertFalse(saved['protection_enabled'])
            self.assertNotIn('block_auto_updates', saved)
            self.assertEqual((home / '.local/bin/claudeguard').resolve(),
                             (home / '.local/share/ClaudeGuard/bin/claudeguard').resolve())
            agent = home / 'Library/LaunchAgents/com.claudeguard.daemon.plist'
            self.assertTrue(plistlib.loads(agent.read_bytes())['RunAtLoad'])

    def test_login_window_rejected_before_service_changes(self):
        with patch.object(installer, 'console_account', side_effect=RuntimeError('Log in')), \
                patch.object(installer, 'run') as run:
            with self.assertRaises(RuntimeError):
                installer.configure('preinstall')
            run.assert_not_called()

    def test_preinstall_stops_only_target_user_and_owned_services(self):
        account = types.SimpleNamespace(pw_uid=501, pw_dir='/Users/example', pw_name='example')
        with patch.object(installer, 'console_account', return_value=account), \
                patch.object(installer, 'check_existing_owner'), \
                patch.object(installer, 'run') as run:
            installer.configure('preinstall')
            self.assertEqual(run.call_count, 5)
            self.assertIn(('/bin/launchctl', 'bootout', 'system/com.claudeguard.proxy'),
                          [call.args for call in run.call_args_list])
            self.assertIn(('/usr/bin/pkill', '-u', '501', '-x', 'ClaudeGuardMenuBar'),
                          [call.args for call in run.call_args_list])

    def test_other_account_rejected_before_service_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            helper = Path(tmp) / 'helper.plist'
            helper.write_bytes(plistlib.dumps({'ProgramArguments': ['hosts-helper', '/Users/other/.config/claudeguard']}))
            account = types.SimpleNamespace(pw_uid=501, pw_dir='/Users/example', pw_name='example')
            with patch.object(installer, 'HELPER_PLIST', helper), \
                    patch.object(installer, 'console_account', return_value=account), \
                    patch.object(installer, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'another user'):
                    installer.configure('preinstall')
                run.assert_not_called()

    def test_bad_config_stops_before_service_changes(self):
        account = types.SimpleNamespace(pw_uid=501, pw_dir='/Users/example', pw_name='example')
        with patch.object(installer, 'console_account', return_value=account), \
                patch.object(installer, 'check_existing_owner'), \
                patch.object(installer, 'run_as_user', side_effect=RuntimeError('Bad config')), \
                patch.object(installer, 'run') as run:
            with self.assertRaises(RuntimeError):
                installer.configure('preinstall')
            run.assert_not_called()

    def test_config_preflight_accepts_missing_valid_and_rejects_bad_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            path = home / '.config/claudeguard/config.json'
            path.parent.mkdir(parents=True)
            cases = [None, '{"allowed_ips": ["192.0.2.1"], "protection_enabled": false}',
                     '{bad json', '[]', '{"allowed_ips": "192.0.2.1"}', '{"protection_enabled": "false"}']
            for content in cases:
                with self.subTest(content=content):
                    if content is not None:
                        path.write_text(content)
                    result = subprocess.run([sys.executable, '-I', '-c', installer.USER_PREFLIGHT],
                                            env={**os.environ, 'HOME': tmp}, capture_output=True)
                    self.assertEqual(result.returncode == 0, content in cases[:2])
                    if content is not None:
                        self.assertEqual(path.read_text(), content)

    def test_postinstall_escapes_home_and_starts_helper_before_agent(self):
        with tempfile.TemporaryDirectory(prefix='pkg-test-') as tmp:
            home = Path(tmp) / 'A & B'
            home.mkdir()
            account = types.SimpleNamespace(pw_uid=501, pw_dir=str(home), pw_name='example')
            helper_plist = Path(tmp) / 'helper.plist'
            with patch.object(installer, 'console_account', return_value=account), \
                    patch.object(installer, 'HELPER_PLIST', helper_plist), \
                    patch.object(installer, 'prepare_executables'), \
                    patch.object(installer, 'run') as run, \
                    patch.object(installer.Path, 'exists', return_value=False):
                installer.configure('postinstall')
            body = plistlib.loads(helper_plist.read_bytes())
            self.assertEqual(body['ProgramArguments'][1], str(home / '.config/claudeguard'))
            calls = [call.args for call in run.call_args_list]
            self.assertIn('/usr/bin/sudo', calls[0])
            self.assertIn('/usr/bin/python3', calls[0])
            self.assertEqual(calls[2][2], 'system')
            self.assertEqual(calls[3][2], 'gui/501')

    def test_executable_refresh_preserves_contents_and_mode_and_replaces_inode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = root / 'app'
            binaries = [root / name for name in ('sing-box', 'hosts-helper', 'pf-anchor')] + [app]
            for binary in binaries:
                binary.write_bytes(b'installed executable')
                binary.chmod(0o755)
            for _ in range(2):
                before = {p: p.stat().st_ino for p in binaries}
                with patch.object(installer, 'HELPER', root), patch.object(installer, 'APP', str(app)), \
                        patch.object(installer, 'run') as run:
                    installer.prepare_executables()
                for binary in binaries:
                    self.assertNotEqual(binary.stat().st_ino, before[binary])
                    self.assertEqual(binary.read_bytes(), b'installed executable')
                    self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
                self.assertEqual(run.call_args.args, (str(root / 'sing-box'), 'version'))

    def test_engine_launch_failure_prevents_starting_services(self):
        account = types.SimpleNamespace(pw_uid=501, pw_dir='/Users/example', pw_name='example')
        with patch.object(installer, 'console_account', return_value=account), \
                patch.object(installer, 'check_existing_owner'), \
                patch.object(installer, 'prepare_executables', side_effect=RuntimeError('Engine killed')), \
                patch.object(installer, 'run') as run, patch.object(installer, 'run_as_user') as user:
            with self.assertRaisesRegex(RuntimeError, 'Engine killed'):
                installer.configure('postinstall')
            run.assert_not_called()
            user.assert_not_called()


if __name__ == '__main__':
    unittest.main()
