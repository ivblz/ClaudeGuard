"""Uninstall regressions with mocked dispatch and temporary hosts fixtures only."""
import contextlib
import io
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / 'uninstall.sh').read_text()


class UninstallTests(unittest.TestCase):
    def test_restore_existing_binary_skip_missing_and_preserve_foreign_link(self):
        block = SCRIPT.split('# Put the real binary back where its own installer would have put it.', 1)[1].split('# Remove the shared application', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'real-claude'
            bin_dir = root / '.local/bin'
            bin_dir.mkdir(parents=True)
            link = bin_dir / 'claude'
            def restore():
                return subprocess.run(['/bin/bash', '-c', block],
                    env={**os.environ, 'HOME': directory, 'REAL_CLAUDE_TARGET': str(target)},
                    capture_output=True, text=True)
            result = restore()
            self.assertEqual(result.returncode, 0)
            self.assertIn('restoration skipped', result.stdout)
            self.assertNotIn('Reinstall', result.stdout)
            self.assertFalse(link.is_symlink())
            target.touch()
            self.assertEqual(restore().returncode, 0)
            self.assertEqual(link.resolve(), target.resolve())
            link.unlink()
            link.symlink_to(root / 'foreign-missing-binary')
            self.assertEqual(restore().returncode, 0)
            self.assertEqual(os.readlink(link), str(root / 'foreign-missing-binary'))
            link.unlink()
            bin_dir.rmdir()
            result = restore()
            self.assertEqual(result.returncode, 1)
            self.assertIn('destination directory is missing or not writable', result.stderr)

    def test_cli_dispatch_propagates_failure_without_loading_config(self):
        cli = runpy.run_path(str(ROOT / 'bin/claudeguard'))
        main = cli['main']
        with patch.dict(main.__globals__, ConfigManager=lambda: self.fail('config loaded')), \
                patch.object(sys, 'argv', ['claudeguard', 'uninstall']), \
                patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 7)) as run:
            with self.assertRaises(SystemExit) as caught:
                main()
            self.assertEqual(caught.exception.code, 7)
            run.assert_called_once_with(['/bin/bash', str(ROOT / 'uninstall.sh')], check=False)

    def test_cli_missing_script_reports_error(self):
        main = runpy.run_path(str(ROOT / 'bin/claudeguard'))['main']
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(main.__globals__, PROJECT_DIR=directory), \
                patch.object(sys, 'argv', ['claudeguard', 'uninstall']), \
                patch.object(subprocess, 'run') as run, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                main()
            self.assertEqual(caught.exception.code, 1)
            run.assert_not_called()

    def test_hosts_cleanup_keeps_foreign_lines_and_rejects_partial_block(self):
        body = SCRIPT.split("<<'PYTHON'\n", 1)[1].split('\nPYTHON', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            hosts = Path(directory) / 'hosts'
            output = Path(directory) / 'clean'
            body = body.replace("HOSTS_PATH = '/etc/hosts'", f'HOSTS_PATH = {str(hosts)!r}')
            hosts.write_text('127.0.0.1 localhost\n# BEGIN CLAUDEGUARD BLOCKS\n127.0.0.1 claude.ai\n# END CLAUDEGUARD BLOCKS\n# foreign\n')
            with patch.object(sys, 'argv', ['cleanup', str(output)]):
                exec(compile(body, 'hosts cleanup', 'exec'), {})
                self.assertEqual(output.read_text(), '127.0.0.1 localhost\n# foreign\n')
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                output.unlink()
                hosts.write_text('# BEGIN CLAUDEGUARD BLOCKS\nunfinished\n')
                with self.assertRaises(ValueError):
                    exec(compile(body, 'hosts cleanup', 'exec'), {})
                self.assertFalse(output.exists())

    def test_failed_cleanup_exits_and_removes_private_temp_directory(self):
        block = SCRIPT.split('# 3. Restore /etc/hosts file', 1)[1].split('# Flush DNS', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            # No Python cleanup or privileged command is executed in this shell.
            result = subprocess.run(['/bin/bash', '-c',
                'python3() { return 1; }; sudo() { echo UNEXPECTED_SUDO; return 99; };\n' + block],
                env={**os.environ, 'TMPDIR': directory}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('Hosts cleanup failed', result.stderr)
            self.assertNotIn('UNEXPECTED_SUDO', result.stdout)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_failed_copy_exits_and_removes_private_temp_directory(self):
        block = SCRIPT.split('# 3. Restore /etc/hosts file', 1)[1].split('# Flush DNS', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(['/bin/bash', '-c',
                'python3() { return 0; }; sudo() { return 1; };\n' + block],
                env={**os.environ, 'TMPDIR': directory}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('Cannot restore /etc/hosts', result.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [])
