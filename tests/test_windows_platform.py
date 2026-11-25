"""Shell integration policy without modifying the user's scheduled tasks."""
import json
import subprocess
import sys
import unittest
import uuid
import xml.etree.ElementTree as ET
from unittest.mock import patch

from src.windows import windows_platform as platform


@unittest.skipUnless(sys.platform == 'win32', 'Windows named events')
class ActivationTests(unittest.TestCase):
    def test_second_launch_signals_once_and_missing_app_is_detected(self):
        with patch.object(platform, '_activation_name', return_value='Local\\ClaudeGuard-Test-' + uuid.uuid4().hex):
            self.assertFalse(platform.signal_existing_instance())
            handle = platform.activation_event()
            try:
                self.assertFalse(platform.consume_activation(handle))
                self.assertTrue(platform.signal_existing_instance())
                self.assertTrue(platform.consume_activation(handle))
                self.assertFalse(platform.consume_activation(handle))
            finally:
                platform.close_handle(handle)
            self.assertFalse(platform.signal_existing_instance())


class StartupPolicyTests(unittest.TestCase):
    def test_startup_uses_elevated_interactive_user(self):
        with (patch.object(platform.sys, 'frozen', True, create=True),
              patch.object(platform, 'installed_program', return_value=platform.Path(sys.executable).resolve()),
              patch.object(platform, 'current_sid', return_value='S-1-5-21-123'),
              patch.object(platform, 'run_system', return_value=subprocess.CompletedProcess([], 0)) as run):
            platform.set_startup(True)
        payload = json.loads(run.call_args.kwargs['input'])
        task = ET.fromstring(payload['xml'])
        ns = {'t': platform.TASK_NS}
        self.assertEqual(task.findtext('.//t:Principal/t:RunLevel', namespaces=ns), 'HighestAvailable')
        self.assertEqual(task.findtext('.//t:Principal/t:LogonType', namespaces=ns), 'InteractiveToken')
        self.assertEqual(task.findtext('.//t:Principal/t:UserId', namespaces=ns), 'S-1-5-21-123')
        self.assertEqual(task.findtext('.//t:Exec/t:Arguments', namespaces=ns), '--startup')
        self.assertEqual(payload['name'], 'ClaudeGuard-S-1-5-21-123')

    def test_portable_copy_cannot_register_elevated_startup(self):
        with (patch.object(platform.sys, 'frozen', True, create=True),
              patch.object(platform, 'current_sid', return_value='S-1-5-21-123'),
              patch.object(platform, 'installed_program', return_value=platform.Path('different.exe')),
              patch.object(platform, 'run_system') as run):
            with self.assertRaisesRegex(RuntimeError, 'Install.cmd'):
                platform.set_startup(True)
            run.assert_not_called()

    def test_startup_removal_is_scoped_to_current_user_task(self):
        with (patch.object(platform, 'current_sid', return_value='S-1-5-21-123'),
              patch.object(platform, 'run_system', return_value=subprocess.CompletedProcess([], 0)) as run):
            platform.set_startup(False)
        self.assertEqual(run.call_args.args[0],
                         ['schtasks.exe', '/Delete', '/TN', 'ClaudeGuard-S-1-5-21-123', '/F'])


if __name__ == '__main__':
    unittest.main()
