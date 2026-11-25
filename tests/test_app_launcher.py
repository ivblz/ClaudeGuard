"""Alert text is data, never executable AppleScript. No apps are launched."""
import unittest
from unittest.mock import patch

from src import app_launcher


class AlertTests(unittest.TestCase):
    def test_untrusted_text_is_passed_as_arguments(self):
        script = 'on run argv\n    display alert (item 1 of argv) message (item 2 of argv) as critical\nend run'
        cases = [
            ('ClaudeGuard', 'Обычная ошибка 🚫'),
            ('--title', '-e'),
            ('Title "quoted"', '"\ndo shell script "echo injected"\n--'),
            ('', 'Backslash \\ and newline\nsecond line'),
        ]
        for title, message in cases:
            with self.subTest(title=title, message=message), \
                    patch.object(app_launcher.subprocess, 'run') as run:
                app_launcher.show_mac_alert(title, message)
                run.assert_called_once_with(
                    ['osascript', '-e', script, '--', title, message], check=False)
