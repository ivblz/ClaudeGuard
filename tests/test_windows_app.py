import os
import queue
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

from src.windows import windows_app


class WindowsSettingsTests(unittest.TestCase):
    def test_vpn_whitelist_and_proxy_use_shared_validators(self):
        whitelist = windows_app.whitelist_entries("192.0.2.2, 2001:db8::/48\n192.0.2.2")
        profile = windows_app.parse_profile("socks5://user:example@proxy.test:1080")
        self.assertEqual(whitelist, ["192.0.2.2", "2001:db8::/48"])
        self.assertEqual(profile["type"], "socks")
        self.assertEqual(profile["password"], "example")
        self.assertEqual(windows_app.model_id(" claude-opus-4-8 "), "claude-opus-4-8")

    def test_invalid_vpn_ip_and_invalid_proxy_are_rejected(self):
        with self.assertRaises(ValueError):
            windows_app.whitelist_entries("example.test")
        with self.assertRaises(ValueError):
            windows_app.parse_profile("{}")

    def test_missing_path_override_does_not_launch_alternate_executable(self):
        discover = Mock()
        with self.assertRaisesRegex(RuntimeError, "configured executable"):
            windows_app.app_path("missing.exe", discover)
        discover.assert_not_called()

    def test_worker_merges_a_setting_before_checking(self):
        tray = windows_app.Tray.__new__(windows_app.Tray)
        tray.work = queue.Queue()
        tray.events = queue.Queue()
        tray.process_stop = Mock()
        tray.guard = Mock()
        tray.config = Mock()
        tray.closing = False
        tray.pending_patch = None
        tray.render_status = Mock()
        existing = {"connection_mode": "vpn", "allowed_ips": ["192.0.2.2"]}
        tray.data = existing
        tray.config.load_config.return_value = existing
        status = {"state": "allowed", "mode": "proxy"}
        tray.guard.tick.return_value = status
        operations = Mock()
        operations.attach_mock(tray.guard.invalidate_process_verdict, "invalidate")
        operations.attach_mock(tray.config.save_config, "save")
        operations.attach_mock(tray.guard.resume_process_verdict, "resume")
        operations.attach_mock(tray.guard.tick, "tick")
        tray.save_settings({"connection_mode": "proxy"})
        tray.work.put(("quit", None))
        tray.run_guard()
        updated = {**existing, "connection_mode": "proxy"}
        self.assertEqual(operations.mock_calls, [call.invalidate(), call.save(updated), call.resume(),
                                                 call.tick(enforce_processes=False)])
        self.assertEqual(tray.events.get_nowait(), (tray.settings_saved, (status, updated, None)))


class WindowsTrayLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tray = tray = windows_app.Tray.__new__(windows_app.Tray)
        tray.root = Mock()
        tray.activation = object()
        tray.menu = Mock()
        tray.dialog = None
        tray.closing = False
        tray.finished = False
        tray.events = queue.Queue()
        tray.work = queue.Queue()
        tray.process_stop = threading.Event()
        tray.guard = Mock()
        tray.config = None

    @patch("src.windows.windows_app.platform.consume_activation", return_value=False)
    def test_failing_event_callback_preserves_polling_and_drains_next_event(self, consume):
        tray = self.tray
        failed = Mock(side_effect=RuntimeError("private details"))
        next_callback = Mock()
        tray.events.put((failed, ()))
        tray.events.put((next_callback, ("result",)))

        with self.assertLogs(windows_app.LOGGER, level="ERROR") as logs:
            tray.handle_events()

        self.assertIn("RuntimeError", logs.output[0])
        self.assertNotIn("private details", logs.output[0])
        next_callback.assert_called_once_with("result")
        tray.root.after.assert_called_once_with(windows_app.EVENT_POLL_MS, tray.handle_events)

    @patch("src.windows.windows_app.platform.consume_activation", side_effect=[True, True, False])
    def test_activation_opens_menu_and_focuses_an_existing_dialog(self, consume):
        tray = self.tray
        tray.handle_events()
        tray.menu.show.assert_called_once_with(None)

        tray.dialog = Mock()
        tray.handle_events()
        tray.dialog.window.lift.assert_called_once_with()
        tray.dialog.window.focus_force.assert_called_once_with()
        tray.menu.show.assert_called_once()

        tray.handle_events()
        self.assertEqual(consume.call_args_list, [call(tray.activation)] * 3)
        tray.dialog.window.lift.assert_called_once()

    @patch("src.windows.windows_app.ConfigManager")
    @patch("src.windows.windows_app.platform.consume_activation", return_value=True)
    def test_activation_and_quit_can_be_requested_during_background_preparation(self, consume, config):
        tray = self.tray
        tray.icon = Mock()
        preparing = threading.Event()
        resume = threading.Event()

        def prepare():
            preparing.set()
            if not resume.wait(5):
                raise RuntimeError("Timed out waiting to finish backend preparation")

        tray.guard.prepare.side_effect = prepare
        thread = threading.Thread(target=tray.run_guard, daemon=True)
        thread.start()
        try:
            self.assertTrue(preparing.wait(5))
            tray.handle_events()
            tray.menu.show.assert_called_once_with(None)
            tray.request_quit()
            tray.icon.stop.assert_called_once_with()
            tray.menu.hide.assert_called_once_with()
            tray.guard.close.assert_not_called()
        finally:
            tray.request_quit()
            resume.set()
            thread.join(5)

        self.assertFalse(thread.is_alive())
        tray.guard.tick.assert_not_called()
        tray.guard.close.assert_called_once_with()
        tray.handle_events()
        tray.icon.stop.assert_called_once_with()
        tray.root.destroy.assert_called_once_with()


@unittest.skipUnless(sys.platform == "win32", "Windows notification-area APIs")
class WindowsNativeIconTests(unittest.TestCase):
    def test_native_icon_dispatches_clicks_updates_and_exits(self):
        try:
            from pystray._win32 import win32
        except ModuleNotFoundError as error:
            self.skipTest(f"Windows tray dependencies are unavailable ({error.name})")

        clicks = queue.Queue()
        ready = threading.Event()
        errors = []
        initial = windows_app.render_icon("checking")
        updated = windows_app.render_icon("allowed")
        icon = windows_app.notification_icon("ClaudeGuardTest", initial, "ClaudeGuard test", clicks.put)
        native_show = icon._show

        def show():
            native_show()
            ready.set()

        def run():
            try:
                icon.run()
            except Exception as error:
                errors.append(error)
                ready.set()

        with patch.object(icon, "_show", side_effect=show):
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            try:
                self.assertTrue(ready.wait(5))
                self.assertFalse(errors)
                for button in (win32.WM_LBUTTONUP, win32.WM_RBUTTONUP):
                    self.assertTrue(win32.PostMessage(icon._hwnd, win32.WM_NOTIFY, 0, button))
                    clicks.get(timeout=5)

                icon.set_status(updated, "ClaudeGuard updated")
                self.assertTrue(win32.PostMessage(icon._hwnd, win32.WM_NOTIFY, 0, win32.WM_LBUTTONUP))
                clicks.get(timeout=5)
                self.assertIs(icon.icon, updated)
                self.assertEqual(icon.title, "ClaudeGuard updated")
            finally:
                icon.stop()
                thread.join(5)

        self.assertFalse(thread.is_alive())
        self.assertFalse(errors)
        self.assertIsNone(icon._hwnd)


@unittest.skipUnless(sys.platform == "win32", "Windows menu dependencies")
class WindowsMenuTests(unittest.TestCase):
    def setUp(self):
        from src.windows import windows_menu
        self.menu = windows_menu

    def test_vpn_command_order_and_ip_visibility(self):
        ip = "192.0.2.2"
        data = {"connection_mode": "vpn", "allowed_ips": [ip]}
        expected = [["refresh"], ["protection"], ["model"], ["manage_ips"], ["quit"]]
        for current_ip in (None, ip):
            self.assertEqual(self.row_keys(data, current_ip), expected)
        self.assertEqual(self.row_keys(data, "192.0.2.3")[3], ["add_ip", "manage_ips"])

    def test_proxy_and_model_rows(self):
        data = {"connection_mode": "proxy", "model_override_enabled": True}
        self.assertEqual(self.row_keys(data, "192.0.2.3"),
                         [["refresh"], ["protection"], ["model", "change_model"], ["proxy"], ["quit"]])

    def test_proxy_endpoint_shows_host_and_port(self):
        profile = {"server": "2001:db8::1", "server_port": 1080, "password": "example"}
        self.assertEqual(self.menu.proxy_endpoint(profile), "[2001:db8::1]:1080")

    def row_keys(self, data, ip):
        return [[key for key, _ in group] for group in self.menu.menu_rows(data, ip)]


class WindowsLaunchTests(unittest.TestCase):
    def setUp(self):
        self.proxy_url = "http://127.0.0.1:17943"
        self.config = {"protection_enabled": True}
        self.status = {"mode": "proxy", "state": "allowed", "protection_enabled": True,
                       "protected": True, "proxy_url": self.proxy_url}

    @patch("src.windows.windows_app.platform.launch_from_shell")
    def test_launch_requires_confirmed_enforcement(self, launch):
        self.status["protected"] = False
        with self.assertRaisesRegex(RuntimeError, "blocked access"):
            windows_app.launch_claude("desktop", self.config, self.status)
        launch.assert_not_called()

    @patch("src.windows.windows_app.platform.launch_from_shell")
    def test_proxy_launch_without_listener_fails_closed(self, launch):
        self.status["proxy_url"] = None
        with self.assertRaisesRegex(RuntimeError, "proxy is unavailable"):
            windows_app.launch_claude("cli", self.config, self.status)
        launch.assert_not_called()

    @patch("src.windows.windows_app.platform.discover_cli")
    @patch("src.windows.windows_app.platform.launch_from_shell")
    def test_proxy_cli_launch_uses_model_and_replaces_proxy_environment(self, launch, discover):
        discover.return_value = Path("claude.exe")
        self.config.update(model_override_enabled=True, default_model="opus")
        with patch.dict(os.environ, {"no_proxy": "*", "https_proxy": "http://old.test", "_PYI_TEST": "old"}):
            windows_app.launch_claude("cli", self.config, self.status)
        args, options = launch.call_args
        self.assertEqual(args[0], [discover.return_value, "--model", "opus"])
        self.assertTrue(options["console"])
        environment = {key.upper(): value for key, value in options["env"].items()}
        self.assertEqual(environment["HTTPS_PROXY"], self.proxy_url)
        self.assertEqual(environment["NO_PROXY"], "")
        self.assertNotIn("_PYI_TEST", environment)

    @patch("src.windows.windows_app.platform.app_command", return_value=["ClaudeGuard.exe"])
    @patch("src.windows.windows_app.platform.discover_desktop_app", return_value="Claude_test!App")
    @patch("src.windows.windows_app.platform.launch_from_shell")
    def test_proxy_msix_launch_preserves_proxy_flags(self, launch, discover, app_command):
        windows_app.launch_claude("desktop", self.config, self.status)
        args, options = launch.call_args
        self.assertEqual(args[0], ["ClaudeGuard.exe", "--activate-desktop", discover.return_value,
                                   f"--proxy-server={self.proxy_url}", "--disable-quic"])
        self.assertTrue(options["wait"])
        self.assertEqual(options["env"]["PYINSTALLER_RESET_ENVIRONMENT"], "1")

    @patch("src.windows.windows_app.platform.launch_from_shell")
    def test_disabled_protection_launch_has_no_managed_proxy_flags(self, launch):
        with tempfile.TemporaryDirectory() as directory:
            desktop = Path(directory) / "Claude.exe"
            desktop.touch()
            self.config.update(protection_enabled=False, real_claude_app_path=str(desktop))
            self.status.update(protection_enabled=False, state="disabled", protected=False)
            windows_app.launch_claude("desktop", self.config, self.status)
            self.assertEqual(launch.call_args.args[0], [desktop])

    def test_worker_closes_guard_before_finishing_quit(self):
        tray = windows_app.Tray.__new__(windows_app.Tray)
        tray.work = queue.Queue()
        tray.events = queue.Queue()
        tray.process_stop = Mock()
        tray.guard = Mock()
        tray.work.put(("quit", None))
        tray.run_guard()
        tray.process_stop.set.assert_called_once_with()
        tray.guard.close.assert_called_once_with()
        self.assertEqual(tray.events.get_nowait(), (tray.finish_quit, (None,)))


class WindowsProcessMonitorTests(unittest.TestCase):
    def setUp(self):
        self.tray = windows_app.Tray.__new__(windows_app.Tray)
        self.tray.closing = False
        self.tray.pending_patch = None
        self.tray.notified_block_episode = 0
        self.tray.show_error = Mock()
        self.tray.render_status = Mock()
        self.blocked = {"state": "blocked", "block_episode": 1, "error": "Proxy unavailable."}
        self.tray.guard = Mock()
        self.tray.guard.status.return_value = self.blocked

    def test_monitor_scans_repeatedly_and_queues_changed_results(self):
        tray = self.tray
        tray.events = queue.Queue()
        tray.process_stop = Mock()
        tray.process_stop.wait.side_effect = [False, False, False, True]
        closed = {**self.blocked, "cli_closed": 1}
        tray.guard.enforce_processes.side_effect = [self.blocked, closed, closed]
        tray.run_process_monitor()
        self.assertEqual(tray.guard.enforce_processes.call_count, 3)
        self.assertEqual(tray.events.get_nowait(), (tray.show_process_status, (self.blocked,)))
        self.assertEqual(tray.events.get_nowait(), (tray.show_process_status, (closed,)))
        self.assertTrue(tray.events.empty())
        tray.show_error.assert_not_called()

    def test_notifications_require_a_confirmed_exit_and_are_deduplicated(self):
        tray = self.tray
        tray.status = {"state": "allowed"}
        tray.show_process_status(self.blocked)
        tray.show_process_status({**self.blocked, "state": "offline", "cli_closed": 1})
        tray.show_error.assert_not_called()
        tray.show_process_status({**self.blocked, "cli_closed": 1})
        tray.show_process_status({**self.blocked, "cli_closed": 2, "desktop_closed": 1})
        new_block = {**self.blocked, "block_episode": 2, "desktop_closed": 1}
        tray.guard.status.return_value = new_block
        tray.show_process_status(new_block)
        self.assertEqual(tray.show_error.call_args_list, [
            call("Claude Code was closed.\n\nProxy unavailable.", title="ClaudeGuard 🚫 Blocked"),
            call("Claude Desktop was closed.\n\nProxy unavailable.", title="ClaudeGuard 🚫 Blocked"),
        ])
        self.assertEqual(tray.status, {"state": "allowed"})

    def test_queued_closure_alert_does_not_interrupt_new_status_or_settings(self):
        tray = self.tray
        tray.status = {"state": "offline"}
        closed = {**self.blocked, "cli_closed": 1}
        tray.guard.status.return_value = tray.status
        tray.show_process_status(closed)
        tray.guard.status.return_value = {**self.blocked, "block_episode": 2}
        tray.show_process_status(closed)
        tray.guard.status.return_value = self.blocked
        tray.pending_patch = {"protection_enabled": False}
        tray.show_process_status(closed)
        tray.show_error.assert_not_called()
        self.assertEqual(tray.status, {"state": "offline"})

    def test_launch_refusal_uses_closure_alert_when_it_also_closed_claude(self):
        tray = self.tray
        closed = {**self.blocked, "desktop_closed": 1, "cli_closed": 1}
        tray.show_launch_error(closed, None, self.blocked["error"])
        tray.show_launch_error(closed, None, self.blocked["error"])
        self.assertEqual(tray.show_error.call_args_list, [
            call("Claude Desktop and Claude Code were closed.\n\nProxy unavailable.", title="ClaudeGuard 🚫 Blocked"),
            call("Proxy unavailable."),
        ])


if __name__ == "__main__":
    unittest.main()
