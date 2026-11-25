"""Exercise process identity checks and Windows closure with disposable targets."""

from contextlib import contextmanager, ExitStack
from dataclasses import replace
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from src.windows import windows_backend as backend
from src.windows.windows_config import ConfigManager
from src.windows.windows_process_guard import (
    ProcessReport, WindowsProcessGuard, _Entry, _Identity, _path_key,
)


BLOCKED = {"state": "blocked", "protection_enabled": True}
HOME = r"C:\Users\Test"
LOCAL = HOME + r"\AppData\Local"
DESKTOP = LOCAL + r"\AnthropicClaude\app-1.2.3\claude.exe"
CLI = HOME + r"\.local\bin\claude.exe"


class ProcessFixture:
    pid = 100
    sid = "S-1-5-1"
    session = 2

    def __init__(self):
        self.entries = []
        self.identities = {}
        self.reopened = {}
        self.fail = set()
        self.closed = []
        self.scans = 0

    def add(self, pid, path, *, parent=0, created=None, sid=None, session=None, package=""):
        path = _path_key(path)
        self.entries.append(_Entry(pid, parent, path.rsplit("\\", 1)[1]))
        self.identities[pid] = _Identity(path, created or pid, sid or self.sid,
                                        self.session if session is None else session, _path_key(package))

    def snapshot(self):
        self.scans += 1
        return 999, self.entries

    def session_for(self, pid):
        return self.identities[pid].session

    @contextmanager
    def open(self, pid, *, terminate=False):
        yield pid, terminate

    def running(self, handle):
        return handle[0] not in self.closed

    def identity(self, handle):
        pid, terminate = handle
        if terminate and pid in self.reopened:
            return self.reopened[pid]
        return self.identities[pid]

    def close_process(self, handle):
        pid, terminate = handle
        assert terminate
        if pid in self.fail:
            raise PermissionError("private details")
        self.closed.append(pid)
        return True


class ProcessGuardTests(unittest.TestCase):
    def setUp(self):
        self.processes = ProcessFixture()
        self.guard = WindowsProcessGuard(self.processes, home=HOME, local_app_data=LOCAL)

    def test_only_confirmed_blocked_state_scans(self):
        for state in ("allowed", "offline", "disabled", "error"):
            self.assertEqual(self.guard.enforce({}, dict(BLOCKED, state=state)), ProcessReport())
        self.assertEqual(self.guard.enforce({}, dict(BLOCKED, protection_enabled=False)), ProcessReport())
        self.assertEqual(self.processes.scans, 0)

    def test_known_paths_and_same_installation_descendants(self):
        add = self.processes.add
        desktop_dir = DESKTOP.rsplit("\\", 1)[0]
        add(1, LOCAL + r"\AnthropicClaude\Claude.exe")
        add(2, DESKTOP, parent=1)
        add(3, DESKTOP, parent=2)
        add(4, desktop_dir + r"\resources\claude-ssh-broker.exe", parent=2)
        add(5, CLI)
        add(6, HOME + r"\Downloads\claude.exe")
        add(7, LOCAL + r"\AnthropicClaude-other\app-1.2.3\claude.exe")
        add(8, LOCAL + r"\AnthropicClaude\app-other\claude.exe")
        add(9, desktop_dir + r"\resources\claude-ssh-broker.exe", parent=5)
        add(10, LOCAL + r"\AnthropicClaude\app-2.0.0\resources\claude-ssh-broker.exe", parent=2)
        add(11, desktop_dir + r"\resources\node.exe", parent=2)
        add(12, HOME + r"\Tools\claude-custom.exe")
        add(13, HOME + r"\Tools\claude-custom.exe", sid="S-1-5-2")
        add(14, DESKTOP, session=3)
        result = self.guard.enforce({"real_claude_cli_path": HOME + r"\tools\Claude-custom.exe"}, BLOCKED)
        self.assertEqual(result, ProcessReport(4, 2))
        self.assertEqual(self.processes.closed, [1, 2, 3, 4, 5, 12])

    def test_packaged_desktop_requires_registered_package_and_expected_image(self):
        package = r"C:\Program Files\WindowsApps\Claude_1.2.3.4_x64__pzs8sxrjxfjjc"
        self.processes.add(1, package + r"\app\Claude.exe", package=package)
        self.processes.add(2, package + r"\app\Claude.exe")
        self.processes.add(3, package + r"\other\Claude.exe", package=package)
        self.assertEqual(self.guard.enforce({}, BLOCKED), ProcessReport(1, 0))
        self.assertEqual(self.processes.closed, [1])

    def test_shared_executables_are_ignored_even_if_configured(self):
        cmd = r"C:\Windows\System32\cmd.exe"
        powershell = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        self.processes.add(1, cmd)
        self.processes.add(2, powershell)
        self.assertEqual(self.guard.enforce({"real_claude_cli_path": cmd,
                                            "real_claude_app_path": powershell}, BLOCKED), ProcessReport())

    def test_changed_identity_and_new_pid_are_skipped(self):
        for pid in range(1, 6):
            self.processes.add(pid, DESKTOP, created=1000 if pid == 5 else None)
        for pid, fields in enumerate(({"created": 7}, {"path": _path_key(CLI)},
                                      {"sid": "S-1-5-2"}, {"session": 3}), start=1):
            self.processes.reopened[pid] = replace(self.processes.identities[pid], **fields)
        self.assertEqual(self.guard.enforce({}, BLOCKED), ProcessReport())
        self.assertEqual(self.processes.closed, [])

    def test_stale_blocked_verdict_stops_before_close(self):
        self.processes.add(1, CLI)
        current = iter((True, True, False))
        self.assertEqual(self.guard.enforce({}, BLOCKED, should_enforce=lambda: next(current)), ProcessReport())
        self.assertEqual(self.processes.closed, [])

    def test_retry_reports_failures_without_private_details(self):
        self.processes.add(1, CLI)
        self.processes.add(2, DESKTOP)
        self.processes.fail.add(1)
        self.assertEqual(self.guard.enforce({}, BLOCKED),
                         ProcessReport(1, 0, "Could not close every identified Claude process."))
        self.processes.fail.clear()
        self.assertEqual(self.guard.enforce({}, BLOCKED), ProcessReport(0, 1))


@unittest.skipUnless(sys.platform == "win32", "requires native Windows process APIs")
class NativeProcessTests(unittest.TestCase):
    def test_blocks_real_disposable_targets_and_preserves_unrelated_processes(self):
        with TemporaryDirectory() as directory, ExitStack() as stack:
            stack.enter_context(patch("src.windows.windows_process_guard._WindowsProcesses._package_dir", return_value=""))
            home = Path(directory)
            local = home / "AppData" / "Local"
            launcher = local / "AnthropicClaude" / "Claude.exe"
            desktop = launcher.parent / "app-1.2.3" / "Claude.exe"
            cli = home / ".local" / "bin" / "Claude.exe"
            custom = home / "custom-installed" / "Claude-alt.exe"
            unrelated = home / "Downloads" / "Claude.exe"
            shell = Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"
            guard = WindowsProcessGuard(home=home, local_app_data=local)
            settings = {"real_claude_cli_path": str(custom), "real_claude_app_path": str(shell)}
            python = Path(sys._base_executable)
            env = os.environ.copy()
            env["PYTHONHOME"] = sys.base_prefix
            env["PATH"] = str(python.parent) + os.pathsep + env.get("PATH", "")

            def start(command):
                child = stack.enter_context(subprocess.Popen(
                    command, cwd=python.parent, env=env, stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                ))
                stack.callback(child.kill)
                return child

            def start_claude(path):
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists():
                    shutil.copyfile(python, path)
                return start([path, "-S", "-c", "import time; time.sleep(60)"])

            protected = [start_claude(path) for path in (launcher, desktop, cli, custom)]
            preserved = [start_claude(unrelated), start([shell, "/d", "/q", "/k"])]
            helper = desktop.parent / "resources" / "claude-ssh-broker.exe"
            helper.parent.mkdir()
            shutil.copyfile(python, helper)
            future = launcher.parent / "app-1.2.4" / "claude.exe"
            stack.enter_context(patch("src.windows.windows_process_guard._registered_package_dirs", return_value=()))
            programs = {_path_key(str(path)) for path in (launcher, desktop, cli, custom, helper)}
            self.assertEqual(set(guard.approved_program_paths(settings)), programs)
            future.parent.mkdir()
            shutil.copyfile(python, future)
            self.assertEqual(set(guard.approved_program_paths(settings)), programs | {_path_key(str(future))})

            stack.enter_context(patch.object(backend, "WindowsFirewall"))
            stack.enter_context(patch.object(backend, "_private_paths"))
            stack.enter_context(patch.object(backend, "_strong_host_families", return_value={4}))
            config = ConfigManager(home / "config.json")
            config.config.update(settings, allowed_ips=["1.1.1.1"], protection_enabled=False)
            config.save_config()
            windows_guard = backend.WindowsGuard(config.path, process_guard=guard)
            stack.callback(windows_guard.close)
            stack.enter_context(patch.object(windows_guard._dns_checks, "run", side_effect=lambda fn, hosts, timeout: dict.fromkeys(hosts, set())))
            ip_checks = stack.enter_context(patch.object(windows_guard._ip_checks, "run"))
            self.assertEqual(windows_guard.tick()["state"], "disabled")
            self.assertTrue(all(child.poll() is None for child in protected + preserved))

            config.config["protection_enabled"] = True
            config.save_config()
            ip_checks.return_value = {4: ("1.1.1.1", "10.8.0.14")}
            self.assertEqual(windows_guard.tick()["state"], "allowed")
            self.assertTrue(all(child.poll() is None for child in protected + preserved))
            ip_checks.return_value = {}
            self.assertEqual(windows_guard.tick()["state"], "offline")
            self.assertTrue(all(child.poll() is None for child in protected + preserved))

            ip_checks.return_value = {4: ("9.9.9.9", "192.168.1.8")}
            blocked = windows_guard.tick()
            self.assertEqual(blocked["state"], "blocked")
            self.assertEqual((blocked["desktop_closed"], blocked["cli_closed"]), (2, 2))
            self.assertEqual([child.wait(timeout=5) for child in protected], [1] * 4)
            self.assertTrue(all(child.poll() is None for child in preserved))

            relaunched = start_claude(desktop)
            retried = windows_guard.enforce_processes()
            self.assertEqual((retried["desktop_closed"], retried["cli_closed"]), (3, 2))
            self.assertEqual(relaunched.wait(timeout=5), 1)
            self.assertTrue(all(child.poll() is None for child in preserved))


if __name__ == "__main__":
    unittest.main()
