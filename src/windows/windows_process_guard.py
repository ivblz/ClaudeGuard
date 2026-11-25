"""Close identified Claude processes when the Windows connection is blocked."""

import ctypes as ct
from contextlib import contextmanager
from ctypes import wintypes as wt
from dataclasses import dataclass
import ntpath
import os
from pathlib import Path, PureWindowsPath
import re
import stat

from src.windows.windows_platform import api, check, process_sid


CLAUDE_EXE = "claude.exe"
VERSION_DIR = re.compile(r"app-\d+(?:\.\d+)+(?:-[a-z0-9.-]+)?\Z")
CLAUDE_FAMILY = "Claude_pzs8sxrjxfjjc"
CLAUDE_PACKAGE = re.compile(r"claude_\d+(?:\.\d+){3}_(?:x86|x64|arm64|neutral)__pzs8sxrjxfjjc\Z")
HELPER_PATHS = frozenset({
    r"resources\chrome-native-host.exe",
    r"resources\claude-ssh-askpass.exe",
    r"resources\claude-ssh-broker.exe",
    r"resources\claude-ssh-proxy.exe",
    r"resources\app.asar.unpacked\resources\github-mcp\github-mcp-server.exe",
})
SHARED_EXECUTABLES = frozenset({
    "alacritty.exe", "bash.exe", "claudeguard.exe", "cmd.exe", "conhost.exe", "explorer.exe", "fish.exe",
    "git-bash.exe", "mintty.exe", "node.exe", "nu.exe", "openconsole.exe",
    "powershell.exe", "powershell_ise.exe", "pwsh.exe", "python.exe", "pythonw.exe",
    "sh.exe", "sing-box.exe", "wezterm.exe", "windowsterminal.exe", "wsl.exe", "wslhost.exe", "wt.exe",
    "zsh.exe",
})
GONE = frozenset({87, 1168})  # ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND
ERROR_NO_MORE_FILES = 18
ERROR_INSUFFICIENT_BUFFER = 122
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_TERMINATE = 0x0001
SYNCHRONIZE = 0x00100000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258


def _path_key(value):
    if not isinstance(value, str) or not value or "\0" in value:
        return ""
    value = ntpath.normcase(value)
    if value.startswith("\\\\?\\unc\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return ntpath.normpath(value) if PureWindowsPath(value).is_absolute() else ""


def _override(value):
    if not isinstance(value, str):
        return ""
    path = _path_key(os.path.expanduser(value))
    if not path.endswith(".exe") or ntpath.basename(path) in SHARED_EXECUTABLES:
        return ""
    return path


def _locations(home, local_app_data):
    home = str(Path.home() if home is None else home)
    local = str(local_app_data if local_app_data is not None else
                os.environ.get("LOCALAPPDATA") or ntpath.join(home, "AppData", "Local"))
    return home, local


def _claude_package_dir(full_name, get_path):
    if not CLAUDE_PACKAGE.fullmatch(full_name.lower()):
        return ""
    size = wt.DWORD()
    if get_path(full_name, ct.byref(size), None) != ERROR_INSUFFICIENT_BUFFER:
        return ""
    directory = ct.create_unicode_buffer(size.value)
    if get_path(full_name, ct.byref(size), directory):
        return ""
    return _path_key(directory.value)


def _registered_package_dirs():
    number = ct.POINTER(wt.DWORD)
    get_packages = api("kernel32", "GetPackagesByPackageFamily", wt.LONG, wt.LPCWSTR,
                       number, ct.POINTER(wt.LPWSTR), number, wt.LPWSTR)
    get_path = api("kernel32", "GetPackagePathByFullName", wt.LONG, wt.LPCWSTR, number, wt.LPWSTR)
    count, size = wt.DWORD(), wt.DWORD()
    if get_packages(CLAUDE_FAMILY, ct.byref(count), None, ct.byref(size), None) != ERROR_INSUFFICIENT_BUFFER:
        return ()
    packages = (wt.LPWSTR * count.value)()
    names = ct.create_unicode_buffer(size.value)
    if get_packages(CLAUDE_FAMILY, ct.byref(count), packages, ct.byref(size), names):
        return ()
    return tuple(directory for package in packages[:count.value]
                 if (directory := _claude_package_dir(package, get_path)))


def _is_plain(path, is_type):
    try:
        info = path.stat(follow_symlinks=False)
    except OSError:
        return False
    return (is_type(info.st_mode)
            and not (info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT))


def _installed_helpers(directory):
    paths = set()
    for relative in HELPER_PATHS:
        path = directory / relative
        parent = path.parent
        while parent != directory and _is_plain(parent, stat.S_ISDIR):
            parent = parent.parent
        if parent == directory and _is_plain(path, stat.S_ISREG):
            paths.add(str(path))
    return paths


def approved_program_paths(settings, *, home=None, local_app_data=None):
    """Return exact Claude executable paths for the Windows firewall policy."""
    if os.name != "nt":
        return ()
    targets = _Targets(settings, *_locations(home, local_app_data))
    overrides = targets.cli_exes | ({targets.desktop_exe} - {""})
    programs = {path for path in overrides if _is_plain(Path(path), stat.S_ISREG)}
    for root in map(Path, targets.desktop_dirs):
        if not _is_plain(root, stat.S_ISDIR):
            continue
        directories = [root]
        try:
            directories.extend(child for child in root.iterdir()
                               if VERSION_DIR.fullmatch(child.name.lower()) and _is_plain(child, stat.S_ISDIR))
        except (FileNotFoundError, NotADirectoryError):
            pass  # Squirrel can replace an installation while it is being scanned.
        for directory in directories:
            executable = directory / CLAUDE_EXE
            if _is_plain(executable, stat.S_ISREG):
                programs.add(str(executable))
                programs.update(_installed_helpers(directory))
    # WindowsApps can deny stat even when the package registration is visible.
    for root in _registered_package_dirs():
        for directory in (Path(root), Path(root) / "app"):
            programs.add(str(directory / CLAUDE_EXE))
            programs.update(_installed_helpers(directory))
    return tuple(sorted(programs))


class _Targets:
    def __init__(self, settings, home, local):
        self.desktop_exe = _override(settings.get("real_claude_app_path"))
        self.cli_exes = {
            _path_key(ntpath.join(home, ".local", "bin", CLAUDE_EXE)),
            _override(settings.get("real_claude_cli_path")),
        } - {""}
        self.desktop_dirs = {
            _path_key(ntpath.join(local, "AnthropicClaude")),
            _path_key(ntpath.join(local, "Programs", "Claude")),
        } - {""}
        self.names = {CLAUDE_EXE, *(ntpath.basename(path) for path in HELPER_PATHS),
                      *(ntpath.basename(path) for path in self.cli_exes)}
        if self.desktop_exe:
            self.names.add(ntpath.basename(self.desktop_exe))

    def desktop_dir(self, path, package):
        if path == self.desktop_exe:
            return ntpath.dirname(path)
        directory, exe = ntpath.split(path)
        if exe != CLAUDE_EXE:
            return ""
        parent, version = ntpath.split(directory)
        if directory in self.desktop_dirs or (parent in self.desktop_dirs and VERSION_DIR.fullmatch(version)):
            return directory
        if package and directory in (package, ntpath.join(package, "app")):
            return directory
        return ""


@dataclass(frozen=True)
class _Entry:
    pid: int
    parent_pid: int
    name: str


@dataclass(frozen=True)
class _Identity:
    path: str
    created: int
    sid: str
    session: int
    package: str = ""


@dataclass(frozen=True)
class ProcessReport:
    desktop_closed: int = 0
    cli_closed: int = 0
    error: str | None = None


class _ProcessEntry32(ct.Structure):
    _fields_ = [
        ("size", wt.DWORD), ("usage", wt.DWORD), ("pid", wt.DWORD),
        ("heap", ct.c_size_t), ("module_id", wt.DWORD), ("threads", wt.DWORD),
        ("parent_pid", wt.DWORD), ("priority", wt.LONG), ("flags", wt.DWORD),
        ("exe", wt.WCHAR * 260),
    ]


def _file_time(value):
    return (value.dwHighDateTime << 32) | value.dwLowDateTime


class _WindowsProcesses:
    def __init__(self):
        kernel = "kernel32"
        number = ct.POINTER(wt.DWORD)
        file_time = ct.POINTER(wt.FILETIME)
        entry = ct.POINTER(_ProcessEntry32)
        self._snapshot = api(kernel, "CreateToolhelp32Snapshot", wt.HANDLE, wt.DWORD, wt.DWORD)
        self._first = api(kernel, "Process32FirstW", wt.BOOL, wt.HANDLE, entry)
        self._next = api(kernel, "Process32NextW", wt.BOOL, wt.HANDLE, entry)
        self._open = api(kernel, "OpenProcess", wt.HANDLE, wt.DWORD, wt.BOOL, wt.DWORD)
        self._close = api(kernel, "CloseHandle", wt.BOOL, wt.HANDLE)
        self._image = api(kernel, "QueryFullProcessImageNameW", wt.BOOL, wt.HANDLE,
                          wt.DWORD, wt.LPWSTR, number)
        self._times = api(kernel, "GetProcessTimes", wt.BOOL, wt.HANDLE, *([file_time] * 4))
        self._now = api(kernel, "GetSystemTimePreciseAsFileTime", None, file_time)
        self._session = api(kernel, "ProcessIdToSessionId", wt.BOOL, wt.DWORD, number)
        self._pid = api(kernel, "GetProcessId", wt.DWORD, wt.HANDLE)
        self._package = api(kernel, "GetPackageFullName", wt.LONG, wt.HANDLE, number, wt.LPWSTR)
        self._package_path = api(kernel, "GetPackagePathByFullName", wt.LONG, wt.LPCWSTR, number, wt.LPWSTR)
        self._terminate = api(kernel, "TerminateProcess", wt.BOOL, wt.HANDLE, wt.UINT)
        self._wait = api(kernel, "WaitForSingleObject", wt.DWORD, wt.HANDLE, wt.DWORD)
        self.pid = os.getpid()
        self.sid = process_sid(api(kernel, "GetCurrentProcess", wt.HANDLE)())
        self.session = self.session_for(self.pid)

    def snapshot(self):
        timestamp = wt.FILETIME()
        self._now(ct.byref(timestamp))
        snapshot = self._snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
        if snapshot == ct.c_void_p(-1).value:
            raise ct.WinError(ct.get_last_error())
        entries = []
        try:
            entry = _ProcessEntry32()
            entry.size = ct.sizeof(entry)
            found = self._first(snapshot, ct.byref(entry))
            while found:
                entries.append(_Entry(entry.pid, entry.parent_pid, ntpath.normcase(entry.exe)))
                found = self._next(snapshot, ct.byref(entry))
            if ct.get_last_error() != ERROR_NO_MORE_FILES:
                raise ct.WinError(ct.get_last_error())
        finally:
            self._close(snapshot)
        return _file_time(timestamp), entries

    def session_for(self, pid):
        session = wt.DWORD()
        check(self._session(pid, ct.byref(session)))
        return session.value

    @contextmanager
    def open(self, pid, *, terminate=False):
        rights = PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE
        if terminate:
            rights |= PROCESS_TERMINATE
        handle = check(self._open(rights, False, pid))
        try:
            yield handle
        finally:
            self._close(handle)

    def _package_dir(self, handle):
        size = wt.DWORD()
        if self._package(handle, ct.byref(size), None) != ERROR_INSUFFICIENT_BUFFER:
            return ""
        package = ct.create_unicode_buffer(size.value)
        if self._package(handle, ct.byref(size), package):
            return ""
        return _claude_package_dir(package.value, self._package_path)

    def identity(self, handle):
        image = ct.create_unicode_buffer(32768)
        count = wt.DWORD(len(image))
        check(self._image(handle, 0, image, ct.byref(count)))
        path = _path_key(image.value)
        created, exited, kernel, user = (wt.FILETIME() for _ in range(4))
        check(self._times(handle, ct.byref(created), ct.byref(exited), ct.byref(kernel), ct.byref(user)))
        sid = process_sid(handle)
        session = self.session_for(check(self._pid(handle)))
        package = self._package_dir(handle) if ntpath.basename(path) == CLAUDE_EXE else ""
        return _Identity(path, _file_time(created), sid, session, package)

    def running(self, handle):
        result = self._wait(handle, 0)
        if result not in (WAIT_OBJECT_0, WAIT_TIMEOUT):
            raise ct.WinError(ct.get_last_error())
        return result == WAIT_TIMEOUT

    def close_process(self, handle):
        if not self._terminate(handle, 1):
            error = ct.WinError(ct.get_last_error())
            if not self.running(handle):
                return False
            raise error
        result = self._wait(handle, 200)
        if result == WAIT_TIMEOUT:
            raise OSError("Windows is still closing the process.")
        if result != WAIT_OBJECT_0:
            raise ct.WinError(ct.get_last_error())
        return True


class WindowsProcessGuard:
    def __init__(self, processes=None, *, home=None, local_app_data=None):
        self._processes = processes
        self._home, self._local = _locations(home, local_app_data)

    def approved_program_paths(self, settings):
        return approved_program_paths(settings, home=self._home, local_app_data=self._local)

    def _candidates(self, targets):
        processes = self._processes
        timestamp, entries = processes.snapshot()
        results = []
        for entry in entries:
            if entry.pid == processes.pid or entry.name not in targets.names:
                continue
            try:
                if processes.session_for(entry.pid) != processes.session:
                    continue
                with processes.open(entry.pid) as handle:
                    if not processes.running(handle):
                        continue
                    identity = processes.identity(handle)
            except OSError:
                # An entry may exit or be inaccessible before it can be identified.
                continue
            if (identity.sid == processes.sid and identity.session == processes.session
                    and identity.created <= timestamp and ntpath.basename(identity.path) == entry.name):
                results.append((entry, identity))
        return sorted(results, key=lambda result: result[1].created)

    def _identified(self, targets):
        desktop = {}
        for entry, identity in self._candidates(targets):
            directory = targets.desktop_dir(identity.path, identity.package)
            if not directory:
                parent = desktop.get(entry.parent_pid)
                if parent:
                    parent_dir, created = parent
                    if created < identity.created and identity.path.startswith(parent_dir + "\\"):
                        if identity.path[len(parent_dir) + 1:] in HELPER_PATHS:
                            directory = parent_dir
            if directory:
                desktop[entry.pid] = (directory, identity.created)
                yield entry.pid, identity, "desktop"
            elif identity.path in targets.cli_exes:
                yield entry.pid, identity, "cli"

    def enforce(self, settings, status, *, should_enforce=None):
        if status.get("state") != "blocked" or status.get("protection_enabled") is not True:
            return ProcessReport()
        if self._processes is None and os.name != "nt":
            return ProcessReport()
        if should_enforce is not None and not should_enforce():
            return ProcessReport()

        counts = {"desktop": 0, "cli": 0}
        error = None
        try:
            if self._processes is None:
                self._processes = _WindowsProcesses()
            processes = self._processes
            targets = _Targets(settings, self._home, self._local)
            for pid, identity, kind in self._identified(targets):
                if should_enforce is not None and not should_enforce():
                    break
                try:
                    with processes.open(pid, terminate=True) as handle:
                        # Query and terminate through this same handle. A process
                        # that replaced the snapshot PID cannot pass this check.
                        if not processes.running(handle) or processes.identity(handle) != identity:
                            continue
                        if should_enforce is not None and not should_enforce():
                            break
                        if processes.close_process(handle):
                            counts[kind] += 1
                except OSError as exc:
                    if getattr(exc, "winerror", None) not in GONE:
                        error = "Could not close every identified Claude process."
        except OSError:
            error = "Could not inspect Windows processes."
        return ProcessReport(counts["desktop"], counts["cli"], error)
