"""Windows shell integration used by the ClaudeGuard tray."""
import ctypes as ct
import json
import os
import shutil
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET
from ctypes import wintypes as wt
from pathlib import Path


APP_TITLE = "ClaudeGuard"
TASK_PREFIX = "ClaudeGuard-"
TASK_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"
ERROR_ALREADY_EXISTS = 183
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_CONSOLE = 0x10
CREATE_UNICODE_ENVIRONMENT = 0x400
EXTENDED_STARTUPINFO_PRESENT = 0x80000
POWERSHELL = r"WindowsPowerShell\v1.0\powershell.exe"


def api(dll, name, result, *arguments):
    function = getattr(ct.WinDLL(dll, use_last_error=True), name)
    function.restype = result
    function.argtypes = arguments
    return function


def check(result):
    if not result:
        raise ct.WinError(ct.get_last_error())
    return result


def notify(message, error=False):
    api("user32", "MessageBoxW", ct.c_int, wt.HWND, wt.LPCWSTR, wt.LPCWSTR, wt.UINT)(
        None, message, APP_TITLE, 0x10 if error else 0x40
    )


def app_command():
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, str(Path(__file__).with_name("windows_app.py"))]


def is_admin():
    return bool(api("shell32", "IsUserAnAdmin", wt.BOOL)())


def elevate(args):
    program, *arguments = app_command() + list(args)
    result = api("shell32", "ShellExecuteW", ct.c_ssize_t, wt.HWND, wt.LPCWSTR,
                 wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR, ct.c_int)(
        None, "runas", program, subprocess.list2cmdline(arguments), str(Path(program).parent), 1
    )
    return result > 32


def close_handle(handle):
    api("kernel32", "CloseHandle", wt.BOOL, wt.HANDLE)(handle)


def instance_handle():
    # Firewall policy is machine-wide, so the lock must cover logon sessions.
    create = api("kernel32", "CreateMutexW", wt.HANDLE, wt.LPVOID, wt.BOOL, wt.LPCWSTR)
    ct.set_last_error(0)
    handle = check(create(None, False, r"Global\ClaudeGuard-Windows"))
    if ct.get_last_error() != ERROR_ALREADY_EXISTS:
        return handle
    close_handle(handle)
    return None


def _activation_name():
    return "Local\\ClaudeGuard-Activate-" + current_sid()


def activation_event():
    """Auto-reset event used by a second launch to reveal the existing tray."""
    return check(api("kernel32", "CreateEventW", wt.HANDLE, wt.LPVOID, wt.BOOL,
                     wt.BOOL, wt.LPCWSTR)(None, False, False, _activation_name()))


def signal_existing_instance():
    handle = api("kernel32", "OpenEventW", wt.HANDLE, wt.DWORD, wt.BOOL,
                 wt.LPCWSTR)(0x0002, False, _activation_name())
    if not handle:
        return False
    try:
        return bool(api("kernel32", "SetEvent", wt.BOOL, wt.HANDLE)(handle))
    finally:
        close_handle(handle)


def consume_activation(handle):
    result = api("kernel32", "WaitForSingleObject", wt.DWORD, wt.HANDLE,
                 wt.DWORD)(handle, 0)
    if result == 0xFFFFFFFF:
        raise ct.WinError(ct.get_last_error())
    return result == 0


def system_directory():
    path = ct.create_unicode_buffer(32768)
    check(api("kernel32", "GetSystemDirectoryW", wt.UINT, wt.LPWSTR, wt.UINT)(path, len(path)))
    return Path(path.value)


def run_system(command, *, timeout=15, **options):
    executable, *arguments = command
    system = system_directory()
    env = os.environ.copy()
    env.update(SYSTEMROOT=str(system.parent), WINDIR=str(system.parent),
               PATH=os.pathsep.join(map(str, (system, system / "Wbem", (system / POWERSHELL).parent))),
               PSMODULEPATH=str((system / POWERSHELL).parent / "Modules"))
    if options.get("encoding") or options.get("text"):
        options.setdefault("errors", "replace")
    restore_dll_dir = getattr(sys, "_MEIPASS", None)
    set_dll_dir = api("kernel32", "SetDllDirectoryW", wt.BOOL, wt.LPCWSTR)
    if restore_dll_dir:
        check(set_dll_dir(None))
    try:
        return subprocess.run([str(system / executable), *arguments], env=env,
                              creationflags=CREATE_NO_WINDOW, capture_output=True, timeout=timeout,
                              cwd=system, **options)
    finally:
        if restore_dll_dir:
            set_dll_dir(restore_dll_dir)


def token_sid(token):
    get_info = api("advapi32", "GetTokenInformation", wt.BOOL, wt.HANDLE, ct.c_int,
                   wt.LPVOID, wt.DWORD, ct.POINTER(wt.DWORD))
    needed = wt.DWORD()
    get_info(token, 1, None, 0, ct.byref(needed))
    check(needed.value)
    token_user = ct.create_string_buffer(needed.value)
    check(get_info(token, 1, token_user, needed, ct.byref(needed)))
    sid = ct.cast(token_user, ct.POINTER(ct.c_void_p))[0]
    string_sid = wt.LPWSTR()
    check(api("advapi32", "ConvertSidToStringSidW", wt.BOOL, wt.LPVOID,
              ct.POINTER(wt.LPWSTR))(sid, ct.byref(string_sid)))
    try:
        return string_sid.value
    finally:
        api("kernel32", "LocalFree", wt.HLOCAL, wt.HLOCAL)(ct.cast(string_sid, wt.HLOCAL))


def process_sid(process):
    token = wt.HANDLE()
    check(api("advapi32", "OpenProcessToken", wt.BOOL, wt.HANDLE, wt.DWORD,
              ct.POINTER(wt.HANDLE))(process, 8, ct.byref(token)))
    try:
        return token_sid(token)
    finally:
        close_handle(token)


def current_sid():
    return process_sid(api("kernel32", "GetCurrentProcess", wt.HANDLE)())


def shell_process(rights):
    shell = api("user32", "GetShellWindow", wt.HWND)()
    if not shell:
        raise RuntimeError("The Windows desktop shell is unavailable.")
    pid = wt.DWORD()
    check(api("user32", "GetWindowThreadProcessId", wt.DWORD, wt.HWND,
              ct.POINTER(wt.DWORD))(shell, ct.byref(pid)))
    return check(api("kernel32", "OpenProcess", wt.HANDLE, wt.DWORD, wt.BOOL, wt.DWORD)(
        rights, False, pid
    ))


def is_interactive_account():
    try:
        shell = shell_process(0x1000)  # PROCESS_QUERY_LIMITED_INFORMATION
    except RuntimeError:
        return False
    try:
        return process_sid(shell) == current_sid()
    finally:
        close_handle(shell)


class StartupInfo(ct.Structure):
    _fields_ = [
        ("cb", wt.DWORD), ("lpReserved", wt.LPWSTR), ("lpDesktop", wt.LPWSTR),
        ("lpTitle", wt.LPWSTR), ("dwX", wt.DWORD), ("dwY", wt.DWORD),
        ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD), ("dwXCountChars", wt.DWORD),
        ("dwYCountChars", wt.DWORD), ("dwFillAttribute", wt.DWORD), ("dwFlags", wt.DWORD),
        ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD), ("lpReserved2", wt.LPVOID),
        ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE), ("hStdError", wt.HANDLE),
    ]


class StartupInfoEx(ct.Structure):
    _fields_ = [("startup", StartupInfo), ("attributes", wt.LPVOID)]


class ProcessInfo(ct.Structure):
    _fields_ = [("process", wt.HANDLE), ("thread", wt.HANDLE),
                ("pid", wt.DWORD), ("tid", wt.DWORD)]


def launch_from_shell(command, *, env=None, console=False, wait=False, bundled=False):
    """Create the process with Explorer's token, including when the tray is elevated."""
    # https://devblogs.microsoft.com/oldnewthing/20190425-00/?p=102443
    initialize = api("kernel32", "InitializeProcThreadAttributeList", wt.BOOL,
                     wt.LPVOID, wt.DWORD, wt.DWORD, ct.POINTER(ct.c_size_t))
    size = ct.c_size_t()
    initialize(None, 1, 0, ct.byref(size))
    check(size.value)
    attributes = ct.create_string_buffer(size.value)
    shell = wt.HANDLE(shell_process(0x0080))  # PROCESS_CREATE_PROCESS
    try:
        check(initialize(attributes, 1, 0, ct.byref(size)))
        try:
            update = api("kernel32", "UpdateProcThreadAttribute", wt.BOOL, wt.LPVOID,
                         wt.DWORD, ct.c_size_t, wt.LPVOID, ct.c_size_t, wt.LPVOID, wt.LPVOID)
            check(update(attributes, 0, 0x00020000, ct.byref(shell), ct.sizeof(shell), None, None))
            startup = StartupInfoEx()
            startup.startup.cb = ct.sizeof(startup)
            startup.attributes = ct.cast(attributes, wt.LPVOID)
            child = ProcessInfo()
            line = ct.create_unicode_buffer(subprocess.list2cmdline([str(arg) for arg in command]))
            flags = EXTENDED_STARTUPINFO_PRESENT | (CREATE_NEW_CONSOLE if console else CREATE_NO_WINDOW)
            environment = None
            if env is not None:
                values = [f"{key}={env[key]}" for key in sorted(env, key=str.casefold)]
                environment = ct.create_unicode_buffer("\0".join(values) + "\0")
                flags |= CREATE_UNICODE_ENVIRONMENT
            create = api("kernel32", "CreateProcessW", wt.BOOL, wt.LPCWSTR, wt.LPWSTR,
                         wt.LPVOID, wt.LPVOID, wt.BOOL, wt.DWORD, wt.LPVOID, wt.LPCWSTR,
                         ct.POINTER(StartupInfoEx), ct.POINTER(ProcessInfo))
            set_dll_dir = api("kernel32", "SetDllDirectoryW", wt.BOOL, wt.LPCWSTR)
            restore_dll_dir = getattr(sys, "_MEIPASS", None) if not bundled else None
            if restore_dll_dir:
                check(set_dll_dir(None))
            try:
                check(create(str(command[0]), line, None, None, False, flags, environment,
                             str(Path.home()), ct.byref(startup), ct.byref(child)))
            finally:
                if restore_dll_dir:
                    set_dll_dir(restore_dll_dir)
            close_handle(child.thread)
            try:
                if wait:
                    result = api("kernel32", "WaitForSingleObject", wt.DWORD, wt.HANDLE,
                                 wt.DWORD)(child.process, 10000)
                    if result == 0x102:
                        raise RuntimeError("Windows timed out while starting the application.")
                    if result:
                        raise ct.WinError(ct.get_last_error())
                    code = wt.DWORD()
                    check(api("kernel32", "GetExitCodeProcess", wt.BOOL, wt.HANDLE,
                              ct.POINTER(wt.DWORD))(child.process, ct.byref(code)))
                    if code.value:
                        raise RuntimeError(f"Windows could not start the application (exit code {code.value}).")
            finally:
                close_handle(child.process)
        finally:
            api("kernel32", "DeleteProcThreadAttributeList", None, wt.LPVOID)(attributes)
    finally:
        close_handle(shell)


class GUID(ct.Structure):
    _fields_ = [("value", ct.c_ubyte * 16)]

    @classmethod
    def parse(cls, value):
        return cls.from_buffer_copy(uuid.UUID(value).bytes_le)


def activate_desktop(app_id, arguments):
    """Called by a separate, unelevated copy of the tray for MSIX activation."""
    ole32 = ct.WinDLL("ole32")
    if ole32.CoInitializeEx(None, 2) < 0:
        return 1
    try:
        manager_id = GUID.parse("45BA127D-10A8-46EA-8AB7-56EA9078943C")
        interface_id = GUID.parse("2E941141-7F97-4756-BA1D-9DECDE894A3D")
        instance = ct.c_void_p()
        if ole32.CoCreateInstance(ct.byref(manager_id), None, 4, ct.byref(interface_id),
                                  ct.byref(instance)) < 0:
            return 1
        vtable = ct.cast(instance, ct.POINTER(ct.POINTER(ct.c_void_p))).contents
        release = ct.WINFUNCTYPE(wt.ULONG, ct.c_void_p)(vtable[2])
        try:
            activate = ct.WINFUNCTYPE(ct.c_long, ct.c_void_p, wt.LPCWSTR, wt.LPCWSTR,
                                      wt.DWORD, ct.POINTER(wt.DWORD))(vtable[3])
            pid = wt.DWORD()
            return int(activate(instance, app_id, subprocess.list2cmdline(arguments),
                                2, ct.byref(pid)) < 0)  # AO_NOERRORUI
        finally:
            release(instance)
    finally:
        ole32.CoUninitialize()


def discover_desktop_app():
    local = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    for path in (local / "AnthropicClaude" / "Claude.exe",
                 local / "Programs" / "Claude" / "Claude.exe"):
        if path.is_file():
            return path
    script = ("[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
              "Get-StartApps -Name Claude | Where-Object { $_.Name -eq 'Claude' "
              "-and $_.AppID -like 'Claude_*!*' } | Select-Object -First 1 "
              "-ExpandProperty AppID | ConvertTo-Json -Compress")
    result = run_system([POWERSHELL, "-NoProfile", "-NonInteractive",
                         "-Command", script], encoding="utf-8", errors="replace")
    output = result.stdout.strip()
    if result.returncode == 0 and output:
        return json.loads(output)
    return None


def discover_cli():
    native = Path.home() / ".local" / "bin" / "claude.exe"
    if native.is_file():
        return native
    path = shutil.which("claude.exe")
    return Path(path) if path else None


def startup_task_name():
    return TASK_PREFIX + current_sid()


def startup_enabled():
    result = run_system(["schtasks.exe", "/Query", "/TN", startup_task_name(), "/XML"])
    if result.returncode:
        return False
    xml = result.stdout
    if xml.startswith((b"\xff\xfe", b"\xfe\xff")):
        xml = xml.decode("utf-16")
    elif xml.startswith(b"<\x00"):
        xml = xml.decode("utf-16-le")
    else:
        # Redirected schtasks output can declare UTF-16 yet use the console code page.
        xml = xml.decode("oem" if os.name == "nt" else "utf-8")
    task = ET.fromstring(xml)
    program = task.findtext(f".//{{{TASK_NS}}}Exec/{{{TASK_NS}}}Command", default="")
    enabled = task.findtext(f".//{{{TASK_NS}}}Settings/{{{TASK_NS}}}Enabled", default="true")
    level = task.findtext(f".//{{{TASK_NS}}}Principal/{{{TASK_NS}}}RunLevel", default="LeastPrivilege")
    return (enabled == "true" and level == "HighestAvailable"
            and Path(program).resolve() == Path(sys.executable).resolve())


def installed_program(sid):
    folder = ct.create_unicode_buffer(260)
    # CSIDL_PROGRAM_FILES is the system installation directory for this x64 app.
    lookup = api("shell32", "SHGetFolderPathW", ct.c_long, wt.HWND, ct.c_int,
                 wt.HANDLE, wt.DWORD, wt.LPWSTR)
    if lookup(None, 0x26, None, 0, folder):
        raise RuntimeError("Could not locate Program Files.")
    return Path(folder.value) / f"ClaudeGuard-{sid}" / "ClaudeGuard.exe"


def set_startup(enabled):
    task = startup_task_name()
    if not enabled:
        command = ["schtasks.exe", "/Delete", "/TN", task, "/F"]
        if run_system(["schtasks.exe", "/Query", "/TN", task]).returncode:
            return
        if run_system(command).returncode:
            raise RuntimeError("Task Scheduler could not remove the ClaudeGuard sign-in task.")
        return
    if not getattr(sys, "frozen", False):
        raise RuntimeError("Sign-in startup is available in the Windows release.")
    sid = current_sid()
    program = Path(sys.executable).resolve()
    if program != installed_program(sid):
        raise RuntimeError("Run Install.cmd before enabling sign-in startup.")
    definition = ET.Element("Task", {"version": "1.4", "xmlns": TASK_NS})
    triggers = ET.SubElement(definition, "Triggers")
    trigger = ET.SubElement(triggers, "LogonTrigger")
    ET.SubElement(trigger, "UserId").text = sid
    ET.SubElement(trigger, "Delay").text = "PT10S"
    principal = ET.SubElement(ET.SubElement(definition, "Principals"), "Principal", id="User")
    ET.SubElement(principal, "UserId").text = sid
    ET.SubElement(principal, "LogonType").text = "InteractiveToken"
    ET.SubElement(principal, "RunLevel").text = "HighestAvailable"
    settings = ET.SubElement(definition, "Settings")
    ET.SubElement(settings, "DisallowStartIfOnBatteries").text = "false"
    ET.SubElement(settings, "StopIfGoingOnBatteries").text = "false"
    ET.SubElement(settings, "ExecutionTimeLimit").text = "PT0S"
    action = ET.SubElement(ET.SubElement(definition, "Actions", Context="User"), "Exec")
    ET.SubElement(action, "Command").text = str(program)
    ET.SubElement(action, "Arguments").text = "--startup"
    ET.SubElement(action, "WorkingDirectory").text = str(program.parent)
    # Pass the definition through stdin so registration does not rely on a temporary file.
    script = ("$ErrorActionPreference = 'Stop'; "
              "$data = [Console]::In.ReadToEnd() | ConvertFrom-Json; "
              "Register-ScheduledTask -TaskName $data.name -Xml $data.xml -Force | Out-Null")
    result = run_system([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
                        input=json.dumps({"name": task, "xml": ET.tostring(definition, encoding="unicode")}),
                        encoding="ascii")
    if result.returncode:
        raise RuntimeError("Task Scheduler could not register ClaudeGuard to start at sign-in.")
