"""ClaudeGuard notification-area application for Windows 10 and 11."""
import argparse
import json
import logging
import os
import queue
import re
import stat
import subprocess
import sys
import threading
import time
import traceback
from logging.handlers import RotatingFileHandler
from pathlib import Path

if __package__ in (None, "") and not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.windows import windows_platform as platform
from src.windows.windows_config import CONFIG_PATH, DEFAULT_CONFIG, ConfigManager, validate_whitelist_entry
from src.proxy_config import parse_profile


PROCESS_CHECK_INTERVAL = 3
EVENT_POLL_MS = 40
LOGGER = logging.getLogger("claudeguard.windows")
LOGGER.addHandler(logging.NullHandler())
LOGGER.propagate = False


def configure_diagnostics():
    path = Path(CONFIG_PATH).parent / "windows-runtime" / "tray.log"
    try:
        for entry in (*reversed(path.parents), path, path.with_suffix(".log.1")):
            try:
                info = entry.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            if getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                return
        path.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(path, maxBytes=262144, backupCount=1, encoding="utf-8")
    except OSError:
        return
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.INFO)


def log_failure(operation, error):
    # A launch or networking exception can contain settings or credentials.
    # Record stack locations and exception types without messages, locals or arguments.
    stack = " <- ".join(f"{Path(frame.filename).name}:{frame.lineno}:{frame.name}"
                        for frame in traceback.extract_tb(error.__traceback__))
    LOGGER.error("%s (%s) %s", operation, type(error).__name__, stack)


def whitelist_entries(value):
    entries = [validate_whitelist_entry(entry) for entry in re.split(r"[,\s]+", value.strip()) if entry]
    return list(dict.fromkeys(entries))


def model_id(value):
    value = value.strip()
    if not value or value.startswith("-") or re.search(r"\s|[\x00-\x1f]", value):
        raise ValueError("Enter a Claude model ID such as claude-opus-4-8.")
    return value


def executable_override(name, value):
    value = value.strip()
    if value:
        path = Path(value).expanduser()
        if not path.is_absolute() or path.suffix.lower() != ".exe" or not path.is_file():
            raise ValueError(f"Select an existing {name} executable or clear its override.")
    return value


def notification_icon(name, image, title, open_menu):
    from pystray._win32 import Icon, win32
    from src.windows.windows_menu import pointer_position

    update_message = win32.WM_USER + 12

    class MenuIcon(Icon):
        def __init__(self):
            super().__init__(name, image, title)
            self._message_handlers[update_message] = self._apply_status
            self.requested_status = image, title
            self.stopping = threading.Event()

        def run(self):
            # All shell calls stay on the icon thread. pystray's default setup
            # thread waits indefinitely if creating the Win32 window fails.
            try:
                self._run()
            finally:
                self._HWND_TO_ICON.pop(self._hwnd, None)
                self._hwnd = None
                self._release_icon()

        def _mark_ready(self):
            self.update_menu()
            try:
                win32.ChangeWindowMessageFilterEx(self._hwnd, win32.WM_NOTIFY, win32.MSGFLT_ALLOW, None)
            except OSError as error:
                log_failure("Allowing notification-area clicks", error)
            if self.stopping.is_set():
                self._stop()
            else:
                win32.PostMessage(self._hwnd, update_message, 0, 0)

        def set_status(self, image, title):
            self.requested_status = image, title
            if self._hwnd and not self.stopping.is_set():
                win32.PostMessage(self._hwnd, update_message, 0, 0)

        def _apply_status(self, wparam, lparam):
            if self.stopping.is_set():
                return
            try:
                image, title = self.requested_status
                if self.icon is not image:
                    self.icon = image
                if self.title != title:
                    self.title = title
                self.visible = True
            except Exception as error:
                log_failure("Updating the notification-area icon", error)

        def stop(self):
            self.stopping.set()
            if self._hwnd:
                self._stop()

        def _on_notify(self, wparam, lparam):
            if lparam in (win32.WM_LBUTTONUP, win32.WM_RBUTTONUP):
                open_menu(pointer_position())

    return MenuIcon()


def app_path(configured, discover):
    if configured:
        path = Path(configured).expanduser()
        if path.is_absolute() and path.suffix.lower() == ".exe" and path.is_file():
            return path
        raise RuntimeError("The configured executable could not be found. Update it under Configure Claude apps.")
    return discover()


def launch_environment():
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("_PYI_")}
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    return env


def launch_claude(kind, config, status):
    protection_enabled = config.get("protection_enabled") is not False
    if status.get("protection_enabled") != protection_enabled:
        raise RuntimeError("Protection settings changed. Check the connection and try again.")
    allowed = status["state"] == "allowed" and status.get("protected")
    if protection_enabled and not allowed:
        raise RuntimeError(status.get("error") or "ClaudeGuard has blocked access on this connection.")

    proxy = status.get("proxy_url") if protection_enabled and status["mode"] == "proxy" else None
    if protection_enabled and status["mode"] == "proxy" and not proxy:
        raise RuntimeError("The local proxy is unavailable.")

    if kind == "desktop":
        target = app_path(config.get("real_claude_app_path"), platform.discover_desktop_app)
        if target is None:
            raise RuntimeError("Claude Desktop was not found. Select its executable under Configure Claude apps.")
        args = [f"--proxy-server={proxy}", "--disable-quic"] if proxy else []
        if isinstance(target, Path):
            platform.launch_from_shell([target, *args], env=launch_environment())
        else:
            platform.launch_from_shell([*platform.app_command(), "--activate-desktop", target, *args],
                                       env=launch_environment(), wait=True, bundled=True)
        return

    target = app_path(config.get("real_claude_cli_path"), platform.discover_cli)
    if target is None:
        raise RuntimeError("Claude Code was not found. Install its native Windows build or select claude.exe under Configure Claude apps.")
    model = config.get("default_model")
    args = ["--model", model] if config.get("model_override_enabled") and model else []
    env = launch_environment()
    if proxy:
        names = {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
        env = {key: value for key, value in env.items() if key.casefold() not in names}
        env.update(HTTP_PROXY=proxy, HTTPS_PROXY=proxy, ALL_PROXY=proxy, NO_PROXY="")
    platform.launch_from_shell([target, *args], env=env, console=True)


def render_icon(state, light=None):
    from src.windows.windows_tray_icon import render_tray_icon

    return render_tray_icon(state, light)


class Tray:
    def __init__(self, root, guard, activation):
        from PIL import Image, ImageTk
        from src.windows.windows_menu import TrayMenu
        from src.windows.windows_tray_icon import tray_theme

        self.root = root
        root.withdraw()
        asset_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[2]))
        asset = asset_dir / "assets" / "AppIcon.png"
        if asset.is_file():
            with Image.open(asset) as image:
                self.window_icon = ImageTk.PhotoImage(image.resize((48, 48)), master=root)
        else:
            self.window_icon = ImageTk.PhotoImage(render_icon("checking"), master=root)
        root.iconphoto(True, self.window_icon)
        self.guard = guard
        self.activation = activation
        self.config = None
        self.data = None
        self.work = queue.Queue()
        self.events = queue.Queue()
        self.dialog = None
        self.pending_patch = None
        self.status = {"state": "checking"}
        self.closing = False
        self.finished = False
        self.refresh_queued = False
        self.notified_block_episode = 0
        self.process_stop = threading.Event()
        self.tray_state = "checking"
        self.icon_theme = tray_theme()
        self.tray_image = render_icon(self.tray_state, self.icon_theme)
        self.menu = TrayMenu(root, {
            "mode": self.select_mode, "refresh": self.refresh, "protection": self.toggle_protection,
            "model": self.toggle_model, "change_model": self.change_model, "add_ip": self.add_current_ip,
            "manage_ips": self.manage_ips, "proxy": self.configure_proxy, "quit": self.confirm_quit,
            "desktop": lambda: self.launch("desktop"), "cli": lambda: self.launch("cli"),
            "app_paths": self.configure_app_paths, "startup": self.open_startup,
        })
        self.icon = notification_icon(
            "ClaudeGuard", self.tray_image, "ClaudeGuard",
            lambda anchor: self.events.put((self.open_menu, (anchor,))),
        )
        self.render_status()
        self.tray_thread = threading.Thread(target=self.run_icon, daemon=True)
        self.worker = threading.Thread(target=self.run_guard, daemon=True)
        self.process_worker = threading.Thread(target=self.run_process_monitor, daemon=True)
        self.worker.start()
        self.process_worker.start()
        self.tray_thread.start()
        root.after(EVENT_POLL_MS, self.handle_events)

    def run_icon(self):
        try:
            self.icon.run()
        except Exception as error:
            log_failure("Running the notification-area icon", error)
        if not self.closing:
            LOGGER.error("The notification-area icon stopped unexpectedly")
            self.events.put((self.show_error, ("The Windows notification-area icon could not start.",)))

    def handle_events(self):
        if self.finished:
            return
        self.root.after(EVENT_POLL_MS, self.handle_events)
        if not self.closing:
            try:
                if platform.consume_activation(self.activation):
                    self.open_menu()
                    LOGGER.info("ClaudeGuard opened from a second launch")
            except Exception as error:
                log_failure("Opening ClaudeGuard from a second launch", error)
        for _ in range(8):
            try:
                callback, args = self.events.get_nowait()
            except queue.Empty:
                break
            if self.closing and callback != self.finish_quit:
                continue
            try:
                callback(*args)
            except Exception as error:
                name = getattr(callback, "__name__", type(callback).__name__)
                log_failure(f"Tray callback {name}", error)
            if self.finished:
                return

    def open_menu(self, anchor=None):
        if self.closing:
            return
        if self.dialog is None:
            from src.windows import windows_menu
            light = windows_menu.tray_theme("AppsUseLightTheme")
            if light != windows_menu.LIGHT:
                actions = self.menu.actions
                self.menu.hide()
                self.menu.window.destroy()
                windows_menu.set_theme(light)
                self.menu = windows_menu.TrayMenu(self.root, actions)
                self.render_status()
            self.menu.show(anchor)
        else:
            self.dialog.window.lift()
            self.dialog.window.focus_force()

    def refresh(self):
        if not self.closing and self.pending_patch is None and not self.refresh_queued:
            self.refresh_queued = True
            self.status = {**self.status, "state": "checking", "error": None}
            self.render_status()
            self.work.put(("refresh", time.monotonic()))

    def launch(self, kind):
        if not self.closing and self.data is not None and self.pending_patch is None:
            self.work.put(("launch", kind))

    def run_process_monitor(self):
        previous = (None, 0, 0, None)
        while not self.process_stop.wait(PROCESS_CHECK_INTERVAL):
            try:
                status = self.guard.enforce_processes()
            except Exception as error:
                log_failure("Checking Claude processes", error)
                continue
            result = (status.get("block_episode"), status.get("desktop_closed", 0),
                      status.get("cli_closed", 0), status.get("process_enforcement_error"))
            if result != previous:
                previous = result
                self.events.put((self.show_process_status, (status,)))

    def run_guard(self):
        interval = 0
        last_check = 0
        while True:
            try:
                action, argument = self.work.get(timeout=interval)
            except queue.Empty:
                action, argument = "check", None

            if action == "quit" or self.closing:
                error = None
                try:
                    self.process_stop.set()
                    self.guard.close()
                except Exception as exc:
                    log_failure("Closing the Windows protection backend", exc)
                    error = str(exc) or "Could not finish updating protection."
                self.events.put((self.finish_quit, (error,)))
                return

            if action in ("get_startup", "set_startup"):
                try:
                    if action == "get_startup":
                        self.events.put((self.show_startup, (platform.startup_enabled(),)))
                    else:
                        platform.set_startup(argument)
                except Exception as exc:
                    log_failure("Managing sign-in startup", exc)
                    self.events.put((self.show_error, (str(exc) or "Could not update sign-in startup.",)))
                continue

            if action == "refresh" and argument is not None and argument <= last_check:
                self.events.put((self.refresh_finished, (status, data)))
                continue
            error = None
            data = None
            started = time.monotonic()
            try:
                if self.config is None:
                    LOGGER.info("Preparing the Windows protection backend")
                    self.guard.prepare()
                    self.config = ConfigManager(CONFIG_PATH)
                    LOGGER.info("Windows protection backend ready")
                    if self.closing:
                        continue
                if action == "settings":
                    try:
                        data = self.config.load_config()
                        updated = {**data, **argument}
                        self.config.save_config(updated)
                        data = updated
                    finally:
                        if not self.closing:
                            self.guard.resume_process_verdict()
                if self.closing:
                    continue
                status = self.guard.tick(enforce_processes=False)
                if action != "settings":
                    data = self.config.load_config()
                if action == "launch" and not self.closing:
                    launch_claude(argument, data, status)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
                log_failure(f"Windows protection action {action}", exc)
                error = str(exc) or "Windows could not complete the requested action."
                status = self.guard.status() if action == "launch" else {"state": "error", "error": error}
            except Exception as exc:
                log_failure(f"Windows protection action {action}", exc)
                error = "ClaudeGuard encountered an unexpected error."
                status = {"state": "error", "error": error}

            last_check = time.monotonic()
            LOGGER.info("Connection check (%s, %s) finished in %.2fs",
                        action, status.get("state", "unknown"), last_check - started)
            if action == "settings":
                self.events.put((self.settings_saved, (status, data, error)))
            elif action == "refresh":
                self.events.put((self.refresh_finished, (status, data)))
            elif action == "launch" and error:
                self.events.put((self.show_launch_error, (status, data, error)))
            else:
                self.events.put((self.show_status, (status, data)))
            interval = status.get("check_interval", 3)

    def refresh_finished(self, status, data):
        self.refresh_queued = False
        self.show_status(status, data)

    def show_status(self, status, data):
        if data is not None:
            self.data = data
        self.status = status
        self.render_status()
        return self.show_blocked_alert(status)

    def show_launch_error(self, status, data, error):
        if not self.show_status(status, data) and not self.closing:
            self.show_error(error)

    def show_process_status(self, status):
        if self.closing:
            return
        if self.status.get("block_episode") is not None:
            self.render_status()
        self.show_blocked_alert(status)

    def show_blocked_alert(self, status):
        episode = status.get("block_episode")
        if (self.closing or self.pending_patch is not None or status.get("state") != "blocked" or episode is None
                or episode <= self.notified_block_episode):
            return False
        desktop = status.get("desktop_closed")
        cli = status.get("cli_closed")
        if not (desktop or cli):
            return False

        current = self.guard.status()
        if current.get("state") != "blocked" or current.get("block_episode") != episode:
            return False

        self.notified_block_episode = episode
        message = ("Claude Desktop and Claude Code were closed." if desktop and cli else
                   "Claude Desktop was closed." if desktop else "Claude Code was closed.")
        reason = status.get("error") or "ClaudeGuard has blocked access on this connection."
        self.show_error(f"{message}\n\n{reason}", title="ClaudeGuard 🚫 Blocked")
        return True

    def render_status(self):
        from src.windows.windows_menu import status_label
        from src.windows.windows_tray_icon import tray_theme

        pending = self.pending_patch is not None
        data = self.data if self.data is not None else DEFAULT_CONFIG
        if pending:
            data = {**data, **self.pending_patch}
        status = {"state": "checking"} if pending else self.status
        episode = status.get("block_episode")
        if episode is not None:
            current = self.guard.status()
            warning = current.get("process_enforcement_error")
            if current.get("block_episode") == episode and warning:
                details = "\n\n".join(filter(None, (status.get("error"), warning)))
                status = {**status, "error": details}
        mode = "proxy" if data.get("connection_mode") == "proxy" else "vpn"
        current_ip = status.get("ip") if status.get("mode") == mode == "vpn" else None
        self.menu.update(status, data, current_ip, pending=pending or self.data is None or self.closing)
        state = status.get("state", "checking")
        light = tray_theme()
        if (state, light) != (self.tray_state, self.icon_theme):
            self.tray_state = state
            self.icon_theme = light
            self.tray_image = render_icon(state, light)
        label, _ = status_label(status, mode, data)
        self.icon.set_status(self.tray_image, f"ClaudeGuard — {label}")

    def save_settings(self, patch):
        if self.closing or self.data is None or self.pending_patch is not None:
            return
        self.guard.invalidate_process_verdict()
        self.pending_patch = patch
        self.render_status()
        self.work.put(("settings", patch))

    def settings_saved(self, status, data, error):
        self.pending_patch = None
        self.show_status(status, data)
        error = error or (status.get("error") if status.get("state") == "error" else None)
        if error:
            self.show_error(error)

    def select_mode(self, mode):
        self.save_settings({"connection_mode": mode})

    def toggle_protection(self):
        self.save_settings({"protection_enabled": self.data.get("protection_enabled") is False})

    def toggle_model(self):
        enabled = not self.data.get("model_override_enabled")
        patch = {"model_override_enabled": enabled}
        if enabled:
            try:
                model_id(self.data.get("default_model") or "")
            except (TypeError, AttributeError, ValueError):
                patch["default_model"] = DEFAULT_CONFIG["default_model"]
        self.save_settings(patch)

    def prompt(self, title, text, value, validate, *, multiline=False):
        from src.windows.windows_menu import Dialog

        self.dialog = dialog = Dialog(self.root, title)
        try:
            dialog.label(text)
            field = dialog.field(value, multiline=multiline)
            field.pack(fill="x")
            read = (lambda: field.get("1.0", "end-1c")) if multiline else field.get
            return dialog.show(field, lambda: validate(read().strip()), multiline=multiline)
        finally:
            self.dialog = None

    def change_model(self):
        entered = self.prompt("ClaudeGuard Default Model",
                              "Enter Claude model ID (e.g. claude-opus-4-8):",
                              self.data.get("default_model") or "", model_id)
        if entered is not None:
            self.save_settings({"default_model": entered})

    def add_current_ip(self):
        if self.status.get("mode") == "vpn" and self.status.get("ip"):
            ip = validate_whitelist_entry(self.status["ip"])
            entries = self.data.get("allowed_ips")
            if not isinstance(entries, list):
                entries = []
            self.save_settings({"allowed_ips": list(dict.fromkeys([*entries, ip]))})

    def manage_ips(self):
        entries = self.data.get("allowed_ips")
        value = ", ".join(str(entry) for entry in entries) if isinstance(entries, list) else ""
        entered = self.prompt("ClaudeGuard IP Whitelist",
                              "Enter Whitelisted VPN IPs (comma separated):", value, whitelist_entries)
        if entered is not None:
            self.save_settings({"allowed_ips": entered})

    def configure_proxy(self):
        profile = self.data.get("proxy_profile")
        value = json.dumps(profile, ensure_ascii=False, indent=2) if profile else ""
        entered = self.prompt(
            "ClaudeGuard Proxy",
            "Enter a proxy URL or outbound JSON. Leave empty to remove the profile. "
            "To use the proxy, close Claude and relaunch it from the ⋯ menu.",
            value, lambda text: {"proxy_profile": parse_profile(text) if text else None,
                                 "proxy_enabled": True, "connection_mode": "proxy"},
            multiline=True,
        )
        if entered is not None:
            self.save_settings(entered)

    def configure_app_paths(self):
        import tkinter as tk
        from tkinter import filedialog
        from src.windows.windows_menu import Dialog, styled_button

        if self.closing or self.data is None or self.pending_patch is not None:
            return
        self.dialog = dialog = Dialog(self.root, "ClaudeGuard Apps")
        try:
            fields = {}
            for key, name in (("real_claude_app_path", "Claude Desktop"), ("real_claude_cli_path", "Claude Code")):
                dialog.label(f"{name} executable")
                row = tk.Frame(dialog.body, bg=dialog.body["bg"])
                row.pack(fill="x", pady=(0, dialog.px(8)))
                value = self.data.get(key)
                field = dialog.field(value if isinstance(value, str) and value.lower().endswith(".exe") else "",
                                     parent=row)
                field.pack(side="left", fill="x", expand=True)
                fields[key] = name, field

                def browse(target=field):
                    selected = filedialog.askopenfilename(parent=dialog.window,
                                                          filetypes=[("Windows executables", "*.exe")])
                    if selected:
                        target.delete(0, "end")
                        target.insert(0, selected)

                styled_button(row, "Browse…", browse, padding=dialog.px(8)).pack(side="right", padx=(6, 0))

            entered = dialog.show(
                fields["real_claude_app_path"][1],
                lambda: {key: executable_override(name, field.get()) for key, (name, field) in fields.items()},
            )
        finally:
            self.dialog = None
        if entered is not None:
            self.save_settings(entered)

    def open_startup(self):
        if self.closing:
            return
        if getattr(sys, "frozen", False):
            self.work.put(("get_startup", None))
        else:
            self.show_error("Sign-in startup is available in the Windows release.")

    def show_startup(self, enabled):
        import tkinter as tk
        from src.windows.windows_menu import BACKGROUND, FOREGROUND, Dialog

        if self.closing or self.dialog is not None:
            return
        self.menu.hide()
        self.dialog = dialog = Dialog(self.root, "ClaudeGuard Sign-in")
        try:
            dialog.label("ClaudeGuard starts automatically after you sign in.")
            selected = tk.BooleanVar(dialog.window, enabled)
            control = tk.Checkbutton(dialog.body, text="Start ClaudeGuard when I sign in", variable=selected,
                                     bg=BACKGROUND, fg=FOREGROUND, activebackground=BACKGROUND,
                                     activeforeground=FOREGROUND, selectcolor=BACKGROUND,
                                     font=("Segoe UI", 11), highlightthickness=0)
            control.pack(anchor="w")
            result = dialog.show(control, selected.get)
        finally:
            self.dialog = None
        if result is not None and result != enabled:
            self.work.put(("set_startup", result))

    def show_error(self, message, *, title="ClaudeGuard"):
        from tkinter import messagebox

        parent = self.dialog.window if self.dialog is not None else self.root
        messagebox.showerror(title, message, parent=parent)

    def confirm_quit(self):
        from tkinter import messagebox

        if self.closing:
            return
        enabled = self.status.get("protection_enabled", True)
        if self.pending_patch is not None:
            enabled = enabled or self.pending_patch.get("protection_enabled") is True
        message = ("Quit ClaudeGuard? It will leave blocking rules in place until you restart it or turn off protection."
                   if enabled else "Quit ClaudeGuard?")
        if messagebox.askyesno("ClaudeGuard", message, parent=self.root):
            self.request_quit()

    def request_quit(self):
        if self.closing:
            return
        self.closing = True
        self.process_stop.set()
        self.icon.stop()
        self.menu.hide()
        try:
            self.guard.invalidate_process_verdict()
        except Exception as error:
            log_failure("Suspending Claude process monitoring", error)
        finally:
            self.work.put(("quit", None))

    def finish_quit(self, error):
        self.finished = True
        try:
            if error:
                self.show_error(error)
        finally:
            self.root.destroy()
        if not error:
            LOGGER.info("ClaudeGuard shutdown complete")


def smoke_test():
    import tkinter as tk
    from PIL import ImageTk
    from src.windows.windows_backend import WindowsGuard
    from src.windows.windows_menu import TrayMenu

    if not callable(WindowsGuard):
        raise RuntimeError("The Windows protection backend is unavailable.")
    if not platform.current_sid().startswith("S-1-") or not platform.system_directory().is_dir():
        raise RuntimeError("Windows runtime APIs did not return the expected values.")
    if getattr(sys, "frozen", False):
        if not Path(sys._MEIPASS, "assets", "AppIcon.png").is_file():
            raise RuntimeError("The bundled ClaudeGuard icon is missing.")
    root = tk.Tk()
    root.withdraw()
    try:
        tray_icon = render_icon("allowed")
        image = ImageTk.PhotoImage(tray_icon, master=root)
        root.iconphoto(True, image)
        notification_icon("ClaudeGuardSmokeTest", tray_icon, "ClaudeGuard", lambda anchor: None)
        menu = TrayMenu(root, {})
        for mode in ("vpn", "proxy"):
            data = {
                "connection_mode": mode, "allowed_ips": ["192.0.2.20"],
                "proxy_profile": {"server": "proxy.example", "server_port": 1080},
            }
            menu.update({"state": "allowed"}, data, "192.0.2.20")
            menu.show((root.winfo_screenwidth() // 2, root.winfo_screenheight() // 2))
            root.update_idletasks()
            menu.hide()
    finally:
        root.destroy()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="ClaudeGuard")
    parser.add_argument("--smoke-test", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--startup", action="store_true", help=argparse.SUPPRESS)
    maintenance = parser.add_mutually_exclusive_group()
    maintenance.add_argument("--enable-startup", action="store_true", help=argparse.SUPPRESS)
    maintenance.add_argument("--disable-protection", action="store_true")
    parser.add_argument("--activate-desktop", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
    args = list(sys.argv[1:] if argv is None else argv)
    options = parser.parse_args(args)
    if sys.platform != "win32":
        parser.error("The ClaudeGuard tray requires Windows.")
    if options.smoke_test:
        try:
            smoke_test()
        except Exception as exc:
            if sys.stderr is not None:
                print(str(exc), file=sys.stderr)
            return 1
        return 0
    if options.activate_desktop:
        app_id, *arguments = options.activate_desktop
        if not re.fullmatch(r"Claude_[A-Za-z0-9]+![A-Za-z0-9._-]+", app_id, re.IGNORECASE):
            return 1
        return platform.activate_desktop(app_id, arguments)

    try:
        if not platform.is_admin():
            if platform.elevate(args):
                return 0
            platform.notify("Administrator approval is required to update Windows Firewall.", error=True)
            return 1
        if not platform.is_interactive_account():
            platform.notify("Start ClaudeGuard from an administrator account signed in to this Windows desktop.",
                            error=True)
            return 1
        if options.enable_startup:
            platform.set_startup(True)
            return 0
        handle = platform.instance_handle()
        if handle is None:
            if options.disable_protection:
                platform.notify("Quit ClaudeGuard from the notification area before clearing its rules.")
            return int(options.disable_protection)
        try:
            from src.windows.windows_backend import WindowsGuard

            configure_diagnostics()
            LOGGER.info("Starting ClaudeGuard Windows")
            guard = WindowsGuard(config_path=CONFIG_PATH)
            if options.disable_protection:
                guard.prepare()
                config = ConfigManager(CONFIG_PATH)
                guard.disable()
                config.protection_enabled = False
                platform.set_startup(False)
                return 0

            import tkinter as tk

            activation = platform.activation_event()
            try:
                root = tk.Tk()
                root.report_callback_exception = lambda kind, error, trace: log_failure("Tk callback", error)
                tray = Tray(root, guard, activation)
                try:
                    LOGGER.info("ClaudeGuard tray event loop started")
                    root.mainloop()
                finally:
                    tray.request_quit()
                    tray.worker.join(timeout=2)
                    tray.tray_thread.join(timeout=2)
                    if tray.worker.is_alive():
                        LOGGER.warning("The Windows protection worker was still closing after the UI exited")
                    if tray.tray_thread.is_alive():
                        LOGGER.warning("The notification-area icon was still closing after the UI exited")
            finally:
                platform.close_handle(activation)
        finally:
            platform.close_handle(handle)
    except Exception as exc:
        log_failure("ClaudeGuard startup", exc)
        platform.notify(str(exc) or "ClaudeGuard could not start.", error=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
