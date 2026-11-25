"""The compact Windows notification-area menu and its dialogs."""
import ctypes
import sys
import tkinter as tk
from ctypes import wintypes
from tkinter import font

from PIL import Image, ImageDraw, ImageTk

from src.windows.windows_art import emoji_image, mode_image


from src.windows.windows_tray_icon import tray_theme

def set_theme(light):
    global LIGHT, BACKGROUND, BORDER, DIVIDER, FOREGROUND, MUTED, HOVER, FOCUS, DIALOG_HEADER
    LIGHT = light
    BACKGROUND = ("#f7f7f7" if LIGHT else "#222222")
    BORDER = ("#bababa" if LIGHT else "#505050")
    DIVIDER = ("#d7d7d7" if LIGHT else "#494949")
    FOREGROUND = ("#191919" if LIGHT else "#f2f2f2")
    MUTED = ("#555555" if LIGHT else "#a5a5a5")
    HOVER = ("#e2e2e2" if LIGHT else "#3b3b3b")
    FOCUS = ("#0067aa" if LIGHT else "#3090d5")
    DIALOG_HEADER = ("#eeeeee" if LIGHT else "#2b2b2b")


set_theme(tray_theme("AppsUseLightTheme"))

STATE_LABELS = {
    "checking": ("Checking connection…", "⚪"),
    "offline": ("Offline (no connection)", "⚪"),
    "allowed": ("Protected", "🟢"),
    "blocked": ("Claude blocked", "🔴"),
    "error": ("Protection error", "🔴"),
    "disabled": ("Protection Disabled", "🟡"),
}

ROW_EMOJI = {"refresh": "🔄", "add_ip": "➕", "manage_ips": "⚙️", "proxy": "⚙️"}


def status_label(status, mode, data):
    state = status.get("state", "checking")
    label, symbol = STATE_LABELS.get(state, STATE_LABELS["error"])
    if state == "allowed":
        label = f"{label} ({'Proxy' if mode == 'proxy' else 'VPN'} OK)"
    elif state == "blocked" and mode == "proxy":
        label = "Proxy unavailable" if data.get("proxy_profile") else "Proxy not configured"
    return label, symbol


def proxy_endpoint(profile):
    server = profile.get("server") if isinstance(profile, dict) else None
    if not isinstance(server, str) or not server or not profile.get("server_port"):
        return "Not configured"
    if ":" in server and not server.startswith("["):
        server = f"[{server}]"
    return f"{server}:{profile['server_port']}"


def menu_rows(data, current_ip):
    groups = [
        [("refresh", "Re-check Now")],
        [("protection", "✓  Protection Active" if data.get("protection_enabled") is not False
          else "Protection Disabled")],
        [("model", f"✓  Default Model: {data.get('default_model', '')}"
          if data.get("model_override_enabled") else "Default Model Override (off)")],
    ]
    if data.get("model_override_enabled"):
        groups[-1].append(("change_model", "    Change Model…"))
    if data.get("connection_mode") == "proxy":
        groups.append([("proxy", "Configure Proxy…")])
    else:
        vpn_rows = []
        allowed = data.get("allowed_ips")
        if current_ip and (not isinstance(allowed, list) or current_ip not in allowed):
            vpn_rows.append(("add_ip", f"Whitelist Current IP ({current_ip})"))
        vpn_rows.append(("manage_ips", "Manage Whitelisted IPs…"))
        groups.append(vpn_rows)
    groups.append([("quit", "Quit ClaudeGuard")])
    return groups


def pointer_position():
    if sys.platform != "win32":
        return None
    point = wintypes.POINT()
    if ctypes.windll.user32.GetCursorPos(ctypes.byref(point)):
        return point.x, point.y
    return None


def monitor_work_area(window, x, y):
    if sys.platform == "win32":
        class MonitorInfo(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.DWORD), ("rcMonitor", wintypes.RECT),
                        ("rcWork", wintypes.RECT), ("dwFlags", wintypes.DWORD)]

        user32 = ctypes.windll.user32
        user32.MonitorFromPoint.argtypes = [wintypes.POINT, wintypes.DWORD]
        user32.MonitorFromPoint.restype = wintypes.HANDLE
        user32.GetMonitorInfoW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MonitorInfo)]
        monitor = user32.MonitorFromPoint(wintypes.POINT(x, y), 2)
        info = MonitorInfo(ctypes.sizeof(MonitorInfo))
        if monitor and user32.GetMonitorInfoW(monitor, ctypes.byref(info)):
            work = info.rcWork
            return work.left, work.top, work.right, work.bottom
    return 0, 0, window.winfo_screenwidth(), window.winfo_screenheight()


class RoundedPopup(tk.Toplevel):
    def __init__(self, parent, radius, stroke, background=None, **kwargs):
        background = background or BACKGROUND
        super().__init__(parent, bg=background, **kwargs)
        self.withdraw()
        self.overrideredirect(True)
        self.radius = radius
        self.stroke = stroke
        self.background = background
        self.title_label = None
        self.picture_key = None
        self.picture = None

        # Insets keep rectangular child windows clear of the curved outline.
        self.inset_y = max(stroke + 1, radius // 2)
        inset_x = max(stroke + 1, radius // 3)
        self.rim = tk.Label(self, bg=background, borderwidth=0, highlightthickness=0)
        self.rim.place(x=0, y=0, relwidth=1, relheight=1)
        self.body = tk.Frame(self, bg=background)
        self.body.pack(fill="both", expand=True, padx=inset_x, pady=self.inset_y)

    def draw_border(self, width, height):
        header = self.title_label.winfo_reqheight() + self.inset_y if self.title_label else 0
        key = width, height, header
        if key == self.picture_key:
            return
        resolution = 4
        image_width, image_height = width * resolution, height * resolution
        radius = self.radius * resolution
        stroke = self.stroke * resolution
        edge = resolution // 2
        picture = Image.new("RGB", (image_width, image_height), self.background)
        ImageDraw.Draw(picture).rounded_rectangle(
            (edge, edge, image_width - edge - 1, image_height - edge - 1), radius=radius - edge,
            fill=self.background, outline="#6a6a6a", width=stroke)
        if header:
            interior = edge + stroke
            mask = Image.new("L", picture.size)
            ImageDraw.Draw(mask).rounded_rectangle(
                (interior, interior, image_width - interior - 1, image_height - interior - 1),
                radius=radius - interior, fill=255)
            section = (0, 0, image_width, header * resolution)
            picture.paste(DIALOG_HEADER, section, mask.crop(section))
        self.picture = ImageTk.PhotoImage(picture.resize((width, height), Image.Resampling.LANCZOS), master=self)
        self.rim.configure(image=self.picture)
        self.picture_key = key


def place_window(window, width, height, x, y):
    window.draw_border(width, height)
    if sys.platform != "win32" or (x >= 0 and y >= 0):
        window.geometry(f"{width}x{height}+{max(0, x)}+{max(0, y)}")
    else:
        window.geometry(f"{width}x{height}")
    window.deiconify()
    window.update_idletasks()
    if sys.platform != "win32":
        return
    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32
    user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
    user32.GetAncestor.restype = wintypes.HWND
    user32.SetWindowRgn.argtypes = [wintypes.HWND, wintypes.HANDLE, wintypes.BOOL]
    gdi32.CreateRoundRectRgn.argtypes = [ctypes.c_int] * 6
    gdi32.CreateRoundRectRgn.restype = wintypes.HANDLE
    gdi32.DeleteObject.argtypes = [wintypes.HANDLE]
    handle = user32.GetAncestor(window.winfo_id(), 2)
    if not handle:
        return
    if x < 0 or y < 0:
        user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                                       ctypes.c_int, ctypes.c_int, wintypes.UINT]
        # Negative Tk geometry offsets are relative to the far edge of the screen.
        user32.SetWindowPos(handle, None, x, y, width, height, 0x0004 | 0x0010)
    diameter = window.radius * 2
    region = gdi32.CreateRoundRectRgn(0, 0, width + 1, height + 1, diameter, diameter)
    if region and not user32.SetWindowRgn(handle, region, True):
        gdi32.DeleteObject(region)


def short_label(value, text_font, width):
    if text_font.measure(value) <= width:
        return value
    while value and text_font.measure(value + "…") > width:
        value = value[:-1]
    return value + "…"


def styled_button(parent, label, command, *, background=None, active=None,
                  anchor="w", foreground=None, size=12, padding=0, weight="normal"):
    foreground = foreground or FOREGROUND
    background = background or BACKGROUND
    active = active or HOVER
    button = tk.Button(parent, text=label, command=command, font=("Segoe UI", size, weight),
                       anchor=anchor, bg=background, fg=foreground, activebackground=active,
                       activeforeground=FOREGROUND, disabledforeground=MUTED,
                       relief="flat", overrelief="flat", borderwidth=0, padx=padding, pady=0,
                       highlightthickness=1, highlightbackground=background, highlightcolor=FOCUS,
                       takefocus=True, cursor="hand2")
    button.bind("<Enter>", lambda event: button.configure(bg=button["activebackground"])
                if button["state"] == "normal" else None)
    button.bind("<Leave>", lambda event: button.configure(bg=background))
    button.bind("<Return>", lambda event: button.invoke())
    return button


class TrayMenu:
    def __init__(self, root, actions):
        self.actions = actions
        self.scale = root.winfo_fpixels("1i") / 96
        self.width = self.px(348)
        self.anchor = (0, 0)
        self.visible = False
        self.more_visible = False
        self.mode = None
        self.mode_enabled = None
        self.rows = None
        self.normal_font = font.Font(root, family="Segoe UI", size=12)
        self.status_font = font.Font(root, family="Segoe UI", size=12, weight="bold")
        self.endpoint_value = ""
        self.status_details = ""
        self.tooltip_timer = None
        self.tooltip = None
        self.emoji_photos = {}
        self.mode_photos = {}

        window = self.window = RoundedPopup(root, self.px(12), self.px(1), takefocus=True)
        window.attributes("-topmost", True)
        window.title("ClaudeGuard")
        window.bind("<Escape>", lambda event: self.escape())
        window.bind("<FocusOut>", lambda event: window.after_idle(self.close_if_unfocused))
        window.protocol("WM_DELETE_WINDOW", self.hide)

        margin = self.px(15)
        content = tk.Frame(window.body, bg=BACKGROUND, width=self.width - 2)
        content.pack(fill="x", padx=margin, pady=(self.px(9), self.px(8)))

        header = tk.Frame(content, bg=BACKGROUND, height=self.px(38))
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="Status:", font=self.status_font, fg=MUTED, bg=BACKGROUND).pack(side="left")
        self.dot = tk.Label(header, bg=BACKGROUND, borderwidth=0, padx=0, pady=0)
        self.dot.pack(side="left", padx=(self.px(4), self.px(7)))
        self.more_button = styled_button(header, "⋯", self.toggle_more, size=14, anchor="center", foreground=MUTED)
        self.more_button.pack(side="right", ipadx=self.px(6))
        self.status = tk.Label(header, font=self.status_font, fg=MUTED, bg=BACKGROUND, anchor="w")
        self.status.pack(side="left", fill="x", expand=True)
        self.bind_tooltip(self.status, lambda: self.status_details)
        self.bind_tooltip(self.more_button, lambda: "Windows options")

        self.pill = tk.Canvas(content, bg=BACKGROUND, highlightthickness=0, height=self.px(39))
        self.pill.pack(fill="x", pady=(self.px(3), self.px(5)))
        self.pill_photo = None
        self.pill_item = self.pill.create_image(0, 0, anchor="nw")
        self.mode_buttons = [styled_button(self.pill, label, lambda target=mode: self.select_mode(target),
                                           anchor="center", size=12, weight="bold")
                             for mode, label in (("vpn", "VPN"), ("proxy", "Proxy"))]
        self.pill.bind("<Configure>", lambda event: self.draw_pill(event.width))
        self.pill.bind("<Button-1>", lambda event: self.select_mode(
            "vpn" if event.x < self.pill.winfo_width() / 2 else "proxy"))

        self.endpoint = tk.Label(content, font=self.normal_font, fg=MUTED, bg=BACKGROUND, anchor="w",
                                 compound="left", padx=self.px(3))
        self.endpoint.pack(fill="x", ipady=self.px(10))
        self.bind_tooltip(self.endpoint, lambda: self.endpoint_value)
        self.commands = tk.Frame(content, bg=BACKGROUND)
        self.commands.pack(fill="x")

        self.more = RoundedPopup(window, self.px(10), self.px(1))
        self.more.attributes("-topmost", True)
        self.more.title("ClaudeGuard Windows options")
        self.more.bind("<Escape>", lambda event: self.close_more())
        self.more.bind("<FocusOut>", lambda event: window.after_idle(self.close_if_unfocused))
        for key, name in (("desktop", "Launch Claude Desktop"), ("cli", "Launch Claude Code"),
                          ("app_paths", "Configure Claude apps…"), ("startup", "Start at sign-in…")):
            self.row_button(self.more.body, key, name)

    def px(self, value):
        return max(1, round(value * self.scale))

    def emoji_photo(self, symbol, size):
        key = symbol, size
        if key not in self.emoji_photos:
            self.emoji_photos[key] = ImageTk.PhotoImage(emoji_image(symbol, size), master=self.window)
        return self.emoji_photos[key]

    def mode_photo(self, mode, color):
        key = mode, color
        if key not in self.mode_photos:
            self.mode_photos[key] = ImageTk.PhotoImage(mode_image(mode, self.px(17), color), master=self.window)
        return self.mode_photos[key]

    def draw_pill(self, width):
        if width < self.px(20) or self.mode is None:
            return
        height = self.px(39)
        resolution = 3
        picture = Image.new("RGB", (width * resolution, height * resolution), BACKGROUND)
        draw = ImageDraw.Draw(picture)
        draw.rounded_rectangle((0, 0, width * resolution - 1, height * resolution - 1),
                               radius=height * resolution // 2, fill=("#e9e9e9" if LIGHT else "#323232"), outline=("#acacac" if LIGHT else "#545454"),
                               width=self.px(1) * resolution)
        gap = self.px(3)
        half = width // 2
        selected = ("#ffffff" if LIGHT else "#575757") if self.mode_enabled else ("#d7d7d7" if LIGHT else "#424242")
        left = 0 if self.mode == "vpn" else half
        draw.rounded_rectangle(((left + gap) * resolution, gap * resolution,
                                (left + half - gap) * resolution, (height - gap) * resolution),
                               radius=(height - 2 * gap) * resolution // 2, fill=selected)
        self.pill_photo = ImageTk.PhotoImage(picture.resize((width, height), Image.Resampling.LANCZOS),
                                             master=self.window)
        self.pill.itemconfigure(self.pill_item, image=self.pill_photo)
        for index, (mode, button) in enumerate(zip(("vpn", "proxy"), self.mode_buttons)):
            chosen = index == int(self.mode == "proxy")
            background = selected if chosen else ("#e9e9e9" if LIGHT else "#323232")
            color = FOREGROUND if chosen and self.mode_enabled else MUTED
            picture = self.mode_photo(mode, color)
            # Keep the icons unstippled. select_mode guards unavailable mode switches.
            button.configure(bg=background, highlightbackground=background, activebackground=background,
                             fg=color, activeforeground=FOREGROUND if self.mode_enabled else color,
                             image=picture, compound="left", padx=self.px(7), takefocus=self.mode_enabled,
                             cursor="hand2" if self.mode_enabled else "arrow")
            hover_picture = self.mode_photo(mode, FOREGROUND)
            button.bind("<Enter>", lambda event, control=button, icon=hover_picture:
                        control.configure(fg=FOREGROUND, image=icon) if self.mode_enabled else None)
            button.bind("<Leave>", lambda event, control=button, fg=color, icon=picture:
                        control.configure(fg=fg, image=icon))
            inset = self.px(17)
            button.place(x=index * half + inset, y=self.px(7), width=half - 2 * inset, height=self.px(25))

    def select_mode(self, mode):
        if self.mode_enabled and self.mode != mode:
            self.actions["mode"](mode)

    def row_button(self, parent, key, title, enabled=True):
        def invoke():
            if not enabled:
                return
            if key not in ("refresh", "protection", "model", "add_ip"):
                self.hide()
            self.actions[key]()

        row = tk.Frame(parent, bg=BACKGROUND, height=self.px(39))
        row.pack(fill="x")
        row.pack_propagate(False)
        symbol = ROW_EMOJI.get(key)
        width = self.width - self.px(47)
        if symbol:
            width -= self.px(25)
        button = styled_button(row, short_label(title, self.normal_font, width), invoke, padding=self.px(3))
        if symbol:
            button.configure(image=self.emoji_photo(symbol, self.px(20)), compound="left")
        if not enabled:
            button.configure(cursor="arrow", takefocus=False)
            if symbol:
                # Windows Tk stipples images in disabled buttons. Keep the image intact and guard invocation.
                button.configure(fg=MUTED, activeforeground=MUTED, activebackground=BACKGROUND)
            else:
                button.configure(state="disabled")
        button.pack(fill="both", expand=True)
        if button["text"] != title:
            self.bind_tooltip(button, lambda: title)

    def update(self, status, data, current_ip, pending=False):
        mode = "proxy" if data.get("connection_mode") == "proxy" else "vpn"
        mode_enabled = data.get("protection_enabled") is not False and not pending
        label, symbol = status_label(status, mode, data)
        self.status_details = status.get("error") or ""
        available = self.width - self.px(146)
        self.status.configure(text=short_label(label, self.status_font, available))
        if not self.status_details and self.status["text"] != label:
            self.status_details = label
        self.dot.configure(image=self.emoji_photo(symbol, self.px(20)))
        self.endpoint_value = (f"Proxy: {proxy_endpoint(data.get('proxy_profile'))}" if mode == "proxy"
                               else f"Current IP: {current_ip or ('…' if status.get('state') == 'checking' else 'Unavailable')}")
        endpoint = short_label(self.endpoint_value, self.normal_font, self.width - self.px(43 if mode == "proxy" else 68))
        picture = "" if mode == "proxy" else self.emoji_photo("🌐", self.px(20))
        self.endpoint.configure(text=endpoint, image=picture)
        if (mode, mode_enabled) != (self.mode, self.mode_enabled):
            self.mode, self.mode_enabled = mode, mode_enabled
            self.draw_pill(self.pill.winfo_width())
        groups = menu_rows(data, current_ip)
        if (groups, pending) != self.rows:
            selected = self.window.focus_get()
            focused_row = selected in (widget.winfo_children()[0] for widget in self.commands.winfo_children()
                                       if widget.winfo_children())
            self.rows = groups, pending
            for child in self.commands.winfo_children():
                child.destroy()
            for group in groups:
                tk.Frame(self.commands, bg=DIVIDER, height=1).pack(fill="x", padx=self.px(3))
                for key, title in group:
                    self.row_button(self.commands, key, title, enabled=not pending or key == "quit")
            if self.visible:
                self.place()
                if focused_row:
                    self.window.focus_set()

    def show(self, anchor=None):
        self.anchor = anchor or self.window.winfo_pointerxy()
        self.visible = True
        self.close_more(restore_focus=False)
        self.place()
        self.window.lift()
        self.window.focus_force()

    def place(self):
        self.window.update_idletasks()
        height = self.window.winfo_reqheight()
        x, y = self.anchor
        left, top, right, bottom = monitor_work_area(self.window, x, y)
        gap = self.px(7)
        x = min(max(x - self.width + gap, left + gap), right - self.width - gap)
        y = y + gap if y + gap + height <= bottom else y - height - gap
        y = min(max(y, top + gap), bottom - height - gap)
        place_window(self.window, self.width, height, x, y)

    def hide(self):
        self.close_more(restore_focus=False)
        self.clear_tooltip()
        self.visible = False
        self.window.withdraw()

    def escape(self):
        if self.more_visible:
            self.close_more()
        else:
            self.hide()
        return "break"

    def close_if_unfocused(self):
        if not self.visible:
            return
        focus = self.window.focus_displayof()
        if focus is None or focus.winfo_toplevel() not in (self.window, self.more):
            self.hide()

    def toggle_more(self):
        self.clear_tooltip()
        if self.more_visible:
            self.close_more()
            return
        self.more.update_idletasks()
        width = self.px(235)
        height = self.more.winfo_reqheight()
        x = self.window.winfo_rootx()
        y = self.more_button.winfo_rooty()
        left, top, right, bottom = monitor_work_area(self.window, x, y)
        gap = self.px(4)
        edge = x + self.width + gap
        x = edge if edge + width < right else max(left + gap, x - width - gap)
        y = min(max(y, top + gap), bottom - height - gap)
        self.more_visible = True
        place_window(self.more, width, height, x, y)
        self.more.lift()
        self.more.focus_force()

    def close_more(self, restore_focus=True):
        if self.more_visible:
            self.more_visible = False
            if restore_focus and self.visible:
                self.more_button.focus_force()
            self.more.withdraw()
        return "break"

    def bind_tooltip(self, widget, value):
        widget.bind("<Enter>", lambda event: self.schedule_tooltip(widget, value), add="+")
        widget.bind("<Leave>", lambda event: self.clear_tooltip(), add="+")

    def schedule_tooltip(self, widget, value):
        self.clear_tooltip()
        if value() and (widget != self.endpoint or widget["text"] != value()):
            self.tooltip_timer = self.window.after(650, self.show_tooltip, widget, value)

    def show_tooltip(self, widget, value):
        self.tooltip_timer = None
        if not self.visible or not value() or not widget.winfo_exists():
            return
        tip = self.tooltip = RoundedPopup(self.window, self.px(6), self.px(1), background=("#fafafa" if LIGHT else "#303030"))
        tip.attributes("-topmost", True)
        tk.Label(tip.body, text=value(), font=("Segoe UI", 10), bg=("#fafafa" if LIGHT else "#303030"), fg=FOREGROUND,
                 padx=self.px(8), pady=self.px(4), justify="left", wraplength=self.px(350)).pack()
        tip.update_idletasks()
        x, y = widget.winfo_rootx(), widget.winfo_rooty() + widget.winfo_height()
        left, top, right, bottom = monitor_work_area(widget, x, y)
        width, height = tip.winfo_reqwidth(), tip.winfo_reqheight()
        place_window(tip, width, height, max(left, min(x, right - width - 4)),
                     max(top, min(y, bottom - height - 4)))

    def clear_tooltip(self):
        if self.tooltip_timer is not None:
            self.window.after_cancel(self.tooltip_timer)
            self.tooltip_timer = None
        if self.tooltip is not None:
            self.tooltip.destroy()
            self.tooltip = None


class Dialog:
    def __init__(self, root, title):
        self.scale = root.winfo_fpixels("1i") / 96
        self.width = self.px(422)
        self.window = RoundedPopup(root, self.px(12), self.px(1))
        self.window.title(title)
        self.window.bind("<Escape>", lambda event: self.close())
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.result = None
        outer = self.window.body
        self.window.title_label = tk.Label(outer, text=title, anchor="w", font=("Segoe UI", 11, "bold"),
                                           bg=DIALOG_HEADER, fg=MUTED, padx=self.px(18), pady=self.px(8))
        self.window.title_label.pack(fill="x")
        tk.Frame(outer, bg=("#cccccc" if LIGHT else "#383838"), height=1).pack(fill="x")
        self.body = tk.Frame(outer, bg=BACKGROUND)
        self.body.pack(fill="both", expand=True, padx=self.px(18), pady=self.px(16))
        self.error = tk.Label(self.body, fg=("#ae241a" if LIGHT else "#ff8782"), bg=BACKGROUND, font=("Segoe UI", 10),
                              justify="left", wraplength=self.width - self.px(39))

    def px(self, value):
        return max(1, round(value * self.scale))

    def label(self, text):
        tk.Label(self.body, text=text, anchor="w", justify="left", font=("Segoe UI", 11),
                 fg=FOREGROUND, bg=BACKGROUND, wraplength=self.width - self.px(39)).pack(fill="x", pady=(0, self.px(9)))

    def field(self, value, multiline=False, parent=None):
        args = dict(bg=("#ffffff" if LIGHT else "#181818"), fg=FOREGROUND, insertbackground=FOREGROUND, relief="flat", borderwidth=5,
                    highlightthickness=2, highlightbackground=BORDER, highlightcolor=FOCUS,
                    selectbackground=("#b4dbff" if LIGHT else "#20587e"), selectforeground=FOREGROUND)
        parent = parent or self.body
        if multiline:
            field = tk.Text(parent, height=6, wrap="word", font=("Consolas", 10), **args)
            field.insert("1.0", value)
        else:
            field = tk.Entry(parent, font=("Segoe UI", 11), **args)
            field.insert(0, value)
        return field

    def show(self, focus, submit, *, multiline=False):
        footer = tk.Frame(self.body, bg=BACKGROUND)
        footer.pack(fill="x", side="bottom", pady=(self.px(15), 0))

        def accept():
            try:
                self.result = submit()
            except ValueError as exc:
                self.error.configure(text=str(exc))
                self.error.pack(fill="x", anchor="w", pady=(self.px(7), 0))
                self.fit()
                return
            self.close()

        if not multiline:
            self.window.bind("<Return>", lambda event: accept())
        else:
            self.window.bind("<Control-Return>", lambda event: accept())
        for label, action, bg, active in (("OK", accept, "#0078d4", "#1588df"),
                                          ("Cancel", self.close, ("#e9e9e9" if LIGHT else "#323232"), ("#dedede" if LIGHT else "#464646"))):
            button = styled_button(footer, label, action, background=bg, active=active, foreground="white" if label == "OK" else FOREGROUND, anchor="center", size=10)
            button.pack(side="right", ipadx=self.px(23), ipady=self.px(4), padx=(self.px(8), 0))

        x, y = self.window.winfo_pointerxy()
        left, top, right, bottom = monitor_work_area(self.window, x, y)
        self.window.update_idletasks()
        height = self.window.winfo_reqheight()
        place_window(self.window, self.width, height, (left + right - self.width) // 2,
                     (top + bottom - height) // 2)
        self.window.lift()
        focus.focus_force()
        self.window.grab_set()
        self.window.wait_window()
        return self.result

    def fit(self):
        self.window.update_idletasks()
        x, y = self.window.winfo_rootx(), self.window.winfo_rooty()
        _, top, _, bottom = monitor_work_area(self.window, x, y)
        height = self.window.winfo_reqheight()
        place_window(self.window, self.width, height, x, max(top, min(y, bottom - height)))

    def close(self):
        self.window.destroy()
        return "break"
