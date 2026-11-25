"""Monochrome equivalents of the macOS status item glyphs."""

_SHIELD = (
    (16, 2), (17.3, 2.3), (19.6, 3.7), (22.5, 4.9), (26.1, 5.9),
    (27.1, 6.5), (27.5, 7.5), (27.5, 14.9), (27.1, 18.7),
    (25.9, 21.8), (23.9, 24.6), (21.3, 27), (17, 29.7),
    (16, 30), (15, 29.7), (10.7, 27), (8.1, 24.6), (6.1, 21.8),
    (4.9, 18.7), (4.5, 14.9), (4.5, 7.5), (4.9, 6.5),
    (5.9, 5.9), (9.5, 4.9), (12.4, 3.7), (14.7, 2.3),
)
_SHIELD_INTERIOR = (
    (16, 4.7), (18.5, 6.1), (21.8, 7.4), (24.9, 8.3), (24.9, 14.9),
    (24.5, 18), (23.5, 20.7), (22, 22.9), (19.7, 25), (16, 27.3),
    (12.3, 25), (10, 22.9), (8.5, 20.7), (7.5, 18), (7.1, 14.9),
    (7.1, 8.3), (10.2, 7.4), (13.5, 6.1),
)


def tray_theme(setting="SystemUsesLightTheme"):
    """Return whether Windows uses a light taskbar."""
    try:
        import winreg

        path = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            return winreg.QueryValueEx(key, setting)[0] == 1
    except (ImportError, OSError):
        return False


def render_tray_icon(state, light=None):
    from PIL import Image, ImageDraw

    if light is None:
        light = tray_theme()

    # Draw the glyph in a 32-unit coordinate space and filter the alpha
    # channel before applying the foreground color.
    scale = 8
    mask = Image.new("L", (32 * scale, 32 * scale))
    draw = ImageDraw.Draw(mask)

    def coordinates(values):
        return tuple(round(value * scale) for value in values)

    def stroke(start, end, width, fill):
        radius = width / 2
        draw.line((*coordinates(start), *coordinates(end)),
                  fill=fill, width=round(width * scale))
        for x, y in (start, end):
            draw.ellipse(coordinates((x - radius, y - radius, x + radius, y + radius)),
                         fill=fill)

    draw.polygon([coordinates(point) for point in _SHIELD], fill=255)
    if state == "allowed":
        draw.rounded_rectangle(coordinates((12.25, 9, 19.75, 17)),
                               radius=4 * scale, fill=0)
        draw.rounded_rectangle(coordinates((14.35, 11.2, 17.65, 17)),
                               radius=2 * scale, fill=255)
        draw.rounded_rectangle(coordinates((10.75, 14.25, 21.25, 21.75)),
                               radius=1.5 * scale, fill=0)
    elif state == "disabled":
        draw.polygon([coordinates(point) for point in _SHIELD_INTERIOR], fill=0)
    elif state in ("offline", "checking"):
        stroke((4.5, 4.5), (27.5, 27.5), 5.75, 0)
        stroke((4.5, 4.5), (27.5, 27.5), 2.6, 255)
    else:
        stroke((12.25, 12.25), (19.75, 19.75), 2.65, 0)
        stroke((19.75, 12.25), (12.25, 19.75), 2.65, 0)

    image = Image.new("RGBA", (64, 64), "#1b1b1b" if light else "#ffffff")
    image.putalpha(mask.resize(image.size, Image.Resampling.LANCZOS))
    return image
