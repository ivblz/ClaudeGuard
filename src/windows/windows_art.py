"""Render Windows menu symbols with transparent, antialiased edges."""
from functools import lru_cache
from math import cos, pi, sin

from PIL import Image, ImageChops, ImageDraw, ImageFont


CIRCLES = {"⚪": ("#ffffff", "#cccccc"), "🟡": ("#ffec52", "#eaa600"),
           "🟢": ("#73e839", "#10a80d"), "🔴": ("#ff6b67", "#d51923")}


@lru_cache(maxsize=4)
def emoji_font(size):
    try:
        return ImageFont.truetype("seguiemj.ttf", size)
    except OSError:
        return None


def windows_emoji(symbol, size):
    font = emoji_font(size)
    if font is None:
        return None
    try:
        measure = ImageDraw.Draw(Image.new("RGBA", (1, 1)))
        left, top, right, bottom = measure.textbbox((0, 0), symbol, font=font, embedded_color=True)
        picture = Image.new("RGBA", (right - left, bottom - top))
        ImageDraw.Draw(picture).text((-left, -top), symbol, font=font, embedded_color=True)
    except (OSError, ValueError):
        # Some Windows versions ship an emoji font that FreeType cannot color.
        return None
    bounds = picture.getbbox()
    if bounds is None:
        return None
    red, green, blue, _ = picture.split()
    if symbol != "⚪" and not (ImageChops.difference(red, blue).getbbox()
                              or ImageChops.difference(red, green).getbbox()):
        return None
    return picture.crop(bounds)


def globe(draw, color, fill=None):
    draw.ellipse((4, 4, 59, 59), fill=fill, outline=color, width=4)
    draw.ellipse((18, 4, 45, 59), outline=color, width=3)
    draw.arc((6, 8, 57, 32), 12, 168, fill=color, width=3)
    draw.arc((6, 31, 57, 55), 192, 348, fill=color, width=3)


def fallback_emoji(symbol):
    picture = Image.new("RGBA", (64, 64))
    draw = ImageDraw.Draw(picture)
    if symbol in CIRCLES:
        highlight, base = CIRCLES[symbol]
        draw.ellipse((2, 2, 61, 61), fill=base)
        draw.ellipse((8, 5, 55, 47), fill=highlight)
    elif symbol == "🔄":
        draw.rounded_rectangle((1, 1, 62, 62), radius=13, fill="#267eb3", outline="#61c5ed", width=3)
        draw.arc((14, 14, 50, 50), 187, 318, fill="white", width=5)
        draw.arc((14, 14, 50, 50), 7, 138, fill="white", width=5)
        draw.polygon(((51, 16), (51, 32), (36, 29)), fill="white")
        draw.polygon(((12, 47), (12, 31), (27, 34)), fill="white")
    elif symbol == "➕":
        draw.rounded_rectangle((3, 23, 60, 40), radius=5, fill="#77b6e7")
        draw.rounded_rectangle((23, 3, 40, 60), radius=5, fill="#77b6e7")
    elif symbol == "⚙️":
        teeth = []
        for tooth in range(8):
            for offset, radius in ((-0.28, 22), (-0.17, 30), (0.17, 30), (0.28, 22)):
                angle = tooth * pi / 4 + offset
                teeth.append((32 + cos(angle) * radius, 32 + sin(angle) * radius))
        draw.polygon(teeth, fill="#8ca9bf", outline="#c5d5e3", width=2)
        draw.ellipse((19, 19, 45, 45), fill="#52708a", outline="#e3ebf1", width=3)
        draw.ellipse((26, 26, 38, 38), fill=(0, 0, 0, 0))
    elif symbol == "🌐":
        globe(draw, "#beefff", fill="#0087cb")
    return picture


@lru_cache(maxsize=48)
def emoji_image(symbol, size):
    picture = windows_emoji(symbol, max(64, size * 4))
    if picture is None:
        picture = fallback_emoji(symbol)
    picture.thumbnail((size, size), Image.Resampling.LANCZOS)
    result = Image.new("RGBA", (size, size))
    result.paste(picture, ((size - picture.width) // 2, (size - picture.height) // 2))
    return result


@lru_cache(maxsize=24)
def mode_image(mode, size, color):
    picture = Image.new("RGBA", (64, 64))
    draw = ImageDraw.Draw(picture)
    if mode == "vpn":
        draw.polygon(((32, 3), (50, 10), (55, 15), (55, 33), (51, 44), (44, 53),
                      (32, 61), (20, 53), (13, 44), (9, 33), (9, 15), (14, 10)), fill=color)
        draw.arc((23, 14, 41, 34), 180, 360, fill=(0, 0, 0, 0), width=4)
        draw.rounded_rectangle((20, 25, 44, 43), radius=3, fill=(0, 0, 0, 0))
    else:
        globe(draw, color)
    return picture.resize((size, size), Image.Resampling.LANCZOS)
