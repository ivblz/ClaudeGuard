import sys
import unittest
from unittest.mock import MagicMock, patch

from src.windows import windows_app, windows_tray_icon

try:
    from PIL import Image
except ImportError:
    Image = None


class TrayThemeTests(unittest.TestCase):
    def test_reads_the_system_theme_and_defaults_to_dark_taskbars(self):
        registry = MagicMock()
        with patch.dict(sys.modules, {"winreg": registry}):
            registry.QueryValueEx.return_value = (1, 4)
            self.assertTrue(windows_tray_icon.tray_theme())
            self.assertEqual(registry.QueryValueEx.call_args.args[1], "SystemUsesLightTheme")
            registry.QueryValueEx.return_value = (0, 4)
            self.assertFalse(windows_tray_icon.tray_theme())
            registry.OpenKey.side_effect = FileNotFoundError
            self.assertFalse(windows_tray_icon.tray_theme())


@unittest.skipIf(Image is None, "Pillow is required for tray glyphs")
class TrayIconTests(unittest.TestCase):
    def test_theme_changes_only_the_foreground_color(self):
        dark = windows_app.render_icon("allowed", light=False)
        light = windows_app.render_icon("allowed", light=True)
        self.assertEqual(dark.size, (64, 64))
        self.assertEqual(dark.getchannel("A").tobytes(), light.getchannel("A").tobytes())
        for icon, foreground in ((dark, (255, 255, 255)), (light, (27, 27, 27))):
            self.assertEqual(icon.mode, "RGBA")
            self.assertEqual(icon.getpixel((0, 0))[3], 0)
            self.assertEqual({pixel[:3] for _, pixel in icon.getcolors()}, {foreground})
            self.assertTrue(any(0 < alpha < 255 for alpha in icon.getchannel("A").tobytes()))

    def test_status_glyphs_at_notification_area_size(self):
        status = {}
        for state in ("allowed", "blocked", "disabled", "offline", "checking", "error"):
            icon = windows_app.render_icon(state, light=False)
            status[state] = icon.getchannel("A").resize((16, 16), Image.Resampling.LANCZOS)

        self.assertEqual(len({icon.tobytes() for icon in status.values()}), 4)
        self.assertEqual(status["checking"].tobytes(), status["offline"].tobytes())
        self.assertEqual(status["error"].tobytes(), status["blocked"].tobytes())
        self.assertLess(status["allowed"].getpixel((7, 9)), 32)  # lock body
        self.assertGreater(status["allowed"].getpixel((7, 6)), 150)  # lock shackle aperture
        self.assertLess(status["blocked"].getpixel((7, 7)), 96)  # X intersection
        self.assertLess(status["disabled"].getpixel((6, 7)), 32)  # outline interior
        self.assertGreater(status["offline"].getpixel((7, 7)), 150)  # diagonal bar
