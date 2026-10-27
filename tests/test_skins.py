"""Built-in skin selection, persistence, branding and unchanged scan contracts."""
import base64
import json
from pathlib import Path
import tempfile
import unittest

from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QGraphicsDropShadowEffect, QScrollArea

from kekkai.core.storage import Preferences
from kekkai.dashboard import render
from kekkai.gui.window import MainWindow
from kekkai.gui.widgets import logo, wordmark
from kekkai.skins import SKINS, get_skin, set_skin, tokens, stylesheet


class SkinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kekkai-skins-")
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(lambda: set_skin("retro"))
        self.preferences = Preferences(self.root / "preferences.json")
        self.window = MainWindow(self.preferences, self.root)
        self.window.show()
        QTest.qWait(40)
        self.addCleanup(self.close_window)

    def close_window(self):
        self.window.close()
        self.window.deleteLater()
        self.app.processEvents()

    def test_selector_applies_and_persists_skin_without_restarting_or_resetting_project(self):
        selector = self.window.settings_page.skin
        self.assertEqual(selector.count(), len(SKINS))
        self.assertEqual(selector.itemText(selector.findData("hardware")), "Hardware")
        self.assertEqual(selector.itemText(selector.findData("monochrome-crt")), "Monochrome CRT")
        self.window.settings_page.project_name.setText("Unsaved project name")
        for identifier in SKINS:
            selector.setCurrentIndex(selector.findData(identifier))
            self.assertEqual(self.window.skin, identifier)
            self.assertEqual(Preferences(self.preferences.path).data["skin"], identifier)
            self.assertEqual(self.window.target, self.root)
            self.assertEqual(self.window.settings_page.project_name.text(), "Unsaved project name")
            self.assertFalse(self.window.running())

    def test_saved_skin_is_restored_when_opening_a_new_window(self):
        self.window.change_skin("violet")
        other = MainWindow(Preferences(self.preferences.path), self.root)
        try:
            self.assertEqual(other.skin, "violet")
            self.assertIn("#7B2EFF", other.styleSheet())
            self.assertEqual(other.settings_page.skin.currentData(), "violet")
        finally:
            other.close()
            other.deleteLater()
            self.app.processEvents()

    def test_all_skins_have_distinct_effects_and_fit_supported_widths(self):
        for identifier in SKINS:
            self.window.change_skin(identifier)
            for theme in ("light", "dark"):
                self.window.apply_theme(theme)
                effects = self.window.findChildren(QGraphicsDropShadowEffect)
                self.assertTrue(all(effect.isEnabled() == get_skin(identifier).paper for effect in effects))
                for width, height in ((1420, 980), (960, 650)):
                    self.window.resize(width, height)
                    QTest.qWait(30)
                    scroll = self.window.pages["home"].findChild(QScrollArea)
                    self.assertEqual(scroll.horizontalScrollBar().maximum(), 0, (identifier, theme, width))
                    if width < 1100:
                        self.assertLessEqual(self.window.brand_logo.geometry().right(), self.window.sidebar.contentsRect().right())

    def test_retro_logo_and_violet_logo_switch_together_with_branding(self):
        self.window.change_skin("retro")
        self.assertEqual(get_skin().wordmark.name, "Logo Kekkai retro.png")
        retro = wordmark().toImage()
        self.window.change_skin("violet")
        self.assertEqual(get_skin().wordmark.name, "logo+nome.png")
        self.assertNotEqual(retro, wordmark().toImage())
        self.assertFalse(self.window.windowIcon().isNull())

    def test_hardware_artwork_is_available_for_both_full_and_compact_branding(self):
        self.window.change_skin("hardware")
        self.assertEqual(get_skin().name, "Hardware")
        self.assertEqual(get_skin().wordmark.name, "logo-hardware.png")
        self.assertTrue(get_skin().wordmark.is_file())
        self.assertFalse(wordmark().isNull())
        compact = logo()
        self.assertFalse(compact.isNull())
        self.assertGreater(compact.width(), compact.height())
        self.assertEqual(self.window.settings_page.skin.currentData(), "hardware")

    def test_hardware_chart_screens_and_text_have_readable_contrast_in_both_modes(self):
        def luminance(value):
            channels = [int(value[index:index+2], 16) / 255 for index in (1, 3, 5)]
            channels = [value / 12.92 if value <= .04045 else ((value + .055) / 1.055) ** 2.4 for value in channels]
            return sum(value * weight for value, weight in zip(channels, (.2126, .7152, .0722)))
        self.window.change_skin("hardware")
        for theme in ("light", "dark"):
            self.window.apply_theme(theme)
            palette = tokens(theme)
            for foreground, background in (("text-primary", "surface"), ("muted", "surface"),
                                          ("text-primary", "surface-end"), ("text-secondary", "surface-end"),
                                          ("muted", "surface-end"),
                                          ("on-primary", "primary"), ("screen-text", "screen-bg"),
                                          ("screen-muted", "screen-bg")):
                high, low = sorted((luminance(palette[foreground]), luminance(palette[background])), reverse=True)
                self.assertGreaterEqual((high + .05) / (low + .05), 4.5, (theme, foreground))
            image = self.window.pages["home"].severity_chart.grab().toImage()
            self.assertEqual(image.pixelColor(17, 17).name(), palette["screen-bg"].lower())

    def test_monochrome_branding_and_flat_chrome_are_available_in_both_modes(self):
        self.window.change_skin("monochrome-crt")
        self.assertEqual(get_skin().name, "Monochrome CRT")
        self.assertEqual(get_skin().wordmark.name, "logo-monochrome-crt.png")
        self.assertFalse(wordmark().isNull())
        self.assertFalse(logo().isNull())
        for theme in ("light", "dark"):
            self.window.apply_theme(theme)
            qss = stylesheet(theme)
            self.assertNotIn("qlineargradient", qss)
            self.assertNotIn("@", qss)
            chart = self.window.pages["home"].severity_chart
            self.assertEqual(chart.grab().toImage().pixelColor(17, 17).name(),
                             tokens(theme)["surface-raised"].lower())

    def test_monochrome_text_and_statuses_have_contrast_in_both_modes(self):
        def luminance(value):
            channels = [int(value[index:index+2], 16) / 255 for index in (1, 3, 5)]
            channels = [v / 12.92 if v <= .04045 else ((v + .055) / 1.055) ** 2.4 for v in channels]
            return sum(v * weight for v, weight in zip(channels, (.2126, .7152, .0722)))
        for theme in ("light", "dark"):
            palette = tokens(theme, "monochrome-crt")
            pairs = [(ink, paper) for ink in ("text-primary", "text-secondary", "muted", "warning")
                     for paper in ("surface", "surface-raised", "sidebar")]
            pairs.append(("on-primary", "primary"))
            pairs.extend((("success", "badge-success"), ("muted", "badge-muted")))
            for ink, paper in pairs:
                high, low = sorted((luminance(palette[ink]), luminance(palette[paper])), reverse=True)
                self.assertGreaterEqual((high + .05) / (low + .05), 4.5, (theme, ink, paper))

    def test_report_skin_is_explicit_offline_and_does_not_change_active_skin(self):
        set_skin("retro")
        for identifier in SKINS:
            html = render({"project":"UI fixture"}, skin=identifier)
            self.assertIn(f'data-skin="{identifier}"', html)
            encoded = base64.b64encode(get_skin(identifier).wordmark.read_bytes()).decode("ascii")
            self.assertIn(encoded, html)
            self.assertIn("Content-Security-Policy", html)
            self.assertEqual(get_skin().identifier, "retro")

    def test_unknown_skins_and_non_string_preferences_are_rejected(self):
        for value in ("../retro", "missing", [], None):
            if value is not None:
                with self.assertRaises(ValueError):
                    get_skin(value)
            self.preferences.data["skin"] = value
            with self.assertRaises(ValueError):
                self.preferences.save()
        self.preferences.data["skin"] = "retro"

    def test_old_preferences_migrate_to_retro_without_losing_other_settings(self):
        self.preferences.path.write_text(json.dumps({"theme":"light","language":"en"}),encoding="utf-8")
        migrated = Preferences(self.preferences.path)
        self.assertEqual(migrated.data["skin"], "retro")
        self.assertEqual(migrated.data["theme"], "light")
        self.assertEqual(migrated.data["language"], "en")

    def test_palette_copies_and_light_dark_modes_remain_independent(self):
        for identifier in SKINS:
            dark = tokens("dark", identifier)
            light = tokens("light", identifier)
            self.assertNotEqual(dark["background"], light["background"])
            dark["background"] = "changed"
            self.assertNotEqual(tokens("dark", identifier)["background"], "changed")

    def test_scan_diagnostics_remain_readable_after_changing_skins(self):
        page = self.window.scan_page
        page.receive({"kind":"scanner_finished", "scanner":"semgrep", "status":"error",
                      "findings":0, "duration_seconds":1.5, "error":"Parser fixture error"})
        for identifier, theme in (("violet", "dark"), ("retro", "light"), ("hardware", "light"),
                                  ("monochrome-crt", "light"), ("monochrome-crt", "dark")):
            self.window.change_skin(identifier)
            self.window.apply_theme(theme)
            self.assertEqual(page.scanner_table.item(0, 1).text(), "COMPLETED")
            self.assertEqual(page.scanner_table.item(0, 1).foreground().color().name(), tokens(theme)["text-primary"].lower())
            self.assertEqual(page.scanner_table.item(0, 4).foreground().color().name(), tokens(theme)["warning"].lower())
            self.assertIn("Parser fixture error", page.scanner_table.item(0, 4).text())

    def test_skin_change_preserves_loaded_dashboard_filter_values(self):
        self.window.show_dashboard()
        dashboard = self.window.pages["dashboard"]
        loaded = []
        dashboard.view.loadFinished.connect(loaded.append)
        loop = QEventLoop()
        timer = QTimer()
        timer.setSingleShot(True)
        timer.timeout.connect(loop.quit)
        dashboard.view.loadFinished.connect(loop.quit)
        timer.start(15000)
        loop.exec()
        timer.stop()
        self.assertTrue(loaded and loaded[-1])
        values = []
        dashboard.page.runJavaScript("document.querySelector('.search').value = 'KEEP_FILTER'", values.append)
        self.wait_for(values)
        for identifier in ("violet", "monochrome-crt"):
            self.window.change_skin(identifier)
            values.clear()
            dashboard.page.runJavaScript("JSON.stringify({skin:document.documentElement.dataset.skin,filter:document.querySelector('.search').value})", values.append)
            self.wait_for(values)
            self.assertEqual(json.loads(values[0]), {"skin":identifier,"filter":"KEEP_FILTER"})

    def wait_for(self, values):
        for _ in range(100):
            if values:
                return
            QTest.qWait(20)
        self.fail("JavaScript callback timed out")


if __name__ == "__main__":
    unittest.main()
