"""Functional and layout checks for the reference-inspired desktop UI."""
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QScrollArea

from kekkai import configuration, engine
from kekkai.core.storage import Preferences
from kekkai.gui.window import MainWindow
from kekkai.gui.widgets import IconTile
from kekkai.themes import tokens


class ReferenceUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kekkai-reference-ui-")
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.window = MainWindow(Preferences(self.root / "preferences.json"), self.root, language="en")
        self.window.show()
        QTest.qWait(40)
        self.addCleanup(self.close_window)

    def close_window(self):
        self.window.close()
        self.window.deleteLater()
        self.app.processEvents()

    def test_empty_overview_has_icons_and_no_invented_scan_results(self):
        home = self.window.pages["home"]
        self.assertEqual(len(home.findChildren(IconTile)), 5)
        for name in ("Findings", "Bloqueantes", "Tempo total"):
            self.assertEqual(home.metrics[name].text(), "—")
        self.assertFalse(home.severity_chart.summary)
        self.assertFalse(home.quick_button.icon().isNull())
        self.assertFalse(home.full_button.icon().isNull())
        self.assertIn("Run a scan", home.performance_chart.accessibleDescription())

    def test_overview_fits_supported_window_widths_in_both_themes(self):
        home = self.window.pages["home"]
        scroll = home.findChild(QScrollArea)
        for theme in ("dark", "light"):
            self.window.apply_theme(theme)
            for width, height in ((1420, 980), (1100, 800), (960, 650)):
                with self.subTest(theme=theme, width=width):
                    self.window.resize(width, height)
                    QTest.qWait(30)
                    self.assertEqual(scroll.horizontalScrollBar().maximum(), 0)
                    self.assertEqual(home.status_badges.theme, theme)
                    self.assertTrue(all(tile.theme == theme for tile in home.findChildren(IconTile)))

    def test_badges_preserve_completed_status_and_error_diagnostic(self):
        results = [engine.make_result(name, "skipped", None, []) for name in engine.SCANNER_ORDER]
        results[0] = engine.make_result("semgrep", "error", 2, [], error="Parser unavailable")
        summary = engine.build_summary(deepcopy(configuration.DEFAULTS), self.root, "UI test fixture", results)
        self.window.summary = summary
        self.window.refresh()
        home = self.window.pages["home"]
        self.assertEqual(home.scanner_table.item(0, 1).text(), "COMPLETED")
        self.assertIn("Parser unavailable", home.scanner_table.item(0, 4).text())
        self.assertEqual(summary["scanners"]["semgrep"]["status"], "error")
        self.assertFalse(home.scanner_table.item(0, 0).icon().isNull())
        self.assertIn("semgrep:", home.performance_chart.accessibleDescription())
        self.assertEqual([name for name, _ in home.severity_chart.severity_data()],
                         ["Critical", "High", "Medium", "Low", "Warn", "Info"])

    def test_reference_scan_buttons_still_only_prepare_configuration(self):
        home = self.window.pages["home"]
        with patch("kekkai.scanners.docker_preflight") as preflight:
            for button, profile in ((home.quick_button, "quick"), (home.full_button, "full")):
                self.window.navigate("home")
                QTest.mouseClick(button, Qt.MouseButton.LeftButton)
                self.assertEqual(self.window.selected_page, "scan")
                self.assertEqual(self.window.scan_page.profile.currentText(), profile)
                self.assertFalse(self.window.running())
                self.assertIsNone(self.window.worker)
            preflight.assert_not_called()

    def test_retro_surfaces_have_hard_shadows_and_native_controls(self):
        from PySide6.QtGui import QIcon
        from PySide6.QtWidgets import QGraphicsDropShadowEffect
        from kekkai.gui.widgets import SkinCanvas
        self.window.apply_theme("light")
        self.assertIsInstance(self.window.centralWidget(), SkinCanvas)
        self.assertEqual(tokens("light")["font-body"], "Consolas")
        self.assertIn("#F5EFE1", self.window.styleSheet())
        self.assertNotIn("qlineargradient", self.window.styleSheet())
        shadows = self.window.findChildren(QGraphicsDropShadowEffect)
        self.assertTrue(shadows)
        self.assertTrue(all(shadow.blurRadius() == 0 for shadow in shadows))
        self.assertFalse(self.window.running())
        self.window.apply_theme("dark")
        checked = self.window.navigation["home"].icon().pixmap(48, 48, QIcon.Mode.Normal, QIcon.State.On).toImage()
        self.assertEqual(checked.pixelColor(6, 30).name(), tokens("dark")["on-primary"].lower())


if __name__ == "__main__":
    unittest.main()
