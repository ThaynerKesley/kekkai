"""Qt tests drive the application itself; no external app or AI account is used."""
import json
import os
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

import yaml

from kekkai import configuration
from kekkai.core.storage import Preferences

try:
    from PySide6.QtCore import Qt, QEventLoop, QTimer
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication, QLineEdit, QMessageBox, QFileDialog, QInputDialog
    from kekkai.gui.window import MainWindow, NAVIGATION
    QT_AVAILABLE = True
except ImportError:
    QT_AVAILABLE = False


@unittest.skipUnless(QT_AVAILABLE, "Install requirements.txt for desktop tests")
class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kekkai-qt-test-")
        self.root = Path(self.temp.name)
        self.config = deepcopy(configuration.DEFAULTS)
        self.config["policy"]["gitleaks"]["enabled"] = True
        (self.root / ".kekkai.yml").write_text(yaml.safe_dump(self.config), encoding="utf-8")
        prefs = Preferences(self.root / "preferences.json")
        self.window = MainWindow(prefs, self.root)
        self.window.scan_page.open_dashboard.setChecked(False)
        self.window.show()
        QTest.qWait(40)

    def tearDown(self):
        if self.window.running():
            self.window.cancel_scan()
            self.wait_for(lambda: not self.window.running(), 10000)
        self.window.close()
        self.window.deleteLater()
        self.app.processEvents()
        self.temp.cleanup()

    def wait_for(self, predicate, timeout=10000):
        if predicate():
            return
        # A real event loop releases the GIL while native Qt threads emit queued signals.
        loop = QEventLoop()
        poll = QTimer()
        poll.timeout.connect(lambda: loop.quit() if predicate() else None)
        deadline = QTimer()
        deadline.setSingleShot(True)
        deadline.timeout.connect(loop.quit)
        poll.start(20)
        deadline.start(timeout)
        loop.exec()
        poll.stop()
        deadline.stop()
        self.assertTrue(predicate(), "Qt condition timed out")

    def test_navigation_and_credits(self):
        for name, title in NAVIGATION:
            QTest.mouseClick(self.window.navigation[name], Qt.MouseButton.LeftButton)
            self.assertIs(self.window.stack.currentWidget(), self.window.pages[name])
            self.assertEqual(self.window.header_title.text(), title)
        self.assertIn("Thayner Kesley", self.window.credit.text())
        self.assertIn('Kekkai',self.window.windowTitle())
        self.assertFalse(self.window.windowIcon().isNull())

    def test_home_shortcuts_prepare_scan_without_starting(self):
        from PySide6.QtWidgets import QPushButton
        with patch("kekkai.scanners.docker_preflight") as preflight:
            for name, profile in [("homeQuick", "quick"), ("homeFull", "full")]:
                self.window.navigate("home")
                QTest.mouseClick(self.window.findChild(QPushButton, name), Qt.MouseButton.LeftButton)
                self.assertEqual(self.window.selected_page, "scan")
                self.assertEqual(self.window.scan_page.profile.currentText(), profile)
                self.assertFalse(self.window.running())
                self.assertIsNone(self.window.worker)
            preflight.assert_not_called()
        self.assertFalse((self.root / ".security/reports/summary.json").exists())
        self.assertTrue(self.window.scan_page.start.isEnabled())

    def test_remove_recent_project_preserves_active_project_and_files(self):
        marker = self.root / "source.py"
        marker.write_text("KEEP", encoding="utf-8")
        self.window.preferences.remember(self.root)
        self.window.refresh()
        self.window.navigate("projects")
        page = self.window.pages["projects"]
        page.list.setCurrentRow(0)
        QTest.mouseClick(page.remove, Qt.MouseButton.LeftButton)
        self.assertEqual(page.list.count(), 0)
        self.assertEqual(Preferences(self.window.preferences.path).data["recent_projects"], [])
        self.assertEqual(self.window.target, self.root)
        self.assertEqual(marker.read_text(), "KEEP")
        self.window.refresh()
        self.assertEqual(page.list.count(), 0)

    def report_fixture(self):
        from kekkai import engine
        results = [engine.make_result(name, "skipped", None, []) for name in engine.SCANNER_ORDER]
        findings = engine.parse_gitleaks([{"RuleID": "fixture-rule", "Description": "Original scanner description", "File": "source.py", "StartLine": 1}], True, self.root)
        results[1] = engine.make_result("gitleaks", "fail", 1, findings)
        summary = engine.build_summary(self.config, self.root, "Export fixture", results)
        # A second location checks that a PDF is complete even when the visible report is filtered.
        extra = deepcopy(findings[0])
        extra.update(id="fixture-second-location", location={"file": "second.py", "line": 2})
        summary["findings"].append(extra)
        return summary

    def test_browser_and_html_export_use_selected_snapshot(self):
        from kekkai import engine
        from kekkai.core.storage import ReportStore
        summary = self.report_fixture()
        dirs = engine.prepare_output_dirs(self.root, ".security")
        archived = ReportStore(dirs["root"]).archive(summary, dirs["reports"], None)
        self.window.refresh_reports()
        self.window.pages["reports"].list.selectRow(0)
        with patch("kekkai.gui.window.QDesktopServices.openUrl", return_value=True) as opened:
            self.window.open_report("browser")
        url = opened.call_args.args[0]
        html = Path(url.toLocalFile()).read_text(encoding="utf-8")
        self.assertIn("Export fixture", html)
        self.assertIn('class="standalone"', html)
        self.assertIn("Content-Security-Policy", html)
        self.assertTrue((archived / "summary.json").is_file())
        exported = self.root / "selected-report.html"
        with patch.object(QFileDialog, "getSaveFileName", return_value=(str(exported), "HTML (*.html)")):
            self.window.open_report("html")
        self.assertEqual(exported.read_text(encoding="utf-8"), html)

    def test_scan_completion_can_open_browser_without_changing_app_page(self):
        from kekkai.core.service import run_scan
        outcome = run_scan(self.root, deepcopy(configuration.DEFAULTS))
        self.window.navigate("scan")
        self.window.scan_page.open_dashboard.setChecked(True)
        self.window.scan_page.report_viewer.setCurrentIndex(1)
        with patch("kekkai.gui.window.QDesktopServices.openUrl", return_value=True) as opened:
            self.window.scan_completed(outcome)
        self.assertEqual(self.window.selected_page, "scan")
        self.assertTrue(Path(opened.call_args.args[0].toLocalFile()).is_file())

    def test_pdf_export_has_complete_snapshot_without_changing_visible_view(self):
        summary = self.report_fixture()
        dashboard = self.window.pages["dashboard"]
        dashboard.show_summary({**summary, "project": "Visible dashboard"}, "dark")
        destination = self.root / "report.pdf"
        with patch.object(QFileDialog, "getSaveFileName", return_value=(str(destination), "PDF (*.pdf)")):
            self.window.export_dashboard("pdf", summary)
        self.wait_for(lambda: self.window.pdf_export is None, 30000)
        self.assertTrue(destination.read_bytes().startswith(b"%PDF-"))
        self.assertGreater(destination.stat().st_size, 10000)
        from PySide6.QtPdf import QPdfDocument
        from PySide6.QtCore import QBuffer, QIODevice
        buffer = QBuffer(self.window)
        buffer.setData(destination.read_bytes())
        buffer.open(QIODevice.OpenModeFlag.ReadOnly)
        document = QPdfDocument(self.window)
        try:
            document.load(buffer)
            self.assertEqual(document.error(), QPdfDocument.Error.None_)
            text = "\n".join(document.getAllText(page).text() for page in range(document.pageCount()))
            # PDF extractors can omit spaces from tightly kerned headings.
            self.assertIn("Exportfixture", "".join(text.split()))
            self.assertIn("source.py", text)
            self.assertIn("second.py", text)
        finally:
            document.close()
            buffer.close()
        self.assertEqual(dashboard.summary["project"], "Visible dashboard")
        self.assertEqual(dashboard.theme, "dark")

    def test_failed_pdf_does_not_replace_an_existing_file(self):
        from kekkai.gui.report_view import PdfExport
        destination = self.root / "existing.pdf"
        destination.write_bytes(b"KEEP")
        job = PdfExport(self.window)
        job.destination = destination
        complete = []
        job.finished.connect(lambda path, success: complete.append(success))
        job.printed(b"")
        self.assertEqual(complete, [False])
        self.assertEqual(destination.read_bytes(), b"KEEP")

    def test_english_navigation_forms_and_live_dashboard(self):
        from kekkai.i18n import set_language
        other=MainWindow(self.window.preferences,self.root,language='en')
        try:
            other.show()
            self.assertEqual(other.navigation['home'].text(),'Overview')
            self.assertEqual(other.navigation['projects'].text(),'Projects')
            self.assertEqual(other.navigation['reports'].text(),'Reports')
            self.assertIn('DEVELOPED BY',other.credit.text())
            other.navigate('settings')
            self.assertEqual(other.header_title.text(),'Settings')
            self.assertEqual(other.settings_page.language.currentData(),'en')
            self.assertEqual(other.scan_page.project_type.itemText(0),'Local code / non-web')
            other.navigate('dashboard')
            ready=[]
            def inspect():
                other.pages['dashboard'].page.runJavaScript("document.documentElement.lang + '|' + document.querySelector('.report-nav a').textContent",ready.append)
            timer=QTimer();timer.timeout.connect(inspect);timer.start(70)
            try:self.wait_for(lambda:'en|Overview' in ready)
            finally:timer.stop()
        finally:
            other.close();other.deleteLater();self.app.processEvents();set_language('pt_BR')

    def test_report_deletion_requires_confirmation_and_preserves_history(self):
        from kekkai.core.service import run_scan
        outcome=run_scan(self.root,deepcopy(configuration.DEFAULTS))
        self.window.scan_completed(outcome)
        reports=self.window.pages['reports']
        current=self.root/'.security/reports/summary.json'
        self.assertEqual(len(reports.entries),2)
        with patch.object(QMessageBox,'question',return_value=QMessageBox.StandardButton.No):self.window.open_report('delete')
        self.assertTrue(current.exists())
        with patch.object(QMessageBox,'question',return_value=QMessageBox.StandardButton.Yes):self.window.open_report('delete')
        self.assertFalse(current.exists())
        self.assertEqual(len(reports.entries),1)
        self.assertTrue(Path(reports.entries[0]['path']).is_file())
        self.assertTrue((self.root/'.kekkai.yml').is_file())

    def test_web_project_choice_and_zap_callout(self):
        self.window.navigate('scan')
        self.window.config['policy']['zap'].update(enabled=True,target='http://localhost:4173')
        self.window.scan_page.project_type.setCurrentIndex(1)
        self.window.refresh()
        self.assertTrue(self.window.config['project']['web'])
        self.assertTrue(self.window.scan_page.zap_callout.isVisible())
        self.window.save_config()
        self.assertTrue(yaml.safe_load((self.root/'.kekkai.yml').read_text())['project']['web'])
        self.window.scan_page.project_type.setCurrentIndex(0)
        self.assertFalse(self.window.scan_page.zap_callout.isVisible())
        self.assertFalse(self.window.scan_page.toggles['zap'].isEnabled())

    def test_import_prompts_and_persists_project_type(self):
        project=self.root/'imported';project.mkdir()
        with patch.object(QFileDialog,'getExistingDirectory',return_value=str(project)),patch.object(QInputDialog,'getItem',return_value=('Aplicação web',True)) as prompt:
            self.window.choose_project()
        prompt.assert_called_once()
        self.assertTrue(yaml.safe_load((project/'.kekkai.yml').read_text())['project']['web'])

    def test_target_probe_and_ready_status(self):
        self.window.navigate('scan')
        self.window.config['policy']['zap'].update(enabled=True,target='http://localhost:4173')
        self.window.set_project_type(True)
        self.app.processEvents()
        with patch('kekkai.gui.worker.probe_zap_container',return_value={'reachable':True}),patch('kekkai.gui.worker.test_target',return_value={'reachable':True,'http_status':403,'latency_ms':12}):
            QTest.mouseClick(self.window.scan_page.test_target,Qt.MouseButton.LeftButton)
            self.wait_for(lambda:not self.window.probes)
        self.assertIn('HTTP 403',self.window.scan_page.target_status.text())
        self.assertIn('HTTP 403',self.window.scan_page.scanner_table.item(5,1).text())

    def test_ai_connection_button_no_source_or_key_logs(self):
        self.window.navigate('ai')
        fields=self.window.ai_page.providers['deepseek']
        fields['model'].setText('deepseek-flash');fields['key'].setText('UNIT_TEST_CREDENTIAL')
        response={'choices':[{'finish_reason':'stop','message':{'content':'{"ok":true}'}}]}
        with patch('kekkai.ai_providers.post_json',return_value=response) as post:
            QTest.mouseClick(fields['test'],Qt.MouseButton.LeftButton)
            self.wait_for(lambda:not self.window.probes)
        self.assertIn('Conectado',fields['status'].text())
        self.assertNotIn('app.py',json.dumps(post.call_args.args[2]))
        self.assertNotIn('UNIT_TEST_CREDENTIAL',fields['status'].text()+self.window.scan_page.log.toPlainText())

    def test_scan_diagnostic_displayed(self):
        self.window.navigate('scan')
        self.window.scan_page.receive({'kind':'scanner_finished','scanner':'yara','status':'skipped','findings':0,'duration_seconds':0,
                                     'diagnostic':{'summary':'Nenhuma regra YARA configurada.'}})
        self.assertIn('Nenhuma regra',self.window.scan_page.scanner_table.item(3,4).text())

    def test_theme_toggles_and_shared_tokens(self):
        self.assertEqual(self.window.theme, "dark")
        QTest.mouseClick(self.window.theme_button, Qt.MouseButton.LeftButton)
        self.assertEqual(self.window.theme, "light")
        self.assertIn("#F5E4D7", self.window.styleSheet())
        self.assertEqual(self.window.pages["dashboard"].theme, "light")
        QTest.mouseClick(self.window.theme_button, Qt.MouseButton.LeftButton)
        self.assertEqual(self.window.theme, "dark")
        self.assertIn("#242038", self.window.styleSheet())

    def test_provider_fields_are_masked_and_config_is_key_free(self):
        for name in ("deepseek", "qwen", "openai", "anthropic"):
            key = self.window.ai_page.providers[name]["key"]
            self.assertEqual(key.echoMode(), QLineEdit.EchoMode.Password)
            key.setText("UNIT_TEST_CREDENTIAL")
        config = self.window.collect_config()
        self.assertNotIn("UNIT_TEST_CREDENTIAL", json.dumps(config))
        self.window.save_config()
        self.assertNotIn("UNIT_TEST_CREDENTIAL", (self.root / ".kekkai.yml").read_text())

    def test_click_scan_offline_updates_status_and_reports(self):
        self.window.navigate("scan")
        with patch("kekkai.scanners.docker_preflight", return_value="Docker offline"):
            QTest.mouseClick(self.window.scan_page.start, Qt.MouseButton.LeftButton)
            self.wait_for(lambda: self.window.summary is not None and self.window.scan_page.start.isEnabled())
        self.assertEqual(self.window.summary["result"], "error")
        self.assertEqual(self.window.summary["scanners"]["gitleaks"]["status"], "error")
        self.assertEqual(self.window.scan_page.progress.value(), 7)
        self.assertTrue((self.root / ".security/dashboard/index.html").is_file())
        self.assertEqual(len(self.window.pages["reports"].entries), 2)
        self.assertTrue(self.window.scan_page.start.isEnabled())

    def test_dashboard_javascript_loads_offline_and_theme_changes(self):
        self.window.show_dashboard()
        page = self.window.pages["dashboard"].page
        ready = []
        self.window.pages["dashboard"].view.loadFinished.connect(ready.append)
        self.wait_for(lambda: bool(ready), 10000)
        self.assertTrue(ready[-1])
        results = []
        page.runJavaScript("JSON.stringify({cards:document.querySelectorAll('#cards .card').length,theme:document.documentElement.dataset.theme,credit:document.body.innerText.includes('Thayner Kesley')})", results.append)
        self.wait_for(lambda: bool(results))
        values = json.loads(results[0])
        self.assertEqual(values["cards"], 7)
        self.assertTrue(values["credit"])
        self.window.apply_theme("light")
        theme = []
        page.runJavaScript("document.documentElement.dataset.theme", theme.append)
        self.wait_for(lambda: bool(theme))
        self.assertEqual(theme[0], "light")

    def test_desktop_ai_requires_consent_and_discards_key(self):
        (self.root / "app.py").write_text("print('fixture')\n", encoding="utf-8")
        (self.root / "guide.md").write_text("Review fixture security. Return JSON.", encoding="utf-8")
        fields = self.window.ai_page.providers["deepseek"]
        fields["enabled"].setChecked(True)
        fields["model"].setText("deepseek-v4-pro")
        fields["key"].setText("UNIT_TEST_CREDENTIAL")
        self.window.ai_page.guide_mode.setCurrentIndex(1)
        self.window.ai_page.guide_path.setText("guide.md")
        self.window.toggle_scanner("ai", True)
        requests = []
        response = {"choices": [{"finish_reason": "stop", "message": {"content": '{"findings":[]}'}}], "usage": {"prompt_tokens": 10, "completion_tokens": 20}}
        from kekkai import engine as engine
        with patch.object(QMessageBox, "exec", return_value=QMessageBox.StandardButton.Yes) as dialog, patch("kekkai.scanners.docker_preflight", return_value=None), patch("kekkai.scanners.run_gitleaks", return_value=engine.make_result("gitleaks", "pass", 0, [])), patch("kekkai.ai_providers.post_json", return_value=response) as post:
            self.window.start_scan()
            self.window.worker.consent_requested.connect(requests.append)
            self.wait_for(lambda: self.window.summary is not None and not self.window.running())
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["provider"], "deepseek")
        self.assertEqual(self.window.summary["scanners"]["ai"]["status"], "pass")
        post.assert_called_once()
        dialog.assert_called_once()
        self.assertEqual(fields["key"].text(), "")
        self.assertIsNone(self.window.worker.interaction.key)
        self.assertFalse(self.window.requested_ai)
        for path in (self.root / ".security").rglob("*"):
            if path.is_file():
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("UNIT_TEST_CREDENTIAL", text)
                self.assertNotIn("print('fixture')", text)

    def test_cancel_button_preserves_report(self):
        import time
        from kekkai import engine as engine
        cancelled = []
        import threading
        started = threading.Event()
        def delayed(*args):
            started.set()
            for _ in range(30):
                if self.window.worker.cancel_event.is_set():
                    cancelled.append(True)
                    break
                time.sleep(.02)
            return engine.make_result("gitleaks", "pass", 0, [])
        self.window.navigate("scan")
        with patch("kekkai.scanners.docker_preflight", return_value=None), patch("kekkai.scanners.run_gitleaks", side_effect=delayed):
            self.window.start_scan()
            self.wait_for(started.is_set)
            QTest.mouseClick(self.window.scan_page.cancel, Qt.MouseButton.LeftButton)
            self.wait_for(lambda: self.window.scan_page.start.isEnabled())
        self.assertTrue(cancelled)
        self.assertIsNone(self.window.summary)
        self.assertFalse((self.root / ".security/reports/summary.json").exists())
        self.assertTrue(self.window.scan_page.start.isEnabled())

    @unittest.skipUnless(os.environ.get("KEKKAI_DOCKER_TESTS") == "1", "Real GUI scan opt-in")
    def test_real_gitleaks_started_by_gui_button(self):
        (self.root / "app.py").write_text("print('clean fixture')\n", encoding="utf-8")
        self.window.navigate("scan")
        QTest.mouseClick(self.window.scan_page.start, Qt.MouseButton.LeftButton)
        self.wait_for(lambda: self.window.summary is not None and not self.window.running(), 60000)
        self.assertEqual(self.window.summary["scanners"]["gitleaks"]["status"], "pass")
        self.assertEqual(self.window.summary["result"], "approved")
        self.assertEqual(len(self.window.pages["reports"].entries), 2)


if __name__ == "__main__":
    unittest.main()
