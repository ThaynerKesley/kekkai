"""Desktop services and provider contracts, without UI automation or real AI keys."""
import json
import os
import subprocess
import tempfile
import threading
import unittest
import zipfile
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from kekkai import configuration, ai_review
from kekkai import engine as engine
from kekkai.ai.credentials import WindowsCredentialStore
from kekkai.ai_providers import DeepSeekProvider, QwenProvider, ProviderError
from kekkai.core.execution import ExecutionContext, ScanCancelled
from kekkai.core.service import run_scan
from kekkai.core.storage import Preferences, ReportStore, save_project_config
from kekkai.dashboard import render
from kekkai.themes import tokens


class DesktopCoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kekkai-desktop-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = deepcopy(configuration.DEFAULTS)

    def test_core_no_qt_dependency_and_skipped_scan(self):
        outcome = run_scan(self.root, self.config)
        self.assertEqual(outcome["summary"]["result"], "approved")
        self.assertTrue((self.root / ".security/dashboard/index.html").is_file())
        self.assertEqual(outcome["summary"]["scanners"]["ai"]["status"], "skipped")

    def test_progress_events_are_structured_and_sanitized(self):
        self.config["policy"]["gitleaks"]["enabled"] = True
        events = []
        with patch("kekkai.scanners.docker_preflight", return_value="Docker offline"):
            result = run_scan(self.root, self.config, on_event=events.append)
        self.assertEqual(result["summary"]["result"], "error")
        self.assertEqual(sum(e["kind"] == "scanner_finished" for e in events), 7)
        self.assertNotIn("findings", json.dumps([event for event in events if event["kind"] == "scanner_started"]))
        self.assertFalse(any("key" in event or "source" in event for event in events))

    def test_cancel_preserves_previous_report(self):
        previous = self.root / ".security/reports/summary.json"
        previous.parent.mkdir(parents=True)
        previous.write_text("previous report", encoding="utf-8")
        cancelled = threading.Event()
        cancelled.set()
        with self.assertRaises(ScanCancelled):
            run_scan(self.root, self.config, cancel=cancelled)
        self.assertEqual(previous.read_text(), "previous report")

    def test_cancellable_docker_owns_only_its_container(self):
        cancel = threading.Event()
        process = unittest.mock.Mock()
        process.poll.return_value = None
        def communicate(timeout=None):
            if timeout is not None:
                cancel.set()
                raise subprocess.TimeoutExpired("owned scanner", timeout)
            process.poll.return_value = -1
            return ("", "")
        process.communicate.side_effect = communicate
        with patch("subprocess.Popen", return_value=process), patch.object(engine, "stop_container") as stop:
            outcome = ExecutionContext(cancel).run_docker(["docker", "run"], 30, "kekkai-owned-test")
        stop.assert_called_once_with("kekkai-owned-test")
        process.kill.assert_called_once()
        self.assertEqual(outcome["error"], "Scan cancelado pelo usuário.")

    def test_no_key_in_preferences_or_yaml(self):
        preferences = Preferences(self.root / "prefs.json")
        preferences.data["scan_defaults"] = self.config
        preferences.save()
        save_project_config(self.root, self.config)
        self.assertNotIn("api_key", (self.root / ".kekkai.yml").read_text())
        self.config["ai"]["api_key"] = "UNIT_TEST_CREDENTIAL"
        preferences.data["scan_defaults"] = self.config
        with self.assertRaises(ValueError):
            preferences.save()
        self.assertNotIn("UNIT_TEST_CREDENTIAL", (self.root / "prefs.json").read_text())

    def test_profiles_persist(self):
        preferences = Preferences(self.root / "prefs.json")
        preferences.data["profiles"] = {"quick": {"scanners": {"gitleaks": True}}}
        preferences.save()
        loaded = Preferences(preferences.path)
        self.assertTrue(loaded.data["profiles"]["quick"]["scanners"]["gitleaks"])

    def test_malformed_preferences_are_reported(self):
        path = self.root / "prefs.json"
        path.write_text(json.dumps({"recent_projects": None}), encoding="utf-8")
        with self.assertRaises(ValueError):
            Preferences(path)

    def test_unknown_project_configuration_is_preserved(self):
        self.config["custom_extension"] = {"owner": "Fixture"}
        self.config["profile"] = "quick"
        save_project_config(self.root, self.config)
        import yaml
        data = yaml.safe_load((self.root / ".kekkai.yml").read_text())
        self.assertEqual(data["custom_extension"], {"owner": "Fixture"})
        self.assertNotIn("profile", data)

    def test_history_and_export(self):
        outcome = run_scan(self.root, self.config)
        store = ReportStore(self.root / ".security")
        archived = store.archive(outcome["summary"], Path(outcome["dirs"]["reports"]), Path(outcome["dirs"]["dashboard"]) / "index.html")
        self.assertTrue((archived / "dashboard.html").is_file())
        self.assertEqual(len(store.list_reports()), 2)
        destination = self.root / "export.zip"
        store.export(archived, destination)
        with zipfile.ZipFile(destination) as archive:
            self.assertIn("summary.json", archive.namelist())
            self.assertIn("dashboard.html", archive.namelist())
        with self.assertRaises(ValueError):
            store.export(archived, archived / "nested.zip")
        with self.assertRaises(ValueError):
            store.export(self.root, destination)

    def test_shared_palettes_and_credit(self):
        self.assertEqual(tokens("dark")["primary"], "#725AC1")
        self.assertEqual(tokens("light")["primary"], "#73877B")
        html = render({"project": "Fixture"}, "light")
        self.assertIn('data-theme="light"', html)
        self.assertIn("Thayner Kesley", html)
        self.assertIn("Findings por severidade", html)
        self.assertNotIn("__KEKKAI_", html)
        self.assertNotIn('<script src="http', html)
        self.assertNotIn("</script><script>", render({"project": "</script><script>alert(1)</script>"}))

    def test_palette_body_and_button_contrast(self):
        def luminance(color):
            values = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
            values = [x / 12.92 if x <= .04045 else ((x + .055) / 1.055) ** 2.4 for x in values]
            return sum(x * w for x, w in zip(values, [.2126, .7152, .0722]))
        for theme in ("light", "dark"):
            palette = tokens(theme)
            for foreground, background in [("text-primary", "surface"), ("text-secondary", "surface"), ("muted", "surface"), ("on-primary", "primary")]:
                high, low = sorted([luminance(palette[foreground]), luminance(palette[background])], reverse=True)
                self.assertGreaterEqual((high + .05) / (low + .05), 4.5, (theme, foreground, background))

    def test_deepseek_json_adapter_and_usage(self):
        response = {"choices": [{"finish_reason": "stop", "message": {"content": '{"findings":[]}'}}], "usage": {"prompt_tokens": 10, "completion_tokens": 20}}
        with patch("kekkai.ai_providers.post_json", return_value=response) as post:
            text, usage = DeepSeekProvider().scan(key="UNIT_TEST_CREDENTIAL", model="deepseek-flash", guide="guide", bundle="FILE", schema=ai_review.SCHEMA, timeout=1, max_output_tokens=20)
        self.assertEqual(text, '{"findings":[]}')
        self.assertEqual(usage["input_tokens"], 10)
        body = post.call_args.args[2]
        self.assertEqual(body["response_format"], {"type": "json_object"})
        self.assertEqual(len(body["messages"]), 2)
        self.assertNotIn("previous_response_id", body)

    def test_qwen_official_region_and_json_mode(self):
        response = {"choices": [{"finish_reason": "stop", "message": {"content": '{"findings":[]}'}}]}
        with patch("kekkai.ai_providers.post_json", return_value=response) as post:
            QwenProvider().scan(key="UNIT_TEST_CREDENTIAL", model="qwen-plus", guide="guide", bundle="FILE", schema={}, timeout=1, max_output_tokens=20)
        self.assertTrue(post.call_args.args[0].startswith("https://dashscope-intl.aliyuncs.com/"))
        self.assertFalse(post.call_args.args[2]["enable_thinking"])
        with self.assertRaises(ProviderError):
            QwenProvider("http://untrusted.invalid")

    @unittest.skipUnless(os.name == "nt", "Windows credential integration")
    def test_native_vault_round_trip_in_isolated_namespace(self):
        store = WindowsCredentialStore()
        namespace = "Kekkai/UnitTests/" + uuid4().hex
        with patch.object(store, "_target", return_value=namespace):
            try:
                store.save("deepseek", "UNIT_TEST_CREDENTIAL")
                self.assertEqual(store.read("deepseek"), "UNIT_TEST_CREDENTIAL")
                self.assertTrue(store.configured("deepseek"))
            finally:
                store.delete("deepseek")
            self.assertIsNone(store.read("deepseek"))


if __name__ == "__main__":
    unittest.main()
