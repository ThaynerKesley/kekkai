"""Opt-in real Docker acceptance tests. Run with SECSCAN_DOCKER_TESTS=1."""
import json
import os
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from secscan import configuration, scanners
from secscan import secscan as api
from secscan.files import Exclusions, Sanitizer


@unittest.skipUnless(os.environ.get("SECSCAN_DOCKER_TESTS") == "1", "Docker integration opt-in")
class DockerIntegration(unittest.TestCase):
    def setUp(self):
        if scanners.docker_preflight():
            self.skipTest("Docker indisponível")
        self.temp = tempfile.TemporaryDirectory(prefix="secscan-integration-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.exclusions = Exclusions(self.root, [*configuration.EXCLUDES, "IDEA", "references", "external refs"])
        self.policy = deepcopy(configuration.DEFAULTS["policy"])
        self.performance = deepcopy(configuration.DEFAULTS["performance"])

    def file(self, path, content):
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")

    def test_real_gitleaks_custom_config_and_exclusions(self):
        self.file(".gitleaks.toml", "[[rules]]\nid='fixture-rule'\nregex='''SECSCAN_SECRET_[A-Za-z0-9]{16}'''\n")
        lab_value = "SECSCAN_SECRET_" + "A" * 16
        self.file("src/leak.py", 'test_value = "' + lab_value + '"')
        # A sizeable ignored subtree validates traversal exclusions, not only parsing filters.
        for path in ["node_modules/large.js", "sub/node_modules/large.js", "IDEA/external.py", "references/external.py", "external refs/external.py"]:
            self.file(path, ('"' + lab_value + '"\n') * 20000)
        result = scanners.run_gitleaks(api, self.root, self.policy["gitleaks"], self.exclusions)
        self.assertEqual(result["status"], "fail", result.get("error"))
        self.assertEqual(result["total_findings"], 1)
        self.assertEqual(result["findings"][0]["location"]["file"], "src/leak.py")
        self.assertNotIn(lab_value, json.dumps(result["raw"]))

    def test_real_gitleaks_default_rules_with_empty_exclusions(self):
        self.file('example.py','print(1)')
        result=scanners.run_gitleaks(api,self.root,self.policy['gitleaks'],Exclusions(self.root,[]))
        self.assertEqual(result['status'],'pass',result.get('error'))
        self.assertEqual(result['findings'],[])

    def test_real_trivy_vulnerable_dependency_warm_cache(self):
        self.file("requirements.txt", "Flask==0.12.2\n")
        warm = scanners.run_sca(api, self.root, self.policy["sca"], self.exclusions, self.performance)
        self.assertNotEqual(warm['status'],'error',warm.get('error'))
        result = scanners.run_sca(api, self.root, self.policy["sca"], self.exclusions, self.performance)
        self.assertEqual(result["status"], "fail", result.get("error"))
        self.assertGreater(result["details"]["version_risk"]["blocking"], 0)
        self.assertTrue(result["cache"]["cache_hit"])
        self.assertEqual(result["cache"]["trivy_db_download_seconds"], 0)
        self.assertTrue(all(f["location"]["file"] == "requirements.txt" for f in result["findings"]))

    def test_real_license_classification(self):
        # Composer lockfiles embed explicit package license identifiers (no install/network needed).
        self.file("composer.lock", json.dumps({"packages": [{"name": "fixture/license", "version": "1.0.0",
                   "license": ["MIT"], "type": "library", "require": {}}], "packages-dev": []}))
        policy = self.policy["sca"]
        policy["version_risk"]["enabled"] = False
        result = scanners.run_sca(api, self.root, policy, self.exclusions, self.performance)
        self.assertNotEqual(result["status"], "error", result.get("error"))
        self.assertGreater(result["details"]["license"]["findings"], 0)
        findings = result["findings"]
        self.assertTrue(any(f["technical"]["license"] == "MIT" for f in findings))
        self.assertTrue(any(f["technical"]["classification"].lower() == "notice" for f in findings))
        self.assertFalse(any(f["blocking"] for f in findings))

    def test_real_owasp_mapping_and_exclusions(self):
        code = "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n"
        self.file("src/app.py", code)
        self.file("IDEA/external.py", code)
        self.file("node_modules/external.py", code)
        result = scanners.run_semgrep(api, self.root, self.policy["owasp"], self.exclusions, owasp=True)
        self.assertNotEqual(result["status"], "error", result.get("error"))
        self.assertGreater(result["total_findings"], 0)
        self.assertEqual(result["details"]["edition"], "2025")
        self.assertTrue(all(f["location"]["file"] == "src/app.py" for f in result["findings"]))
        self.assertTrue(all(f["technical"]["owasp_categories"] for f in result["findings"]))
        self.assertNotIn("app.run(debug=True)", json.dumps(result["raw"]))

    def test_real_semgrep_auto(self):
        self.file("app.py", "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n")
        result = scanners.run_semgrep(api, self.root, self.policy["semgrep"], self.exclusions)
        self.assertNotEqual(result["status"], "error", result.get("error"))

    def test_real_zap_local_target_memory_only_reports(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from secscan.runner import run_zap
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<!doctype html><html><title>SecScan fixture</title><p>Fixture</p></html>")

            def log_message(self, *args):
                return
        server = ThreadingHTTPServer(("0.0.0.0", 0), Handler)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        policy = {**self.policy["zap"], "target": f"http://localhost:{server.server_port}"}
        result = run_zap(api, policy)
        self.assertNotEqual(result["status"], "error", result.get("error"))
        self.assertIn("site", result["raw"])
        self.assertFalse(list(self.root.rglob("zap*")))


if __name__ == "__main__":
    api.configure_stdio()
    unittest.main()
