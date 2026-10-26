"""Regression and acceptance tests; provider requests never reach the network."""
import io
import json
import subprocess
import tempfile
import time
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import yaml

from secscan import ai_review, cache, configuration, runner, scanners
from secscan import secscan as api
from secscan.ai_providers import OpenAIProvider, AnthropicProvider, ProviderError
from secscan.files import Exclusions, Sanitizer


class Workspace(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="secscan-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = deepcopy(configuration.DEFAULTS)
        self.config['policy']['yara']['use_managed']=False  # Fixture tests isolate manual rules from the user's shared library.
        self.config["profile"] = "full"

    def file(self, path, content=""):
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
        return destination

    def findings(self):
        return {"findings": [{"title": "Review authorization", "severity": "HIGH", "confidence": "HIGH",
             "cwe": "CWE-862", "owasp": "A01:2025", "file": "src/app.py", "line": 1,
             "description": "Validate ownership", "impact": "Unauthorized access", "evidence": "Source omitted",
             "recommendation": "Enforce authorization"}]}


class ConfigTests(Workspace):
    def test_legacy_policy(self):
        self.file(".secscan.yml", yaml.safe_dump({"policy": {"trivy": {"enabled": True, "severity": ["MEDIUM"]}, "zap": {"enabled": True}}}))
        loaded = configuration.load(self.root)
        self.assertTrue(loaded["policy"]["sca"]["enabled"])
        self.assertEqual(loaded["policy"]["sca"]["version_risk"]["fail_on"], ["MEDIUM"])
        self.assertFalse(loaded["policy"]["sca"]["license"]["enabled"])

    def test_quick(self):
        self.file(".secscan.yml", yaml.safe_dump({"policy": {"zap": {"enabled": True}, "sca": {"license": {"full_scan": True}}}}))
        loaded = configuration.load(self.root, "quick")
        self.assertFalse(loaded["policy"]["zap"]["enabled"])
        self.assertFalse(loaded["policy"]["sca"]["license"]["full_scan"])

    def test_no_credentials_in_yaml(self):
        self.config["ai"]["api_key"] = "UNIT_TEST_CREDENTIAL"
        with self.assertRaises(ValueError):
            configuration.validate(self.config)

    def test_invalid_worker_count(self):
        self.config["performance"]["max_workers"] = 20
        with self.assertRaises(ValueError):
            configuration.validate(self.config)

    def test_empty_thresholds_are_respected(self):
        self.config["policy"]["zap"]["fail_on"] = []
        configuration.validate(self.config)
        self.assertEqual(api.classify_zap(1, []), "warn")

    def test_literal_exclusions(self):
        for path in ["../project", "C:/private", "a*", ""]:
            self.config["scan"]["exclude_paths"] = [path]
            with self.subTest(path=path), self.assertRaises(ValueError):
                configuration.validate(self.config)


class FilesTests(Workspace):
    def test_exclusions_recursive_and_nested(self):
        for name in ["src/app.py", "node_modules/x/a.js", "packages/x/node_modules/a.js", "IDEA/external/a.py", "src/keep.py", "references/a.py"]:
            self.file(name)
        paths = Exclusions(self.root, ["node_modules", "IDEA/", "references/"])
        self.assertEqual([p.relative_to(self.root).as_posix() for p in paths.files()], ["src/app.py", "src/keep.py"])

    def test_scanner_translation(self):
        exclusions = Exclusions(self.root, ["node_modules", "IDEA", "src/generated"])
        self.assertIn("**/node_modules", exclusions.semgrep_flags())
        self.assertIn("--skip-dirs", exclusions.trivy_flags())
        self.assertIn("--skip-files", exclusions.trivy_flags())
        import re
        self.assertTrue(any(re.search(pattern, "/src/sub/node_modules/pkg/file.js") for pattern in exclusions.gitleaks_regexes()))
        self.assertFalse(exclusions.matches("someIDEA/file.py"))

    def test_oversized_files(self):
        self.file("large.py", "a" * 1024)
        self.file("small.py", "ok")
        self.assertEqual([p.name for p in Exclusions(self.root, []).files(20)], ["small.py"])

    def test_symlink_not_followed(self):
        destination = self.file("source.py", "fixture")
        try:
            (self.root / "link.py").symlink_to(destination)
        except OSError:
            self.skipTest("Windows não permite criar symlinks neste terminal")
        self.assertEqual([p.name for p in Exclusions(self.root, []).files()], ["source.py"])

    def test_report_sanitization(self):
        value = "UNIT_TEST_SENSITIVE_VALUE"
        sanitizer = Sanitizer()
        sanitizer.secrets.add(value)
        data = sanitizer.clean({"title": "found " + value, "Match": value, "lines": "source code", "evidence": "code", "offsets": [{"offset": 0}]})
        self.assertNotIn(value, json.dumps(data))
        self.assertNotIn("source code", json.dumps(data))
        self.assertEqual(data["offsets"], [{"offset": 0}])


class PolicyTests(Workspace):
    def sca_data(self):
        return {"Results": [{"Target": "package-lock.json", "Type": "npm", "Vulnerabilities": [
            {"PkgName": "fixture", "InstalledVersion": "1", "FixedVersion": "2", "VulnerabilityID": "TEST-1", "Severity": "HIGH", "References": ["https://example.invalid/advisory"]},
            {"PkgName": "fixture", "VulnerabilityID": "TEST-2", "Severity": "MEDIUM"}],
            "Licenses": [{"Name": "MIT", "Category": "Permissive", "PkgName": "fixture"},
                         {"Name": "GPL-3.0", "Category": "Reciprocal", "PkgName": "other"}]}]}

    def test_sca_separate_modules(self):
        findings, details = scanners.parse_sca(api, self.sca_data(), self.config["policy"]["sca"], self.root)
        self.assertEqual(details["version_risk"]["findings"], 2)
        self.assertEqual(details["version_risk"]["blocking"], 1)
        self.assertEqual(details["license"]["blocking"], 0)
        self.assertEqual(findings[0]["technical"]["ecosystem"], "npm")
        self.assertEqual(len(findings[0]["technical"]["references"]), 1)

    def test_license_policy(self):
        policy = self.config["policy"]["sca"]
        policy["license"]["deny"] = ["MIT"]
        policy["license"]["allow"] = []
        findings, details = scanners.parse_sca(api, self.sca_data(), policy, self.root)
        self.assertEqual(details["license"]["blocking"], 1)
        policy["license"].update(deny=[], allow=["MIT"])
        _, details = scanners.parse_sca(api, self.sca_data(), policy, self.root)
        self.assertEqual(details["license"]["blocking"], 1)
        policy["license"].update(allow=[], fail_on_classification=["RECIPROCAL"])
        _, details = scanners.parse_sca(api, self.sca_data(), policy, self.root)
        self.assertEqual(details["license"]["blocking"], 1)

    def test_owasp_auto_and_inconsistent_metadata(self):
        rules = {"rules": [{"id": "old", "metadata": {"owasp": ["A03:2021 - Injection"]}},
                           {"id": "new", "metadata": {"owasp": ["A05:2025 - Injection"]}},
                           {"id": "bad", "metadata": {"owasp": ["A03:2025 - Injection"]}}]}
        selected, details = scanners.select_owasp_rules(rules, "auto")
        self.assertEqual(details["edition"], "2025")
        self.assertEqual([r["id"] for r in selected["rules"]], ["new"])
        self.assertEqual(details["categories"][4]["applicable_rules"], 1)

    def test_unsupported_edition(self):
        with self.assertRaises(ValueError):
            scanners.select_owasp_rules({"rules": [{"metadata": {"owasp": "A03:2021 - Injection"}}]}, "2025")

    def test_precedence_and_exit_result(self):
        self.assertEqual(api.decide_result([{"status": "error"}, {"status": "fail"}]), "error")
        self.assertEqual(api.decide_result([{"status": "warn"}, {"status": "fail"}]), "blocked")
        self.assertEqual(api.decide_result([{"status": "warn"}, {"status": "skipped"}]), "approved")

    def test_dedup_preserves_semgrep_blocking(self):
        data = {"results": [{"check_id": "shared-rule", "path": "src/app.py", "start": {"line": 1}, "extra": {"severity": "WARNING"}}]}
        first = api.parse_semgrep(data, True, self.root)
        second = deepcopy(first)
        second[0].update(scanner="owasp", blocking=False)
        results = [api.make_result("semgrep", "fail", 0, first), api.make_result("owasp", "warn", 0, second)]
        scanners.deduplicate(results, api)
        self.assertEqual(len(results[0]["findings"]), 0)
        self.assertTrue(results[1]["findings"][0]["blocking"])
        self.assertEqual(results[0]["total_findings"], 1)


class CacheTests(Workspace):
    def test_persistent_mode_keeps_scan_cache(self):
        options = {**self.config["performance"]["trivy_cache"], "mode": "persistent", "max_size_mb": None}
        with patch("secscan.cache.global_cache_dir", return_value=self.root / "persistent"), patch.object(cache.TrivyCache, "invoke") as invoke:
            with cache.TrivyCache(options, api) as instance:
                flags = instance.prepare(False, False)
                self.assertEqual(flags[flags.index("--cache-backend") + 1], "fs")
            invoke.assert_not_called()

    def create_db(self, age=0):
        updated = datetime.now(timezone.utc) - timedelta(hours=age)
        self.file("db/trivy.db", "fixture db")
        self.file("db/metadata.json", json.dumps({"UpdatedAt": updated.isoformat()}))

    def test_fresh_db_never_downloads(self):
        self.create_db()
        instance = cache.TrivyCache(self.config["performance"]["trivy_cache"], api)
        instance.path = self.root
        with patch.object(instance, "invoke") as invoke:
            flags = instance.prepare(True, False)
        invoke.assert_not_called()
        self.assertIn("--skip-db-update", flags)
        self.assertNotIn("--skip-java-db-update", flags)
        self.assertTrue(instance.metrics["cache_hit"])

    def test_missing_db_downloads_before_skip(self):
        instance = cache.TrivyCache(self.config["performance"]["trivy_cache"], api)
        instance.path = self.root
        def download(args, timeout=600):
            self.create_db()
            return {"exit_code": 0, "error": None}
        with patch.object(instance, "invoke", side_effect=download) as invoke:
            flags = instance.prepare(True, False)
        self.assertIn("--download-db-only", invoke.call_args.args[0])
        self.assertIn("--skip-db-update", flags)
        self.assertFalse(instance.metrics["cache_hit"])

    def test_expired_db_updates(self):
        self.create_db(25)
        instance = cache.TrivyCache(self.config["performance"]["trivy_cache"], api)
        instance.path = self.root
        with patch.object(instance, "invoke", return_value={"exit_code": 0, "error": None}) as invoke:
            instance.prepare(True, False)
        self.assertTrue(invoke.called)
        self.assertFalse(instance.metrics["cache_hit"])

    def test_license_only_avoids_db(self):
        instance = cache.TrivyCache(self.config["performance"]["trivy_cache"], api)
        instance.path = self.root
        with patch.object(instance, "invoke") as invoke:
            flags = instance.prepare(False, False)
        invoke.assert_not_called()
        self.assertNotIn("--skip-db-update", flags)

    def test_ephemeral_deleted(self):
        options = {**self.config["performance"]["trivy_cache"], "mode": "ephemeral"}
        with cache.TrivyCache(options, api) as instance:
            path = instance.path
            (path / "marker").write_text("fixture")
        self.assertFalse(path.exists())
        self.assertEqual(instance.metrics["cache_size_after"], 0)

    def test_smart_cleanup_preserves_useful_databases(self):
        self.create_db()
        options = {**self.config["performance"]["trivy_cache"], "max_size_mb": 0.000001}
        with patch("secscan.cache.global_cache_dir", return_value=self.root / "persistent"), patch.object(cache.TrivyCache, "invoke", return_value={"exit_code": 0, "error": None}) as invoke:
            with cache.TrivyCache(options, api) as instance:
                (instance.path / "db").mkdir()
                (instance.path / "db/trivy.db").write_bytes(b"fixture")
            calls = [call.args[0] for call in invoke.call_args_list]
            self.assertTrue(any("--scan-cache" in args for args in calls))
            self.assertFalse(any("--vuln-db" in args or "--all" in args for args in calls))
            self.assertTrue(instance.metrics["cleanup_warnings"])


class YaraTests(Workspace):
    def test_real_yara_match_metadata_and_offsets(self):
        self.file(".secscan/yara/a.yar", 'rule fixture : test { meta: severity="HIGH" author="test" strings: $a="UNIT_TEST_PATTERN" condition: $a }')
        self.file("src/app.py", 'print("UNIT_TEST_PATTERN")')
        self.file("IDEA/app.py", 'print("UNIT_TEST_PATTERN")')
        result = scanners.run_yara(api, self.root, self.config["policy"]["yara"], Exclusions(self.root, ["IDEA"]))
        self.assertEqual(result["status"], "warn")
        self.assertEqual(result["total_findings"], 1)
        self.assertEqual(result["findings"][0]["severity"], "HIGH")
        self.assertTrue(result["findings"][0]["technical"]["offsets"])
        self.assertNotIn("UNIT_TEST_PATTERN", json.dumps(result))

    def test_invalid_rule(self):
        self.file(".secscan/yara/a.yar", "rule invalid syntax")
        result = scanners.run_yara(api, self.root, self.config["policy"]["yara"], Exclusions(self.root, []))
        self.assertEqual(result["status"], "error")

    def test_multiple_rules_default_warn_and_blocking(self):
        self.file(".secscan/yara/a.yar", 'rule fixture { condition: true }')
        self.file(".secscan/yara/b.yara", 'rule fixture { condition: true }')
        self.file("file.bin", "fixture")
        policy = self.config["policy"]["yara"]
        policy["fail_on_match"] = True
        result = scanners.run_yara(api, self.root, policy, Exclusions(self.root, []))
        self.assertEqual(result["total_findings"], 2)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["findings"][0]["severity"], "WARN")


class AITests(Workspace):
    def test_two_chunks_have_no_history(self):
        self.file("first/a.py", "print('first fixture')")
        self.file("second/b.py", "print('second fixture')")
        self.file("guide.md", "Test review guide.")
        options = deepcopy(self.config["ai"])
        options.update(provider="openai", model="unit-test-model", guide={"mode": "custom", "path": "guide.md"})
        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", side_effect=["", "", "", "", "s"]), patch("secscan.ai_review.hidden_key", return_value="UNIT_TEST_CREDENTIAL"), patch("secscan.ai_providers.post_json", return_value={"status": "completed", "output": [{"content": [{"type": "output_text", "text": '{"findings":[]}'}]}]}) as post:
            result = ai_review.run_ai(api, self.root, options, Exclusions(self.root, []), api.make_result("gitleaks", "pass", 0, []), Sanitizer(), True, "full")
        self.assertEqual(result["status"], "pass")
        self.assertEqual(post.call_count, 2)
        first = post.call_args_list[0].args[2]
        second = post.call_args_list[1].args[2]
        self.assertIn("FILE: first/a.py", json.dumps(first))
        self.assertNotIn("FILE: first/a.py", json.dumps(second))
        self.assertEqual(len(second["input"]), 1)
        self.assertNotIn("previous_response_id", second)

    def test_api_key_and_source_not_persisted_in_any_report(self):
        text = self.findings()
        text["findings"][0]["description"] = "UNIT_TEST_CREDENTIAL print('fixture')"
        text["findings"][0]["evidence"] = "print('fixture')"
        result, _, _, _ = self.run_interactive(provider_text=json.dumps(text))
        results = [api.make_result(name, "skipped", None, []) for name in runner.SCANNER_ORDER]
        results[-1] = result
        summary = api.build_summary(self.config, self.root, "Test", results)
        dirs = api.prepare_output_dirs(self.root, ".security")
        runner.persist(api, results, summary, dirs)
        api.generate_dashboard(summary, dirs["dashboard"] / "index.html")
        for path in dirs["root"].rglob("*"):
            if path.is_file():
                content = path.read_text(encoding="utf-8")
                self.assertNotIn("UNIT_TEST_CREDENTIAL", content)
                self.assertNotIn("print('fixture')", content)
                self.assertNotIn("Test review guide.", content)

    def test_default_guide_missing_and_custom(self):
        # Isolate the absence case from any guide the user supplies in the real project.
        with patch("secscan.ai_review.__file__", str(self.root / "ai_review.py")), self.assertRaisesRegex(ValueError, "padrão não encontrado"):
            ai_review.load_guide(self.root, self.config["ai"])
        self.file("custom.md", "Test review guide.")
        self.config["ai"]["guide"] = {"mode": "custom", "path": "custom.md"}
        self.assertEqual(ai_review.load_guide(self.root, self.config["ai"]), "Test review guide.")

    def test_safe_selection(self):
        for path in ["src/app.py", ".env.example", "node_modules/a.js", "IDEA/a.py", "credentials.json", ".env", "private.key", "vendor/a.py", "src/leak.py"]:
            self.file(path, "print('fixture')")
        self.file("src/binary.py", "\0bad")
        gitleaks = api.make_result("gitleaks", "warn", 1, [{"location": {"file": "src/leak.py"}}])
        files, _ = ai_review.select_files(self.root, Exclusions(self.root, [*configuration.EXCLUDES, "IDEA"]), self.config["ai"], gitleaks, Sanitizer())
        self.assertEqual({path for path, _ in files}, {"src/app.py", ".env.example"})

    def test_chunking_deterministic(self):
        files = [("a/a.py", "aaa"), ("a/b.py", "bbb"), ("b/c.py", "ccc")]
        chunks = ai_review.chunks(files, 200)
        self.assertEqual(chunks, ai_review.chunks(files, 200))
        self.assertEqual(len(chunks), 2)
        self.assertIn("FILE: a/a.py", chunks[0][0])
        self.assertIn("END FILE", chunks[0][0])

    def test_schema_and_local_repair(self):
        value = self.findings()
        result = ai_review.parse_response("```json\n" + json.dumps(value) + "\n```", {"src/app.py"}, {"src/app.py": 1})
        self.assertEqual(result, value)
        with self.assertRaises(ValueError):
            ai_review.parse_response("free text", {"src/app.py"}, {"src/app.py": 1})
        value["findings"][0]["file"] = "../outside.py"
        with self.assertRaises(ValueError):
            ai_review.parse_response(json.dumps(value), {"src/app.py"}, {"src/app.py": 1})

    def test_skipped_without_explicit_request(self):
        self.config["ai"]["enabled"] = True
        with patch("builtins.input") as prompt:
            result = ai_review.run_ai(api, self.root, self.config["ai"], Exclusions(self.root, []), {}, Sanitizer(), False, "full")
        self.assertEqual(result["status"], "skipped")
        prompt.assert_not_called()

    def run_interactive(self, options=None, consent="s", provider_text=None):
        self.file("src/app.py", "print('fixture')")
        self.file("guide.md", "Test review guide.")
        ai_options = deepcopy(options or self.config["ai"])
        ai_options.update(provider="openai", model="unit-test-model")
        ai_options["guide"] = {"mode": "custom", "path": "guide.md"}
        text = provider_text if provider_text is not None else json.dumps(self.findings())
        sanitizer = Sanitizer()
        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", side_effect=["", "", "", "", consent]), patch("secscan.ai_review.hidden_key", return_value="UNIT_TEST_CREDENTIAL") as key, patch("secscan.ai_providers.post_json", return_value={"status": "completed", "output": [{"content": [{"type": "output_text", "text": text}]}], "usage": {"input_tokens": 5, "output_tokens": 10}}) as post:
            result = ai_review.run_ai(api, self.root, ai_options, Exclusions(self.root, []), api.make_result("gitleaks", "pass", 0, []), sanitizer, True, "full")
        return result, sanitizer, post, key

    def test_interactive_key_lifecycle_and_stateless_request(self):
        result, sanitizer, post, key = self.run_interactive()
        self.assertEqual(result["status"], "warn")
        self.assertTrue(result["findings"][0]["ai_assisted"])
        self.assertFalse(result["findings"][0]["blocking"])
        self.assertNotIn("UNIT_TEST_CREDENTIAL", sanitizer.secrets)
        self.assertNotIn("UNIT_TEST_CREDENTIAL", json.dumps(result))
        body = post.call_args.args[2]
        self.assertFalse(body["store"])
        self.assertNotIn("previous_response_id", body)
        self.assertNotIn("conversation", body)
        self.assertEqual(result["details"]["usage"]["total_tokens"], 15)
        self.assertEqual(list(self.root.rglob("*.json")), [])
        key.assert_called_once()

    def test_denied_consent(self):
        result, _, post, key = self.run_interactive(consent="n")
        self.assertEqual(result["status"], "skipped")
        post.assert_not_called()
        key.assert_not_called()

    def test_invalid_ai_json_is_error(self):
        result, _, _, _ = self.run_interactive(provider_text="invalid")
        self.assertEqual(result["status"], "error")

    def test_ai_policy_opt_in_blocking(self):
        options = deepcopy(self.config["ai"])
        options["fail_on_findings"] = True
        result, _, _, _ = self.run_interactive(options)
        self.assertEqual(result["status"], "fail")

    def test_no_getpass_fallback(self):
        import getpass, warnings
        def unsafe(prompt):
            warnings.warn("cannot hide input", getpass.GetPassWarning)
        with patch("getpass.getpass", side_effect=unsafe), self.assertRaises(getpass.GetPassWarning):
            ai_review.hidden_key()

    def test_anthropic_stateless_adapter(self):
        adapter = AnthropicProvider()
        with patch("secscan.ai_providers.post_json", return_value={"stop_reason": "end_turn", "content": [{"type": "text", "text": '{"findings":[]}'}], "usage": {}}) as post:
            adapter.scan(key="UNIT_TEST_CREDENTIAL", model="unit-test-model", guide="guide", bundle="FILE", schema=ai_review.SCHEMA, timeout=1, max_output_tokens=20)
        body = post.call_args.args[2]
        self.assertEqual(len(body["messages"]), 1)
        self.assertNotIn("cache_control", body)
        self.assertNotIn("conversation", body)


class RunnerTests(Workspace):
    def test_offline_cli_generates_dashboard_and_exit_one(self):
        config = deepcopy(configuration.DEFAULTS)
        for name in ("semgrep", "gitleaks", "sca", "owasp", "zap"):
            config["policy"][name]["enabled"] = True
        self.file(".secscan.yml", yaml.safe_dump(config))
        with patch("sys.argv", ["secscan", "check", str(self.root)]), patch("secscan.scanners.docker_preflight", return_value="Docker indisponível") as preflight, patch.object(api, "run_docker") as docker:
            code = runner.main(api)
        self.assertEqual(code, 1)
        preflight.assert_called_once()
        docker.assert_not_called()
        self.assertTrue((self.root / ".security/dashboard/index.html").is_file())
        summary = json.loads((self.root / ".security/reports/summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["result"], "error")

    def test_real_parallel_bound(self):
        import threading
        for name in ("semgrep", "gitleaks", "sca", "owasp", "zap"):
            self.config["policy"][name]["enabled"] = True
        self.config["performance"]["max_workers"] = 2
        active = 0
        peak = 0
        lock = threading.Lock()
        def run(name):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.03)
            with lock:
                active -= 1
            return api.make_result(name, "pass", 0, [])
        with patch("secscan.scanners.docker_preflight", return_value=None), patch("secscan.scanners.run_semgrep", side_effect=lambda *args, **kw: run("owasp" if kw.get("owasp") else "semgrep")), patch("secscan.scanners.run_gitleaks", side_effect=lambda *args: run("gitleaks")), patch("secscan.scanners.run_sca", side_effect=lambda *args: run("sca")), patch("secscan.runner.run_zap", side_effect=lambda *args, **kwargs: run("zap")), patch("secscan.runner.test_target", return_value={"reachable": True}):
            results, performance, _ = runner.execute(api, self.root, self.config)
        self.assertEqual(peak, 2)
        self.assertEqual(performance["max_workers"], 2)
        self.assertTrue(any(item["parallel_with"] for item in results))

    def test_offline_one_preflight_all_docker_errors_dashboard(self):
        for name in ("semgrep", "gitleaks", "sca", "owasp", "zap"):
            self.config["policy"][name]["enabled"] = True
        with patch("secscan.scanners.docker_preflight", return_value="Docker indisponível") as preflight, patch.object(api, "run_docker") as docker:
            results, performance, _ = runner.execute(api, self.root, self.config)
        preflight.assert_called_once()
        docker.assert_not_called()
        self.assertEqual(sum(x["status"] == "error" for x in results), 5)
        summary = api.build_summary(self.config, self.root, "Test", results)
        self.assertEqual(summary["result"], "error")
        self.assertIn("secscan-summary", api.render_dashboard(summary))

    def test_clean_project_reporting(self):
        self.file(".secscan.yml", yaml.safe_dump({"policy": {}}))
        with patch("sys.argv", ["secscan", "check", str(self.root)]):
            code = runner.main(api)
        self.assertEqual(code, 0)
        summary = json.loads((self.root / ".security/reports/summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["scanners"]["ai"]["status"], "skipped")
        self.assertTrue((self.root / ".security/dashboard/index.html").is_file())
        self.assertIn("trivy", summary["scanners"])

    def test_failure_isolated_and_workers_bounded(self):
        self.config["policy"]["yara"]["enabled"] = True
        self.config["policy"]["gitleaks"]["enabled"] = True
        self.file(".secscan/yara/invalid.yar", "invalid")
        with patch("secscan.scanners.docker_preflight", return_value=None), patch("secscan.scanners.run_gitleaks", return_value=api.make_result("gitleaks", "pass", 0, [])):
            results, performance, _ = runner.execute(api, self.root, self.config)
        results = {x["name"]: x for x in results}
        self.assertEqual(results["yara"]["status"], "error")
        self.assertEqual(results["gitleaks"]["status"], "pass")
        self.assertEqual(performance["max_workers"], 3)

    def test_report_only_sanitized_ai(self):
        results = [api.make_result(name, "skipped", None, []) for name in runner.SCANNER_ORDER]
        results[-1]["raw"] = {"findings": [{"evidence": "[REDACTED]"}]}
        summary = api.build_summary(self.config, self.root, "Test", results)
        dirs = api.prepare_output_dirs(self.root, ".security")
        runner.persist(api, results, summary, dirs)
        data = (dirs["raw"] / "ai.json").read_text(encoding="utf-8")
        self.assertNotIn("prompt", data)
        self.assertNotIn("api_key", data)

    def test_html_script_injection_escaped(self):
        html = api.render_dashboard({"project": "</script><script>alert(1)</script>"})
        self.assertNotIn("</script><script>alert(1)", html)

    def test_no_repeated_pull(self):
        command = api.docker_command("fixture", [], "example:fixture", ["scan"])
        self.assertEqual(command[command.index("--pull") + 1], "missing")


if __name__ == "__main__":
    unittest.main()
