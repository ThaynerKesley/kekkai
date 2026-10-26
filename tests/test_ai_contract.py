"""Nullable guide fields and safe schema diagnostics; no authenticated API calls."""
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from secscan import ai_review, configuration, runner
from secscan import secscan as api
from secscan.ai_providers import ProviderError
from secscan.files import Exclusions, Sanitizer


class AIContractTests(unittest.TestCase):
    def finding(self):
        return {'title': 'Review ownership', 'severity': 'HIGH', 'confidence': 'HIGH',
                'cwe': None, 'owasp': None, 'file': 'app.py', 'line': None,
                'description': 'Validate the ownership boundary', 'impact': 'Unauthorized access',
                'evidence': 'Source omitted', 'recommendation': 'Enforce ownership'}

    def parse(self, finding):
        return ai_review.parse_response(json.dumps({'findings': [finding]}), {'app.py'}, {'app.py': 3})

    def test_unknown_mapping_and_line_are_preserved_as_null(self):
        finding = self.finding()
        self.assertEqual(self.parse(finding)['findings'][0], finding)
        finding.update(cwe='CWE-862', owasp='A01:2025', line=2)
        self.assertEqual(self.parse(finding)['findings'][0], finding)

    def test_null_does_not_allow_unknown_paths(self):
        finding = self.finding()
        finding['file'] = '../outside.py'
        with self.assertRaisesRegex(ValueError, 'fora do contexto'):
            self.parse(finding)

    def test_known_lines_must_be_real_integers_within_the_file(self):
        for line in (True, '2', 0, -1, 4):
            finding = self.finding()
            finding['line'] = line
            with self.subTest(line=line), self.assertRaises((ProviderError, ValueError)):
                self.parse(finding)

    def test_schema_diagnostic_identifies_field_without_echoing_its_value(self):
        finding = self.finding()
        finding['confidence'] = 'PRIVATE_RESPONSE_MARKER'
        with self.assertRaises(ProviderError) as caught:
            self.parse(finding)
        info = caught.exception.diagnostic
        self.assertIn('findings[0].confidence', info['summary'])
        self.assertEqual(info['technical_details']['validation_issues'][0]['constraint'], 'enum')
        self.assertNotIn('PRIVATE_RESPONSE_MARKER', json.dumps(info))

    def test_required_and_extra_fields_remain_errors_with_safe_diagnostics(self):
        finding = self.finding()
        del finding['title']
        with self.assertRaises(ProviderError) as caught:
            self.parse(finding)
        issue = caught.exception.diagnostic['technical_details']['validation_issues'][0]
        self.assertEqual(issue['missing_fields'], ['title'])
        finding = self.finding()
        finding['PRIVATE_KEY_MARKER'] = 'PRIVATE_RESPONSE_MARKER'
        with self.assertRaises(ProviderError) as caught:
            self.parse(finding)
        info = json.dumps(caught.exception.diagnostic)
        self.assertNotIn('PRIVATE_KEY_MARKER', info)
        self.assertNotIn('PRIVATE_RESPONSE_MARKER', info)

    def test_diagnostics_are_bounded_and_wrong_shapes_are_rejected(self):
        finding = self.finding()
        for key in ('title', 'description', 'impact', 'recommendation', 'evidence', 'file'):
            finding[key] = 100
        with self.assertRaises(ProviderError) as caught:
            self.parse(finding)
        self.assertEqual(len(caught.exception.diagnostic['technical_details']['validation_issues']), 5)
        for value in ([], {'findings': None}, {'findings': [{}]}):
            with self.subTest(value=value), self.assertRaises(ProviderError):
                ai_review.parse_response(json.dumps(value), set(), {})

    def test_deepseek_review_nullable_fields_reaches_sanitized_reports(self):
        options = deepcopy(configuration.DEFAULTS['ai'])
        options.update(provider='deepseek', model='deepseek-v4-pro', guide={'mode': 'custom', 'path': 'guide.md'})
        options['providers']['deepseek']['enabled'] = True
        class Interaction:
            def configure(self, settings):
                return 'deepseek', 'deepseek-v4-pro', settings
            def authorize(self, *args):
                return True
            def read_key(self):
                return 'UNIT_TEST_CREDENTIAL'
        response = {'choices': [{'finish_reason': 'stop', 'message': {'content': json.dumps({'findings': [self.finding()]})}}]}
        with tempfile.TemporaryDirectory(prefix='kekkai-ai-contract-') as folder:
            root = Path(folder)
            (root/'app.py').write_text("print('PRIVATE_SOURCE_MARKER')\n", encoding='utf-8')
            (root/'guide.md').write_text('Use null for unknown cwe, owasp and line. Return JSON.', encoding='utf-8')
            with patch('secscan.ai_providers.post_json', return_value=response) as post:
                result = ai_review.run_ai(api, root, options, Exclusions(root, []), api.make_result('gitleaks', 'pass', 0, []),
                                          Sanitizer(), True, 'full', interaction=Interaction())
            self.assertEqual(result['status'], 'warn')
            self.assertIsNone(result['findings'][0]['location']['line'])
            self.assertIsNone(result['findings'][0]['technical']['cwe'])
            self.assertIsNone(result['findings'][0]['technical']['owasp'])
            body = post.call_args.args[2]
            self.assertEqual(body['response_format'], {'type': 'json_object'})
            self.assertEqual(body['messages'][0]['content'].count('null') > 0, True)
            results = [api.make_result(name, 'skipped', None, []) for name in api.SCANNER_ORDER]
            results[-1] = result
            summary = api.build_summary(configuration.DEFAULTS, root, 'fixture', results)
            dirs = api.prepare_output_dirs(root, '.security')
            runner.persist(api, results, summary, dirs)
            api.generate_dashboard(summary, dirs['dashboard']/'index.html')
            for path in (root/'.security').rglob('*'):
                if path.is_file():
                    text = path.read_text(encoding='utf-8')
                    self.assertNotIn('UNIT_TEST_CREDENTIAL', text)
                    self.assertNotIn("print('PRIVATE_SOURCE_MARKER')", text)


if __name__ == '__main__':
    unittest.main()
