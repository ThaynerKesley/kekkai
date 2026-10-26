"""Native YARA-X acceptance without malware samples or network by default."""
import hashlib
import io
import json
import os
import tempfile
import unittest
import zipfile
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from secscan import configuration, scanners
from secscan import secscan as engine
from secscan.files import Exclusions
from secscan.yara_library import YaraRuleManager, RuleManagerError, extract_package

RULE = '''rule Kekkai_Test : harmless {
meta:
  author = "Test fixture"
  license = "MIT"
strings:
  $marker = "KEKKAI_HARMLESS_TEST_MARKER"
condition:
  $marker
}
'''


class YaraManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='kekkai-yara-test-')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.manager=YaraRuleManager(self.root/'library')

    def rule(self,text=RULE):
        path=self.root/'custom.yar';path.write_text(text,encoding='utf-8');return path

    def test_custom_detection_metadata_disable_revalidate_and_rollback(self):
        installed=self.manager.import_files([self.rule()])
        self.assertEqual((installed['valid'],installed['active']),(1,1))
        project=self.root/'project';project.mkdir()
        (project/'sample.txt').write_text('KEKKAI_HARMLESS_TEST_MARKER')
        policy=deepcopy(configuration.DEFAULTS['policy']['yara'])
        with patch('secscan.scanners.YaraRuleManager',return_value=self.manager):
            result=scanners.run_yara(engine,project,policy,Exclusions(project,[]))
        self.assertEqual(result['status'],'warn')
        finding=result['findings'][0]
        self.assertEqual(finding['rule'],'Kekkai_Test')
        self.assertEqual(finding['file'],'sample.txt')
        self.assertEqual(finding['tags'],['harmless'])
        self.assertEqual(finding['technical']['metadata']['author'],'Test fixture')
        self.assertNotIn('KEKKAI_HARMLESS_TEST_MARKER',json.dumps(result))
        disabled=self.manager.revalidate(installed['id'],['Kekkai_Test'])
        self.assertEqual(disabled['active'],0)
        self.assertEqual(self.manager.active_sets(),[])
        self.manager.rollback(installed['id'])
        self.assertEqual(len(self.manager.active_sets()),1)
        self.manager.set_enabled(installed['id'],False)
        self.assertEqual(self.manager.active_sets(),[])

    def test_invalid_rule_and_dependants_are_quarantined(self):
        source=RULE+'\nrule Invalid { condition: missing_identifier }\nrule Dependant { condition: Invalid }\n'
        entry=self.manager.import_files([self.rule(source)])
        self.assertEqual(entry['valid'],1)
        self.assertGreaterEqual(entry['invalid'],1)
        self.assertTrue(entry['issues'])
        self.assertEqual([r.identifier for r in self.manager.load(entry)],['Kekkai_Test'])

    def test_failed_validation_and_update_preserve_previous_snapshot(self):
        first=self.manager.import_files([self.rule()])
        with self.assertRaises(RuleManagerError):self.manager.import_files([self.rule('rule Broken { condition: ??? }')])
        with patch('secscan.yara_library.fetch',side_effect=RuleManagerError('Network unavailable')):
            with self.assertRaises(RuleManagerError):self.manager.update()
        self.assertEqual(self.manager.state()['libraries'][0]['id'],first['id'])
        self.assertEqual(len(self.manager.active_sets()),1)
        self.assertTrue(self.manager.state()['last_error'])

    def test_digest_failure_prevents_install(self):
        release={'tag_name':'test','assets':[{'name':'yara-forge-rules-core.zip','digest':'sha256:'+'0'*64,
                  'browser_download_url':'https://github.com/YARAHQ/yara-forge/releases/download/test/yara-forge-rules-core.zip'}]}
        with patch('secscan.yara_library.fetch',side_effect=[json.dumps(release).encode(),b'corrupt archive']):
            with self.assertRaises(RuleManagerError):self.manager.update()
        self.assertEqual(self.manager.state()['libraries'],[])

    def test_source_tamper_and_extra_rules_prevent_activation(self):
        entry=self.manager.import_files([self.rule()])
        folder=self.manager.snapshot_path(entry)
        source=next(folder.glob('*.yar'));source.write_text(RULE+'\n// modified')
        with self.assertRaises(RuleManagerError):self.manager.load(entry)
        source.write_text(RULE)
        (folder/'extra.yar').write_text('rule Injected { condition: true }')
        with self.assertRaises(RuleManagerError):self.manager.load(entry)

    def test_include_is_contained_and_snapshot_covers_include_hash(self):
        (self.root/'helper.inc').write_text('private rule Helper { condition: true }')
        path=self.rule('include "helper.inc"\n'+RULE)
        entry=self.manager.import_files([path])
        self.assertEqual(entry['valid'],2)
        self.assertEqual(entry['active'],1)
        path.write_text('include "../outside.inc"\n'+RULE)
        with self.assertRaises(RuleManagerError):self.manager.import_files([path])

    def test_archive_traversal_is_refused(self):
        archive=self.root/'bad.zip'
        with zipfile.ZipFile(archive,'w') as z:z.writestr('../escape.yar',RULE)
        destination=self.root/'sources';destination.mkdir()
        with self.assertRaises(RuleManagerError):extract_package(archive,destination)
        self.assertFalse((self.root/'escape.yar').exists())

    def test_offline_auto_update_failure_uses_previous_valid_set(self):
        self.manager.import_files([self.rule()]);self.manager.settings(True,'core',1)
        with patch('secscan.yara_library.time.time',return_value=10**12),patch('secscan.yara_library.fetch',side_effect=RuleManagerError('Network unavailable')):
            self.assertEqual(len(self.manager.active_sets(auto_update=True)),1)

    @unittest.skipUnless(os.environ.get('KEKKAI_NETWORK_TESTS')=='1','Official Forge download opt-in')
    def test_official_core_download_validate_and_load_offline(self):
        entry=self.manager.update('core')
        self.assertGreater(entry['valid'],0)
        self.assertGreater(entry['active'],0)
        self.assertRegex(entry['download_sha256'],r'^[a-f0-9]{64}$')
        with patch('secscan.yara_library.fetch',side_effect=AssertionError('Offline load must not fetch')):
            self.assertEqual(len(list(self.manager.load(entry))),entry['valid'])


if __name__=='__main__':unittest.main()
