"""Publication regressions: confined writes, complete AI consent, localization."""
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from kekkai import ai_review, configuration
from kekkai import engine as engine
from kekkai.core.service import run_scan
from kekkai.core.storage import Preferences, ReportStore, save_project_config
from kekkai.dashboard import render
from kekkai.files import Exclusions, atomic_write_text, Sanitizer
from kekkai.i18n import get_language, set_language, tr


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='kekkai-publication-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.addCleanup(set_language, get_language())
        set_language('pt_BR')

    def link(self, path, destination, directory=False):
        try:
            path.symlink_to(destination, target_is_directory=directory)
        except OSError:
            self.skipTest('Filesystem does not allow test symlinks')

    def test_output_file_link_cannot_overwrite_external_file(self):
        victim=self.root/'private.txt';victim.write_text('KEEP')
        project=self.root/'project';project.mkdir()
        dirs=engine.prepare_output_dirs(project,'.security')
        self.link(dirs['reports']/'summary.json',victim)
        with self.assertRaises(OSError):run_scan(project,deepcopy(configuration.DEFAULTS))
        self.assertEqual(victim.read_text(),'KEEP')

    def test_output_ancestor_link_is_rejected_before_directory_creation(self):
        victim=self.root/'external';victim.mkdir()
        project=self.root/'project';project.mkdir()
        self.link(project/'.security',victim,True)
        with self.assertRaises(OSError):engine.prepare_output_dirs(project,'.security')
        self.assertEqual(list(victim.iterdir()),[])

    def test_settings_do_not_follow_preseeded_temporary_or_destination_links(self):
        victim=self.root/'private.txt';victim.write_text('KEEP')
        project=self.root/'project';project.mkdir()
        self.link(project/'.kekkai.yml.tmp',victim)
        save_project_config(project,deepcopy(configuration.DEFAULTS))
        self.assertEqual(victim.read_text(),'KEEP')
        (project/'.kekkai.yml').unlink()
        self.link(project/'.kekkai.yml',victim)
        with self.assertRaises(OSError):save_project_config(project,deepcopy(configuration.DEFAULTS))
        self.assertEqual(victim.read_text(),'KEEP')

    def test_atomic_writer_replaces_hardlink_without_mutating_original(self):
        import os
        original=self.root/'original.txt';original.write_text('KEEP')
        destination=self.root/'output.txt'
        os.link(original,destination)
        atomic_write_text(destination,'NEW')
        self.assertEqual(original.read_text(),'KEEP')
        self.assertEqual(destination.read_text(),'NEW')

    def test_repository_guide_cannot_silently_read_outside_or_excluded_files(self):
        project=self.root/'project';project.mkdir()
        guide=self.root/'private-notes.md';guide.write_text('Private prose without credential markers.')
        options=deepcopy(configuration.DEFAULTS['ai']);options['guide']={'mode':'custom','path':'../private-notes.md'}
        with self.assertRaises(ValueError):ai_review.load_guide(project,options)
        self.assertEqual(ai_review.load_guide(project,options,authorized_path=str(guide)),guide.read_text())
        local=project/'notes.md';local.write_text('Local notes.')
        options['guide']['path']='notes.md'
        with self.assertRaises(ValueError):ai_review.load_guide(project,options,exclusions=Exclusions(project,['notes.md']))
        with self.assertRaises(ValueError):ai_review.load_guide(project,options,authorized_path=str(local),protected={'notes.md'})

    def test_language_preference_roundtrip_and_stable_machine_codes(self):
        prefs=Preferences(self.root/'prefs.json');prefs.data['language']='en';prefs.save()
        self.assertEqual(Preferences(prefs.path).data['language'],'en')
        set_language('en')
        self.assertEqual(tr('Visão geral'),'Overview')
        summary=run_scan(self.root,deepcopy(configuration.DEFAULTS))['summary']
        self.assertEqual(summary['result'],'approved')
        self.assertEqual(engine.RESULT_LABELS['approved'],'APPROVED')
        self.assertEqual(summary['message'],'No issue configured as blocking was identified.')
        self.assertEqual(engine.STATUS_LABELS['fail'],'COMPLETED WITH ERROR')

    def test_english_renderer_does_not_translate_or_execute_user_data(self):
        project='Visão geral </script><script>alert(1)</script>'
        html=render({'project':project,'findings':[]},language='en')
        self.assertIn('lang="en"',html)
        self.assertIn('Overview</a>',html)
        self.assertIn('What is blocking publication?',html)
        payload=html.split('id="kekkai-summary">',1)[1].split('</script>',1)[0]
        self.assertEqual(json.loads(payload)['project'],project)
        self.assertNotIn('</script>',payload)
        self.assertIn('Visão geral',payload)

    def test_report_delete_preserves_other_runs_source_and_cache(self):
        project=self.root/'project';project.mkdir();(project/'source.py').write_text('SOURCE')
        config=deepcopy(configuration.DEFAULTS)
        result=run_scan(project,config);dirs={k:Path(v) for k,v in result['dirs'].items()}
        store=ReportStore(dirs['root']);snapshot=store.archive(result['summary'],dirs['reports'],dirs['dashboard']/'index.html')
        cache=dirs['root']/'cache';cache.mkdir();(cache/'keep').write_text('KEEP')
        store.delete(dirs['reports']/'summary.json')
        self.assertTrue((snapshot/'summary.json').is_file())
        self.assertTrue((cache/'keep').is_file())
        self.assertTrue((project/'source.py').is_file())
        store.delete(snapshot/'summary.json')
        self.assertEqual(store.list_reports(),[])
        with self.assertRaises(ValueError):store.delete(project/'source.py')

    def test_binary_metadata_is_never_serialized_as_content(self):
        value=Sanitizer().clean({'metadata':{'description':b'PRIVATE_BYTES'}})
        self.assertNotIn('PRIVATE_BYTES',json.dumps(value))


if __name__=='__main__':unittest.main()
