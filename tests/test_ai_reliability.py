"""Bounded retries, partial progress and estimates with mocked provider traffic."""
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from secscan import ai_review, configuration
from secscan import secscan as engine
from secscan.ai_cost import estimate_cost, estimate_plan
from secscan.ai_providers import DeepSeekProvider, ProviderError
from secscan.files import Exclusions, Sanitizer


class Interaction:
    def configure(self,options):return 'deepseek','deepseek-v4-pro',options
    def authorize(self,provider,selection,files):
        self.selection=selection;self.files=files;return True
    def read_key(self):return 'UNIT_TEST_CREDENTIAL'


def response(reason='stop',content=None):
    return {'choices':[{'finish_reason':reason,'message':{'content':content or '{"findings":[]}'}}],
            'usage':{'prompt_tokens':100,'completion_tokens':20,'prompt_cache_hit_tokens':10,
                     'completion_tokens_details':{'reasoning_tokens':5}}}


class AIReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='kekkai-ai-retry-test-')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        for directory in ('one','two'):
            (self.root/directory).mkdir();(self.root/directory/'app.py').write_text('print(1)')
        (self.root/'guide.md').write_text('Review the source and return findings JSON.')
        self.options=deepcopy(configuration.DEFAULTS['ai'])
        self.options.update(provider='deepseek',model='deepseek-v4-pro',guide={'mode':'custom','path':'guide.md'})
        self.options['providers']['deepseek']['enabled']=True

    def run_review(self,responses):
        interaction=Interaction();events=[]
        with patch('secscan.ai_providers.post_json',side_effect=responses) as post,patch('secscan.ai_review.time.sleep'):
            result=ai_review.run_ai(engine,self.root,self.options,Exclusions(self.root,[]),engine.make_result('gitleaks','pass',0,[]),
                                   Sanitizer(),True,'full',interaction=interaction,on_event=events.append)
        return result,post,events,interaction

    def test_truncation_retries_with_larger_budget_and_continues_all_groups(self):
        result,post,events,interaction=self.run_review([response('length'),response(),response()])
        self.assertEqual(result['status'],'pass')
        self.assertEqual(result['details']['groups_completed'],2)
        self.assertEqual(result['details']['usage']['requests'],3)
        self.assertEqual(result['details']['usage']['input_tokens'],300)
        self.assertEqual(result['details']['usage']['reasoning_tokens'],15)
        bodies=[call.args[2] for call in post.call_args_list]
        self.assertGreater(bodies[1]['max_tokens'],bodies[0]['max_tokens'])
        self.assertTrue(all(len(b['messages'])==2 for b in bodies))
        self.assertEqual(bodies[0]['messages'][1],bodies[1]['messages'][1])
        self.assertNotEqual(bodies[1]['messages'][1],bodies[2]['messages'][1])
        self.assertEqual([(e['group'],e['attempt']) for e in events],[(1,1),(1,2),(2,1)])
        self.assertEqual(interaction.selection['guide']['path'],str((self.root/'guide.md').resolve()))
        self.assertEqual(result['details']['cost']['currency'],'USD')

    def test_exhausted_group_does_not_stop_later_groups(self):
        result,post,_,_=self.run_review([response('length'),response('length'),response()])
        self.assertEqual(result['status'],'error')
        self.assertEqual(post.call_count,3)
        self.assertEqual(result['details']['groups_completed'],1)
        self.assertEqual(result['details']['groups_total'],2)
        self.assertTrue(result['details']['partial'])
        self.assertEqual(result['details']['usage']['output_tokens'],60)
        self.assertEqual(len(result['details']['group_errors']),1)

    def test_schema_failure_is_retried(self):
        result,post,_,_=self.run_review([response(content='{"findings":null}'),response(),response()])
        self.assertEqual(result['status'],'pass');self.assertEqual(post.call_count,3)

    def test_malformed_provider_shapes_raise_safe_recoverable_error(self):
        for value in ({'choices':[None]},{'choices':'invalid'},{'choices':[{'message':None}]},{'choices':[],'usage':[]},{'choices':[{'finish_reason':{}}]}):
            with self.subTest(value=value),self.assertRaises(ProviderError) as caught:DeepSeekProvider().parse_response(value)
            self.assertTrue(caught.exception.diagnostic['recoverable'])

    def test_estimates_respect_cache_manual_rates_and_retry_output_budget(self):
        cost=estimate_cost('deepseek','deepseek-v4-pro',{'input_tokens':1000000,'output_tokens':1000000,'cached_input_tokens':500000})
        self.assertAlmostEqual(cost['minimum'],.33+.011+1.98)
        self.assertEqual(cost['maximum'],2*cost['minimum'])
        self.assertEqual(estimate_cost('custom','test',{'input_tokens':1000000}, {'input_per_million':2,'output_per_million':3})['minimum'],2)
        plan=estimate_plan('deepseek','deepseek-v4-pro',[('text',{'file.py'})],'guide',{},self.options)
        self.assertEqual(plan['max_requests'],2)
        self.assertEqual(plan['output_token_budget'],8192+32768)


if __name__=='__main__':unittest.main()
