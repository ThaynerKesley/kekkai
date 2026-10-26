"""Regression coverage for scanner classifications and safe provider diagnostics."""
import io
import json
import tempfile
import threading
import unittest
import urllib.error
from copy import deepcopy
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from secscan import configuration, scanners, runner, ai_review
from secscan import secscan as api
from secscan.files import Exclusions
from secscan.ai_providers import DeepSeekProvider, QwenProvider, ProviderError, post_json, capabilities
from secscan.web_target import test_target, is_web_project


class ScannerDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='kekkai-diagnostics-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = deepcopy(configuration.DEFAULTS)
        self.config['policy']['yara']['use_managed']=False
        self.exclusions = Exclusions(self.root, [])

    def semgrep(self, errors=None, code=0, findings=False, owasp=False, stderr=''):
        results = [{'check_id':'test.rule','path':'/src/valid.py','start':{'line':1},'extra':{'severity':'ERROR','message':'fixture',
                    'lines':'PRIVATE_SOURCE_FIXTURE','metadata':{'owasp':'A03:2021 - Injection'}}}] if findings else []
        data = {'results':results,'errors':errors or [],'paths':{'scanned':['/src/valid.py','/src/broken.py']},'version':'fixture'}
        outcome = {'exit_code':code,'error':None,'infrastructure':False,'stdout':json.dumps(data),'stderr':stderr}
        selection = ({'rules':[]},{'edition':'2021','categories':[]})
        with patch('secscan.scanners.scan_command',return_value=outcome), patch('secscan.scanners.urllib.request.urlopen') as get, patch('secscan.scanners.select_owasp_rules',return_value=selection):
            get.return_value.__enter__.return_value.read.return_value=b'rules: []'
            return scanners.run_semgrep(api,self.root,self.config['policy']['owasp' if owasp else 'semgrep'],self.exclusions,owasp)

    def partial(self):
        return [{'code':3,'level':'warn','type':'PartialParsing','path':'/src/broken.py','message':'PRIVATE_SOURCE_FIXTURE'}]

    def test_semgrep_normal_exit(self):
        self.assertEqual(self.semgrep()['status'],'pass')

    def test_semgrep_findings_exit_one(self):
        self.assertEqual(self.semgrep(code=1,findings=True)['status'],'fail')

    def test_semgrep_partial_warning(self):
        result=self.semgrep(self.partial())
        self.assertEqual(result['status'],'warn')
        self.assertEqual(result['diagnostic']['error_type'],'parse_error')
        self.assertNotIn('PRIVATE_SOURCE_FIXTURE',json.dumps(result))

    def test_semgrep_partial_retains_blocking_findings(self):
        result=self.semgrep(self.partial(),code=3,findings=True)
        self.assertEqual(result['status'],'fail')
        self.assertEqual(result['total_findings'],1)
        self.assertTrue(result['details']['partial'])

    def test_semgrep_fatal_preserves_partial_findings(self):
        result=self.semgrep([{'level':'error','type':'FatalError','code':2}],code=2,findings=True)
        self.assertEqual(result['status'],'error')
        self.assertEqual(result['total_findings'],1)

    def test_semgrep_network_ruleset_failure(self):
        result=self.semgrep(code=7,stderr='ConnectionError: semgrep registry inaccessible')
        self.assertEqual(result['diagnostic']['error_type'],'network_error')
        self.assertEqual(self.semgrep(code=5)['diagnostic']['error_type'],'ruleset_error')
        malformed=self.semgrep([{'type':'PatternParseError','level':'warn','code':4}])
        self.assertEqual(malformed['status'],'error')
        self.assertEqual(malformed['diagnostic']['error_type'],'ruleset_error')

    def test_semgrep_invalid_or_all_failed_is_error(self):
        self.assertEqual(self.semgrep(code=3)['status'],'error')
        errors=[{'type':'ParseError','level':'warn','code':3,'path':'/src/'+name} for name in ('valid.py','broken.py')]
        self.assertEqual(self.semgrep(errors)['status'],'error')

    def test_semgrep_terminated_and_truncated(self):
        self.assertEqual(self.semgrep(code=137)['status'],'error')
        outcome={'exit_code':0,'error':None,'infrastructure':False,'stdout':'{"results":','stderr':''}
        with patch('secscan.scanners.scan_command',return_value=outcome):
            self.assertEqual(scanners.run_semgrep(api,self.root,self.config['policy']['semgrep'],self.exclusions)['status'],'error')

    def test_owasp_valid(self):
        self.assertEqual(self.semgrep(owasp=True)['status'],'pass')

    def test_owasp_registry_failure(self):
        with patch('secscan.scanners.urllib.request.urlopen',side_effect=urllib.error.URLError('PRIVATE_SOURCE_FIXTURE')):
            result=scanners.run_semgrep(api,self.root,self.config['policy']['owasp'],self.exclusions,True)
        self.assertEqual(result['diagnostic']['error_type'],'network_error')
        self.assertNotIn('PRIVATE_SOURCE_FIXTURE',json.dumps(result))

    def test_owasp_findings(self):
        self.assertEqual(self.semgrep(findings=True,owasp=True)['status'],'fail')

    def test_owasp_partial_survives_dedup(self):
        result=self.semgrep(self.partial(),owasp=True)
        results=[api.make_result(n,'skipped',None,[]) for n in api.SCANNER_ORDER]
        results[api.SCANNER_ORDER.index('owasp')]=result
        self.assertEqual(scanners.deduplicate(results,api)[4]['status'],'warn')

    def test_yara_no_rules(self):
        self.assertEqual(scanners.run_yara(api,self.root,self.config['policy']['yara'],self.exclusions)['status'],'skipped')
        self.config['policy']['yara']['rules']=['.secscan/yara/']
        self.assertEqual(scanners.run_yara(api,self.root,self.config['policy']['yara'],self.exclusions)['status'],'skipped')

    def test_yara_valid_rule(self):
        (self.root/'rule.yar').write_text('rule fixture { condition: true }')
        (self.root/'sample.txt').write_text('fixture')
        self.config['policy']['yara']['rules']=['rule.yar']
        result=scanners.run_yara(api,self.root,self.config['policy']['yara'],self.exclusions)
        self.assertEqual(result['status'],'warn')
        self.assertEqual(result['total_findings'],1)

    def test_yara_invalid_rule_location(self):
        (self.root/'broken.yar').write_text('rule fixture { condition: }')
        self.config['policy']['yara']['rules']=['broken.yar']
        result=scanners.run_yara(api,self.root,self.config['policy']['yara'],self.exclusions)
        self.assertEqual(result['status'],'error')
        self.assertEqual(result['diagnostic']['technical_details']['line'],1)
        self.assertIn('E001',result['diagnostic']['technical_details']['compiler_error'])
        self.assertNotIn('condition:',json.dumps(result))

    def test_zap_non_web_without_container(self):
        with patch.object(api,'run_docker') as docker:
            result=runner.run_zap(api,self.config['policy']['zap'],web=False)
        self.assertEqual(result['status'],'skipped');docker.assert_not_called()

    def test_zap_offline_without_container(self):
        with patch('secscan.runner.test_target',return_value={'reachable':False,'diagnostic':{'error_type':'target_unreachable','summary':'offline'}}),patch.object(api,'run_docker') as docker:
            result=runner.run_zap(api,{'target':'http://localhost:4173','mode':'baseline','fail_on':[]})
        self.assertEqual(result['status'],'skipped');docker.assert_not_called()

    def test_zap_online_windows_translation(self):
        outcome={'exit_code':0,'error':None,'stdout':json.dumps({'site':[{'alerts':[]}]}),'stderr':'','infrastructure':False}
        with patch('secscan.runner.probe_zap_container',return_value={'reachable':True}),patch('secscan.runner.os.name','nt'),patch.object(api,'run_docker',return_value=outcome) as docker:
            result=runner.run_zap(api,{'target':'http://localhost:4173','mode':'baseline','fail_on':[]},preflight={'reachable':True})
        self.assertEqual(result['status'],'pass')
        self.assertEqual(docker.call_args.args[0][-1],'http://host.docker.internal:4173')

    def test_zap_container_failure_is_error(self):
        outcome={'exit_code':3,'error':None,'stdout':'{}','stderr':'','infrastructure':False}
        with patch('secscan.runner.probe_zap_container',return_value={'reachable':True}),patch.object(api,'run_docker',return_value=outcome):
            result=runner.run_zap(api,{'target':'http://localhost:4173','mode':'baseline','fail_on':[]},preflight={'reachable':True})
        self.assertEqual(result['status'],'error')

    def test_target_http_errors_are_reachable(self):
        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self): self.send_response(403);self.end_headers()
            def log_message(self,*args): pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        result=test_target(f'http://localhost:{server.server_port}')
        self.assertTrue(result['reachable']);self.assertEqual(result['http_status'],403)

    def test_project_compatibility_and_invalid_target(self):
        self.config['policy']['zap'].update(enabled=True,target='http://localhost:4173')
        self.assertTrue(is_web_project(self.config))
        self.config['project']['web']=False
        self.assertFalse(is_web_project(self.config))
        for target in ('http://remote.invalid','http://localhost:999999','http://user:password@localhost','http://localhost?token=x'):
            self.assertEqual(test_target(target)['diagnostic']['error_type'],'configuration_error')


class ProviderDiagnosticsTests(unittest.TestCase):
    def response(self,text='{"findings":[]}'):
        return {'choices':[{'finish_reason':'stop','message':{'content':text}}]}

    def scan(self,adapter,model):
        return adapter.scan(key='UNIT_TEST_CREDENTIAL',model=model,guide='Return JSON',bundle='PRIVATE_SOURCE_FIXTURE',schema=ai_review.SCHEMA,timeout=1,max_output_tokens=8192)

    def test_deepseek_payload_capabilities(self):
        with patch('secscan.ai_providers.post_json',return_value=self.response()) as post:
            self.scan(DeepSeekProvider(),'deepseek-flash')
        body=post.call_args.args[2]
        self.assertEqual(body['response_format'],{'type':'json_object'})
        self.assertNotIn('text',body);self.assertNotIn('enable_thinking',body)
        self.assertTrue(post.call_args.args[0].endswith('/chat/completions'))

    def test_deepseek_version_name_maps_to_official_api_id(self):
        with patch('secscan.ai_providers.post_json',return_value=self.response()) as post:
            self.scan(DeepSeekProvider(),'DeepSeek-V4-Pro-0813')
        self.assertEqual(post.call_args.args[2]['model'],'deepseek-v4-pro')
        self.assertEqual(post.call_args.args[2]['response_format'],{'type':'json_object'})

    def test_qwen_native_schema(self):
        with patch('secscan.ai_providers.post_json',return_value=self.response()) as post:self.scan(QwenProvider(),'qwen3.8-max')
        self.assertEqual(post.call_args.args[2]['response_format']['type'],'json_schema')

    def test_qwen_without_native_schema(self):
        for model in ('qwen-plus','qwen2.5-coder-32b-instruct','custom-model'):
            with self.subTest(model=model),patch('secscan.ai_providers.post_json',return_value=self.response()) as post:
                text,_=self.scan(QwenProvider(),model)
                self.assertEqual(ai_review.parse_response(text,set(),{})['findings'],[])
                self.assertNotEqual(post.call_args.args[2].get('response_format',{}).get('type'),'json_schema')
                if model!='qwen-plus':self.assertNotIn('response_format',post.call_args.args[2])

    def http_error(self,status,message,code='InvalidParameter'):
        error=urllib.error.HTTPError('https://api.deepseek.com/chat/completions',status,'rejected',{},io.BytesIO(json.dumps({'error':{'code':code,'message':message}}).encode()))
        with patch('secscan.ai_providers.urllib.request.build_opener') as opener:
            opener.return_value.open.side_effect=error
            with self.assertRaises(ProviderError) as caught:
                post_json('https://api.deepseek.com/chat/completions',{'Authorization':'Bearer UNIT_TEST_CREDENTIAL'},{'model':'deepseek-flash'},1)
        return caught.exception

    def test_deepseek_http_400_is_safe_and_specific(self):
        error=self.http_error(400,'unsupported response_format PRIVATE_SOURCE_FIXTURE UNIT_TEST_CREDENTIAL')
        self.assertEqual(error.diagnostic['error_type'],'unsupported_feature')
        self.assertIn('HTTP 400',str(error))
        self.assertNotIn('PRIVATE_SOURCE_FIXTURE',json.dumps(error.diagnostic));self.assertNotIn('UNIT_TEST_CREDENTIAL',str(error))

    def test_authentication_error(self):
        self.assertEqual(self.http_error(401,'Invalid API key').diagnostic['error_type'],'authentication_error')

    def test_endpoint_error(self):
        self.assertEqual(self.http_error(404,'not found').diagnostic['error_type'],'network_error')

    def test_model_and_workspace_error(self):
        self.assertIn('Modelo indisponível',str(self.http_error(400,'ModelNotFound')))
        self.assertIn('Workspace',str(self.http_error(400,'Invalid workspace id')))

    def test_qwen_workspace_endpoint(self):
        base='https://fixture-workspace.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1'
        self.assertEqual(QwenProvider(base).base_url,base)
        for url in ('https://fixture.evil.aliyuncs.com/compatible-mode/v1',base+'?token=x',base.replace('https','http')):
            with self.assertRaises(ProviderError):QwenProvider(url)

    def test_malformed_json_response(self):
        with self.assertRaises(ValueError):ai_review.parse_response('not JSON',set(),{})

    def test_schema_validation_failure(self):
        with self.assertRaises(ProviderError):ai_review.parse_response('{"unexpected":[]}',set(),{})

    def test_thinking_model_rejected_before_request(self):
        with patch('secscan.ai_providers.post_json') as post,self.assertRaises(ProviderError):self.scan(QwenProvider(),'qwen3-235b-a22b-thinking-2507')
        post.assert_not_called()

    def test_connection_never_sends_source(self):
        with patch('secscan.ai_providers.post_json',return_value=self.response('{"ok":true}')) as post:
            result=DeepSeekProvider().test_connection('UNIT_TEST_CREDENTIAL','deepseek-flash')
        self.assertTrue(result['connected'])
        body=post.call_args.args[2]
        self.assertNotIn('PRIVATE_SOURCE_FIXTURE',json.dumps(body))
        self.assertEqual(body['max_tokens'],128)
        self.assertEqual(body['thinking'],{'type':'disabled'})

    def test_connection_rejects_invalid_schema(self):
        with patch('secscan.ai_providers.post_json',return_value=self.response('{"wrong":true}')),self.assertRaises(ProviderError):
            QwenProvider().test_connection('UNIT_TEST_CREDENTIAL','qwen-plus')


if __name__=='__main__':unittest.main()
