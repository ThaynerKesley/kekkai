"""Local, versioned YARA-X library backed by authenticated official release metadata.

Downloads are staged, hashed and compiled in a bounded child process before an
atomic pointer change. Invalid rules are quarantined by YARA-X, never activated.
"""
from .i18n import tr
import hashlib
import io
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import zipfile
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from uuid import uuid4

from .core.storage import user_data_dir
from .files import is_link, Sanitizer, atomic_write_text

RELEASE_API = 'https://api.github.com/repos/YARAHQ/yara-forge/releases/latest'
TIERS = ('core','extended','full')
MAX_DOWNLOAD = 32*1024*1024
MAX_SOURCE = 64*1024*1024
_LOCK = threading.RLock()
_WINDOWS_JOB = None
_COMPILED_CACHE = OrderedDict()


class RuleManagerError(RuntimeError):
    pass


def engine_status():
    try:
        import yara_x
        version=importlib.metadata.version('yara-x')
        supported=hasattr(yara_x.Compiler,'ignore_invalid_rules')
        return {'available':True,'version':version,'compatible':supported}
    except ImportError:
        return {'available':False,'version':None,'compatible':False}


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def atomic_json(path, data):
    atomic_write_text(path,json.dumps(data,ensure_ascii=False,indent=2))


def fetch(url, limit):
    req=urllib.request.Request(url,headers={'User-Agent':'Kekkai-YARA-Rule-Manager','Accept':'application/vnd.github+json'})
    try:
        with urllib.request.urlopen(req,timeout=30) as response:
            data=response.read(limit+1)
        if len(data)>limit:
            raise RuleManagerError('Download excede o limite permitido.')
        return data
    except (OSError, ValueError):
        raise RuleManagerError(tr('Não foi possível acessar as releases oficiais. A versão local continua disponível.')) from None


def extract_package(archive, destination):
    total=0
    with zipfile.ZipFile(archive) as bundle:
        if len(bundle.infolist())>10000:
            raise RuleManagerError('Pacote contém arquivos demais.')
        for item in bundle.infolist():
            path=PurePosixPath(item.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in item.filename or ':' in item.filename or ((item.external_attr>>16)&0o170000)==0o120000:
                raise RuleManagerError('Pacote contém path ou link não permitido.')
            total+=item.file_size
            if total>MAX_SOURCE:
                raise RuleManagerError('Pacote descompactado excede 64 MB.')
            if item.is_dir():
                continue
            if path.suffix.lower() not in {'.yar','.yara','.inc'}:
                continue
            target=destination/Path(*path.parts)
            target.parent.mkdir(parents=True,exist_ok=True)
            with bundle.open(item) as source,target.open('wb') as output:
                shutil.copyfileobj(source,output,length=64*1024)


def expand_includes(path, root, chain=()):
    path=path.resolve()
    if not path.is_relative_to(root.resolve()) or is_link(path) or not path.is_file() or len(chain)>16 or path in chain:
        raise RuleManagerError('Include ausente, cíclico ou fora do pacote.')
    if path.stat().st_size>MAX_SOURCE:
        raise RuleManagerError('Arquivo de regras excede o limite.')
    source=path.read_text(encoding='utf-8-sig')
    def replace(match):
        included=PurePosixPath(match[1])
        if included.is_absolute() or '..' in included.parts or '\\' in match[1] or ':' in match[1]:
            raise RuleManagerError('Include fora do pacote não permitido.')
        return expand_includes(path.parent/Path(*included.parts),root,(*chain,path))
    source=re.sub(r'^\s*include\s+"([^"\n]+)"\s*$',replace,source,flags=re.M)
    if len(source.encode('utf-8'))>MAX_SOURCE:
        raise RuleManagerError('Includes excedem o limite de 64 MB.')
    return source


def compile_sources(directory, disabled=()):
    import yara_x
    if not hasattr(yara_x.Compiler,'ignore_invalid_rules'):
        raise RuleManagerError('Gerenciador requer YARA-X 1.21+. Atualize requirements.txt.')
    compiler=yara_x.Compiler()
    compiler.enable_includes(False)
    compiler.ignore_invalid_rules(True)
    compiler.max_warnings(100)
    compiler.ignore_module('console')  # Rules must never print inspected file content.
    for module in ('cuckoo','magic'):
        try:
            probe=yara_x.Compiler();probe.enable_includes(False);probe.add_source(f'import "{module}" rule probe {{ condition: true }}')
        except yara_x.CompileError:
            compiler.ignore_module(module)
    issues=[]
    private_rules=set()
    source_hashes={}
    for path in sorted(directory.rglob('*')):
        if path.suffix.lower() not in {'.yar','.yara','.inc'} or not path.is_file():
            continue
        relative=path.relative_to(directory).as_posix()
        source_hashes[relative]=digest(path)
        if path.suffix.lower()=='.inc':
            continue
        namespace=hashlib.sha256(relative.encode()).hexdigest()[:16]
        compiler.new_namespace(namespace)
        try:
            source=expand_includes(path,directory)
            # Native rule disabling preserves dependencies by compiling private support rules.
            for identifier in disabled:
                if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',identifier):
                    source=re.sub(r'(?m)^(\s*)(?!private\b)((?:global\s+)?rule\s+'+re.escape(identifier)+r'\b)',r'\1private \2',source)
            private_rules.update((namespace,match) for match in re.findall(r'(?m)^\s*(?:global\s+)?private\s+(?:global\s+)?rule\s+([A-Za-z_][A-Za-z0-9_]*)',source))
            compiler.add_source(source,origin=relative)
        except (yara_x.CompileError,RuleManagerError,UnicodeError,OSError):
            issues.append({'file':relative,'rule':None,'reason':tr('Arquivo/include não compilável; fonte omitida.')})
    errors=compiler.errors()
    for item in compiler.ignored_rules():
        issues.append({'rule':item.name,'reason':str(item.reason).split('.')[-1]})
    for error in errors[:1000]:
        issues.append({'rule':None,'reason':error.get('type','CompileError'),'code':error.get('code')})
    rules=compiler.build()
    entries=[]
    for rule in rules:
        metadata=Sanitizer().clean(dict(rule.metadata))
        entries.append({'name':rule.identifier,'namespace':rule.namespace,'tags':list(rule.tags),
                        'author':metadata.get('author') or metadata.get('authors') or tr('Não informado'),
                        'license':metadata.get('license') or metadata.get('license_url') or tr('Não informada'),'origin':metadata.get('source_url') or metadata.get('source') or metadata.get('reference') or tr('Pacote/importação'),
                        'metadata':metadata,'active':(rule.namespace,rule.identifier) not in private_rules and rule.identifier not in disabled})
    if not entries:
        raise RuleManagerError(tr('Nenhuma regra válida encontrada; conjunto anterior preservado.'))
    invalid=sum(1 for item in issues if item.get('rule'))
    details = {'rules':entries,'valid':len(entries),'invalid':invalid+sum(item.get('file') is not None for item in issues),
            'active':sum(item['active'] for item in entries),'issues':issues[:2000],
            'source_hashes':source_hashes,'cache_format':'validated-source-v1','engine_version':engine_status()['version']}
    return rules, details


def compile_snapshot(directory, disabled=()):
    # Canonical source remains inspectable by the OS and antivirus. Native binary
    # caches may be quarantined because their signature strings resemble malware.
    # Persist validated sources and metadata; compile once per process on use.
    _, details = compile_sources(directory, disabled)
    return details


def validate_child(directory, disabled=()):
    result_path=directory/'validation.json'
    disabled_path=directory/'disabled.json'
    atomic_json(disabled_path,list(disabled))
    command=[sys.executable,'-m','secscan.yara_library','validate',str(directory)]
    try:
        completed=subprocess.run(command,capture_output=True,timeout=120,
                                 creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0),cwd=Path(__file__).resolve().parent.parent)
    except (OSError,subprocess.TimeoutExpired):
        raise RuleManagerError('Validação YARA excedeu limites ou não iniciou. Conjunto anterior preservado.') from None
    if completed.returncode or not result_path.is_file():
        raise RuleManagerError('Pacote não pôde ser validado com YARA-X; conjunto anterior preservado.')
    return json.loads(result_path.read_text(encoding='utf-8'))


class YaraRuleManager:
    def __init__(self, root=None):
        self.root=(Path(root) if root else user_data_dir()/'yara-library').resolve()
        self.root.mkdir(parents=True,exist_ok=True)
        self.manifest=self.root/'manifest.json'

    def state(self):
        if not self.manifest.is_file():
            return {'libraries':[],'snapshots':[],'auto_update':False,'update_hours':168,'tier':'core','checked_at':0,'last_error':None}
        value=json.loads(self.manifest.read_text(encoding='utf-8'))
        if not isinstance(value,dict) or not isinstance(value.get('libraries'),list):
            raise RuleManagerError('Manifesto local de regras inválido.')
        return value

    def settings(self,auto_update,tier,hours=168):
        if tier not in TIERS or not 1<=hours<=8760:
            raise RuleManagerError('Configuração do gerenciador inválida.')
        with _LOCK:
            state=self.state();state.update(auto_update=bool(auto_update),tier=tier,update_hours=int(hours));atomic_json(self.manifest,state)

    def snapshot_path(self,entry):
        identifier=entry['id']
        if not re.fullmatch(r'[a-f0-9]{32}',identifier):
            raise RuleManagerError('Identificador de snapshot inválido.')
        path=self.root/'snapshots'/identifier
        if is_link(path) or not path.resolve().is_relative_to(self.root) or not path.is_dir():
            raise RuleManagerError('Snapshot fora da biblioteca.')
        return path

    def install(self,folder,origin,version,tier=None,download_sha256=None):
        with _LOCK:
            validated=validate_child(folder)
            identifier=uuid4().hex
            destination=self.root/'snapshots'/identifier
            destination.parent.mkdir(exist_ok=True)
            shutil.copytree(folder,destination)
            entry={'id':identifier,'origin':origin,'version':version,'tier':tier,'enabled':True,'disabled_rules':[],
                   'installed_at':datetime.now(timezone.utc).isoformat(),'download_sha256':download_sha256,**validated}
            state=self.state()
            previous=[x for x in state['libraries'] if x['origin']!=origin and not (origin=='YARA Forge' and x['origin']=='YARA Forge')]
            state['libraries']=previous+[entry]
            state['snapshots'].append(entry.copy())
            state.update(checked_at=time.time(),last_error=None)
            atomic_json(self.manifest,state)
            return entry

    def update(self,tier='core'):
        if tier not in TIERS:
            raise RuleManagerError('Pacote YARA Forge inválido.')
        try:
            release=json.loads(fetch(RELEASE_API,2*1024*1024))
            asset=next(a for a in release['assets'] if a['name']==f'yara-forge-rules-{tier}.zip')
            expected=asset.get('digest','')
            if not re.fullmatch(r'sha256:[a-f0-9]{64}',expected):
                raise RuleManagerError('Release sem SHA-256 oficial; atualização recusada.')
            url=asset['browser_download_url']
            if not re.fullmatch(r'https://github\.com/YARAHQ/yara-forge/releases/download/[A-Za-z0-9_.-]+/yara-forge-rules-'+tier+r'\.zip',url):
                raise RuleManagerError('URL do pacote oficial inválida.')
            data=fetch(url,MAX_DOWNLOAD)
            actual=hashlib.sha256(data).hexdigest()
            if actual!=expected[7:]:
                raise RuleManagerError('SHA-256 do download não corresponde à release oficial.')
            with tempfile.TemporaryDirectory(prefix='kekkai-yara-stage-') as temp:
                staging=Path(temp);archive=staging/'package.zip';archive.write_bytes(data)
                sources=staging/'sources';sources.mkdir();extract_package(archive,sources)
                return self.install(sources,'YARA Forge',str(release['tag_name']),tier,actual)
        except (KeyError,StopIteration,ValueError,OSError,zipfile.BadZipFile,RuleManagerError):
            with _LOCK:
                state=self.state();state.update(checked_at=time.time(),last_error=tr('Atualização falhou; versão anterior preservada.'));atomic_json(self.manifest,state)
            raise RuleManagerError(tr('Atualização falhou (rede, integridade ou validação). Última versão validada preservada.')) from None

    def import_files(self,paths):
        paths=[Path(p).resolve() for p in paths]
        if not paths or any(p.suffix.lower() not in {'.yar','.yara'} or is_link(p) or not p.is_file() for p in paths):
            raise RuleManagerError('Selecione arquivos .yar/.yara regulares.')
        if sum(p.stat().st_size for p in paths)>MAX_SOURCE:
            raise RuleManagerError('Regras excedem 64 MB.')
        with tempfile.TemporaryDirectory(prefix='kekkai-yara-import-') as temp:
            root=Path(temp)
            for index,path in enumerate(paths):
                # Expand only includes contained in the selected file's directory.
                source=expand_includes(path,path.parent)
                (root/f'{index}-{path.name}').write_text(source,encoding='utf-8')
            return self.install(root,'Custom '+uuid4().hex[:8],datetime.now(timezone.utc).isoformat())

    def revalidate(self,identifier,disabled=None):
        state=self.state();entry=next(x for x in state['libraries'] if x['id']==identifier)
        with tempfile.TemporaryDirectory(prefix='kekkai-yara-revalidate-') as temp:
            staging=Path(temp)/'rules';shutil.copytree(self.snapshot_path(entry),staging)
            values=entry.get('disabled_rules',[]) if disabled is None else list(disabled)
            data=validate_child(staging,values)
            destination=self.root/'snapshots'/uuid4().hex
            shutil.copytree(staging,destination)
            new={**entry,**data,'id':destination.name,'disabled_rules':values,'installed_at':datetime.now(timezone.utc).isoformat()}
            with _LOCK:
                state=self.state();state['libraries']=[new if x['id']==identifier else x for x in state['libraries']];state['snapshots'].append(new.copy());atomic_json(self.manifest,state)
            return new

    def set_enabled(self,identifier,enabled):
        with _LOCK:
            state=self.state()
            for entry in state['libraries']:
                if entry['id']==identifier:entry['enabled']=bool(enabled)
            atomic_json(self.manifest,state)

    def rollback(self,identifier):
        with _LOCK:
            state=self.state();entry=next(x.copy() for x in state['snapshots'] if x['id']==identifier)
            self.load(entry)
            state['libraries']=[x for x in state['libraries'] if x['origin']!=entry['origin']]+[entry]
            atomic_json(self.manifest,state)
            return entry

    def load(self,entry):
        folder=self.snapshot_path(entry)
        if entry['engine_version']!=engine_status()['version']:
            raise RuleManagerError('Motor YARA-X mudou. Valide novamente a biblioteca antes de usar.')
        if entry.get('cache_format') != 'validated-source-v1':
            raise RuleManagerError(tr('Formato antigo da biblioteca. Valide novamente antes de usar.'))
        sources=entry.get('source_hashes',{})
        actual={p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.suffix.lower() in {'.yar','.yara','.inc'} and p.is_file()}
        if not sources or actual!=set(sources):
            raise RuleManagerError(tr('Integridade das fontes YARA inválida; biblioteca não ativada.'))
        total=0
        for relative,expected in sources.items():
            path=folder/relative
            if not path.resolve().is_relative_to(folder) or any(is_link(p) for p in (path,*path.parents)):
                raise RuleManagerError('Path de fonte YARA inválido.')
            total+=path.stat().st_size
            if total>MAX_SOURCE or digest(path)!=expected:
                raise RuleManagerError(tr('Integridade das fontes YARA inválida; biblioteca não ativada.'))
        key=(entry['id'],entry['engine_version'],tuple(sorted(sources.items())),tuple(sorted(entry.get('disabled_rules',[]))))
        with _LOCK:
            if key not in _COMPILED_CACHE:
                compiled,_=compile_sources(folder,entry.get('disabled_rules',[]))
                _COMPILED_CACHE[key]=compiled
                while len(_COMPILED_CACHE)>2:_COMPILED_CACHE.popitem(last=False)
            _COMPILED_CACHE.move_to_end(key)
            return _COMPILED_CACHE[key]

    def active_sets(self,auto_update=False):
        state=self.state()
        if auto_update and state['auto_update'] and time.time()-state['checked_at']>state['update_hours']*3600:
            try:self.update(state['tier'])
            except RuleManagerError:pass  # Visible last_error; offline fallback is intentional.
        return [(entry,self.load(entry)) for entry in self.state()['libraries'] if entry['enabled'] and entry['active']]


def limit_validation_resources():
    global _WINDOWS_JOB
    if os.name!='nt':
        import resource
        resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3))
        resource.setrlimit(resource.RLIMIT_CPU,(110,110))
        return
    import ctypes
    from ctypes import wintypes
    class Basic(ctypes.Structure):
        _fields_=[('process_time',ctypes.c_longlong),('job_time',ctypes.c_longlong),('flags',wintypes.DWORD),
                  ('minimum_working',ctypes.c_size_t),('maximum_working',ctypes.c_size_t),('active_processes',wintypes.DWORD),
                  ('affinity',ctypes.c_size_t),('priority',wintypes.DWORD),('scheduling',wintypes.DWORD)]
    class IO(ctypes.Structure):
        _fields_=[(name,ctypes.c_ulonglong) for name in ('read_operations','write_operations','other_operations','read_bytes','write_bytes','other_bytes')]
    class Extended(ctypes.Structure):
        _fields_=[('basic',Basic),('io',IO),('process_memory',ctypes.c_size_t),('job_memory',ctypes.c_size_t),
                  ('peak_process_memory',ctypes.c_size_t),('peak_job_memory',ctypes.c_size_t)]
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateJobObjectW.argtypes=[ctypes.c_void_p,wintypes.LPCWSTR];kernel.CreateJobObjectW.restype=wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD];kernel.SetInformationJobObject.restype=wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes=[wintypes.HANDLE,wintypes.HANDLE];kernel.AssignProcessToJobObject.restype=wintypes.BOOL
    kernel.GetCurrentProcess.restype=wintypes.HANDLE
    handle=kernel.CreateJobObjectW(None,None)
    limits=Extended();limits.basic.flags=0x100;limits.process_memory=2*1024**3
    if not handle or not kernel.SetInformationJobObject(handle,9,ctypes.byref(limits),ctypes.sizeof(limits)) or not kernel.AssignProcessToJobObject(handle,kernel.GetCurrentProcess()):
        raise RuleManagerError('Não foi possível limitar a memória do compilador YARA-X.')
    _WINDOWS_JOB=handle


def validation_main():
    directory=Path(sys.argv[2]).resolve()
    try:
        limit_validation_resources()
        values=json.loads((directory/'disabled.json').read_text())
        atomic_json(directory/'validation.json',compile_snapshot(directory,values))
        return 0
    except Exception:
        # Child stderr is never copied to the UI or report, including compiler source.
        return 1


if __name__=='__main__':
    raise SystemExit(validation_main())
