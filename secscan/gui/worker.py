"""Qt signal bridge to core services. Widgets and source bundles never mix."""
from ..i18n import tr
import threading
from copy import deepcopy
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from ..ai.credentials import WindowsCredentialStore
from ..core.execution import ScanCancelled
from ..core.service import run_scan
from ..ai_providers import create_provider, ProviderError
from ..web_target import test_target
from ..diagnostics import diagnostic
from ..files import Sanitizer
from ..runner import probe_zap_container
from .. import secscan as engine
from ..yara_library import RuleManagerError


class DesktopAIInteraction:
    def __init__(self, options: dict, key: str | None, request_callback, cancel: threading.Event, authorized_guide=None):
        self.options = deepcopy(options)
        self.key = key
        self.request_callback = request_callback
        self.cancel = cancel
        self.reply = threading.Event()
        self.consent = False
        self.authorized_guide = authorized_guide

    def configure(self, options):
        return self.options.get("provider"), self.options.get("model"), options

    def authorize(self, provider, selection, files):
        self.reply.clear()
        self.request_callback({"provider": provider, "selection": dict(selection), "files": files})
        while not self.reply.wait(.2):
            if self.cancel.is_set():
                raise ScanCancelled(tr("Scan cancelado pelo usuário."))
        return self.consent and not self.cancel.is_set()

    def answer(self, consent):
        self.consent = bool(consent)
        self.reply.set()

    def read_key(self):
        if self.key:
            return self.key
        value = WindowsCredentialStore().read(self.options["provider"])
        if not value:
            raise ValueError(tr("Informe uma API key na tela AI Review ou salve-a no cofre Windows."))
        return value

    def clear(self):
        self.key = None


class ScanWorker(QThread):
    progress_event = Signal(dict)
    consent_requested = Signal(dict)
    completed = Signal(dict)
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, target: Path, config: dict, profile: str, requested_ai: bool, key: str | None, parent=None, authorized_guide=None):
        super().__init__(parent)
        self.target = target
        self.config = deepcopy(config)
        self.profile = profile
        self.requested_ai = requested_ai
        self.cancel_event = threading.Event()
        self.interaction = DesktopAIInteraction(config["ai"], key, self.consent_requested.emit, self.cancel_event, authorized_guide)

    def run(self):
        try:
            outcome = run_scan(self.target, self.config, profile=self.profile, requested_ai=self.requested_ai,
                               cancel=self.cancel_event, on_event=self.progress_event.emit, ai_interaction=self.interaction)
            self.completed.emit(outcome)
        except ScanCancelled:
            self.cancelled.emit()
        except Exception:
            self.failed.emit(tr("Não foi possível concluir o scan. Verifique o projeto, a configuração, Docker e as permissões de saída."))
        finally:
            self.interaction.clear()

    def request_cancel(self):
        self.cancel_event.set()
        self.interaction.answer(False)


class ProbeWorker(QThread):
    result_ready = Signal(str, dict)

    def __init__(self, name, options, key=None, parent=None):
        super().__init__(parent)
        self.name, self.options, self.key = name, dict(options), key

    def run(self):
        key = None
        try:
            if self.name == 'zap':
                result = test_target(self.options['target'])
                if result['reachable']:
                    docker=probe_zap_container(engine,self.options['target'])
                    result['docker_reachable']=docker['reachable']
                    if not docker['reachable']:result['diagnostic']=docker['diagnostic']
            else:
                key = self.key or WindowsCredentialStore().read(self.name)
                if not key:
                    raise ValueError('missing_key')
                adapter = create_provider(self.name, self.options.get('base_url'))
                result = adapter.test_connection(key, self.options.get('model'))
        except ProviderError as error:
            result = {'connected': False, 'diagnostic': error.diagnostic}
        except (ValueError, OSError):
            result = {'connected': False, 'diagnostic': diagnostic('configuration_error', 'connection_configuration', tr('Verifique modelo, chave em memória/cofre e endpoint oficial.'))}
        except Exception:
            result = {'connected': False, 'diagnostic': diagnostic('internal_error', 'probe_failed', tr('Não foi possível concluir o teste. Verifique configuração e conectividade.'))}
        finally:
            sanitizer = Sanitizer()
            if key:
                sanitizer.secrets.add(key)
            if self.key:
                sanitizer.secrets.add(self.key)
            result = sanitizer.clean(result)
            self.key = None
            key = None
        self.result_ready.emit(self.name, result)


class RuleManagerWorker(QThread):
    completed=Signal(dict)
    failed=Signal(str)

    def __init__(self,manager,action,arguments,parent=None):
        super().__init__(parent)
        self.manager,self.action,self.arguments=manager,action,arguments

    def run(self):
        try:
            getattr(self.manager,self.action)(**self.arguments)
            self.completed.emit(self.manager.state())
        except (RuleManagerError,OSError,ValueError,StopIteration):
            self.failed.emit(tr('Operação de regras não concluída. Verifique rede, integridade e compatibilidade; a versão anterior foi preservada.'))
