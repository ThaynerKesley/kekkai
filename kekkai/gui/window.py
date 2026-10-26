"""Desktop coordinator. Configuration and events are the boundary to the core."""
from copy import deepcopy
from pathlib import Path

from PySide6.QtCore import QUrl, QSize, Slot
from PySide6.QtGui import QDesktopServices, QCloseEvent, QIcon
from PySide6.QtWidgets import (QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QFrame,
    QStackedWidget, QButtonGroup, QLabel, QFileDialog, QMessageBox, QInputDialog)

from .. import configuration
from .. import engine
from ..ai.credentials import CredentialError, WindowsCredentialStore
from ..core.storage import Preferences, ReportStore, save_project_config
from ..dashboard import render
from ..themes import tokens
from .pages import HomePage, ScanPage, ScannersPage, AIReviewPage, SettingsPage, ProjectsPage, ReportsPage, AboutPage
from .policies import PolicyDialog
from .report_view import DashboardPage
from .widgets import button, icon, label, logo, wordmark
from .worker import ScanWorker, ProbeWorker, RuleManagerWorker
from .yara_page import YaraRulesPage
from ..yara_library import YaraRuleManager,RuleManagerError
from ..i18n import tr, set_language, get_language

NAVIGATION = [("home", tr("Visão geral")), ("dashboard", "Dashboard"), ("scan", "Scan"),
              ("projects", tr("Projetos")), ("reports", tr("Relatórios")), ("scanners", "Scanners"),
              ('yara_rules','YARA Rules'), ("ai", "AI Review"), ("settings", tr("Configurações")), ("about", tr("Sobre / Créditos"))]


class MainWindow(QMainWindow):
    def __init__(self, preferences: Preferences | None = None, target: Path | None = None, language: str | None = None):
        super().__init__()
        self.preferences = preferences or Preferences()
        set_language(language or self.preferences.data['language'])
        self.language = get_language()
        self.theme = self.preferences.data["theme"]
        self.target = (target or Path(self.preferences.data["default_directory"])).resolve()
        self.config = configuration.merge(configuration.DEFAULTS, self.preferences.data["scan_defaults"])
        self.summary = None
        self.requested_ai = False
        self.authorized_guide = None
        self.worker = None
        self.scan_active = False
        self.probes = {}
        self.rule_manager=YaraRuleManager()
        self.rule_worker=None
        self.close_after_probes = False
        self.close_after_scan = False
        self.selected_page = "home"
        self.setWindowTitle("Kekkai Desktop")
        self.resize(1340, 880)
        self.setMinimumSize(960, 650)
        self.setWindowIcon(QIcon(logo(self.theme)))
        root = QWidget()
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.setCentralWidget(root)
        self.sidebar = QFrame()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(220)
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(18, 28, 18, 24)
        sidebar_layout.setSpacing(7)
        brand = QHBoxLayout()
        self.brand_logo = QLabel()
        self.brand_logo.setPixmap(logo(self.theme))
        brand.addWidget(self.brand_logo)
        self.brand_text = QLabel()
        self.brand_text.setPixmap(wordmark())
        self.brand_text.setAccessibleName('Kekkai')
        self.brand_logo.setVisible(False)
        brand.addWidget(self.brand_text)
        brand.addStretch()
        sidebar_layout.addLayout(brand)
        self.sidebar_caption = label("SECURITY WORKSPACE", "eyebrow")
        sidebar_layout.addSpacing(15)
        sidebar_layout.addWidget(self.sidebar_caption)
        sidebar_layout.addSpacing(8)
        self.navigation = {}
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        for name, title in NAVIGATION:
            nav = button(title, lambda checked=False, page=name: self.navigate(page), name="nav_" + name)
            nav.setCheckable(True)
            nav.setProperty("nav", True)
            nav.setToolTip(title)
            nav.setAccessibleName(title)
            nav.setIconSize(QSize(21, 21))
            self.nav_group.addButton(nav)
            sidebar_layout.addWidget(nav)
            self.navigation[name] = nav
        sidebar_layout.addStretch()
        self.credit = label(tr("DESENVOLVIDO POR\nThayner Kesley"), "muted", wrap=True)
        sidebar_layout.addWidget(self.credit)
        layout.addWidget(self.sidebar)
        workspace = QWidget()
        body = QVBoxLayout(workspace)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        top = QFrame()
        top.setObjectName("topbar")
        top_layout = QHBoxLayout(top)
        top_layout.setContentsMargins(26, 14, 26, 14)
        self.header_title = label(tr("Visão geral"), "heading")
        self.workspace_label = label(tr("LOCAL · PRONTO"), "muted")
        self.theme_button = button(tr("Tema claro"), self.toggle_theme, name="themeToggle")
        self.select_button = button(tr("Selecionar projeto"), self.choose_project)
        top_layout.addWidget(self.header_title)
        top_layout.addStretch()
        top_layout.addWidget(self.workspace_label)
        top_layout.addWidget(self.theme_button)
        top_layout.addWidget(self.select_button)
        body.addWidget(top)
        self.stack = QStackedWidget()
        body.addWidget(self.stack, 1)
        layout.addWidget(workspace, 1)
        self.pages = {
            'yara_rules':YaraRulesPage(self),
            "home": HomePage(self), "dashboard": DashboardPage(self), "scan": ScanPage(self),
            "projects": ProjectsPage(self), "reports": ReportsPage(self), "scanners": ScannersPage(self),
            "ai": AIReviewPage(self), "settings": SettingsPage(self), "about": AboutPage(),
        }
        for page in self.pages.values():
            self.stack.addWidget(page)
        self.scan_page = self.pages["scan"]
        self.ai_page = self.pages["ai"]
        self.settings_page = self.pages["settings"]
        try:
            self.pages['yara_rules'].refresh(self.rule_manager.state())
        except (OSError,ValueError,RuleManagerError):
            self.pages['yara_rules'].feedback.setText(tr('Manifesto YARA inválido; verifique a biblioteca local.'))
        self.scan_page.open_dashboard.setChecked(self.preferences.data["open_dashboard"])
        self.select_project(self.target, remember=False)
        self.apply_theme(self.theme)
        self.navigate("home")

    def running(self):
        # Completion includes queued UI/report updates, not only the native thread exit.
        return self.scan_active

    def managed_yara_available(self):
        return any(entry['enabled'] and entry['active'] for entry in self.pages['yara_rules'].entries)

    def notice(self, text, *, error=False):
        if error:
            QMessageBox.warning(self, "Kekkai", text)
        else:
            self.statusBar().showMessage(text, 7000)

    def output_root(self):
        path = Path(self.config["reporting"]["output_dir"])
        return path.resolve() if path.is_absolute() else (self.target / path).resolve()

    def select_project(self, target: Path, remember=True):
        if self.running():
            self.notice(tr("Aguarde ou cancele o scan antes de trocar de projeto."))
            return
        if not target.is_dir():
            self.notice(tr("Selecione um diretório existente."), error=True)
            return
        try:
            config = configuration.load(target) if (target / ".kekkai.yml").is_file() else configuration.merge(configuration.DEFAULTS, self.preferences.data["scan_defaults"])
            if not (target / ".kekkai.yml").is_file() and not self.preferences.data["scan_defaults"]:
                for name in ("semgrep", "gitleaks", "sca", "owasp"):
                    config["policy"][name]["enabled"] = True
            configuration.validate(config)
            self.config = config
            self.target = target.resolve()
            self.summary = None
            self.authorized_guide = None
            self.scan_page.progress.setValue(0)
            self.scan_page.log.clear()
            self.scan_page.target_status.setText(tr('Alvo ainda não testado'))
            self.requested_ai = False
            self.ai_page.clear_keys()
            self.ai_page.refresh(self.config, False)
            self.check_key_status()
            self.settings_page.refresh(self.config, self.preferences.data)
            entries = ReportStore(self.output_root()).list_reports()
            if entries:
                self.summary = entries[0]["summary"]
            if remember:
                self.preferences.remember(self.target)
            self.refresh()
            self.setWindowTitle("Kekkai Desktop · " + (config["project"]["name"] or target.name))
        except (OSError, ValueError):
            self.notice(tr("Não foi possível carregar o projeto. Verifique .kekkai.yml, preferências e permissões."), error=True)

    def choose_project(self):
        if self.running():
            self.notice(tr("Aguarde ou cancele o scan antes de trocar de projeto."))
            return
        directory = QFileDialog.getExistingDirectory(self, tr("Selecionar projeto"), str(self.target))
        if directory:
            target = Path(directory)
            try:
                imported = configuration.load(target) if (target/'.kekkai.yml').is_file() else None
                choice = None
                if imported is None or imported['project'].get('web') is None:
                    choice, accepted = QInputDialog.getItem(self, tr('Tipo de projeto'), tr('Este projeto é uma aplicação web?'), [tr('Código local / não web'), tr('Aplicação web')], 0, False)
                    if not accepted:
                        return
                self.select_project(target)
                if self.target == target.resolve() and choice is not None:
                    self.set_project_type(choice == tr('Aplicação web'))
                    save_project_config(self.target, self.config)
                    self.notice(tr('Tipo de projeto salvo em .kekkai.yml.'))
            except (OSError, ValueError):
                self.notice(tr('Não foi possível importar/salvar o projeto. Verifique configuração e permissões.'), error=True)

    def set_project_type(self, web):
        if self.running():
            return
        self.config['project']['web'] = bool(web)
        self.refresh()

    def set_zap_target(self, target):
        if not self.running():
            if self.config['policy']['zap']['target'] != target.strip():
                self.scan_page.target_status.setText(tr('Alvo ainda não testado'))
            self.config['policy']['zap']['target'] = target.strip()

    def test_zap_target(self):
        if self.running() or 'zap' in self.probes:
            return
        self.set_zap_target(self.scan_page.zap_target.text())
        self.scan_page.target_status.setText(tr('Verificando alvo web…'))
        self.scan_page.test_target.setEnabled(False)
        self.start_probe('zap', {'target': self.config['policy']['zap']['target']})

    def test_ai_connection(self, name):
        if self.running() or name in self.probes:
            return
        fields = self.ai_page.providers[name]
        fields['test'].setEnabled(False)
        fields['status'].setText(tr('Testando autenticação/modelo/JSON · nenhum código enviado…'))
        self.start_probe(name, {'model': fields['model'].text().strip(), 'base_url': fields['base'].currentText().strip()}, fields['key'].text())

    def start_probe(self, name, options, key=None):
        worker = ProbeWorker(name, options, key, self)
        self.probes[name] = worker
        worker.result_ready.connect(self.probe_result)
        worker.finished.connect(self.probe_finished)
        worker.finished.connect(worker.deleteLater)
        worker.start()

    @Slot(str, dict)
    def probe_result(self, name, result):
        info = result.get('diagnostic')
        if name == 'zap':
            text = tr('Acessível · HTTP {status} · {latency} ms', status=result['http_status'], latency=result['latency_ms']) if result.get('reachable') else info['summary']
            if result.get('docker_reachable') is False:
                text=tr('HTTP local acessível · ')+info['summary']
            elif result.get('docker_reachable'):
                text+=tr(' · Docker acessível')
            self.scan_page.target_status.setText(text)
            self.scan_page.test_target.setEnabled(not self.running())
            if not self.running():
                self.refresh()
        else:
            fields = self.ai_page.providers[name]
            fields['status'].setText(result.get('summary') or info['summary'])
            fields['test'].setEnabled(not self.running())

    @Slot()
    def probe_finished(self):
        worker = self.sender()
        self.probes = {name: item for name, item in self.probes.items() if item is not worker}
        if self.close_after_probes and not self.probes:
            self.close()

    def choose_guide(self):
        path, _ = QFileDialog.getOpenFileName(self, tr("Selecionar security guide"), str(self.target), tr("Markdown (*.md);;Todos os arquivos (*)"))
        if path:
            self.authorized_guide = str(Path(path).resolve())
            self.ai_page.guide_mode.setCurrentIndex(1)
            self.ai_page.guide_path.setText(path)

    def navigate(self, name):
        self.selected_page = name
        self.stack.setCurrentWidget(self.pages[name])
        self.navigation[name].setChecked(True)
        self.header_title.setText(tr(dict(NAVIGATION)[name]))
        if name == "dashboard":
            self.show_dashboard(navigate=False)
        elif name == "reports":
            self.refresh_reports()
        elif name=='yara_rules':
            try:self.pages[name].refresh(self.rule_manager.state())
            except (OSError,ValueError,RuleManagerError):self.notice(tr('Manifesto YARA inválido; verifique a biblioteca local.'),error=True)

    def import_yara_rules(self):
        paths,_=QFileDialog.getOpenFileNames(self,tr('Importar regras YARA'),str(self.target),'YARA (*.yar *.yara)')
        if paths:self.yara_action('import_files',paths=paths)

    def save_yara_settings(self):
        page=self.pages['yara_rules']
        try:
            self.rule_manager.settings(page.auto.isChecked(),page.tier.currentText(),page.hours.value())
            page.refresh(self.rule_manager.state())
            self.notice(tr('Preferências de atualização YARA salvas.'))
        except (OSError,RuleManagerError):self.notice(tr('Não foi possível salvar preferências YARA.'),error=True)

    def yara_action(self,action,**arguments):
        if self.running() or self.rule_worker is not None:
            self.notice(tr('Aguarde o scan/operação de regras em andamento.'))
            return
        page=self.pages['yara_rules'];entry=page.selected()
        if action in {'validate','toggle','rule_toggle'} and not entry:
            self.notice(tr('Selecione uma biblioteca instalada.'));return
        if action=='validate':action='revalidate';arguments={'identifier':entry['id']}
        elif action=='toggle':action='set_enabled';arguments={'identifier':entry['id'],'enabled':not entry['enabled']}
        elif action=='rule_toggle':
            row=page.rule_table.currentRow()
            if not 0<=row<len(page.visible_rules):return
            name=page.visible_rules[row]['name'];disabled=set(entry.get('disabled_rules',[]))
            if name in disabled:disabled.remove(name)
            else:disabled.add(name)
            action='revalidate';arguments={'identifier':entry['id'],'disabled':list(disabled)}
        if action=='rollback' and not arguments.get('identifier'):return
        worker=RuleManagerWorker(self.rule_manager,action,arguments,self)
        self.rule_worker=worker;page.set_busy(True)
        worker.completed.connect(self.rules_completed);worker.failed.connect(lambda message:self.notice(message,error=True))
        worker.finished.connect(self.rules_finished);worker.finished.connect(worker.deleteLater);worker.start()

    @Slot(dict)
    def rules_completed(self,state):
        self.pages['yara_rules'].refresh(state)
        self.refresh()
        self.notice(tr('Biblioteca YARA atualizada e validada. Regras inválidas permaneceram isoladas.'))

    @Slot()
    def rules_finished(self):
        self.rule_worker=None
        self.pages['yara_rules'].set_busy(False)
        if self.close_after_probes:self.close()

    def refresh(self):
        self.ai_page.update_usage(self.summary)
        self.pages["home"].refresh(self.target, self.config, self.summary, self.theme, self.requested_ai)
        self.scan_page.refresh(self.target, self.config, self.requested_ai)
        self.pages["scanners"].refresh(self.config, self.summary, self.requested_ai)
        self.ai_page.enabled.blockSignals(True)
        self.ai_page.enabled.setChecked(self.requested_ai)
        self.ai_page.enabled.blockSignals(False)
        self.ai_page.enabled.setEnabled(self.scan_page.profile.currentText() != "quick" and not self.running())
        self.pages["projects"].list.clear()
        self.pages["projects"].list.addItems([str(self.target), *[x for x in self.preferences.data["recent_projects"] if x != str(self.target)]])
        self.refresh_reports()

    def refresh_reports(self):
        try:
            self.pages["reports"].refresh(ReportStore(self.output_root()).list_reports())
        except OSError:
            self.notice(tr("Não foi possível listar os relatórios do projeto."))

    def show_dashboard(self, navigate=True):
        if navigate:
            self.navigate("dashboard")
            return
        if not self.summary:
            # Honest empty state, rendered by the same report renderer with all scanners skipped.
            empty = engine.build_summary(self.config, self.target, tr("Nenhum scan executado"),
                [engine.make_result(name, "skipped", None, []) for name in engine.SCANNER_ORDER])
            empty["message"] = tr("Execute um scan para visualizar os dados reais deste projeto.")
            empty["result"] = "not_scanned"
            self.pages["dashboard"].show_summary(empty, self.theme)
        else:
            self.pages["dashboard"].show_summary(self.summary, self.theme)

    def apply_theme(self, theme):
        if theme not in {"light", "dark"}:
            return
        self.theme = theme
        self.preferences.data["theme"] = theme
        stylesheet = (Path(__file__).parents[1] / "themes" / "desktop.qss").read_text(encoding="utf-8")
        for key, value in sorted(tokens(theme).items(), key=lambda item: len(item[0]), reverse=True):
            stylesheet = stylesheet.replace("@" + key, value)
        self.setStyleSheet(stylesheet)
        self.brand_logo.setPixmap(logo(theme))
        self.theme_button.setText(tr("Tema claro") if theme == "dark" else tr("Tema escuro"))
        for name, nav in self.navigation.items():
            nav.setIcon(icon(name, tokens(theme)["text-primary"]))
        self.pages["home"].refresh(self.target, self.config, self.summary, theme, self.requested_ai)
        self.pages["dashboard"].set_theme(theme)
        self.settings_page.theme.blockSignals(True)
        self.settings_page.theme.setCurrentIndex(0 if theme == "dark" else 1)
        self.settings_page.theme.blockSignals(False)

    def toggle_theme(self):
        self.apply_theme("light" if self.theme == "dark" else "dark")
        try:
            self.preferences.save()
        except (OSError, ValueError):
            self.notice(tr("Tema aplicado nesta sessão; não foi possível salvar a preferência."))

    def toggle_scanner(self, name, enabled):
        if self.running():
            return
        if name == "ai":
            self.requested_ai = bool(enabled)
            self.ai_page.enabled.blockSignals(True)
            self.ai_page.enabled.setChecked(self.requested_ai)
            self.ai_page.enabled.blockSignals(False)
        else:
            self.config["policy"][name]["enabled"] = bool(enabled)
        self.refresh()

    def profile_changed(self, profile):
        if not hasattr(self, "scan_page"):
            return
        saved = self.preferences.data.get("profiles", {}).get(profile, {})
        for name, enabled in saved.get("scanners", {}).items():
            if name in self.config["policy"] and type(enabled) is bool:
                self.config["policy"][name]["enabled"] = enabled
        if profile == "quick":
            self.requested_ai = False
        self.refresh()

    def save_profile(self):
        profile = self.scan_page.profile.currentText()
        self.preferences.data.setdefault("profiles", {})[profile] = {"scanners": {
            name: bool(self.config["policy"][name]["enabled"] and not (profile == "quick" and name == "zap"))
            for name in engine.SCANNER_ORDER if name != "ai"}}
        try:
            self.preferences.save()
            self.notice(tr("Perfil salvo localmente: ") + profile)
        except (OSError, ValueError):
            self.notice(tr("Não foi possível salvar o perfil."), error=True)

    def edit_policy(self, name):
        if self.running():
            self.notice(tr("Aguarde o scan para editar policies."))
            return
        dialog = PolicyDialog(name, self.config, self)
        if dialog.exec() and dialog.result_config is not None:
            self.config = dialog.result_config
            self.refresh()

    def collect_config(self):
        config = deepcopy(self.config)
        config['policy']['zap']['target'] = self.scan_page.zap_target.text().strip()
        self.settings_page.apply(config)
        config["ai"].update(self.ai_page.values())
        configuration.validate(config)
        return config

    def save_config(self):
        if self.running():
            self.notice(tr("Aguarde o scan para salvar a configuração."))
            return
        try:
            config = self.collect_config()
            save_project_config(self.target, config)
            self.config = config
            self.refresh()
            self.notice(tr("Configuração salva em .kekkai.yml, sem credenciais."))
        except (OSError, ValueError):
            self.notice(tr("Configuração inválida ou sem permissão de escrita. Verifique os campos; nenhuma chave é gravada no YAML."), error=True)

    def save_settings(self):
        try:
            config = self.collect_config()
            directory = self.settings_page.default_directory.text().strip()
            if not Path(directory).is_dir():
                raise ValueError(tr("Diretório inválido."))
            self.preferences.data.update(default_directory=directory, open_dashboard=self.settings_page.open_dashboard.isChecked(), scan_defaults=config,
                                         language=self.settings_page.language.currentData())
            self.preferences.save()
            self.config = config
            self.scan_page.open_dashboard.setChecked(self.preferences.data["open_dashboard"])
            self.refresh()
            self.notice(tr("Preferências locais salvas. Use Salvar configuração para atualizar o YAML do projeto."))
            if self.preferences.data['language'] != self.language:
                self.notice(tr('Idioma salvo. Reinicie o Kekkai para aplicar a alteração.'))
        except (OSError, ValueError):
            self.notice(tr("Preferências inválidas ou sem permissão de escrita. Verifique diretório, exclusões e limites."), error=True)

    def save_provider(self, name):
        fields = self.ai_page.providers[name]
        try:
            self.config["ai"].update(self.ai_page.values())
            configuration.validate(self.config)
            if fields["save"].isChecked():
                WindowsCredentialStore().save(name, fields["key"].text())
                fields["key"].clear()
                fields["status"].setText(tr("Chave salva no cofre Windows · nunca exibida"))
            self.preferences.data["scan_defaults"] = deepcopy(self.config)
            self.preferences.save()
            self.notice(tr("Configuração do provider salva. Uso de IA ainda exige consentimento por scan."))
        except (OSError, ValueError, CredentialError):
            self.notice(tr("Não foi possível salvar o provider/cofre. Verifique modelo, endpoint oficial e campo de chave."), error=True)

    def check_key_status(self):
        store = WindowsCredentialStore()
        for name, fields in self.ai_page.providers.items():
            if fields["key"].text():
                continue
            try:
                configured = store.available and store.configured(name)
                fields["status"].setText(tr("Chave disponível no cofre Windows") if configured else tr("Chave não configurada"))
            except CredentialError:
                fields["status"].setText(tr("Cofre indisponível · use uma chave em memória"))

    def delete_key(self, name):
        answer = QMessageBox.question(self, tr("Remover chave salva"), tr("Remover a credencial deste provider do cofre Windows?"), QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            WindowsCredentialStore().delete(name)
            self.ai_page.providers[name]["key"].clear()
            self.ai_page.providers[name]["status"].setText(tr("Chave removida do cofre"))
        except CredentialError:
            self.notice(tr("Não foi possível remover a credencial do cofre Windows."), error=True)

    def start_scan(self, profile=None):
        if self.rule_worker is not None:
            self.notice(tr('Aguarde a validação de regras antes do scan.'));return
        if self.probes:
            self.notice(tr('Aguarde os testes de conexão antes de iniciar o scan.'))
            return
        if self.running():
            self.notice(tr("Um scan já está em andamento."))
            return
        if profile:
            self.scan_page.profile.setCurrentText(profile)
        profile = self.scan_page.profile.currentText()
        try:
            config = self.collect_config()
            requested_ai = self.requested_ai and profile != "quick"
            if not any(config["policy"][name]["enabled"] for name in config["policy"]) and not requested_ai:
                raise ValueError(tr("Nenhum scanner habilitado."))
            provider = config["ai"]["provider"]
            if requested_ai and (not config["ai"]["providers"][provider]["enabled"] or not config["ai"]["model"]):
                self.notice(tr("Habilite o provider e informe o modelo na tela AI Review."), error=True)
                return
            self.config = config
            key = self.ai_page.providers[provider]["key"].text() or None if requested_ai else None
            self.worker = ScanWorker(self.target, config, profile, requested_ai, key, self, authorized_guide=self.authorized_guide)
            self.worker.progress_event.connect(self.scan_page.receive)
            self.worker.consent_requested.connect(self.confirm_ai)
            self.worker.completed.connect(self.scan_completed)
            self.worker.failed.connect(lambda message: self.notice(message, error=True))
            self.worker.cancelled.connect(lambda: self.notice(tr("Scan cancelado. O último relatório foi preservado.")))
            self.worker.finished.connect(self.scan_finished)
            self.worker.finished.connect(self.worker.deleteLater)
            self.scan_page.set_running(True)
            self.select_button.setEnabled(False)
            self.pages["settings"].setEnabled(False)
            self.pages["scanners"].setEnabled(False)
            self.ai_page.setEnabled(False)
            self.workspace_label.setText(tr("LOCAL · SCAN EM ANDAMENTO"))
            self.navigate("scan")
            self.scan_active = True
            self.worker.start()
        except (OSError, ValueError):
            self.notice(tr("Revise a configuração e habilite ao menos um scanner antes de iniciar."), error=True)

    @Slot(dict)
    def confirm_ai(self, request):
        if not self.worker or self.worker.cancel_event.is_set():
            return
        selection = request["selection"]
        self.scan_page.progress_label.setText(tr("Aguardando consentimento para envio à IA…"))
        message = QMessageBox(self)
        message.setWindowTitle(tr("Confirmar envio para IA"))
        message.setIcon(QMessageBox.Icon.Question)
        message.setText(tr("Enviar os arquivos selecionados para ") + request["provider"] + "?")
        message.setInformativeText(tr('Arquivos: {count}\nTamanho aproximado: {size:.2f} MB\nOmitidos por limite de tamanho: {omitted}\nRetenção depende do provider. O Kekkai não salva source bundles nem histórico de conversa.', count=len(request['files']), size=selection['selected_bytes']/1024/1024, omitted=selection['size_files_omitted']))
        guide = selection.get('guide')
        if guide:
            message.setInformativeText(message.informativeText() + f"\nGuide: {guide['path']} ({guide['bytes']} bytes)" + (tr(' · fora do projeto') if guide['outside_target'] else ''))
        plan=selection.get('token_estimate')
        if plan:
            cost=plan.get('cost_at_output_budget')
            price=f"US$ {cost['minimum']:.4f}–{cost['maximum']:.4f}" if cost else tr('tarifa não configurada')
            message.setInformativeText(message.informativeText()+tr('\n\n{groups} grupos · até {requests} requisições com tentativas.\nEntrada aproximada: {incoming:,} tokens (heurística).\nCusto estimado se consumir todo o orçamento de saída: {price}. Não é cobrança exata.', groups=plan['groups'], requests=plan['max_requests'], incoming=plan['input_tokens_approx'], price=price))
        message.setDetailedText("\n".join(request["files"]))
        message.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        message.setDefaultButton(QMessageBox.StandardButton.No)
        self.worker.interaction.answer(message.exec() == QMessageBox.StandardButton.Yes)

    def cancel_scan(self):
        if self.running():
            self.worker.request_cancel()
            self.scan_page.cancel.setEnabled(False)
            self.scan_page.progress_label.setText(tr("Cancelamento solicitado. Encerrando somente os scanners deste scan…"))

    @Slot(dict)
    def scan_completed(self, outcome):
        self.summary = outcome["summary"]
        dirs = outcome["dirs"]
        if dirs:
            root, reports, dashboard = Path(dirs["root"]), Path(dirs["reports"]), Path(dirs["dashboard"]) / "index.html"
            try:
                if self.config["reporting"]["dashboard"]:
                    engine.write_text(dashboard, render(self.summary, self.theme))
                ReportStore(root).archive(self.summary, reports, dashboard if self.config["reporting"]["dashboard"] else None)
            except OSError:
                self.notice(tr("Scan concluído; não foi possível arquivar o histórico."))
        self.refresh()
        self.notice(tr("Scan concluído: ") + engine.RESULT_LABELS[self.summary["result"]])
        self.scan_page.progress_label.setText(tr("Scan concluído · ") + engine.RESULT_LABELS[self.summary["result"]])
        if self.scan_page.open_dashboard.isChecked():
            self.show_dashboard()

    @Slot()
    def scan_finished(self):
        self.scan_active = False
        self.scan_page.set_running(False)
        self.select_button.setEnabled(True)
        self.pages["settings"].setEnabled(True)
        self.pages["scanners"].setEnabled(True)
        self.ai_page.setEnabled(True)
        self.ai_page.clear_keys()
        self.check_key_status()
        self.requested_ai = False
        self.ai_page.enabled.blockSignals(True)
        self.ai_page.enabled.setChecked(False)
        self.ai_page.enabled.blockSignals(False)
        self.workspace_label.setText(tr("LOCAL · PRONTO"))
        self.refresh()
        if self.close_after_scan:
            self.close()

    def open_report(self, action):
        selected = self.pages["reports"].selected()
        if not selected:
            self.notice(tr("Selecione uma execução disponível."))
            return
        path = Path(selected["path"])
        if action == "dashboard":
            self.pages["dashboard"].show_summary(selected["summary"], self.theme)
            self.selected_page = "dashboard"
            self.stack.setCurrentWidget(self.pages["dashboard"])
            self.navigation["dashboard"].setChecked(True)
            self.header_title.setText("Dashboard")
        elif action == "summary":
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
        elif action == "raw":
            raw = path.parent / "raw"
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(raw if raw.is_dir() else path.parent)))
        elif action == "export":
            destination, _ = QFileDialog.getSaveFileName(self, tr("Exportar relatório"), str(self.target / "kekkai-report.zip"), "ZIP (*.zip)")
            if destination:
                try:
                    ReportStore(self.output_root()).export(path.parent, Path(destination))
                    self.notice(tr("Relatório exportado com sucesso."))
                except (OSError, ValueError):
                    self.notice(tr("Não foi possível exportar. Escolha um destino fora do diretório do relatório."), error=True)
        elif action == 'delete':
            if self.running():
                self.notice(tr('Aguarde o scan antes de excluir relatórios.'))
                return
            try:
                store=ReportStore(self.output_root())
                targets=store.deletion_targets(path)
                answer=QMessageBox.question(self,tr('Excluir relatório'),tr('Excluir permanentemente este item de relatório? Histórico separado permanece disponível.\n\n')+'\n'.join(str(x) for x in targets),QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,QMessageBox.StandardButton.No)
                if answer!=QMessageBox.StandardButton.Yes:return
                store.delete(path)
                self.pages['dashboard'].clear()
                entries=store.list_reports()
                self.summary=entries[0]['summary'] if entries else None
                self.refresh()
                self.notice(tr('Relatório excluído. Código-fonte e demais execuções preservados.'))
            except (OSError,ValueError):
                self.notice(tr('Não foi possível excluir o relatório. Verifique paths e permissões.'),error=True)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if not hasattr(self, "navigation"):
            return
        compact = self.width() < 1100
        self.sidebar.setFixedWidth(76 if compact else 220)
        self.brand_text.setVisible(not compact)
        self.brand_logo.setVisible(compact)
        self.sidebar_caption.setVisible(not compact)
        self.credit.setVisible(not compact)
        for name, title in NAVIGATION:
            self.navigation[name].setText("" if compact else tr(title))

    def closeEvent(self, event: QCloseEvent):
        if self.probes or self.rule_worker is not None:
            self.close_after_probes = True
            self.notice(tr('Aguardando os testes de conexão encerrarem para fechar com segurança…'))
            event.ignore()
        elif self.running():
            answer = QMessageBox.question(self, tr("Scan em andamento"), tr("Cancelar o scan e fechar ao encerrar os scanners?"), QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
            if answer == QMessageBox.StandardButton.Yes:
                self.close_after_scan = True
                self.cancel_scan()
            event.ignore()
        else:
            self.ai_page.clear_keys()
            self.pages["dashboard"].cleanup()
            event.accept()
