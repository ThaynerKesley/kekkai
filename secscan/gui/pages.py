"""Desktop pages: forms and presentation consume a shared configuration model."""
from pathlib import Path

from PySide6.QtCore import Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDoubleSpinBox, QFormLayout, QGridLayout,
    QHBoxLayout, QHeaderView, QLineEdit, QListWidget, QPlainTextEdit, QProgressBar,
    QSpinBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QAbstractItemView)

from ..ai_providers import PROVIDER_BASE_URLS
from ..web_target import is_web_project
from .. import secscan as engine
from ..themes import tokens
from .widgets import Card, ScanChart, button, label, scroll_page
from ..i18n import tr, LANGUAGES

DESCRIPTIONS = {
    "semgrep": tr("Análise estática de código com regras Semgrep CE."),
    "gitleaks": tr("Detecção de credenciais e secrets expostos."),
    "sca": tr("Risco de versão e obrigações de licenciamento."),
    "yara": tr("Patterns das suas regras YARA, com engine YARA-X."),
    "owasp": tr("Findings mapeados para a edição real do OWASP Top 10."),
    "zap": tr("Análise dinâmica baseline da aplicação local."),
    "ai": tr("Revisão assistida por IA, com consentimento por execução."),
}
PROVIDER_LABELS = {"deepseek": "DeepSeek", "qwen": "Qwen", "openai": "OpenAI", "anthropic": "Anthropic"}


def table(headers) -> QTableWidget:
    widget = QTableWidget(0, len(headers))
    widget.setHorizontalHeaderLabels([tr(value) for value in headers])
    widget.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    widget.verticalHeader().hide()
    widget.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    widget.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    widget.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    widget.setShowGrid(False)
    widget.verticalHeader().setDefaultSectionSize(43)
    return widget


def fill_row(widget, index, values):
    for column, value in enumerate(values):
        item = QTableWidgetItem(str(value))
        item.setToolTip(str(value))
        widget.setItem(index, column, item)


def color_status(widget, row, status, theme):
    cell = widget.item(row, 1)
    palette = tokens(theme)
    key = {"pass": "success", "warn": "warning", "fail": "danger", "error": "danger", "skipped": "muted"}.get(status, "text-primary")
    cell.setForeground(QColor(palette[key]))
    font = cell.font()
    font.setBold(True)
    cell.setFont(font)


def wrap_layout(layout):
    widget = QWidget()
    widget.setLayout(layout)
    return widget


class HomePage(QWidget):
    def __init__(self, window):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll, _, layout = scroll_page()
        outer.addWidget(scroll)
        self.title = label(tr("Seu workspace de segurança"), "title")
        layout.addWidget(self.title)
        layout.addWidget(label(tr("Verificações consistentes. Decisões claras. Seus projetos sob controle."), "muted", wrap=True))
        metric_row = QGridLayout()
        self.metrics = {}
        for index, name in enumerate(["Findings", "Bloqueantes", "Tempo total", "Scanners ativos"]):
            card = Card()
            card.body.addWidget(label(name, "muted"))
            value = label("—", "metric")
            card.body.addWidget(value)
            metric_row.addWidget(card, 0, index)
            self.metrics[name] = value
        layout.addLayout(metric_row)
        row = QHBoxLayout()
        project = Card(tr("Projeto atual"))
        self.project_name = label(tr("Nenhum projeto"), "heading")
        self.project_path = label(tr("Selecione um diretório para começar."), "muted", wrap=True)
        self.result = label(tr("Nenhum scan executado"), "heading")
        project.body.addWidget(self.project_name)
        project.body.addWidget(self.project_path)
        project.body.addWidget(self.result)
        project.body.addWidget(button(tr("Selecionar projeto"), window.choose_project))
        row.addWidget(project, 3)
        actions = Card(tr("Iniciar uma verificação"))
        actions.body.addWidget(label(tr("Quick prioriza verificações estáticas. Full inclui todos os scanners configurados. IA exige uma solicitação explícita."), "muted", wrap=True))
        actions.body.addWidget(button("Quick scan", lambda: window.start_scan("quick"), primary=True, name="homeQuick"))
        actions.body.addWidget(button("Full scan", lambda: window.start_scan("full"), name="homeFull"))
        actions.body.addWidget(button(tr("Abrir dashboard"), window.show_dashboard))
        row.addWidget(actions, 2)
        layout.addLayout(row)
        charts = QHBoxLayout()
        self.severity_chart = ScanChart("severity")
        self.performance_chart = ScanChart("performance")
        for title, chart in [(tr("Findings por severidade"), self.severity_chart), (tr("Tempo por scanner"), self.performance_chart)]:
            card = Card(title)
            card.body.addWidget(chart)
            charts.addWidget(card)
        layout.addLayout(charts)
        self.scanner_table = table(["Scanner", "Status", "Findings", tr("Tempo")])
        self.scanner_table.setMinimumHeight(340)
        status_card = Card(tr("Última execução"))
        status_card.body.addWidget(self.scanner_table)
        layout.addWidget(status_card)
        layout.addStretch()

    def refresh(self, target, config, summary, theme, requested_ai=False):
        self.project_name.setText(config.get("project", {}).get("name") or target.name)
        self.project_path.setText(str(target))
        enabled = sum(bool(config["policy"][name]["enabled"]) for name in engine.SCANNER_ORDER if name != "ai")
        enabled += int(requested_ai)
        self.metrics["Scanners ativos"].setText(str(enabled))
        totals = (summary or {}).get("totals", {})
        self.metrics["Findings"].setText(str(totals.get("total", "—")))
        self.metrics["Bloqueantes"].setText(str(totals.get("blocking", "—")))
        seconds = (summary or {}).get("performance", {}).get("total_seconds")
        self.metrics["Tempo total"].setText(f"{seconds:.1f}s" if isinstance(seconds, (int, float)) else "—")
        self.result.setText(engine.RESULT_LABELS.get((summary or {}).get("result"), tr("Nenhum scan executado")))
        self.scanner_table.setRowCount(len(engine.SCANNER_ORDER))
        for index, name in enumerate(engine.SCANNER_ORDER):
            own = (summary or {}).get("scanners", {}).get(name, {})
            fill_row(self.scanner_table, index, [engine.DISPLAY_NAMES[name], engine.STATUS_LABELS.get(own.get("status"), "—"),
                    own.get("total_findings", "—"), f"{own['duration_seconds']:.1f}s" if "duration_seconds" in own else "—"])
            color_status(self.scanner_table, index, own.get("status"), theme)
        self.severity_chart.update_data(summary, theme)
        self.performance_chart.update_data(summary, theme)


class ScanPage(QWidget):
    def __init__(self, window):
        super().__init__()
        self.owner = window
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll, _, layout = scroll_page()
        outer.addWidget(scroll)
        layout.addWidget(label(tr("Execute um scan"), "title"))
        layout.addWidget(label(tr("Selecione o projeto, revise o perfil e acompanhe cada verificação em tempo real."), "muted", wrap=True))
        setup = Card(tr("Alvo e perfil"))
        path_row = QHBoxLayout()
        self.target = QLineEdit()
        self.target.setReadOnly(True)
        self.target.setAccessibleName(tr("Diretório do projeto"))
        path_row.addWidget(self.target, 1)
        path_row.addWidget(button(tr("Selecionar pasta"), window.choose_project))
        setup.body.addLayout(path_row)
        form = QFormLayout()
        self.profile = QComboBox()
        self.profile.addItems(["quick", "full"])
        self.profile.setCurrentText("full")
        self.profile.setAccessibleName(tr("Perfil de scan"))
        self.profile.currentTextChanged.connect(window.profile_changed)
        form.addRow(tr("Perfil"), self.profile)
        self.project_type = QComboBox()
        self.project_type.addItem(tr("Código local / não web"), False)
        self.project_type.addItem(tr("Aplicação web"), True)
        self.project_type.setAccessibleName(tr("Tipo de projeto"))
        self.project_type.currentIndexChanged.connect(lambda: window.set_project_type(self.project_type.currentData()))
        form.addRow(tr("Tipo de projeto"), self.project_type)
        setup.body.addLayout(form)
        self.profile_note = label("", "muted", wrap=True)
        setup.body.addWidget(self.profile_note)
        self.zap_callout = Card(tr("ZAP precisa da aplicação web rodando localmente"))
        self.zap_callout.body.addWidget(label(tr("Inicie sua aplicação antes do scan. O alvo será verificado antes de iniciar o container."), "muted", wrap=True))
        zap_row = QHBoxLayout()
        self.zap_target = QLineEdit()
        self.zap_target.setAccessibleName(tr("Alvo web ZAP"))
        self.zap_target.editingFinished.connect(lambda: window.set_zap_target(self.zap_target.text()))
        self.test_target = button(tr("Testar alvo"), window.test_zap_target, name="testTarget")
        zap_row.addWidget(self.zap_target, 1)
        zap_row.addWidget(self.test_target)
        self.zap_callout.body.addLayout(zap_row)
        self.target_status = label(tr("Alvo ainda não testado"), "muted", wrap=True)
        self.zap_callout.body.addWidget(self.target_status)
        setup.body.addWidget(self.zap_callout)
        self.toggles = {}
        scanner_grid = QGridLayout()
        for index, name in enumerate(engine.SCANNER_ORDER):
            toggle = QCheckBox(engine.DISPLAY_NAMES[name])
            toggle.setToolTip(tr(DESCRIPTIONS[name]))
            toggle.setObjectName("toggle_" + name)
            toggle.toggled.connect(lambda enabled, scanner=name: window.toggle_scanner(scanner, enabled))
            scanner_grid.addWidget(toggle, index // 3, index % 3)
            self.toggles[name] = toggle
        setup.body.addLayout(scanner_grid)
        options = QHBoxLayout()
        self.open_dashboard = QCheckBox(tr("Abrir dashboard ao concluir"))
        self.open_dashboard.setChecked(True)
        options.addWidget(self.open_dashboard)
        options.addStretch()
        options.addWidget(button(tr("Salvar perfil"), window.save_profile))
        setup.body.addLayout(options)
        controls = QHBoxLayout()
        self.start = button(tr("Iniciar scan"), lambda: window.start_scan(), primary=True, name="startScan")
        self.cancel = button(tr("Cancelar scan"), window.cancel_scan, name="cancelScan")
        self.cancel.setEnabled(False)
        controls.addWidget(self.start)
        controls.addWidget(self.cancel)
        controls.addStretch()
        setup.body.addLayout(controls)
        layout.addWidget(setup)
        progress = Card("Progresso")
        self.progress_label = label(tr("Pronto para iniciar"), "muted")
        self.progress = QProgressBar()
        self.progress.setRange(0, len(engine.SCANNER_ORDER))
        self.progress.setValue(0)
        self.progress.setFormat(tr("%v de %m verificações concluídas"))
        progress.body.addWidget(self.progress_label)
        progress.body.addWidget(self.progress)
        self.scanner_table = table(["Scanner", "Status", "Findings", tr("Duração"), tr("Diagnóstico")])
        for column in (2, 3):
            self.scanner_table.horizontalHeader().setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self.scanner_table.setMinimumHeight(340)
        self.scanner_table.setRowCount(len(engine.SCANNER_ORDER))
        for index, name in enumerate(engine.SCANNER_ORDER):
            fill_row(self.scanner_table, index, [engine.DISPLAY_NAMES[name], "AGUARDANDO", "—", "—"])
        progress.body.addWidget(self.scanner_table)
        layout.addWidget(progress)
        logs = Card(tr("Eventos do scan"))
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(300)
        self.log.setAccessibleName(tr("Eventos resumidos do scan"))
        self.log.setMinimumHeight(160)
        logs.body.addWidget(self.log)
        layout.addWidget(logs)
        layout.addStretch()

    def refresh(self, target, config, requested_ai):
        self.target.setText(str(target))
        quick = self.profile.currentText() == "quick"
        web = is_web_project(config)
        self.project_type.blockSignals(True)
        self.project_type.setCurrentIndex(1 if web else 0)
        self.project_type.blockSignals(False)
        self.zap_target.setText(config['policy']['zap']['target'])
        self.zap_callout.setVisible(web and config['policy']['zap']['enabled'] and not quick)
        self.profile_note.setText(tr("Quick: sem ZAP e IA; license-full desativado.") if quick else tr("Full: todos os scanners selecionados. IA pede confirmação antes do envio."))
        for name, toggle in self.toggles.items():
            toggle.blockSignals(True)
            toggle.setChecked(requested_ai if name == "ai" else config["policy"][name]["enabled"])
            toggle.setEnabled(not (quick and name in {"zap", "ai"}) and not (name == 'zap' and not web))
            if quick and name in {"zap", "ai"}:
                toggle.setChecked(False)
            toggle.blockSignals(False)
        if not self.owner.running() and self.progress.value() == 0:
            for index, name in enumerate(engine.SCANNER_ORDER):
                state = tr('Pronto') if config['policy'].get(name, {}).get('enabled') else tr('Não selecionado')
                if name == 'yara' and config['policy']['yara']['enabled']:
                    rules = config['policy']['yara']['rules']
                    state = tr('Regras configuradas') if self.owner.managed_yara_available() or rules and (rules != ['.secscan/yara/'] or (target/'.secscan/yara').exists()) else tr('Não configurado')
                if name == 'zap':
                    state = tr('Não aplicável') if not web else tr('Desativado em quick') if quick else self.target_status.text() if config['policy']['zap']['enabled'] else tr('Não selecionado')
                if name == 'ai':
                    state = (config['ai'].get('provider') or tr('Provider não escolhido')) if requested_ai else tr('Não solicitado')
                self.scanner_table.item(index, 1).setText(state)

    def set_running(self, running):
        self.project_type.setEnabled(not running)
        self.zap_target.setEnabled(not running)
        self.test_target.setEnabled(not running)
        self.start.setEnabled(not running)
        self.cancel.setEnabled(running)
        self.profile.setEnabled(not running)
        for toggle in self.toggles.values():
            toggle.setEnabled(not running)
        if running:
            self.progress.setValue(0)
            self.log.clear()
            self.progress_label.setText(tr("Preparando scanners e verificando Docker…"))

    @Slot(dict)
    def receive(self, event):
        if event['kind'] == 'ai_progress':
            message=tr('IA · grupo {group}/{groups} · tentativa {attempt}/{max_attempts}', **{key:event[key] for key in ('group','groups','attempt','max_attempts')})
            self.progress_label.setText(message)
            self.log.appendPlainText(message)
            return
        name = event["scanner"]
        row = engine.SCANNER_ORDER.index(name)
        if event["kind"] == "scanner_started":
            status = tr("EM EXECUÇÃO") if event["enabled"] else tr("NÃO SELECIONADO")
            fill_row(self.scanner_table, row, [engine.DISPLAY_NAMES[name], status, "—", "—", ""])
            if event["enabled"]:
                self.progress_label.setText(tr("Em execução: ") + engine.DISPLAY_NAMES[name])
        else:
            status = engine.STATUS_LABELS[event["status"]]
            fill_row(self.scanner_table, row, [engine.DISPLAY_NAMES[name], status, event["findings"], f"{event['duration_seconds']:.1f}s", ""])
            color_status(self.scanner_table, row, event["status"], self.owner.theme)
            self.progress.setValue(self.progress.value() + 1)
            self.log.appendPlainText(f"{engine.DISPLAY_NAMES[name]} · {status} · {event['findings']} findings · {event['duration_seconds']:.1f}s")
            if event.get('diagnostic'):
                message = event['diagnostic']['summary']
                item = QTableWidgetItem(message)
                item.setToolTip(message)
                self.scanner_table.setItem(row, 4, item)
                self.log.appendPlainText(message)
            self.progress_label.setText(tr("Concluído: ") + engine.DISPLAY_NAMES[name])


class ScannersPage(QWidget):
    def __init__(self, window):
        super().__init__()
        self.window = window
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll, _, self.layout = scroll_page()
        outer.addWidget(scroll)
        self.layout.addWidget(label(tr("Scanners e policies"), "title"))
        self.layout.addWidget(label(tr("Controle o que roda e o que bloqueia. Alterações só chegam ao YAML ao salvar a configuração."), "muted", wrap=True))
        self.grid = QGridLayout()
        self.cards = {}
        for index, name in enumerate(engine.SCANNER_ORDER):
            card = Card(engine.DISPLAY_NAMES[name])
            card.body.addWidget(label(DESCRIPTIONS[name], "muted", wrap=True))
            toggle = QCheckBox(tr("Habilitado") if name != "ai" else tr("Solicitar neste scan"))
            toggle.toggled.connect(lambda value, scanner=name: window.toggle_scanner(scanner, value))
            card.body.addWidget(toggle)
            policy = label("", "muted", wrap=True)
            last = label("", "muted", wrap=True)
            card.body.addWidget(policy)
            card.body.addWidget(last)
            card.body.addWidget(button(tr("Configurar policy"), lambda checked=False, scanner=name: window.edit_policy(scanner)))
            self.grid.addWidget(card, index // 2, index % 2)
            self.cards[name] = (toggle, policy, last)
        self.layout.addLayout(self.grid)
        self.layout.addWidget(button(tr("Salvar configuração do projeto"), window.save_config, primary=True))
        self.layout.addStretch()

    def refresh(self, config, summary, requested_ai):
        for name, (toggle, policy_label, last_label) in self.cards.items():
            section = config["ai"] if name == "ai" else config["policy"][name]
            toggle.blockSignals(True)
            toggle.setChecked(requested_ai if name == "ai" else section["enabled"])
            toggle.blockSignals(False)
            if name == "sca":
                text = "Version Risk: " + (", ".join(section["version_risk"]["fail_on"]) or tr("sem bloqueio por severidade"))
                text += tr("\nLicenças: ") + (tr("habilitado") if section["license"]["enabled"] else tr("desabilitado"))
            elif "fail_on" in section:
                text = tr("Bloqueantes: ") + (", ".join(section["fail_on"]) or tr("nenhum"))
                if name == "ai" and not section["fail_on_findings"]:
                    text = tr("Revisão manual · sem bloqueio automático")
            elif "fail_on_findings" in section:
                text = tr("Findings bloqueiam") if section["fail_on_findings"] else tr("Findings geram avisos")
            else:
                text = tr("Matches bloqueiam") if section.get("fail_on_match") else tr("Matches geram avisos")
            policy_label.setText(text)
            if name == 'yara' and not self.window.managed_yara_available() and (not section['rules'] or section['rules'] == ['.secscan/yara/'] and not (self.window.target/'.secscan/yara').exists()):
                policy_label.setText(text+tr('\nNão configurado · nenhuma regra YARA'))
            if name == 'zap' and not is_web_project(config):
                policy_label.setText(text+tr('\nNão aplicável · projeto não web'))
            own = (summary or {}).get("scanners", {}).get(name, {})
            last_label.setText(tr('Último: {status} · {count} findings · {seconds:.1f}s', status=engine.STATUS_LABELS.get(own.get('status'), tr('não executado')), count=own.get('total_findings', 0), seconds=own.get('duration_seconds', 0)))
            if own.get('diagnostic'):
                last_label.setText(last_label.text()+'\n'+own['diagnostic']['summary'])


class AIReviewPage(QWidget):
    def __init__(self, window):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll, _, layout = scroll_page()
        outer.addWidget(scroll)
        layout.addWidget(label("AI Security Review", "title"))
        privacy = Card(tr("Uma decisão explícita, a cada scan"))
        privacy.body.addWidget(label(tr("A revisão envia arquivos selecionados a um serviço externo. Antes do envio você verá o escopo e deverá confirmar. Retenção depende do provider; as chamadas não usam histórico. Findings exigem validação manual."), "muted", wrap=True))
        self.enabled = QCheckBox(tr("Solicitar revisão por IA nesta execução"))
        self.enabled.toggled.connect(lambda value: window.toggle_scanner("ai", value))
        privacy.body.addWidget(self.enabled)
        form = QFormLayout()
        self.provider = QComboBox()
        for name, title in PROVIDER_LABELS.items():
            self.provider.addItem(title, name)
        self.provider.setAccessibleName(tr("Provider de IA"))
        form.addRow(tr("Provider do scan"), self.provider)
        self.guide_mode = QComboBox()
        self.guide_mode.addItem(tr("Padrão"), "default")
        self.guide_mode.addItem(tr("Customizado"), "custom")
        self.guide_path = QLineEdit()
        self.guide_path.setPlaceholderText(tr("C:/meus-prompts/security.md"))
        self.guide_path.setAccessibleName(tr("Security guide customizado"))
        self.guide_mode.currentIndexChanged.connect(lambda: self.guide_path.setEnabled(self.guide_mode.currentData() == "custom"))
        form.addRow("Security guide", self.guide_mode)
        path_row = QHBoxLayout()
        path_row.addWidget(self.guide_path)
        path_row.addWidget(button(tr("Selecionar"), window.choose_guide))
        form.addRow(tr("Caminho customizado"), wrap_layout(path_row))
        privacy.body.addLayout(form)
        self.guide_status = label("", "muted", wrap=True)
        privacy.body.addWidget(self.guide_status)
        layout.addWidget(privacy)
        self.usage_summary=label(tr('Tokens/custo: nenhum scan de IA disponível. A estimativa prévia aparece antes de confirmar o envio.'),'muted',wrap=True)
        layout.addWidget(self.usage_summary)
        grid = QGridLayout()
        self.providers = {}
        for index, (name, title) in enumerate(PROVIDER_LABELS.items()):
            card = Card(title)
            enabled = QCheckBox(tr("Provider habilitado"))
            model = QLineEdit()
            model.setPlaceholderText(tr("Informe um modelo compatível"))
            model.setAccessibleName(title + " model")
            key = QLineEdit()
            key.setEchoMode(QLineEdit.EchoMode.Password)
            key.setMaxLength(2500)
            key.setPlaceholderText(tr("Somente memória, salvo se você optar pelo cofre"))
            key.setAccessibleName(title + " API key")
            base = QComboBox()
            base.setEditable(name == 'qwen')
            base.addItems(PROVIDER_BASE_URLS.get(name, ("https://api.openai.com/v1" if name == "openai" else "https://api.anthropic.com/v1",)))
            base.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
            base.setMinimumContentsLength(15)
            base.setToolTip(tr("Apenas endpoints oficiais. Para Qwen, selecione a região da sua chave."))
            save = QCheckBox(tr("Salvar chave no cofre do Windows"))
            save.setToolTip(tr("Opcional. A chave nunca vai para YAML, JSON, logs ou dashboard."))
            status = label(tr("Chave não configurada"), "muted")
            form = QFormLayout()
            form.addRow(enabled)
            form.addRow("Model", model)
            if name == 'deepseek':
                form.addRow(label(tr('API: deepseek-v4-pro ou deepseek-flash. DeepSeek-V4-Pro-0813 é a versão; será usado deepseek-v4-pro.'), 'muted', wrap=True))
            if name == 'qwen':
                form.addRow(label(tr('Use o ID oficial do modelo e a região/workspace da chave. Base URL aceita endpoints oficiais maas.aliyuncs.com.'), 'muted', wrap=True))
            form.addRow("Base URL", base)
            form.addRow("API key", key)
            card.body.addLayout(form)
            card.body.addWidget(status)
            card.body.addWidget(save)
            actions = QHBoxLayout()
            actions.addWidget(button(tr("Salvar provider"), lambda checked=False, provider=name: window.save_provider(provider)))
            actions.addWidget(button(tr("Remover chave salva"), lambda checked=False, provider=name: window.delete_key(provider)))
            test = None
            if name in {'deepseek', 'qwen'}:
                test = button(tr("Testar conexão"), lambda checked=False, provider=name: window.test_ai_connection(provider), name='testConnection_'+name)
                card.body.addWidget(label(tr("Teste envia apenas uma mensagem mínima, sem arquivos. Pode consumir tokens da API."), "muted", wrap=True))
                card.body.addWidget(test)
            card.body.addLayout(actions)
            key.textChanged.connect(lambda text, status_label=status: status_label.setText(tr("Chave disponível nesta sessão") if text else tr("Campo de chave vazio; cofre consultado apenas após consentimento")))
            grid.addWidget(card, index // 2, index % 2)
            self.providers[name] = {"enabled": enabled, "model": model, "key": key, "base": base, "save": save, "status": status, 'test': test}
        layout.addLayout(grid)
        layout.addStretch()

    def refresh(self, config, requested_ai):
        ai = config["ai"]
        selected = ai.get("provider") or "deepseek"
        self.provider.setCurrentIndex(max(0, self.provider.findData(selected)))
        self.enabled.blockSignals(True)
        self.enabled.setChecked(requested_ai)
        self.enabled.blockSignals(False)
        self.guide_mode.setCurrentIndex(1 if ai["guide"]["mode"] == "custom" else 0)
        self.guide_path.setText(ai["guide"].get("path") or "")
        self.guide_path.setEnabled(ai["guide"]["mode"] == "custom")
        default_path = Path(__file__).parents[1] / "prompts" / "security.md"
        self.guide_status.setText(tr("Guide padrão: ") + str(default_path) + (tr(" · disponível") if default_path.is_file() else tr(" · não encontrado; selecione customizado")))
        for name, fields in self.providers.items():
            settings = ai.get("providers", {}).get(name, {})
            fields["enabled"].setChecked(settings.get("enabled", name in {"openai", "anthropic"}))
            fields["model"].setText(settings.get("model") or (ai.get("model") if name == selected else "") or "")
            if settings.get("base_url"):
                fields["base"].setCurrentText(settings["base_url"])

    def values(self):
        selected = self.provider.currentData()
        providers = {name: {"enabled": fields["enabled"].isChecked(), "model": fields["model"].text().strip() or None,
                           "base_url": fields["base"].currentText()} for name, fields in self.providers.items()}
        return {"provider": selected, "model": providers[selected]["model"], "base_url": providers[selected]["base_url"],
                "providers": providers, "guide": {"mode": self.guide_mode.currentData(), "path": self.guide_path.text().strip() or None}}

    def clear_keys(self):
        for fields in self.providers.values():
            fields["key"].clear()

    def update_usage(self,summary):
        own=(summary or {}).get('scanners',{}).get('ai',{})
        usage=own.get('usage')
        if not usage:
            self.usage_summary.setText(tr('Tokens/custo: nenhum scan de IA disponível. A estimativa prévia aparece antes de confirmar o envio.'))
            return
        cost=own.get('cost')
        # Older reports had usage but no cost. Compute an explicitly dated estimate locally.
        if not cost:
            from ..ai_cost import estimate_cost
            cost=estimate_cost(own.get('provider'),own.get('model'),usage)
        price=tr('US$ {minimum:.4f}–{maximum:.4f} (estimativa)', minimum=cost['minimum'], maximum=cost['maximum']) if cost else tr('indisponível; configure tarifas em Scanners → AI policy')
        self.usage_summary.setText(tr('Última IA: {incoming:,} entrada · {outgoing:,} saída · {requests} requisições · Custo: {price}\nGrupos: {completed}/{total}. Tokens da saída incluem reasoning quando informado pelo provider.', incoming=usage.get('input_tokens',0), outgoing=usage.get('output_tokens',0), requests=usage.get('requests',0), price=price, completed=own.get('groups_completed','?'), total=own.get('groups_total','?')))


class SettingsPage(QWidget):
    def __init__(self, window):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll, _, layout = scroll_page()
        outer.addWidget(scroll)
        layout.addWidget(label(tr("Configurações"), "title"))
        layout.addWidget(label(tr("Preferências locais e parâmetros do projeto. Credenciais ficam fora dessas configurações."), "muted", wrap=True))
        card = Card(tr("Workspace e aparência"))
        form = QFormLayout()
        self.theme = QComboBox()
        self.theme.addItem(tr("Escuro · Midnight Violet"), "dark")
        self.theme.addItem(tr("Claro · Dusty Olive"), "light")
        self.theme.currentIndexChanged.connect(lambda: window.apply_theme(self.theme.currentData()))
        self.language = QComboBox()
        for code, name in LANGUAGES.items():
            self.language.addItem(name, code)
        self.language.setCurrentIndex(self.language.findData(window.language))
        self.language.setAccessibleName(tr('Idioma'))
        form.addRow(tr('Idioma'), self.language)
        form.addRow(label(tr('A alteração de idioma será aplicada ao reiniciar o Kekkai.'), 'muted', wrap=True))
        self.default_directory = QLineEdit()
        self.project_name = QLineEdit()
        self.open_dashboard = QCheckBox(tr("Abrir dashboard ao final do scan"))
        form.addRow(tr("Tema"), self.theme)
        form.addRow(tr("Diretório inicial"), self.default_directory)
        form.addRow(tr("Nome do projeto"), self.project_name)
        form.addRow(self.open_dashboard)
        card.body.addLayout(form)
        layout.addWidget(card)
        scan = Card(tr("Scan e performance"))
        form = QFormLayout()
        self.excludes = QPlainTextEdit()
        self.excludes.setMaximumHeight(140)
        self.excludes.setAccessibleName(tr("Exclusões de scan"))
        self.parallel = QCheckBox(tr("Executar scanners independentes em paralelo"))
        self.workers = QSpinBox()
        self.workers.setRange(1, 8)
        self.cache_mode = QComboBox()
        self.cache_mode.addItems(["smart", "ephemeral", "persistent"])
        self.ttl = QDoubleSpinBox()
        self.ttl.setRange(.1, 8760)
        self.ttl.setSuffix(" h")
        self.cache_size = QSpinBox()
        self.cache_size.setRange(1, 100000)
        self.cache_size.setSuffix(" MB")
        self.unlimited = QCheckBox(tr("Sem orçamento de tamanho"))
        self.keep_cache = QCheckBox(tr("Manter scan cache em smart"))
        form.addRow(tr("Exclusões (um path por linha)"), self.excludes)
        form.addRow(self.parallel)
        form.addRow(tr("Máximo de workers"), self.workers)
        form.addRow("Cache Trivy", self.cache_mode)
        form.addRow(tr("TTL da base"), self.ttl)
        form.addRow(tr("Orçamento de cache"), self.cache_size)
        form.addRow(self.unlimited)
        form.addRow(self.keep_cache)
        scan.body.addLayout(form)
        scan.body.addWidget(label(tr("Bases úteis nunca são apagadas automaticamente para cumprir o orçamento. Persistent mantém caches; ephemeral é descartado após a execução."), "muted", wrap=True))
        layout.addWidget(scan)
        reports = Card(tr("Relatórios"))
        form = QFormLayout()
        self.reporting = QCheckBox(tr("Salvar relatórios sanitizados"))
        self.dashboard = QCheckBox(tr("Gerar dashboard HTML offline"))
        self.output = QLineEdit()
        form.addRow(self.reporting)
        form.addRow(self.dashboard)
        form.addRow(tr("Diretório de saída"), self.output)
        reports.body.addLayout(form)
        reports.body.addWidget(button(tr("Salvar preferências e aplicar"), window.save_settings, primary=True))
        reports.body.addWidget(button(tr("Salvar também no .secscan.yml do projeto"), window.save_config))
        layout.addWidget(reports)
        layout.addStretch()

    def refresh(self, config, preferences):
        self.theme.blockSignals(True)
        self.theme.setCurrentIndex(0 if preferences["theme"] == "dark" else 1)
        self.theme.blockSignals(False)
        self.default_directory.setText(preferences["default_directory"])
        self.project_name.setText(config["project"]["name"])
        self.open_dashboard.setChecked(preferences["open_dashboard"])
        self.excludes.setPlainText("\n".join(config["scan"]["exclude_paths"]))
        self.parallel.setChecked(config["performance"]["parallel"])
        self.workers.setValue(config["performance"]["max_workers"])
        cache = config["performance"]["trivy_cache"]
        self.cache_mode.setCurrentText(cache["mode"])
        self.ttl.setValue(cache["ttl_hours"])
        self.cache_size.setValue(cache["max_size_mb"] or 750)
        self.unlimited.setChecked(cache["max_size_mb"] is None)
        self.keep_cache.setChecked(cache["keep_scan_cache"])
        self.reporting.setChecked(config["reporting"]["enabled"])
        self.dashboard.setChecked(config["reporting"]["dashboard"])
        self.output.setText(config["reporting"]["output_dir"])

    def apply(self, config):
        config["project"]["name"] = self.project_name.text().strip()
        config["scan"]["exclude_paths"] = [x.strip() for x in self.excludes.toPlainText().splitlines() if x.strip()]
        config["performance"].update(parallel=self.parallel.isChecked(), max_workers=self.workers.value(),
            trivy_cache={"mode": self.cache_mode.currentText(), "ttl_hours": self.ttl.value(),
                         "max_size_mb": None if self.unlimited.isChecked() else self.cache_size.value(), "keep_scan_cache": self.keep_cache.isChecked()})
        config["reporting"].update(enabled=self.reporting.isChecked(), dashboard=self.dashboard.isChecked(), output_dir=self.output.text().strip())


class ProjectsPage(QWidget):
    def __init__(self, window):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 22, 26, 26)
        layout.addWidget(label(tr("Projetos"), "title"))
        layout.addWidget(label(tr("Diretórios recentes deste computador. Nenhum source code é copiado para o workspace."), "muted", wrap=True))
        card = Card(tr("Recentes"))
        self.list = QListWidget()
        self.list.itemDoubleClicked.connect(lambda item: window.select_project(Path(item.text())))
        self.list.setAccessibleName(tr("Projetos recentes"))
        card.body.addWidget(self.list)
        card.body.addWidget(button(tr("Abrir projeto selecionado"), lambda: window.select_project(Path(self.list.currentItem().text())) if self.list.currentItem() else window.choose_project()))
        card.body.addWidget(button(tr("Adicionar projeto"), window.choose_project, primary=True))
        layout.addWidget(card, 1)


class ReportsPage(QWidget):
    def __init__(self, window):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 22, 26, 26)
        layout.addWidget(label(tr("Relatórios"), "title"))
        layout.addWidget(label(tr("Último resultado e execuções arquivadas pela GUI, com dados sanitizados."), "muted", wrap=True))
        card = Card(tr("Execuções disponíveis"))
        self.entries = []
        self.list = table([tr("Projeto"), tr("Data"), tr("Resultado"), "Findings", tr("Tempo")])
        self.list.setAccessibleName(tr("Execuções disponíveis"))
        self.list.itemDoubleClicked.connect(lambda item: window.open_report("dashboard"))
        card.body.addWidget(self.list)
        self.path = label(tr("Nenhum relatório selecionado"), "muted", wrap=True)
        self.list.itemSelectionChanged.connect(self.selection_changed)
        card.body.addWidget(self.path)
        actions = QHBoxLayout()
        for text, kind in [(tr("Abrir summary.json"), "summary"), ("Raw reports", "raw"), ("Dashboard", "dashboard"), (tr("Exportar ZIP"), "export"),(tr('Excluir relatório'),'delete')]:
            actions.addWidget(button(text, lambda checked=False, action=kind: window.open_report(action)))
        card.body.addLayout(actions)
        self.empty = label(tr("Execute um scan com reporting habilitado para criar o primeiro relatório."), "muted", wrap=True)
        card.body.addWidget(self.empty)
        layout.addWidget(card, 1)

    def refresh(self, entries):
        self.entries = entries
        self.list.setRowCount(len(entries))
        self.empty.setVisible(not entries)
        for index, entry in enumerate(entries):
            summary = entry["summary"]
            fill_row(self.list, index, [summary.get("project", tr("Projeto")), summary.get("timestamp", "—"),
                     engine.RESULT_LABELS.get(summary.get("result"), "—"), summary.get("totals", {}).get("total", 0),
                     f"{summary.get('performance', {}).get('total_seconds', 0):.1f}s"])
        if entries:
            self.list.selectRow(0)

    def selected(self):
        row = self.list.currentRow()
        return self.entries[row] if 0 <= row < len(self.entries) else None

    def selection_changed(self):
        selected = self.selected()
        self.path.setText(selected["path"] if selected else tr("Nenhum relatório selecionado"))


class AboutPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(38, 34, 38, 34)
        layout.addWidget(label("Kekkai Desktop", "title"))
        layout.addWidget(label(tr("Um workspace local para entender e priorizar riscos de software."), "muted", wrap=True))
        card = Card(tr("Créditos"))
        card.body.addWidget(label("Thayner Kesley", "title"))
        card.body.addWidget(label(tr("Criador do projeto Kekkai"), "muted"))
        card.body.addWidget(label(tr("Interface desktop com PySide6 / Qt. Semgrep CE, Gitleaks, Trivy, YARA-X e OWASP ZAP mantêm suas respectivas licenças e créditos. A análise de licença é uma indicação de risco; findings de IA requerem validação manual."), "muted", wrap=True))
        layout.addWidget(card)
        layout.addStretch()
