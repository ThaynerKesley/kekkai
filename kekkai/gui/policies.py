"""Visual scanner policies, validated against the existing config contracts."""
from ..i18n import tr
from copy import deepcopy

from PySide6.QtWidgets import QDialog, QVBoxLayout, QFormLayout, QCheckBox, QLineEdit, QPlainTextEdit, QComboBox, QDoubleSpinBox, QSpinBox, QDialogButtonBox, QMessageBox, QScrollArea, QWidget

from ..configuration import validate
from .widgets import label


class PolicyDialog(QDialog):
    def __init__(self, name: str, config: dict, parent=None):
        super().__init__(parent)
        self.name = name
        self.config = deepcopy(config)
        self.result_config = None
        self.controls = {}
        self.setWindowTitle("Policy · " + name.upper())
        self.resize(560, 620)
        layout = QVBoxLayout(self)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        self.form = QFormLayout(content)
        self.form.setSpacing(14)
        scroll.setWidget(content)
        layout.addWidget(scroll)
        section = self.config["ai"] if name == "ai" else self.config["policy"][name]
        if name in {"semgrep", "gitleaks", "ai"}:
            self.boolean("fail_on_findings", tr("Bloquear quando houver findings"), section["fail_on_findings"])
        if name in {"sca", "owasp", "ai"}:
            thresholds = section["version_risk"]["fail_on"] if name == "sca" else section["fail_on"]
            self.severities("fail_on", thresholds)
        if name == "sca":
            self.boolean("version_enabled", tr("Version Risk habilitado"), section["version_risk"]["enabled"])
            licenses = section["license"]
            self.boolean("license_enabled", tr("Licenciamento habilitado"), licenses["enabled"])
            self.boolean("full_scan", tr("Análise completa de licenças (mais lenta)"), licenses["full_scan"])
            for field, title in [("allow", tr("Licenças permitidas")), ("deny", tr("Licenças bloqueadas")), ("fail_on_classification", tr("Classificações bloqueantes"))]:
                self.text(field, title + tr(" (separadas por vírgula)"), ", ".join(licenses[field]))
            self.form.addRow(label(tr("Allow vazio não restringe licenças. Deny sempre bloqueia. Esta análise é indicação de risco, não parecer jurídico."), "muted", wrap=True))
        elif name == "yara":
            rules = QPlainTextEdit("\n".join(section["rules"]))
            rules.setMaximumHeight(120)
            rules.setAccessibleName(tr("Arquivos e pastas de regras YARA"))
            self.controls["rules"] = rules
            self.form.addRow(tr("Regras (um path por linha)"), rules)
            self.boolean("fail_on_match", tr("Qualquer match bloqueia"), section["fail_on_match"])
            size = QDoubleSpinBox()
            size.setRange(.1, 1024)
            size.setValue(section["max_file_size_mb"])
            self.controls["max_file_size_mb"] = size
            self.form.addRow(tr("Tamanho máximo de arquivo (MB)"), size)
            timeout = QSpinBox()
            timeout.setRange(1, 300)
            timeout.setValue(section["timeout_seconds"])
            self.controls["timeout_seconds"] = timeout
            self.form.addRow(tr("Timeout por arquivo (s)"), timeout)
        elif name == "owasp":
            self.combo("version", tr("Edição OWASP"), ["auto", "2025", "2021", "2017"], str(section["version"]))
        elif name == "zap":
            self.text("target", tr("Aplicação local (URL)"), section["target"])
            self.form.addRow(label(tr("Modo baseline. O alvo precisa estar disponível; apenas hosts locais são permitidos."), "muted", wrap=True))
            for threshold in ("FAIL", "WARN"):
                self.boolean(threshold, tr("Bloquear alertas ") + threshold, threshold in section["fail_on"])
        if name == "ai":
            attempts=QSpinBox();attempts.setRange(1,3);attempts.setValue(section.get('max_attempts',2));self.controls['max_attempts']=attempts
            self.form.addRow(tr('Tentativas por grupo'),attempts)
            for key,title in [('max_output_tokens',tr('Tokens de saída iniciais')),('max_retry_output_tokens',tr('Teto de saída das tentativas'))]:
                value=QSpinBox();value.setRange(128,393216);value.setValue(section.get(key,32768));self.controls[key]=value;self.form.addRow(title,value)
            self.boolean('manual_pricing',tr('Usar tarifas manuais (USD por milhão)'),section.get('pricing',{}).get('input_per_million') is not None)
            for key,title in [('input_per_million',tr('Preço entrada / 1M tokens')),('output_per_million',tr('Preço saída / 1M tokens'))]:
                value=QDoubleSpinBox();value.setRange(0,10000);value.setDecimals(6);value.setValue(section.get('pricing',{}).get(key) or 0);self.controls[key]=value;self.form.addRow(title,value)
            self.combo("minimum_confidence", tr("Confiança mínima para bloqueio"), ["HIGH", "MEDIUM", "LOW"], section["minimum_confidence"])
            self.form.addRow(label(tr("Findings de IA requerem validação manual. Por padrão não bloqueiam."), "muted", wrap=True))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.commit)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def boolean(self, key, title, value):
        widget = QCheckBox(title)
        widget.setChecked(bool(value))
        self.controls[key] = widget
        self.form.addRow(widget)

    def text(self, key, title, value):
        widget = QLineEdit(value)
        widget.setAccessibleName(title)
        self.controls[key] = widget
        self.form.addRow(title, widget)

    def combo(self, key, title, values, current):
        widget = QComboBox()
        widget.addItems(values)
        widget.setCurrentText(current)
        self.controls[key] = widget
        self.form.addRow(title, widget)

    def severities(self, key, selected):
        values = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        if self.name != "ai":
            values.append("INFO")
        if self.name == "sca":
            values.append("UNKNOWN")
        for severity in values:
            self.boolean(key + "." + severity, tr("Bloquear ") + severity, severity in selected)

    def commit(self):
        section = self.config["ai"] if self.name == "ai" else self.config["policy"][self.name]
        if self.name in {"semgrep", "gitleaks", "ai"}:
            section["fail_on_findings"] = self.controls["fail_on_findings"].isChecked()
        if self.name in {"sca", "owasp", "ai"}:
            selected = [key.split(".", 1)[1] for key, control in self.controls.items() if key.startswith("fail_on.") and control.isChecked()]
            (section["version_risk"] if self.name == "sca" else section)["fail_on"] = selected
        if self.name == "sca":
            section["version_risk"]["enabled"] = self.controls["version_enabled"].isChecked()
            section["license"].update(enabled=self.controls["license_enabled"].isChecked(), full_scan=self.controls["full_scan"].isChecked())
            for key in ("allow", "deny", "fail_on_classification"):
                section["license"][key] = [x.strip() for x in self.controls[key].text().split(",") if x.strip()]
        elif self.name == "yara":
            section.update(rules=[x.strip() for x in self.controls["rules"].toPlainText().splitlines() if x.strip()],
                           fail_on_match=self.controls["fail_on_match"].isChecked(), max_file_size_mb=self.controls["max_file_size_mb"].value(),
                           timeout_seconds=self.controls["timeout_seconds"].value())
        elif self.name == "owasp":
            section["version"] = self.controls["version"].currentText()
        elif self.name == "zap":
            section.update(target=self.controls["target"].text().strip(), fail_on=[x for x in ("FAIL", "WARN") if self.controls[x].isChecked()])
        elif self.name == "ai":
            for key in ('max_attempts','max_output_tokens','max_retry_output_tokens'):section[key]=self.controls[key].value()
            section['pricing']={key:self.controls[key].value() if self.controls['manual_pricing'].isChecked() else None for key in ('input_per_million','output_per_million')}
            section["minimum_confidence"] = self.controls["minimum_confidence"].currentText()
        try:
            validate(self.config)
        except ValueError:
            QMessageBox.warning(self, tr("Configuração inválida"), tr("Verifique thresholds, paths e limites. Nenhuma alteração foi aplicada."))
            return
        self.result_config = self.config
        self.accept()
