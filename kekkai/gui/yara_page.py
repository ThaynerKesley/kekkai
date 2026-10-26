"""Rule-library presentation; compilation/downloads belong to the local service."""
from ..i18n import tr
from PySide6.QtWidgets import QWidget,QVBoxLayout,QHBoxLayout,QCheckBox,QComboBox,QSpinBox,QLineEdit
from .widgets import Card,button,label,scroll_page
from .pages import table,fill_row
from ..yara_library import engine_status


class YaraRulesPage(QWidget):
    def __init__(self,window):
        super().__init__()
        self.owner=window
        layout=QVBoxLayout(self);layout.setContentsMargins(0,0,0,0)
        scroll,_,body=scroll_page();layout.addWidget(scroll)
        body.addWidget(label('YARA Rules','title'))
        body.addWidget(label(tr('Biblioteca validada de detecção e threat hunting. Match é um sinal para investigação, não confirmação de malware.'),'muted',wrap=True))
        self.engine=label('','muted',wrap=True);body.addWidget(self.engine)
        self.counts=label('','heading',wrap=True);body.addWidget(self.counts)
        setup=Card(tr('Fonte e atualização'))
        row=QHBoxLayout()
        self.tier=QComboBox();self.tier.addItems(['core','extended','full']);self.tier.setAccessibleName(tr('Pacote YARA Forge'))
        row.addWidget(self.tier)
        self.update_button=button(tr('Atualizar YARA Forge'),lambda:window.yara_action('update',tier=self.tier.currentText()),primary=True)
        self.import_button=button(tr('Importar .yar/.yara'),window.import_yara_rules)
        row.addWidget(self.update_button);row.addWidget(self.import_button);setup.body.addLayout(row)
        setup.body.addWidget(label(tr('Core é o padrão. Extended/Full são opções avançadas, com maior custo e possibilidade de falsos positivos. Download tem SHA-256 oficial e validação local antes de ativar.'),'muted',wrap=True))
        row=QHBoxLayout();self.auto=QCheckBox(tr('Atualizar automaticamente antes do scan, quando vencido'))
        self.hours=QSpinBox();self.hours.setRange(1,8760);self.hours.setSuffix(' h');self.hours.setValue(168)
        row.addWidget(self.auto);row.addWidget(self.hours)
        row.addWidget(button(tr('Salvar atualização'),window.save_yara_settings));setup.body.addLayout(row)
        self.feedback=label('','muted',wrap=True);setup.body.addWidget(self.feedback);body.addWidget(setup)
        libraries=Card(tr('Bibliotecas instaladas'))
        self.library_table=table([tr('Origem'),tr('Versão'),tr('Válidas'),tr('Inválidas'),tr('Ativas'),tr('Estado')]);self.library_table.setMinimumHeight(150)
        self.library_table.itemSelectionChanged.connect(self.show_rules)
        libraries.body.addWidget(self.library_table)
        row=QHBoxLayout()
        self.validate_button=button(tr('Validar selecionada'),lambda:window.yara_action('validate'))
        self.disable_button=button(tr('Ativar/desativar biblioteca'),lambda:window.yara_action('toggle'))
        row.addWidget(self.validate_button);row.addWidget(self.disable_button);libraries.body.addLayout(row)
        self.history=QComboBox();self.history.setAccessibleName(tr('Histórico YARA'))
        row=QHBoxLayout();row.addWidget(self.history,1);self.rollback_button=button('Rollback',lambda:window.yara_action('rollback',identifier=self.history.currentData()));row.addWidget(self.rollback_button)
        libraries.body.addLayout(row);body.addWidget(libraries)
        rules=Card(tr('Regras e compatibilidade'))
        self.search=QLineEdit();self.search.setPlaceholderText(tr('Buscar regra, autor ou licença'));self.search.textChanged.connect(self.show_rules)
        rules.body.addWidget(self.search)
        self.rule_table=table([tr('Regra'),tr('Autor'),tr('Licença'),tr('Origem'),tr('Ativa')]);self.rule_table.setMinimumHeight(280);rules.body.addWidget(self.rule_table)
        self.rule_disable=button(tr('Desativar/reativar regra selecionada'),lambda:window.yara_action('rule_toggle'))
        rules.body.addWidget(self.rule_disable)
        self.issues=label('','muted',wrap=True);rules.body.addWidget(self.issues);body.addWidget(rules);body.addStretch()
        self.entries=[];self.visible_rules=[]

    def selected(self):
        row=self.library_table.currentRow()
        return self.entries[row] if 0<=row<len(self.entries) else None

    def refresh(self,state):
        engine=engine_status()
        self.engine.setText(tr('Motor: YARA-X {version} · {compatibility} · biblioteca offline local', version=engine['version'] or tr('não instalado'), compatibility=tr('compatível') if engine['compatible'] else tr('requer yara-x >=1.21')))
        self.entries=state['libraries']
        valid=sum(e['valid'] for e in self.entries);invalid=sum(e['invalid'] for e in self.entries);active=sum(e['active'] for e in self.entries if e['enabled'])
        self.counts.setText(tr('Instaladas: {installed} · Válidas: {valid} · Inválidas: {invalid} · Ativas: {active}', installed=valid+invalid, valid=valid, invalid=invalid, active=active))
        self.feedback.setText(state.get('last_error') or (tr('Última versão validada disponível offline.') if valid else tr('Nenhuma regra disponível. Atualize Core ou importe suas regras.')))
        self.tier.setCurrentText(state['tier']);self.auto.setChecked(state['auto_update']);self.hours.setValue(state['update_hours'])
        self.library_table.setRowCount(len(self.entries))
        for index,entry in enumerate(self.entries):fill_row(self.library_table,index,[entry['origin'],entry['version'],entry['valid'],entry['invalid'],entry['active'] if entry['enabled'] else 0,tr('Ativada') if entry['enabled'] else tr('Desativada')])
        self.history.clear()
        for entry in reversed(state['snapshots']):self.history.addItem(f"{entry['origin']} · {entry['version']} · {entry['installed_at'][:19]}",entry['id'])
        if self.entries:self.library_table.selectRow(0)
        else:self.show_rules()

    def show_rules(self,*args):
        entry=self.selected()
        query=self.search.text().casefold()
        self.visible_rules=[r for r in (entry or {}).get('rules',[]) if query in (r['name']+' '+str(r['author'])+' '+str(r['license'])).casefold()][:250]
        self.rule_table.setRowCount(len(self.visible_rules))
        for index,r in enumerate(self.visible_rules):fill_row(self.rule_table,index,[r['name'],r['author'],r['license'],r['origin'],tr('Sim') if r['active'] and entry['enabled'] else tr('Não')])
        problems=(entry or {}).get('issues',[])
        self.issues.setText(tr('Até 250 regras por filtro. ')+ (tr('\nIncompatibilidades: ')+'\n'.join(f"{i.get('rule') or i.get('file') or 'Regra'} · {i.get('code','')} {i['reason']}" for i in problems[:15]) if problems else tr('\nNenhuma incompatibilidade registrada nesta seleção.')))

    def set_busy(self,busy):
        for control in (self.update_button,self.import_button,self.validate_button,self.disable_button,self.rollback_button,self.rule_disable):control.setEnabled(not busy)
        if busy:self.feedback.setText(tr('Processando regras em segundo plano; versão ativa preservada até a validação concluir…'))
