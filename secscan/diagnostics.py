"""Safe, normalized diagnostics. External prose is never copied into reports."""
from .i18n import tr
import re


def diagnostic(error_type, code, summary, *, recoverable=False, **details):
    return {"error_type": error_type, "error_code": str(code), "summary": summary,
            "recoverable": recoverable, "technical_details": details}


def attach(result, info):
    result["diagnostic"] = info
    result["error"] = info["summary"]
    return result


def process_diagnostic(outcome, scanner):
    text = (outcome.get("stderr", "") + "\n" + outcome.get("stdout", "")).lower()
    code = outcome.get("exit_code")
    details = {"exit_code": code, "stdout_bytes": len(outcome.get("stdout", "").encode()),
               "stderr_bytes": len(outcome.get("stderr", "").encode())}
    if code in (137, -9):
        return diagnostic("scanner_error", code, tr("Processo encerrado inesperadamente; verifique o limite de memória."), **details)
    if code in (143, -15):
        return diagnostic("scanner_error", code, tr("Processo do scanner foi interrompido."), **details)
    if any(text in (outcome.get("error") or "").lower() for text in ("tempo esgotado", "timeout after")):
        return diagnostic("timeout", code, tr("O scanner excedeu seu tempo limite."), recoverable=True, **details)
    if outcome.get("infrastructure"):
        return diagnostic("dependency_missing", code, tr("Docker ou imagem do scanner indisponível. Verifique Docker Desktop e o PATH."), recoverable=True, **details)
    if scanner == 'Semgrep' and any(x in text for x in ("connection", "resolve", "registry", "ssl", "httperror", "network")):
        return diagnostic("network_error", code, tr("Não foi possível acessar o Semgrep Registry ou carregar suas regras."), recoverable=True, **details)
    if code in (4, 5, 7, 8):
        return diagnostic("ruleset_error", code, "Ruleset, padrão ou linguagem inválidos; verifique a configuração do Semgrep.", **details)
    return diagnostic("scanner_error", code, tr('{v0} não concluiu de forma confiável (código {v1}).', v0=scanner, v1=code), **details)


def semgrep_diagnostic(outcome, data):
    errors = data.get("errors", [])
    scanned = data.get("paths", {}).get("scanned", []) if isinstance(data.get("paths"), dict) else []
    metadata = []
    for error in errors:
        if not isinstance(error, dict):
            return True, diagnostic("scanner_error", "invalid_errors", tr("Semgrep retornou um diagnóstico inválido."))
        kind = error.get("type", "Unknown")
        kind = kind[0] if isinstance(kind, list) and kind else kind
        kind = kind if isinstance(kind, str) and re.fullmatch(r"[A-Za-z_]+", kind) else "Unknown"
        # Only identifiers/locations are retained; error messages may contain source excerpts.
        path = error.get("path")
        start = error.get("spans", [{}])[0].get("start", {}) if error.get("spans") else {}
        metadata.append({"type": kind, "code": error.get("code") if type(error.get("code")) is int else None,
                         "level": str(error.get("level", "error")).lower(),
                         "file": path if isinstance(path, str) and len(path) < 1024 else None,
                         "line": start.get("line") if type(start.get("line")) is int else None})
    partial_types = {"ParseError", "PartialParsing", "LexicalError", "Timeout", "OutOfMemory"}
    ruleset_types = {'PatternParseError', 'RuleParseError', 'InvalidRuleSchemaError', 'UnknownLanguageError', 'InvalidYaml', 'SemgrepRuleError'}
    fatal = outcome.get("error") or outcome.get("exit_code") not in (0, 1, 3)
    fatal = fatal or any(e['type'] in ruleset_types for e in metadata)
    fatal = fatal or any(e["type"] not in partial_types and e["level"] not in {"warn", "warning"} for e in metadata)
    # An invalid-target exit without specific evidence of isolated file errors is fatal.
    fatal = fatal or (outcome.get("exit_code") == 3 and (not metadata or any(e["type"] not in partial_types for e in metadata)))
    failed = {e["file"] for e in metadata if e["file"]}
    fatal = fatal or bool(metadata and not data.get("results") and (not scanned or set(scanned) <= failed))
    if fatal:
        info = process_diagnostic(outcome, "Semgrep")
        if any(e['type'] in ruleset_types for e in metadata):
            info.update(error_type='ruleset_error', summary=tr('Semgrep rejeitou regras ou configuração; o scan não pode ser considerado completo.'))
        elif metadata and all(e['type'] in {'ParseError', 'PartialParsing', 'LexicalError'} for e in metadata):
            info.update(error_type='parse_error', summary=tr('Erros de parsing impediram cobertura confiável do alvo; o scan não foi concluído.'))
        info["technical_details"].update(errors=metadata, version=data.get("version"), partial=bool(data.get("results")))
        return True, info
    if metadata:
        count = len(failed) or len(metadata)
        parsing = all(e["type"] in {"ParseError", "PartialParsing", "LexicalError"} for e in metadata)
        return False, diagnostic("parse_error" if parsing else "scanner_error", "partial_scan",
            tr('{v0} arquivo(s) com análise parcial por {v1}. Os demais resultados foram preservados.', v0=count, v1='erro de parsing' if parsing else 'limite ou aviso do scanner'),
            recoverable=True, errors=metadata, version=data.get("version"), exit_code=outcome.get("exit_code"), partial=True)
    return False, None


def safe_semgrep_errors(data):
    _, info = semgrep_diagnostic({"exit_code": 0, "error": None}, data)
    return info["technical_details"].get("errors", []) if info else []
