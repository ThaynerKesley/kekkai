"""Translate template-owned text before any user report data is embedded."""
import ast
import json
import re
from html import escape, unescape

from ..i18n import translate


def localize_summary(summary: dict, language: str) -> dict:
    # Localize only Kekkai-owned narratives. Original scanner/AI/user data is retained.
    from ..engine import executive_copy, RESULT_MESSAGES

    result = {**summary, "language": language}
    if summary.get("result") in RESULT_MESSAGES:
        message = dict.__getitem__(RESULT_MESSAGES, summary["result"])
        result["message"] = translate(message, language)
    findings = []
    for finding in summary.get("findings", []):
        if finding.get("scanner") in {"gitleaks", "semgrep", "owasp", "sca", "trivy", "zap", "yara"} and not finding.get("ai_assisted"):
            finding = {**finding, **executive_copy(finding["scanner"], finding.get("technical", {}), "", language=language)}
        findings.append(finding)
    result["findings"] = findings
    return result

_QUOTED = re.compile(r'"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27')


def localize_template(template: str, language: str) -> str:
    if language == 'pt_BR':
        return template
    html, separator, javascript = template.partition('  <script>')

    def text_node(match):
        text = match[1]
        return '>' + escape(translate(unescape(text), language), quote=False) + '<'

    html = re.sub(r'>([^<>]+)<', text_node, html)
    html = re.sub(r'(aria-label|placeholder|title|alt)="([^"]*)"',
                  lambda m: m[1] + '="' + escape(translate(unescape(m[2]), language), quote=True) + '"', html)
    html = html.replace('lang="pt-BR"', 'lang="en"')

    def literal(match):
        try:
            value = ast.literal_eval(match[0])
        except (SyntaxError, ValueError):
            return match[0]
        translated = translate(value, language)
        return json.dumps(translated, ensure_ascii=False) if translated != value else match[0]

    return html + separator + _QUOTED.sub(literal, javascript)
