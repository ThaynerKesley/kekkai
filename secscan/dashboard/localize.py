"""Translate template-owned text before any user report data is embedded."""
import ast
import json
import re
from html import escape, unescape

from ..i18n import translate

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
