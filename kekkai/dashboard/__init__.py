"""Standalone offline renderer, used by Qt WebEngine and exported reports."""
import json
import base64
from pathlib import Path

from ..themes import css_tokens
from ..skins import get_skin
from ..i18n import get_language, normalize_language
from .localize import localize_template, localize_summary

TEMPLATE = (Path(__file__).parent / "template.html").read_text(encoding="utf-8")
STYLE = (Path(__file__).parent / "styles.css").read_text(encoding="utf-8")


def appearance(skin: str | None = None) -> dict[str, str]:
    selected = get_skin(skin)
    return {"skin": selected.identifier, "css": css_tokens(selected.identifier) + "\n" + STYLE,
            "wordmark": 'data:image/png;base64,' + base64.b64encode(selected.wordmark.read_bytes()).decode('ascii'),
            "icon": 'data:image/png;base64,' + base64.b64encode(selected.icon.read_bytes()).decode('ascii')}


def render(summary: dict, theme: str = "dark", *, embedded: bool = False, language: str | None = None,
           skin: str | None = None) -> str:
    if theme not in {"light", "dark"}:
        raise ValueError("Tema inválido.")
    language = normalize_language(language or get_language())
    payload = json.dumps(localize_summary(summary, language), ensure_ascii=False, indent=2).replace("<", "\\u003c").replace("&", "\\u0026")
    template = localize_template(TEMPLATE, language)
    visual = appearance(skin)
    return (template.replace("__KEKKAI_STYLE__", visual["css"])
            .replace('__KEKKAI_SKIN__', visual["skin"])
            .replace('__KEKKAI_WORDMARK__', visual["wordmark"])
            .replace('__KEKKAI_ICON__', visual["icon"])
            .replace("__KEKKAI_THEME__", theme).replace("__KEKKAI_EMBEDDED__", "embedded" if embedded else "standalone")
            .replace("__KEKKAI_SUMMARY__", payload))
