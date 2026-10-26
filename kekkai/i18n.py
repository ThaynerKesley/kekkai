"""Application-owned messages. Configuration keys and user data stay unchanged.

Portuguese remains the source language for compatibility. Locale is selected at
startup, before workers run; it is shared with the desktop and offline renderer.
"""
import json
from pathlib import Path

LANGUAGES = {"pt_BR": "Português (Brasil)", "en": "English"}
_language = "pt_BR"
_english = json.loads((Path(__file__).parent / "locales" / "en.json").read_text(encoding="utf-8"))


def normalize_language(value: str) -> str:
    aliases = {"pt": "pt_BR", "pt-BR": "pt_BR", "pt_BR": "pt_BR", "en": "en", "en-US": "en", "en_US": "en"}
    if value not in aliases:
        raise ValueError("Unsupported language. Use pt_BR or en.")
    return aliases[value]


def set_language(value: str) -> None:
    global _language
    _language = normalize_language(value)


def get_language() -> str:
    return _language


def translate(message: str, language: str) -> str:
    return _english.get(message, message) if language == "en" else message


def tr(message: str, **values) -> str:
    translated = translate(message, _language)
    return translated.format(**values) if values else translated


class TranslatedLabels(dict):
    """Stable machine keys with labels resolved in the current startup locale."""
    def __getitem__(self, key):
        return tr(super().__getitem__(key))

    def get(self, key, default=None):
        value = super().get(key, default)
        return tr(value) if isinstance(value, str) else value
