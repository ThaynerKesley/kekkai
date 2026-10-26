"""Shared theme tokens, derived from the supplied reference palettes."""
import json
from pathlib import Path


TOKENS = json.loads((Path(__file__).parent / "tokens.json").read_text(encoding="utf-8"))


def tokens(theme: str = "dark") -> dict[str, str]:
    if theme not in TOKENS:
        raise ValueError("Tema inválido: use light ou dark.")
    return dict(TOKENS[theme])


def css_tokens() -> str:
    blocks = []
    for theme in ("light", "dark"):
        selectors = f'html[data-theme="{theme}"]' + (", :root" if theme == "light" else "")
        declarations = ";".join(f"--{key}:{value}" for key, value in tokens(theme).items())
        blocks.append(f"{selectors} {{{declarations}; color-scheme:{theme};}}")
    return "\n".join(blocks)
