"""Built-in desktop skins: local assets, palettes and presentation settings."""
from dataclasses import dataclass
import json
from pathlib import Path

from ..branding import ASSETS


@dataclass(frozen=True)
class Skin:
    identifier: str
    name: str
    paper: bool
    wordmark: Path
    icon: Path
    hardware: bool = False
    mark_aspect: float = 1.0
    monochrome: bool = False

    @property
    def directory(self) -> Path:
        return Path(__file__).parent / self.identifier


SKINS = {
    "violet": Skin("violet", "Violet", False, ASSETS / "logo+nome.png", ASSETS / "logo.png"),
    "retro": Skin("retro", "Retro", True, ASSETS / "Logo Kekkai retro.png", ASSETS / "Logo Kekkai retro.png"),
    "hardware": Skin("hardware", "Hardware", False, ASSETS / "logo-hardware.png", ASSETS / "logo-hardware.png",
                     hardware=True, mark_aspect=1.26),
    "monochrome-crt": Skin("monochrome-crt", "Monochrome CRT", False,
                           ASSETS / "logo-monochrome-crt.png", ASSETS / "logo-monochrome-crt.png",
                           mark_aspect=.89, monochrome=True),
}
DEFAULT_SKIN = "retro"
_active_skin = DEFAULT_SKIN
_palettes = {key: json.loads((skin.directory / "tokens.json").read_text(encoding="utf-8"))
             for key, skin in SKINS.items()}


def get_skin(identifier: str | None = None) -> Skin:
    key = _active_skin if identifier is None else identifier
    if not isinstance(key, str) or key not in SKINS:
        raise ValueError("Skin inválida.")
    return SKINS[key]


def set_skin(identifier: str) -> None:
    global _active_skin
    _active_skin = get_skin(identifier).identifier


def tokens(theme: str = "dark", skin: str | None = None) -> dict[str, str]:
    if theme not in {"light", "dark"}:
        raise ValueError("Tema inválido: use light ou dark.")
    return dict(_palettes[get_skin(skin).identifier][theme])


def stylesheet(theme: str, skin: str | None = None) -> str:
    source = (get_skin(skin).directory / "desktop.qss").read_text(encoding="utf-8")
    for key, value in sorted(tokens(theme, skin).items(), key=lambda item: len(item[0]), reverse=True):
        source = source.replace("@" + key, value)
    return source


def css_tokens(skin: str | None = None) -> str:
    blocks = []
    for theme in ("light", "dark"):
        selector = f'html[data-theme="{theme}"]' + (", :root" if theme == "light" else "")
        declarations = ";".join(f"--{key}:{value}" for key, value in tokens(theme, skin).items())
        blocks.append(f"{selector} {{{declarations}; color-scheme:{theme};}}")
    return "\n".join(blocks)
