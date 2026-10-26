"""Non-sensitive desktop preferences and completed report snapshots."""
import json
import os
import shutil
import zipfile
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import yaml

from ..configuration import DEFAULTS, merge, validate
from ..files import Sanitizer, is_link, atomic_write_text, atomic_write_bytes, safe_directory
from ..i18n import LANGUAGES


def user_data_dir() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share"))
    return base / "SecScan" / "desktop"


class Preferences:
    def __init__(self, path: Path | None = None):
        self.path = path or user_data_dir() / "preferences.json"
        self.data = {"theme": "dark", "language": "pt_BR", "default_directory": str(Path.cwd()), "open_dashboard": True,
                     "recent_projects": [], "scan_defaults": {}, "profiles": {}}
        if self.path.is_file():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if not isinstance(loaded, dict):
                    raise ValueError("Preferences inválidas.")
                self.data.update({key: loaded[key] for key in self.data if key in loaded})
            except (OSError, ValueError):
                # Inform the caller; an invalid file must not silently replace user settings.
                raise ValueError("Preferências desktop inválidas. Verifique preferences.json no diretório local SecScan.") from None
        if not isinstance(self.data["theme"], str) or self.data["theme"] not in {"dark", "light"}:
            self.data["theme"] = "dark"
        self.validate()

    def validate(self):
        data = self.data
        valid = (isinstance(data["theme"], str) and isinstance(data["language"], str) and data["language"] in LANGUAGES and isinstance(data["default_directory"], str)
                 and type(data["open_dashboard"]) is bool and isinstance(data["recent_projects"], list)
                 and all(isinstance(x, str) for x in data["recent_projects"])
                 and isinstance(data["scan_defaults"], dict) and isinstance(data["profiles"], dict))
        if not valid:
            raise ValueError("Estrutura das preferências desktop inválida.")
        validate(merge(DEFAULTS, data["scan_defaults"]))
        for name, profile in data["profiles"].items():
            if name not in {"quick", "full"} or not isinstance(profile, dict) or not isinstance(profile.get("scanners"), dict):
                raise ValueError("Perfil desktop inválido.")
            if any(scanner not in DEFAULTS["policy"] or type(enabled) is not bool for scanner, enabled in profile["scanners"].items()):
                raise ValueError("Scanners do perfil desktop inválidos.")

    def save(self):
        self.validate()
        defaults = merge(DEFAULTS, self.data["scan_defaults"])
        validate(defaults)  # Also rejects credential fields in saved preferences.
        atomic_write_text(self.path, json.dumps(Sanitizer().clean(self.data), ensure_ascii=False, indent=2))

    def remember(self, target: Path):
        recent = [str(target), *[str(x) for x in self.data["recent_projects"] if str(x) != str(target)]]
        self.data["recent_projects"] = recent[:20]
        self.save()


def save_project_config(target: Path, config: dict):
    validate(config)
    path = target / ".secscan.yml"
    # Preserve user extensions; only the derived execution profile is transient.
    atomic_write_text(path, yaml.safe_dump({k: v for k, v in config.items() if k != "profile"}, sort_keys=False, allow_unicode=True))


class ReportStore:
    def __init__(self, root: Path):
        self.root = root.resolve()

    def archive(self, summary: dict, reports: Path, dashboard: Path | None) -> Path:
        safe = Sanitizer().clean(summary)
        name = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:8]
        destination = self.root / "history" / name
        if destination.exists():
            raise FileExistsError("Snapshot já existe.")
        safe_directory(destination)
        atomic_write_text(destination / "summary.json", json.dumps(safe, ensure_ascii=False, indent=2))
        raw = reports / "raw"
        if raw.is_dir() and not is_link(raw):
            for path in raw.iterdir():
                if path.is_file() and not is_link(path):
                    atomic_write_bytes(destination / path.name, path.read_bytes())
        if dashboard and dashboard.is_file() and not is_link(dashboard):
            atomic_write_bytes(destination / "dashboard.html", dashboard.read_bytes())
        return destination

    def list_reports(self) -> list[dict]:
        paths = [self.root / "reports" / "summary.json"]
        history = self.root / "history"
        if history.is_dir() and not is_link(history):
            paths.extend(sorted(history.glob("*/summary.json"), reverse=True))
        entries = []
        for path in paths:
            if not path.is_file() or is_link(path) or path.stat().st_size > 20 * 1024 * 1024:
                continue
            try:
                summary = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(summary, dict) or not isinstance(summary.get("scanners"), dict):
                continue
            entries.append({"summary": summary, "path": str(path)})
        return entries

    def export(self, report_directory: Path, destination: Path):
        directory = report_directory.resolve()
        if not directory.is_relative_to(self.root) or is_link(directory):
            raise ValueError("Relatório fora do diretório autorizado.")
        if destination.resolve().is_relative_to(directory):
            raise ValueError("Escolha um destino de exportação fora do relatório.")
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in directory.rglob("*"):
                if not path.is_file() or any(is_link(p) for p in (path, *path.parents)):
                    continue
                if path.suffix.lower() in {".json", ".html", ".yaml"}:
                    archive.write(path, path.relative_to(directory).as_posix())

    def deletion_targets(self, report_path: Path):
        path=report_path.resolve()
        if path.name!='summary.json' or path not in [Path(x['path']).resolve() for x in self.list_reports()]:
            raise ValueError('Selecione um relatório listado pelo aplicativo.')
        if path.parent==self.root/'reports':
            targets=[path.parent]
            if (self.root/'dashboard').is_dir():targets.append(self.root/'dashboard')
        elif path.parent.parent==self.root/'history':
            targets=[path.parent]
        else:
            raise ValueError('Relatório fora das pastas autorizadas.')
        for directory in targets:
            resolved=directory.resolve()
            if resolved==self.root or not resolved.is_relative_to(self.root) or any(is_link(x) for x in (directory,*directory.parents)):
                raise ValueError('Path de relatório não permitido.')
            if any(is_link(x) for x in directory.rglob('*')):
                raise ValueError('Relatório contém links; exclusão automática recusada.')
        return targets

    def delete(self, report_path: Path):
        targets=self.deletion_targets(report_path)
        # Only recognized, validated report folders. Never remove the output root/cache/source.
        for directory in targets:
            shutil.rmtree(directory)
        return targets
