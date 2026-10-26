"""One exclusion vocabulary, safe traversal, and report sanitization."""
from .i18n import tr
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Iterator


def is_link(path: Path) -> bool:
    try:
        info = path.lstat()
        return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)
    except OSError:
        return True


def reject_link_path(path: Path) -> Path:
    """Inspect lexical ancestors before resolution can hide a project-supplied link."""
    absolute = Path(os.path.abspath(path))
    for candidate in (absolute, *absolute.parents):
        if (candidate.exists() or candidate.is_symlink()) and is_link(candidate):
            raise OSError(tr("Destino contém symlink/junction; gravação recusada."))
    return absolute


def safe_directory(path: Path) -> Path:
    path = reject_link_path(path)
    path.mkdir(parents=True, exist_ok=True)
    return reject_link_path(path)


def atomic_write_bytes(path: Path, content: bytes) -> None:
    """Replace a regular destination without opening/truncating an existing link.

    Random exclusive temporary files also avoid following preseeded .tmp files.
    This protects project-supplied paths; it is not a sandbox against another
    process already running with the same user's filesystem authority.
    """
    path = reject_link_path(path)
    safe_directory(path.parent)
    descriptor, name = tempfile.mkstemp(prefix=".kekkai-write-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        reject_link_path(path)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def atomic_write_text(path: Path, content: str) -> None:
    atomic_write_bytes(path, content.encode("utf-8"))


class Exclusions:
    def __init__(self, target: Path, paths: list[str]):
        self.target = target.resolve()
        self.paths = list(dict.fromkeys(p.replace("\\", "/").strip("/").removeprefix("./") for p in paths))

    def matches(self, relative: str) -> bool:
        parts = relative.replace("\\", "/").strip("/").split("/")
        candidate = "/".join(parts).casefold()
        for pattern in self.paths:
            key = pattern.casefold()
            if "/" not in key:
                if key in [part.casefold() for part in parts]:
                    return True
            elif candidate == key or candidate.startswith(key + "/"):
                return True
        return False

    def files(self, max_bytes: int | None = None) -> Iterator[Path]:
        def fail(error):
            raise OSError("Não foi possível percorrer todos os arquivos do projeto.") from error
        for root, dirs, names in os.walk(self.target, followlinks=False, onerror=fail):
            folder = Path(root)
            dirs[:] = sorted(d for d in dirs if not is_link(folder / d)
                             and not self.matches((folder / d).relative_to(self.target).as_posix()))
            for name in sorted(names):
                path = folder / name
                if is_link(path) or self.matches(path.relative_to(self.target).as_posix()):
                    continue
                if path.is_file() and (max_bytes is None or path.stat().st_size <= max_bytes):
                    yield path

    def semgrep_flags(self) -> list[str]:
        flags = []
        for value in self.paths:
            for pattern in ([value, "**/" + value] if "/" not in value else [value]):
                flags.extend(["--exclude", pattern])
        return flags

    def trivy_flags(self) -> list[str]:
        flags = []
        for value in self.paths:
            patterns = ["/src/" + value]
            if "/" not in value:
                patterns.append("**/" + value)
            for pattern in patterns:
                flags.extend(["--skip-dirs", pattern, "--skip-files", pattern])
        return flags

    def gitleaks_regexes(self) -> list[str]:
        def escape_go(value):
            # Python re.escape also escapes spaces; RE2 does not accept all those escapes.
            return re.sub(r"([\\.^$|?*+(){}\[\]])", r"\\\1", value)
        return [(r"(^|/)" if "/" not in p else r"^(/src/)?") + escape_go(p) + r"(/|$)" for p in self.paths]


class Sanitizer:
    """No matching bytes or source evidence survive into on-disk reports."""
    def __init__(self):
        self.secrets: set[str] = set()
        self.source_lines: set[str] = set()

    def add_gitleaks(self, data: list[dict], target: Path):
        for item in data:
            for key in ("Secret", "Match"):
                value = item.get(key)
                if isinstance(value, str) and value and value not in {"REDACTED", "SECRET_REDACTED"}:
                    self.secrets.add(value)
            relative = str(item.get("File", "")).replace("\\", "/").removeprefix("/src/")
            path = (target / relative).resolve()
            if not path.is_relative_to(target.resolve()) or is_link(path):
                continue
            try:
                if path.stat().st_size > 2 * 1024 * 1024:
                    continue
                lines = path.read_text(encoding="utf-8").splitlines()
                for index in range(max(0, int(item.get("StartLine", 1)) - 1), min(len(lines), int(item.get("EndLine", item.get("StartLine", 1))))):
                    line = lines[index].strip()
                    if line:
                        self.source_lines.add(line)
                        self.secrets.update(v for v in re.findall(r"['\"]([^'\"]{4,})['\"]", line))
            except (OSError, UnicodeError, ValueError, TypeError):
                continue

    def text(self, value: str) -> str:
        return self._text(value, self._pattern())

    def _pattern(self):
        values = sorted((self.secrets | self.source_lines) - {""}, key=len, reverse=True)
        return re.compile("|".join(re.escape(value) for value in values)) if values else None

    def _text(self, value: str, pattern) -> str:
        if pattern:
            value = pattern.sub("[REDACTED]", value)
        value = re.sub(r"-----BEGIN [^-]*(?:PRIVATE KEY)[^-]*-----.*?-----END [^-]+-----", "[PRIVATE KEY REDACTED]", value, flags=re.S)
        value = re.sub(r"(?i)(?:Bearer\s+|sk-(?:proj-)?|gh[pousr]_)[A-Za-z0-9_.\-]{12,}", "[REDACTED]", value)
        value = re.sub(r"(?i)\b(api[_-]?key|password|secret|access[_-]?token)\b\s*[:=]\s*['\"]?[^\s'\",;]{4,}", r"\1=[REDACTED]", value)
        value = re.sub(r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1[REDACTED]@", value)
        value = re.sub(r"(?i)([?&](?:token|key|password|secret|access_token)=)[^&\s]+", r"\1[REDACTED]", value)
        return value

    def clean(self, value: Any) -> Any:
        # Compile once per report, rather than searching every source line in every field.
        return self._clean(value, self._pattern())

    def _clean(self, value: Any, pattern) -> Any:
        if isinstance(value, (bytes, bytearray, memoryview)):
            return "[BINARY DATA REDACTED]"
        if isinstance(value, dict):
            output = {}
            for key, item in value.items():
                lowered = key.lower().replace("_", "")
                if lowered in {"secret", "match", "lines", "snippet", "evidence", "content", "sourcecode", "metavars", "data", "bytes"}:
                    output[key] = "[REDACTED]"
                else:
                    output[key] = self._clean(item, pattern)
            return output
        if isinstance(value, list):
            return [self._clean(x, pattern) for x in value]
        if isinstance(value, tuple):
            return [self._clean(x, pattern) for x in value]
        if isinstance(value, str):
            return self._text(value, pattern)
        return value
