"""Per-user Trivy DB lifecycle. Only Trivy itself mutates persistent cache contents."""
import json
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from .files import is_link

TRIVY_IMAGE = "aquasec/trivy:latest"


def global_cache_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "SecScan" / "cache" / "trivy"


def cache_size(path: Path) -> int:
    if not path.exists():
        return 0
    total = 0
    for root, dirs, files in os.walk(path, followlinks=False):
        folder = Path(root)
        dirs[:] = [d for d in dirs if not is_link(folder / d)]
        for name in files:
            candidate = folder / name
            if not is_link(candidate):
                total += candidate.stat().st_size
    return total


def db_info(path: Path, java: bool = False) -> dict:
    folder = path / ("java-db" if java else "db")
    binary = folder / ("trivy-java.db" if java else "trivy.db")
    result = {"exists": False, "age_hours": None, "updated_at": None}
    if not binary.is_file() or is_link(binary) or is_link(folder):
        return result
    try:
        metadata = json.loads((folder / "metadata.json").read_text(encoding="utf-8"))
        updated = metadata.get("UpdatedAt") or metadata.get("DownloadedAt")
        stamp = datetime.fromisoformat(updated.replace("Z", "+00:00"))
        age = max(0, (datetime.now(timezone.utc) - stamp).total_seconds() / 3600)
        result.update(exists=True, age_hours=round(age, 3), updated_at=updated)
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    return result


class CacheLock:
    """OS lock releases on process exit, including crashes; avoids stale lock files."""
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = path.open("a+b")
        if path.stat().st_size == 0:
            self.handle.write(b"0")
            self.handle.flush()

    def acquire(self):
        deadline = time.monotonic() + 120
        while True:
            try:
                self.handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except OSError:
                if time.monotonic() >= deadline:
                    self.handle.close()
                    raise RuntimeError("Cache Trivy em uso por outro scan; tente novamente.") from None
                time.sleep(0.2)

    def close(self):
        self.handle.close()


class TrivyCache:
    def __init__(self, options: dict, api):
        self.options = options
        self.keep_scan_cache = options["mode"] == "persistent" or options["keep_scan_cache"]
        self.api = api
        self.temp = tempfile.TemporaryDirectory(prefix="secscan-trivy-") if options["mode"] == "ephemeral" else None
        self.path = Path(self.temp.name) if self.temp else global_cache_dir()
        self.lock = None
        self.metrics = {"mode": options["mode"], "cache_hit": False,
                        "download_avoided": False, "db_updated": False,
                        "trivy_db_download_seconds": 0.0, "trivy_scan_seconds": 0.0,
                        "cache_size_before": 0, "cache_size_after": 0,
                        "db_age_hours": None, "cleanup_warnings": []}

    def __enter__(self):
        self.path.mkdir(parents=True, exist_ok=True)
        if any(is_link(p) for p in (self.path, *self.path.parents)):
            raise RuntimeError("O cache Trivy não pode usar symlink ou junction.")
        if self.temp is None:
            self.lock = CacheLock(self.path.parent / "trivy.lock")
            self.lock.acquire()
        self.metrics["cache_size_before"] = cache_size(self.path)
        return self

    def invoke(self, args: list[str], timeout: int = 600) -> dict:
        name = self.api.container_name("trivy-cache")
        cmd = self.api.docker_command(name, ["-v", f"{self.path.resolve().as_posix()}:/cache"], TRIVY_IMAGE,
                                      ["--cache-dir", "/cache", *args])
        return self.api.run_docker(cmd, timeout, name)

    def prepare(self, vulnerabilities: bool, java: bool) -> list[str]:
        flags = ["--cache-dir", "/cache", "--cache-backend", "memory", "--skip-check-update", "--skip-version-check"]
        if self.keep_scan_cache:
            flags[flags.index("memory")] = "fs"
        for use, is_java, skip, download in [
            (vulnerabilities, False, "--skip-db-update", "--download-db-only"),
            (vulnerabilities and java, True, "--skip-java-db-update", "--download-java-db-only"),
        ]:
            if not use:
                continue
            before = db_info(self.path, is_java)
            fresh = before["exists"] and before["age_hours"] < self.options["ttl_hours"]
            if not is_java:
                self.metrics["cache_hit"] = fresh
                self.metrics["download_avoided"] = fresh
            if not fresh:
                started = time.perf_counter()
                outcome = self.invoke(["fs", download, "--no-progress", "--skip-version-check"])
                self.metrics["trivy_db_download_seconds"] += time.perf_counter() - started
                if outcome["exit_code"] != 0:
                    raise RuntimeError(outcome["error"] or "Trivy não conseguiu obter/atualizar sua base; verifique rede e registries.")
                after = db_info(self.path, is_java)
                if not after["exists"]:
                    raise RuntimeError("Trivy não disponibilizou uma base válida após o download.")
                if not is_java:
                    self.metrics["db_updated"] = before["updated_at"] != after["updated_at"]
            # Download/preparation happened once for this invocation, and a valid DB is present.
            flags.append(skip)
        self.metrics["db_age_hours"] = db_info(self.path)["age_hours"]
        return flags

    def clean(self, flags: list[str]):
        outcome = self.invoke(["clean", *flags], 120)
        if outcome["exit_code"] != 0:
            self.metrics["cleanup_warnings"].append("Trivy não conseguiu limpar " + ", ".join(flags))

    def __exit__(self, exc_type, exc, traceback):
        try:
            if self.temp:
                self.temp.cleanup()
                self.metrics["cache_size_after"] = 0
                return
            if not self.keep_scan_cache:
                self.clean(["--scan-cache"])
            maximum = self.options["max_size_mb"]
            if maximum is not None and cache_size(self.path) > maximum * 1024 * 1024:
                # All disposable contents are removed through supported Trivy commands.
                self.clean(["--scan-cache", "--checks-bundle", "--vex-repo"])
                if cache_size(self.path) > maximum * 1024 * 1024:
                    self.metrics["cleanup_warnings"].append("Cache acima do limite após limpeza seletiva; bases úteis preservadas. Use cache clean para remover databases explicitamente.")
            self.metrics["cache_size_after"] = cache_size(self.path)
            metadata = {"last_used": datetime.now(timezone.utc).isoformat(),
                        "last_update": db_info(self.path)["updated_at"],
                        "size_bytes": self.metrics["cache_size_after"], "mode": self.options["mode"],
                        "tool_image": TRIVY_IMAGE}
            self.api.write_json(self.path.parent / "metadata.json", metadata)
        finally:
            if self.lock:
                self.lock.close()


def status() -> dict:
    path = global_cache_dir()
    return {"path": str(path), "size_bytes": cache_size(path), "database": db_info(path), "java_database": db_info(path, True)}
