"""Per-scan cancellation and Docker process ownership for desktop integrations."""
from ..i18n import tr
import subprocess
import threading
import time

from .. import secscan as engine


class ScanCancelled(RuntimeError):
    pass


class ExecutionContext:
    def __init__(self, cancel: threading.Event | None = None):
        self.cancel = cancel or threading.Event()

    def __getattr__(self, name):
        return getattr(engine, name)

    def check_cancelled(self):
        if self.cancel.is_set():
            raise ScanCancelled(tr("Scan cancelado pelo usuário."))

    def run_docker(self, command: list[str], timeout: int, name: str) -> dict:
        self.check_cancelled()
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       stdin=subprocess.DEVNULL,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except OSError:
            return {"exit_code": -1, "stdout": "", "stderr": "", "error": tr("Não foi possível iniciar Docker; verifique o PATH."), "infrastructure": True}
        deadline = time.monotonic() + timeout
        try:
            while True:
                if self.cancel.is_set() or time.monotonic() >= deadline:
                    # A unique name belongs to this invocation only; unrelated containers are untouched.
                    engine.stop_container(name)
                    process.kill()
                    process.communicate()
                    reason = tr("Scan cancelado pelo usuário.") if self.cancel.is_set() else tr('Tempo esgotado após {v0}s.', v0=timeout)
                    return {"exit_code": -1, "stdout": "", "stderr": "", "error": reason, "infrastructure": False}
                try:
                    stdout, stderr = process.communicate(timeout=0.2)
                    break
                except subprocess.TimeoutExpired:
                    continue
            # Decode only complete byte streams; polling cannot split UTF-8 characters.
            stdout = stdout.decode("utf-8", errors="replace")
            stderr = stderr.decode("utf-8", errors="replace")
            error = engine.docker_infrastructure_error(stdout, stderr) if process.returncode else None
            return {"exit_code": process.returncode, "stdout": stdout, "stderr": stderr, "error": error, "infrastructure": error is not None}
        finally:
            if process.poll() is None:
                engine.stop_container(name)
                process.kill()
                process.communicate()
