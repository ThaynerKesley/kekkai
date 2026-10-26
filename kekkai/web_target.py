"""Bounded local HTTP preflight without response bodies, redirects or proxy use."""
from .i18n import tr
import time
import urllib.error
import urllib.request
from .diagnostics import diagnostic


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def is_web_project(config):
    explicit = config.get("project", {}).get("web")
    # Preserve project configurations that predate project.web.
    return explicit if isinstance(explicit, bool) else bool(config["policy"]["zap"]["enabled"])


def test_target(target, timeout=3):
    from .engine import validate_zap_target
    valid, _ = validate_zap_target(target)
    if not valid:
        return {"reachable": False, "diagnostic": diagnostic("configuration_error", "invalid_target", tr("Alvo ZAP inválido. Use HTTP/HTTPS em um host local, sem credenciais na URL."))}
    started = time.perf_counter()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(urllib.request.Request(target, method="HEAD"), timeout=timeout) as response:
            status = response.status
    except urllib.error.HTTPError as error:
        status = error.code  # 401/403/404/redirects prove an HTTP server is reachable.
        error.close()
    except (urllib.error.URLError, TimeoutError, OSError):
        return {"reachable": False, "diagnostic": diagnostic("target_unreachable", "connection_failed",
            tr("Alvo web indisponível. Inicie a aplicação local e execute o scan novamente."), recoverable=True)}
    return {"reachable": True, "http_status": status, "latency_ms": round((time.perf_counter()-started)*1000, 1)}
