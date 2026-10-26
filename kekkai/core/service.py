"""Application entry point shared by desktop clients, without importing Qt."""
from ..i18n import tr
from copy import deepcopy
from pathlib import Path
from threading import Event

from .. import configuration, runner
from .. import engine
from .execution import ExecutionContext


def run_scan(target: Path, config: dict, *, profile="full", requested_ai=False,
             cancel: Event | None = None, on_event=None, ai_interaction=None) -> dict:
    target = target.resolve()
    if not target.is_dir():
        raise ValueError(tr("Selecione um diretório de projeto existente."))
    effective = deepcopy(config)
    configuration.validate(effective)
    if profile not in {"quick", "full"}:
        raise ValueError(tr("Perfil inválido."))
    effective["profile"] = profile
    if profile == "quick":
        effective["policy"]["zap"]["enabled"] = False
        effective["policy"]["sca"]["license"]["full_scan"] = False
    context = ExecutionContext(cancel)
    context.check_cancelled()
    results, performance, sanitizer = runner.execute(context, target, effective, requested_ai,
        on_event=on_event, ai_interaction=ai_interaction)
    context.check_cancelled()
    summary = engine.build_summary(effective, target, engine.resolve_project_name(effective, target), results)
    summary.update(performance=performance, profile=profile,
                   trivy_database=next((item.get("cache") for item in results if item["name"] == "sca"), None))
    summary = sanitizer.clean(summary)
    dirs = None
    if effective["reporting"]["enabled"]:
        dirs = engine.prepare_output_dirs(target, effective["reporting"]["output_dir"])
        runner.persist(context, results, summary, dirs)
        if effective["reporting"]["dashboard"]:
            engine.generate_dashboard(summary, dirs["dashboard"] / "index.html")
    return {"summary": summary, "dirs": {key: str(value) for key, value in dirs.items()} if dirs else None}
