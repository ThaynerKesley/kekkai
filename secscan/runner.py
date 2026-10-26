"""Bounded execution, common sanitization, and CLI lifecycle."""
import argparse
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import configuration, scanners
from .ai_review import run_ai
from .cache import TrivyCache, status as cache_status
from .files import Exclusions, Sanitizer
from .diagnostics import diagnostic, attach, process_diagnostic
from .web_target import is_web_project, test_target
from .i18n import tr, set_language

SCANNER_ORDER = ("semgrep", "gitleaks", "sca", "yara", "owasp", "zap", "ai")


def probe_zap_container(api,target):
    url=api.zap_fallback_url(target) or target if os.name=='nt' else target
    network=['--add-host','host.docker.internal:host-gateway'] if os.name=='nt' else ['--network','host']
    script=("import urllib.request,urllib.error,json,sys; "
            "op=urllib.request.build_opener(urllib.request.ProxyHandler({}),type('NoRedirect',(urllib.request.HTTPRedirectHandler,),{'redirect_request':lambda self,*args:None})()); "
            "url=sys.argv[1];\n"
            "try:\n r=op.open(url,timeout=4); print(json.dumps({'reachable':True,'http_status':r.status}));r.close()\n"
            "except urllib.error.HTTPError as e:\n b=e.read(1024).decode('utf-8','replace'); print(json.dumps({'reachable':True,'http_status':e.code,'host_rejected':'This host' in b and 'not allowed' in b}));e.close()\n"
            "except Exception:\n print(json.dumps({'reachable':False}))")
    name=api.container_name('zap-preflight')
    command=api.docker_command(name,[*network,'--entrypoint','python'],'ghcr.io/zaproxy/zaproxy:stable',['-c',script,url])
    outcome=api.run_docker(command,20,name)
    if outcome['error']:
        return {'reachable':False,'diagnostic':process_diagnostic(outcome,'ZAP preflight')}
    try:
        value=json.loads(outcome['stdout'])
        if value.get('reachable') and not value.get('host_rejected'):
            return value
    except (ValueError,AttributeError):
        return {'reachable':False,'diagnostic':diagnostic('scanner_error','zap_preflight_json','Preflight Docker não retornou JSON válido.')}
    return {'reachable':False,'diagnostic':diagnostic('target_unreachable','docker_target_unreachable',
        tr('Aplicação acessível no computador, mas indisponível para o Docker. Verifique bind em localhost/::1 e allowlist de hosts. No Vite, inicie com npm run dev -- --host 0.0.0.0 e permita o host Docker somente no ambiente local.'),recoverable=True,
        scope='docker', host_rejected=bool(value.get('host_rejected')), http_status=value.get('http_status'))}


def run_zap(api, policy: dict, *, web=True, preflight=None) -> dict:
    if not web:
        return attach(api.make_result("zap", "skipped", None, []), diagnostic("unsupported_feature", "non_web", tr("DAST/ZAP se aplica somente a projetos web.")))
    allowed, reason = api.validate_zap_target(policy["target"])
    if not allowed:
        return attach(api.make_result("zap", "error", None, []), diagnostic('configuration_error', 'invalid_target', reason))
    if policy["mode"] != "baseline":
        return attach(api.make_result("zap", "error", None, []), diagnostic('configuration_error', 'zap_mode', 'ZAP suporta apenas mode: baseline.'))
    probe = preflight if preflight is not None else test_target(policy["target"])
    if not probe["reachable"]:
        status = "error" if probe["diagnostic"]["error_type"] == "configuration_error" else "skipped"
        return attach(api.make_result("zap", status, None, []), probe["diagnostic"])
    container_probe=probe_zap_container(api,policy['target'])
    if not container_probe['reachable']:
        problem=container_probe['diagnostic']
        status='skipped' if problem['error_type']=='target_unreachable' else 'error'
        return attach(api.make_result('zap',status,None,[]),problem)
    # All native reports stay in container tmpfs, never on the host filesystem.
    script = (
        "import subprocess,json,pathlib,sys; "
        "r=subprocess.run(['zap-baseline.py','-t',sys.argv[1],'-J','zap.json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE); "
        "p=pathlib.Path('/zap/wrk/zap.json'); "
        "text=(r.stdout+r.stderr).decode('utf-8','replace').lower(); "
        "reason='target_connection' if any(x in text for x in ['failed to access','connection refused','failed to connect']) else 'baseline_failure'; "
        "print(json.dumps({'report':json.loads(p.read_text()) if p.exists() else None,'reason':reason})); sys.exit(r.returncode)"
    )
    def invoke(url, network):
        name = api.container_name("zap")
        command = api.docker_command(name, [*network, "--tmpfs", "/zap/wrk:rw,mode=1777", "--entrypoint", "python"],
                                     "ghcr.io/zaproxy/zaproxy:stable", ["-c", script, url])
        return api.run_docker(command, api.ZAP_TIMEOUT, name)
    target = policy["target"]
    if os.name == "nt":
        fallback = api.zap_fallback_url(target)
        outcome = invoke(fallback or target, ["--add-host", "host.docker.internal:host-gateway"])
    else:
        outcome = invoke(target, ["--network", "host"])
        if outcome["exit_code"] not in (0, 1, 2) and not outcome["infrastructure"] and api.zap_fallback_url(target):
            outcome = invoke(api.zap_fallback_url(target), ["--add-host", "host.docker.internal:host-gateway"])
    if outcome["error"]:
        return attach(api.make_result("zap", "error", outcome["exit_code"], []), process_diagnostic(outcome, "ZAP"))
    try:
        data = json.loads(outcome["stdout"])
    except ValueError:
        return api.make_result("zap", "error", outcome["exit_code"], [], "ZAP não retornou relatório JSON válido.")
    if not isinstance(data, dict) or not data.get("site"):
        if isinstance(data,dict) and 'report' in data:
            envelope=data
            data=envelope.get('report')
            if not isinstance(data,dict) or not data.get('site'):
                return attach(api.make_result('zap','error',outcome['exit_code'],[]),diagnostic('target_unreachable' if envelope.get('reason')=='target_connection' else 'scanner_error',envelope.get('reason','baseline_failure'),
                    tr('ZAP perdeu acesso ao alvo durante o scan.') if envelope.get('reason')=='target_connection' else tr('Baseline ZAP não produziu relatório válido. Verifique recursos e configuração do container.'),recoverable=True,exit_code=outcome['exit_code']))
        else:
            return api.make_result("zap", "error", outcome["exit_code"], [], tr("ZAP não conseguiu analisar o alvo ou produzir relatório. Verifique a aplicação local."))
    safe = Sanitizer().clean(data)
    for site in safe.get("site", []):
        for alert in site.get("alerts", []):
            for instance in alert.get("instances", []):
                for key in ("evidence", "attack", "param"):
                    instance.pop(key, None)
    findings = api.parse_zap(safe, policy["fail_on"])
    status = api.classify_zap(outcome["exit_code"], policy["fail_on"])
    if status != "error" and any(f["blocking"] for f in findings):
        status = "fail"
    result = api.make_result("zap", status, outcome["exit_code"], findings,
                             tr("ZAP não concluiu o scan.") if status == "error" else None)
    result["raw"] = safe
    return result


def execute(api, target: Path, config: dict, requested_ai: bool = False, *, on_event=None, ai_interaction=None) -> tuple[list[dict], dict, Sanitizer]:
    started = time.perf_counter()
    policy = config["policy"]
    if requested_ai and config["profile"] != "quick" and config["ai"]["enabled"] is not False and not policy["gitleaks"]["enabled"]:
        policy["gitleaks"].update(enabled=True, fail_on_findings=False)
    exclude_paths = list(config["scan"]["exclude_paths"])
    output = Path(config["reporting"]["output_dir"])
    output = output if output.is_absolute() else target / output
    if output.resolve() == target.resolve():
        raise ValueError("reporting.output_dir não pode ser a raiz do projeto.")
    if output.resolve().is_relative_to(target.resolve()):
        exclude_paths.append(output.resolve().relative_to(target.resolve()).as_posix())
    # Default report folders stay excluded even if a custom exclusion list is supplied.
    exclude_paths.extend([".security", ".git"])
    exclusions = Exclusions(target, exclude_paths)
    web = is_web_project(config)
    zap_probe = test_target(policy["zap"]["target"]) if web and policy["zap"]["enabled"] else None
    zap_ready = bool(web and zap_probe and zap_probe["reachable"])
    need_docker = any(policy[name]["enabled"] for name in ("semgrep", "gitleaks", "sca", "owasp")) or zap_ready
    docker_error = scanners.docker_preflight() if need_docker else None
    tasks = {
        "semgrep": lambda: scanners.run_semgrep(api, target, policy["semgrep"], exclusions),
        "gitleaks": lambda: scanners.run_gitleaks(api, target, policy["gitleaks"], exclusions),
        "sca": lambda: scanners.run_sca(api, target, policy["sca"], exclusions, config["performance"]),
        "yara": lambda: scanners.run_yara(api, target, policy["yara"], exclusions),
        "owasp": lambda: scanners.run_semgrep(api, target, policy["owasp"], exclusions, owasp=True),
        "zap": lambda: run_zap(api, policy["zap"], web=web, preflight=zap_probe),
    }
    def timed(name, function):
        begin = time.perf_counter()
        executed = bool(policy[name]["enabled"] and (name == "yara" or not docker_error) and (name != "zap" or zap_ready))
        if on_event:
            on_event({"kind": "scanner_started", "scanner": name, "enabled": policy[name]["enabled"]})
        if not policy[name]["enabled"]:
            result = api.make_result(name, "skipped", None, [])
        elif name == "zap" and not zap_ready:
            result = function()
        elif docker_error and name != "yara":
            result = attach(api.make_result(name, "error", None, []), diagnostic('dependency_missing', 'docker_unavailable', tr('Docker indisponível. Inicie Docker Desktop com engine Linux/WSL2.'), recoverable=True))
        else:
            print(tr('[secscan] iniciando {v0}...', v0=api.DISPLAY_NAMES[name]))
            try:
                result = function()
            except Exception:
                result = api.unexpected_failure(name)
        end = time.perf_counter()
        if result["status"] == "skipped":
            executed = False
        result.update(executed=executed, duration_seconds=round(end - begin, 3), started_seconds=round(begin - started, 3), ended_seconds=round(end - started, 3))
        if on_event:
            on_event({"kind": "scanner_finished", "scanner": name, "status": result["status"],
                      "findings": result["total_findings"], "duration_seconds": result["duration_seconds"], "diagnostic": result.get("diagnostic")})
        return result
    parallel = config["performance"]["parallel"]
    workers = config["performance"]["max_workers"] if parallel else 1
    if parallel:
        print(tr('[secscan] scanners independentes em paralelo (máximo {v0})...', v0=workers))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(timed, name, function): name for name, function in tasks.items()}
        by_name = {result["name"]: result for result in (future.result() for future in as_completed(futures))}
    sanitizer = Sanitizer()
    sensitive = by_name["gitleaks"].pop("_sensitive_data", [])
    sanitizer.add_gitleaks(sensitive, target)
    sensitive.clear()
    ai_started = time.perf_counter()
    if on_event:
        on_event({"kind": "scanner_started", "scanner": "ai", "enabled": requested_ai and config["profile"] != "quick"})
    ai_args = {} if ai_interaction is None else {"interaction": ai_interaction}
    if on_event:
        ai_args['on_event'] = on_event
    ai = run_ai(api, target, config["ai"], exclusions, by_name["gitleaks"], sanitizer, requested_ai, config["profile"], **ai_args)
    ai.update(duration_seconds=round(time.perf_counter() - ai_started, 3), started_seconds=round(ai_started - started, 3),
              ended_seconds=round(time.perf_counter() - started, 3), executed=ai["status"] != "skipped")
    if on_event:
        on_event({"kind": "scanner_finished", "scanner": "ai", "status": ai["status"],
                  "findings": ai["total_findings"], "duration_seconds": ai["duration_seconds"], "diagnostic": ai.get("diagnostic")})
    by_name["ai"] = ai
    results = scanners.deduplicate([by_name[name] for name in SCANNER_ORDER], api)
    for index, result in enumerate(results):
        overlaps = [other["name"] for other in results if other["name"] != result["name"]
                    and result["executed"] and other["executed"]
                    and max(result["started_seconds"], other["started_seconds"]) < min(result["ended_seconds"], other["ended_seconds"])]
        result["parallel_with"] = overlaps
        results[index] = sanitizer.clean(result)
    performance = {"total_seconds": round(time.perf_counter() - started, 3), "parallel": parallel,
                   "max_workers": workers, "profile": config["profile"],
                   "scanners": {item["name"]: {"duration_seconds": item["duration_seconds"], "parallel_with": item["parallel_with"],
                                             "started_seconds": item["started_seconds"], "ended_seconds": item["ended_seconds"]} for item in results}}
    return results, performance, sanitizer


def persist(api, results: list[dict], summary: dict, dirs: dict) -> None:
    filenames = {name: name + ".json" for name in SCANNER_ORDER}
    filenames["sca"] = "trivy-sca.json"
    for result in results:
        # Always replace previous reports so disabled/error scans cannot expose stale data.
        raw = result.get("raw", {"status": result["status"], "findings": [], "error": result.get("error")})
        if isinstance(raw, dict) and result.get("diagnostic"):
            raw = {**raw, "diagnostic": result["diagnostic"]}
        api.write_json(dirs["raw"] / filenames[result["name"]], raw)
        if result["name"] == "sca":
            api.write_json(dirs["raw"] / "trivy.json", raw)
        if result["name"] == "zap":
            native = {**summary, "findings": result["findings"], "totals": api.build_totals(result["findings"])}
            api.write_text(dirs["raw"] / "zap-native.html", api.render_dashboard(native))
            # Existing ZAP Automation Framework output may embed unsanitized evidence.
            yaml_path = dirs["raw"] / "zap.yaml"
            if yaml_path.exists():
                api.write_text(yaml_path, "# Relatório substituído por zap.json sanitizado.\n")
    api.write_json(dirs["reports"] / "summary.json", summary)


def cache_cli(api, args) -> int:
    if args.cache_action == "status":
        print(json.dumps(cache_status(), ensure_ascii=False, indent=2))
        return 0
    scope = args.scope
    if scope is None:
        print("1 - scan cache / 2 - databases / 3 - tudo")
        scope = {"1": "scan", "2": "databases", "3": "all"}.get(input("Limpeza [1]: ").strip() or "1")
        if scope is None:
            print("Opção inválida.")
            return 1
    if scope in {"databases", "all"} and not args.yes:
        if input(tr("Remover databases persistentes? [s/N] ")).strip().lower() not in {"s", "sim", "y", "yes"}:
            print("Limpeza cancelada.")
            return 0
    error = scanners.docker_preflight()
    if error:
        print(error)
        return 1
    options = {"mode": "persistent", "ttl_hours": 24, "keep_scan_cache": True, "max_size_mb": None}
    with TrivyCache(options, api) as cache:
        flags = {"scan": ["--scan-cache"], "databases": ["--vuln-db", "--java-db"], "all": ["--all"]}[scope]
        cache.clean(flags)
    if cache.metrics["cleanup_warnings"]:
        print("\n".join(cache.metrics["cleanup_warnings"]))
        return 1
    print("Cache limpo pelo Trivy: " + scope)
    return 0


def main(api) -> int:
    language_parser = argparse.ArgumentParser(add_help=False)
    language_parser.add_argument('--language', choices=['pt_BR', 'en'], default='pt_BR')
    language_args, _ = language_parser.parse_known_args()
    set_language(language_args.language)
    parser = argparse.ArgumentParser(prog="kekkai", description=tr("Scanners locais e revisão de segurança opcional."), parents=[language_parser])
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check")
    check.add_argument("target", nargs="?", default=".")
    check.add_argument('--language', choices=['pt_BR', 'en'], default=argparse.SUPPRESS)
    check.add_argument("--profile", choices=["quick", "full"], default="full")
    check.add_argument("--ai", action="store_true", help=tr("Solicitar IA; ainda exige consentimento interativo."))
    cache = commands.add_parser("cache")
    cache_commands = cache.add_subparsers(dest="cache_action", required=True)
    cache_commands.add_parser("status")
    clean = cache_commands.add_parser("clean")
    clean.add_argument("--scope", choices=["scan", "databases", "all"])
    clean.add_argument("--yes", action="store_true", help=tr("Confirmar explicitamente a limpeza selecionada."))
    args = parser.parse_args()
    try:
        if args.command == "cache":
            return cache_cli(api, args)
        target = Path(args.target).resolve()
        if not target.is_dir():
            raise ValueError(tr("Caminho do projeto não é um diretório."))
        config = configuration.load(target, args.profile)
        print(tr('[secscan] iniciando scan\n[secscan] alvo: {v0}', v0=target))
        results, performance, sanitizer = execute(api, target, config, args.ai)
        summary = api.build_summary(config, target, api.resolve_project_name(config, target), results)
        summary.update(performance=performance, profile=args.profile,
                       trivy_database=next((item.get("cache") for item in results if item["name"] == "sca"), None))
        summary = sanitizer.clean(summary)
        reporting = config["reporting"]
        dirs = None
        if reporting["enabled"]:
            dirs = api.prepare_output_dirs(target, reporting["output_dir"])
            persist(api, results, summary, dirs)
            if reporting["dashboard"]:
                api.generate_dashboard(summary, dirs["dashboard"] / "index.html")
        api.print_summary(summary, dirs, reporting)
        print(tr('\nTempo total: {v0:.1f}s', v0=performance['total_seconds']))
        return 0 if summary["result"] == "approved" else 1
    except (OSError, ValueError, RuntimeError):
        # YAML/config errors never print values that could contain credentials.
        print(tr("[secscan] configuração, arquivos ou cache inválidos. Verifique .secscan.yml, paths e permissões."))
        return 1
    except (EOFError, KeyboardInterrupt):
        print(tr("[secscan] operação interrompida."))
        return 1
    except Exception:
        print(tr("[secscan] falha inesperada ao executar ou salvar os relatórios; verifique Docker e permissões de saída."))
        return 1
