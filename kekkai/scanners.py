"""Scanner integrations; Docker reports are captured in memory before persistence."""
from .i18n import tr
import hashlib
import json
import re
import tempfile
import tomllib
import time
import urllib.request
import urllib.error
from collections import Counter
from pathlib import Path

import yaml

from .cache import TRIVY_IMAGE, TrivyCache
from .files import Exclusions, Sanitizer, is_link
from .diagnostics import diagnostic, attach, process_diagnostic, semgrep_diagnostic, safe_semgrep_errors
from .yara_library import YaraRuleManager, RuleManagerError

OWASP_CONFIG = "p/owasp-top-ten"
OWASP_CONFIG_URL = "https://semgrep.dev/c/p/owasp-top-ten"
OWASP_CATEGORIES = {
    "2017": ["Injection", "Broken Authentication", "Sensitive Data Exposure", "XML External Entities (XXE)",
             "Broken Access Control", "Security Misconfiguration", "Cross-Site Scripting (XSS)",
             "Insecure Deserialization", "Using Components with Known Vulnerabilities", "Insufficient Logging & Monitoring"],
    "2021": ["Broken Access Control", "Cryptographic Failures", "Injection", "Insecure Design",
             "Security Misconfiguration", "Vulnerable and Outdated Components", "Identification and Authentication Failures",
             "Software and Data Integrity Failures", "Security Logging and Monitoring Failures", "Server-Side Request Forgery (SSRF)"],
    "2025": ["Broken Access Control", "Security Misconfiguration", "Software Supply Chain Failures", "Cryptographic Failures",
             "Injection", "Insecure Design", "Authentication Failures", "Software or Data Integrity Failures",
             "Security Logging and Alerting Failures", "Mishandling of Exceptional Conditions"],
}


def labels(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    return [str(x) for x in value] if isinstance(value, list) else []


def category_mapping(metadata: dict, edition: str) -> list[str]:
    result = []
    for value in labels(metadata.get("owasp")):
        match = re.match(r"^A0?(\d+):" + edition + r"(?:\s|[-–—])+(.*)$", value)
        if not match:
            continue
        index = int(match[1]) - 1
        if not 0 <= index < 10:
            continue
        canonical = OWASP_CATEGORIES[edition][index]
        def comparable(text):
            return re.sub(r"[^a-z0-9]", "", text.lower().replace("&", "and").replace(" or ", " and "))
        if comparable(match[2]) == comparable(canonical):
            result.append(f"A{index + 1:02}:{edition} - {canonical}")
    return list(dict.fromkeys(result))


def select_owasp_rules(data: dict, edition: str) -> tuple[dict, dict]:
    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("Ruleset OWASP oficial sem regras válidas.")
    available = [year for year in OWASP_CATEGORIES if any(category_mapping(r.get("metadata", {}), year) for r in rules)]
    chosen = max(available) if edition == "auto" and available else edition
    selected = [r for r in rules if category_mapping(r.get("metadata", {}), chosen)] if chosen in OWASP_CATEGORIES else []
    if not selected:
        raise ValueError("A edição OWASP solicitada não está suportada pelas regras selecionadas.")
    counts = Counter(category for r in selected for category in category_mapping(r.get("metadata", {}), chosen))
    info = {"edition": chosen, "ruleset": OWASP_CONFIG, "ruleset_url": OWASP_CONFIG_URL,
            "ruleset_sha256": hashlib.sha256(yaml.safe_dump({"rules": selected}, sort_keys=True).encode()).hexdigest(),
            "selected_rules": len(selected), "registry_rules": len(rules),
            "categories": [{"category": f"A{i + 1:02}:{chosen} - {name}",
                            "applicable_rules": counts[f"A{i + 1:02}:{chosen} - {name}"], "findings": 0}
                           for i, name in enumerate(OWASP_CATEGORIES[chosen])],
            "coverage_note": tr("Findings mapeados e regras selecionadas; não representam cobertura total. Regras selecionadas podem não se aplicar às linguagens deste projeto.")}
    return {"rules": selected}, info


def docker_preflight() -> str | None:
    import subprocess
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=30,
                                encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL)
        if result.returncode:
            return tr("Docker indisponível. Inicie Docker Desktop com o engine Linux/WSL2 e tente novamente.")
    except (OSError, subprocess.TimeoutExpired):
        return tr("Docker não encontrado ou indisponível. Verifique Docker Desktop e o PATH.")
    return None


def scan_command(api, scanner: str, target: Path, image: str, args: list[str], timeout: int, mounts=None) -> dict:
    name = api.container_name(scanner)
    command = api.docker_command(name, ["-v", f"{target.resolve().as_posix()}:/src:ro", "-w", "/src", *(mounts or [])], image, args)
    return api.run_docker(command, timeout, name)


def parse_outcome(outcome: dict, name: str, api) -> tuple[dict | list | None, dict | None]:
    if outcome["error"] or outcome["exit_code"] not in (0, 1):
        return None, api.make_result(name, "error", outcome["exit_code"], [],
                                    outcome["error"] or tr('{v0} encerrou com código {v1}; scan incompleto.', v0=name, v1=outcome['exit_code']))
    try:
        return json.loads(outcome["stdout"]), None
    except (ValueError, TypeError):
        return None, api.make_result(name, "error", outcome["exit_code"], [], tr('Relatório JSON de {v0} ausente ou inválido.', v0=name))


def run_semgrep(api, target: Path, policy: dict, exclusions: Exclusions, owasp: bool = False) -> dict:
    name = "owasp" if owasp else "semgrep"
    with tempfile.TemporaryDirectory(prefix="kekkai-rules-") as folder:
        info = {}
        config = "auto"
        mounts = []
        if owasp:
            try:
                with urllib.request.urlopen(OWASP_CONFIG_URL, timeout=45) as response:
                    contents = response.read(20 * 1024 * 1024 + 1)
                if len(contents) > 20 * 1024 * 1024:
                    raise ValueError("Ruleset muito grande.")
                data = yaml.safe_load(contents)
                selected, info = select_owasp_rules(data, str(policy["version"]))
                rules_path = Path(folder) / "owasp.yml"
                api.write_text(rules_path, yaml.safe_dump(selected, sort_keys=False))
                mounts = ["-v", f"{rules_path.as_posix()}:/rules/owasp.yml:ro"]
                config = "/rules/owasp.yml"
            except (urllib.error.URLError, TimeoutError, OSError):
                return attach(api.make_result(name, "error", None, []), diagnostic("network_error", "owasp_registry", tr("Não foi possível acessar o Semgrep Registry para carregar p/owasp-top-ten."), recoverable=True))
            except (ValueError, yaml.YAMLError, TypeError, AttributeError):
                return attach(api.make_result(name, "error", None, []), diagnostic("ruleset_error", "owasp_ruleset", tr("Ruleset OWASP inválido ou edição sem regras compatíveis. Verifique a edição selecionada.")))
        # Semgrep auto requires its default metrics mode; explicit OWASP rules do not.
        args = ["semgrep", "scan", "--config", config, "--json", "--quiet", "--metrics", "off" if owasp else "auto", "--disable-version-check",
                "--no-rewrite-rule-ids", "--jobs", "2", *exclusions.semgrep_flags(), "/src"]
        outcome = scan_command(api, name, target, "semgrep/semgrep:latest", args, api.SEMGREP_TIMEOUT, mounts)
        try:
            data = json.loads(outcome["stdout"])
        except (ValueError, TypeError):
            problem = process_diagnostic(outcome, 'Semgrep')
            if outcome['exit_code'] in (0, 1, 3) and not outcome.get('error'):
                problem.update(error_type='scanner_error', error_code='invalid_json', summary=tr('Semgrep não retornou um JSON íntegro; o scan não pode ser validado.'))
            failure = attach(api.make_result(name, "error", outcome["exit_code"], []), problem)
            failure["details"] = info
            return failure
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            return api.make_result(name, "error", outcome["exit_code"], [], "Formato Semgrep inesperado.")
        safe_data = Sanitizer().clean(data)
        safe_data["errors"] = safe_semgrep_errors(data)
        # Rule messages/metadata are retained; source lines, metavariables, fixes and traces are removed.
        for item in safe_data["results"]:
            extra = item.get("extra", {})
            for key in ("lines", "metavars", "dataflow_trace", "fix", "fix_regex"):
                extra.pop(key, None)
        findings = api.parse_semgrep(safe_data, bool(policy.get("fail_on_findings", True)), target)
        for finding in findings:
            finding["scanner"] = name
            if owasp:
                technical = finding["technical"]
                categories = category_mapping(technical.get("metadata", {}), info["edition"])
                finding["id"] = finding["id"].replace("semgrep-", "owasp-", 1)
                finding["category"] = "owasp"
                finding["blocking"] = finding["severity"] in policy["fail_on"]
                technical.update(owasp_categories=categories, cwe=labels(technical.get("metadata", {}).get("cwe")), evidence="[REDACTED]")
        if owasp:
            for category in info["categories"]:
                category["findings"] = sum(category["category"] in f["technical"]["owasp_categories"] for f in findings)
        fatal, problem = semgrep_diagnostic(outcome, data)
        status = "error" if fatal else api.status_from_findings(findings)
        if problem and status == "pass":
            status = "warn"
        result = api.make_result(name, status, outcome["exit_code"], findings)
        if problem:
            attach(result, problem)
        info.update(version=data.get("version"), partial=bool(problem), scanned_files=len(data.get("paths", {}).get("scanned", [])))
        result.update(raw=safe_data, details=info)
        return result


def run_gitleaks(api, target: Path, policy: dict, exclusions: Exclusions) -> dict:
    with tempfile.TemporaryDirectory(prefix="kekkai-gitleaks-config-") as folder:
        config_path = Path(folder) / "gitleaks.toml"
        custom = target / ".gitleaks.toml"
        if custom.is_file():
            if is_link(custom):
                raise ValueError("Gitleaks config não pode usar symlink/junction.")
            original = custom.read_text(encoding="utf-8-sig")
            tomllib.loads(original)
        else:
            original = '[extend]\nuseDefault = true\n'
        excluded = exclusions.gitleaks_regexes()
        # Gitleaks rejects empty allowlists. No exclusions needs no extra table.
        extra = ('\n[[allowlists]]\ndescription = "Kekkai centralized exclusions"\npaths = '
                 + json.dumps(excluded, ensure_ascii=False) + '\n') if excluded else ''
        api.write_text(config_path, original + extra)
        args = ["dir", "/src", "--config=/config/gitleaks.toml", "--redact=100", "--no-banner", "--log-level=fatal",
                "--report-format=json", "--report-path=-", "--exit-code=1"]
        outcome = scan_command(api, "gitleaks", target, "zricethezav/gitleaks:latest", args, api.GITLEAKS_TIMEOUT,
                               ["-v", f"{config_path.as_posix()}:/config/gitleaks.toml:ro"])
        data, failure = parse_outcome(outcome, "gitleaks", api)
        if failure:
            return failure
        if not isinstance(data, list):
            return api.make_result("gitleaks", "error", outcome["exit_code"], [], "Formato Gitleaks inesperado.")
        sanitizer = Sanitizer()
        sanitizer.add_gitleaks(data, target)
        findings = api.parse_gitleaks(sanitizer.clean(data), policy["fail_on_findings"], target)
        result = api.make_result("gitleaks", api.status_from_findings(findings), outcome["exit_code"], findings)
        # Private in-memory data is consumed before report consolidation and never serialized.
        result.update(raw=sanitizer.clean(data), _sensitive_data=data)
        return result


def parse_sca(api, data: dict, policy: dict, target: Path) -> tuple[list[dict], dict]:
    findings = []
    if policy["version_risk"]["enabled"]:
        findings = api.parse_trivy(data, policy["version_risk"]["fail_on"], target)
        index = 0
        for result in data.get("Results") or []:
            for vuln in result.get("Vulnerabilities") or []:
                findings[index]["technical"].update(references=vuln.get("References") or [], ecosystem=result.get("Type"),
                                                     dependency_target=api.display_path(result.get("Target"), target))
                index += 1
        for finding in findings:
            finding.update(scanner="sca", module="version_risk")
            finding["id"] = finding["id"].replace("trivy-", "sca-", 1)
    license_policy = policy["license"]
    classifications = Counter()
    if license_policy["enabled"]:
        allow = {x.casefold() for x in license_policy["allow"]}
        deny = {x.casefold() for x in license_policy["deny"]}
        fail_classes = {x.casefold() for x in license_policy["fail_on_classification"]}
        for result in data.get("Results") or []:
            for item in result.get("Licenses") or []:
                name = str(item.get("Name") or "Unknown")
                classification = str(item.get("Category") or "Unknown")
                classifications[classification] += 1
                reasons = []
                if name.casefold() in deny:
                    reasons.append("deny")
                if allow and name.casefold() not in allow:
                    reasons.append("outside_allowlist")
                if classification.casefold() in fail_classes:
                    reasons.append("classification_policy")
                finding = api.normalize_finding(scanner="sca", severity="WARN" if reasons or classification.lower() in {"unknown", "restricted", "forbidden", "reciprocal"} else "INFO",
                    blocking=bool(reasons), category="license", location={"file": api.display_path(item.get("FilePath") or result.get("Target"), target)},
                    technical={"license": name, "classification": classification, "package": item.get("PkgName"),
                               "ecosystem": result.get("Type"), "confidence": item.get("Confidence"), "policy_reasons": reasons},
                    plain_message=name, finding_key="license-" + str(item.get("PkgName")) + "-" + name, index=len(findings))
                finding.update(module="license")
                findings.append(finding)
    details = {}
    for module in ("version_risk", "license"):
        own = [f for f in findings if f["module"] == module]
        details[module] = {"status": api.status_from_findings(own) if policy[module]["enabled"] else "skipped",
                           "findings": len(own), "blocking": sum(f["blocking"] for f in own),
                           "warnings": sum(not f["blocking"] and f["severity"] != "INFO" for f in own),
                           "severity_counts": dict(Counter(f["severity"] for f in own))}
    details["license"].update(classification_counts=dict(classifications), disclaimer=tr("Indicação de risco, não parecer jurídico."))
    return findings, details


def run_sca(api, target: Path, policy: dict, exclusions: Exclusions, performance: dict) -> dict:
    scanners = [name for name, enabled in [("vuln", policy["version_risk"]["enabled"]), ("license", policy["license"]["enabled"])] if enabled]
    if not scanners:
        return api.make_result("sca", "skipped", None, [])
    java = any(path.suffix.lower() in {".jar", ".war", ".ear"} for path in exclusions.files())
    cache = TrivyCache(performance["trivy_cache"], api)
    result = None
    try:
        with cache:
            flags = cache.prepare("vuln" in scanners, java)
            args = ["fs", "--scanners", ",".join(scanners), "--format", "json", "--exit-code", "0", "--no-progress", *flags,
                    *exclusions.trivy_flags()]
            if policy["license"]["enabled"] and policy["license"]["full_scan"]:
                args.append("--license-full")
            args.append("/src")
            started = time.perf_counter()
            outcome = scan_command(api, "sca", target, TRIVY_IMAGE, args, api.TRIVY_TIMEOUT,
                                   ["-v", f"{cache.path.resolve().as_posix()}:/cache"])
            cache.metrics["trivy_scan_seconds"] = time.perf_counter() - started
            data, failure = parse_outcome(outcome, "sca", api)
            if failure:
                result = failure
            elif not isinstance(data, dict) or data.get("Results") is not None and not isinstance(data["Results"], list):
                result = api.make_result("sca", "error", outcome["exit_code"], [], "Formato Trivy inesperado.")
            else:
                findings, details = parse_sca(api, data, policy, target)
                result = api.make_result("sca", api.status_from_findings(findings), outcome["exit_code"], findings)
                result.update(raw=data, details=details)
    except Exception as error:
        # Do not propagate Docker stderr, payloads, or tracebacks into reports.
        message = str(error) if isinstance(error, RuntimeError) else "Falha no SCA/cache Trivy; verifique o acesso ao cache e Docker."
        result = api.make_result("sca", "error", None, [], message)
    result["cache"] = cache.metrics
    return result


def run_yara(api, target: Path, policy: dict, exclusions: Exclusions) -> dict:
    try:
        managed=YaraRuleManager().active_sets(auto_update=True) if policy.get('use_managed',True) else []
    except (RuleManagerError,OSError,ValueError):
        return attach(api.make_result('yara','error',None,[]),diagnostic('ruleset_error','managed_library',tr('Biblioteca YARA inválida ou incompatível. Valide-a na seção YARA Rules.')))
    manual=bool(policy['rules']) and not (policy['rules']==['.kekkai/yara/'] and not (target/'.kekkai/yara').exists())
    if not manual and not managed:
        return attach(api.make_result("yara", "skipped", None, []), diagnostic("configuration_error", "no_rules", tr("Nenhuma regra YARA configurada."), recoverable=True))
    try:
        import yara_x
    except ImportError:
        return api.make_result("yara", "error", None, [], "YARA-X não instalado. Execute python -m pip install -r requirements.txt.")
    compiler = yara_x.Compiler()
    compiler.enable_includes(False)  # Prevent rule includes from reading arbitrary host files.
    rule_files = set()
    try:
        for value in policy["rules"] if manual else []:
            path = Path(value)
            if not path.is_absolute():
                path = target / path
            if is_link(path) or not path.exists():
                raise ValueError("rules path")
            if path.is_dir():
                walker = Exclusions(path, [])
                rule_files.update(p for p in walker.files(1024 * 1024) if p.suffix.lower() in {".yar", ".yara"})
            elif path.suffix.lower() in {".yar", ".yara"} and path.stat().st_size <= 1024 * 1024:
                rule_files.add(path)
            else:
                raise ValueError("rules extension or size")
        for index, path in enumerate(sorted(rule_files)):
            compiler.new_namespace(path.stem + "_" + str(index))
            compiler.add_source(path.read_text(encoding="utf-8-sig"), origin=path.name)
        if not rule_files and not managed:
            return attach(api.make_result('yara','skipped',None,[]),diagnostic('configuration_error','no_rules',tr('Nenhuma regra YARA configurada.'),recoverable=True))
        rules = compiler.build()
    except Exception as error:
        # Compiler prose includes rule source; retain only safe location metadata.
        position = re.search(r"(?:line |:)(\d+)(?::\d+)?", str(error))
        line = int(position[1]) if position else None
        filename = path.name if 'path' in locals() else None
        compiler_code = re.search(r"error\[(E\d+)\]", str(error))
        compiler_reason = next((reason for reason in ("syntax error", "unknown identifier", "invalid regular expression", "duplicate identifier", "include") if reason in str(error).lower()), "Regra rejeitada")
        return attach(api.make_result("yara", "error", None, []), diagnostic("ruleset_error", "yara_compile" if rule_files else "yara_path",
            tr('Regra YARA inválida: {v0}', v0=filename or 'ruleset') + (f", linha {line}" if line else "") + ". Verifique sintaxe, path, tamanho e includes (desabilitados).",
            file=filename, line=line, compiler_error=(compiler_code[1] + ': ' if compiler_code else '') + compiler_reason))
    sets=[(entry,yara_x.Scanner(compiled)) for entry,compiled in managed]
    if rule_files:
        sets.append(({'origin':'Manual','version':'local'},yara_x.Scanner(rules)))
    for _,scanner in sets:scanner.set_timeout(int(policy['timeout_seconds']))
    findings = []
    scanned = 0
    total_bytes=0
    scan_started=time.monotonic()
    incomplete=0
    for path in exclusions.files(int(policy["max_file_size_mb"] * 1024 * 1024)):
        check_cancelled = getattr(api, "check_cancelled", None)
        if check_cancelled:
            check_cancelled()
        if path in rule_files:
            continue
        size=path.stat().st_size
        if time.monotonic()-scan_started>policy.get('max_scan_seconds',300) or total_bytes+size>policy.get('max_total_size_mb',1024)*1024*1024:
            incomplete+=1
            break
        scanned += 1
        total_bytes+=size
        data=path.read_bytes()
        matches=[]
        for entry,scanner in sets:
            try:
                matches.extend((entry,rule) for rule in scanner.scan(data).matching_rules if rule.identifier not in entry.get('disabled_rules',[]))
            except yara_x.TimeoutError:
                incomplete+=1
        for entry,rule in matches:
            metadata = dict(rule.metadata)
            severity = str(metadata.get("severity", "WARN")).upper()
            if severity not in api.SEVERITY_RANK:
                severity = "WARN"
            offsets = [{"pattern": pattern.identifier, "offset": match.offset, "length": match.length}
                       for pattern in rule.patterns for match in pattern.matches]
            relative = path.relative_to(target).as_posix()
            finding = api.normalize_finding(scanner="yara", severity=severity, blocking=policy["fail_on_match"], category="yara",
                location={"file": relative}, technical={"rule": rule.identifier, "namespace": rule.namespace, "tags": list(rule.tags),
                    "metadata": metadata, "offsets": offsets,'rule_origin':entry['origin'],'rule_version':entry['version']}, plain_message="Regra YARA correspondente", finding_key=rule.identifier, index=len(findings))
            finding.update(rule=rule.identifier, file=relative, tags=list(rule.tags))
            findings.append(finding)
    result = api.make_result("yara", api.status_from_findings(findings), 0, findings)
    if incomplete:
        if result['status']=='pass':result['status']='warn'
        attach(result,diagnostic('timeout','yara_limits',tr('Análise YARA parcial: {v0} limite(s)/timeout(s). Matches válidos preservados.', v0=incomplete),recoverable=True))
    result.update(raw={"findings": findings}, details={"engine": "YARA-X", "rule_files": len(rule_files), "scanned_files": scanned,
        'scanned_bytes':total_bytes,'partial':bool(incomplete),'libraries':[{k:entry.get(k) for k in ('id','origin','version','tier','valid','invalid','active','download_sha256')} for entry,_ in managed]})
    return result


def deduplicate(results: list[dict], api) -> list[dict]:
    """Keep one shared SAST finding while preserving both engines' independent policies."""
    for result in results:
        unique = {}
        for finding in result["findings"]:
            technical = finding["technical"]
            identity = (finding["scanner"], finding.get("module"), technical.get("check_id") or technical.get("rule_id") or technical.get("rule") or technical.get("vulnerability_id") or technical.get("license") or finding["title"],
                        technical.get("namespace"), technical.get("package"), technical.get("installed_version"),
                        finding["location"].get("file"), finding["location"].get("line"), finding["location"].get("url"))
            if identity in unique:
                unique[identity]["blocking"] = unique[identity]["blocking"] or finding["blocking"]
            else:
                unique[identity] = finding
        result["findings"] = list(unique.values())
        result["total_findings"] = len(result["findings"])
        result["blocking_findings"] = sum(f["blocking"] for f in result["findings"])
        result["warning_findings"] = result["total_findings"] - result["blocking_findings"]
    by_name = {result["name"]: result for result in results}
    semgrep = by_name["semgrep"]
    owasp = by_name["owasp"]
    def key(finding):
        return (finding["technical"].get("check_id"), finding["location"].get("file"), finding["location"].get("line"))
    owasp_by_key = {key(f): f for f in owasp["findings"]}
    retained = []
    for finding in semgrep["findings"]:
        shared = owasp_by_key.get(key(finding))
        if shared:
            shared["blocking"] = shared["blocking"] or finding["blocking"]
            shared["technical"]["also_detected_by"] = ["semgrep"]
            shared["technical"]["semgrep_blocking"] = finding["blocking"]
        else:
            retained.append(finding)
    semgrep["details"] = {**semgrep.get("details", {}), "shared_findings": len(semgrep["findings"]) - len(retained)}
    # Scanner counters preserve all detections; summary.findings deduplicates canonical rows.
    semgrep["findings"] = retained
    owasp["blocking_findings"] = sum(f["blocking"] for f in owasp["findings"])
    owasp["warning_findings"] = len(owasp["findings"]) - owasp["blocking_findings"]
    if owasp["status"] not in {"error", "skipped"}:
        owasp["status"] = api.status_from_findings(owasp["findings"])
        if owasp['status'] == 'pass' and owasp.get('diagnostic'):
            owasp['status'] = 'warn'
    return results
