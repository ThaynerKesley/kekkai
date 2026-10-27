"""Shared finding contracts, scanner parsers and report generation."""
import json
import os
import re
import subprocess
import time
from datetime import datetime
from html import unescape
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse


from kekkai.i18n import tr, TranslatedLabels, translate, get_language


SCANNER_ORDER = ("semgrep", "gitleaks", "sca", "yara", "owasp", "zap", "ai")
DISPLAY_NAMES = {
    "semgrep": "Semgrep",
    "gitleaks": "Gitleaks",
    "trivy": "Trivy",
    "sca": "SCA",
    "yara": "YARA Rules",
    "owasp": "OWASP Top 10",
    "ai": "AI Security Review",
    "zap": "ZAP",
}
STATUS_LABELS = {
    "pass": "PASS",
    "warn": "WARN",
    "fail": "COMPLETED WITH ERROR",
    "error": "ERROR",
    "skipped": "SKIPPED",
}
RESULT_LABELS = TranslatedLabels({
    "approved": "APROVADO",
    "blocked": "BLOQUEADO",
    "error": "ERRO",
})
RESULT_MESSAGES = TranslatedLabels({
    "approved": "Nenhum problema configurado como bloqueante foi identificado.",
    "blocked": "Foram identificados problemas que precisam ser corrigidos antes da publicação.",
    "error": "Uma ou mais verificações de segurança não puderam ser concluídas.",
})
SEVERITY_RANK = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "WARN": 3,
    "LOW": 4,
    "INFO": 5,
}
SEMGREP_TIMEOUT = 600
GITLEAKS_TIMEOUT = 300
TRIVY_TIMEOUT = 600
ZAP_TIMEOUT = 900
ALLOWED_ZAP_HOSTS = {"localhost", "127.0.0.1", "host.docker.internal"}


def write_text(path: Path, content: str) -> None:
    from kekkai.files import atomic_write_text
    atomic_write_text(path, content)


def write_json(path: Path, data: Any) -> None:
    write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def container_name(scanner: str) -> str:
    return f"kekkai-{scanner}-{os.getpid()}-{int(time.time())}"


def docker_command(
    name: str,
    docker_args: list[str],
    image: str,
    image_args: list[str],
) -> list[str]:
    return ["docker", "run", "--rm", "--pull", "missing", "--name", name, *docker_args, image, *image_args]


def stop_container(name: str) -> None:
    try:
        subprocess.run(
            ["docker", "rm", "-f", name],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            stdin=subprocess.DEVNULL,
        )
    except Exception:
        pass


def trim_output(text: str, limit: int = 400) -> str:
    compact = " ".join((text or "").split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1].rstrip() + "…"


def docker_infrastructure_error(stdout: str, stderr: str) -> str | None:
    text = f"{stdout}\n{stderr}".lower()
    if any(
        marker in text
        for marker in (
            "cannot connect to the docker daemon",
            "docker daemon is not running",
            "error during connect",
            "docker_engine",
            "npipe",
        )
    ):
        return tr("Docker não está em execução ou não está acessível.")
    if any(marker in text for marker in ("unable to find image", "manifest unknown", "pull access denied")):
        return "Não foi possível obter a imagem Docker do scanner."
    if "manifest for" in text and "not found" in text:
        return "Não foi possível obter a imagem Docker do scanner."
    if "executable file not found" in text:
        return "O comando do scanner não foi encontrado na imagem Docker."
    return None


def run_docker(command: list[str], timeout: int, name: str) -> dict:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        stop_container(name)
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "error": tr('Tempo esgotado após {v0}s.', v0=timeout),
            "infrastructure": False,
        }
    except FileNotFoundError:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "error": tr("Docker não encontrado no PATH."),
            "infrastructure": True,
        }
    except Exception:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "error": "Falha ao iniciar o processo do scanner.",
            "infrastructure": True,
        }

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    infra = docker_infrastructure_error(stdout, stderr) if completed.returncode != 0 else None
    return {
        "exit_code": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "error": infra,
        "infrastructure": infra is not None,
    }


def display_path(path: str | None, target: Path | None = None) -> str | None:
    if not path:
        return None
    normalized = str(path).replace("\\", "/")
    for prefix in ("/src/", "src/"):
        if normalized.startswith(prefix):
            return normalized[len(prefix) :]
    if normalized.startswith("/src"):
        return normalized[4:].lstrip("/") or None
    if target is not None:
        try:
            return Path(path).resolve().relative_to(target.resolve()).as_posix()
        except Exception:
            pass
    return normalized


def shorten(text: str, limit: int = 360) -> str:
    compact = " ".join((text or "").split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1].rstrip() + "…"


def strip_html(value: str | None) -> str:
    if not value:
        return ""
    text = re.sub(r"(?i)<br\s*/?>", "\n", value)
    text = re.sub(r"(?i)</p>", "\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = unescape(text)
    text = text.replace("\r", "")
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def make_id(scanner: str, index: int, key: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "-", key or "").strip("-") or "item"
    return f"{scanner}-{index + 1}-{safe[:80]}"


def mask_secret(value: str) -> str:
    return "SECRET_REDACTED"


def make_result(
    name: str,
    status: str,
    exit_code: int | None,
    findings: list[dict],
    error: str | None = None,
) -> dict:
    total = len(findings)
    blocking = sum(1 for item in findings if item.get("blocking"))
    result = {
        "name": name,
        "status": status,
        "exit_code": exit_code,
        "total_findings": total,
        "blocking_findings": blocking,
        "warning_findings": total - blocking,
        "findings": findings,
        "error": error,
    }
    if error:
        from kekkai.diagnostics import diagnostic
        result["diagnostic"] = diagnostic("scanner_error", "scanner_failure", error)
    return result


def status_from_findings(findings: list[dict]) -> str:
    if any(item.get("blocking") for item in findings):
        return "fail"
    if findings:
        return "warn"
    return "pass"


def unexpected_failure(scanner: str) -> dict:
    label = DISPLAY_NAMES.get(scanner, scanner)
    return make_result(
        scanner,
        "error",
        None,
        [],
        tr('{v0} encontrou uma falha inesperada e não concluiu.', v0=label),
    )


def resolve_project_name(config: dict, target: Path) -> str:
    configured = (config.get("project") or {}).get("name") or ""
    if isinstance(configured, str) and configured.strip():
        return configured.strip()
    folder = target.resolve().name.strip()
    if folder and folder not in {".", ".."}:
        return folder
    anchor = target.resolve().anchor.strip("\\/")
    return anchor or "projeto"


def prepare_output_dirs(
    target: Path,
    output_dir: str,
    history_timestamp: str | None = None,
) -> dict[str, Path]:
    """Cria as pastas do scan atual.

    history_timestamp reserva o layout .security/history/<timestamp>/ para
    uma versão futura. O scan atual sempre grava em reports/ e sobrescreve.
    """
    root = Path(output_dir)
    if not root.is_absolute():
        root = target / root
    if history_timestamp:
        reports = root / "history" / history_timestamp
    else:
        reports = root / "reports"
    raw = reports / "raw"
    dashboard = root / "dashboard"
    from kekkai.files import safe_directory
    safe_directory(raw)
    safe_directory(dashboard)
    return {"root": root, "reports": reports, "raw": raw, "dashboard": dashboard}


def executive_copy(scanner: str, technical: dict, plain_message: str, *, language: str | None = None) -> dict[str, str]:
    def text(message, **values):
        return translate(message, language or get_language()).format(**values)

    if scanner in {"trivy", "sca"} and "license" in technical:
        return {
            "title": text("Licença: ") + str(technical["license"]),
            "description": text("Classificação da ferramenta: ") + str(technical.get("classification", "Unknown")) + text(". Indicação de risco; não é parecer jurídico."),
            "impact": text("Obrigações e permissões dependem do contexto de uso e distribuição."),
            "recommendation": text("Validar a licença conforme a política da organização."),
        }
    if scanner == "yara":
        return {
            "title": "YARA Rules: " + str(technical.get("rule", "")),
            "description": text("O arquivo corresponde à regra. Isso é um sinal para investigação, não confirmação automática de malware. Conteúdo do match omitido."),
            "impact": text("O match exige investigação do arquivo e do contexto da regra."),
            "recommendation": text("Revisar o arquivo e a regra correspondente."),
        }
    if scanner in {"trivy", "sca"}:
        package = technical.get("package") or text("uma dependência")
        severity = text({"CRITICAL": "crítica", "HIGH": "alta", "MEDIUM": "média", "LOW": "baixa",
                         "UNKNOWN": "desconhecida", "INFO": "informativa"}.get(str(technical.get("severity")).upper(), "conhecida"))
        fixed = technical.get("fixed_version") or ""
        if fixed:
            recommendation = text('Atualizar {v0} para a versão {v1}.', v0=package, v1=fixed)
        else:
            recommendation = text('Atualizar {v0} para uma versão corrigida.', v0=package)
        return {
            "title": text("Dependência vulnerável"),
            "description": (
                text('O projeto utiliza uma versão de {v0} com uma vulnerabilidade conhecida de severidade {v1}.', v0=package, v1=severity)
            ),
            "impact": text("Essa falha pode afetar a disponibilidade ou a segurança da aplicação."),
            "recommendation": recommendation,
        }
    if scanner == "gitleaks":
        return {
            "title": text("Segredo exposto no projeto"),
            "description": (
                text("Foi encontrado um possível segredo no código ou em um arquivo do projeto. "
                "O valor foi ocultado neste relatório.")
            ),
            "impact": text("Credenciais expostas podem permitir acesso indevido a sistemas e dados."),
            "recommendation": (
                text("Remover o segredo do projeto, rotacionar a credencial e passar a "
                "guardá-la fora do código.")
            ),
        }
    if scanner == "zap":
        return {
            "title": text("Risco na aplicação web"),
            "description": text("A aplicação apresentou um alerta de segurança. Consulte o alerta original nos detalhes técnicos."),
            "impact": text("Esse ponto pode indicar uma configuração insegura ou um comportamento abusável."),
            "recommendation": text("Aplicar a correção recomendada para este alerta. Consulte a solução original nos detalhes técnicos."),
        }
    rule_id = technical.get("check_id") or text("indicada")
    return {
        "title": text("Possível problema no código"),
        "description": text("O scanner identificou um possível problema na regra {v0}. Consulte a mensagem original nos detalhes técnicos.", v0=rule_id),
        "impact": text("O trecho indicado pode introduzir uma falha se chegar à publicação."),
        "recommendation": text("Revisar o trecho apontado e corrigir conforme a regra {v0}.", v0=rule_id),
    }


def normalize_finding(
    *,
    scanner: str,
    severity: str,
    blocking: bool,
    category: str,
    location: dict,
    technical: dict,
    plain_message: str,
    finding_key: str,
    index: int,
) -> dict:
    copy = executive_copy(scanner, technical, plain_message)
    return {
        "id": make_id(scanner, index, finding_key),
        "scanner": scanner,
        "title": copy["title"],
        "description": copy["description"],
        "severity": severity,
        "blocking": blocking,
        "category": category,
        "location": {
            "file": location.get("file"),
            "line": location.get("line"),
            "url": location.get("url"),
        },
        "technical": technical,
        "recommendation": copy["recommendation"],
        "impact": copy["impact"],
    }


def map_semgrep_severity(value: str | None) -> str:
    normalized = (value or "").upper()
    return {
        "ERROR": "HIGH",
        "HIGH": "HIGH",
        "CRITICAL": "CRITICAL",
        "WARNING": "MEDIUM",
        "MEDIUM": "MEDIUM",
        "INFO": "INFO",
        "LOW": "LOW",
    }.get(normalized, "MEDIUM")


def parse_semgrep(data: Any, fail_on_findings: bool, target: Path | None = None) -> list[dict]:
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return []
    findings = []
    for index, item in enumerate(results):
        if not isinstance(item, dict):
            continue
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        start = item.get("start") if isinstance(item.get("start"), dict) else {}
        end = item.get("end") if isinstance(item.get("end"), dict) else {}
        check_id = str(item.get("check_id") or "semgrep-rule")
        message = str(extra.get("message") or "")
        severity = map_semgrep_severity(str(extra.get("severity") or ""))
        path = display_path(item.get("path"), target)
        line = start.get("line")
        findings.append(
            normalize_finding(
                scanner="semgrep",
                severity=severity,
                blocking=bool(fail_on_findings),
                category=str(metadata.get("category") or "sast"),
                location={"file": path, "line": line, "url": None},
                technical={
                    "check_id": check_id,
                    "message": message,
                    "severity": severity,
                    "column": start.get("col"),
                    "end_line": end.get("line"),
                    "end_column": end.get("col"),
                    "path": path,
                    "metadata": metadata,
                },
                plain_message=message,
                finding_key=check_id,
                index=index,
            )
        )
    return findings


def parse_gitleaks(data: Any, fail_on_findings: bool, target: Path | None = None) -> list[dict]:
    items = data
    if isinstance(data, dict):
        items = data.get("findings") or data.get("Results") or []
    if not isinstance(items, list):
        return []
    findings = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("RuleID") or item.get("ruleID") or item.get("RuleId") or "gitleaks")
        description = str(item.get("Description") or item.get("description") or "")
        path = display_path(item.get("File") or item.get("file"), target)
        start_line = item.get("StartLine")
        if start_line is None:
            start_line = item.get("startLine")
        end_line = item.get("EndLine")
        if end_line is None:
            end_line = item.get("endLine")
        match = item.get("Match") or item.get("match") or ""
        masked_match = mask_secret(match) if isinstance(match, str) else "SECRET_REDACTED"
        findings.append(
            normalize_finding(
                scanner="gitleaks",
                severity="HIGH",
                blocking=bool(fail_on_findings),
                category="secret",
                location={"file": path, "line": start_line, "url": None},
                technical={
                    "rule_id": rule_id,
                    "description": description,
                    "file": path,
                    "start_line": start_line,
                    "end_line": end_line,
                    "match": masked_match,
                },
                plain_message=description,
                finding_key=rule_id,
                index=index,
            )
        )
    return findings


def parse_trivy(data: Any, blocking_severities: list[str], target: Path | None = None) -> list[dict]:
    if not isinstance(data, dict):
        return []
    blocking = {item.upper() for item in blocking_severities}
    findings = []
    index = 0
    for result in data.get("Results") or []:
        if not isinstance(result, dict):
            continue
        scanned_target = display_path(str(result.get("Target") or ""), target)
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            reported_severity = str(vuln.get("Severity") or "UNKNOWN").upper()
            severity = reported_severity
            if severity not in SEVERITY_RANK:
                severity = "INFO"
            package = str(vuln.get("PkgName") or tr("dependência"))
            vuln_id = str(vuln.get("VulnerabilityID") or "vulnerabilidade")
            findings.append(
                normalize_finding(
                    scanner="trivy",
                    severity=severity,
                    blocking=severity in blocking or reported_severity in blocking,
                    category="dependency",
                    location={"file": scanned_target, "line": None, "url": None},
                    technical={
                        "vulnerability_id": vuln_id,
                        "package": package,
                        "installed_version": vuln.get("InstalledVersion") or "",
                        "fixed_version": vuln.get("FixedVersion") or "",
                        "severity": severity,
                        "title": vuln.get("Title") or "",
                        "description": vuln.get("Description") or "",
                        "primary_url": vuln.get("PrimaryURL") or "",
                        "target": scanned_target,
                    },
                    plain_message=str(vuln.get("Title") or vuln_id),
                    finding_key=f"{package}-{vuln_id}",
                    index=index,
                )
            )
            index += 1
    return findings


def zap_severity(riskcode: str | None, riskdesc: str | None) -> str:
    code = str(riskcode or "")
    mapped = {"0": "INFO", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}.get(code)
    if mapped:
        return mapped
    text = (riskdesc or "").lower()
    if "high" in text:
        return "HIGH"
    if "medium" in text:
        return "MEDIUM"
    if "low" in text:
        return "LOW"
    if "info" in text:
        return "INFO"
    return "INFO"


def zap_confidence(value: str | None) -> str:
    return {
        "0": "False Positive",
        "1": "Low",
        "2": "Medium",
        "3": "High",
        "4": "Confirmed",
    }.get(str(value or ""), str(value or ""))


def zap_alert_blocking(severity: str, fail_on: list[str]) -> bool:
    configured = {item.upper() for item in fail_on}
    if severity == "HIGH" and "FAIL" in configured:
        return True
    if severity == "MEDIUM" and "WARN" in configured:
        return True
    return False


def parse_zap(data: Any, fail_on: list[str]) -> list[dict]:
    sites = []
    if isinstance(data, dict):
        sites = data.get("site") or []
    elif isinstance(data, list):
        sites = data
    if isinstance(sites, dict):
        sites = [sites]
    if not isinstance(sites, list):
        return []
    findings = []
    index = 0
    for site in sites:
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts") or []
        if not isinstance(alerts, list):
            continue
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            name = str(alert.get("alert") or alert.get("name") or "Alerta ZAP")
            severity = zap_severity(alert.get("riskcode"), alert.get("riskdesc"))
            instances = alert.get("instances") or []
            urls = []
            if isinstance(instances, list):
                for instance in instances:
                    if isinstance(instance, dict) and instance.get("uri"):
                        urls.append(str(instance["uri"]))
            description = strip_html(str(alert.get("desc") or alert.get("description") or ""))
            solution = strip_html(str(alert.get("solution") or ""))
            reference = strip_html(str(alert.get("reference") or ""))
            findings.append(
                normalize_finding(
                    scanner="zap",
                    severity=severity,
                    blocking=zap_alert_blocking(severity, fail_on),
                    category="dast",
                    location={"file": None, "line": None, "url": urls[0] if urls else None},
                    technical={
                        "alert": name,
                        "risk": alert.get("riskdesc") or severity,
                        "confidence": zap_confidence(alert.get("confidence")),
                        "description": description,
                        "solution": solution,
                        "reference": reference,
                        "plugin_id": str(alert.get("pluginid") or alert.get("alertRef") or ""),
                        "urls": urls[:20],
                    },
                    plain_message=name,
                    finding_key=str(alert.get("pluginid") or name),
                    index=index,
                )
            )
            index += 1
    return findings


def classify_zap(exit_code: int, fail_on: list[str]) -> str:
    configured = {item.upper() for item in fail_on}
    if exit_code == 0:
        return "pass"
    if exit_code == 2:
        if "WARN" in configured:
            return "fail"
        return "warn"
    if exit_code == 1:
        if "FAIL" in configured:
            return "fail"
        return "warn"
    return "error"


def zap_fallback_url(target_url: str) -> str | None:
    parsed = urlparse(target_url)
    host = (parsed.hostname or "").lower()
    if host not in {"localhost", "127.0.0.1"}:
        return None
    port = f":{parsed.port}" if parsed.port else ""
    userinfo = ""
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo += f":{parsed.password}"
        userinfo += "@"
    return urlunparse(parsed._replace(netloc=f"{userinfo}host.docker.internal{port}"))


def validate_zap_target(target_url: str) -> tuple[bool, str]:
    """Limita o ZAP a alvos locais.

    Extensões previstas e ainda não implementadas: *.local, *.test,
    allowlist explícita e uma flag de override. Active scan remoto
    não faz parte desta versão.
    """
    try:
        parsed = urlparse(target_url)
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return False, tr("Alvo ZAP inválido; verifique URL e porta.")
    if parsed.scheme not in {"http", "https"} or not hostname:
        return False, tr("Alvo ZAP inválido; use HTTP/HTTPS e host local.")
    if hostname not in ALLOWED_ZAP_HOSTS:
        return False, tr("Alvo ZAP bloqueado por segurança; apenas hosts locais são permitidos.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment or any(c in target_url for c in '\r\n') or port == 0:
        return False, tr("Alvo ZAP inválido; remova credenciais, query e fragmento da URL.")
    return True, ""


def decide_result(results: list[dict]) -> str:
    statuses = [item["status"] for item in results]
    if "error" in statuses:
        return "error"
    if "fail" in statuses:
        return "blocked"
    return "approved"


def build_totals(findings: list[dict]) -> dict:
    totals = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "warning": 0,
        "info": 0,
        "blocking": 0,
        "total": len(findings),
    }
    buckets = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "WARN": "warning",
        "INFO": "info",
    }
    for finding in findings:
        bucket = buckets.get(finding.get("severity") or "")
        if bucket and bucket != "warning":
            totals[bucket] += 1
        if finding.get("blocking"):
            totals["blocking"] += 1
        elif finding.get("severity") != "INFO":
            totals["warning"] += 1
    return totals


def build_summary(config: dict, target: Path, project_name: str, results: list[dict]) -> dict:
    by_name = {item["name"]: item for item in results}
    findings: list[dict] = []
    for scanner in SCANNER_ORDER:
        findings.extend(by_name[scanner]["findings"])
    findings.sort(
        key=lambda item: (
            not item.get("blocking"),
            SEVERITY_RANK.get(item.get("severity") or "", 9),
            SCANNER_ORDER.index(item.get("scanner") or "zap"),
            item.get("title") or "",
        )
    )
    result = decide_result(results)
    scanners = {}
    for scanner in SCANNER_ORDER:
        item = by_name[scanner]
        scanners[scanner] = {
            "status": item["status"],
            "findings": item["total_findings"],
            "total_findings": item["total_findings"],
            "blocking_findings": item["blocking_findings"],
            "warning_findings": item["warning_findings"],
            "exit_code": item["exit_code"],
            "error": item["error"],
            "diagnostic": item.get("diagnostic"),
            "duration_seconds": item.get("duration_seconds", 0),
            "parallel_with": item.get("parallel_with", []),
            **item.get("details", {}),
        }
    # Compatibility alias for consumers of the previous dependency scanner key.
    sca_info = scanners["sca"]
    version_info = sca_info.get("version_risk", {})
    scanners["trivy"] = {**sca_info, "alias_of": "sca", "status": version_info.get("status", sca_info["status"]),
                         "findings": version_info.get("findings", sca_info["findings"]),
                         "total_findings": version_info.get("findings", sca_info["findings"]),
                         "blocking_findings": version_info.get("blocking", sca_info["blocking_findings"])}
    return {
        "project": project_name,
        "language": get_language(),
        "target": str(target),
        "zap_target": config["policy"]["zap"].get("target") or "",
        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        "result": result,
        "message": RESULT_MESSAGES[result],
        "totals": build_totals(findings),
        "scanners": scanners,
        "findings": findings,
        "policy": config["policy"],
    }


def render_dashboard(summary: dict) -> str:
    from kekkai.dashboard import render
    return render(summary)


def generate_dashboard(summary: dict, destination: Path) -> Path:
    write_text(destination, render_dashboard(summary))
    return destination
