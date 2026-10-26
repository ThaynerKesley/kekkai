"""Validated configuration with backwards-compatible Trivy policy migration."""
from .i18n import tr
from copy import deepcopy
from pathlib import Path
import math

import yaml

from .ai_providers import PROVIDERS, PROVIDER_BASE_URLS, allowed_base

EXCLUDES = ["node_modules/", "dist/", "build/", "coverage/", ".git/",
            ".security/", ".cache/", ".venv/", "__pycache__/"]
DEFAULTS = {
    "project": {"name": "", "web": None},
    "scan": {"exclude_paths": EXCLUDES},
    "performance": {"parallel": True, "max_workers": 3,
                    "trivy_cache": {"mode": "smart", "ttl_hours": 24,
                                    "max_size_mb": 750, "keep_scan_cache": False}},
    "policy": {
        "semgrep": {"enabled": False, "fail_on_findings": True},
        "gitleaks": {"enabled": False, "fail_on_findings": True},
        "sca": {"enabled": False,
                "version_risk": {"enabled": True, "fail_on": ["HIGH", "CRITICAL"]},
                "license": {"enabled": True, "full_scan": False,
                            "fail_on_classification": [], "allow": [], "deny": []}},
        "yara": {"enabled": False, "rules": [".secscan/yara/"],
                 "fail_on_match": False, "max_file_size_mb": 50, "timeout_seconds": 10},
        "owasp": {"enabled": False, "version": "auto", "fail_on": ["HIGH", "CRITICAL"]},
        "zap": {"enabled": False, "target": "", "mode": "baseline", "fail_on": ["FAIL"]},
    },
    "ai": {"enabled": "optional", "provider": None, "model": None,
           "fail_on_findings": False, "minimum_confidence": "HIGH",
           "fail_on": ["HIGH", "CRITICAL"], "max_file_size_kb": 256,
           "chunk_size_kb": 512, "max_total_size_mb": 10, "max_output_tokens": 8192,
           "timeout_seconds": 120, "guide": {"mode": "default", "path": None}},
    "reporting": {"enabled": True, "dashboard": True, "output_dir": ".security"},
}
DEFAULTS['ai'].update(max_attempts=2, max_retry_output_tokens=32768,
                      pricing={'input_per_million':None, 'output_per_million':None})
DEFAULTS['policy']['yara'].update(use_managed=True,max_scan_seconds=300,max_total_size_mb=1024)
DEFAULTS["ai"]["providers"] = {
    name: {"enabled": name in {"openai", "anthropic"}, "model": None,
           "base_url": PROVIDER_BASE_URLS.get(name, ("https://api.openai.com/v1" if name == "openai" else "https://api.anthropic.com/v1",))[0]}
    for name in PROVIDERS
}


def merge(default: dict, override: dict) -> dict:
    result = deepcopy(default)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def validate(config: dict) -> None:
    def section(value, label):
        if not isinstance(value, dict):
            raise ValueError(tr('{v0} precisa ser uma seção YAML.', v0=label))

    def boolean(value, label):
        if not isinstance(value, bool):
            raise ValueError(f"{label} precisa ser true ou false.")

    def strings(value, label):
        if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
            raise ValueError(f"{label} precisa ser uma lista de textos.")

    def positive(value, label):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError(tr('{v0} precisa ser um número positivo.', v0=label))

    for key in DEFAULTS:
        section(config[key], key)
    if config["project"].get("web") is not None:
        boolean(config["project"]["web"], "project.web")
    for name in DEFAULTS["policy"]:
        item = config["policy"][name]
        section(item, f"policy.{name}")
        boolean(item["enabled"], f"policy.{name}.enabled")
    for name in ("semgrep", "gitleaks"):
        boolean(config["policy"][name]["fail_on_findings"], f"policy.{name}.fail_on_findings")
    sca = config["policy"]["sca"]
    for name in ("version_risk", "license"):
        section(sca[name], f"sca.{name}")
        boolean(sca[name]["enabled"], f"sca.{name}.enabled")
    boolean(sca["license"]["full_scan"], "sca.license.full_scan")
    for key in ("allow", "deny", "fail_on_classification"):
        strings(sca["license"][key], f"sca.license.{key}")
    for item, label, allowed in [
        (sca["version_risk"], "sca.version_risk", {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO"}),
        (config["policy"]["owasp"], "owasp", {"LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO"}),
        (config["policy"]["zap"], "zap", {"WARN", "FAIL"}),
        (config["ai"], "ai", {"LOW", "MEDIUM", "HIGH", "CRITICAL"}),
    ]:
        strings(item["fail_on"], f"{label}.fail_on")
        item["fail_on"] = [x.upper() for x in item["fail_on"]]
        if set(item["fail_on"]) - allowed:
            raise ValueError(tr('{v0}.fail_on contém valor não suportado.', v0=label))
    strings(config["scan"]["exclude_paths"], "scan.exclude_paths")
    # Shared semantics intentionally use relative directories/files, not engine-specific globs.
    for value in config["scan"]["exclude_paths"]:
        cleaned = value.replace("\\", "/").strip("/")
        if value.startswith(("/", "\\")) or not cleaned or cleaned in {".", ".."} or ":" in cleaned or ".." in cleaned.split("/") or any(c in cleaned for c in "*?[]\n\r"):
            raise ValueError("exclude_paths aceita caminhos relativos literais, sem globs ou '..'.")
    perf = config["performance"]
    boolean(perf["parallel"], "performance.parallel")
    if type(perf["max_workers"]) is not int or not 1 <= perf["max_workers"] <= 8:
        raise ValueError("max_workers deve estar entre 1 e 8.")
    cache = perf["trivy_cache"]
    section(cache, "performance.trivy_cache")
    if cache["mode"] not in {"smart", "ephemeral", "persistent"}:
        raise ValueError("Modo do cache Trivy inválido.")
    positive(cache["ttl_hours"], "trivy_cache.ttl_hours")
    if cache["max_size_mb"] is not None:
        positive(cache["max_size_mb"], "trivy_cache.max_size_mb")
    boolean(cache["keep_scan_cache"], "trivy_cache.keep_scan_cache")
    yara = config["policy"]["yara"]
    boolean(yara['use_managed'], 'yara.use_managed')
    positive(yara['max_scan_seconds'],'yara.max_scan_seconds')
    positive(yara['max_total_size_mb'],'yara.max_total_size_mb')
    strings(yara["rules"], "yara.rules")
    boolean(yara["fail_on_match"], "yara.fail_on_match")
    positive(yara["max_file_size_mb"], "yara.max_file_size_mb")
    positive(yara["timeout_seconds"], "yara.timeout_seconds")
    if str(config["policy"]["owasp"]["version"]) not in {"auto", "2017", "2021", "2025"}:
        raise ValueError("Edição OWASP não suportada: use auto, 2017, 2021 ou 2025.")
    ai = config["ai"]
    if type(ai['max_attempts']) is not int or not 1 <= ai['max_attempts'] <= 3:
        raise ValueError('ai.max_attempts deve estar entre 1 e 3.')
    positive(ai['max_retry_output_tokens'], 'ai.max_retry_output_tokens')
    section(ai['pricing'], 'ai.pricing')
    for key in ('input_per_million','output_per_million'):
        value=ai['pricing'].get(key)
        if value is not None and (isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or value<0):
            raise ValueError('Tarifas de IA precisam ser números não negativos ou null.')
    section(ai["providers"], "ai.providers")
    for name, values in ai["providers"].items():
        if name not in PROVIDERS:
            raise ValueError(tr("Provider não suportado."))
        section(values, "ai.providers." + name)
        boolean(values["enabled"], "ai.providers." + name + ".enabled")
        if values.get("model") is not None and not isinstance(values["model"], str):
            raise ValueError("Model precisa ser texto ou null.")
        allowed_urls = PROVIDER_BASE_URLS.get(name, ("https://api.openai.com/v1" if name == "openai" else "https://api.anthropic.com/v1",))
        if values.get("base_url") not in allowed_urls and not allowed_base(name, values.get("base_url", "")):
            raise ValueError("Base URL precisa ser um endpoint oficial do provider.")
    if ai["enabled"] not in (True, False, "optional"):
        raise ValueError("ai.enabled deve ser optional, true ou false.")
    boolean(ai["fail_on_findings"], "ai.fail_on_findings")
    if ai["minimum_confidence"] not in {"LOW", "MEDIUM", "HIGH"}:
        raise ValueError("ai.minimum_confidence inválida.")
    section(ai["guide"], "ai.guide")
    if ai["guide"]["mode"] not in {"default", "custom"}:
        raise ValueError("ai.guide.mode deve ser default ou custom.")
    for key in ("max_file_size_kb", "chunk_size_kb", "max_total_size_mb", "max_output_tokens", "timeout_seconds"):
        positive(ai[key], f"ai.{key}")
    for key in ("enabled", "dashboard"):
        boolean(config["reporting"][key], f"reporting.{key}")
    for value, label in [(config["reporting"]["output_dir"], "reporting.output_dir"),
                         (config["policy"]["zap"]["target"], "zap.target"),
                         (config["project"]["name"], "project.name")]:
        if not isinstance(value, str):
            raise ValueError(f"{label} precisa ser um texto.")
    if not config["reporting"]["output_dir"].strip():
        raise ValueError("reporting.output_dir não pode ser vazio.")
    # Credentials must never become reporting configuration, even through unknown YAML fields.
    def reject_credentials(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if str(key).lower().replace("-", "_") in {"api_key", "apikey", "password", "token", "secret", "authorization"}:
                    raise ValueError(tr("Credenciais não são permitidas no YAML; use entrada oculta para IA."))
                reject_credentials(value)
        elif isinstance(node, list):
            for value in node:
                reject_credentials(value)
    reject_credentials(config)


def load(target: Path, profile: str = "full") -> dict:
    path = target / ".secscan.yml"
    if not path.is_file():
        raise ValueError(tr(".secscan.yml não encontrado"))
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    except yaml.YAMLError:
        raise ValueError(tr(".secscan.yml inválido; verifique a sintaxe YAML.")) from None
    if not isinstance(loaded, dict) or not isinstance(loaded.get("policy"), dict):
        raise ValueError(tr(".secscan.yml sem a seção policy"))
    loaded = deepcopy(loaded)
    legacy = loaded["policy"].get("trivy")
    if legacy is not None and "sca" not in loaded["policy"]:
        if not isinstance(legacy, dict):
            raise ValueError("policy.trivy precisa ser uma seção YAML.")
        loaded["policy"]["sca"] = {"enabled": legacy.get("enabled", False),
            "version_risk": {"enabled": True, "fail_on": legacy.get("severity", ["HIGH", "CRITICAL"])},
            "license": {"enabled": False}}
    config = merge(DEFAULTS, loaded)
    validate(config)
    if profile == "quick":
        config["policy"]["zap"]["enabled"] = False
        config["policy"]["sca"]["license"]["full_scan"] = False
    config["profile"] = profile
    return config
