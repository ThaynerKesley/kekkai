# Kekkai

<p align="center">
  <img src="kekkai/assets/logo+nome.png" alt="Kekkai logo" width="320">
</p>

**A local security workspace for code, dependencies, secrets, YARA rules, and web applications.**

[English](README.md) · [Português (Brasil)](README.pt-BR.md) · [MIT license](LICENSE)

Created by **Thayner Kesley**. Kekkai brings independent security tools into a PySide6 desktop application. It applies your policies, preserves useful partial results, and generates an offline HTML dashboard. Findings are signals to investigate; an approved scan does not prove that software is secure.

## Usage video

Watch the usage walkthrough directly in the player below.

https://github.com/user-attachments/assets/04db24dc-0ab5-4170-8df3-3e8485dfd3ef

## What it does

| Check | Engine | Purpose |
| --- | --- | --- |
| Static analysis | Semgrep CE | Code patterns and security findings |
| Secrets | Gitleaks | Exposed credentials, with configurable rules |
| Software composition | Trivy | Dependency vulnerabilities and license indicators |
| YARA Rules | YARA-X | Validated Forge/custom detection and hunting rules |
| OWASP Top 10 | Semgrep Registry | Findings mapped to an available OWASP edition |
| Local web application | OWASP ZAP baseline | Dynamic checks against a running local target |
| Optional AI review | OpenAI, Anthropic, DeepSeek, Qwen | Structured, consented review with manual validation |

The desktop includes project selection, quick/full profiles, scanner policies, progress, cancellation, report history/export/deletion, a YARA Rule Manager, light/dark themes, and Portuguese/English interfaces. Kekkai provides a graphical desktop interface only.

## Requirements

- Python **3.11+** and `pip` in a virtual environment. Development validation uses Python 3.13 on Windows.
- Docker with Linux containers for Semgrep, Gitleaks, Trivy, OWASP, and ZAP. On Windows, use Docker Desktop with its Linux/WSL2 engine.
- YARA-X runs natively through the Python package; the managed library requires `yara-x >=1.21,<2`.
- PySide6/Qt WebEngine is installed with `requirements.txt`. Linux desktop installations may need the platform dependencies required by Qt.
- Internet access is needed for initial dependency/image/database/rule downloads and AI requests. The saved dashboard and previously validated YARA library work offline. Other scanners depend on their own cached resources and upstream behavior.

Kekkai uses the installed Docker executable and third-party images (`semgrep/semgrep:latest`, `zricethezav/gitleaks:latest`, `aquasec/trivy:latest`, `ghcr.io/zaproxy/zaproxy:stable`). Those tags can change independently of Kekkai.

## Install and start

Windows / PowerShell:

```powershell
git clone https://github.com/ThaynerKesley/kekkai.git
Set-Location kekkai
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe kekkai.py --language en
```

To start without a console window on Windows, use `.\.venv\Scripts\pythonw.exe -m kekkai`.

Open a project directly:

```powershell
.\.venv\Scripts\python.exe kekkai.py C:\path\to\project --language en
```

Linux desktop / WSL with graphical application support:

```bash
git clone https://github.com/ThaynerKesley/kekkai.git
cd kekkai
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
docker info
.venv/bin/python -m kekkai --language en
```

The application opens a desktop window. Vulnerable dependencies and dummy credentials used by regression tests are created in isolated temporary projects.

## Skins

In **Settings → Workspace and appearance**, select a **Skin**: **Violet**,
**Retro**, **Hardware**, or **Monochrome CRT**, each with light and dark modes.
Monochrome CRT uses sage monochrome panels, pixel details and dithered charts.
Skin changes apply and save immediately;
the selected skin and its logo also appear in the report viewer and HTML exports.
The built-in registry, palettes and stylesheets live in `kekkai/skins/`.

## Choose your language

```powershell
python kekkai.py --language en
python kekkai.py --language pt_BR
python -m kekkai --language en
```

The desktop language can also be saved in **Settings → Language**. Restart Kekkai to apply a changed preference. Portuguese is the compatibility default. The generated dashboard uses the active language. Project names, paths, machine-readable keys/statuses, rule metadata, and external finding text retain their original values/language.

The application package is `kekkai`; `python kekkai.py` and `python -m kekkai` both open the same GUI. Startup accepts an optional project directory and language. Scanner selection, profiles, review consent and report management are handled inside the application.

## First scan

1. Open a project in the desktop application. Choose **Local code / non-web** or **Web application**. Imported projects without this setting prompt for it.
2. Review **Scanners**, exclusions, and policies. New desktop projects initially enable the static checks; an existing project YAML takes precedence.
3. Install **Core** in **YARA Rules**, or import your own rules, then enable the YARA scanner when desired.
4. Use **Quick scan** or **Full scan** on the overview to open the Scan page with that profile. Finish configuring the project and scanners, then click **START**. These shortcuts never start a scan. AI always requires a separate request and confirmation.
5. Inspect findings, partial coverage, and diagnostics. Save the project configuration explicitly if you want to persist it to YAML.

Use **Save configuration** in the GUI to write `.kekkai.yml` inside the selected project. For a prepared configuration, copy the reviewed example:

```powershell
Copy-Item .kekkai.example.yml C:\path\to\project\.kekkai.yml
```

The complete example is [`.kekkai.example.yml`](.kekkai.example.yml). API keys never belong in project YAML.

### Profiles and scan decisions

- **Quick:** disables ZAP, AI, and full license scanning; other configured static checks remain available.
- **Full:** runs enabled checks. The GUI requests and confirms optional AI review; `ai.enabled` alone never sends source.
- Internal scanner states are `pass`, `warn`, `fail`, `error`, and `skipped`. Finished checks display **COMPLETED**; technical errors and partial coverage appear in **Diagnostic**. Skipped checks remain **SKIPPED**. Internal statuses and policy blocking are preserved.
- Overall decisions are `approved`, policy `blocked`, or technical `error`. Technical errors take precedence. Warnings and skipped checks do not by themselves block publication. These are report decisions; closing the GUI does not return a scan result code.
- A scanner failure does not cancel the remaining checks. Isolated parsing warnings preserve available findings and show partial coverage. Skipped or partial checks must be considered when interpreting approval.

Recent projects can be removed from **Projects → Remove from recents**. This changes only the local shortcut list; removing the active project keeps it open and preserves its files and reports.

## Configuration

Project YAML controls project type, literal relative exclusions, enabled scanners, severity thresholds, YARA limits, OWASP edition, ZAP target, AI limits, parallelism, reporting, and Trivy cache behavior. Simple exclusion folder names match at any depth; paths are literal, not shell globs.

SCA has separate **Version Risk** and **Licensing** policies. License deny rules, nonempty allowlists, and blocking classifications are cumulative. License results indicate risk and require context; they are not legal advice. Older `policy.trivy` configurations migrate to SCA while preserving their earlier behavior.

Independent checks use up to `performance.max_workers` workers (1–8, default 3). AI follows secret scanning so flagged files can be excluded. Cancellation stops containers owned by that run; an active download/HTTP request may need to reach its timeout before shutdown completes. The last complete report is retained if cancellation occurs before persistence.

## YARA Rule Manager

**YARA Rules** integrates the [official YARA Forge releases](https://github.com/YARAHQ/yara-forge/releases). **Core** is the default tier; **Extended** and **Full** are advanced options with higher resource use and potential false positives. Rules have their own licenses and provenance; downloading a ruleset does not relicense it under Kekkai's MIT license.

The manager provides:

- Official SHA-256 verification, bounded downloads/extraction, and staged native YARA-X validation before activation.
- Valid/invalid/active counts, rule names, tags, author/license metadata, origin, version, and safe compatibility diagnostics. Private support rules count as valid but are not active detections.
- Custom `.yar`/`.yara` import; contained includes are expanded. Traversal, cyclic/outside includes and unsupported modules are rejected or quarantined. Invalid rules and affected dependencies are never activated.
- Manual updates, optional configurable automatic checks before scans, immutable history, library/rule disabling, revalidation, and rollback.
- Offline use of the last validated sources. Source hashes and engine version are checked on load. Native rules are compiled in memory and cached for the process; no compiled signature binary is required on disk. Engine upgrades require revalidation.

Validation runs in a child with a 120-second timeout and a 2 GiB memory limit. Default scanning limits are 50 MiB per file, 10 seconds per file, 300 seconds total, and 1,024 MiB of scanned input. Reaching a limit preserves valid matches and marks the result partial. Rule validation/compilation and file I/O add overhead outside the aggregate scan timer. No match bytes are included in reports.

A harmless custom acceptance rule:

```yara
rule Kekkai_Harmless_Test : test {
    meta:
        author = "Your name"
        license = "MIT"
    strings:
        $marker = "KEKKAI_HARMLESS_TEST_MARKER"
    condition:
        $marker
}
```

Import the rule, enable YARA, and scan a text file containing the marker. Results identify the rule, file, tags, metadata, and library version. A match is an investigation signal, **not confirmed malware**. Legacy `policy.yara.rules` paths remain supported; direct manual-rule includes are disabled.

## AI review and cost estimates

Configure an official provider endpoint/model in **AI Review**. DeepSeek uses API model IDs `deepseek-v4-pro` and `deepseek-flash`; the version alias `DeepSeek-V4-Pro-0813` is normalized. Qwen supports the documented regional endpoints and constrained official workspace endpoints. Capabilities determine JSON/schema mode; local schema and file/line validation always apply.

Each review requires explicit consent showing selected files, approximate size, the resolved guide path/size, request count, and token/cost estimates. Repository-selected external/excluded guides require explicit local selection; secret-bearing guides are rejected. The built-in guide is [`kekkai/prompts/security.md`](kekkai/prompts/security.md). A locally chosen external guide remains supported and is disclosed in consent.

Requests contain only the guide and current source group, without conversation history or previous responses. Known sensitive files, excluded paths, detected secret files and size-limited files are omitted. Bounded retries address truncated/invalid responses: default 2 attempts per group, initially 8,192 output tokens, up to 32,768 on retry. Exhausted groups are recorded and later groups continue; authentication/configuration incompatibilities stop further requests. Valid earlier findings are preserved and incomplete reviews remain errors.

Tokens reported by the API are aggregated, including available failed-response usage, cache hits and reasoning usage. Costs are **estimates**, not billing records. Calls that time out without usage may still be charged by the provider. Input token planning uses a bytes/3 heuristic; output budgets and retry limits are configurable.

The built-in DeepSeek price snapshot is dated **2026-10-26**, with a cache-aware off-peak/peak range. For example, 100,000 uncached input tokens plus 20,000 output tokens on V4 Pro estimates **US$0.1056–0.2112**. Verify the [official pricing](https://api-docs.deepseek.com/quick_start/pricing/); rates can change. Other models/providers can use manual USD-per-million input/output rates in the AI policy. No account/billing API is queried.

Keys are masked and memory-only by default. Explicitly saving a key on Windows uses **Windows Credential Manager**, without a plaintext fallback. Provider configuration can be saved independently of keys. Connection tests send only a minimal no-source message and can consume API tokens. AI findings always require manual validation; provider retention policies apply to submitted content.

## Reports, history, and privacy

Default project output:

```text
.security/
  reports/summary.json
  reports/raw/                 # Reduced/sanitized scanner results
  dashboard/index.html         # Self-contained HTML
  history/<timestamp-id>/      # Desktop snapshots; raw files are flattened here
```

The desktop lists the current result and archived runs. Select an entry in **Reports** to open its dashboard in Kekkai or in your default browser, export a standalone **HTML**, generate a **PDF**, open summary/raw data, export a ZIP, or delete the report after confirmation. Deleting the current result does not delete separate history; deleting one snapshot preserves other runs, source, and cache. Completed GUI runs archive their results in the local report history.

On the Scan page, **Open dashboard when complete** lets you choose **Kekkai** or **Browser**. Save the default viewer in **Settings → Open report in**.

Browser/HTML reports use the Kekkai dashboard with embedded branding, charts, search, filters, grouping, technical detail and light/dark themes. The HTML is self-contained and requires no server or internet connection. Export actions are also available above the integrated dashboard. PDF exports use a separate light A4 layout and include every finding and its technical details, regardless of the current on-screen filters. Generating a PDF does not change the dashboard you are viewing. Browser reports also provide **Print / Save PDF**.

Kekkai-owned titles, descriptions, impact and recommendations follow the selected language, including when reopening older reports. Original scanner messages, identifiers and AI-produced prose are preserved in their original language; upstream messages and solutions remain available in the technical details.

Sanitization removes known secret forms, source/evidence fields and matching content where supported. **Reports still contain project paths, dependency names, policy, endpoints and findings. Review them before sharing.** No detector can guarantee that all sensitive information has been removed. Gitleaks custom rules/allowlists affect coverage.

`.gitignore` allows only the application package, regression tests, launch script, dependencies, license and reviewed project documentation. Other root-level files stay local by default. Additional rules exclude project YAML, reports, caches, environments, keys, private screenshots and design references inside application folders. The published assets include the supplied Kekkai logos. A custom report output directory outside the default requires its own ignore/review rules. Never commit real credentials or force-add ignored artifacts.

The integrated viewer uses an off-the-record WebEngine profile and blocks remote navigation, popups, and unrelated local files. Temporary rendered HTML is removed on close. Scanner source mounts are read-only, but exclusions are scanner instructions, not a filesystem sandbox hiding excluded files from a trusted scanner container. Semgrep auto configuration can use its own registry/metrics behavior. Run tools only against projects and local applications you are authorized to assess.

## Local web targets and ZAP troubleshooting

Set `project.web: true`, enable ZAP, and start the application before scanning. Only HTTP/HTTPS localhost, `127.0.0.1`, and `host.docker.internal` targets are accepted; URL credentials, query strings and fragments are rejected. Kekkai checks both host and container reachability.

On Windows, a server bound only to `localhost`/`::1` can be reachable from the host but unavailable to Docker. For a local Vite development target, the start command can be `npm run dev -- --host 0.0.0.0`, with the Docker hostname explicitly allowed in the local host allowlist as needed. This listens on all interfaces; use an appropriate local firewall/trusted development network. Kekkai does not modify your application's server configuration. Offline/non-web targets are skipped with diagnostics; container/report failures remain technical errors.

## Trivy cache

- **smart:** reuses fresh databases, keeps scan cache in memory by default, and selectively cleans disposable cache.
- **persistent:** retains supported caches.
- **ephemeral:** uses temporary storage discarded after the run.

The default database TTL is 24 hours and cleanup budget is 750 MiB. Usable databases are not automatically deleted to meet this budget. The application cache locations are `%LOCALAPPDATA%\Kekkai\cache\trivy` on Windows and `$XDG_CACHE_HOME/Kekkai/cache/trivy` (or `~/.cache/Kekkai/cache/trivy`) on Linux.

Configure the cache mode, TTL and size budget in **Settings**. Smart mode cleans disposable entries through supported Trivy operations while preserving useful databases.

## Development and verification

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m compileall -q kekkai tests kekkai.py
```

Real Docker and official Forge acceptance checks are opt-in:

```powershell
$env:KEKKAI_DOCKER_TESTS = '1'
$env:KEKKAI_NETWORK_TESTS = '1'
python -m unittest discover -s tests -v
Remove-Item Env:\KEKKAI_DOCKER_TESTS
Remove-Item Env:\KEKKAI_NETWORK_TESTS
```

Tests use harmless markers, mock AI traffic, temporary projects and an isolated vault namespace. They never need real AI keys. Network/Docker checks consume local resources and download upstream data.

Architecture: `core/service.py` exposes the shared scan API; `runner.py` orchestrates; `scanners.py` integrates tools; `configuration.py` validates policies; `ai_providers.py`/`ai_review.py` implement stateless AI boundaries; `yara_library.py` manages validated rules; `core/storage.py` handles preferences/history; `gui/` presents Qt screens; `dashboard/` renders offline HTML; `themes/` shares tokens. Extend these components instead of creating a parallel backend.

Contributions should include focused regression tests, preserve the desktop workflow and machine-readable contracts, and keep secrets/real scan artifacts out of commits. Application preferences are stored under `%LOCALAPPDATA%\Kekkai\desktop` (or `~/.local/share/Kekkai/desktop`); the Windows vault namespace is `Kekkai/AI`.

For an existing installation, rename each project configuration to `.kekkai.yml` and custom rule folders to `.kekkai/yara/`. Re-enter saved API keys in the new Kekkai vault namespace. Personal preferences, downloaded rules, reports, cache and keys are local runtime data and are never part of the source distribution.

## License and credits

Kekkai is licensed under [MIT](LICENSE), copyright © 2026 Thayner Kesley. Third-party engines, Python/Qt dependencies and downloaded rule libraries retain their respective licenses and credits. Kekkai does not redistribute the Forge rule packages in this repository.
