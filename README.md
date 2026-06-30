# AppMapper — Attack Surface Discovery & Application Intelligence

AppMapper is a modular, **discovery / recon / analysis-only** framework for mapping
and *understanding* the attack surface of a web application. It enumerates assets,
fingerprints technologies, analyzes SSL/TLS and frontend code, parses authenticated
traffic, crawls authenticated areas across roles, maps workflows, flags sensitive
functions, compares role access, analyzes APIs, builds an attack-surface graph,
generates a manual-testing checklist, indexes everything into a local searchable
knowledge base, and writes consolidated **JSON / Markdown / HTML** reports.

> ⚠️ **NOT a vulnerability scanner. Performs NO exploitation.**
> It only **discovers → understands → maps → prioritizes**. It never does SQLi/XSS/
> CSRF testing, auth bypass, MFA bypass, password attacks, token cracking, IdP
> attacks, session manipulation, or privilege escalation. See [Scope](#scope).

---

## Contents
- [Quick start](#quick-start)
- [Install](#install)
- [Commands](#commands)
- [`scan` flags](#scan-flags)
- [Authentication modes](#authentication-modes)
- [Config file (`target.yaml`)](#config-file-targetyaml)
- [Feature reference](#feature-reference)
- [Outputs](#outputs)
- [Recipes](#recipes)
- [Scope](#scope)

📖 Full CLI & scan-modes reference: [`docs/scanning.md`](docs/scanning.md) · Examples: [`docs/examples.md`](docs/examples.md) · Archiving & workspace: [`docs/archiving.md`](docs/archiving.md) · Architecture: [`docs/architecture.md`](docs/architecture.md)

---

## Quick start

```bash
cd AppMapper
source .venv/bin/activate          # macOS/Linux  (or prefix commands with ./.venv/bin/python)
# Windows: .\.venv\Scripts\Activate.ps1   (PowerShell)  ·  .venv\Scripts\activate.bat   (cmd)

# 1) Simplest anonymous scan
python main.py scan --url https://demo.testfire.net --domain testfire.net

# 2) Read the reports
open reports/report.html           # macOS  ·  Linux: xdg-open  ·  Windows: start reports\report.html
```

> If you see a `typer`/import error, you're not using the project venv. Activate it first
> (`source .venv/bin/activate`, or `.\.venv\Scripts\Activate.ps1` on Windows), or run via
> the venv interpreter directly (`./.venv/bin/python` / `.venv\Scripts\python.exe`).

---

## Install

Ships a Poetry-format `pyproject.toml`. **With Poetry:**

```bash
poetry install
poetry run appmapper scan --url https://example.com --domain example.com
```

**With a plain virtualenv + pip** — requires Python 3.12+.

<details open><summary><b>macOS / Linux</b></summary>

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install httpx dnspython cryptography pydantic pydantic-settings pyyaml \
            sqlalchemy structlog typer rich playwright
playwright install chromium                            # download the browser binary
pip install pytest pytest-asyncio respx ruff black     # dev/test tools
```
</details>

<details><summary><b>Windows (PowerShell)</b></summary>

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
# If activation is blocked, allow scripts for this session first:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
pip install httpx dnspython cryptography pydantic pydantic-settings pyyaml `
            sqlalchemy structlog typer rich playwright
playwright install chromium                            # download the browser binary
pip install pytest pytest-asyncio respx ruff black     # dev/test tools
```
</details>

<details><summary><b>Windows (cmd.exe)</b></summary>

```bat
py -3.12 -m venv .venv
.\.venv\Scripts\activate.bat
pip install httpx dnspython cryptography pydantic pydantic-settings pyyaml sqlalchemy structlog typer rich playwright
playwright install chromium
pip install pytest pytest-asyncio respx ruff black
```
</details>

> **Playwright** is required for the browser-driven features (`auth capture`, exploration
> capture, `--session`, `--browser-tech`). The `pip install … playwright` step adds the
> Python package; `playwright install chromium` downloads the actual browser — both are
> needed. (`poetry install` installs the package, but you still run `playwright install
> chromium` once afterwards.)

> **Running commands:** this README uses the macOS/Linux venv path `./.venv/bin/python`.
> The Windows equivalent is `.venv\Scripts\python.exe` (PowerShell/cmd). Once the venv is
> activated, plain `python main.py …` works on every platform.

**Optional extras**
- **nmap** service discovery — install the `nmap` binary (module skips gracefully if absent).
  On Windows, install from [nmap.org/download](https://nmap.org/download) and ensure `nmap.exe` is on `PATH`.

Run the test suite / linters:

```bash
pytest -q          # unit tests (network mocked)
ruff check .
black --check .
```

---

## Commands

> Full scan modes, every command, and all supporting arguments: [`docs/scanning.md`](docs/scanning.md).

| Command | Purpose |
|---|---|
| `start` | Start/activate an assessment: scaffold `assessments/<name>/` + `<name>.db` and set it active. |
| `status` | Show the active assessment (database, config, reports dir, captures). |
| `stop` | Deactivate the current assessment **without archiving** (files kept; resume later with `start`). |
| `scan` | Run discovery + Tier-2 intelligence against a target, then write reports. |
| `report` | Regenerate reports from previously stored results. |
| `list-assets` | Print discovered subdomains, directories and API endpoints. |
| `query` | Search the local knowledge base (FTS5) built from discovered data. |
| `summary` | Print the application summary for a stored target. |
| `auth capture` | Open a browser to log in manually (IdP/MFA/SSO), then save the session. |

```bash
python main.py start       testfire                                   # active DB + reports dir
python main.py scan        --url https://demo.testfire.net --domain testfire.net
python main.py status      # which assessment/DB is active?
python main.py report      --domain testfire.net
python main.py list-assets --domain testfire.net
python main.py query       --q "Show all upload endpoints" --domain testfire.net
python main.py summary     --domain testfire.net
python main.py auth capture --role admin --url https://demo.testfire.net   # needs playwright
```

**Active assessment.** After `start <name>`, every command uses `<name>.db` as its
database **and** writes to `reports/<name>/` by default — no need to repeat `--db` /
`--report-dir`. Explicit flags always override; with no active assessment the default DB
is `asdf.db`. See [`docs/examples.md`](docs/examples.md) for the full workflow.

Every command accepts `--db <file>` to choose the SQLite store and `--help` for full options.

---

## `scan` flags

`python main.py scan [OPTIONS]` — run discovery + Tier-2 intelligence, then write
reports. Every option is optional individually, but you must supply a target via
**either** `--url` **or** `--config`. CLI flags override values from `--config`.

### Target

| Flag | Arg | Default | Description |
|---|---|---|---|
| `--url` | TEXT | — | Target URL, e.g. `https://example.com`. Required unless provided via `--config`. |
| `--domain` | TEXT | URL host | Apex/registrable domain. Defaults to the host of `--url`; used as the storage key and to tell internal vs. third-party hosts apart. |
| `--config` | PATH | — | YAML target config (multi-role auth, crawl seeds, per-role captures). See [Config file](#config-file-targetyaml). |

### Network / TLS

| Flag | Arg | Default | Description |
|---|---|---|---|
| `--insecure` | flag | off | **Ignore TLS certificate errors** (self-signed, expired, hostname-mismatch) for the HTTP probes, the authenticated crawl, **and every browser module** (`--browser-tech`, plus `auth capture` / `auth explore`, which take their own `--insecure`). Use for staging/UAT environments served over self-signed or otherwise invalid certificates — it clears Playwright's `net::ERR_CERT_*` errors. Secure-by-default: omit it and TLS is verified. The env-based equivalent is `ASDF_VERIFY_TLS=false`. |

### Authentication (single-role, from the CLI)

For multi-role comparison use `--config` with a `users:` list instead.

| Flag | Arg | Default | Description |
|---|---|---|---|
| `--username` | TEXT | — | Username for a form-login role. |
| `--password` | TEXT | — | Password for a form-login role. |
| `--jwt-token` | TEXT | — | Bearer token; sent as `Authorization: Bearer …` on read-only discovery requests (APIs / microservices / gateways). |
| `--role` | TEXT | `default` | Label the single-role credentials/captures are attributed to (drives role comparison + the Access Matrix). |
| `--session` | PATH | — | Playwright `storage_state` JSON from `auth capture` — reuses a real browser session (cookies + localStorage tokens). |
| `--auth-mode` | TEXT | `auto` | Force a mode: `none \| jwt \| session \| cookie \| har \| login \| auto`. `auto` infers from what's provided. See [Authentication modes](#authentication-modes). |

### Captured traffic / exploration input

| Flag | Arg | Default | Description |
|---|---|---|---|
| `--har` | PATH | — | HAR file to parse (also extracts cookies/JWTs/`Authorization` as masked artifacts, and response **keys**). |
| `--burp` | PATH | — | Burp Suite export (XML or JSON) to parse. |
| `--exploration` | PATH | — | `exploration.json` from `auth explore` — becomes first-class input to workflow/role/API/graph/summary. |

### Authenticated crawl (Tier 2)

| Flag | Arg | Default | Description |
|---|---|---|---|
| `--crawl` / `--no-crawl` | flag | `--crawl` | Toggle the authenticated crawl. `--no-crawl` analyzes only captures/discovery (no crawl traffic). |
| `--crawl-path` | TEXT | — | Extra authenticated entry path(s) to seed the crawl. **Repeatable**: `--crawl-path /dashboard --crawl-path /admin`. |
| `--max-pages` | INT | `60` | Max pages crawled **per role**. |
| `--max-depth` | INT | `2` | Maximum link-follow depth from each seed. |
| `--offline` | flag | off | **Zero outbound traffic.** Analyze captures only: force-skips every discovery module, disables the crawl + browser fingerprint, and gates the live role-access probe. The Access Matrix is still produced (it's derived from captured traffic), as are secrets / hidden endpoints / response intelligence. |

> **Which phases touch the network?** Discovery modules, the authenticated crawl, the browser fingerprint, **and the legacy role-access probe** all send requests. `--no-crawl` only stops the crawl; **`--offline` stops all of them** — use it when you only have capture files and must not reach the target.

### Discovery modules & fingerprinting

| Flag | Arg | Default | Description |
|---|---|---|---|
| `--wordlist` | PATH | built-in | Directory-enumeration wordlist; also widens the per-role reachability probe. |
| `--skip` | TEXT | — | Skip a discovery module. **Repeatable**. Names: `subdomains, directories, techstack, ssl, js_analysis, nmap, api_discovery`. |
| `--subdomain-sources` | TEXT | all available | Passive subdomain providers (comma-separated): `crtsh,alienvault,bufferover,rapiddns,securitytrails,virustotal`. crt.sh/OTX/RapidDNS need no key; SecurityTrails/VirusTotal run only when their key is set (see env vars below). One provider failing never fails the scan. |
| `--dns` | flag | off | Passively resolve DNS records (A/CNAME/TXT/MX/…) for **discovered** hosts only (no brute-force; skipped under `--offline`). |
| `--browser-tech` | flag | off | Boot the app in a real browser and fingerprint the **runtime** stack (React/Tailwind/etc. on SPAs). Needs Playwright. |
| `--browser-wait` | INT | `4000` | Settle time (ms) before the runtime fingerprint snapshot (give SPAs time to boot). |

> **API keys (optional)** for the key-gated subdomain providers, via environment:
> `ASDF_SECURITYTRAILS_API_KEY`, `ASDF_VIRUSTOTAL_API_KEY`. Without them those providers
> are simply skipped; the keyless sources still run.

### AI application summary

| Flag | Arg | Default | Description |
|---|---|---|---|
| `--ai-provider` | TEXT | `template` | Summary engine: `template` (offline, deterministic), `ollama` (local), or `openai_compatible`. |
| `--ai-base-url` | TEXT | — | Base URL for `ollama` / `openai_compatible` (e.g. `http://localhost:11434`). |
| `--ai-model` | TEXT | provider default | Model name (e.g. `llama3`, `gpt-4o-mini`). |

> The LLM only ever receives **structured metadata** (counts, host/service/module names) — never raw HAR, response bodies, or secrets.

### Output, storage & logging

| Flag | Arg | Default | Description |
|---|---|---|---|
| `--report-dir` | TEXT | active assessment, else `default` | Logical report-folder **name** → `reports/<name>/`. Defaults to the active assessment's name (from `start`). |
| `--db` | TEXT | active assessment, else `asdf.db` | SQLite path or full SQLAlchemy URL. Defaults to the active assessment's DB. New columns auto-migrate on open. |
| `--archive` | flag | off | After reporting, sweep all artifacts into a timestamped `archives/<target>_<ts>/` folder and leave the repo clean. |
| `--log-level` | TEXT | `INFO` | `DEBUG \| INFO \| WARNING \| ERROR`. |
| `--log-json` | flag | off | Emit structured JSON logs instead of console formatting. |

> **Scan history is automatic.** Each scan writes the latest `report.{html,md,json}` **and**
> a numbered snapshot `report_<N>.{html,md,json}` in the same folder (last **10** retained),
> so successive scans never overwrite previous results. `report.*` is always the latest.

### Common invocations

```bash
# Anonymous, full discovery + reports
python main.py scan --url https://demo.testfire.net --domain testfire.net

# Multi-role comparison from a config, into the project folder
python main.py scan --config target.yaml --output-dir reports/run1

# API role only; skip slow network modules; JSON logs
python main.py scan --url https://api.example.com --domain api.example.com \
    --jwt-token "eyJ..." --role api --skip subdomains --skip nmap --log-json

# Analyze captures with ZERO traffic to the target (HAR/exploration only)
python main.py scan --config target.yaml --offline --output-dir reports/offline

# SPA runtime fingerprint with a captured session
python main.py scan --session sessions/admin.json --url https://app.example.com \
    --domain app.example.com --browser-tech --browser-wait 6000
```

### Other commands' options (quick reference)

| Command | Required | Optional |
|---|---|---|
| `start` | `<name>` (argument) | — (creates `assessments/<name>/` + `<name>.db`, sets it active) |
| `status` | — | — (prints the active assessment) |
| `stop` | — | — (clears the active pointer; no archiving, files kept) |
| `auth capture` | `--url` | `--role` (def `admin`), `--out`, `--headless`, `--timeout` (def 60000 ms), `--insecure` |
| `auth explore` | `--url` | `--role`, `--out`, `--har`, `--headless`, `--safe-mode`, `--debug-browser`, `--timeout`, `--insecure` |
| `report` | `--domain` | `--db`, `--report-dir` |
| `list-assets` | `--domain` | `--db` |
| `query` | `--q` | `--domain`, `--db` |
| `summary` | `--domain` | `--db`, `--ai-provider`, `--ai-base-url`, `--ai-model` |

---

## Authentication modes

AppMapper **consumes** authenticated sessions rather than automating every identity
provider. Pick a mode per role (or with `--auth-mode`); `auto` infers it from what
each role provides.

| Mode | Configure | Use for |
|---|---|---|
| **none** | (nothing) | Public/unauthenticated discovery. |
| **jwt** | `jwt_token:` / `--jwt-token` | REST APIs, microservices, API gateways (sends `Authorization: Bearer`). |
| **session** | `session_file:` / `--session` | Browser sessions captured with `auth capture` — Keycloak, OAuth2/OIDC, SAML, Azure AD/Entra, Okta, Auth0, social login (cookies + localStorage tokens reused). |
| **har** | `har:` / `burp:` | Reuse captured traffic; extracts cookies, JWTs, session IDs and `Authorization` headers per role. |
| **login** | `username/password` (+ optional `login:`) | Form-login apps; AppMapper performs a single configured login POST and crawls. |

**Capture a browser session (handles IdP/MFA by hand):**

```bash
# Opens a browser; you log in manually; the session is saved to sessions/admin.json
python main.py auth capture --role admin --url https://app.example.com
#   add --headless for headless/CI contexts

python main.py scan --session sessions/admin.json \
    --url https://app.example.com --domain app.example.com --crawl-path /dashboard
```

The scan also **detects the identity provider** (Keycloak / Okta / Auth0 / Azure
AD-Entra / SAML / OIDC) and inventories each role's session and **masked** auth
artifacts. Secrets are never stored or printed in full.

### Exploration Capture Mode (recommended for SPAs)

Log in **and explore the app by hand** while AppMapper records everything —
page navigations, API requests/responses (incl. response **schemas/keys**), form
submissions, uploads, downloads, WebSocket connections, multi-tab SSO popups, and
masked auth artifacts:

```bash
# Browser opens; authenticate + click around.
# Finish by CLOSING THE WINDOW or pressing Enter in the terminal — whichever first.
python main.py auth explore --role qa --url https://app.example.com
#   writes exploration/qa.json  +  exploration/qa.har

# Feed the capture into a scan — it becomes first-class input to workflow mapping,
# role comparison, API analysis, the attack-surface graph and the AI summary
python main.py scan --exploration exploration/qa.json \
    --url https://app.example.com --domain app.example.com --role qa
```

`auth explore` is a **passive observer**: during the session it never navigates,
reloads, opens/closes tabs, changes focus, or injects scripts, so SSO popups, OIDC
redirects and SPAs behave exactly as in a normal browser.

| Flag | Description |
|---|---|
| `--role` | Identity label all captured activity is tagged with (default `admin`). |
| `--out` / `--har` | Output paths (default `exploration/<role>.json` / `.har`). |
| `--safe-mode` | Strictest passive mode: **zero** JavaScript injection (skips even the one end-of-session tech fingerprint). |
| `--debug-browser` | Log every browser event (tab created/closed, navigation, popup, download) with a timestamp. |
| `--headless` | Run without a visible window (CI). |
| `--timeout` | Initial navigation timeout in ms (default 60000). |

This is the best option for **JavaScript SPAs** (Angular/React/Vue), where a plain
crawler can't follow JS-rendered links — your real clicks capture the true API and
page surface. Still discovery-only: AppMapper only *observes* your manual session.

---

## Config file (`target.yaml`)

Everything above can live in a YAML file (`--config target.yaml`). CLI flags
override file values. See [`config/default.yaml`](config/default.yaml) for the
fully-commented template.

```yaml
target_url: https://app.example.com   # `url:` is also accepted
domain: app.example.com

auth_mode: auto                 # none | jwt | session | cookie | har | login | auto

crawl_start:                    # extra authenticated crawl seeds (base is often the login page)
  - /dashboard

users:
  - role: admin
    session_file: sessions/admin.json     # browser session (Keycloak/OIDC/SAML/…)
  - role: api
    jwt_token: eyJhbGci...                 # API / microservice role
  - role: user
    username: jsmith
    password: user123
    login:                                 # optional; auto-detected if omitted
      url: /Auth/Login
      username_field: Username
      password_field: Password
    har: captures/user.har                 # optional per-role capture
```

With **two or more roles**, AppMapper builds a **role attack-surface comparison**:
per-role endpoint counts plus admin-only / user-only / shared endpoint sets.

---

## Feature reference

### Tier 1 — Discovery
| # | Module | Path |
|---|--------|------|
| 1 | Subdomain discovery — **multi-source passive** (crt.sh, AlienVault OTX, BufferOver, RapidDNS, + keyed SecurityTrails/VirusTotal) with fallback + DNS validation | `modules/recon/subdomains.py` |
| 2 | Directory enumeration (configurable wordlist) | `modules/recon/directories.py` |
| 3 | Tech-stack fingerprinting (+ client-side libraries) | `modules/fingerprint/techstack.py` |
| 4 | SSL/TLS analysis | `modules/ssl/ssl_scanner.py` |
| 5 | JavaScript / frontend analysis | `modules/frontend/js_analysis.py` |
| 6 | Nmap service discovery (`-sV`, no scripts) | `modules/network/nmap_scan.py` |
| 7 | HAR parser | `parsers/har_parser.py` |
| 8 | Burp traffic parser (XML + JSON) | `parsers/burp_parser.py` |
| 9 | API discovery (Swagger/OpenAPI/GraphQL) | `modules/api/discovery.py` |

### Tier 2 — Application Intelligence
| # | Capability | Path |
|---|------------|------|
| 1 | Authenticated crawling (per role + anonymous; auto-probes common login paths; **Authenticated Crawl Coverage** lists each role's post-login pages) | `modules/auth/crawler.py` |
| 2 | Workflow mapping (page graph + ASCII tree) | `modules/intelligence/workflow_mapper.py` |
| 3 | Sensitive function discovery (auth/users/files/data/admin) | `modules/intelligence/function_detector.py` |
| 4 | Role-based access analysis (counts + role-only/shared) | `modules/intelligence/access_diff.py` |
| 5 | API intelligence (methods/params/types + authz-sensitive flag; **full host/URL** per endpoint) | `modules/api/analyzer.py` |
| 6 | Attack-surface graph (JSON / GraphML / Draw.io) | `modules/intelligence/graph_builder.py` |
| 7 | Pentest checklist generator | `modules/intelligence/checklist_generator.py` |
| 8 | Local knowledge base (SQLite FTS5) | `modules/knowledge/` |
| 9 | AI application summary (template / Ollama / OpenAI-compatible) | `modules/ai/app_summary.py` |

### Tier 2 — Accuracy & Pentest Guidance
| Capability | Path |
|---|---|
| Unified asset inventory — normalized IDs, static/GIS noise split out | `modules/intelligence/asset_inventory.py`, `path_normalizer.py` |
| **Passive Subdomain Intelligence** — merges multi-source subdomains with runtime hosts; source attribution + confidence + cloud provider | `modules/intelligence/subdomain_intelligence.py` |
| **DNS Intelligence** — host inventory, cloud/auth/gateway detection, dangling-CNAME & email-posture findings (opt-in `--dns` for live records) | `modules/intelligence/dns_intelligence.py` |
| Response intelligence (status/type/size + JSON **keys only**) | `modules/intelligence/response_analyzer.py` |
| Role visibility / redesigned Access Matrix (4 states) | `modules/intelligence/role_visibility.py` |
| API gateway detection + classification | `modules/intelligence/gateway_detector.py` |
| Business-module & dependency inference | `modules/intelligence/{business_modules,dependency_inventory}.py` |
| Authorization test candidates (recommendations only) | `modules/intelligence/authz_candidates.py` |
| Pentest attack plan (4 phases) | `modules/intelligence/pentest_plan.py` |
| Captured-artifact IdP detection (+ realm) | `modules/auth/idp_analyzer.py` |
| Session inventory from captured artifacts | `modules/intelligence/session_inventory.py` |
| Confidence scoring helper | `modules/intelligence/confidence.py` |

### Tier 2 — External Domain Intelligence
Every captured request (exploration / HAR / Burp / authenticated crawl) is run
through a **domain classifier** that surfaces the full set of hosts the app talks
to. Reports gain: **Hostname Inventory**, **Internal APIs** (grouped, with role
visibility), **Third-Party Services**, **Authentication Infrastructure**, an **API
Relationship Graph** (`domain_graph.{json,graphml,drawio}`), **Role-Based API
Visibility**, **High-Value Attack Surface**, and an **Infrastructure Summary**.
Hosts are classified as Primary / Internal API / Microservice / Authentication
Provider / Third Party / Analytics / CDN / Payment / Unknown.
(`modules/intelligence/domain_classifier.py`)

### Tier 2 — Enterprise Authentication
| Capability | Path |
|---|---|
| Auth strategy manager (none/jwt/cookie/session/har/login; pluggable) | `modules/auth/auth_manager.py` |
| Browser session capture & reuse (Playwright `storage_state`) | `modules/auth/{playwright_auth,session_manager}.py` |
| Identity-provider detection (Keycloak/Okta/Auth0/Azure/SAML/OIDC) | `modules/auth/idp_detector.py` |
| JWT / cookie helpers + secret masking | `modules/auth/{jwt_auth,cookie_auth,masking}.py` |

---

## Outputs

Each scan writes to `--output-dir` (default `reports/`):

| File | Contents |
|---|---|
| `report.md` / `report.html` / `report.json` | Consolidated **attack-surface assessment** (see sections below). |
| `graph.json` / `graph.graphml` / `graph.drawio` | Attack-surface graph (open `.drawio` in diagrams.net, `.graphml` in yEd/Gephi). |
| `output.md` / `output.json` | Back-compat Tier-1 report names. |

The report is organized for a pentester, not just discovery:

- **Executive Summary**, **Technology Stack** (incl. runtime SPA fingerprint)
- **Discovered Assets** — directory hits carry a **confidence + SPA-fallback validation** (a `/.env` returning HTML is flagged *low / "SPA fallback suspected"*, not an exposed secret)
- **Identity Provider Analysis** — Keycloak/Azure/Okta/Auth0/SAML + realm
- **Session Inventory** — per-role cookies / local storage / session storage / auth tokens actually captured
- **Access Matrix — Role Visibility** — 4 states (✓ Observed · ? Not Observed · 🚫 Access Denied · ↪ Redirected); role-exclusive vs. shared Applications & APIs
- **API Inventory** — normalized (`/zone/{id}`), with **Static Assets** and **GIS / Map Resources** split into their own sections
- **API Gateway Analysis** — a host fronting ≥2 backend services is classified an API Gateway (with confidence)
- **Business Modules**, **Third-Party Dependencies**, **Infrastructure Architecture**
- **Response Intelligence** — per-endpoint status/content-type/size + JSON **keys only** (never values)
- **Attack Surface Prioritization**
- **Authorization Test Candidates** — `endpoint + reason + tests` (IDOR / privilege escalation / role bypass …) — *recommendations only*
- **Pentest Attack Plan** — 4 phases: Authentication → Authorization → Business Logic → Related Applications
- Findings carry **confidence scores** with evidence throughout.

All results also persist to SQLite (`--db`), so `report`, `list-assets`, `query`,
and `summary` work without re-scanning.

---

## Recipes

```bash
# Anonymous full scan + reports
python main.py scan --url https://demo.testfire.net --domain testfire.net

# Multi-role access comparison from a config (admin vs user vs anonymous)
python main.py scan --config target.yaml --wordlist wordlists/common.txt

# API/JWT role only, skip slow modules
python main.py scan --url https://api.example.com --domain api.example.com \
    --jwt-token "eyJ..." --role api --skip subdomains --skip nmap

# Enterprise SSO: capture a session by hand, then scan with it
python main.py auth capture --role admin --url https://sso-app.example.com
python main.py scan --session sessions/admin.json \
    --url https://sso-app.example.com --domain sso-app.example.com --crawl-path /dashboard

# Reuse captured traffic (no login)
python main.py scan --url https://app.example.com --domain app.example.com \
    --auth-mode har --har captures/admin.har

# Query the knowledge base / print the summary later
python main.py query   --q "admin functions" --domain app.example.com
python main.py summary --domain app.example.com --ai-provider ollama --ai-base-url http://localhost:11434
```

---

## Architecture

A plugin base (`core/base.BaseModule`) + registry + async orchestrator. Discovery
modules run concurrently; Tier-2 intelligence runs as post-processing phases over
the stored data. New modules drop in as `BaseModule` subclasses; new auth strategies
register with `AuthManager`. See [`docs/architecture.md`](docs/architecture.md).

---

## Scope

AppMapper is a **discovery and intelligence** platform. It deliberately does **not**
implement, and must not be extended with: SQL injection / XSS / CSRF testing,
authentication or MFA bypass, password spraying / brute forcing, token cracking,
identity-provider attacks, session manipulation, privilege-escalation testing, or
any exploitation. Credentials and captured sessions are used only to *reach* and
*observe* authenticated surface. Discover → Understand → Map → Prioritize — not exploit.
