# Architecture

## Overview

AppMapper is a **pipeline of independent discovery modules** plus a set of
**post-processing intelligence phases**, coordinated by an orchestrator. Results
are normalized into Pydantic DTOs, persisted via SQLAlchemy (SQLite), and rendered
into JSON / Markdown / HTML reports plus attack-surface graph exports.

```
                 ┌──────────┐
  CLI ─────────▶ │  config  │  load_target() → TargetInput (+ users[], auth_mode)
 (main.py)       └────┬─────┘  Settings (env)
                      ▼
               ┌─────────────┐   build_modules(skip=…)
               │  registry   │ ───────────────────────────┐
               └─────────────┘                            ▼
                      ▼                            ┌──────────────────┐
               ┌─────────────┐   ScanContext       │  BaseModule(s)   │
               │ orchestrator│ ──────────────────▶ │ run() -> Result  │  (async, concurrent)
               │             │ ◀── ModuleResult ── └──────────────────┘
               │             │
               │  PHASES:    │   1. discovery modules (Tier 1, concurrent)
               │             │   2. capture ingestion (per-role HAR/Burp)
               │             │   3. role access comparison
               │             │   4. auth intel: IdP detect + sessions + artifacts
               │             │   5. authenticated crawl (per role + anonymous)
               │             │   6. intelligence: functions, APIs, workflow,
               │             │      checklist, knowledge index
               └──────┬──────┘
                      │ persist (replace-by-target)
                      ▼
               ┌─────────────┐      ┌──────────────────────┐
               │  storage    │ ───▶ │ SQLite ORM + FTS5     │
               └──────┬──────┘      └──────────────────────┘
                      ▼
               ┌─────────────┐  reports/report.{md,html,json}
               │  reporting  │ ─▶ reports/graph.{json,graphml,drawio}
               └─────────────┘  (+ back-compat output.{md,json})
```

## Layers

| Layer | Package | Responsibility |
|-------|---------|----------------|
| CLI | `main.py` | Typer commands: `scan`, `report`, `list-assets`, `query`, `summary`, `auth capture` |
| Config | `config/` | `Settings` (env) + `load_target()` (YAML/CLI → `TargetInput`) |
| Core | `core/` | logging, HTTP client, `BaseModule`, `registry`, `Orchestrator` |
| Models | `models/` | Pydantic DTOs (`schemas`) + SQLAlchemy ORM (`db_models`) |
| Storage | `storage/` | `Database` repository (`save_*`, `fetch_all`, FTS5 index, schema migration) |
| Discovery modules | `modules/{recon,fingerprint,ssl,frontend,network,api}` | Tier-1 `BaseModule` plugins |
| Auth | `modules/auth/` | crawler, `AuthManager`, session/jwt/cookie helpers, IdP detection, Playwright capture, masking |
| Intelligence | `modules/intelligence/` | workflow, function detection, access diff, graph builder, checklist |
| Knowledge / AI | `modules/knowledge/`, `modules/ai/` | FTS knowledge base; app-summary providers |
| Parsers | `parsers/` | HAR + Burp capture parsing |
| Reporting | `reporting/` | JSON + Markdown + HTML renderers; graph exports |

## The plugin contract

Every discovery module subclasses `core.base.BaseModule`:

```python
class BaseModule(ABC):
    name: str            # stable id, used in --skip and persistence routing
    category: str        # recon | fingerprint | ssl | frontend | network | api | auth
    async def run(self, ctx: ScanContext) -> ModuleResult: ...
```

- `ScanContext` carries the target, runtime config (timeout, concurrency, TLS
  verification, wordlist), the active identity (`active_user`), and an `options`
  bag (crawl bounds, seed paths, capture files).
- `ModuleResult` is a uniform envelope (`module`, `ok`, `error`, `data`, `items`).
- `safe_run()` wraps `run()` so a failing module degrades to `ok=False` instead of
  aborting the scan; the orchestrator isolates every phase the same way.

Intelligence phases (functions, access diff, API analyzer, workflow, checklist,
knowledge, AI summary) are **pure functions over stored data**, not `BaseModule`s —
the orchestrator calls them after discovery and persists their output.

## Orchestration phases

`Orchestrator.run()` executes, each phase isolated:

1. **Discovery** — selected `BaseModule`s run concurrently (`asyncio.gather`);
   results persisted via `_persist`.
2. **Capture ingestion** — per-role and global HAR/Burp parsed, tagged by role,
   stored in `har_requests` / `burp_requests`.
3. **Role access comparison** (`modules/access/comparison.py`) — when ≥2 roles,
   probe each role's GET-reachable endpoints and store `role_endpoint_access`.
4. **Auth intelligence** (`_auth_intel`) — detect the identity provider, resolve
   each role's session, and inventory masked artifacts (`idp_info`, `sessions`,
   `auth_artifacts`).
5. **Authenticated crawl** (`modules/auth/crawler.py`) — per role + anonymous.
6. **Intelligence** — function detection, API analysis, workflow mapping,
   checklist generation, and the FTS knowledge index, derived from stored data.

## Identities, authentication & sessions

The reusable identity model is `models.schemas.UserCredential`
(`role`, `username`, `password`, `jwt_token`, `cookie`, `session_file`,
`auth_mode`, `login`, `har`, `burp`). A `TargetInput` holds `users[]`,
a target-level `auth_mode`, and `crawl_start` seed paths.

**`AuthManager`** (`modules/auth/auth_manager.py`) resolves a role into a
`ResolvedSession` (cookies + headers + masked artifacts) by dispatching on a
**strategy** via a registry:

| Strategy | Resolver | Source |
|---|---|---|
| `none` | empty session | anonymous |
| `jwt` | `jwt_auth.bearer_header` | `Authorization: Bearer` |
| `cookie` | `cookie_auth.parse_cookie_string` | raw cookie string |
| `session` | `session_manager.resolve_session` | Playwright `storage_state` (cookies + localStorage bearer) |
| `har` | HAR/Burp extraction | captured cookies + `Authorization` |
| `login` | crawler-driven form login | configured username/password |

The registry is the extension point: **future strategies** (device-code,
client-credentials, service-account, API-key, certificate) register a new resolver
with `AuthManager.register(...)` and the `ResolvedSession` contract — no caller or
architecture changes. The crawler and access-comparison both consume
`ResolvedSession`; `ScanContext.for_user(user)` scopes a context to one identity.

- **Session capture** (`modules/auth/playwright_auth.py`) — Playwright is an
  *optional, lazily-imported* dependency. `auth capture` opens a real browser so
  the user completes any IdP/MFA/SSO flow by hand, then saves `storage_state`.
  Missing Playwright degrades to a clear install hint; the rest of AppMapper is
  unaffected.
- **IdP detection** (`modules/auth/idp_detector.py`) — observes the login redirect
  chain, response headers, login-page signatures, OAuth/SAML params, and the OIDC
  discovery document to classify Keycloak / Okta / Auth0 / Azure AD-Entra / SAML /
  OIDC. Read-only GETs to public endpoints only.
- **Masking** (`modules/auth/masking.py`) — every token/cookie/storage value is
  masked (`first4…last4 (N chars)`) before it is stored or reported. **Raw secrets
  are never persisted.**

## Concurrency model

HTTP-bound modules (subdomains, directories, techstack, js_analysis, api_discovery)
use a shared `httpx.AsyncClient` and a bounded `asyncio.Semaphore`. Blocking work
(SSL sockets, the nmap subprocess) is pushed to threads via `asyncio.to_thread`.
Discovery modules run concurrently with `asyncio.gather`; the authenticated crawl
runs per role. Persistence is serialized (SQLite single-writer).

## Data model

A parent `targets` row owns child tables; saves are **replace-by-target** so
re-running a scan refreshes rather than duplicates.

| Group | Tables |
|---|---|
| Tier 1 | `subdomains`, `directories`, `technologies`, `ssl_findings`, `js_findings`, `network_services`, `api_endpoints`, `har_requests`, `burp_requests` |
| Roles / access | `users` (metadata only), `role_endpoint_access` |
| Tier 2 intelligence | `crawl_endpoints`, `forms`, `workflow_edges`, `sensitive_functions`, `api_intel`, `checklist_items` |
| Enterprise auth | `idp_info`, `auth_artifacts` (**masked values only**), `sessions` |
| Knowledge | `knowledge_fts` (SQLite **FTS5** virtual table) |

`har_requests` / `burp_requests` carry a `role` column. **No credentials or raw
secrets are stored** — `users` holds only `has_password`/`has_token` flags, and
`auth_artifacts` holds masked values. `Database.init_db()` runs `create_all` plus a
lightweight forward-migration (`_ensure_columns`) and creates the FTS index, so
older databases upgrade automatically.

## Reporting

`reporting.build_report(data, **summary_opts)` assembles a single structure
consumed by all renderers. `write_reports()` emits `report.{md,html,json}` and
`graph.{json,graphml,drawio}` (plus back-compat `output.{md,json}`). The HTML
renderer is a dependency-free Markdown subset converter. Report sections:
executive summary, technology inventory, authentication overview, session
inventory, masked auth artifacts, role comparison matrix, workflow map, sensitive
functions, API inventory & intelligence, pentest checklist, application summary.

The **app summary** (`modules/ai/app_summary.py`) uses a provider abstraction —
`TemplateProvider` (deterministic, offline, default), `OllamaProvider`,
`OpenAICompatibleProvider` — and falls back to the template if an LLM call fails.

## Extending

**Add a discovery module:**
1. Create `modules/<category>/<name>.py` with a `BaseModule` subclass.
2. Add a result DTO to `models/schemas.py`.
3. Register the class in `core/registry.py`.
4. Add a `save_*` helper + table (if new persistence) and a branch in
   `Orchestrator._persist`.
5. Add a renderer section in `reporting/` if it should appear in reports.

**Add an intelligence phase:** write a pure function over the `fetch_all(target_id)`
dict, persist via a `save_*` helper, and call it from `Orchestrator._run_tier2`.

**Add an auth strategy:** implement a resolver returning a `ResolvedSession` and
register it with `AuthManager.register("<strategy>", resolver)`; set the role's
`auth_mode` to select it.

## Safety / scope

A **discovery-only** platform; guardrails enforced in code:

- nmap runs `-sV` only; script/exploit flags (`--script`, `-sC`, `-A`) are rejected.
- Directory / API discovery and crawling issue read-only **GET** requests; forms
  are discovered but never submitted. The only state-touching request is a single
  configured form-login POST (the `login` strategy).
- The crawler skips session-destroying links (logout) and is bounded by
  `max_pages` / `max_depth`, same-host only.
- Credentials, tokens and captured sessions are used only to *reach* and *observe*
  authenticated surface. Secrets are masked everywhere.

**Out of scope (must not be added):** SQLi / XSS / CSRF testing, authentication or
MFA bypass, password spraying / brute forcing, token cracking, identity-provider
attacks, session manipulation, privilege-escalation testing, any exploitation.
Discover → Understand → Map → Prioritize — not exploit.
