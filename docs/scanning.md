# Scanning & CLI Reference

How scanning works in AppMapper, the scan modes, and every command with its
arguments. Everything here is **discovery / analysis only** — AppMapper never
exploits, replays, brute-forces, or bypasses authentication.

> Run `python main.py <command> --help` for the authoritative, always-current flag
> list. This document explains *how the pieces fit together*.

---

## Mental model

There is really **one scan command** (`python main.py scan`) that runs in different
*modes* depending on the inputs you give it and whether you allow network traffic.
Around it sit **capture commands** (which produce scan inputs) and **post-scan
commands** (which read back stored results and manage the workspace).

```
auth capture ─┐                          ┌─ report
auth explore ─┤→  captures/sessions  →  scan  →  reports/  ─┤─ list-assets / query / summary
   --har / --burp ┘                       │                  └─ archive → archives/
                                          └─ (--archive)
```

---

## Scan modes

The mode is determined by **what input you provide** and **whether traffic is
allowed**, not by separate commands.

| Mode | Trigger | Behavior |
|------|---------|----------|
| **Unauthenticated active discovery** | `scan --url …` (no credentials) | Runs the discovery modules against the live target as an anonymous user. |
| **Authenticated active discovery** | `scan --url …` + a credential (`--jwt-token` / `--session` / `--username`+`--password` / `--config` users) | Discovery modules + authenticated Tier-2 crawl + live per-role access probe. |
| **Offline capture analysis** | `scan --offline` + a capture | **Zero traffic to the target.** Skips all network modules, the crawl, the browser fingerprint, and the live probe. Pure analysis of captures. |
| **Capture ingestion** (HAR / Burp / Exploration) | `--har` / `--burp` / `--exploration` (online or offline) | Parses pre-recorded traffic into the request inventory, role attribution, and intelligence. |

`--offline` is equivalent to `--skip`-ing every discovery module **and** disabling
the crawl, browser fingerprint, and live role probe.

### Discovery modules (active phase)

Run in this order; disable any with `--skip <name>` (repeatable):

| Module | Purpose |
|--------|---------|
| `subdomains` | Subdomain enumeration |
| `directories` | Directory / path enumeration (uses `--wordlist`) |
| `techstack` | Technology fingerprinting (headers / HTML) |
| `ssl` | TLS / SSL certificate + configuration inspection |
| `js_analysis` | JavaScript analysis (endpoints, secrets, routes) |
| `nmap` | Network port / service scan |
| `api_discovery` | API endpoint discovery |

### Tier-2 phases (after discovery)

- **Authenticated crawl** — `--crawl` (default on; `--no-crawl` disables). Spiders
  authenticated pages per role, seeded by `--crawl-path` and any `crawl_start:` in
  the config.
- **Role access comparison** — compares what each role can reach (captures + live probe).
- **Intelligence** — browser / JS / runtime-config intelligence, service registry,
  secrets, hidden APIs, **redirect intelligence** and **JWT & authorization intelligence**
  (see below) → rendered into the report.

### Authentication strategies (`--auth-mode`, or per-user in YAML)

`none` (anonymous) · `jwt` · `session` (Playwright `storage_state`) · `cookie` ·
`har` · `auto` (default — inferred from whatever credential you supplied).

### Redirect Intelligence

Reconstructs HTTP **301/302/303/307/308** chains from captured traffic and correlates
each with authentication/SSO, related internal applications, and external services. It
runs automatically as part of the Intelligence phase — no flag required — and works in
`--offline` mode (it reads captures, never follows or probes a redirect).

- **Capture** — the redirect target (`Location` / HAR `redirectURL` / httpx
  `resp.history`) is parsed from HAR, Burp, and the live crawl. Secret-bearing query
  values are redacted before anything is stored.
- **Correlation** — each chain's terminal is classified via the domain classifier:
  Keycloak / OIDC / SAML auth (e.g. `…/realms/…`), same-org **Related Application**
  (different host, same registrable domain), or external **Third-Party Service**.
- **Report output** (both a front-matter **Authentication Redirect Flow** summary and a
  full **Redirect Intelligence** section):
  - **Redirect Inventory** — source → target, status, purpose, confidence, source.
  - **Redirect Flow Diagram** (text) — e.g. `app → auth/auth → auth/realms → Login Page`.
  - **Authentication Redirect Flow** — the SSO bounce with purpose + confidence.
  - **External Redirect Summary** — per off-domain host: count, classification, paths.
  - **Flags** — **Open Redirect Candidates** (a redirect-bearing query param such as
    `?next=`/`?redirect_uri=` whose destination crosses domains — *flagged passively,
    never tested*), **Cross-Domain Redirects**, **Third-Party Redirects**.

```
Authentication Redirect Flow
  https://ww-rtwhatif-qa.example.com
  → https://auth-eu-test.example.com/auth
  → https://auth-eu-test.example.com/realms/demo_realm
  → Login Page
  Purpose: Keycloak Authentication · Confidence: High
```

### JWT & Authorization Intelligence

Decodes the **payload** of a captured access token (no signature verification — read-only
inspection) and turns it, together with the captured auth artifacts, into an authorization
picture rendered as a **suite of sections immediately below the Executive Intelligence
Summary** — so a tester understands the auth/authz architecture in the first pages without
manually decoding a JWT. Runs automatically in the Intelligence phase and works `--offline`.

**Report sections (in order):**

1. **Executive Intelligence Summary** — user · authentication + model · realm/client ·
   applications/roles/admin/security-sensitive · token lifetime · highest-risk application.
2. **Authentication Intelligence** — Identity Provider, realm, client (`azp`), authentication
   type, **authentication model** (Cookie / JWT / **Hybrid**), and a token-storage summary.
3. **JWT Intelligence Summary** — header analysis (algorithm, **signature model**, **key
   rotation** from `kid`), token type, lifetime (`exp − iat`), trusted apps, scopes.
4. **User Intelligence** — username, display name, email, locale, email-verified (PII masked
   by default — see below).
5. **Application Access Summary** — per `resource_access` application: total / admin / user
   roles.
6. **Authorization Intelligence** — role totals (admin / read / write / security-sensitive),
   **Highest-Value Applications** ranking, and **Authorization Testing Priorities** (per-app
   admin roles + suggested test types — recommendations only, never executed).
7. **Authentication Risk Analysis** — JWT-in-localStorage (XSS), long-lived token, hybrid
   auth, multi-application trust, administrative privileges; **Refresh Token Intelligence**
   (observed, or *inferred* via `offline_access`); auth/authz discussion points.

**Token sourcing.** Bearer JWTs are decoded from captured **HAR / Burp** request headers and,
for exploration captures, **re-decoded fresh from the sibling `capture.har`** on every import
(so the summary always reflects current analysis — no re-capture needed when the tool is
updated). JWTs embedded in JavaScript / runtime config are also decoded (and flagged as
*embedded*, distinct from the session token). Only **masked summaries** are persisted — the
raw token is never stored.

**PII policy (`--show-pii`).** By default the display name and email are masked
(`Test H****`, `d*****.h*****@example.com`); the **username and role names are always shown**
(they are the authorization model under assessment); `sub` is opaque. Pass **`--show-pii`**
(on `scan` or `report`, internal environments only) to unmask name/email. A report generated
*without* `--show-pii` always re-masks at render time, so PII never leaks even if a prior
`--show-pii` scan persisted it unmasked.

> Note: a pure `--jwt-token` live scan with no captured traffic is not summarized (the token
> never reaches the captured data).

```
Executive Intelligence Summary
  User: testuser      Authentication: Keycloak OIDC Bearer Token (model: Hybrid)
  Realm: demo_realm   Client: demo-floods
  Applications: 6     Roles: 93     Admin: 28     Security-Sensitive: 39
  Token Lifetime: 3 Hours     Trusted Apps: 5     Highest-Risk App: demo-floods

Application Access Summary
  | Application                 | Total | Admin | User |
  | demo-floods             |  36   |   9   |  27  |
  | demo-mam                |  22   |   7   |  15  |
  | demo-device-management  |  18   |   7   |  11  |
```

---

## `scan` — argument reference

**Target / identity**

| Arg | Meaning |
|-----|---------|
| `--url` | Target URL (or set in `--config`) |
| `--domain` | Apex domain (defaults to the URL host) |
| `--config` | YAML target file (supports multiple `users:`). Capture paths in the file resolve **relative to the file's directory**. |
| `--role` | Role label for single-user CLI creds |
| `--username` / `--password` | Form-login credentials |
| `--jwt-token` | Bearer token for authenticated discovery |
| `--session` | Playwright `storage_state` JSON to reuse |
| `--auth-mode` | `none \| jwt \| session \| har \| auto` |

**Capture inputs**

| Arg | Meaning |
|-----|---------|
| `--har` | HAR capture file to parse |
| `--burp` | Burp XML / JSON export to parse |
| `--exploration` | `auth explore` output: `exploration.json`, a standalone `browser_intelligence.json`, or a `<role>_browser/` folder |

**Discovery control**

| Arg | Meaning |
|-----|---------|
| `--wordlist` | Directory-enum wordlist |
| `--skip` | Module(s) to skip (repeatable): `subdomains directories techstack ssl js_analysis nmap api_discovery` |
| `--offline` | Analyze captures only; send no traffic to the target |
| `--crawl / --no-crawl` | Authenticated Tier-2 crawl (default on) |
| `--crawl-path` | Extra authenticated entry path(s) to seed the crawl (repeatable) |
| `--max-pages` | Crawl page cap per role (default 60) |
| `--max-depth` | Crawl link depth (default 2) |
| `--browser-tech` | Browser-runtime fingerprint for SPAs (needs Playwright) |
| `--browser-wait` | Settle time before fingerprinting, ms (default 4000) |

**AI summary**

| Arg | Meaning |
|-----|---------|
| `--ai-provider` | `template \| ollama \| openai_compatible` (default `template`) |
| `--ai-base-url` / `--ai-model` | Provider configuration |

**Output / storage / archive**

| Arg | Meaning |
|-----|---------|
| `--report-dir` | Logical report folder **NAME** → `reports/<name>` (default `reports/default`). Letters/digits/`-`/`_` only — not a filesystem path. |
| `--db` | SQLite path or SQLAlchemy URL (default `asdf.db`) |
| `--archive` | After reporting, sweep all artifacts into `archives/<target>_<timestamp>/` and leave the repo clean |
| `--show-pii` | Unmask user name/email in JWT/User Intelligence (internal environments only; default masked) |
| `--log-level` / `--log-json` | Logging |
| `--output-dir` | *(hidden, deprecated alias for `--report-dir`)* |

---

## Capture commands (produce scan inputs)

### `auth capture`
Log in by hand (IdP / MFA / SSO) and save the browser session. AppMapper does **not**
automate the login — you authenticate manually; it persists the resulting Playwright
`storage_state`.

| Arg | Meaning |
|-----|---------|
| `--role` | Role label for the captured session |
| `--url` *(required)* | Application URL to open |
| `--out` | Output path (default `sessions/<role>.json`) |
| `--headless` | Run without a visible window |
| `--timeout` | Initial navigation timeout, ms (default 60000) |

→ feed to `scan --session sessions/<role>.json`.

### `auth explore`
**Exploration Capture Mode** — you browse and explore manually while AppMapper
**passively** records navigations, API requests/responses, form submissions, uploads,
downloads, WebSocket connections, and masked auth artifacts. It never navigates,
reloads, opens/closes tabs, changes focus, or injects scripts while you work, so SSO
popups, OIDC redirects, and SPAs behave normally. Finish by **closing the browser
window** or pressing Enter in the terminal.

| Arg | Meaning |
|-----|---------|
| `--role` | Role to associate captured activity with |
| `--url` *(required)* | Application URL to open |
| `--out` | `exploration.json` (default `exploration/<role>.json`) |
| `--har` | `captured.har` (default `exploration/<role>.har`) |
| `--headless` | Run without a visible window |
| `--safe-mode` | Strict passive capture: never inject JavaScript (no in-page fingerprint) |
| `--debug-browser` | Log every browser event (tab/navigation/popup/download) |
| `--timeout` | Initial navigation timeout, ms (default 60000) |

→ feed to `scan --exploration exploration/<role>.json`.

---

## Post-scan & workspace commands

| Command | Key args | Purpose |
|---------|----------|---------|
| `report` | `--domain` *(req)*, `--db`, `--report-dir`, `--show-pii` | Regenerate JSON / Markdown / HTML reports from stored DB results |
| `list-assets` | `--domain` *(req)*, `--db` | Print subdomains, directories, API endpoints, hosts, backend services, related apps |
| `query` | `--q` *(req)*, `--domain`, `--db` | Full-text search (SQLite FTS5) over discovered data |
| `summary` | `--domain` *(req)*, `--db`, `--ai-*` | Print the AI application summary |
| `archive` | `--url`, `--role` *(repeatable)* | Archive the current artifacts **without** scanning |
| `latest` | `--summary`, `--report` | Show / locate the most recent archived assessment |
| `migrate-workspace` | *(none)* | Reorganize a legacy repo root into the managed `assessments/` layout |

`scan --archive` (or the standalone `archive` command) sweeps every engagement
artifact — reports, captures, exploration, sessions, screenshots, downloads, logs,
the assessment database (never `asdf.db`), stray root HARs, and a **copy** of the
config — into a self-contained `archives/<target>_<timestamp>/` folder, then updates
the `current_assessment` pointer and leaves the repo clean. Inspect the result with
`latest` / `latest --summary` / `latest --report`. See
[`archiving.md`](archiving.md) for the full archive layout, metadata schema, pointer
behavior, and workspace migration.

---

## Recipes

```bash
# Offline analysis of a browser exploration, into reports/rni, then archive
./.venv/bin/python main.py scan --config assessments/rni/target.yaml \
    --offline --report-dir rni --archive

# Live authenticated scan with a JWT, skip nmap, deeper crawl
./.venv/bin/python main.py scan --url https://app.example.com \
    --jwt-token "$TOKEN" --role admin --skip nmap --max-depth 3

# Anonymous active discovery with a wordlist
./.venv/bin/python main.py scan --url https://app.example.com \
    --wordlist wordlists/common.txt

# Capture a session by hand, then scan with it
./.venv/bin/python main.py auth capture --role admin --url https://app.example.com
./.venv/bin/python main.py scan --session sessions/admin.json --url https://app.example.com

# Multi-role engagement from a YAML definition
./.venv/bin/python main.py scan --config assessments/default/target.yaml --offline
```
