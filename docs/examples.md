# Scan Examples

A practical, copy-paste set of scan workflows, worked against the public test target
**`demo.testfire.net`** (Altoro Mutual — an intentionally vulnerable demo bank; public
credentials `admin` / `admin` and `jsmith` / `demo1234`).

Everything here is **discovery / analysis only** — AppMapper never exploits, replays,
brute-forces, or bypasses authentication. See [`scanning.md`](scanning.md) for the full flag
reference and the scan mental model.

> Commands are written with the project virtualenv (`./.venv/bin/python`). If you have the
> venv activated, plain `python main.py …` works too. On Windows use
> `.venv\Scripts\python.exe main.py …`.

---

## 0. Start an assessment (recommended first step)

```bash
python main.py start testfire
```

Scaffolds `assessments/testfire/` (with a `target.yaml` and `captures/`), creates
`testfire.db`, and sets it as the **active** assessment. Every later command then uses
`testfire.db` as its database **and** writes to `reports/testfire/` automatically — no
need to repeat `--db` or `--report-dir` — until you `start` a different assessment or
pass the flags explicitly:

```bash
python main.py scan --url https://demo.testfire.net --domain testfire.net --insecure
python main.py report --domain testfire.net          # same DB + reports/testfire/, no flags
python main.py status                                # show the active assessment
python main.py scan ... --db other.db --report-dir x # explicit flags always override
```

This keeps each engagement in its own database (instead of piling into the shared
`asdf.db` scratch DB), and pairs naturally with `--archive` to snapshot the whole
engagement. The active pointer lives in `.active_assessment.json` (git-ignored); switch
engagements by running `start <other>`.

**Scan history is automatic** (last 10 retained). Every scan writes the latest
`report.{html,md,json}` *and* keeps a numbered snapshot `report_<N>.{html,md,json}`, so
successive scans in the same assessment never overwrite previous results. Only the 10
most-recent snapshots are kept (older ones are pruned automatically):

```
reports/testfire/
├── report.html        report.md        report.json      ← always the latest
├── report_1.html      report_1.md      report_1.json    ← scan #1
└── report_2.html      report_2.md      report_2.json    ← scan #2
```

## 1. URL alone (anonymous discovery)

```bash
./.venv/bin/python main.py scan \
  --url https://demo.testfire.net --domain testfire.net \
  --report-dir testfire
```

Tier-1 discovery + passive intelligence with no credentials. `--report-dir testfire` writes
to `reports/testfire/`.

## 2. With username & password (form login)

```bash
./.venv/bin/python main.py scan \
  --url https://demo.testfire.net --domain testfire.net \
  --username admin --password admin --role admin \
  --report-dir testfire
```

`--auth-mode` defaults to `auto`, which infers form login from the supplied credentials.
`--role` labels the identity so it appears in the access matrix.

## 3. With a single `.har` file (one role)

```bash
./.venv/bin/python main.py scan \
  --url https://demo.testfire.net --domain testfire.net \
  --har captures/testfire.har --role user \
  --report-dir testfire
```

The HAR is parsed for endpoints, masked tokens/secrets, and response keys. Auth mode
auto-infers `har`.

## 4. Two `.har` files = two roles (admin + common user)

The single-role CLI takes one `--har`, so multi-role engagements use a **config file**.
Create `assessments/testfire/target.yaml`:

```yaml
url: https://demo.testfire.net
domain: testfire.net
users:
  - role: admin
    har: captures/admin.har      # paths are relative to THIS file's folder
    auth_mode: har
  - role: user
    har: captures/user.har
    auth_mode: har
```

Put the HARs in `assessments/testfire/captures/`, then:

```bash
./.venv/bin/python main.py scan \
  --config assessments/testfire/target.yaml \
  --report-dir testfire
```

This produces the **role comparison / access matrix** — what `admin` can see or reach that
`user` cannot.

## 5. Capture authentication using a browser

Two steps: capture the session by logging in manually, then scan with it.

```bash
# (a) opens a real browser; log in by hand (IdP / MFA / SSO are fine), session is saved
./.venv/bin/python main.py auth capture --url https://demo.testfire.net --role admin
#   → writes sessions/admin.json

# (b) scan, reusing that authenticated session
./.venv/bin/python main.py scan \
  --url https://demo.testfire.net --domain testfire.net \
  --session sessions/admin.json --role admin \
  --report-dir testfire
```

## 6. Capture authentication **and** explore all the links

Exploration mode is a passive observer: it records every navigation, API request/response,
form submission, upload/download, WebSocket and (masked) auth artifact while *you* drive the
browser — it never clicks or navigates for you.

```bash
# (a) browser opens; log in and click around; finish by CLOSING the window (or pressing Enter)
./.venv/bin/python main.py auth explore --url https://demo.testfire.net --role admin
#   → writes exploration/admin.json (+ exploration/admin.har)

# (b) feed the exploration into a scan
./.venv/bin/python main.py scan \
  --url https://demo.testfire.net --domain testfire.net \
  --exploration exploration/admin.json \
  --report-dir testfire
```

---

## Handy add-ons

Append any of these to a `scan`:

| Flag | Effect |
|------|--------|
| `--insecure` | Ignore TLS cert errors (self-signed / expired certs on staging/UAT) |
| `--dns` | Passively resolve DNS records (A/CNAME/TXT/MX/…) for **discovered** hosts only |
| `--subdomain-sources crtsh,alienvault,rapiddns` | Choose passive subdomain providers (default: all available) |
| `--browser-tech` | Boot the app in a real browser and fingerprint the runtime stack (needs Playwright) |
| `--no-crawl` | Analyze captures/discovery only — no authenticated crawl traffic |
| `--offline` | **Zero** traffic to the target — analyze captures only |
| `--archive` | Sweep all artifacts into a timestamped `archives/<target>_<ts>/` folder when done |

**Prerequisite for the browser workflows (5 & 6):** Playwright must be installed —
`pip install playwright && playwright install chromium`.

Multi-role engagements (example 4) can also mix modes per user — `auth_mode` accepts
`har`, `exploration`, or `storage_state`. See [`scanning.md`](scanning.md#authentication-modes)
and [`archiving.md`](archiving.md) for the managed-workspace layout.

---

## Troubleshooting: the scan caught no post-login pages

A form-login scan (example 2) that returns only public pages is almost always one of these.
The report now surfaces it directly in an **Authenticated Crawl Coverage** section — a
form-login role with `0` pages is flagged with a ⚠️ and the likely causes.

1. **Expired / self-signed TLS certificate.** The authenticated crawl verifies TLS by
   default, so a bad certificate makes every request (including the login POST) fail with
   `CERTIFICATE_VERIFY_FAILED`. Re-run with **`--insecure`**. (Many public test targets —
   including `demo.testfire.net` — have expired certs.)

2. **The login form is on a separate page.** AppMapper auto-detects the form on the base URL
   and then probes common login paths (`/login`, `/login.jsp`, `/signin`, `/account/login`,
   …). If your app's form lives somewhere else, or needs specific field names, set them
   explicitly in the config:

   ```yaml
   url: https://demo.testfire.net
   domain: testfire.net
   users:
     - role: user2
       username: sspeed
       password: Demo1234
       auth_mode: login
       login:
         url: /doLogin              # the form ACTION (POST target), not the form's page
         username_field: uid
         password_field: passw
         extra_fields: { btnSubmit: "Login" }
         success_contains: "Sign Off"   # text only present once authenticated
   ```
   ```bash
   python main.py scan --config assessments/<name>/target.yaml --insecure --report-dir <name>
   ```

3. **Invalid credentials**, or **the crawl was disabled** (`--no-crawl` / `--offline`).

> Tip: the most robust option for tricky logins (SSO, MFA, multi-step, heavy JS) is the
> browser flow (examples 5 & 6) — you log in by hand and AppMapper reuses the real session;
> still add `--insecure` to the scan when the cert is bad.
