# Archiving & Workspace Management

How AppMapper keeps the repository clean between engagements: each assessment's
artifacts are swept into a self-contained, timestamped folder under `archives/`, a
`current_assessment` pointer tracks the latest, and a one-time `migrate-workspace`
step reorganizes a legacy repo into the managed layout.

Like everything else in AppMapper, archiving is **analysis-only**: it moves the
tester's own files and makes no network requests. Archives contain live tokens
(raw HARs, sessions, exploration captures), so the whole `archives/` tree is
git-ignored.

> Implementation: [`core/archive.py`](../core/archive.py) (archive engine) and
> [`core/workspace.py`](../core/workspace.py) (migration). Commands live in
> [`main.py`](../main.py); see also [`scanning.md`](scanning.md).

---

## The managed workspace

```
AppMapper/
├── assessments/            # reusable assessment definitions (tracked in git)
│   ├── default/target.yaml
│   └── rni/target.yaml
├── archives/               # self-contained engagement snapshots (git-ignored)
│   └── <target>_<timestamp>/
│
├── captures/  exploration/  reports/  sessions/   # working dirs (git-ignored)
├── screenshots/  downloads/  logs/                # swept on --archive
│
├── asdf.db                 # application state — TRACKED, never archived/moved
├── current_assessment      # pointer → newest archive (symlink, git-ignored)
├── core/  modules/  parsers/  reporting/  ...      # source code
└── main.py
```

Four clearly separated concerns:

| Concern | Location | Tracked in git? |
|---------|----------|-----------------|
| Source code | `core/`, `modules/`, … | yes |
| Assessment definitions | `assessments/<name>/target.yaml` | yes |
| Assessment artifacts | `archives/<target>_<ts>/` | no (live tokens) |
| Application state | `asdf.db` | yes |

---

## Archive layout

`scan --archive` (or the standalone `archive` command) creates one timestamped
folder and **moves** every engagement artifact into it, leaving the working dirs
empty:

```
archives/
└── demo_20260622_203015/
    ├── config_snapshot/            # COPY of the assessment config (definition stays reusable)
    │   └── target.yaml
    ├── captures/                   # HARs (incl. stray root *.har, auto-collected)
    ├── exploration/                # exploration.json + <role>_browser/ folders
    ├── reports/                    # reports/<name>/{report.html,report.json,report.md, …}
    ├── sessions/                   # Playwright storage_state, <role>_browser/
    ├── screenshots/  downloads/  logs/
    ├── browser_intelligence/  js_intelligence/  runtime_config/
    ├── databases/                  # the assessment DB(s) (never asdf.db)
    │   └── demo.db
    ├── assessment/                 # the MOVED assessments/<name>/ definition (close-out)
    │   └── demo/{target.yaml, captures/*.har}
    └── assessment_metadata.json
```

**Folder name** = `<sanitized-target>_<YYYYMMDD_HHMMSS>`, e.g.
`https://ww-rtwhatif-qa.example.com` → `ww-rtwhatif-qa_20260622_203015`.

What gets swept, and the rules:

| Source | → archive subfolder | Notes |
|--------|---------------------|-------|
| `captures/`, `exploration/`, `reports/`, `sessions/`, `screenshots/`, `downloads/`, `logs/`, `browser_intelligence/`, `js_intelligence/`, `runtime_config/` | same name | moved recursively (so `reports/<name>/…` is preserved) |
| root-level `*.har` (outside `captures/`) | `captures/` | logged: *"HAR file discovered outside captures directory. Archiving automatically."* |
| the scan's DB **+ every stray root-level engagement DB** (`*.db` / `*.sqlite` / `*.sqlite3`) | `databases/` | **never** `asdf.db` (protected) |
| the `--config` file used | `config_snapshot/` | **copied** (canonical record of the config used) |
| the active assessment's `assessments/<name>/` folder | `assessment/<name>/` | **moved** on close-out (`scan --archive` / `archive` with an active assessment) — target.yaml + its `captures/*.har` (live tokens) leave the workspace; only folders directly under `assessments/` are moved |

Never touched: `archives/`, `current_assessment[.txt]`, `.active_assessment.json`,
`.venv`, `.git`, and `asdf.db`. Archiving cannot recurse into prior archives.

> Database scope: `scan --archive` archives the scan's own DB **and sweeps every other
> engagement DB sitting in the repo root** (any `*.db` / `*.sqlite` / `*.sqlite3` except
> the protected `asdf.db`) into `databases/`, so the workspace is left fully clean for the
> next engagement. With the `start`/active-assessment workflow it also clears the active
> assessment pointer afterward.

---

## `assessment_metadata.json`

Written into every archive. Example:

```json
{
  "target": "https://ww-rtwhatif-qa.example.com",
  "target_name": "ww-rtwhatif-qa",
  "assessment_name": "demo",
  "config_file": "assessments/demo/target.yaml",
  "assessment_date": "2026-06-22T20:30:15",
  "archive_timestamp": "2026-06-22T20:30:15",
  "roles": ["admin", "user"],
  "database_files": ["demo.db"],
  "report_count": 4,
  "har_count": 2,
  "exploration_count": 2,
  "session_count": 1,
  "screenshots": 1,
  "downloads": 0,
  "logs": 1,
  "artifact_counts": { "...": "per-source move counts" },
  "generated_by": "AppMapper"
}
```

| Field | Meaning |
|-------|---------|
| `target` / `target_name` | Full target URL / sanitized first label |
| `assessment_name` | Engagement label — the `assessments/<name>/` folder, else the target name |
| `config_file` | Path of the config that was snapshotted (relative to repo root), or `null` |
| `assessment_date` / `archive_timestamp` | ISO timestamp of the archive |
| `roles` | Roles in the engagement |
| `database_files` | Assessment DB filenames archived (empty when only `asdf.db` was in play) |
| `report_count` / `har_count` / `exploration_count` / `session_count` | Artifact tallies |
| `screenshots` / `downloads` / `logs` | Legacy count keys (kept for compatibility) |
| `artifact_counts` | Per-source move counts |
| `generated_by` | Always `"AppMapper"` |

---

## The `current_assessment` pointer

After each archive, AppMapper repoints `current_assessment` at the newest folder:

- **Symlink** `current_assessment → archives/<target>_<ts>/` on systems that support it.
- **Text fallback** `current_assessment.txt` (containing the relative path) on
  filesystems without symlink support (e.g. some Windows setups).

`latest_archive()` resolves it in this order: symlink → `.txt` → newest
`archives/*` folder by mtime. Both pointer forms are git-ignored.

---

## Commands

### `scan --archive`
Run an engagement and archive it in one step: generate reports → sweep artifacts →
write metadata → update the pointer → leave the repo clean. Passes the `--config`
(for the snapshot) and the scan's DB automatically.

```bash
./.venv/bin/python main.py scan --config assessments/rni/target.yaml \
    --offline --report-dir rni --archive
```

### `archive`
Archive the **current** artifacts without scanning.

| Arg | Meaning |
|-----|---------|
| `--url` | Target URL/name for the folder (else inferred from the newest `reports/*/report.json`) |
| `--role` | Role label(s) for metadata (repeatable) |

```bash
./.venv/bin/python main.py archive --url https://app.example.com --role admin --role user
```

### `latest`
Inspect the most recent archive (via the pointer, falling back to newest folder).

| Mode | Output |
|------|--------|
| *(none)* | Target, Path, Created, Roles, Reports, HAR Files |
| `--summary` | Artifact counts (HARs, exploration, reports, screenshots, downloads, logs) |
| `--report` | Path to the main report inside the archive (html → md → json) |

```bash
./.venv/bin/python main.py latest
./.venv/bin/python main.py latest --report   # → prints e.g. archives/<…>/reports/rni/report.html
```

---

## Workspace migration (`migrate-workspace`)

A one-time reorganization of a legacy repo root (assessment files mixed with source)
into the managed layout. It is conservative — it relocates reusable **definitions**
and only **reports** the rest.

```bash
./.venv/bin/python main.py migrate-workspace
```

| Action | Behavior |
|--------|----------|
| Config YAMLs | `targets.yaml` → `assessments/default/target.yaml`; `targets_<name>.yaml` → `assessments/<name>/target.yaml` (moved). Existing destinations are **skipped**, never overwritten. |
| Assessment DBs | `*.db` / `*.sqlite` / `*.sqlite3` except `asdf.db` → **reported only**, left in place (archived on the next `scan --archive`). |
| Stray root HARs | Reported; cleaned up at archive time. |
| `asdf.db`, `assessments/` | Preserved. |

The report it prints (and returns) has: `configs_migrated`, `files_skipped`,
`databases_detected`, `stray_hars`.

> After migration, capture paths in `assessments/<name>/target.yaml` resolve
> **relative to that file's directory**, so each assessment is self-contained and
> runs from any working directory. Drop the engagement's HARs/exploration JSON into
> the assessment's own `captures/` or `exploration/` subfolder.

---

## What is and isn't committed

Git-ignored (contain live tokens or are regenerable):
`archives/`, `captures/`, `exploration/`, `reports/`, `sessions/`, `screenshots/`,
`downloads/`, `logs/`, `*.har`, `current_assessment`, `current_assessment.txt`,
and all `*.db` / `*.sqlite` / `*.sqlite3` **except** `asdf.db`.

Tracked: source code, `assessments/` definitions, and `asdf.db` (application state).
Capture files dropped inside `assessments/<name>/captures/` or `…/exploration/` are
still ignored by the global `*.har` / `exploration/` rules, so customer data placed
there is never committed.
