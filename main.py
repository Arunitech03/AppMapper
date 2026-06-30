"""ASDF Framework CLI.

Commands:
    scan         Run discovery modules (+ optional capture parsing), then report.
    report       Regenerate JSON + Markdown reports from stored results.
    list-assets  Print discovered assets for a target.

Discovery / analysis only — no exploitation. See README for constraints.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from config.settings import Settings, load_target
from core.archive import resolve_report_dir
from core.logging import configure_logging, get_logger
from core.orchestrator import Orchestrator
from core.registry import all_module_names, build_modules
from models.schemas import ScanContext
from modules.knowledge.query import to_fts_query
from reporting import write_reports
from storage.database import Database

app = typer.Typer(
    help="Attack Surface Discovery & Pentest Automation Framework (Tier 1, discovery-only).",
    no_args_is_help=True,
    add_completion=False,
)
auth_app = typer.Typer(help="Authentication helpers (session capture).", no_args_is_help=True)
app.add_typer(auth_app, name="auth")
console = Console()


@auth_app.command()
def capture(
    role: str = typer.Option("admin", "--role", help="Role label for the captured session"),
    url: str = typer.Option(..., "--url", help="Application URL to open in the browser"),
    out: str | None = typer.Option(
        None, "--out", help="Output path (default sessions/<role>.json)"
    ),
    headless: bool = typer.Option(
        False, "--headless", help="Run without a visible window (headless/CI contexts)"
    ),
    timeout: int = typer.Option(60000, "--timeout", help="Initial navigation timeout (ms)"),
    insecure: bool = typer.Option(
        False,
        "--insecure",
        help="Ignore TLS certificate errors (self-signed/expired/invalid certs on staging/UAT)",
    ),
) -> None:
    """Open a browser to log in manually (IdP/MFA/SSO), then save the session state.

    AppMapper does not automate the login — you authenticate by hand; it persists the
    resulting browser state (Playwright storage_state) for later authenticated scans.
    """
    from modules.auth.playwright_auth import PlaywrightNotInstalled
    from modules.auth.playwright_auth import capture as do_capture

    out_path = out or f"sessions/{role}.json"
    try:
        written = do_capture(
            role,
            url,
            out_path,
            headless=headless,
            nav_timeout_ms=timeout,
            ignore_https_errors=insecure,
        )
    except PlaywrightNotInstalled as exc:
        console.print(f"[yellow]{exc}[/yellow]")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]Session saved:[/green] {written}")
    console.print(f"Use it with:  python main.py scan --session {written} --url {url}")


@auth_app.command()
def explore(
    role: str = typer.Option("admin", "--role", help="Role to associate captured activity with"),
    url: str = typer.Option(..., "--url", help="Application URL to open in the browser"),
    out: str | None = typer.Option(
        None, "--out", help="exploration.json (default exploration/<role>.json)"
    ),
    har: str | None = typer.Option(
        None, "--har", help="captured.har (default exploration/<role>.har)"
    ),
    headless: bool = typer.Option(False, "--headless", help="Run without a visible window"),
    safe_mode: bool = typer.Option(
        False,
        "--safe-mode",
        help="Strict passive capture: never inject JavaScript (no in-page fingerprint)",
    ),
    debug_browser: bool = typer.Option(
        False,
        "--debug-browser",
        help="Log every browser event (tab created/closed, navigation, popup, download)",
    ),
    timeout: int = typer.Option(60000, "--timeout", help="Initial navigation timeout (ms)"),
    insecure: bool = typer.Option(
        False,
        "--insecure",
        help="Ignore TLS certificate errors (self-signed/expired/invalid certs on staging/UAT)",
    ),
) -> None:
    """Exploration Capture Mode: log in and explore manually while AppMapper records.

    AppMapper is a passive observer — it never navigates, reloads, opens/closes tabs,
    changes focus, or injects scripts while you work, so SSO popups, OIDC redirects and
    SPAs behave normally. Records navigations, API requests/responses, form submissions,
    uploads, downloads, WebSocket connections and (masked) auth artifacts.

    Finish by CLOSING THE BROWSER WINDOW or pressing Enter in this terminal — whichever
    first. Feed the result into a scan with `--exploration exploration/<role>.json`.
    """
    from modules.auth.explorer import explore as do_explore
    from modules.auth.playwright_auth import PlaywrightNotInstalled

    out_json = out or f"exploration/{role}.json"
    har_path = har or f"exploration/{role}.har"
    try:
        data = do_explore(
            role,
            url,
            out_json,
            har_path,
            headless=headless,
            safe_mode=safe_mode,
            debug_browser=debug_browser,
            nav_timeout_ms=timeout,
            ignore_https_errors=insecure,
        )
    except PlaywrightNotInstalled as exc:
        console.print(f"[yellow]{exc}[/yellow]")
        raise typer.Exit(code=1) from exc

    console.print(
        f"[green]Exploration captured[/green] "
        f"(navigations={len(data['navigations'])}, api={len(data['api_calls'])}, "
        f"forms={len(data['forms'])}, uploads={len(data['uploads'])}, "
        f"downloads={len(data['downloads'])}, websockets={len(data['websockets'])})"
    )
    techs = data.get("technologies", {})
    detected = (techs.get("frontend") or []) + (techs.get("libraries") or [])
    if detected:
        console.print(f"[green]Technologies:[/green] {', '.join(detected)}")
    console.print(f"  {out_json}\n  {har_path}")
    console.print(
        f"Use it with:  python main.py scan --exploration {out_json} --url {url} --role {role}"
    )


_SCAFFOLD_URL = "https://example.com"  # placeholder url written by `start` into target.yaml


def _settings(db: str | None, report_dir: str | None, log_level: str, log_json: bool) -> Settings:
    from core.assessment import active_db

    overrides: dict[str, object] = {"log_level": log_level, "log_json": log_json}
    # Fall back to the active assessment's DB (set by `start`) unless --db is given.
    db = db or active_db()
    if db:
        overrides["database_url"] = db if "://" in db else f"sqlite:///{db}"
    if report_dir:
        overrides["report_dir"] = report_dir
    return Settings(**overrides)


def _db_file(settings: Settings) -> str | None:
    """The sqlite file backing this scan, for archiving (None for non-sqlite/asdf.db)."""
    url = settings.database_url
    if not url.startswith("sqlite:///"):
        return None
    path = url[len("sqlite:///") :]
    if not path or Path(path).name == "asdf.db":
        return None
    return path


def _report_dir_name(report_dir: str | None, output_dir: str | None) -> str | None:
    """Pick the logical report-folder name, honoring the deprecated --output-dir alias."""
    if output_dir is not None:
        console.print("[yellow]--output-dir is deprecated. Use --report-dir instead.[/yellow]")
        if report_dir is None:
            return output_dir
    return report_dir


def _resolved_report(report_dir: str | None, output_dir: str | None = None) -> str:
    """Map the logical --report-dir name to reports/<name>, or exit on a bad value.

    Falls back to the active assessment's name (so reports land in reports/<name>/
    without --report-dir) when neither flag is given.
    """
    from core.assessment import active_name

    name = _report_dir_name(report_dir, output_dir) or active_name()
    try:
        return str(resolve_report_dir(name))
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc


@app.command()
def start(
    name: str = typer.Argument(
        ..., help="Assessment name (creates <name>.db + assessments/<name>/)"
    ),
) -> None:
    """Start/activate an assessment.

    Scaffolds ``assessments/<name>/`` (with a ``target.yaml`` and ``captures/``), creates
    ``<name>.db``, and sets it as the **active** database — every later command uses it by
    default (override per-command with ``--db``). Re-run to switch the active assessment.
    """
    from core.assessment import start_assessment

    try:
        info = start_assessment(name)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc

    console.print(f"[green]Assessment '{info['name']}' is now active.[/green]")
    console.print(f"  Database : {info['db']}  [dim](used by default; override with --db)[/dim]")
    console.print(
        f"  Config   : {info['target']}"
        + ("" if info["created_target"] else "  [dim](kept existing)[/dim]")
    )
    console.print(f"  Captures : {info['folder']}/captures/")
    console.print(f"  Reports  : reports/{info['name']}/  [dim](default for this assessment)[/dim]")
    console.print(
        f"\nNext: edit [cyan]{info['target']}[/cyan], then run:  "
        f"[cyan]python main.py scan --config {info['target']}[/cyan]"
    )


@app.command()
def status() -> None:
    """Show the active assessment (set by `start`) and where its files live."""
    from core.assessment import active_db, active_name

    name = active_name()
    if not name:
        console.print("[yellow]No active assessment.[/yellow]  Run:  python main.py start <name>")
        return

    db = active_db() or "—"
    cfg = Path("assessments") / name / "target.yaml"

    def _mark(exists: bool) -> str:
        return "[dim](exists)[/dim]" if exists else "[yellow](not found)[/yellow]"

    console.print(f"[green]Active assessment:[/green] {name}")
    console.print(
        f"  Database : {db}  {_mark(Path(db).exists())}  [dim](default; override --db)[/dim]"
    )
    console.print(f"  Config   : {cfg}  {_mark(cfg.exists())}")
    console.print(f"  Reports  : reports/{name}/  [dim](default; override --report-dir)[/dim]")
    console.print(f"  Captures : assessments/{name}/captures/")


@app.command()
def scan(
    url: str | None = typer.Option(
        None, "--url", help="Target URL, e.g. https://example.com (or set in --config)"
    ),
    domain: str | None = typer.Option(None, "--domain", help="Apex domain (defaults to URL host)"),
    username: str | None = typer.Option(None, "--username"),
    password: str | None = typer.Option(None, "--password"),
    jwt_token: str | None = typer.Option(
        None, "--jwt-token", help="Bearer token for authed discovery"
    ),
    role: str | None = typer.Option(None, "--role", help="Role label for single-user CLI creds"),
    session: str | None = typer.Option(
        None, "--session", help="Playwright storage_state JSON to reuse as the session"
    ),
    auth_mode: str | None = typer.Option(
        None, "--auth-mode", help="none | jwt | session | har | auto"
    ),
    exploration: str | None = typer.Option(
        None,
        "--exploration",
        help="`auth explore` capture to ingest: exploration.json, a standalone "
        "browser_intelligence.json, or a <role>_browser/ folder",
    ),
    config: str | None = typer.Option(
        None, "--config", help="YAML target config file (supports users[])"
    ),
    har: str | None = typer.Option(None, "--har", help="HAR capture file to parse"),
    burp: str | None = typer.Option(None, "--burp", help="Burp XML/JSON export to parse"),
    wordlist: str | None = typer.Option(None, "--wordlist", help="Directory-enum wordlist"),
    db: str | None = typer.Option(None, "--db", help="SQLite path or SQLAlchemy URL"),
    report_dir: str | None = typer.Option(
        None,
        "--report-dir",
        help="Logical report folder NAME (letters/digits/-/_); reports are written "
        "to reports/<name> (default: reports/default). Not a filesystem path.",
    ),
    output_dir: str | None = typer.Option(
        None,
        "--output-dir",
        hidden=True,
        help="Deprecated alias for --report-dir.",
    ),
    crawl: bool = typer.Option(True, "--crawl/--no-crawl", help="Authenticated crawl (Tier 2)"),
    crawl_path: list[str] = typer.Option(
        [], "--crawl-path", help="Extra authenticated entry path(s) to seed the crawl"
    ),
    max_pages: int = typer.Option(60, "--max-pages", help="Crawl page cap per role"),
    max_depth: int = typer.Option(2, "--max-depth", help="Crawl link depth"),
    browser_tech: bool = typer.Option(
        False, "--browser-tech", help="Browser-runtime tech fingerprint (SPAs; needs Playwright)"
    ),
    browser_wait: int = typer.Option(
        4000, "--browser-wait", help="Browser settle time before fingerprinting (ms)"
    ),
    ai_provider: str = typer.Option(
        "template", "--ai-provider", help="template | ollama | openai_compatible"
    ),
    ai_base_url: str | None = typer.Option(None, "--ai-base-url"),
    ai_model: str | None = typer.Option(None, "--ai-model"),
    skip: list[str] = typer.Option(
        [], "--skip", help=f"Modules to skip: {', '.join(all_module_names())}"
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Analyze captures only — send NO traffic to the target "
        "(skips all discovery modules, the crawl, browser fingerprint and the live role probe)",
    ),
    archive: bool = typer.Option(
        False,
        "--archive",
        help="After reporting, move all assessment artifacts into a self-contained "
        "archives/<target>_<timestamp>/ folder and leave the repository clean",
    ),
    dns: bool = typer.Option(
        False,
        "--dns",
        help="Passively resolve DNS records (A/CNAME/TXT/MX/…) for DISCOVERED hosts only "
        "(no brute-force; skipped under --offline)",
    ),
    show_pii: bool = typer.Option(
        False,
        "--show-pii",
        help="Unmask user name/email in JWT intelligence (internal environments only)",
    ),
    insecure: bool = typer.Option(
        False,
        "--insecure",
        help="Ignore TLS certificate errors for HTTP probes and browser modules "
        "(self-signed/expired/invalid certs on staging/UAT)",
    ),
    subdomain_sources: str | None = typer.Option(
        None,
        "--subdomain-sources",
        help="Passive subdomain sources (comma-separated): crtsh,alienvault,bufferover,"
        "rapiddns,securitytrails,virustotal. Default: all available (key-gated sources "
        "need ASDF_SECURITYTRAILS_API_KEY / ASDF_VIRUSTOTAL_API_KEY).",
    ),
    log_level: str = typer.Option("INFO", "--log-level"),
    log_json: bool = typer.Option(False, "--log-json"),
) -> None:
    """Run a discovery scan (+ Tier-2 intelligence) against the target, then report."""
    settings = _settings(db, _resolved_report(report_dir, output_dir), log_level, log_json)
    configure_logging(settings.log_level, settings.log_json)
    log = get_logger("cli")
    if db is None:
        from core.assessment import active_name

        if active_name():
            console.print(
                f"[dim]Active assessment: {active_name()} ({settings.database_url})[/dim]"
            )

    # Offline mode: guarantee zero outbound traffic to the target. Force-skip every
    # network discovery module, disable the crawl + browser fingerprint, and gate the
    # live role-access probe (via the `offline` option below).
    if offline:
        skip = list(set(skip) | set(all_module_names()))
        crawl = False
        browser_tech = False

    # When no target is given, fall back to the active assessment's config (set by `start`).
    from core.assessment import active_name, clear_active

    defaulted_config = False
    if url is None and config is None:
        active = active_name()
        candidate = Path("assessments") / (active or "") / "target.yaml"
        if active and candidate.exists():
            config = str(candidate)
            defaulted_config = True

    target = None
    if url is not None or config is not None:
        try:
            target = load_target(
                config_path=config,
                url=url,
                domain=domain,
                username=username,
                password=password,
                jwt_token=jwt_token,
                role=role,
                session=session,
                auth_mode=auth_mode,
                exploration=exploration,
            )
        except (ValueError, OSError) as exc:
            if not archive:
                console.print(f"[red]{exc}[/red]")
                raise typer.Exit(code=2) from exc
        # An unedited scaffold (https://example.com from `start`) is not a real target.
        if target is not None and defaulted_config and target.url.rstrip("/") == _SCAFFOLD_URL:
            target = None

    if target is None:
        # Nothing to scan. With --archive, archive whatever's present and reset the
        # active assessment (close-out); otherwise it's a usage error.
        if archive:
            from core.archive import archive_assessment

            tgt = _infer_target() or active_name() or "assessment"
            dest = archive_assessment(tgt, config_path=config, database_path=_db_file(settings))
            console.print(f"[green]Archived (no scan target):[/green] {dest}")
            cleared = clear_active()
            if cleared:
                console.print(
                    f"[green]Active assessment cleared:[/green] {cleared}  "
                    "[dim](run `start <name>` to begin a new one)[/dim]"
                )
            raise typer.Exit()
        console.print(
            "[red]A target URL is required.[/red] Pass --url or --config, or `start <name>` "
            "and edit assessments/<name>/target.yaml."
        )
        raise typer.Exit(code=2)
    ctx = ScanContext(
        target=target,
        timeout=settings.http_timeout,
        max_concurrency=settings.http_max_concurrency,
        user_agent=settings.user_agent,
        verify_tls=settings.verify_tls and not insecure,
        wordlist_path=wordlist,
        options={
            "global_har": har,
            "global_burp": burp,
            "crawl": crawl,
            # Seed paths: CLI --crawl-path plus any `crawl_start:` from the config.
            "crawl_paths": list(crawl_path) + list(target.crawl_start),
            "max_pages": max_pages,
            "max_depth": max_depth,
            "browser_tech": browser_tech,
            "browser_wait": browser_wait,
            "offline": offline,
            "show_pii": show_pii,
            "dns": dns,
            "subdomain_sources": (
                [s.strip() for s in subdomain_sources.split(",") if s.strip()]
                if subdomain_sources
                else None
            ),
            "securitytrails_key": settings.securitytrails_api_key,
            "virustotal_key": settings.virustotal_api_key,
        },
    )
    log.info("scan.targets", roles=[u.role for u in target.users] or ["<anonymous>"])

    database = Database(settings.database_url)
    orchestrator = Orchestrator(database)
    modules = build_modules(skip=skip)

    # Discovery → captures → role comparison → Tier-2 intelligence (crawl/analysis).
    results = asyncio.run(orchestrator.run(ctx, modules))

    target_id = database.get_target_id(target.domain) or database.upsert_target(target)
    data = database.fetch_all(target_id, show_pii=show_pii)
    summary_opts = {"provider": ai_provider, "base_url": ai_base_url, "model": ai_model}
    # History is kept by default: each scan also writes a numbered report_<N>.* snapshot
    # alongside the latest report.*, so previous scans in the same folder are preserved.
    paths = write_reports(
        data, settings.report_dir, show_pii=show_pii, version=True, **summary_opts
    )

    _print_scan_summary(results, paths)
    if "snapshot_html" in paths:
        console.print(f"[green]History snapshot:[/green] {paths['snapshot_html']}")

    if archive:
        from core.archive import archive_assessment
        from core.assessment import clear_active

        dest = archive_assessment(
            target.url,
            roles=[u.role for u in target.users],
            config_path=config,
            database_path=_db_file(settings),
        )
        console.print(f"[green]Assessment archived:[/green] {dest}")
        console.print("[dim]Repository cleaned · pointer: current_assessment[/dim]")
        # Close out the engagement: clear the active pointer so `start` begins fresh.
        cleared = clear_active()
        if cleared:
            console.print(
                f"[green]Active assessment cleared:[/green] {cleared}  "
                "[dim](run `start <name>` to begin a new one)[/dim]"
            )


@app.command()
def archive(
    url: str | None = typer.Option(
        None, "--url", help="Target URL/name for the archive (else inferred from reports)"
    ),
    role: list[str] = typer.Option([], "--role", help="Role label(s) for metadata (repeatable)"),
) -> None:
    """Archive the current assessment artifacts into archives/<target>_<timestamp>/."""
    from core.archive import archive_assessment
    from core.assessment import active_name, clear_active

    target = url or _infer_target() or active_name() or "assessment"
    dest = archive_assessment(target, roles=list(role))
    console.print(f"[green]Assessment archived:[/green] {dest}")
    console.print("[dim]Repository cleaned · pointer updated: current_assessment[/dim]")
    cleared = clear_active()
    if cleared:
        console.print(
            f"[green]Active assessment cleared:[/green] {cleared}  "
            "[dim](run `start <name>` to begin a new one)[/dim]"
        )


@app.command(name="migrate-workspace")
def migrate_workspace_cmd() -> None:
    """Reorganize a legacy repo root into the managed assessments/ layout."""
    from core.workspace import migrate_workspace

    report = migrate_workspace()

    console.print("[bold]Workspace Migration[/bold]\n")

    migrated = report["configs_migrated"]
    if migrated:
        console.print("[green]Configs migrated:[/green]")
        for m in migrated:
            console.print(f"  {m['from']} -> {m['to']}")
    else:
        console.print("[dim]No assessment configs to migrate.[/dim]")

    if report["files_skipped"]:
        console.print("\n[yellow]Skipped:[/yellow]")
        for s in report["files_skipped"]:
            console.print(f"  {s['file']} ({s['reason']})")

    if report["databases_detected"]:
        console.print("\n[cyan]Assessment databases detected[/cyan] (left in place; ", end="")
        console.print("archived on next `scan --archive`):")
        for db in report["databases_detected"]:
            console.print(f"  {db}")

    if report["stray_hars"]:
        console.print("\n[cyan]Stray HAR files[/cyan] (archived on next `scan --archive`):")
        for h in report["stray_hars"]:
            console.print(f"  {h}")

    console.print("\n[dim]asdf.db and assessments/ are preserved.[/dim]")


@app.command()
def latest(
    summary: bool = typer.Option(False, "--summary", help="Print the artifact summary only"),
    report: bool = typer.Option(False, "--report", help="Print the main report path only"),
) -> None:
    """Show (or locate) the most recent archived assessment."""
    from core.archive import latest_archive, load_metadata

    arch = latest_archive()
    if not arch:
        console.print("[yellow]No archived assessments found.[/yellow] Run `scan --archive`.")
        raise typer.Exit(code=1)
    meta = load_metadata(arch)

    if report:
        for name in ("report.html", "report.md", "report.json"):
            # Reports live in logical subfolders (reports/<name>/report.html); the
            # top-level path is also checked for legacy archives.
            matches = sorted((arch / "reports").rglob(name))
            if matches:
                console.print(str(matches[0]))
                return
        console.print("[yellow]No report found in the latest archive.[/yellow]")
        raise typer.Exit(code=1)

    if summary:
        console.print("[bold]Assessment Summary[/bold]\n")
        console.print(f"HAR Files: {meta.get('har_files', 0)}")
        console.print(f"Exploration Files: {meta.get('exploration_files', 0)}")
        console.print(f"Reports: {meta.get('reports', 0)}")
        console.print(f"Screenshots: {meta.get('screenshots', 0)}")
        console.print(f"Downloads: {meta.get('downloads', 0)}")
        console.print(f"Logs: {meta.get('logs', 0)}")
        return

    console.print("[bold]Latest Assessment[/bold]\n")
    console.print(f"Target:   {meta.get('target', 'n/a')}")
    console.print(f"Path:     {arch}")
    console.print(f"Created:  {meta.get('assessment_date', 'n/a')}")
    console.print(f"Roles:    {', '.join(meta.get('roles', [])) or '—'}")
    console.print(f"Reports:  {meta.get('reports', 0)}")
    console.print(f"HAR Files:{meta.get('har_files', 0)}")


def _infer_target() -> str | None:
    """Infer the target URL from an existing report.json, for the `archive` command.

    Reports live in logical subfolders (``reports/<name>/report.json``); the most
    recently written one wins. Legacy top-level ``reports/report.json`` is also read.
    """
    import json as _json
    from pathlib import Path as _Path

    reports = _Path("reports")
    candidates: list[_Path] = []
    for name in ("report.json", "output.json"):
        candidates += sorted(
            reports.glob(f"*/{name}"), key=lambda p: p.stat().st_mtime, reverse=True
        )
        legacy = reports / name
        if legacy.exists():
            candidates.append(legacy)
    for cand in candidates:
        try:
            return (_json.loads(cand.read_text(encoding="utf-8")).get("target") or {}).get("url")
        except (OSError, ValueError):
            pass
    return None


@app.command()
def report(
    domain: str = typer.Option(..., "--domain", help="Target domain to report on"),
    db: str | None = typer.Option(None, "--db"),
    report_dir: str | None = typer.Option(
        None,
        "--report-dir",
        help="Logical report folder NAME; reports go to reports/<name> "
        "(default: reports/default). Not a filesystem path.",
    ),
    output_dir: str | None = typer.Option(
        None, "--output-dir", hidden=True, help="Deprecated alias for --report-dir."
    ),
    show_pii: bool = typer.Option(
        False, "--show-pii", help="Unmask user name/email in JWT intelligence (internal only)"
    ),
) -> None:
    """Regenerate reports from previously stored results."""
    settings = _settings(db, _resolved_report(report_dir, output_dir), "INFO", False)
    configure_logging(settings.log_level, settings.log_json)

    database = Database(settings.database_url)
    target_id = database.get_target_id(domain)
    if target_id is None:
        console.print(f"[red]No stored results for domain:[/red] {domain}")
        raise typer.Exit(code=1)

    data = database.fetch_all(target_id, show_pii=show_pii)
    paths = write_reports(data, settings.report_dir, show_pii=show_pii)
    console.print("[green]Reports written:[/green]")
    for name in ("md", "html", "json"):
        console.print(f"  {paths[name]}")


@app.command(name="list-assets")
def list_assets(
    domain: str = typer.Option(..., "--domain"),
    db: str | None = typer.Option(None, "--db"),
) -> None:
    """Print discovered subdomains, directories and API endpoints."""
    settings = _settings(db, None, "WARNING", False)
    configure_logging(settings.log_level, settings.log_json)

    database = Database(settings.database_url)
    target_id = database.get_target_id(domain)
    if target_id is None:
        console.print(f"[red]No stored results for domain:[/red] {domain}")
        raise typer.Exit(code=1)

    data = database.fetch_all(target_id)

    sub_table = Table(title=f"Subdomains ({len(data.get('subdomains', []))})")
    sub_table.add_column("Name")
    sub_table.add_column("Resolved", justify="center")
    for s in data.get("subdomains", []):
        sub_table.add_row(s["name"], "yes" if s["resolved"] else "no")
    console.print(sub_table)

    dir_table = Table(title=f"Directories ({len(data.get('directories', []))})")
    dir_table.add_column("Path")
    dir_table.add_column("Status", justify="right")
    dir_table.add_column("Category")
    for d in data.get("directories", []):
        dir_table.add_row(d["path"], str(d["status_code"]), d["category"])
    console.print(dir_table)

    api_table = Table(title=f"API Endpoints ({len(data.get('api_endpoints', []))})")
    api_table.add_column("Method")
    api_table.add_column("Path")
    api_table.add_column("Source")
    for a in data.get("api_endpoints", []):
        api_table.add_row(a["method"], a["path"], a["source"])
    console.print(api_table)

    # External domain intelligence: hosts the app communicates with.
    hosts = sorted(
        data.get("hosts", []), key=lambda h: (not h.get("internal"), h.get("classification", ""))
    )
    host_table = Table(title=f"Hosts ({len(hosts)})")
    host_table.add_column("Host")
    host_table.add_column("Classification")
    host_table.add_column("Requests", justify="right")
    host_table.add_column("APIs", justify="right")
    host_table.add_column("Auth", justify="center")
    host_table.add_column("Roles")
    for h in hosts:
        host_table.add_row(
            h["host"],
            h["classification"],
            str(h.get("requests", 0)),
            str(h.get("apis", 0)),
            "yes" if h.get("auth_required") else "—",
            h.get("roles") or "—",
        )
    console.print(host_table)

    # Unified asset intelligence: backend services + related internal apps.
    from modules.intelligence.asset_inventory import build_asset_intelligence

    ai = build_asset_intelligence(data)
    svc_table = Table(title=f"Backend Services ({len(ai.get('services', []))})")
    svc_table.add_column("Service")
    for s in ai.get("services", []):
        svc_table.add_row(s)
    console.print(svc_table)

    app_table = Table(title=f"Related Internal Applications ({len(ai.get('internal_apps', []))})")
    app_table.add_column("Host")
    app_table.add_column("Type")
    for a in ai.get("internal_apps", []):
        app_table.add_row(a["host"], a["app_type"])
    console.print(app_table)


@app.command()
def query(
    q: str = typer.Option(..., "--q", help='Search query, e.g. "upload" or "admin functions"'),
    domain: str | None = typer.Option(None, "--domain", help="Limit to a stored target"),
    db: str | None = typer.Option(None, "--db"),
) -> None:
    """Search the local knowledge base (SQLite FTS5) built from discovered data."""
    settings = _settings(db, None, "WARNING", False)
    configure_logging(settings.log_level, settings.log_json)
    database = Database(settings.database_url)

    target_id = database.get_target_id(domain) if domain else None
    if target_id is None:
        # Default to the most recent target if none specified.
        with database.session() as s:
            from models.db_models import Target

            row = s.query(Target).order_by(Target.id.desc()).first()
            target_id = row.id if row else None
    if target_id is None:
        console.print("[red]No stored targets to query.[/red]")
        raise typer.Exit(code=1)

    fts = to_fts_query(q)
    results = database.search_knowledge(target_id, fts)
    table = Table(title=f'Knowledge query: "{q}"  (FTS: {fts}) — {len(results)} hits')
    table.add_column("Kind")
    table.add_column("Role")
    table.add_column("Category")
    table.add_column("Path")
    for r in results:
        table.add_row(r["kind"], r["role"] or "", r["category"] or "", r["path"])
    console.print(table)


@app.command()
def summary(
    domain: str = typer.Option(..., "--domain"),
    db: str | None = typer.Option(None, "--db"),
    ai_provider: str = typer.Option("template", "--ai-provider"),
    ai_base_url: str | None = typer.Option(None, "--ai-base-url"),
    ai_model: str | None = typer.Option(None, "--ai-model"),
) -> None:
    """Print the application summary for a stored target."""
    settings = _settings(db, None, "WARNING", False)
    configure_logging(settings.log_level, settings.log_json)
    database = Database(settings.database_url)
    target_id = database.get_target_id(domain)
    if target_id is None:
        console.print(f"[red]No stored results for domain:[/red] {domain}")
        raise typer.Exit(code=1)

    from modules.ai import generate_summary

    data = database.fetch_all(target_id)
    result = generate_summary(data, provider=ai_provider, base_url=ai_base_url, model=ai_model)
    console.print(f"[dim]provider: {result.provider}[/dim]\n")
    console.print(result.text)


def _print_scan_summary(results, paths: dict) -> None:
    table = Table(title="Scan Summary")
    table.add_column("Module")
    table.add_column("OK", justify="center")
    table.add_column("Items", justify="right")
    table.add_column("Error")
    for r in results:
        table.add_row(r.module, "✅" if r.ok else "❌", str(r.items), r.error or "")
    console.print(table)
    console.print("[green]Reports:[/green]")
    for name in ("md", "html", "json"):
        if name in paths:
            console.print(f"  {paths[name]}")
    for key in ("graph_json", "graph_graphml", "graph_drawio"):
        if key in paths:
            console.print(f"  {paths[key]}")


if __name__ == "__main__":
    app()
