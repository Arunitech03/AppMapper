"""Scan orchestration.

Runs the selected discovery modules concurrently, then performs two extra
phases: capture ingestion (per-role HAR/Burp) and role-based access comparison.
Module failures are isolated (via :meth:`BaseModule.safe_run`) so one broken
module never aborts the scan.
"""

from __future__ import annotations

import asyncio

from core.base import BaseModule
from core.logging import get_logger
from models.schemas import (
    ApiEndpoint,
    BurpRequest,
    DirectoryHit,
    HarRequest,
    JSFinding,
    ModuleResult,
    NetworkService,
    ScanContext,
    SSLFinding,
    Subdomain,
    TechStack,
    UserCredential,
)
from modules.access.comparison import build_access_records
from modules.api.analyzer import analyze_apis
from modules.auth.crawler import AuthCrawlerModule
from modules.intelligence.checklist_generator import generate_checklist
from modules.intelligence.domain_classifier import build_domain_intel
from modules.intelligence.function_detector import detect_functions
from modules.intelligence.workflow_mapper import build_workflow
from modules.knowledge.index import build_documents
from parsers.burp_parser import parse_burp
from parsers.har_parser import parse_har
from storage.database import Database

log = get_logger("orchestrator")


class Orchestrator:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def run(self, ctx: ScanContext, modules: list[BaseModule]) -> list[ModuleResult]:
        """Execute modules concurrently, ingest captures, compare role access."""
        target_id = self.db.upsert_target(ctx.target)
        log.info(
            "scan.start",
            target=ctx.target.url,
            modules=[m.name for m in modules],
            roles=[u.role for u in ctx.users],
        )

        if ctx.users:
            self.db.save_users(target_id, ctx.users)

        # Parse any exploration.json captures once; reused across phases so the
        # manual exploration feeds captures, crawl, artifacts and intelligence.
        self._exploration = self._load_exploration(ctx)

        results = await asyncio.gather(*(m.safe_run(ctx) for m in modules))
        for result in results:
            try:
                self._persist(target_id, result)
            except Exception as exc:  # noqa: BLE001 - persistence must not abort the run
                log.error("scan.persist_failed", module=result.module, error=str(exc))

        self._ingest_captures(target_id, ctx)
        await self._compare_roles(target_id, ctx)
        await self._run_tier2(target_id, ctx)

        log.info("scan.complete", target=ctx.target.url)
        return list(results)

    # -- Tier 2: application intelligence ---------------------------------
    async def _run_tier2(self, target_id: int, ctx: ScanContext) -> None:
        """Auth intel + authenticated crawl + intelligence analysis (isolated phases)."""
        # 0) Enterprise auth: IdP detection + session/artifact inventory.
        await self._auth_intel(target_id, ctx)

        # 0b) Optional browser-runtime tech fingerprint (Option A) for SPAs.
        if ctx.options.get("browser_tech"):
            await self._browser_tech(target_id, ctx)

        # 1) Authenticated crawl (per role + anonymous) merged with exploration.
        crawl_endpoints = []
        crawl_forms = []
        if ctx.options.get("crawl", True):
            try:
                crawl = await AuthCrawlerModule().safe_run(ctx)
                if crawl.ok and crawl.data:
                    from models.schemas import CrawlEndpoint, DiscoveredForm

                    crawl_endpoints += [CrawlEndpoint(**e) for e in crawl.data.get("endpoints", [])]
                    crawl_forms += [DiscoveredForm(**f) for f in crawl.data.get("forms", [])]
            except Exception as exc:  # noqa: BLE001
                log.error("tier2.crawl_failed", error=str(exc))

        # Manual exploration endpoints/forms are first-class crawl data.
        explored_techs: list[tuple[str, str, str | None]] = []
        for bundle in self._exploration.values():
            crawl_endpoints += bundle["crawl_endpoints"]
            crawl_forms += bundle["forms"]
            explored_techs += bundle.get("technologies", [])
        if crawl_endpoints:
            self._phase(
                "crawl_save", lambda: self.db.save_crawl_endpoints(target_id, crawl_endpoints)
            )
        if crawl_forms:
            self._phase("forms_save", lambda: self.db.save_forms(target_id, crawl_forms))
        # Merge exploration's runtime-detected technologies into the tech stack.
        if explored_techs:
            self._phase(
                "explore_tech", lambda: self.db.merge_technologies(target_id, explored_techs)
            )

        # 2) DB-derived analysis (offline; failures isolated per phase).
        data = self.db.fetch_all(target_id)

        # Optional passive DNS enrichment of DISCOVERED hosts (opt-in --dns; never offline,
        # never brute-force). Resolves only hosts already seen in captured traffic.
        if ctx.options.get("dns") and not ctx.options.get("offline"):
            try:
                await self._resolve_dns(target_id, ctx, data)
            except Exception as exc:  # noqa: BLE001 - DNS optional; isolate failure
                log.error("tier2.dns_failed", error=str(exc))

        # Reconcile the IdP from captured artifacts (fixes live-detection "Unknown").
        self._phase("idp_reconcile", lambda: self._reconcile_idp(target_id, data))

        # Mine captured content (HAR/Burp bodies, JS) for secrets, routes, hidden
        # APIs and config — persisted as masked intel findings.
        self._phase("content_intel", lambda: self._content_intelligence(target_id, ctx))

        self._phase("functions", lambda: self._detect_functions(target_id, data))
        self._phase("apis", lambda: self.db.save_api_intel(target_id, analyze_apis(data)))
        self._phase(
            "workflow", lambda: self.db.save_workflow_edges(target_id, build_workflow(data))
        )

        # Re-fetch so functions/apis are available to checklist + knowledge index.
        data2 = self.db.fetch_all(target_id)
        self._phase(
            "checklist",
            lambda: self.db.save_checklist_items(
                target_id, generate_checklist(data2.get("sensitive_functions", []))
            ),
        )
        self._phase(
            "knowledge",
            lambda: self.db.index_knowledge(target_id, build_documents(data2)),
        )
        # Domain intelligence: classify every host the app talks to, persist the
        # hostname inventory + relationship edges.
        self._phase("domain_intel", lambda: self._persist_domain_intel(target_id, data2))

    def _content_intelligence(self, target_id: int, ctx: ScanContext) -> None:
        """Gather HAR/Burp body content and mine it for masked intel findings."""
        from models.schemas import IntelFinding
        from modules.intelligence.config_intelligence import discover_config
        from modules.intelligence.content_sources import gather_content, sibling_har
        from modules.intelligence.route_discovery import extract_api_refs, extract_routes
        from modules.intelligence.secret_discovery import discover_secrets
        from modules.intelligence.sourcemap_intelligence import analyze_sourcemaps

        har_paths: list[str] = []
        burp_paths: list[str] = []
        for user in ctx.users:
            if user.har:
                har_paths.append(user.har)
            if user.burp:
                burp_paths.append(user.burp)
            if user.exploration:
                sib = sibling_har(user.exploration)
                if sib:
                    har_paths.append(sib)
        if ctx.options.get("global_har"):
            har_paths.append(ctx.options["global_har"])
        if ctx.options.get("global_burp"):
            burp_paths.append(ctx.options["global_burp"])

        # Browser intelligence findings collected during exploration (Sprint B) are
        # saved together with content findings (same table uses replace semantics).
        findings: list[IntelFinding] = []
        from modules.intelligence.browser_secret_discovery import discover_browser_secrets

        for bundle in self._exploration.values():
            findings += bundle.get("intel_findings", [])
            bi = bundle.get("browser_intelligence") or {}
            if bi:
                findings += discover_browser_secrets(bi.get("role", ""), bi)

        if not har_paths and not burp_paths:
            if findings:
                self.db.save_intel_findings(target_id, findings)
                log.info("content_intel.saved", findings=len(findings))
            return  # no HAR/Burp bodies to mine, but browser intel was saved

        corpus = gather_content(har_paths=har_paths, burp_paths=burp_paths)
        base = ctx.target.domain or ""
        findings += list(discover_secrets(corpus, base_domain=base))
        findings += discover_config(corpus)
        # Sprint B.1: runtime config object literals (window.env / __CONFIG__) in JS.
        from modules.intelligence.runtime_config_discovery import discover_runtime_config

        findings += discover_runtime_config(corpus, base_domain=base)
        for route in extract_routes(corpus):
            findings.append(
                IntelFinding(
                    kind="route",
                    category="Routes",
                    name=route,
                    location=route,
                    source="JS",
                    confidence="medium",
                    severity="Informational",
                )
            )
        for ref in extract_api_refs(corpus):
            findings.append(
                IntelFinding(
                    kind="api_ref",
                    category="Hidden API",
                    name=ref,
                    location=ref,
                    source="JS",
                    confidence="medium",
                    severity="Informational",
                )
            )
        sm = analyze_sourcemaps(corpus)
        for m in sm["maps"]:
            findings.append(
                IntelFinding(
                    kind="sourcemap",
                    category="Source Map",
                    name=m,
                    location=m,
                    source="JS",
                    confidence="high",
                    severity="Informational",
                )
            )
        for ref in sm["api_refs"]:
            findings.append(
                IntelFinding(
                    kind="api_ref",
                    category="Hidden API",
                    name=ref,
                    location=ref,
                    source="Source Map",
                    confidence="high",
                    severity="Informational",
                )
            )

        self.db.save_intel_findings(target_id, findings)
        log.info("content_intel.saved", findings=len(findings))

    async def _resolve_dns(self, target_id: int, ctx: ScanContext, data: dict) -> None:
        """Passively resolve discovered hosts (A/AAAA/CNAME/TXT/MX/NS/SOA)."""
        import json as _json
        from urllib.parse import urlparse

        from modules.network.dns_resolver import resolve_hosts

        def chain(value):
            if isinstance(value, list):
                return value
            if isinstance(value, str) and value.strip():
                try:
                    parsed = _json.loads(value)
                    return parsed if isinstance(parsed, list) else []
                except ValueError:
                    return []
            return []

        hosts: set[str] = set()
        for src in ("har_requests", "crawl_endpoints", "burp_requests"):
            for r in data.get(src, []) or []:
                h = urlparse(r.get("url", "")).hostname
                if h:
                    hosts.add(h)
                for hop in chain(r.get("redirect_chain")):
                    hh = urlparse(hop).hostname
                    if hh:
                        hosts.add(hh)
        records = await resolve_hosts(sorted(hosts), timeout=ctx.timeout)
        self.db.save_dns_records(target_id, records)
        log.info("tier2.dns_records", hosts=len(hosts), records=len(records))

    def _reconcile_idp(self, target_id: int, data: dict) -> None:
        """Override idp_info using captured artifacts when live detection was Unknown."""
        from modules.auth.idp_analyzer import effective_idp

        merged = effective_idp(data)
        if merged and (merged.identity_provider != "Unknown" or merged.realm or merged.evidence):
            self.db.save_idp_info(target_id, [merged])

    def _persist_domain_intel(self, target_id: int, data: dict) -> None:
        intel = build_domain_intel(data)
        self.db.save_hosts(target_id, intel["hosts"])
        base = intel["relationships"]["base"]
        self.db.save_domain_edges(
            target_id,
            [
                {"from_host": base, "to_host": e["to"], "kind": e["kind"]}
                for e in intel["relationships"]["edges"]
            ],
        )

    async def _browser_tech(self, target_id: int, ctx: ScanContext) -> None:
        """Boot the page in a real browser and merge runtime-detected technologies."""
        from modules.auth.playwright_auth import PlaywrightNotInstalled
        from modules.fingerprint.runtime_fingerprint import fingerprint_runtime

        # Use the primary role's captured session so authenticated SPAs fully boot.
        primary = ctx.target.primary
        storage = primary.session_file if primary and primary.session_file else None
        settle = int(ctx.options.get("browser_wait", 4000))
        try:
            result = await asyncio.to_thread(
                fingerprint_runtime,
                ctx.target.url,
                storage_state=storage,
                settle_ms=settle,
                ignore_https_errors=not ctx.verify_tls,
            )
        except PlaywrightNotInstalled as exc:
            log.warning("browser_tech.unavailable", hint=str(exc).splitlines()[0])
            return
        except Exception as exc:  # noqa: BLE001
            log.error("browser_tech.failed", error=str(exc))
            return

        rows: list[tuple[str, str, str | None]] = []
        for name in result.get("frontend", []):
            ev = result.get("versions", {}).get(name)
            rows.append((name, "frontend", f"runtime{':' + ev if ev else ''}"))
        for name in result.get("libraries", []):
            ev = result.get("versions", {}).get(name)
            rows.append((name, "library", f"runtime{':' + ev if ev else ''}"))
        if rows:
            self._phase("browser_tech", lambda: self.db.merge_technologies(target_id, rows))

    async def _auth_intel(self, target_id: int, ctx: ScanContext) -> None:
        """Detect the IdP and inventory each role's session + masked artifacts."""
        from modules.auth.auth_manager import AuthManager
        from modules.auth.idp_detector import detect_idp

        try:
            idp = await detect_idp(ctx)
            self.db.save_idp_info(target_id, [idp])
        except Exception as exc:  # noqa: BLE001
            log.error("tier2.idp_failed", error=str(exc))

        manager = AuthManager()
        artifacts = []
        sessions = []
        for user in ctx.users:
            resolved = manager.resolve(user)
            artifacts.extend(manager.collect_artifacts(user, resolved))
            sessions.append(manager.session_info(user))
        # Masked artifacts captured during manual exploration.
        for bundle in self._exploration.values():
            artifacts.extend(bundle["artifacts"])
        # Anonymous baseline always present in the inventory.
        from models.schemas import SessionInfo

        sessions.append(SessionInfo(role="anonymous", source="none", captured=False))
        self._phase("auth_artifacts", lambda: self.db.save_auth_artifacts(target_id, artifacts))
        self._phase("sessions", lambda: self.db.save_sessions(target_id, sessions))

    def _detect_functions(self, target_id: int, data: dict) -> None:
        endpoints: list[dict] = []
        for d in data.get("directories", []):
            endpoints.append({"path": d["path"], "role": None, "method": "GET"})
        for ep in data.get("crawl_endpoints", []):
            endpoints.append(
                {"path": ep["path"], "role": ep.get("role"), "method": ep.get("method", "GET")}
            )
        for api in data.get("api_intel", []):
            endpoints.append({"path": api["path"], "role": None, "method": "GET"})
        for d in data.get("api_endpoints", []):
            endpoints.append({"path": d["path"], "role": None, "method": d.get("method", "GET")})
        self.db.save_sensitive_functions(target_id, detect_functions(endpoints))

    def _phase(self, name: str, fn) -> None:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - one phase must not abort the rest
            log.error("tier2.phase_failed", phase=name, error=str(exc))

    # -- exploration capture ingestion -----------------------------------
    def _load_exploration(self, ctx: ScanContext) -> dict:
        """Parse each role's exploration.json into reusable DTO bundles."""
        from modules.auth import exploration_import

        show_pii = bool(ctx.options.get("show_pii"))
        bundles: dict[str, dict] = {}
        for user in ctx.users:
            if user.exploration:
                try:
                    bundles[user.role] = exploration_import.parse(
                        user.role, user.exploration, show_pii=show_pii
                    )
                    log.info(
                        "exploration.loaded",
                        role=user.role,
                        endpoints=len(bundles[user.role]["crawl_endpoints"]),
                    )
                except (OSError, ValueError) as exc:
                    log.warning("exploration.failed", role=user.role, error=str(exc))
        return bundles

    # -- phase: capture ingestion ----------------------------------------
    def _ingest_captures(self, target_id: int, ctx: ScanContext) -> None:
        """Parse per-role and global HAR/Burp captures, tag by role, persist."""
        har_items: list[HarRequest] = []
        burp_items: list[BurpRequest] = []

        for user in ctx.users:
            har_items += self._parse_har(user.har, user.role)
            burp_items += self._parse_burp(user.burp, user.role)

        # Global captures (CLI --har/--burp) attributed to the primary role.
        primary_role = ctx.target.primary.role if ctx.target.primary else None
        har_items += self._parse_har(ctx.options.get("global_har"), primary_role)
        burp_items += self._parse_burp(ctx.options.get("global_burp"), primary_role)

        # Exploration API calls + navigations become HAR-style requests.
        for bundle in self._exploration.values():
            har_items += bundle["har_requests"]

        if har_items:
            self.db.save_har_requests(target_id, har_items)
            log.info("captures.har", count=len(har_items))
        if burp_items:
            self.db.save_burp_requests(target_id, burp_items)
            log.info("captures.burp", count=len(burp_items))

    def _parse_har(self, path: str | None, role: str | None) -> list[HarRequest]:
        if not path:
            return []
        try:
            from modules.auth.masking import redact_url

            items = parse_har(path)
            for i in items:
                i.role = role
                i.url = redact_url(i.url)  # strip secrets from query strings
            return items
        except (OSError, ValueError) as exc:
            log.warning("captures.har_failed", path=path, error=str(exc))
            return []

    def _parse_burp(self, path: str | None, role: str | None) -> list[BurpRequest]:
        if not path:
            return []
        try:
            from modules.auth.masking import redact_url

            items = parse_burp(path)
            for i in items:
                i.role = role
                i.url = redact_url(i.url)
            return items
        except (OSError, ValueError) as exc:
            log.warning("captures.burp_failed", path=path, error=str(exc))
            return []

    # -- phase: role-based access comparison ------------------------------
    async def _compare_roles(self, target_id: int, ctx: ScanContext) -> None:
        """Probe each role's reachable endpoints and store the access matrix."""
        if ctx.options.get("offline"):
            return  # offline: no live probing — role visibility is HAR-derived
        if len(ctx.users) < 2:
            return  # comparison needs at least two roles to be meaningful
        records = await build_access_records(ctx)
        if records:
            self.db.save_role_access(target_id, records)
            log.info("access.records_saved", count=len(records))

    # -- discovery-result persistence ------------------------------------
    def _persist(self, target_id: int, result: ModuleResult) -> None:
        if not result.ok or result.data is None:
            return
        data = result.data

        if result.module == "subdomains":
            self.db.save_subdomains(target_id, [Subdomain(**d) for d in data])
        elif result.module == "directories":
            self.db.save_directories(target_id, [DirectoryHit(**d) for d in data])
        elif result.module == "techstack":
            self.db.save_techstack(target_id, TechStack(**data))
        elif result.module == "ssl":
            self.db.save_ssl_findings(target_id, [SSLFinding(**d) for d in data])
        elif result.module == "js_analysis":
            self.db.save_js_findings(target_id, JSFinding(**data))
        elif result.module == "nmap":
            self.db.save_network_services(target_id, [NetworkService(**d) for d in data])
        elif result.module == "api_discovery":
            self.db.save_api_endpoints(target_id, [ApiEndpoint(**d) for d in data])
        else:
            log.warning("scan.unknown_module", module=result.module)


__all__ = ["Orchestrator", "UserCredential"]
