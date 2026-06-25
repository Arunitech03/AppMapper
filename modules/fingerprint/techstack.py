"""Module 3: Technology-stack fingerprinting.

A lightweight signature engine that inspects response headers, cookies, meta
tags, HTML body and referenced JS bundles to identify frontend frameworks and
backend platforms. Detection is evidence-based: every match records why it fired.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin

import httpx

from core.base import BaseModule
from core.http import client_for
from models.schemas import ModuleResult, ScanContext, TechStack

# Each signature: (technology, category, kind, pattern)
# kind in {header, cookie, body, meta} ; pattern is a compiled regex.
Signature = tuple[str, str, str, re.Pattern[str]]


def _sig(tech: str, category: str, kind: str, pattern: str) -> Signature:
    return (tech, category, kind, re.compile(pattern, re.IGNORECASE))


SIGNATURES: list[Signature] = [
    # Backend platforms
    _sig("ASP.NET Core", "backend", "header", r"kestrel"),
    _sig("ASP.NET Core", "backend", "cookie", r"\.aspnetcore"),
    _sig("ASP.NET MVC", "backend", "header", r"asp\.net"),
    _sig("ASP.NET MVC", "backend", "header", r"x-aspnetmvc-version"),
    _sig("ASP.NET", "backend", "header", r"x-aspnet-version"),
    _sig("ASP.NET", "backend", "cookie", r"asp\.net_sessionid"),
    _sig("Django", "backend", "cookie", r"csrftoken|django"),
    _sig("Django", "backend", "header", r"wsgiserver"),
    _sig("Flask", "backend", "header", r"werkzeug"),
    _sig("Flask", "backend", "cookie", r"\bsession="),
    _sig("Laravel", "backend", "cookie", r"laravel_session|xsrf-token"),
    _sig("Spring Boot", "backend", "header", r"x-application-context"),
    _sig("Spring Boot", "backend", "cookie", r"jsessionid"),
    _sig("NodeJS", "backend", "header", r"express"),
    _sig("NodeJS", "backend", "cookie", r"connect\.sid"),
    _sig("WordPress", "backend", "body", r"/wp-content/|/wp-includes/"),
    _sig("WordPress", "backend", "meta", r"wordpress"),
    # Frontend frameworks
    _sig("Angular", "frontend", "body", r"ng-version|angular(\.min)?\.js|_nghost|__ngcontext__"),
    _sig("React", "frontend", "body", r"react(\.min)?\.js|data-reactroot|__react"),
    _sig("Vue", "frontend", "body", r"vue(\.min)?\.js|data-v-[0-9a-f]{8}|__vue__"),
]

META_GENERATOR = re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", re.I)

# Resource references in the page: <script src="...">, <link href="...">.
RE_SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
RE_LINK_HREF = re.compile(r"<link[^>]+href=[\"']([^\"']+)[\"']", re.IGNORECASE)

# Client-side library signatures matched against referenced resource URLs and the
# page body. Each: (library, regex). These are UI/JS libraries, not frameworks.
LibrarySig = tuple[str, re.Pattern[str]]


def _lib(name: str, pattern: str) -> LibrarySig:
    return (name, re.compile(pattern, re.IGNORECASE))


LIBRARY_SIGNATURES: list[LibrarySig] = [
    _lib("Bootstrap", r"bootstrap(\.bundle)?(\.min)?\.(js|css)|/bootstrap/"),
    _lib("jQuery", r"jquery[-.]?[0-9.]*(\.min)?\.js|/jquery/"),
    _lib("jQuery UI", r"jquery-ui(\.min)?\.(js|css)"),
    _lib("Font Awesome", r"font-?awesome|/fontawesome/|fa-(solid|brands|regular)"),
    _lib("Tailwind CSS", r"tailwind(css)?(\.min)?\.css|cdn\.tailwindcss\.com"),
    _lib("Bulma", r"bulma(\.min)?\.css"),
    _lib("Foundation", r"foundation(\.min)?\.(js|css)"),
    _lib("Popper.js", r"popper(\.min)?\.js"),
    _lib("lodash", r"lodash(\.min)?\.js"),
    _lib("Underscore.js", r"underscore(\.min)?\.js"),
    _lib("Moment.js", r"moment(\.min)?\.js"),
    _lib("Axios", r"axios(\.min)?\.js"),
    _lib("D3.js", r"\bd3(\.v\d+)?(\.min)?\.js"),
    _lib("Chart.js", r"chart(\.min)?\.js|/chart\.js/"),
    _lib("three.js", r"three(\.min)?\.js"),
    _lib("Alpine.js", r"alpinejs|alpine(\.min)?\.js"),
    _lib("htmx", r"htmx(\.min)?\.js"),
    _lib("Modernizr", r"modernizr(\.min)?\.js"),
    _lib("Handlebars", r"handlebars(\.min)?\.js"),
    _lib("Google Analytics", r"google-analytics\.com/analytics\.js|gtag/js|googletagmanager\.com"),
]

# Content signatures matched against the *contents* of downloaded JS bundles —
# the markers that survive minification. (name, category, regex). This is what
# lets us fingerprint client-rendered SPAs whose frameworks live inside hashed
# bundles rather than named <script src> files.
ContentSig = tuple[str, str, re.Pattern[str]]


def _csig(name: str, category: str, pattern: str) -> ContentSig:
    return (name, category, re.compile(pattern))


JS_CONTENT_SIGNATURES: list[ContentSig] = [
    # Frameworks
    _csig(
        "React",
        "frontend",
        r"__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED|react-dom"
        r"|reactjs\.org/docs/error-decoder|__REACT_DEVTOOLS_GLOBAL_HOOK__",
    ),
    _csig("Angular", "frontend", r"@angular/core|ngDevMode|ng-version=|platformBrowserDynamic|ɵɵ"),
    _csig("Vue.js", "frontend", r"__VUE__|__VUE_DEVTOOLS|vue\.runtime|Vue\.config|__vnode"),
    _csig("Svelte", "frontend", r"__svelte|svelte/internal|create_fragment"),
    _csig("Preact", "frontend", r"preact|__preactattr_"),
    # Libraries
    _csig("lit", "library", r"lit-html|lit-element|litElement|lit\$\d|reactiveElement"),
    _csig("core-js", "library", r"core-js|__core-js_shared__"),
    _csig(
        "Three.js",
        "library",
        r"WebGLRenderer|THREE\.REVISION|three\.module|\bACESFilmicToneMapping\b",
    ),
    _csig("Redux", "library", r"@@redux|redux-toolkit|createStore"),
    _csig("RxJS", "library", r"\brxjs\b|Subscriber\.prototype|Observable\.prototype"),
    _csig("Lodash", "library", r"lodash|runInContext"),
    _csig("Moment.js", "library", r"moment\.js|__moment|MomentJS"),
    _csig("Day.js", "library", r"\bdayjs\b"),
    _csig("D3.js", "library", r"d3-selection|d3-scale|\bd3\.(version|select)\b"),
    _csig("Mapbox GL", "library", r"mapbox-gl|mapboxgl"),
    _csig("Leaflet", "library", r"leaflet|L\.Map\b"),
    _csig("Chart.js", "library", r"chart\.js|Chart\.register"),
    _csig("jQuery", "library", r"jQuery\.fn\.jquery|jquery\.js"),
]

# Progressive Web App markers (manifest link / service worker).
RE_MANIFEST = re.compile(r"<link[^>]+rel=[\"']manifest[\"']", re.IGNORECASE)
RE_SERVICE_WORKER = re.compile(r"serviceWorker\.register|navigator\.serviceWorker", re.IGNORECASE)


class TechStackModule(BaseModule):
    name = "techstack"
    category = "fingerprint"

    async def run(self, ctx: ScanContext) -> ModuleResult:
        async with client_for(ctx) as client:
            try:
                resp = await client.get(ctx.target.url)
            except httpx.HTTPError as exc:
                return ModuleResult(module=self.name, ok=False, error=str(exc), data={}, items=0)

            # Download referenced JS bundles so client-rendered SPAs can be
            # fingerprinted from bundle *contents* (Option B), not just markup.
            scripts = await self._fetch_scripts(client, str(resp.url), resp.text or "", ctx)

        tech = self._fingerprint(resp, scripts)
        return ModuleResult(
            module=self.name,
            data=tech.model_dump(),
            items=len(tech.frontend) + len(tech.backend) + len(tech.servers) + len(tech.libraries),
        )

    async def _fetch_scripts(
        self, client: httpx.AsyncClient, base_url: str, html: str, ctx: ScanContext
    ) -> list[tuple[str, str]]:
        """Download referenced <script src> bundles (bounded), returning (url, content)."""
        max_scripts = int(ctx.options.get("techstack_max_scripts", 12))
        max_bytes = 2_000_000
        urls: list[str] = []
        seen: set[str] = set()
        for src in RE_SCRIPT_SRC.findall(html):
            absolute = urljoin(base_url, src)
            if absolute.split("?")[0].lower().endswith(".js") and absolute not in seen:
                seen.add(absolute)
                urls.append(absolute)
            if len(urls) >= max_scripts:
                break

        sem = asyncio.Semaphore(ctx.max_concurrency)

        async def fetch(url: str) -> tuple[str, str] | None:
            async with sem:
                try:
                    resp = await client.get(url)
                    return (url, (resp.text or "")[:max_bytes])
                except Exception:  # noqa: BLE001 - a failed bundle fetch must not break techstack
                    return None

        results = await asyncio.gather(*(fetch(u) for u in urls))
        return [r for r in results if r is not None]

    def _fingerprint(
        self, resp: httpx.Response, scripts: list[tuple[str, str]] | None = None
    ) -> TechStack:
        headers_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        cookies_blob = "; ".join(f"{k}={v}" for k, v in resp.cookies.items())
        # Some servers set cookies the httpx jar drops (e.g. invalid attrs); also
        # scan the raw set-cookie headers.
        cookies_blob += "\n" + "\n".join(resp.headers.get_list("set-cookie"))
        body = resp.text or ""
        meta = " ".join(META_GENERATOR.findall(body))

        blobs = {"header": headers_blob, "cookie": cookies_blob, "body": body, "meta": meta}

        frontend: dict[str, list[str]] = {}
        backend: dict[str, list[str]] = {}
        evidence: dict[str, list[str]] = {}

        for tech, category, kind, pattern in SIGNATURES:
            match = pattern.search(blobs.get(kind, ""))
            if match:
                bucket = frontend if category == "frontend" else backend
                bucket.setdefault(tech, [])
                evidence.setdefault(tech, []).append(f"{kind}:{match.group(0)[:80]}")

        servers: list[str] = []
        server_header = resp.headers.get("server")
        if server_header:
            servers.append(server_header)
            evidence.setdefault(server_header, []).append("header:Server")
        powered = resp.headers.get("x-powered-by")
        if powered:
            servers.append(powered)
            evidence.setdefault(powered, []).append("header:X-Powered-By")

        libraries = self._detect_libraries(body, evidence)

        # Option B: fingerprint downloaded JS bundle contents (client-rendered SPAs).
        self._detect_from_bundles(scripts or [], frontend, libraries, evidence)

        # Progressive Web App detection (manifest link / service worker).
        bundle_text = "\n".join(c for _, c in (scripts or []))
        if RE_MANIFEST.search(body) or RE_SERVICE_WORKER.search(body + bundle_text):
            libraries.add("PWA")
            evidence.setdefault("PWA", []).append("manifest/service-worker")

        return TechStack(
            frontend=sorted(frontend),
            backend=sorted(backend),
            servers=servers,
            libraries=sorted(libraries),
            evidence=evidence,
        )

    def _detect_from_bundles(
        self,
        scripts: list[tuple[str, str]],
        frontend: dict[str, list[str]],
        libraries: set[str],
        evidence: dict[str, list[str]],
    ) -> None:
        """Scan downloaded bundle contents for framework/library content markers."""
        for url, content in scripts:
            corpus = url + "\n" + content
            for name, category, pattern in JS_CONTENT_SIGNATURES:
                if name in libraries or name in frontend:
                    continue
                match = pattern.search(corpus)
                if match:
                    if category == "frontend":
                        frontend.setdefault(name, [])
                    else:
                        libraries.add(name)
                    short = url.rsplit("/", 1)[-1][:40]
                    evidence.setdefault(name, []).append(f"bundle:{short}:{match.group(0)[:40]}")

    def _detect_libraries(self, body: str, evidence: dict[str, list[str]]) -> set[str]:
        """Detect client-side libraries from <script>/<link> references and body."""
        # Collect referenced resource URLs plus the raw body as the search corpus.
        resources = RE_SCRIPT_SRC.findall(body) + RE_LINK_HREF.findall(body)
        corpus = "\n".join(resources)

        libraries: set[str] = set()
        for name, pattern in LIBRARY_SIGNATURES:
            match = pattern.search(corpus)
            # Fall back to scanning the body (covers inline-referenced library names).
            if not match:
                match = pattern.search(body)
            if match:
                libraries.add(name)
                evidence.setdefault(name, []).append(f"resource:{match.group(0)[:80]}")
        return libraries
