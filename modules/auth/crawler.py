"""Feature 1: Authenticated crawling (discovery-only).

For each configured role (plus a synthetic ``anonymous`` role) the crawler
establishes a session and performs a bounded breadth-first crawl of the
application, recording reachable pages, forms, API-looking links and downloadable
resources.

Scope guardrails (enforced here):
  * Crawling issues **GET requests only**, same-host, bounded by max pages/depth.
  * Forms are *discovered and described*, never submitted.
  * The single state-touching request is the configured **login** POST, using the
    role's own credentials. There is no brute forcing, auth bypass, or
    exploitation of any kind.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import httpx

from core.base import BaseModule
from models.schemas import (
    CrawlEndpoint,
    DiscoveredForm,
    FormField,
    LoginConfig,
    ModuleResult,
    ScanContext,
    UserCredential,
)
from modules.auth.masking import redact_url

RE_HREF = re.compile(r"<a[^>]+href=[\"']([^\"'#]+)[\"']", re.IGNORECASE)
# Never follow session-destroying links — doing so would log the crawler out and
# make every subsequent authenticated request redirect back to the login page.
RE_SKIP_LINK = re.compile(r"logout|signout|sign-out|log-out|logoff", re.IGNORECASE)
# Match the whole <form ...>...</form> element (including the opening-tag
# attributes) so action/method can be read from it.
RE_FORM = re.compile(r"<form\b[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)
RE_FORM_ACTION = re.compile(r"action=[\"']([^\"']*)[\"']", re.IGNORECASE)
RE_FORM_METHOD = re.compile(r"method=[\"']([^\"']*)[\"']", re.IGNORECASE)
RE_INPUT = re.compile(r"<(?:input|select|textarea)\b[^>]*>", re.IGNORECASE)
RE_INPUT_NAME = re.compile(r"name=[\"']([^\"']+)[\"']", re.IGNORECASE)
RE_INPUT_TYPE = re.compile(r"type=[\"']([^\"']+)[\"']", re.IGNORECASE)
RE_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

DOWNLOAD_EXTS = (
    ".pdf",
    ".csv",
    ".xls",
    ".xlsx",
    ".doc",
    ".docx",
    ".zip",
    ".gz",
    ".tar",
    ".json",
    ".xml",
    ".txt",
    ".sql",
    ".bak",
    ".png",
    ".jpg",
    ".svg",
)
API_HINTS = ("/api", "/graphql", "/rest", "/v1/", "/v2/", "/v3/", ".json")
ACCESSIBLE_STATUSES = {200, 201, 202, 203, 204, 206}


class AuthCrawlerModule(BaseModule):
    name = "auth_crawler"
    category = "auth"

    async def run(self, ctx: ScanContext) -> ModuleResult:
        # Roles to crawl: every configured user plus an anonymous baseline.
        roles: list[UserCredential | None] = [*ctx.users, None]
        max_pages = int(ctx.options.get("max_pages", 60))
        max_depth = int(ctx.options.get("max_depth", 2))

        all_endpoints: list[CrawlEndpoint] = []
        all_forms: list[DiscoveredForm] = []

        for user in roles:
            role = user.role if user else "anonymous"
            endpoints, forms = await self._crawl_as(ctx, user, role, max_pages, max_depth)
            all_endpoints.extend(endpoints)
            all_forms.extend(forms)
            self.log.info("crawl.role_done", role=role, pages=len(endpoints), forms=len(forms))

        return ModuleResult(
            module=self.name,
            data={
                "endpoints": [e.model_dump() for e in all_endpoints],
                "forms": [f.model_dump() for f in all_forms],
            },
            items=len(all_endpoints),
        )

    async def _crawl_as(
        self,
        ctx: ScanContext,
        user: UserCredential | None,
        role: str,
        max_pages: int,
        max_depth: int,
    ) -> tuple[list[CrawlEndpoint], list[DiscoveredForm]]:
        base = ctx.target.url
        host = ctx.target.host

        # Resolve the role's session (cookies + headers) via the AuthManager:
        # jwt / cookie / session-file / har all map to concrete request material.
        headers = {"User-Agent": ctx.user_agent}
        cookies: dict[str, str] = {}
        strategy = "none"
        if user is not None:
            from modules.auth.auth_manager import AuthManager

            resolved = AuthManager().resolve(user)
            headers.update(resolved.headers)
            cookies.update(resolved.cookies)
            strategy = user.strategy

        async with httpx.AsyncClient(
            headers=headers,
            cookies=cookies,
            timeout=ctx.timeout,
            verify=ctx.verify_tls,
            follow_redirects=True,
        ) as client:
            seeds = [base]
            # Extra authenticated entry points (e.g. /Home/Index, /dashboard) — useful
            # when the base URL is the login page and session/jwt/cookie modes have no
            # post-login redirect to follow.
            for p in ctx.options.get("crawl_paths", []) or []:
                seeds.append(urljoin(base + "/", str(p).lstrip("/")))

            # Only the "login" strategy needs an interactive form-login POST; all
            # other strategies arrive pre-authenticated via resolved cookies/headers.
            if user is not None and strategy == "login":
                landing = await self._login(client, ctx, user)
                # Seed the crawl from the post-login landing page too (the base URL
                # is often the login page itself and reveals no authed surface).
                if landing and landing.split("#")[0].rstrip("/") != base.rstrip("/"):
                    seeds.append(landing)

            return await self._bfs(client, seeds, host, role, max_pages, max_depth)

    async def _login(
        self, client: httpx.AsyncClient, ctx: ScanContext, user: UserCredential
    ) -> str | None:
        """Perform a configured/auto-detected form login. Returns the landing URL."""
        if not (user.username and user.password):
            return None

        cfg = user.login or LoginConfig()
        login_url = urljoin(ctx.target.url + "/", cfg.url) if cfg.url else None
        u_field, p_field = cfg.username_field, cfg.password_field

        # Auto-detect the login form from the base page when not fully specified.
        if not (login_url and u_field and p_field):
            try:
                page = await client.get(ctx.target.url)
                detected = self._detect_login_form(ctx.target.url, page.text or "")
            except httpx.HTTPError as exc:
                self.log.warning("crawl.login_detect_failed", role=user.role, error=str(exc))
                detected = None
            if detected:
                login_url = login_url or detected[0]
                u_field = u_field or detected[1]
                p_field = p_field or detected[2]

        if not (login_url and u_field and p_field):
            self.log.warning("crawl.login_unresolved", role=user.role)
            return None

        data = {u_field: user.username, p_field: user.password, **cfg.extra_fields}
        try:
            resp = await client.post(login_url, data=data)
        except httpx.HTTPError as exc:
            self.log.warning("crawl.login_failed", role=user.role, error=str(exc))
            return None

        ok = True
        if cfg.success_status is not None:
            ok = resp.status_code == cfg.success_status
        if cfg.success_contains:
            ok = ok and cfg.success_contains in (resp.text or "")
        self.log.info("crawl.login", role=user.role, url=login_url, status=resp.status_code, ok=ok)
        # The final URL (after redirects) is the post-login landing page.
        return str(resp.url) if ok else None

    def _detect_login_form(self, page_url: str, html: str) -> tuple[str, str, str] | None:
        """Find the first form with a password input; return (action, user, pass)."""
        for form_html in RE_FORM.findall(html):
            inputs = self._parse_inputs(form_html)
            pw = next((f.name for f in inputs if f.type.lower() == "password"), None)
            if not pw:
                continue
            user_field = next(
                (
                    f.name
                    for f in inputs
                    if f.type.lower() in {"text", "email"}
                    or re.search(r"user|email|login", f.name, re.IGNORECASE)
                ),
                None,
            )
            action_m = RE_FORM_ACTION.search(form_html)
            action = action_m.group(1) if action_m else page_url
            return (
                urljoin(page_url + "/", action) if action else page_url,
                user_field or "username",
                pw,
            )
        return None

    async def _bfs(
        self,
        client: httpx.AsyncClient,
        seeds: list[str],
        host: str,
        role: str,
        max_pages: int,
        max_depth: int,
    ) -> tuple[list[CrawlEndpoint], list[DiscoveredForm]]:
        seen: set[str] = set()
        endpoints: list[CrawlEndpoint] = []
        forms: list[DiscoveredForm] = []
        queue: list[tuple[str, int]] = [(s, 0) for s in seeds]

        while queue and len(seen) < max_pages:
            url, depth = queue.pop(0)
            norm = url.split("#")[0].rstrip("/")
            if norm in seen:
                continue
            seen.add(norm)

            try:
                resp = await client.get(url)
            except httpx.HTTPError as exc:
                self.log.debug("crawl.get_failed", url=url, error=str(exc))
                continue

            ctype = resp.headers.get("content-type", "")
            path = urlparse(str(resp.url)).path or "/"
            body = resp.text or "" if "html" in ctype else ""
            title_m = RE_TITLE.search(body) if body else None

            # httpx follows redirects transparently; recover the hidden hop chain
            # (requested URL → … → final URL) from resp.history.
            redirect_chain: list[str] = []
            if resp.history:
                redirect_chain = [redact_url(str(h.url)) for h in resp.history]
                redirect_chain.append(redact_url(str(resp.url)))

            endpoints.append(
                CrawlEndpoint(
                    role=role,
                    url=str(resp.url),
                    path=path,
                    method="GET",
                    status_code=resp.status_code,
                    content_type=ctype.split(";")[0] or None,
                    source=self._classify(path, ctype),
                    title=(title_m.group(1).strip()[:200] if title_m else None),
                    redirect_chain=redirect_chain,
                )
            )

            if not body or depth >= max_depth:
                continue

            # Discover forms on this page (described, never submitted).
            for form_html in RE_FORM.findall(body):
                action_m = RE_FORM_ACTION.search(form_html)
                method_m = RE_FORM_METHOD.search(form_html)
                action = action_m.group(1) if action_m else path
                forms.append(
                    DiscoveredForm(
                        role=role,
                        page_url=str(resp.url),
                        action=urljoin(str(resp.url) + "/", action) if action else str(resp.url),
                        method=(method_m.group(1).upper() if method_m else "GET"),
                        fields=self._parse_inputs(form_html),
                    )
                )

            # Enqueue same-host links, skipping session-destroying ones (logout).
            for href in RE_HREF.findall(body):
                if RE_SKIP_LINK.search(href):
                    continue
                nxt = urljoin(str(resp.url), href)
                if urlparse(nxt).hostname == host and nxt.split("#")[0].rstrip("/") not in seen:
                    queue.append((nxt, depth + 1))

        return endpoints, forms

    @staticmethod
    def _classify(path: str, content_type: str) -> str:
        lower = path.lower()
        if any(h in lower for h in API_HINTS) or "json" in content_type:
            return "api"
        if lower.endswith(DOWNLOAD_EXTS):
            return "file"
        return "crawl"

    @staticmethod
    def _parse_inputs(form_html: str) -> list[FormField]:
        fields: list[FormField] = []
        for tag in RE_INPUT.findall(form_html):
            name_m = RE_INPUT_NAME.search(tag)
            if not name_m:
                continue
            type_m = RE_INPUT_TYPE.search(tag)
            fields.append(
                FormField(name=name_m.group(1), type=(type_m.group(1) if type_m else "text"))
            )
        return fields

    @staticmethod
    def _parse_cookie(raw: str) -> dict[str, str]:
        jar: dict[str, str] = {}
        for pair in raw.split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                jar[k.strip()] = v.strip()
        return jar
