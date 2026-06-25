"""Module 5: JavaScript and frontend analysis.

Downloads the target page plus its referenced ``.js`` / ``.html`` assets and
extracts interesting strings: URLs, API endpoints, emails, JWTs, cloud
credential patterns (AWS/Azure/Google), and code comments. Read-only: it fetches
static assets and runs regexes over them.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

import httpx

from core.base import BaseModule
from core.http import client_for
from models.schemas import JSFinding, ModuleResult, ScanContext

# Extraction patterns.
RE_URL = re.compile(r"https?://[^\s\"'<>()]+", re.IGNORECASE)
RE_API = re.compile(r"[\"'`](/(?:api|v\d+|rest|graphql)/[A-Za-z0-9_\-./{}]*)[\"'`]")
RE_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
RE_JWT = re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")
RE_AWS = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
RE_AZURE = re.compile(r"DefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[^;]+")
RE_GOOGLE = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")
RE_COMMENT_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
RE_COMMENT_LINE = re.compile(r"(?<!:)//[^\n\r]{4,200}")
RE_SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)


def _dedupe(values: list[str], limit: int = 500) -> list[str]:
    seen: dict[str, None] = {}
    for v in values:
        v = v.strip()
        if v and v not in seen:
            seen[v] = None
        if len(seen) >= limit:
            break
    return list(seen)


class JSAnalysisModule(BaseModule):
    name = "js_analysis"
    category = "frontend"

    async def run(self, ctx: ScanContext) -> ModuleResult:
        async with client_for(ctx) as client:
            base_url = ctx.target.url
            try:
                page = await client.get(base_url)
            except httpx.HTTPError as exc:
                return ModuleResult(module=self.name, ok=False, error=str(exc), data={}, items=0)

            corpus: list[tuple[str, str]] = [(base_url, page.text or "")]

            # Discover and fetch referenced scripts (same registrable site only).
            script_urls = self._script_urls(base_url, page.text or "")
            corpus.extend(await self._fetch_assets(client, script_urls, ctx.max_concurrency))

        finding = self._extract(corpus)
        return ModuleResult(
            module=self.name, data=finding.model_dump(), items=finding_count(finding)
        )

    def _script_urls(self, base_url: str, html: str) -> list[str]:
        host = urlparse(base_url).hostname
        urls: list[str] = []
        for src in RE_SCRIPT_SRC.findall(html):
            absolute = urljoin(base_url + "/", src)
            if urlparse(absolute).hostname == host and absolute.lower().split("?")[0].endswith(
                (".js", ".html")
            ):
                urls.append(absolute)
        return _dedupe(urls, limit=50)

    async def _fetch_assets(
        self, client: httpx.AsyncClient, urls: list[str], concurrency: int
    ) -> list[tuple[str, str]]:
        sem = asyncio.Semaphore(concurrency)

        async def fetch(url: str) -> tuple[str, str] | None:
            async with sem:
                try:
                    resp = await client.get(url)
                    return (url, resp.text or "")
                except httpx.HTTPError:
                    return None

        results = await asyncio.gather(*(fetch(u) for u in urls))
        return [r for r in results if r is not None]

    def _extract(self, corpus: list[tuple[str, str]]) -> JSFinding:
        urls: list[str] = []
        api: list[str] = []
        emails: list[str] = []
        jwts: list[str] = []
        aws: list[str] = []
        azure: list[str] = []
        google: list[str] = []
        comments: list[str] = []
        sources: list[str] = []

        for src, text in corpus:
            if not text:
                continue
            sources.append(src)
            urls += RE_URL.findall(text)
            api += RE_API.findall(text)
            emails += RE_EMAIL.findall(text)
            jwts += RE_JWT.findall(text)
            aws += RE_AWS.findall(text)
            azure += RE_AZURE.findall(text)
            google += RE_GOOGLE.findall(text)
            comments += [c.strip() for c in RE_COMMENT_BLOCK.findall(text)]
            comments += [c.strip() for c in RE_COMMENT_LINE.findall(text)]

        interesting = _dedupe(jwts + aws + azure + google)
        return JSFinding(
            api_endpoints=_dedupe(api),
            emails=_dedupe(emails),
            urls=_dedupe(urls),
            jwts=_dedupe(jwts),
            aws_keys=_dedupe(aws),
            azure_keys=_dedupe(azure),
            google_api_keys=_dedupe(google),
            comments=_dedupe(comments, limit=200),
            interesting_strings=interesting,
            sources=_dedupe(sources, limit=100),
        )


def finding_count(f: JSFinding) -> int:
    return (
        len(f.api_endpoints)
        + len(f.emails)
        + len(f.urls)
        + len(f.jwts)
        + len(f.aws_keys)
        + len(f.azure_keys)
        + len(f.google_api_keys)
        + len(f.comments)
    )
