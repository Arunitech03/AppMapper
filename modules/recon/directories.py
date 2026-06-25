"""Module 2: Directory enumeration.

Read-only discovery of common paths, admin locations and backup files using a
configurable wordlist plus a built-in high-signal list. Issues only GET requests
and records the response metadata — it never submits forms or payloads.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx

from core.base import BaseModule
from core.http import client_for
from models.schemas import DirectoryHit, ModuleResult, ScanContext

# Expected content-type per category for a *genuine* hit. A secret/backup path
# that returns HTML (the SPA shell) instead is almost certainly an SPA fallback,
# not an exposed file. Used to validate hits and assign confidence (Issue 3).
EXPECTED_CONTENT_TYPE: dict[str, tuple[str, ...]] = {
    "backup": ("application/", "text/plain", "text/x-sql", "application/sql", "application/zip"),
    "api": ("application/json", "application/yaml", "text/yaml", "application/xml"),
}
# Path suffix -> human-readable expected type (for the report).
EXPECTED_LABEL = {
    ".env": "text/plain",
    ".sql": "application/sql",
    ".zip": "application/zip",
    ".tar.gz": "application/gzip",
    ".bak": "application/octet-stream",
    "config": "text/plain",
}

# High-signal paths always checked, with a category for reporting.
BUILTIN_PATHS: dict[str, str] = {
    "admin": "admin",
    "administrator": "admin",
    "login": "common",
    "api": "api",
    "swagger": "api",
    "swagger/index.html": "api",
    "openapi": "api",
    "openapi.json": "api",
    "swagger.json": "api",
    "graphql": "api",
    "robots.txt": "common",
    "sitemap.xml": "common",
    ".git/config": "backup",
    ".env": "backup",
    "backup.zip": "backup",
    "backup.tar.gz": "backup",
    "db.sql": "backup",
    "web.config.bak": "backup",
}

# Status codes that indicate a path "exists" (including auth-gated resources).
PRESENT_STATUSES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405}


class DirectoryEnumModule(BaseModule):
    name = "directories"
    category = "recon"

    async def run(self, ctx: ScanContext) -> ModuleResult:
        paths = self._load_paths(ctx)
        base = ctx.target.url
        sem = asyncio.Semaphore(ctx.max_concurrency)
        hits: list[DirectoryHit] = []

        async with client_for(ctx, follow_redirects=False) as client:
            # Baseline: a path that should NOT exist. If the app returns 200 here
            # (SPA catch-all), any 200 with the same shape is a false positive.
            baseline = await self._baseline(client, base)

            async def probe(path: str, category: str) -> DirectoryHit | None:
                url = f"{base}/{path.lstrip('/')}"
                async with sem:
                    try:
                        resp = await client.get(url)
                    except httpx.HTTPError as exc:
                        self.log.debug("directories.error", url=url, error=str(exc))
                        return None
                if resp.status_code in PRESENT_STATUSES:
                    clen = resp.headers.get("content-length")
                    ctype = resp.headers.get("content-type")
                    length = int(clen) if clen and clen.isdigit() else len(resp.content)
                    hit = DirectoryHit(
                        path="/" + path.lstrip("/"),
                        url=url,
                        status_code=resp.status_code,
                        content_length=length,
                        content_type=ctype,
                        category=category,
                    )
                    self._validate(hit, baseline)
                    return hit
                return None

            results = await asyncio.gather(*(probe(p, c) for p, c in paths.items()))

        hits = [h for h in results if h is not None]
        hits.sort(key=lambda h: h.path)
        return ModuleResult(module=self.name, data=[h.model_dump() for h in hits], items=len(hits))

    async def _baseline(self, client, base: str) -> dict:
        """Fetch an almost-certainly-nonexistent path to fingerprint SPA fallback."""
        probe_url = f"{base}/appmapper-nonexistent-{'z' * 12}"
        try:
            resp = await client.get(probe_url)
            clen = resp.headers.get("content-length")
            return {
                "status": resp.status_code,
                "content_type": (resp.headers.get("content-type") or "").split(";")[0].strip(),
                "length": int(clen) if clen and clen.isdigit() else len(resp.content),
            }
        except httpx.HTTPError:
            return {}

    def _validate(self, hit: DirectoryHit, baseline: dict) -> None:
        """Assign confidence + validation to a hit (Issue 3).

        A sensitive (backup/api) path that returns HTML, or looks identical to the
        SPA-fallback baseline, is demoted to low confidence rather than reported as
        an exposed secret.
        """
        ctype = (hit.content_type or "").split(";")[0].strip().lower()
        low = hit.path.lower()
        hit.expected_content_type = next(
            (label for suffix, label in EXPECTED_LABEL.items() if low.endswith(suffix)), None
        )

        # Auth-gated / redirect responses are existence signals, not content leaks.
        if hit.status_code in {301, 302, 307, 308, 401, 403, 405}:
            hit.confidence = "medium"
            hit.validation = "exists (auth-gated/redirect)"
            return

        sensitive = hit.category in {"backup", "api"}
        looks_like_baseline = bool(baseline) and (
            baseline.get("status") == hit.status_code
            and baseline.get("content_type") == ctype
            and (baseline.get("length") == hit.content_length or ctype == "text/html")
        )

        if sensitive:
            expected = EXPECTED_CONTENT_TYPE.get(hit.category, ())
            type_ok = any(ctype.startswith(e) for e in expected)
            if looks_like_baseline or ctype == "text/html" or not type_ok:
                hit.confidence = "low"
                hit.validation = "SPA fallback suspected"
            else:
                hit.confidence = "high"
                hit.validation = "verified content-type"
        else:
            hit.confidence = "low" if looks_like_baseline else "medium"
            hit.validation = "SPA fallback suspected" if looks_like_baseline else "exists"

    def _load_paths(self, ctx: ScanContext) -> dict[str, str]:
        """Combine the built-in list with an optional wordlist and extra paths.

        ``ctx.options['extra_paths']`` lets the orchestrator inject paths observed
        in capture files so every role is probed against the same universe.
        """
        paths = dict(BUILTIN_PATHS)
        if ctx.wordlist_path:
            wl = Path(ctx.wordlist_path)
            if wl.exists():
                for line in wl.read_text(encoding="utf-8", errors="ignore").splitlines():
                    word = line.strip()
                    if word and not word.startswith("#"):
                        paths.setdefault(word, "common")
            else:
                self.log.warning("directories.wordlist_missing", path=str(wl))
        for extra in ctx.options.get("extra_paths", []) or []:
            paths.setdefault(str(extra).lstrip("/"), "capture")
        return paths
