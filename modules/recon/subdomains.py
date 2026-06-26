"""Module 1: Subdomain discovery.

Passive enumeration from multiple public intelligence sources — Certificate
Transparency (crt.sh), AlienVault OTX, BufferOver, RapidDNS, and (when an API key
is configured) SecurityTrails and VirusTotal — followed by DNS-resolution
validation. Results are merged with per-host source attribution.

Purely passive/observational: no brute forcing, wordlists, zone transfers, or
active enumeration against the target. Each source is best-effort and isolated —
one provider failing only logs a warning and never fails the scan.
"""

from __future__ import annotations

import asyncio
import re

import dns.asyncresolver
import dns.exception
import httpx

from core.base import BaseModule
from core.http import client_for
from models.schemas import ModuleResult, ScanContext, Subdomain

CRTSH_URL = "https://crt.sh/"
# crt.sh runs a heavy Certificate-Transparency DB query that routinely takes
# 10-60s on a cold cache and frequently returns 5xx. The global probe timeout
# (ctx.timeout, default 10s) is far too short, so floor it here and retry a
# couple of times with backoff before giving up.
CRTSH_TIMEOUT = 30.0
CRTSH_ATTEMPTS = 2
CRTSH_BACKOFF = 2.0
# Other providers get a single best-effort attempt; floor their timeout above the
# global probe timeout since some (OTX, RapidDNS) can be slow.
PROVIDER_TIMEOUT = 20.0

# Source key -> human display name. Order = default query order.
_SOURCES: tuple[tuple[str, str], ...] = (
    ("crtsh", "crt.sh"),
    ("alienvault", "AlienVault OTX"),
    ("bufferover", "BufferOver"),
    ("rapiddns", "RapidDNS"),
    ("securitytrails", "SecurityTrails"),
    ("virustotal", "VirusTotal"),
)
# Key-gated providers: query only when their ctx.options key is present.
_KEY_SOURCES = {"securitytrails": "securitytrails_key", "virustotal": "virustotal_key"}
_HOST_RE = re.compile(r"^[a-z0-9._-]+$")


class SubdomainModule(BaseModule):
    name = "subdomains"
    category = "recon"

    async def run(self, ctx: ScanContext) -> ModuleResult:
        domain = ctx.target.domain
        if not domain:
            return ModuleResult(module=self.name, ok=False, error="no domain", data=[], items=0)

        queries = {
            "crtsh": self._query_crtsh,
            "alienvault": self._query_otx,
            "bufferover": self._query_bufferover,
            "rapiddns": self._query_rapiddns,
            "securitytrails": self._query_securitytrails,
            "virustotal": self._query_virustotal,
        }
        selected = self._selected_sources(ctx)
        keys = [k for k, _ in _SOURCES if k in selected]
        results = await asyncio.gather(*(queries[k](ctx, domain) for k in keys))

        # host -> set of provider display names that found it (source attribution)
        display = dict(_SOURCES)
        host_sources: dict[str, set[str]] = {}
        for key, names in zip(keys, results, strict=True):
            for host in names:
                host_sources.setdefault(host, set()).add(display[key])

        subdomains = await self._validate(ctx, host_sources)
        self.log.info("subdomains.enumeration", domain=domain, sources=keys, found=len(subdomains))
        return ModuleResult(
            module=self.name,
            data=[s.model_dump() for s in subdomains],
            items=len(subdomains),
        )

    def _selected_sources(self, ctx: ScanContext) -> set[str]:
        """Resolve which sources to query: ``--subdomain-sources`` (default all)
        intersected with availability (key-gated providers need a configured key)."""
        valid = {k for k, _ in _SOURCES}
        requested = ctx.options.get("subdomain_sources")
        chosen = {s.strip().lower() for s in requested} & valid if requested else set(valid)
        for key, opt in _KEY_SOURCES.items():
            if key in chosen and not ctx.options.get(opt):
                chosen.discard(key)
        return chosen

    # -- normalization --------------------------------------------------------
    def _in_scope(self, raw: str, domain: str) -> str | None:
        host = (raw or "").strip().rstrip(".").lstrip("*.").lower()
        if not host or "@" in host or not _HOST_RE.match(host):
            return None
        if host == domain or not host.endswith("." + domain):
            return None
        return host

    def _collect(self, values, domain: str) -> set[str]:
        out: set[str] = set()
        for v in values:
            host = self._in_scope(v, domain)
            if host:
                out.add(host)
        return out

    # -- providers ------------------------------------------------------------
    async def _query_crtsh(self, ctx: ScanContext, domain: str) -> set[str]:
        """Certificate Transparency names from crt.sh (timeout floor + retry)."""
        params = {"q": f"%.{domain}", "output": "json"}
        timeout = max(ctx.timeout, CRTSH_TIMEOUT)
        records = None
        async with client_for(ctx) as client:
            for attempt in range(1, CRTSH_ATTEMPTS + 1):
                try:
                    resp = await client.get(CRTSH_URL, params=params, timeout=timeout)
                    resp.raise_for_status()
                    records = resp.json()
                    break
                except (httpx.HTTPError, ValueError) as exc:
                    # crt.sh timeouts can carry an empty message — log the type too.
                    self.log.warning(
                        "subdomains.crtsh_failed",
                        attempt=attempt,
                        attempts=CRTSH_ATTEMPTS,
                        error_type=type(exc).__name__,
                        error=str(exc) or repr(exc),
                    )
                    if attempt < CRTSH_ATTEMPTS:
                        await asyncio.sleep(CRTSH_BACKOFF * attempt)
        if records is None:
            return set()
        raw: list[str] = []
        for record in records:
            raw.extend(record.get("name_value", "").splitlines())
        return self._collect(raw, domain)

    async def _query_otx(self, ctx: ScanContext, domain: str) -> set[str]:
        """AlienVault OTX passive DNS."""
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        data = await self._get_json(ctx, "alienvault", url)
        if not isinstance(data, dict):
            return set()
        return self._collect((e.get("hostname", "") for e in data.get("passive_dns") or []), domain)

    async def _query_bufferover(self, ctx: ScanContext, domain: str) -> set[str]:
        """BufferOver passive DNS (best-effort; may require a key / return empty)."""
        url = f"https://dns.bufferover.run/dns?q=.{domain}"
        data = await self._get_json(ctx, "bufferover", url)
        if not isinstance(data, dict):
            return set()
        names: list[str] = []
        for key in ("FDNS_A", "RDNS"):
            for entry in data.get(key) or []:
                names.append(str(entry).split(",")[-1])  # entries look like "ip,host"
        return self._collect(names, domain)

    async def _query_rapiddns(self, ctx: ScanContext, domain: str) -> set[str]:
        """RapidDNS indexed subdomains (HTML table)."""
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        text = await self._get_text(ctx, "rapiddns", url)
        if not text:
            return set()
        found = re.findall(r"[a-z0-9.\-]+\." + re.escape(domain), text.lower())
        return self._collect(found, domain)

    async def _query_securitytrails(self, ctx: ScanContext, domain: str) -> set[str]:
        """SecurityTrails subdomains (key-gated)."""
        key = ctx.options.get("securitytrails_key")
        if not key:
            return set()
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        data = await self._get_json(ctx, "securitytrails", url, headers={"APIKEY": key})
        if not isinstance(data, dict):
            return set()
        return self._collect((f"{s}.{domain}" for s in data.get("subdomains") or []), domain)

    async def _query_virustotal(self, ctx: ScanContext, domain: str) -> set[str]:
        """VirusTotal subdomains relationship (key-gated)."""
        key = ctx.options.get("virustotal_key")
        if not key:
            return set()
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
        data = await self._get_json(ctx, "virustotal", url, headers={"x-apikey": key})
        if not isinstance(data, dict):
            return set()
        return self._collect((it.get("id", "") for it in data.get("data") or []), domain)

    # -- HTTP helpers ---------------------------------------------------------
    async def _get_json(self, ctx: ScanContext, source: str, url: str, *, headers=None):
        timeout = max(ctx.timeout, PROVIDER_TIMEOUT)
        try:
            async with client_for(ctx) as client:
                resp = await client.get(url, headers=headers, timeout=timeout)
                resp.raise_for_status()
                return resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            self.log.warning(
                f"subdomains.{source}_failed",
                error_type=type(exc).__name__,
                error=str(exc) or repr(exc),
            )
            return None

    async def _get_text(self, ctx: ScanContext, source: str, url: str) -> str | None:
        timeout = max(ctx.timeout, PROVIDER_TIMEOUT)
        try:
            async with client_for(ctx) as client:
                resp = await client.get(url, timeout=timeout)
                resp.raise_for_status()
                return resp.text
        except httpx.HTTPError as exc:
            self.log.warning(
                f"subdomains.{source}_failed",
                error_type=type(exc).__name__,
                error=str(exc) or repr(exc),
            )
            return None

    # -- validation -----------------------------------------------------------
    async def _validate(
        self, ctx: ScanContext, host_sources: dict[str, set[str]]
    ) -> list[Subdomain]:
        """Resolve each candidate via DNS (A records); attribute discovered sources."""
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = ctx.timeout
        sem = asyncio.Semaphore(ctx.max_concurrency)

        async def resolve(name: str, sources: set[str]) -> Subdomain:
            source = ", ".join(sorted(sources))
            async with sem:
                try:
                    answer = await resolver.resolve(name, "A")
                    ips = [r.address for r in answer]
                    return Subdomain(name=name, resolved=True, ip_addresses=ips, source=source)
                except (dns.exception.DNSException, Exception):  # noqa: BLE001
                    return Subdomain(name=name, resolved=False, source=source)

        tasks = [resolve(n, s) for n, s in sorted(host_sources.items())]
        return list(await asyncio.gather(*tasks))
