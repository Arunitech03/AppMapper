"""Module 1: Subdomain discovery.

Passive enumeration via Certificate Transparency logs (crt.sh), followed by
optional DNS-resolution validation. Purely passive/observational — no brute
forcing of hostnames against the target.
"""

from __future__ import annotations

import asyncio

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


class SubdomainModule(BaseModule):
    name = "subdomains"
    category = "recon"

    async def run(self, ctx: ScanContext) -> ModuleResult:
        domain = ctx.target.domain
        if not domain:
            return ModuleResult(module=self.name, ok=False, error="no domain", data=[], items=0)

        names = await self._query_crtsh(ctx, domain)
        subdomains = await self._validate(ctx, sorted(names))

        return ModuleResult(
            module=self.name,
            data=[s.model_dump() for s in subdomains],
            items=len(subdomains),
        )

    async def _query_crtsh(self, ctx: ScanContext, domain: str) -> set[str]:
        """Fetch unique names from crt.sh certificate transparency records."""
        params = {"q": f"%.{domain}", "output": "json"}
        timeout = max(ctx.timeout, CRTSH_TIMEOUT)
        names: set[str] = set()
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
            return names

        for record in records:
            value = record.get("name_value", "")
            for line in value.splitlines():
                line = line.strip().lstrip("*.").lower()
                if line.endswith(domain) and "@" not in line:
                    names.add(line)
        names.discard(domain)
        self.log.info("subdomains.crtsh", domain=domain, found=len(names))
        return names

    async def _validate(self, ctx: ScanContext, names: list[str]) -> list[Subdomain]:
        """Resolve each candidate via DNS (A records); mark resolvable ones."""
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = ctx.timeout
        sem = asyncio.Semaphore(ctx.max_concurrency)

        async def resolve(name: str) -> Subdomain:
            async with sem:
                try:
                    answer = await resolver.resolve(name, "A")
                    ips = [r.address for r in answer]
                    return Subdomain(name=name, resolved=True, ip_addresses=ips)
                except (dns.exception.DNSException, Exception):  # noqa: BLE001
                    return Subdomain(name=name, resolved=False)

        return list(await asyncio.gather(*(resolve(n) for n in names)))
