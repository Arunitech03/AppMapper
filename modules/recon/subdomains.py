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
        names: set[str] = set()
        async with client_for(ctx) as client:
            try:
                resp = await client.get(CRTSH_URL, params=params)
                resp.raise_for_status()
                records = resp.json()
            except (httpx.HTTPError, ValueError) as exc:
                self.log.warning("subdomains.crtsh_failed", error=str(exc))
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
