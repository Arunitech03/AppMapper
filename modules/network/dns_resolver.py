"""Passive DNS resolution of already-discovered hosts (opt-in --dns).

Resolves a *fixed list of hosts that were already discovered* during the assessment —
it never brute-forces or enumerates unknown names (no wordlists, no Amass/Subfinder
behaviour). Discovery / passive intelligence only.
"""

from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.exception

from models.schemas import DnsRecord

_RECORD_TYPES = ("A", "AAAA", "CNAME", "TXT", "MX", "NS", "SOA")
_MAX_HOSTS = 60
_MAX_VALUES = 8  # per (host, type)


def _normalise(value, rtype: str) -> str:
    text = str(value).strip().strip('"')
    if rtype == "MX":  # "<pref> <exchange>" -> exchange
        return text.split()[-1].rstrip(".")
    if rtype in ("CNAME", "NS"):
        return text.rstrip(".")
    return text


async def resolve_hosts(
    hosts: list[str], *, timeout: float = 5.0, concurrency: int = 10
) -> list[DnsRecord]:
    """Resolve A/AAAA/CNAME/TXT/MX/NS/SOA for each discovered host (best-effort)."""
    unique = []
    seen = set()
    for h in hosts:
        h = (h or "").strip().lower().rstrip(".")
        if h and "." in h and h not in seen:
            seen.add(h)
            unique.append(h)
    unique = unique[:_MAX_HOSTS]
    if not unique:
        return []

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    sem = asyncio.Semaphore(concurrency)

    async def query(host: str, rtype: str) -> list[DnsRecord]:
        async with sem:
            try:
                answer = await resolver.resolve(host, rtype)
            except (dns.exception.DNSException, Exception):  # noqa: BLE001 - best-effort
                return []
            out: list[DnsRecord] = []
            for rdata in list(answer)[:_MAX_VALUES]:
                val = _normalise(rdata.to_text(), rtype)
                if val:
                    out.append(DnsRecord(host=host, record_type=rtype, value=val))
            return out

    tasks = [query(h, t) for h in unique for t in _RECORD_TYPES]
    results = await asyncio.gather(*tasks)
    return [rec for group in results for rec in group]
