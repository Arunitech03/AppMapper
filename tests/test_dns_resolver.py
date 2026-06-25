"""Tests for passive DNS resolution (resolves only discovered hosts)."""

from __future__ import annotations

import asyncio

import modules.network.dns_resolver as dns_resolver


class _FakeRdata:
    def __init__(self, text):
        self._t = text

    def to_text(self):
        return self._t


class _FakeResolver:
    lifetime = 5.0
    answers = {
        ("auth.example.com", "A"): ["20.1.2.3"],
        ("auth.example.com", "CNAME"): ["auth.azurefd.net."],
    }

    async def resolve(self, host, rtype):
        key = (host, rtype)
        if key in self.answers:
            return [_FakeRdata(v) for v in self.answers[key]]
        raise dns_resolver.dns.exception.DNSException("no record")


def test_resolve_only_given_hosts(monkeypatch):
    monkeypatch.setattr(dns_resolver.dns.asyncresolver, "Resolver", _FakeResolver)
    records = asyncio.run(dns_resolver.resolve_hosts(["auth.example.com", "auth.example.com"]))
    # de-duplicated host; A + CNAME resolved, CNAME trailing dot stripped, others empty
    kinds = {(r.host, r.record_type, r.value) for r in records}
    assert ("auth.example.com", "A", "20.1.2.3") in kinds
    assert ("auth.example.com", "CNAME", "auth.azurefd.net") in kinds
    assert all(r.host == "auth.example.com" for r in records)  # never resolves other names


def test_skips_non_hostnames(monkeypatch):
    monkeypatch.setattr(dns_resolver.dns.asyncresolver, "Resolver", _FakeResolver)
    assert asyncio.run(dns_resolver.resolve_hosts(["", "localhost", "no-dot"])) == []
