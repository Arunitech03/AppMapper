"""Tests for Module 1: subdomain discovery (crt.sh + DNS validation)."""

from __future__ import annotations

import dns.exception
import httpx
import respx

from modules.recon.subdomains import CRTSH_URL, SubdomainModule


@respx.mock
async def test_subdomains_from_crtsh(ctx_factory, monkeypatch):
    respx.get(CRTSH_URL).mock(
        return_value=httpx.Response(
            200,
            json=[
                {"name_value": "api.example.com\nwww.example.com"},
                {"name_value": "*.example.com"},
                {"name_value": "dev.example.com"},
            ],
        )
    )

    async def fake_resolve(self, name, rdtype):  # noqa: ANN001
        raise dns.exception.DNSException("no network in tests")

    monkeypatch.setattr("dns.asyncresolver.Resolver.resolve", fake_resolve)

    ctx = ctx_factory(url="https://example.com", domain="example.com")
    result = await SubdomainModule().run(ctx)

    names = {d["name"] for d in result.data}
    assert {"api.example.com", "www.example.com", "dev.example.com"} <= names
    assert "example.com" not in names  # apex excluded
    assert all(d["resolved"] is False for d in result.data)


@respx.mock
async def test_subdomains_handles_crtsh_failure(ctx_factory):
    respx.get(CRTSH_URL).mock(return_value=httpx.Response(502))
    ctx = ctx_factory(url="https://example.com", domain="example.com")
    result = await SubdomainModule().run(ctx)
    assert result.ok
    assert result.items == 0
