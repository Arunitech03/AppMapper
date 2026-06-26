"""Tests for Module 1: multi-source passive subdomain discovery + DNS validation."""

from __future__ import annotations

import dns.exception
import httpx
import respx

from modules.recon.subdomains import CRTSH_URL, SubdomainModule

OTX_URL = "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns"
RAPIDDNS_URL = "https://rapiddns.io/subdomain/example.com"
ST_URL = "https://api.securitytrails.com/v1/domain/example.com/subdomains"


def _no_dns(monkeypatch):
    async def fake_resolve(self, name, rdtype):  # noqa: ANN001
        raise dns.exception.DNSException("no network in tests")

    monkeypatch.setattr("dns.asyncresolver.Resolver.resolve", fake_resolve)


def _crtsh_only(ctx_factory, **opts):
    return ctx_factory(
        url="https://example.com",
        domain="example.com",
        options={"subdomain_sources": ["crtsh"], **opts},
    )


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
    _no_dns(monkeypatch)

    result = await SubdomainModule().run(_crtsh_only(ctx_factory))

    names = {d["name"] for d in result.data}
    assert {"api.example.com", "www.example.com", "dev.example.com"} <= names
    assert "example.com" not in names  # apex excluded
    assert all(d["resolved"] is False for d in result.data)
    assert all(d["source"] == "crt.sh" for d in result.data)


@respx.mock
async def test_subdomains_handles_crtsh_failure(ctx_factory, monkeypatch):
    monkeypatch.setattr("modules.recon.subdomains.CRTSH_BACKOFF", 0)  # no real sleep in tests
    route = respx.get(CRTSH_URL).mock(return_value=httpx.Response(502))
    result = await SubdomainModule().run(_crtsh_only(ctx_factory))
    assert result.ok
    assert result.items == 0
    assert route.call_count == 2  # retried before giving up (CRTSH_ATTEMPTS)


@respx.mock
async def test_subdomains_retries_then_succeeds(ctx_factory, monkeypatch):
    monkeypatch.setattr("modules.recon.subdomains.CRTSH_BACKOFF", 0)
    _no_dns(monkeypatch)
    # First crt.sh call fails (transient 502), retry returns the records.
    respx.get(CRTSH_URL).mock(
        side_effect=[
            httpx.Response(502),
            httpx.Response(200, json=[{"name_value": "api.example.com"}]),
        ]
    )
    result = await SubdomainModule().run(_crtsh_only(ctx_factory))
    assert {d["name"] for d in result.data} == {"api.example.com"}


@respx.mock
async def test_multi_source_merge_and_attribution(ctx_factory, monkeypatch):
    _no_dns(monkeypatch)
    respx.get(CRTSH_URL).mock(
        return_value=httpx.Response(200, json=[{"name_value": "api.example.com"}])
    )
    respx.get(OTX_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "passive_dns": [{"hostname": "api.example.com"}, {"hostname": "otx.example.com"}]
            },
        )
    )
    respx.get(RAPIDDNS_URL).mock(
        return_value=httpx.Response(200, text="<td>rapid.example.com</td>")
    )

    ctx = ctx_factory(
        url="https://example.com",
        domain="example.com",
        options={"subdomain_sources": ["crtsh", "alienvault", "rapiddns"]},
    )
    result = await SubdomainModule().run(ctx)

    by_name = {d["name"]: d for d in result.data}
    assert {"api.example.com", "otx.example.com", "rapid.example.com"} <= set(by_name)
    # api.example.com found by both crt.sh and OTX -> multi-source attribution
    assert by_name["api.example.com"]["source"] == "AlienVault OTX, crt.sh"
    assert by_name["otx.example.com"]["source"] == "AlienVault OTX"


@respx.mock
async def test_fallback_when_crtsh_fails(ctx_factory, monkeypatch):
    """crt.sh down must NOT zero out discovery — other providers still contribute."""
    monkeypatch.setattr("modules.recon.subdomains.CRTSH_BACKOFF", 0)
    _no_dns(monkeypatch)
    respx.get(CRTSH_URL).mock(return_value=httpx.Response(502))
    respx.get(OTX_URL).mock(
        return_value=httpx.Response(200, json={"passive_dns": [{"hostname": "otx.example.com"}]})
    )
    respx.get(RAPIDDNS_URL).mock(return_value=httpx.Response(200, text="rapid.example.com"))

    ctx = ctx_factory(
        url="https://example.com",
        domain="example.com",
        options={"subdomain_sources": ["crtsh", "alienvault", "rapiddns"]},
    )
    result = await SubdomainModule().run(ctx)
    assert result.ok  # scan never fails because one provider is down
    assert {"otx.example.com", "rapid.example.com"} <= {d["name"] for d in result.data}


@respx.mock
async def test_key_gated_providers_skipped_without_key(ctx_factory, monkeypatch):
    _no_dns(monkeypatch)
    # Only key-gated sources selected, but no keys configured -> nothing queried.
    ctx = ctx_factory(
        url="https://example.com",
        domain="example.com",
        options={"subdomain_sources": ["securitytrails", "virustotal"]},
    )
    result = await SubdomainModule().run(ctx)
    assert result.ok and result.items == 0


@respx.mock
async def test_securitytrails_with_key(ctx_factory, monkeypatch):
    _no_dns(monkeypatch)
    respx.get(ST_URL).mock(return_value=httpx.Response(200, json={"subdomains": ["api", "www"]}))
    ctx = ctx_factory(
        url="https://example.com",
        domain="example.com",
        options={"subdomain_sources": ["securitytrails"], "securitytrails_key": "k"},
    )
    result = await SubdomainModule().run(ctx)
    by_name = {d["name"]: d for d in result.data}
    assert set(by_name) == {"api.example.com", "www.example.com"}
    assert by_name["api.example.com"]["source"] == "SecurityTrails"
