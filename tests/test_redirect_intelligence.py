"""Tests for the Redirect Intelligence Engine."""

from __future__ import annotations

import json

from modules.intelligence.redirect_intelligence import build_redirect_intelligence

BASE = "ww-rtwhatif-qa.example.com"


def _data(har=None, burp=None, crawl=None):
    return {
        "target": {"url": f"https://{BASE}", "domain": BASE},
        "har_requests": har or [],
        "burp_requests": burp or [],
        "crawl_endpoints": crawl or [],
    }


def _keycloak_har():
    return [
        {
            "url": f"https://{BASE}/",
            "response_status": 302,
            "redirect_url": "https://auth-eu-test.example.com/auth",
            "role": "qa",
        },
        {
            "url": "https://auth-eu-test.example.com/auth",
            "response_status": 302,
            "redirect_url": "https://auth-eu-test.example.com/realms/demo_realm",
            "role": "qa",
        },
        {
            "url": "https://auth-eu-test.example.com/realms/demo_realm",
            "response_status": 200,
            "role": "qa",
        },
    ]


def test_keycloak_auth_chain():
    out = build_redirect_intelligence(_data(har=_keycloak_har()))
    assert out["summary"]["total_chains"] == 1
    c = out["chains"][0]
    assert c["purpose"] == "Keycloak Authentication"
    assert c["confidence"] == "High"
    assert c["is_auth"] is True
    # Chain reconstructed end-to-end, terminating at a Login Page descriptor.
    assert c["nodes"][0] == f"https://{BASE}/"
    assert c["nodes"][-1] == "Login Page"
    assert "/realms/demo_realm" in c["nodes"][-2]
    assert len(out["auth_redirect_flow"]) == 1


def test_flow_diagram_has_arrows():
    out = build_redirect_intelligence(_data(har=_keycloak_har()))
    rendered = "\n→ ".join(out["chains"][0]["nodes"])
    assert "→" in rendered
    assert out["flow_diagram"][0] == out["chains"][0]["nodes"]


def test_open_redirect_candidate_flagged():
    har = [
        {
            "url": f"https://{BASE}/login?next=https://evil.attacker.test/x",
            "response_status": 302,
            "redirect_url": "https://evil.attacker.test/x",
        }
    ]
    out = build_redirect_intelligence(_data(har=har))
    flags = out["flags"]
    assert len(flags["open_redirect_candidates"]) == 1
    cand = flags["open_redirect_candidates"][0]
    assert cand["parameters"] == ["next"]
    # evil.attacker.test is cross-domain + third party.
    assert any(t["target_host"] == "evil.attacker.test" for t in flags["third_party_redirects"])
    assert any(t["target_host"] == "evil.attacker.test" for t in flags["cross_domain_redirects"])


def test_same_org_is_related_app_not_third_party():
    har = [
        {
            "url": f"https://{BASE}/go",
            "response_status": 302,
            "redirect_url": "https://billing.example.com/portal",
        }
    ]
    out = build_redirect_intelligence(_data(har=har))
    c = out["chains"][0]
    assert c["purpose"] == "Related Application"
    assert out["flags"]["third_party_redirects"] == []
    # same registrable domain -> not cross-domain
    assert c["cross_domain"] is False


def test_crawl_redirect_chain_json_string():
    # The DB serializes redirect_chain as JSON text; the builder must parse it.
    crawl = [
        {
            "role": "qa",
            "url": "https://app.example.com/final",
            "redirect_chain": json.dumps(
                [
                    f"https://{BASE}/start",
                    "https://app.example.com/mid",
                    "https://app.example.com/final",
                ]
            ),
        }
    ]
    out = build_redirect_intelligence(_data(crawl=crawl))
    assert out["summary"]["total_redirects"] == 2  # two hops
    assert out["chains"][0]["nodes"][0] == f"https://{BASE}/start"


def test_external_redirect_summary():
    har = [
        {
            "url": f"https://{BASE}/a",
            "response_status": 302,
            "redirect_url": "https://cdn.fastly.net/x",
        },
        {
            "url": f"https://{BASE}/b",
            "response_status": 302,
            "redirect_url": "https://cdn.fastly.net/y",
        },
    ]
    out = build_redirect_intelligence(_data(har=har))
    ext = out["external_redirect_summary"]
    assert ext and ext[0]["host"] == "cdn.fastly.net"
    assert ext[0]["count"] == 2


def test_no_secret_leak():
    # A redirect URL carrying a token must never appear unmasked in the output.
    har = [
        {
            "url": f"https://{BASE}/cb?code=eyJhbGORIGSECRET",
            "response_status": 302,
            "redirect_url": "https://auth-eu-test.example.com/token?access_token=eyJhbGORIGSECRET",
        }
    ]
    out = build_redirect_intelligence(_data(har=har))
    blob = json.dumps(out)
    assert "eyJhbGORIGSECRET" not in blob
    assert "REDACTED" in blob
