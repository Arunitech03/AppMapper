"""Tests for the Passive Subdomain Intelligence builder."""

from __future__ import annotations

from modules.intelligence.subdomain_intelligence import build_subdomain_intelligence


def _report():
    return {
        "target": {"domain": "example.com"},
        "domain_intelligence": {
            "base_host": "example.com",
            "hosts": [
                {
                    "host": "gateway-proxy.example.com",
                    "classification": "API Gateway",
                    "requests": 5,
                },
                {
                    "host": "internal-svc.example.com",
                    "classification": "Internal API",
                    "requests": 3,
                },
            ],
            "auth_infra": {"hosts": ["auth.example.com"]},
        },
        "jwt_intelligence": {"primary": {"issuer": "https://auth.example.com/auth/realms/demo"}},
        "javascript_intelligence": {"service_inventory": []},
    }


def _data():
    return {
        "subdomains": [
            {"name": "api.example.com", "resolved": True, "source": "AlienVault OTX, crt.sh"},
            {"name": "dev.example.com", "resolved": False, "source": "RapidDNS"},
            {"name": "stage.example.com", "resolved": False, "source": "AlienVault OTX, RapidDNS"},
            {"name": "cdn.example.com", "resolved": False, "source": "crt.sh"},
        ],
        "dns_records": [
            {"host": "cdn.example.com", "record_type": "CNAME", "value": "edge.fastly.net"}
        ],
    }


def _by_host(si):
    return {h["host"]: h for h in si["hosts"]}


def test_merge_and_source_attribution():
    si = build_subdomain_intelligence(_report(), _data())
    by = _by_host(si)
    assert by["api.example.com"]["source"] == "AlienVault OTX, crt.sh"
    # runtime hosts merged in alongside passive ones
    assert "gateway-proxy.example.com" in by and "auth.example.com" in by


def test_confidence_rules():
    by = _by_host(build_subdomain_intelligence(_report(), _data()))
    assert by["api.example.com"]["confidence"] == "High"  # resolved
    assert by["stage.example.com"]["confidence"] == "Medium"  # 2 sources, unresolved
    assert by["dev.example.com"]["confidence"] == "Low"  # 1 source, unresolved
    assert by["gateway-proxy.example.com"]["confidence"] == "High"  # observed in HAR


def test_purpose_and_per_host_cloud():
    by = _by_host(build_subdomain_intelligence(_report(), _data()))
    assert by["gateway-proxy.example.com"]["purpose"] == "API Gateway"
    assert by["auth.example.com"]["purpose"] == "Authentication"
    assert by["internal-svc.example.com"]["purpose"] == "Internal Service"
    assert by["cdn.example.com"]["provider"] == "Fastly"  # from the CNAME record


def test_summary_and_sources_queried():
    si = build_subdomain_intelligence(_report(), _data())
    s = si["summary"]
    assert s["subdomains_found"] == 4  # passive hosts only
    assert s["resolved_hosts"] == 1
    assert s["authentication_hosts"] >= 1 and s["gateway_hosts"] >= 1
    assert s["internal_services"] >= 1
    assert set(si["sources_queried"]) == {"AlienVault OTX", "RapidDNS", "crt.sh"}


def test_crtsh_fallback_developer_point():
    # All passive hits came from non-crt.sh providers -> fallback inference fires.
    data = {
        "subdomains": [{"name": "x.example.com", "resolved": False, "source": "AlienVault OTX"}]
    }
    pts = " ".join(build_subdomain_intelligence(_report(), data)["developer_points"])
    assert "crt.sh returned no results" in pts
    assert "Authentication infrastructure identified" in pts


def test_empty_report_safe():
    si = build_subdomain_intelligence({})
    assert si["hosts"] == [] and si["summary"]["subdomains_found"] == 0
