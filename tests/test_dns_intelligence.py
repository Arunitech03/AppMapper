"""Tests for DNS Intelligence & Infrastructure Discovery."""

from __future__ import annotations

from modules.intelligence.dns_intelligence import build_dns_intelligence


def _report():
    return {
        "target": {"domain": "ww-rtwhatif-qa.example.com"},
        "domain_intelligence": {
            "base_host": "ww-rtwhatif-qa.example.com",
            "hosts": [
                {
                    "host": "ww-rtwhatif-qa.example.com",
                    "classification": "Primary Application",
                    "requests": 100,
                    "confidence": "high",
                },
                {
                    "host": "gateway-proxy-qa.example.com",
                    "classification": "API Gateway",
                    "requests": 50,
                    "confidence": "high",
                },
                {
                    "host": "api.mapbox.com",
                    "classification": "Third Party Service",
                    "requests": 10,
                    "confidence": "medium",
                },
            ],
            "auth_infra": {"identity_provider": "Keycloak", "hosts": ["auth-eu-test.example.com"]},
            "third_party": [{"host": "api.mapbox.com"}],
        },
        "jwt_intelligence": {
            "primary": {
                "identity_provider": "Keycloak",
                "realm": "demo_realm",
                "issuer": "https://auth-eu-test.example.com/auth/realms/demo_realm",
            }
        },
        "javascript_intelligence": {
            "service_inventory": [
                {
                    "service": "floods-service",
                    "host": "gateway-proxy-qa.example.com",
                    "observed": True,
                },
            ]
        },
    }


def test_host_inventory_and_purposes():
    dns = build_dns_intelligence(_report())
    by_host = {h["host"]: h for h in dns["host_inventory"]}
    assert by_host["auth-eu-test.example.com"]["purpose"] == "Authentication"
    assert by_host["gateway-proxy-qa.example.com"]["purpose"] == "API Gateway"
    assert by_host["ww-rtwhatif-qa.example.com"]["purpose"] == "Application"


def test_auth_infra_and_gateways_and_deps():
    dns = build_dns_intelligence(_report())
    assert dns["auth_infrastructure"]["provider"] == "Keycloak"
    assert dns["auth_infrastructure"]["realm"] == "demo_realm"
    assert dns["gateways"] and dns["gateways"][0]["host"] == "gateway-proxy-qa.example.com"
    assert any(d["service"] == "Mapbox" for d in dns["external_dependencies"])


def test_relationship_and_pentest_and_points():
    dns = build_dns_intelligence(_report())
    graph = "\n".join(dns["relationship_map"])
    assert graph.startswith("ww-rtwhatif-qa.example.com")
    assert "auth-eu-test.example.com" in graph
    assert "Authentication" in dns["pentest_value"]
    pts = " ".join(dns["developer_points"])
    assert "API Gateway discovered" in pts


def test_cloud_and_dns_findings_with_records():
    data = {
        "dns_records": [
            {
                "host": "auth-eu-test.example.com",
                "record_type": "CNAME",
                "value": "auth.azurefd.net",
            },
            {"host": "example.com", "record_type": "TXT", "value": "v=spf1 include:_spf.x ~all"},
            {
                "host": "old.example.com",
                "record_type": "CNAME",
                "value": "deleted.azurewebsites.net",
            },
        ]
    }
    dns = build_dns_intelligence(_report(), data)
    assert dns["cloud_provider"]["provider"] == "Microsoft Azure"
    assert dns["cloud_provider"]["confidence"] == "High"
    titles = [f["finding"] for f in dns["dns_security_findings"]]
    assert any("dangling" in t.lower() for t in titles)
    posture = next(f for f in dns["dns_security_findings"] if "Email" in f["finding"])
    assert "DMARC: Missing" in posture["detail"] and posture["severity"] == "Medium"
    assert dns["summary"]["cloud_providers"] == "Microsoft Azure"


def test_empty_report_safe():
    dns = build_dns_intelligence({})
    assert dns["host_inventory"] == [] and dns["dns_security_findings"] == []
