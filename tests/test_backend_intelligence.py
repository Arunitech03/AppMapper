"""Tests for Backend Service Intelligence & per-service fingerprinting (B7 / B7.1)."""

from __future__ import annotations

import json

from modules.intelligence.backend_intelligence import build_backend_intelligence


def _multi_service_data():
    """Two services behind a gateway on different stacks + Keycloak auth.

    Service names must be hyphenated to match the tool's `service_of_path`. Each service
    is fingerprinted from its OWN (service-specific) path signals — device-service via
    Spring Actuator, alarm-service via the Django admin portal — so shared cookies never
    fan a single framework onto every service.
    """
    gw = "gateway.example.com"
    return {
        "auth_artifacts": [
            {"kind": "cookie", "name": "JSESSIONID", "value_masked": "a…"},
            {"kind": "cookie", "name": "csrftoken", "value_masked": "b…"},
        ],
        "idp_info": [{"identity_provider": "Keycloak"}],
        # Observed traffic → the service registry discovers both services on the gateway.
        "har_requests": [
            {
                "url": f"https://{gw}/device-service/api/v1/list",
                "response_content_type": "application/problem+json",
                "response_keys": "timestamp,status,error,path",
            },
            {
                "url": f"https://{gw}/alarm-service/api/v1/get",
                "response_content_type": "application/json",
            },
        ],
        "directories": [
            {
                "path": "/device-service/actuator",
                "url": f"https://{gw}/device-service/actuator",
                "status_code": 200,
                "category": "management",
            },
            {
                "path": "/device-service/v3/api-docs",
                "url": f"https://{gw}/device-service/v3/api-docs",
                "status_code": 200,
                "category": "api",
            },
            {
                "path": "/alarm-service/admin/login",
                "url": f"https://{gw}/alarm-service/admin/login",
                "status_code": 200,
                "category": "management",
            },
            {
                "path": "/alarm-service/swagger",
                "url": f"https://{gw}/alarm-service/swagger",
                "status_code": 200,
                "category": "api",
            },
        ],
    }


def _report():
    return {
        "target": {"url": "https://portal.example.com", "domain": "example.com"},
        "technology_stack": {"frontend": ["React"], "servers": ["Kestrel"]},
        "dns_intelligence": {
            "auth_infrastructure": {"provider": "Keycloak", "host": "id.example.com"}
        },
    }


def _svc(bi, name_contains):
    return next(s for s in bi["services"] if name_contains.lower() in s["service"].lower())


def test_per_service_independent_fingerprints():
    bi = build_backend_intelligence(_report(), _multi_service_data())
    device = _svc(bi, "device")
    alarm = _svc(bi, "alarm")
    # Each service fingerprinted independently from its OWN signals — no fan-out.
    assert device["framework"] == "Spring Boot"
    assert alarm["framework"] == "Django"
    assert device["framework"] != alarm["framework"]


def test_per_service_management_and_swagger():
    bi = build_backend_intelligence(_report(), _multi_service_data())
    device = _svc(bi, "device")
    assert any("/actuator" in m["endpoint"] for m in device["management_endpoints"])
    assert _svc(bi, "alarm")["swagger"] != "—"


def test_frontend_and_auth_nodes_present():
    bi = build_backend_intelligence(_report(), _multi_service_data())
    names = {s["service"] for s in bi["services"]}
    assert "Frontend" in names and "Authentication" in names
    frontend = next(s for s in bi["services"] if s["service"] == "Frontend")
    assert frontend["framework"] == "React"
    assert (
        next(s for s in bi["services"] if s["service"] == "Authentication")["framework"]
        == "Keycloak"
    )


def test_architecture_tree():
    bi = build_backend_intelligence(_report(), _multi_service_data())
    tree = "\n".join(bi["architecture"])
    assert "Frontend" in tree and "Authentication: Keycloak" in tree
    assert "Device Api" in tree or "device" in tree.lower()


def test_per_service_priority_findings_name_the_service():
    bi = build_backend_intelligence(_report(), _multi_service_data())
    p1 = [f for f in bi["priority_findings"] if f["priority"] == "P1"]
    areas = " ".join(f["area"] for f in p1)
    assert "Device" in areas and "Actuator" in areas


def test_findings_reach_pentest_matrix():
    from modules.intelligence.pentest_matrix import build_pentest_matrix

    report = _report()
    report["backend_intelligence"] = build_backend_intelligence(report, _multi_service_data())
    matrix = build_pentest_matrix(report)
    rows = [r for r in matrix["rows"] if r["section"] == "Backend Technology Intelligence"]
    assert rows and any(r["priority"] == "P1" and "Device" in r["area"] for r in rows)


def test_summary_counts():
    bi = build_backend_intelligence(_report(), _multi_service_data())
    s = bi["summary"]
    assert s["spring_services"] >= 1 and s["backend_services"] >= 2
    assert s["management_endpoints"] >= 1 and s["swagger_endpoints"] >= 1
    assert s["identity_provider"] == "Keycloak"


def test_single_backend_uses_shared_signals():
    # One service only → shared cookie (JSESSIONID) may name it (back-compat with B7).
    data = {
        "auth_artifacts": [{"kind": "cookie", "name": "JSESSIONID", "value_masked": "a…"}],
        "technologies": [
            {
                "name": "Spring Boot",
                "category": "backend",
                "evidence": "header:x-application-context",
            }
        ],
        "har_requests": [{"url": "https://app.example.com/svc/api/x"}],
    }
    bi = build_backend_intelligence({"target": {"url": "https://app.example.com"}}, data)
    assert any(s["framework"] == "Spring Boot" for s in bi["services"])


def test_empty_safe():
    bi = build_backend_intelligence({})
    assert bi["services"] == [] and bi["priority_findings"] == []


def test_no_raw_cookie_value_leak():
    bi = build_backend_intelligence(_report(), _multi_service_data())
    assert "a…" not in json.dumps(bi)
