"""Tests for Backend Technology & Framework Intelligence (Sprint B7)."""

from __future__ import annotations

import json

from modules.intelligence.backend_intelligence import build_backend_intelligence


def _spring_report():
    return {
        "technology_stack": {"backend": ["Spring Boot"], "servers": ["Apache Tomcat"]},
        "dns_intelligence": {"auth_infrastructure": {"provider": "Keycloak"}},
        "auth_intelligence": {"authentication_model": {"model": "Hybrid"}},
    }


def _spring_data():
    return {
        "technologies": [
            {
                "name": "Spring Boot",
                "category": "backend",
                "evidence": "header:x-application-context",
            },
            {"name": "Apache Tomcat", "category": "server", "evidence": "header:Server"},
        ],
        "auth_artifacts": [{"kind": "cookie", "name": "JSESSIONID", "value_masked": "abc…"}],
        "directories": [
            {"path": "/actuator", "status_code": 200, "category": "management"},
            {"path": "/actuator/env", "status_code": 401, "category": "management"},
            {"path": "/v3/api-docs", "status_code": 200, "category": "api"},
        ],
        "har_requests": [
            {
                "response_content_type": "application/problem+json",
                "response_keys": "timestamp,status,error,path",
            }
        ],
        "api_endpoints": [],
        "idp_info": [{"identity_provider": "Keycloak"}],
    }


def test_spring_boot_primary_framework_high_confidence():
    bi = build_backend_intelligence(_spring_report(), _spring_data())
    assert bi["summary"]["primary_framework"] == "Spring Boot"
    assert bi["frameworks"][0]["confidence"] == "high"
    # multi-source evidence (never a single indicator)
    sources = {e["source"] for e in bi["frameworks"][0]["evidence"]}
    assert len(sources) >= 3


def test_application_server_and_auth_stack():
    bi = build_backend_intelligence(_spring_report(), _spring_data())
    assert bi["application_server"] == "Apache Tomcat"
    assert "Spring Security" in bi["authentication_stack"]
    assert bi["identity_provider"] == "Keycloak"


def test_management_endpoints_and_priority_findings():
    bi = build_backend_intelligence(_spring_report(), _spring_data())
    eps = {m["endpoint"] for m in bi["management_endpoints"]}
    assert "/actuator" in eps
    # sensitive actuator (/actuator/env) rated High
    assert any(m["risk"] == "High" for m in bi["management_endpoints"])
    p1 = [f for f in bi["priority_findings"] if f["priority"] == "P1"]
    titles = " ".join(f["area"] for f in p1)
    assert "Actuator" in titles and "API Documentation" in titles


def test_testing_recommendations_present():
    bi = build_backend_intelligence(_spring_report(), _spring_data())
    assert "Spring Boot" in bi["testing_recommendations"]
    assert any("Actuator" in r for r in bi["testing_recommendations"]["Spring Boot"])


def test_backend_findings_reach_pentest_matrix():
    from modules.intelligence.pentest_matrix import build_pentest_matrix

    report = _spring_report()
    report["backend_intelligence"] = build_backend_intelligence(report, _spring_data())
    matrix = build_pentest_matrix(report)
    backend_rows = [r for r in matrix["rows"] if r["section"] == "Backend Technology Intelligence"]
    assert backend_rows and any(r["priority"] == "P1" for r in backend_rows)


def test_django_from_cookies():
    report = {"technology_stack": {}}
    data = {
        "auth_artifacts": [
            {"kind": "cookie", "name": "csrftoken", "value_masked": "x"},
            {"kind": "cookie", "name": "sessionid", "value_masked": "y"},
        ],
        "technologies": [{"name": "Django", "category": "backend", "evidence": "cookie:csrftoken"}],
    }
    bi = build_backend_intelligence(report, data)
    assert bi["summary"]["primary_framework"] == "Django"


def test_aspnet_from_cookie_and_server():
    report = {"technology_stack": {"servers": ["Kestrel"]}}
    data = {
        "auth_artifacts": [
            {"kind": "cookie", "name": ".AspNetCore.Antiforgery.abc", "value_masked": "x"}
        ],
        "technologies": [{"name": "Kestrel", "category": "server", "evidence": "header:Server"}],
    }
    bi = build_backend_intelligence(report, data)
    assert bi["summary"]["primary_framework"] == "ASP.NET Core"
    assert bi["application_server"] == "Kestrel"


def test_empty_safe():
    bi = build_backend_intelligence({})
    assert bi["frameworks"] == [] and bi["summary"]["primary_framework"] == "Not identified"
    assert bi["priority_findings"] == []


def test_no_raw_cookie_value_leak():
    # The engine reads cookie NAMES only — cookie values never enter the output.
    bi = build_backend_intelligence(_spring_report(), _spring_data())
    assert "abc…" not in json.dumps(bi)
