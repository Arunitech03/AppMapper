"""Tests for Phase-2 Authentication & Authorization Intelligence."""

from __future__ import annotations

from modules.intelligence.auth_intelligence import build_auth_intelligence
from modules.intelligence.jwt_intelligence import analyze_jwt
from tests.test_jwt_intelligence import PAYLOAD, _token


def _data(artifacts):
    primary = dict(analyze_jwt(_token(), role="test1"), origin="session")
    return {"jwt_authorization": [primary], "auth_artifacts": artifacts}, {"primary": primary}


HYBRID_ARTIFACTS = [
    {"kind": "cookie", "name": "KEYCLOAK_SESSION", "source": "exploration"},
    {"kind": "cookie", "name": "KEYCLOAK_IDENTITY", "source": "exploration"},
    {"kind": "authorization", "name": "Authorization", "source": "exploration"},
    {"kind": "local_storage", "name": "token", "source": "exploration"},
]


def test_hybrid_authentication_model():
    data, ji = _data(HYBRID_ARTIFACTS)
    ai = build_auth_intelligence(data, ji)
    model = ai["authentication_model"]
    assert model["model"] == "Hybrid"
    assert "Keycloak Session Cookies" in model["uses"]
    assert "JWT Bearer Tokens" in model["uses"]
    assert model["confidence"] == "High"


def test_storage_intelligence():
    data, ji = _data(HYBRID_ARTIFACTS)
    storage = build_auth_intelligence(data, ji)["storage"]
    assert storage["access_token"] == "localStorage"
    assert "KEYCLOAK_SESSION" in storage["session_cookie"]
    assert storage["authorization_header"] == "Observed"


def test_refresh_inferred_from_offline_access():
    data, ji = _data(HYBRID_ARTIFACTS)  # offline_access is in the example realm roles
    refresh = build_auth_intelligence(data, ji)["refresh_token"]
    assert refresh["status"] == "Inferred"
    assert "offline_access" in refresh["basis"]


def test_refresh_present_when_artifact_found():
    arts = HYBRID_ARTIFACTS + [{"kind": "local_storage", "name": "refresh_token", "source": "x"}]
    data, ji = _data(arts)
    refresh = build_auth_intelligence(data, ji)["refresh_token"]
    assert refresh["status"] == "Present"
    assert refresh["storage"] == "localStorage"


def test_risk_analysis_findings():
    data, ji = _data(HYBRID_ARTIFACTS)
    titles = [r["title"] for r in build_auth_intelligence(data, ji)["risk_analysis"]]
    assert any("localStorage" in t for t in titles)  # JWT in localStorage
    assert "Long-lived access token" in titles
    assert "Hybrid authentication model" in titles
    assert "Administrative privileges" in titles


def test_application_ranking_and_priorities():
    data, ji = _data(HYBRID_ARTIFACTS)
    ai = build_auth_intelligence(data, ji)
    ranking = ai["application_ranking"]
    # floods has the most admin roles -> ranked first.
    assert ranking[0]["application"] == "demo-floods"
    prios = {p["application"]: p for p in ai["pentest_priorities"]}
    assert "demo-floods" in prios
    assert "Vertical Privilege Escalation" in prios["demo-floods"]["tests"]
    # CONFIG admin roles add Configuration Tampering.
    assert "Configuration Tampering" in prios["demo-mam"]["tests"]


def test_authorization_totals_and_exec_summary():
    data, ji = _data(HYBRID_ARTIFACTS)
    ai = build_auth_intelligence(data, ji)
    az = ai["authorization"]
    assert az["applications"] == 5
    assert az["total_roles"] == 15  # sanitized token
    assert az["administrative"] == 8
    es = ai["exec_summary"]
    assert es["user"] == "testuser"
    assert es["authentication_model"] == "Hybrid"
    assert es["highest_risk_application"] == "demo-floods"
    assert es["realm"] == "demo_realm"


def test_auth_cards_and_artifacts_summary():
    data, ji = _data(HYBRID_ARTIFACTS)
    ai = build_auth_intelligence(data, ji)
    cards = ai["auth_cards"]
    assert cards["authentication_type"] == "Hybrid"
    assert cards["bearer_tokens"] >= 1 and cards["trusted_apps"] == 5
    summ = ai["artifacts_summary"]
    assert summ["authentication_model"] == "Hybrid"
    assert summ["token_storage"] == "localStorage"
    assert any("KEYCLOAK" in c for c in summ["session_cookies"])


def test_role_intelligence_and_flow():
    data, ji = _data(HYBRID_ARTIFACTS)
    ai = build_auth_intelligence(
        data, ji, service_inventory=[{"service": "floods-service", "host": "gw", "observed": True}]
    )
    ri = ai["role_intelligence"]
    # admin grouped by application + 6-test suggestions per app
    assert ri["admin_by_app"][0]["application"] == "demo-floods"
    assert "Role Manipulation" in ri["test_suggestions"][0]["tests"]
    # per-app breakdown carries write/read
    assert "write_roles" in ri["application_breakdown"][0]
    flow = ai["auth_flow"]
    assert any(b["label"] == "Cookies" for b in flow["browser"])
    assert flow["internal_apis"] == 1
    # service-aware discussion points
    points = " ".join(ai["discussion_points"])
    assert "internal services exposed" in points and "Email verification disabled" in points


def test_no_jwt_returns_empty_exec_summary():
    ai = build_auth_intelligence({"auth_artifacts": []}, {"primary": {}})
    assert ai["present"] is False
    assert ai["exec_summary"] == {}


# Touch PAYLOAD import so linters keep the shared fixture reference meaningful.
assert "demo-floods" in PAYLOAD["resource_access"]
