"""Tests for the Authentication Token Inventory engine."""

from __future__ import annotations

from modules.intelligence.token_inventory import build_token_inventory


def _report():
    return {
        "auth_artifacts": [
            {
                "kind": "authorization",
                "name": "Authorization",
                "value_masked": "Bear…Zhng (4309 chars)",
            },
            {"kind": "local_storage", "name": "token", "value_masked": "eyJh…Zhng (4302 chars)"},
            {
                "kind": "cookie",
                "name": "KEYCLOAK_IDENTITY",
                "value_masked": "eyJh…7Zso (586 chars)",
            },
            {"kind": "cookie", "name": "AUTH_SESSION_ID", "value_masked": "7ec3…1-93 (52 chars)"},
            {"kind": "cookie", "name": "KEYCLOAK_SESSION", "value_masked": "qa_p…02f5 (84 chars)"},
            {"kind": "cookie", "name": "XSRF-TOKEN", "value_masked": "abcd…wxyz (36 chars)"},
            {"kind": "local_storage", "name": "x-api-key", "value_masked": "AIza…1234 (39 chars)"},
            {"kind": "session_storage", "name": "username", "value_masked": "********"},
            {"kind": "local_storage", "name": "theme", "value_masked": "****"},  # ignored
        ],
        "jwt_intelligence": {
            "primary": {
                "identity_provider": "Keycloak",
                "issuer": "https://auth-eu-test.example.com/auth/realms/demo_realm",
                "realm": "demo_realm",
                "client": "demo-floods",
                "applications": ["a", "b", "c", "d", "e"],
                "total_roles": 93,
                "token_lifetime": "3 Hours",
                "trusted_applications": 5,
                "administrative_roles": ["WW_ER_ADMIN"],
                "user": {"username": "testuser", "email": "d*****@x.com"},
            }
        },
        "auth_intelligence": {
            "authentication_model": {"model": "Hybrid"},
            "refresh_token": {"status": "Inferred", "basis": "offline_access", "storage": "—"},
            "authorization": {
                "applications": 5,
                "total_roles": 93,
                "administrative": 28,
                "security_sensitive": 39,
            },
            "storage": {"access_token": "localStorage"},
        },
        "domain_intelligence": {"third_party": [{"host": "api.mapbox.com"}]},
        "javascript_intelligence": {"service_inventory": []},
    }


def _by_type(ti):
    out = {}
    for t in ti["tokens"]:
        out.setdefault(t["type"], t)
    return out


def test_classification_and_decoded_and_risk():
    ti = build_token_inventory(_report())
    bt = _by_type(ti)
    assert bt["Access Token"]["decoded"] == "Yes" and bt["Access Token"]["risk"] == "High"
    assert (
        "JWT format" in bt["Identity Token"]["decoded"] and bt["Identity Token"]["risk"] == "Medium"
    )
    assert bt["Refresh Token"]["risk"] == "Medium"
    assert bt["Session Cookie"]["decoded"] == "N/A"
    assert bt["Anti-CSRF Token"]["risk"] == "Positive"
    assert bt["API Token"]["risk"] == "Informational"
    assert bt["Third-Party Token"]["name"] == "api.mapbox.com"
    # non-auth storage keys are skipped
    assert "theme" not in {t["name"] for t in ti["tokens"]}


def test_detail_cards():
    cards = {c["title"]: c for c in build_token_inventory(_report())["detail_cards"]}
    acc = cards["Access Token"]
    assert acc["realm"] == "demo_realm" and acc["client"] == "demo-floods"
    assert acc["roles"] == 93 and acc["lifetime"] == "3 Hours"
    assert "Identity Token" in cards and cards["Identity Token"]["contains"]
    assert cards["Refresh Token"]["observed"] == "Yes"


def test_correlation_and_graph_and_points():
    ti = build_token_inventory(_report())
    corr = ti["correlation"]
    assert corr["authentication_model"] == "Hybrid"
    assert "Access Token" in corr["observed_tokens"] and "Session Cookie" in corr["observed_tokens"]
    assert corr["identity_consistency"]["sources"]  # access token + session-storage username
    assert corr["authorization_summary"]["administrative"] == 28
    graph = "\n".join(ti["relationship_graph"])
    assert "Browser" in graph and "Access Token" in graph and "Keycloak" in graph
    points = " ".join(ti["developer_points"])
    assert "localStorage" in points and "Hybrid" in points
    assert "Session cookies and bearer tokens used simultaneously" in points


def test_pentest_value():
    pv = build_token_inventory(_report())["pentest_value"]
    assert "Authorization Testing" in pv["Access Token"]
    assert "CSRF Protection Validation" in pv["Anti-CSRF Token"]


def test_empty_report_yields_no_tokens():
    assert build_token_inventory({})["tokens"] == []
