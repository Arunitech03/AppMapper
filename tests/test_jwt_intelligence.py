"""Tests for JWT Authorization Intelligence (validated against the Keycloak example)."""

from __future__ import annotations

import base64
import json

from modules.intelligence.jwt_intelligence import (
    analyze_jwt,
    build_jwt_intelligence,
    harvest_jwt_summaries,
)

# Sanitized real-world Keycloak payload from the feature spec.
PAYLOAD = {
    "exp": 1782111337,
    "iat": 1782100537,
    "iss": "https://auth-eu-test.example.com/auth/realms/demo_realm",
    "aud": [
        "demo-portal",
        "demo-mam",
        "demo-pipe-planner",
        "demo-device-management",
        "account",
    ],
    "sub": "user-guid",
    "typ": "Bearer",
    "azp": "demo-floods",
    "realm_access": {"roles": ["offline_access", "uma_authorization"]},
    "resource_access": {
        "demo-floods": {
            "roles": [
                "WW_ER_ADMIN",
                "WW_ER_USER",
                "FL_USERS_ADMIN",
                "FL_FORECAST_ADMIN",
                "APP_FLOODS",
            ]
        },
        "demo-portal": {"roles": ["APP_PORTAL_ADMIN", "PORTAL_APPS_ADMIN"]},
        "demo-mam": {"roles": ["MAM_ADMIN_CONFIG", "MAM_USER_ANALYSIS"]},
        "demo-pipe-planner": {"roles": ["PIPEPLANNER_ADMIN", "PIPEPLANNER_VIEWER"]},
        "demo-device-management": {"roles": ["DM_ADMIN_CONFIG", "DM_USER_GENERAL"]},
    },
    "scope": "openid profile email demo",
    "email_verified": False,
    "user_name": "testuser",
    "preferred_username": "testuser",
    "name": "Test Mercer",
    "given_name": "Test",
    "family_name": "Mercer",
    "email": "user@example.com",
}
_SIG = "SIGNATURE_PART_NEVER_STORED"


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _token(payload=PAYLOAD) -> str:
    return f"{_b64({'alg': 'RS256', 'typ': 'JWT'})}.{_b64(payload)}.{_SIG}"


def test_analyze_keycloak_token():
    s = analyze_jwt(_token(), role="qa")
    assert s["identity_provider"] == "Keycloak"
    assert s["realm"] == "demo_realm"
    assert s["client"] == "demo-floods"
    assert s["authentication_type"] == "OIDC Bearer Token"
    assert s["token_lifetime"] == "3 Hours"  # 10800s
    assert s["token_lifetime_seconds"] == 10800
    assert s["trusted_applications"] == 5
    assert s["applications"] == [
        "demo-floods",
        "demo-portal",
        "demo-mam",
        "demo-pipe-planner",
        "demo-device-management",
    ]
    assert s["total_roles"] == 15  # 2 realm + 13 resource (sanitized token)
    assert s["scopes"] == ["openid", "profile", "email", "demo"]


def test_role_classification():
    s = analyze_jwt(_token())
    admin = set(s["administrative_roles"])
    assert {
        "WW_ER_ADMIN",
        "FL_USERS_ADMIN",
        "APP_PORTAL_ADMIN",
        "PIPEPLANNER_ADMIN",
        "DM_ADMIN_CONFIG",
    } <= admin
    # offline_access / uma_authorization are security-sensitive grants.
    assert "offline_access" in s["security_sensitive_roles"]
    # Read-only roles classified separately.
    assert "PIPEPLANNER_VIEWER" in s["read_roles"]


def test_risk_indicators():
    risks = analyze_jwt(_token())["risk_indicators"]
    assert "Long-lived access token" in risks
    assert "Multi-application trust" in risks
    assert "Administrative privileges detected" in risks


def test_pii_masking():
    user = analyze_jwt(_token())["user"]
    assert user["name"].startswith("Test M") and "*" in user["name"]
    assert "Mercer" not in user["name"]
    assert user["username"] == "testuser"  # username shown (authorization model)
    assert user["email"] == "u*****@example.com"  # per-segment mask, domain kept
    assert "user@example.com" not in json.dumps(user)


def test_harvest_from_har_and_burp():
    har = [{"headers": {"Authorization": f"Bearer {_token()}"}, "role": "qa"}]
    burp = [{"auth_tokens": [f"Bearer {_token()}"], "role": "admin"}]
    # HAR source
    s1 = harvest_jwt_summaries(har, [])
    assert len(s1) == 1 and s1[0]["realm"] == "demo_realm" and s1[0]["role"] == "qa"
    # Burp source
    s2 = harvest_jwt_summaries([], burp)
    assert len(s2) == 1 and s2[0]["client"] == "demo-floods"
    # Dedup across sources (same token)
    s3 = harvest_jwt_summaries(har, burp)
    assert len(s3) == 1


def test_build_picks_most_privileged_primary():
    low = dict(PAYLOAD, resource_access={"app": {"roles": ["VIEWER"]}}, realm_access={"roles": []})
    data = {
        "jwt_authorization": [
            analyze_jwt(_token(low), role="user"),
            analyze_jwt(_token(), role="qa"),
        ]
    }
    out = build_jwt_intelligence(data)
    assert out["count"] == 2
    assert out["primary"]["role"] == "qa"  # most total_roles


def test_build_merges_js_findings_and_intel_findings():
    # A JWT embedded in a JS file value is decoded on read.
    data_js = {"js_findings": [{"kind": "jwt", "value": f"token={_token()}", "source": "app.js"}]}
    out_js = build_jwt_intelligence(data_js)
    assert out_js["count"] == 1 and out_js["primary"]["realm"] == "demo_realm"

    # A summary persisted at exploration capture (intel_findings kind=jwt_authz).
    summary = analyze_jwt(_token(), role="test1")
    data_intel = {"intel_findings": [{"kind": "jwt_authz", "extra": summary}]}
    out_intel = build_jwt_intelligence(data_intel)
    assert out_intel["count"] == 1 and out_intel["primary"]["role"] == "test1"

    # Same token across sources is deduped to one.
    merged = build_jwt_intelligence(
        {
            "jwt_authorization": [summary],
            "intel_findings": [{"kind": "jwt_authz", "extra": summary}],
            "js_findings": [{"value": _token()}],
        }
    )
    assert merged["count"] == 1


def test_humanize_scales_to_days_and_years():
    long_token = dict(PAYLOAD, iat=1668777249, exp=1720617249)  # ~600 days
    s = analyze_jwt(_token(long_token))
    assert s["token_lifetime"].endswith("Years")  # not "14400 Hours"
    assert "Long-lived access token" in s["risk_indicators"]


def test_header_analysis():
    h = analyze_jwt(_token())["header"]
    assert h["alg"] == "RS256"
    assert h["signature_model"] == "Asymmetric Signing"
    assert h["kid_present"] is False  # example header has no kid
    h2 = analyze_jwt(
        f"{_b64({'alg': 'RS256', 'typ': 'JWT', 'kid': 'abc'})}.{_b64(PAYLOAD)}.{_SIG}"
    )["header"]
    assert h2["kid_present"] is True
    assert "Enabled" in h2["key_rotation"]


def test_application_access_breakdown():
    aa = {a["application"]: a for a in analyze_jwt(_token())["application_access"]}
    floods = aa["demo-floods"]
    assert floods["total_roles"] == 5
    # WW_ER_ADMIN, FL_USERS_ADMIN, FL_FORECAST_ADMIN all contain ADMIN.
    assert floods["admin_roles"] == 3
    assert floods["user_roles"] == 2
    assert "WW_ER_ADMIN" in floods["admin_role_names"]


def test_show_pii_unmasks():
    masked = analyze_jwt(_token())["user"]
    shown = analyze_jwt(_token(), show_pii=True)["user"]
    assert "*" in masked["name"] and masked["email"].endswith("@example.com")
    assert shown["name"] == "Test Mercer"
    assert shown["email"] == "user@example.com"
    # locale + email_verified surfaced
    assert "locale" in shown and "email_verified" in shown


def test_email_mask_per_segment():
    from modules.intelligence.jwt_intelligence import _mask_email

    assert _mask_email("test.user@example.com") == "t*****.u*****@example.com"
    assert _mask_email("user@example.com") == "u*****@example.com"


def test_report_remasks_persisted_unmasked_pii():
    # Simulate a summary persisted UNMASKED by a prior `scan --show-pii`.
    unmasked = dict(analyze_jwt(_token(), show_pii=True), origin="session")
    assert unmasked["user"]["email"] == "user@example.com"
    data = {"jwt_authorization": [unmasked]}
    # A report without show_pii must re-mask, preserving the default-masked invariant.
    masked = build_jwt_intelligence(data, show_pii=False)["primary"]
    assert "*" in masked["user"]["name"] and "*" in masked["user"]["email"]
    # With show_pii, the persisted value is shown as-is.
    shown = build_jwt_intelligence(data, show_pii=True)["primary"]
    assert shown["user"]["email"] == "user@example.com"


def test_deep_dive_fields():
    s = analyze_jwt(_token())
    assert s["issued_at"] and s["issued_at"].endswith("UTC")
    assert s["expires_at"] and s["expires_at"].endswith("UTC")
    assert s["lifetime_class"] == "Long"  # 3h is 60-180min
    assert s["audience_observation"] and "5 applications" in s["audience_observation"]
    # per-application write/read split present
    floods = next(a for a in s["application_access"] if a["application"] == "demo-floods")
    assert "write_roles" in floods and "read_roles" in floods


def test_lifetime_class_boundaries():
    from modules.intelligence.jwt_intelligence import _lifetime_class

    assert _lifetime_class(600) == "Short"  # <15m
    assert _lifetime_class(1800) == "Standard"  # 15-60m
    assert _lifetime_class(7200) == "Long"  # 60-180m
    assert _lifetime_class(36000) == "Very Long"  # >180m


def test_claims_inventory_masked_and_unmasked():
    masked = analyze_jwt(_token())["claims"]
    assert masked["email"] == "u*****@example.com"
    assert "*" in masked["name"]
    # roles/structure preserved
    assert "resource_access" in masked and "realm_access" in masked
    shown = analyze_jwt(_token(), show_pii=True)["claims"]
    assert shown["email"] == "user@example.com"


def test_no_secret_leak():
    s = analyze_jwt(_token())
    blob = json.dumps(s)
    assert _SIG not in blob
    assert _token() not in blob
    assert "user@example.com" not in blob


def test_non_jwt_returns_none():
    assert analyze_jwt("not-a-token") is None
    assert analyze_jwt("") is None
