"""Tests for Browser Storage Deep Intelligence (Sprint B6 / B6.1)."""

from __future__ import annotations

import base64
import json

from modules.intelligence.storage_intelligence import (
    analyze_storage_value,
    build_storage_intelligence,
)


def _b64(o) -> str:
    return base64.b64encode(json.dumps(o).encode()).decode()


def _storage_finding(kind, key, value, role="user"):
    """A storage_intel intel-finding as the import layer would persist it."""
    rec = analyze_storage_value(kind, key, value, role=role)
    return {"kind": "storage_intel", "name": f"{rec['storage']}: {key}", "extra": rec}


# --- the shared analyzer (analyze-before-mask unit) -------------------------


def test_analyze_base64_json_identity():
    rec = analyze_storage_value(
        "local_storage",
        "currentUser",
        _b64({"username": "admin", "email": "jane.doe@corp.com", "tenant": "acme"}),
    )
    assert rec["detected_type"] == "Base64" and rec["decoded_type"] == "JSON"
    assert rec["category"] == "Identity"
    assert set(rec["contains"]) >= {"username", "email", "tenant"}
    assert rec["identity"]["username"] == "admin" and rec["identity"]["tenant"] == "acme"
    # email masked in the extracted identity
    assert "@corp.com" in rec["identity"]["email"] and "jane.doe" not in rec["identity"]["email"]


def test_analyze_jwt_value():
    from tests.test_value_decoder import _jwt

    tok = _jwt(
        {
            "iss": "https://auth/realms/demo",
            "preferred_username": "bob",
            "realm_access": {"roles": ["ADMIN"]},
        }
    )
    rec = analyze_storage_value("cookie", "KEYCLOAK_IDENTITY", tok)
    assert rec["decoded_type"] == "JWT" and rec["category"] == "Authentication"
    assert "issuer" in rec["contains"] and "username" in rec["contains"]
    assert tok not in json.dumps(rec)  # raw token never present


def test_analyze_authorization_object():
    rec = analyze_storage_value("local_storage", "acl", _b64({"roles": ["Admin", "Auditor"]}))
    assert rec["category"] == "Authorization"
    assert rec["authorization"]["roles"] == ["Admin", "Auditor"]


def test_analyze_app_state():
    rec = analyze_storage_value(
        "session_storage", "recentDevice", _b64({"deviceNumber": "359", "deviceType": "METER"})
    )
    assert rec["app_state"].get("current_device") == "359"


def test_analyze_masked_value_classified_only():
    rec = analyze_storage_value("local_storage", "access_token", "eyJh…z9Q (812 chars)")
    assert rec["detected_type"] == "Masked"
    assert rec["category"] == "Authentication" and rec["subtype"] == "Access Token"


# --- the report builder over storage_intel findings ------------------------


def _data() -> dict:
    return {
        "intel_findings": [
            _storage_finding(
                "local_storage",
                "currentUser",
                _b64({"username": "admin", "tenant": "acme", "roles": ["Admin"]}),
            ),
            _storage_finding(
                "session_storage",
                "recentDevice",
                _b64({"deviceNumber": "359", "deviceType": "METER"}),
            ),
            _storage_finding("session_storage", "apiUrl", "https://api.internal.example.com/v1"),
            _storage_finding("local_storage", "access_token", "eyJh…z9Q (812 chars)"),
        ]
    }


def _by_key(si):
    return {i["key"]: i for i in si["inventory"]}


def test_builder_inventory_has_contains_and_confidence():
    si = build_storage_intelligence({}, _data())
    row = _by_key(si)["currentUser"]
    assert row["detected_type"] == "Base64" and row["decoded_type"] == "JSON"
    assert "✓" not in row["contains"][0] and "username" in row["contains"]  # raw field names
    assert row["confidence"] == "high"
    assert si["summary"]["decoded_values"] >= 1


def test_builder_application_state_and_authorization():
    si = build_storage_intelligence({}, _data())
    assert si["application_state"].get("current_device") == "359"
    assert "Admin" in si["authorization_summary"].get("roles", [])
    assert si["summary"]["app_state_objects"] >= 1


def test_builder_configuration_summary():
    si = build_storage_intelligence({}, _data())
    assert any("api.internal" in u for u in si["configuration_summary"]["api_endpoints"])


def test_builder_cross_correlation():
    # username 'admin' also present in JWT intelligence -> a correlation link.
    report = {"jwt_intelligence": {"primary": {"user": {"username": "admin"}, "realm": "acme"}}}
    si = build_storage_intelligence(report, _data())
    joined = " ".join(si["correlations"])
    assert "admin" in joined and si["summary"]["correlated"] >= 1


def test_builder_no_raw_pii_leak():
    data = {
        "intel_findings": [
            _storage_finding("local_storage", "profile", _b64({"email": "jane.doe@corp.com"}))
        ]
    }
    assert "jane.doe@corp.com" not in json.dumps(build_storage_intelligence({}, data))


def test_builder_empty_safe():
    si = build_storage_intelligence({})
    assert si["inventory"] == [] and si["summary"]["total_items"] == 0
