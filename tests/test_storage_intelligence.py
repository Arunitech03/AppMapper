"""Tests for Browser Storage Intelligence (Sprint B6)."""

from __future__ import annotations

import base64
import json

from modules.intelligence.storage_intelligence import build_storage_intelligence


def _b64(o) -> str:
    return base64.b64encode(json.dumps(o).encode()).decode()


def _data() -> dict:
    return {
        "auth_artifacts": [
            # base64-encoded identity object (non-secret -> survives raw)
            {
                "kind": "local_storage",
                "name": "currentUser",
                "value_masked": _b64(
                    {"username": "admin", "email": "jane.doe@corp.com", "tenant": "acme"}
                ),
                "role": "user",
            },
            # masked access token (secret -> masked at capture)
            {
                "kind": "local_storage",
                "name": "access_token",
                "value_masked": "eyJh…z9Q (812 chars)",
                "role": "user",
            },
            # client-side roles
            {
                "kind": "local_storage",
                "name": "roles",
                "value_masked": _b64(["Admin", "Auditor"]),
                "role": "user",
            },
            # plain config URL
            {
                "kind": "session_storage",
                "name": "apiUrl",
                "value_masked": "https://api.internal.example.com/v1",
                "role": "user",
            },
            # app-state preference
            {"kind": "session_storage", "name": "theme", "value_masked": "dark", "role": "user"},
        ]
    }


def _by_key(si: dict) -> dict:
    return {i["key"]: i for i in si["inventory"]}


def test_identity_object_decoded_and_correlated():
    si = build_storage_intelligence({}, _data())
    row = _by_key(si)["currentUser"]
    assert row["original_type"] == "Base64" and row["decoded_type"] == "JSON"
    assert row["classification"].startswith("Identity")
    idn = si["identity_summary"]
    assert idn.get("username") == "admin" and idn.get("tenant") == "acme"
    # email masked in the identity summary
    assert "@corp.com" in idn.get("email", "") and "jane.doe" not in idn.get("email", "")


def test_masked_token_classified_authentication():
    si = build_storage_intelligence({}, _data())
    row = _by_key(si)["access_token"]
    assert row["classification"].startswith("Authentication")
    assert row["original_type"] == "Masked"
    titles = " ".join(f["title"] for f in si["high_value_findings"])
    assert "localStorage" in titles  # token-in-localStorage finding


def test_client_side_roles_high_finding():
    si = build_storage_intelligence({}, _data())
    assert _by_key(si)["roles"]["classification"].startswith("Authorization")
    assert si["summary"]["client_side_roles"] >= 1
    assert any(
        f["severity"] == "High" and "Roles/permissions" in f["title"]
        for f in si["high_value_findings"]
    )


def test_config_url_classified():
    si = build_storage_intelligence({}, _data())
    assert _by_key(si)["apiUrl"]["classification"].startswith("Configuration")
    assert any("api.internal" in u for u in si["configuration_summary"]["api_endpoints"])


def test_app_state_low_risk():
    si = build_storage_intelligence({}, _data())
    assert _by_key(si)["theme"]["classification"].startswith("Application State")


def test_no_raw_secret_or_pii_leak():
    si = build_storage_intelligence({}, _data())
    blob = json.dumps(si)
    assert "jane.doe@corp.com" not in blob  # email masked everywhere


def test_summary_counts():
    si = build_storage_intelligence({}, _data())
    s = si["summary"]
    assert s["total_items"] == 5
    assert s["local_storage_keys"] == 3 and s["session_storage_keys"] == 2
    assert s["decoded_values"] >= 2  # currentUser + roles decoded


def test_empty_safe():
    si = build_storage_intelligence({})
    assert si["inventory"] == [] and si["summary"]["total_items"] == 0
