"""Tests for Cookie JWT Intelligence (Sprint B5)."""

from __future__ import annotations

import base64
import json

from modules.intelligence.cookie_jwt_intelligence import build_cookie_jwt_intelligence
from modules.intelligence.jwt_intelligence import analyze_jwt
from tests.test_jwt_intelligence import PAYLOAD


def _b64(o) -> str:
    return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")


def _token() -> str:
    return f"{_b64({'alg': 'RS256', 'typ': 'JWT'})}.{_b64(PAYLOAD)}.SIG"


def _decoded_cookie(name: str, role: str = "user") -> dict:
    """A decoded cookie-JWT summary as produced at the fetch boundary."""
    return dict(analyze_jwt(_token(), role=role), cookie_name=name, origin="cookie")


def _report() -> dict:
    return {
        "auth_intelligence": {
            "authentication_model": {
                "model": "JWT",
                "uses": ["JWT Bearer Tokens"],
                "confidence": "High",
            }
        }
    }


def _data() -> dict:
    return {
        "cookie_jwt_authorization": [_decoded_cookie("KEYCLOAK_IDENTITY")],
        "auth_artifacts": [
            {"kind": "cookie", "name": "KEYCLOAK_IDENTITY", "value_masked": "eyJh…SIG (900 chars)"},
            {"kind": "cookie", "name": "JSESSIONID", "value_masked": "A1B2…9Z8Y (32 chars)"},
        ],
        "intel_findings": [
            {
                "kind": "cookie_attr",
                "name": "KEYCLOAK_IDENTITY",
                "extra": {"httpOnly": False, "secure": True, "sameSite": "Lax", "domain": "x.io"},
            }
        ],
    }


def test_decoded_cookie_is_classified_and_inventoried():
    cji = build_cookie_jwt_intelligence(_report(), _data())
    inv = {c["cookie"]: c for c in cji["jwt_cookies"]}
    assert "KEYCLOAK_IDENTITY" in inv
    kc = inv["KEYCLOAK_IDENTITY"]
    assert kc["decoded"] == "Yes"
    assert kc["type"] in ("Access Token", "ID Token")
    # cookie attributes correlated from the cookie_attr finding
    assert kc["httponly"] == "No" and kc["secure"] == "Yes" and kc["samesite"] == "Lax"


def test_admin_roles_and_high_risk_findings():
    cji = build_cookie_jwt_intelligence(_report(), _data())
    assert cji["summary"]["admin_cookie_jwts"] >= 1
    titles = " ".join(f["title"] for f in cji["high_value_findings"])
    # non-HttpOnly JWT cookie + admin roles both surface as High findings
    assert "non-HttpOnly" in titles and "Administrative roles" in titles
    assert any(f["severity"] == "High" for f in cji["high_value_findings"])


def test_authentication_model_upgraded():
    report = _report()
    cji = build_cookie_jwt_intelligence(report, _data())
    assert cji["authentication_model"] == "Hybrid Cookie + JWT"
    # the report's auth model is mutated in place
    assert report["auth_intelligence"]["authentication_model"]["model"] == "Hybrid Cookie + JWT"


def test_cookie_only_model():
    report = {"auth_intelligence": {"authentication_model": {"model": "Cookie", "uses": []}}}
    data = {
        "cookie_jwt_authorization": [_decoded_cookie("KEYCLOAK_IDENTITY")],
        "auth_artifacts": [{"kind": "cookie", "name": "KEYCLOAK_IDENTITY", "value_masked": "eyJ…"}],
    }
    cji = build_cookie_jwt_intelligence(report, data)
    assert cji["authentication_model"] == "Cookie-Carried JWT"


def test_opaque_cookie_stays_opaque():
    cji = build_cookie_jwt_intelligence(_report(), _data())
    opaque = {c["cookie"] for c in cji["opaque_cookies"]}
    assert "JSESSIONID" in opaque
    # opaque cookies never appear in the JWT inventory
    assert "JSESSIONID" not in {c["cookie"] for c in cji["jwt_cookies"]}


def test_jwt_format_but_not_decoded():
    # A JWT-format cookie with no decoded summary (value never sent as a request header).
    report = _report()
    data = {
        "auth_artifacts": [
            {"kind": "cookie", "name": "session_jwt", "value_masked": "eyJhbGc…z9 (700 chars)"}
        ]
    }
    cji = build_cookie_jwt_intelligence(report, data)
    row = next(c for c in cji["jwt_cookies"] if c["cookie"] == "session_jwt")
    assert row["decoded"] == "No" and "format only" in row["type"]


def test_decoded_from_capture_time_intel_findings():
    # The common real-world path: cookie JWT decoded at browser-exploration capture time
    # and persisted as a `cookie_jwt` intel finding (no cookie_jwt_authorization present).
    report = _report()
    data = {
        "auth_artifacts": [
            {"kind": "cookie", "name": "KEYCLOAK_IDENTITY", "value_masked": "eyJh…SIG (900 chars)"}
        ],
        "intel_findings": [
            {
                "kind": "cookie_jwt",
                "name": "KEYCLOAK_IDENTITY: demo-floods@demo_realm",
                "extra": _decoded_cookie("KEYCLOAK_IDENTITY"),
            }
        ],
    }
    cji = build_cookie_jwt_intelligence(report, data)
    inv = {c["cookie"]: c for c in cji["jwt_cookies"]}
    assert inv["KEYCLOAK_IDENTITY"]["decoded"] == "Yes"
    assert cji["authentication_model"] == "Hybrid Cookie + JWT"


def test_no_raw_token_leaks():
    cji = build_cookie_jwt_intelligence(_report(), _data())
    assert _token() not in json.dumps(cji)


def test_empty_report_safe():
    cji = build_cookie_jwt_intelligence({})
    assert cji["jwt_cookies"] == [] and cji["cookie_cards"] == []
    assert cji["summary"]["jwt_cookies"] == 0
    assert cji["authentication_model"] is None
