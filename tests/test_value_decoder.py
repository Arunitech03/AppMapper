"""Tests for the recursive value decoder (Sprint B6)."""

from __future__ import annotations

import base64
import gzip
import json
import urllib.parse

from modules.intelligence.value_decoder import decode_value, mask_leaf


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _jwt(payload: dict) -> str:
    h = _b64(json.dumps({"alg": "RS256", "typ": "JWT"})).rstrip("=")
    p = _b64(json.dumps(payload)).rstrip("=")
    return f"{h}.{p}.SIGNATURE"


def test_plain_text():
    r = decode_value("dark")
    assert r["decoded_type"] == "Text" and r["layers"] == []


def test_base64_json_identity():
    val = _b64(json.dumps({"user": "admin", "email": "jane.doe@corp.com", "role": "Admin"}))
    r = decode_value(val)
    assert r["original_type"] == "Base64" and r["decoded_type"] == "JSON"
    # PII masked, non-secret fields preserved.
    assert r["fields"]["role"] == "Admin"
    assert "@corp.com" in r["fields"]["email"] and "jane.doe" not in r["fields"]["email"]


def test_url_encoded_then_json():
    val = urllib.parse.quote(json.dumps({"tenant": "acme", "apiUrl": "https://api.internal/v1"}))
    r = decode_value(val)
    assert [x["type"] for x in r["layers"]] == ["URL-encoded", "JSON"]
    assert r["fields"]["tenant"] == "acme"


def test_base64_gzip_json():
    val = base64.b64encode(gzip.compress(b'{"feature": "beta", "enabled": true}')).decode()
    r = decode_value(val)
    assert r["decoded_type"] == "JSON" and r["fields"]["feature"] == "beta"


def test_hex_json():
    val = b'{"k": "v"}'.hex()
    r = decode_value(val)
    assert r["decoded_type"] == "JSON"


def test_unicode_escaped():
    r = decode_value("\\u0041\\u0042")  # -> "AB"
    assert r["layers"] and r["layers"][0]["type"] == "Unicode-escaped"


def test_jwt_value():
    tok = _jwt(
        {
            "iss": "https://auth/realms/demo",
            "preferred_username": "bob",
            "realm_access": {"roles": ["ADMIN"]},
        }
    )
    r = decode_value(tok)
    assert r["decoded_type"] == "JWT"
    assert (r["jwt"] or {}).get("identity_provider") == "Keycloak"
    # raw token never surfaces in the decode result
    assert tok not in json.dumps(r)


def test_jwt_nested_in_json():
    tok = _jwt({"iss": "https://auth/realms/demo", "preferred_username": "carol"})
    val = _b64(json.dumps({"id_token": tok, "profile": {"name": "Carol Smith"}}))
    r = decode_value(val)
    assert r["jwt"] is not None
    assert tok not in json.dumps(r)  # nested token masked


def test_depth_cap_terminates():
    # Deeply nested base64 must not recurse forever.
    val = "deep"
    for _ in range(12):
        val = _b64(val)
    r = decode_value(val, max_depth=4)
    assert len(r["layers"]) <= 4


def test_mask_leaf_rules():
    assert mask_leaf("apiUrl", "https://api.example.com/v1") == "https://api.example.com/v1"
    assert "…" in mask_leaf("access_token", "abcd" * 12)
    assert mask_leaf("email", "a.b@x.io").endswith("@x.io") and "…" not in mask_leaf(
        "email", "a.b@x.io"
    )
    assert mask_leaf("theme", "dark") == "dark"
