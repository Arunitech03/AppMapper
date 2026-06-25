"""Tests for enterprise auth: masking, AuthManager, session_manager, IdP detection,
Playwright graceful degradation, and auth reporting."""

from __future__ import annotations

import json

import httpx
import respx

from models.schemas import ScanContext, TargetInput, UserCredential
from modules.auth import playwright_auth, session_manager
from modules.auth.auth_manager import AuthManager
from modules.auth.idp_detector import detect_idp
from modules.auth.masking import mask_secret

# --- masking ---------------------------------------------------------------


def test_mask_secret():
    assert mask_secret(None) == ""
    assert mask_secret("abcd") == "****"  # short -> fully masked
    masked = mask_secret("eyJhbGciOiJIUzI1NiJ9.payload.signature")
    assert "…" in masked and masked.startswith("eyJh") and "payload" not in masked


# --- AuthManager strategies ------------------------------------------------


def test_authmanager_jwt_and_cookie():
    am = AuthManager()
    jwt = am.resolve(UserCredential(role="api", jwt_token="eyJ.a.b"))
    assert jwt.headers["Authorization"] == "Bearer eyJ.a.b"
    assert jwt.source == "jwt"

    ck = am.resolve(UserCredential(role="u", cookie="JSESSIONID=xyz; theme=dark"))
    assert ck.cookies == {"JSESSIONID": "xyz", "theme": "dark"}
    # Only the session cookie becomes a (masked) artifact.
    kinds = {(a.name, a.kind) for a in ck.artifacts}
    assert ("JSESSIONID", "cookie") in kinds
    assert all(a.name != "theme" for a in ck.artifacts)


def test_authmanager_none_and_strategy_selection():
    assert UserCredential(role="a", session_file="s.json").strategy == "session"
    assert UserCredential(role="a", jwt_token="t").strategy == "jwt"
    assert UserCredential(role="a", auth_mode="none", jwt_token="t").strategy == "none"
    assert AuthManager().resolve(UserCredential(role="a")).source == "none"


def test_authmanager_har_extraction(tmp_path):
    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://app/api/me",
                        "headers": [{"name": "Authorization", "value": "Bearer eyJ.tok.en"}],
                        "cookies": [{"name": "SESSION", "value": "sess-12345"}],
                    },
                    "response": {"status": 200, "content": {"mimeType": "application/json"}},
                }
            ]
        }
    }
    p = tmp_path / "admin.har"
    p.write_text(json.dumps(har))
    resolved = AuthManager().resolve(UserCredential(role="admin", har=str(p)))
    assert resolved.cookies.get("SESSION") == "sess-12345"
    assert resolved.headers.get("Authorization") == "Bearer eyJ.tok.en"
    kinds = {a.kind for a in resolved.artifacts}
    assert "authorization" in kinds and "cookie" in kinds


# --- session_manager (storage_state) --------------------------------------


def test_session_manager_resolves_storage_state(tmp_path):
    state = {
        "cookies": [
            {"name": "KEYCLOAK_SESSION", "value": "kc-abc-123-xyz"},
            {"name": "theme", "value": "dark"},
        ],
        "origins": [
            {
                "origin": "https://app",
                "localStorage": [
                    {"name": "access_token", "value": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sigaaa"}
                ],
            }
        ],
    }
    p = tmp_path / "admin.json"
    p.write_text(json.dumps(state))
    rs = session_manager.resolve_session("admin", p)
    assert rs.cookies["KEYCLOAK_SESSION"] == "kc-abc-123-xyz"
    assert rs.headers["Authorization"].startswith("Bearer eyJ")
    info = session_manager.session_info("admin", p)
    assert info.captured and info.cookie_count == 2 and info.has_storage


# --- IdP detection ---------------------------------------------------------


@respx.mock
async def test_idp_detect_keycloak():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/" or path == "":
            return httpx.Response(
                302,
                headers={"location": "http://app.local/realms/master/protocol/openid-connect/auth"},
            )
        if path.startswith("/realms/"):
            return httpx.Response(
                200, text="<html>keycloak</html>", headers={"content-type": "text/html"}
            )
        if path == "/.well-known/openid-configuration":
            return httpx.Response(
                200,
                json={"issuer": "http://app.local/realms/master", "authorization_endpoint": "x"},
                headers={"content-type": "application/json"},
            )
        return httpx.Response(404)

    respx.route(host="app.local").mock(side_effect=handler)
    ctx = ScanContext(
        target=TargetInput(url="http://app.local", domain="app.local"), timeout=2, verify_tls=False
    )
    idp = await detect_idp(ctx)
    assert idp.identity_provider == "Keycloak"
    assert idp.authentication_type == "OIDC"


@respx.mock
async def test_idp_detect_okta_redirect():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "app.local" and request.url.path in ("/", ""):
            return httpx.Response(
                302,
                headers={
                    "location": "https://dev-123.okta.com/oauth2/v1/authorize?client_id=x&response_type=code"
                },
            )
        if request.url.host == "dev-123.okta.com":
            return httpx.Response(
                200, text="<html>sign in</html>", headers={"content-type": "text/html"}
            )
        return httpx.Response(404)

    respx.route().mock(side_effect=handler)
    ctx = ScanContext(
        target=TargetInput(url="http://app.local", domain="app.local"), timeout=2, verify_tls=False
    )
    idp = await detect_idp(ctx)
    assert idp.identity_provider == "Okta"


# --- Playwright graceful degradation ---------------------------------------


def test_playwright_capture_graceful(monkeypatch, tmp_path):
    # Force the lazy import to fail and assert a clear, actionable error.
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("playwright"):
            raise ImportError("no playwright")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert playwright_auth.is_available() is False
    try:
        playwright_auth.capture("admin", "http://app", tmp_path / "s.json")
        raise AssertionError("expected PlaywrightNotInstalled")
    except playwright_auth.PlaywrightNotInstalled as exc:
        assert "pip install playwright" in str(exc)
