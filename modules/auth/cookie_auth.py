"""Cookie-based session helpers.

Parses raw cookie strings / cookie lists into a jar and recognizes well-known
session cookie names so they can be surfaced as authentication artifacts.
"""

from __future__ import annotations

import re

# Known session/auth cookie names across common stacks and IdPs.
SESSION_COOKIE_NAMES = {
    "jsessionid",
    "session",
    "sessionid",
    "sid",
    "auth_session_id",
    "auth_session_id_legacy",
    "keycloak_session",
    "keycloak_identity",
    "kc_restart",
    "connect.sid",
    "asp.net_sessionid",
    ".aspnetcore.session",
    "jwttoken",
    "access_token",
    "id_token",
    "oauth_token",
    "_okta_session",
    "auth0",
    "appsession",
    "estsauth",  # Azure AD
    "esctx",
    "fedauth",  # SAML / WS-Fed
}


def parse_cookie_string(raw: str) -> dict[str, str]:
    """Parse a ``name=value; name2=value2`` cookie header into a dict."""
    jar: dict[str, str] = {}
    for pair in (raw or "").split(";"):
        if "=" in pair:
            name, value = pair.split("=", 1)
            jar[name.strip()] = value.strip()
    return jar


def is_session_cookie(name: str) -> bool:
    low = name.lower()
    if low in SESSION_COOKIE_NAMES:
        return True
    return bool(re.search(r"session|auth|token|sso|saml|oidc", low))
