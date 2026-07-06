"""JWT Authorization Intelligence.

Decodes a captured access token's (unverified) payload and derives the authorization
picture a tester needs up front: identity provider, realm, client (``azp``), token
lifetime, trusted applications (``aud``), the per-application role inventory
(``resource_access``), the role model (administrative / write / read / security-
sensitive), and risk indicators.

Discovery-only: the signature is never verified and tokens are never forged or
validated. PII is masked (display name + email); the username and role names — the
authorization model itself — are shown. Raw tokens are never emitted: callers receive
only masked summaries.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from urllib.parse import urlparse

from modules.auth.jwt_auth import decode_jwt
from modules.auth.masking import mask_secret

# PII claim names masked in the claims inventory unless show_pii.
_PII_CLAIMS = ("name", "given_name", "family_name", "email")

_REALM_RE = re.compile(r"/realms/([^/]+)", re.IGNORECASE)
_BEARER_RE = re.compile(r"bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", re.IGNORECASE)
_JWT_RE = re.compile(r"\b([A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]+)\b")
# A JWT begins with a base64url-encoded ``{"alg":...`` header, i.e. ``eyJ``.
_JWT_FIND_RE = re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+)")

# Hosted-IdP host signatures (issuer host -> provider, auth type).
_HOST_PROVIDERS = (
    ("login.microsoftonline.com", "Azure AD / Entra ID", "OIDC Bearer Token"),
    ("login.windows.net", "Azure AD / Entra ID", "OIDC Bearer Token"),
    (".okta.com", "Okta", "OIDC Bearer Token"),
    (".auth0.com", "Auth0", "OIDC Bearer Token"),
    ("accounts.google.com", "Google", "OIDC Bearer Token"),
    (".pingidentity.com", "PingFederate", "OIDC Bearer Token"),
    ("pingone.com", "PingOne", "OIDC Bearer Token"),
    (".onelogin.com", "OneLogin", "OIDC Bearer Token"),
)

# Role-name classification keywords (matched case-insensitively as substrings).
_ADMIN_KW = ("ADMIN", "SUPERUSER", "ROOT", "OWNER")
_WRITE_KW = ("WRITE", "EDIT", "CREATE", "UPDATE", "DELETE", "MODIFY", "MANAGE", "CONFIG", "PUBLISH")
_READ_KW = ("READ", "VIEW", "VIEWER", "GET", "LIST", "ANALYSIS", "GENERAL", "USER")
_SECURITY_KW = ("ADMIN", "USERS", "SECURITY", "AUTH", "IAM", "KEY", "CERT", "TOKEN", "APP_")
_SECURITY_EXACT = {"offline_access", "uma_authorization"}


def analyze_jwt(token: str, role: str | None = None, *, show_pii: bool = False) -> dict | None:
    """Decode a JWT and build its authorization summary, or ``None`` if undecodable.

    Output contains no raw token. PII (name/email) is masked unless ``show_pii`` is set
    (internal environments only). Role names and the username — the authorization model
    under assessment — are always surfaced.
    """
    decoded = decode_jwt(token or "")
    claims = decoded.get("claims") or {}
    if not claims:
        return None

    iss = claims.get("iss") or ""
    provider, auth_type, realm = _identity(iss, claims)
    aud = _as_list(claims.get("aud"))
    applications = list((claims.get("resource_access") or {}).keys())
    roles, buckets, total = _roles(claims)
    name = claims.get("name") or _full_name(claims)
    email = claims.get("email")

    return {
        "role": role,
        "identity_provider": provider,
        "realm": realm,
        "issuer": iss,
        "client": claims.get("azp") or (aud[0] if aud else None),
        "authentication_type": auth_type,
        "header": _header_analysis(decoded.get("header") or {}),
        "session_state": claims.get("session_state"),
        "token_lifetime": _humanize_seconds(_lifetime(claims)),
        "token_lifetime_seconds": _lifetime(claims),
        "lifetime_class": _lifetime_class(_lifetime(claims)),
        "issued_at": _iso(claims.get("iat")),
        "expires_at": _iso(claims.get("exp")),
        "user": {
            "name": name if show_pii else _mask_name(name),
            "display_name": name if show_pii else _mask_name(name),
            "username": claims.get("preferred_username") or claims.get("user_name"),
            "email": email if show_pii else _mask_email(email),
            "locale": claims.get("locale"),
            "subject": claims.get("sub"),
            "email_verified": claims.get("email_verified"),
        },
        "scopes": (claims.get("scope") or "").split(),
        "trusted_applications": len(aud),
        "trusted_application_list": aud,
        "audience_observation": _audience_observation(len(aud)),
        "applications": applications,
        "application_access": _application_access(claims),
        "total_roles": total,
        "roles": roles,
        "administrative_roles": buckets["administrative"],
        "write_roles": buckets["write"],
        "read_roles": buckets["read"],
        "security_sensitive_roles": buckets["security_sensitive"],
        "risk_indicators": _risk_indicators(claims, buckets, aud, applications),
        "claims": _masked_claims(claims, show_pii),
        "token_masked": mask_secret(token),
    }


def _iso(ts) -> str | None:
    """Unix seconds -> ``YYYY-MM-DD HH:MM UTC`` (deterministic, no current time)."""
    if not isinstance(ts, (int, float)):
        return None
    dt = datetime.fromtimestamp(int(ts), tz=UTC)
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def _lifetime_class(seconds: int | None) -> str | None:
    if not seconds or seconds <= 0:
        return None
    if seconds < 900:
        return "Short"
    if seconds <= 3600:
        return "Standard"
    if seconds <= 10800:
        return "Long"
    return "Very Long"


def _audience_observation(count: int) -> str | None:
    if count <= 1:
        return None
    return (
        f"This token is trusted by {count} applications. Compromise of a single token may "
        f"provide access across multiple applications."
    )


def _masked_claims(claims: dict, show_pii: bool) -> dict:
    """A copy of the decoded payload with PII masked (roles/structure preserved)."""
    if show_pii:
        return dict(claims)
    out = dict(claims)
    if "name" in out or "given_name" in out or "family_name" in out:
        full = out.get("name") or _full_name(out)
        if "name" in out:
            out["name"] = _mask_name(full)
    for k in ("given_name", "family_name"):
        if out.get(k):
            out[k] = _mask_name(out[k])
    if out.get("email"):
        out["email"] = _mask_email(out["email"])
    return out


def _header_analysis(header: dict) -> dict:
    """Summarize the JWT header: algorithm, signature model, key rotation."""
    alg = header.get("alg") or "?"
    up = alg.upper()
    if up.startswith(("RS", "ES", "PS")):
        model = "Asymmetric Signing"
    elif up.startswith("HS"):
        model = "Symmetric (HMAC)"
    elif up == "NONE":
        model = "Unsigned"
    else:
        model = "Unknown"
    kid = bool(header.get("kid"))
    return {
        "alg": alg,
        "typ": header.get("typ") or "JWT",
        "kid_present": kid,
        "signature_model": model,
        "key_rotation": "Enabled (kid present)" if kid else "Not indicated",
    }


def _application_access(claims: dict) -> list[dict]:
    """Per-application role breakdown (total / admin / write / read)."""
    out: list[dict] = []
    for app, block in (claims.get("resource_access") or {}).items():
        app_roles = list(block.get("roles") or [])
        admins, writes, reads = [], [], []
        for r in app_roles:
            up = r.upper()
            is_admin = any(k in up for k in _ADMIN_KW)
            if is_admin:
                admins.append(r)
            if is_admin or any(k in up for k in _WRITE_KW):
                writes.append(r)
            if any(k in up for k in _READ_KW) and not is_admin:
                reads.append(r)
        out.append(
            {
                "application": app,
                "total_roles": len(app_roles),
                "admin_roles": len(admins),
                "write_roles": len(writes),
                "read_roles": len(reads),
                "user_roles": len(app_roles) - len(admins),
                "admin_role_names": admins,
            }
        )
    return out


def harvest_jwt_summaries(
    har_rows: list[dict], burp_rows: list[dict], *, show_pii: bool = False
) -> list[dict]:
    """Decode bearer JWTs from captured HAR headers / Burp auth tokens (masked output).

    ``har_rows`` items carry ``{headers: {...}, role}``; ``burp_rows`` items carry
    ``{auth_tokens: [...], role}``. Returns one summary per distinct token. Raw tokens
    are never returned; PII is masked unless ``show_pii``.
    """
    summaries: list[dict] = []
    seen: set[str] = set()

    def add(token: str, role) -> None:
        token = (token or "").strip()
        if not token or token in seen:
            return
        seen.add(token)
        summary = analyze_jwt(token, role=role, show_pii=show_pii)
        if summary:
            summaries.append(summary)

    for row in har_rows or []:
        headers = row.get("headers") or {}
        for name, value in headers.items():
            if name.lower() == "authorization":
                m = _BEARER_RE.search(value or "")
                if m:
                    add(m.group(1), row.get("role"))
    for row in burp_rows or []:
        for tok in row.get("auth_tokens") or []:
            m = _BEARER_RE.search(tok) or _JWT_RE.search(tok)
            if m:
                add(m.group(1), row.get("role"))
    return summaries


def harvest_cookie_jwts(cookie_rows: list[dict], *, show_pii: bool = False) -> list[dict]:
    """Decode JWTs carried inside captured cookies (masked output).

    ``cookie_rows`` items carry ``{cookies: {name: value}, role}`` — the raw
    name/value pairs from captured HAR requests (``har_requests.cookies``). Every
    cookie value is scanned for an embedded JWT; if present it is decoded offline
    (no signature verification) into the same summary shape as a bearer token, tagged
    with ``cookie_name`` and ``origin="cookie"``. Returns one summary per distinct
    token. Raw tokens are never returned; PII is masked unless ``show_pii``.
    """
    summaries: list[dict] = []
    seen: set[str] = set()
    for row in cookie_rows or []:
        role = row.get("role")
        for name, value in (row.get("cookies") or {}).items():
            for tok in find_jwts(str(value or "")):
                if tok in seen:
                    continue
                seen.add(tok)
                summary = analyze_jwt(tok, role=role, show_pii=show_pii)
                if summary:
                    summary["cookie_name"] = name
                    summary["origin"] = "cookie"
                    summaries.append(summary)
    return summaries


def find_jwts(*texts: str) -> list[str]:
    """Return every JWT-looking string found across ``texts`` (order-preserving)."""
    found: list[str] = []
    seen: set[str] = set()
    for t in texts:
        for m in _JWT_FIND_RE.finditer(t or ""):
            tok = m.group(1)
            if tok not in seen:
                seen.add(tok)
                found.append(tok)
    return found


def summarize_jwts(
    tokens: list[str], role: str | None = None, *, show_pii: bool = False
) -> list[dict]:
    """Decode a list of raw tokens into summaries (deduped, undecodable dropped)."""
    out: list[dict] = []
    seen: set[str] = set()
    for tok in tokens:
        if tok in seen:
            continue
        seen.add(tok)
        s = analyze_jwt(tok, role=role, show_pii=show_pii)
        if s:
            out.append(s)
    return out


def _token_signature(s: dict) -> tuple:
    user = s.get("user") or {}
    return (s.get("issuer"), s.get("client"), user.get("subject"), s.get("total_roles"))


def build_jwt_intelligence(data: dict, *, show_pii: bool = False) -> dict:
    """Report-time shaper: merge every decoded-token source, pick the richest as ``primary``.

    Sources (all already masked / decode-on-read, no raw token persisted):
      1. ``data["jwt_authorization"]`` — bearer tokens from captured HAR/Burp headers
         (decoded at the fetch boundary).
      2. ``intel_findings`` of kind ``jwt_authz`` — summaries decoded at exploration
         capture time (where the session token is still raw, before masking).
      3. JWTs embedded in ``js_findings`` values (e.g. tokens baked into JS / runtime
         config), decoded on read.
    """
    summaries: list[dict] = list(data.get("jwt_authorization") or [])

    for f in data.get("intel_findings") or []:
        if f.get("kind") == "jwt_authz" and isinstance(f.get("extra"), dict):
            summaries.append(f["extra"])

    for s in summaries:  # tokens harvested from headers / capture are session tokens
        s.setdefault("origin", "session")

    js_blobs = [str(j.get("value") or "") for j in (data.get("js_findings") or [])]
    js_summaries = summarize_jwts(find_jwts(*js_blobs), show_pii=show_pii)
    for s in js_summaries:  # tokens baked into JS are not the account under test
        s["origin"] = "embedded"
    summaries.extend(js_summaries)

    # Dedup across sources by (issuer, client, subject, role-count); when the same
    # token appears more than once (e.g. a stale capture-time snapshot plus a freshly
    # decoded one), keep the richer summary — the one carrying per-application access.
    by_sig: dict[tuple, dict] = {}
    for s in summaries:
        sig = _token_signature(s)
        existing = by_sig.get(sig)
        if existing is None or len(s.get("application_access") or []) > len(
            existing.get("application_access") or []
        ):
            # Preserve a "session" origin if either copy had it.
            if existing and existing.get("origin") == "session":
                s = {**s, "origin": "session"}
            by_sig[sig] = s
    deduped = list(by_sig.values())

    if not deduped:
        return {}
    # Default-masked invariant: re-mask PII at report time unless show_pii, so a report
    # generated without the flag never exposes PII even if a prior --show-pii scan
    # persisted it unmasked.
    if not show_pii:
        deduped = [_remask_user(s) for s in deduped]
    # Prefer the account under test (a captured session token) over tokens merely
    # embedded in JavaScript; break ties by privilege (role count).
    primary = max(
        deduped,
        key=lambda s: (1 if s.get("origin") == "session" else 0, s.get("total_roles", 0)),
    )
    return {"primary": primary, "tokens": deduped, "count": len(deduped)}


def _remask_user(summary: dict) -> dict:
    """Return a copy of ``summary`` with user name/email + claims PII masked (idempotent)."""
    user = dict(summary.get("user") or {})
    name = user.get("name")
    if name and "*" not in name:
        user["name"] = _mask_name(name)
        user["display_name"] = _mask_name(name)
    email = user.get("email")
    if email and "*" not in email:
        user["email"] = _mask_email(email)
    claims = summary.get("claims")
    out = {**summary, "user": user}
    if isinstance(claims, dict):
        out["claims"] = _masked_claims(claims, show_pii=False)
    return out


# ---------------------------------------------------------------------------
# Claim extraction helpers
# ---------------------------------------------------------------------------


def _identity(iss: str, claims: dict) -> tuple[str, str, str | None]:
    """(identity_provider, authentication_type, realm) from the issuer + claims."""
    auth_type = "OIDC Bearer Token" if claims.get("typ") == "Bearer" else "Bearer Token"
    m = _REALM_RE.search(iss)
    if m:
        return "Keycloak", auth_type, m.group(1)
    host = (urlparse(iss).hostname or "").lower()
    for needle, provider, atype in _HOST_PROVIDERS:
        if needle.lstrip(".") in host:
            return provider, atype, None
    return (
        ("OIDC Provider" if "openid" in (claims.get("scope") or "") else "Unknown"),
        auth_type,
        None,
    )


def _lifetime(claims: dict) -> int | None:
    exp, iat = claims.get("exp"), claims.get("iat")
    if isinstance(exp, (int, float)) and isinstance(iat, (int, float)) and exp > iat:
        return int(exp - iat)
    return None


def _humanize_seconds(seconds: int | None) -> str | None:
    """Human duration, scaling the unit so long-lived tokens read sensibly.

    10800 -> ``"3 Hours"``; 51_840_000 -> ``"600 Days"`` (not ``"14400 Hours"``).
    """
    if not seconds or seconds <= 0:
        return None
    for unit, secs in (("Year", 31_536_000), ("Day", 86_400), ("Hour", 3600), ("Minute", 60)):
        if seconds >= secs:
            value = seconds / secs
            n = int(value)
            label = f"{n}" if value == n else f"{value:.1f}"
            plural = "s" if value != 1 else ""
            return f"{label} {unit}{plural}"
    return f"{seconds} Seconds"


def _roles(claims: dict) -> tuple[list[str], dict[str, list[str]], int]:
    """Flatten realm + resource_access roles; classify; return (roles, buckets, total)."""
    roles: list[str] = list((claims.get("realm_access") or {}).get("roles") or [])
    for app in (claims.get("resource_access") or {}).values():
        roles.extend(app.get("roles") or [])
    total = len(roles)

    buckets: dict[str, list[str]] = {
        "administrative": [],
        "write": [],
        "read": [],
        "security_sensitive": [],
    }
    for r in roles:
        up = r.upper()
        is_admin = any(k in up for k in _ADMIN_KW)
        if is_admin:
            _push(buckets["administrative"], r)
        if is_admin or any(k in up for k in _WRITE_KW):
            _push(buckets["write"], r)
        if any(k in up for k in _READ_KW) and not is_admin:
            _push(buckets["read"], r)
        if is_admin or r in _SECURITY_EXACT or any(k in up for k in _SECURITY_KW):
            _push(buckets["security_sensitive"], r)
    return roles, buckets, total


def _risk_indicators(claims: dict, buckets: dict, aud: list, applications: list) -> list[str]:
    out: list[str] = []
    lifetime = _lifetime(claims)
    if lifetime and lifetime > 3600:
        out.append("Long-lived access token")
    if len(aud) > 1 or len(applications) > 1:
        out.append("Multi-application trust")
    if buckets["administrative"]:
        out.append("Administrative privileges detected")
    realm_roles = (claims.get("realm_access") or {}).get("roles") or []
    if "offline_access" in realm_roles:
        out.append("Offline access granted")
    return out


def _full_name(claims: dict) -> str:
    parts = [claims.get("given_name"), claims.get("family_name")]
    return " ".join(p for p in parts if p)


# ---------------------------------------------------------------------------
# Masking helpers
# ---------------------------------------------------------------------------


def _mask_name(name: str | None) -> str:
    """``Test User`` -> ``Test H*****``; single token -> first 2 chars + ``***``."""
    if not name:
        return ""
    parts = name.strip().split()
    if len(parts) == 1:
        p = parts[0]
        return (p[:2] + "*" * max(1, len(p) - 2)) if len(p) > 2 else "*" * len(p)
    last = parts[-1]
    return f"{parts[0]} {last[0]}{'*' * max(1, len(last) - 1)}"


def _mask_email(email: str | None) -> str:
    """``test.user@example.com`` -> ``d*****.h*****@example.com`` (domain preserved)."""
    if not email or "@" not in email:
        return ""
    local, _, domain = email.partition("@")
    segments = local.split(".")
    masked_local = ".".join((s[0] + "*****") if s else "*****" for s in segments)
    return f"{masked_local}@{domain}"


def _as_list(value) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _push(bucket: list[str], role: str) -> None:
    if role not in bucket:
        bucket.append(role)
