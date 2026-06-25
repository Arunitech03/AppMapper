"""Authentication & Authorization Intelligence.

Turns the decoded JWT (``jwt_intelligence``) plus captured, masked auth artifacts into
the actionable picture a pentester needs first: the authentication model (cookie / JWT /
hybrid), where tokens are stored, refresh-token presence, an application access summary,
authorization totals, application risk ranking, authorization testing priorities, and an
authentication risk analysis.

Pure / offline analysis over already-captured, masked data — it makes no requests and
never stores raw tokens or unmasked PII.
"""

from __future__ import annotations

# Cookie names that signal classic server-side sessions vs Keycloak SSO sessions.
_SESSION_COOKIE_SIGS = ("jsessionid", "phpsessid", "asp.net_sessionid", "sessionid", "connect.sid")
_KEYCLOAK_COOKIE_SIGS = ("keycloak_session", "keycloak_identity", "auth_session_id", "kc_restart")
_TOKEN_NAMES = ("token", "access_token", "accesstoken", "id_token", "jwt", "authorization")
_REFRESH_NAMES = ("refresh_token", "refreshtoken", "refresh")
_ADMIN_KW = ("ADMIN", "SUPERUSER", "ROOT", "OWNER")


def build_auth_intelligence(
    data: dict, jwt_intel: dict, service_inventory: list[dict] | None = None
) -> dict:
    """Assemble the authentication/authorization intelligence section."""
    primary = (jwt_intel or {}).get("primary") or {}
    artifacts = data.get("auth_artifacts") or []
    session_inv = data.get("session_inventory") or _session_counts(artifacts)
    services = service_inventory or []

    model = _auth_model(artifacts, primary)
    storage = _storage(artifacts, primary)
    refresh = _refresh_token(artifacts, primary, storage)
    app_access = sorted(
        primary.get("application_access") or [],
        key=lambda a: (a.get("admin_roles", 0), a.get("total_roles", 0)),
        reverse=True,
    )
    authorization = {
        "applications": len(primary.get("applications") or []),
        "total_roles": primary.get("total_roles", 0),
        "administrative": len(primary.get("administrative_roles") or []),
        "read": len(primary.get("read_roles") or []),
        "write": len(primary.get("write_roles") or []),
        "security_sensitive": len(primary.get("security_sensitive_roles") or []),
    }
    risks = _risk_analysis(primary, model, storage)
    priorities = _pentest_priorities(app_access)
    counts = _captured_counts(session_inv)

    return {
        "present": bool(primary),
        "authentication_model": model,
        "storage": storage,
        "refresh_token": refresh,
        "auth_cards": _auth_cards(primary, model, counts, authorization),
        "artifacts_summary": _artifacts_summary(model, storage, counts, refresh),
        "auth_flow": _auth_flow(primary, storage, services),
        "role_intelligence": _role_intelligence(primary, app_access),
        "application_access": app_access,
        "authorization": authorization,
        "application_ranking": app_access,  # already ranked
        "pentest_priorities": priorities,
        "risk_analysis": risks,
        "discussion_points": _discussion_points(primary, model, refresh, app_access, services),
        "exec_summary": _exec_summary(primary, model, app_access, authorization),
    }


def _session_counts(artifacts: list[dict]) -> list[dict]:
    """Fallback per-kind counts when no session_inventory is supplied."""
    kinds = {
        "cookie": "cookies",
        "local_storage": "local_storage",
        "session_storage": "session_storage",
    }
    agg: dict[str, int] = {"cookies": 0, "local_storage": 0, "session_storage": 0, "auth_tokens": 0}
    for a in artifacts:
        k = (a.get("kind") or "").lower()
        if k in kinds:
            agg[kinds[k]] += 1
        elif k in ("authorization", "access_token", "bearer", "jwt"):
            agg["auth_tokens"] += 1
    return [{"role": "captured", "captured": True, **agg}]


def _captured_counts(session_inv: list[dict]) -> dict:
    """Counts for the captured (non-anonymous) role, else zeros."""
    captured = [s for s in session_inv if s.get("captured")]
    row = captured[0] if captured else {}
    return {
        "cookies": row.get("cookies", 0),
        "local_storage": row.get("local_storage", 0),
        "session_storage": row.get("session_storage", 0),
        "auth_tokens": row.get("auth_tokens", 0),
    }


def _auth_cards(primary: dict, model: dict, counts: dict, authorization: dict) -> dict:
    return {
        "authentication_type": model.get("model", "—"),
        "bearer_tokens": counts.get("auth_tokens", 0) or (1 if primary else 0),
        "cookies": counts.get("cookies", 0),
        "local_storage": counts.get("local_storage", 0),
        "session_storage": counts.get("session_storage", 0),
        "trusted_apps": primary.get("trusted_applications", 0),
        "roles": authorization.get("total_roles", 0),
        "admin_roles": authorization.get("administrative", 0),
    }


def _artifacts_summary(model: dict, storage: dict, counts: dict, refresh: dict) -> dict:
    cookies = storage.get("session_cookie") or ""
    return {
        "authentication_model": model.get("model", "—"),
        "bearer_tokens": counts.get("auth_tokens", 0),
        "cookies": counts.get("cookies", 0),
        "local_storage": counts.get("local_storage", 0),
        "session_storage": counts.get("session_storage", 0),
        "authorization_header": storage.get("authorization_header", "—"),
        "refresh_token": refresh.get("status", "—"),
        "token_storage": storage.get("access_token", "—"),
        "session_cookies": [c.strip() for c in cookies.split(",") if c.strip()],
    }


def _auth_flow(primary: dict, storage: dict, services: list[dict]) -> dict:
    """Browser → storage/cookies/header → gateway → service → internal APIs."""
    browser: list[dict] = []
    if storage.get("access_token") in ("localStorage", "sessionStorage"):
        browser.append({"label": storage["access_token"], "children": ["token"]})
    cookies = [c.strip() for c in (storage.get("session_cookie") or "").split(",") if c.strip()]
    if cookies:
        browser.append({"label": "Cookies", "children": cookies})
    if storage.get("authorization_header") == "Observed":
        browser.append({"label": "Authorization Header", "children": ["Bearer JWT"]})
    gateway = next((s.get("host") for s in services if s.get("host")), None)
    svc = next((s.get("service") for s in services if s.get("observed")), None) or (
        services[0].get("service") if services else None
    )
    return {
        "browser": browser,
        "gateway": gateway,
        "service": svc or primary.get("client"),
        "internal_apis": len(services),
    }


def _role_intelligence(primary: dict, app_access: list[dict]) -> dict:
    admin_by_app = [
        {"application": a["application"], "roles": a.get("admin_role_names") or []}
        for a in app_access
        if a.get("admin_role_names")
    ]
    tests = [
        "Vertical Privilege Escalation",
        "Role Manipulation",
        "Forced Browsing",
        "IDOR",
        "Workflow Bypass",
        "Administrative Function Testing",
    ]
    test_suggestions = [{"application": a["application"], "tests": tests} for a in app_access]
    return {
        "application_breakdown": app_access,
        "admin_by_app": admin_by_app,
        "security_sensitive_roles": primary.get("security_sensitive_roles") or [],
        "test_suggestions": test_suggestions,
    }


# ---------------------------------------------------------------------------


def _artifacts_by_kind(artifacts: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for a in artifacts:
        out.setdefault((a.get("kind") or "").lower(), []).append(a)
    return out


def _auth_model(artifacts: list[dict], primary: dict) -> dict:
    cookies = [a.get("name", "").lower() for a in artifacts if (a.get("kind") or "") == "cookie"]
    has_session_cookie = any(any(s in c for s in _SESSION_COOKIE_SIGS) for c in cookies)
    has_keycloak_cookie = any(any(s in c for s in _KEYCLOAK_COOKIE_SIGS) for c in cookies)
    has_bearer = bool(primary) or any(
        (a.get("kind") or "").lower() in ("authorization", "access_token", "bearer", "jwt")
        for a in artifacts
    )

    uses: list[str] = []
    if has_keycloak_cookie:
        uses.append("Keycloak Session Cookies")
    elif has_session_cookie:
        uses.append("Server-Side Session Cookies")
    if has_bearer:
        uses.append("JWT Bearer Tokens")

    cookie_session = has_keycloak_cookie or has_session_cookie
    if cookie_session and has_bearer:
        model, confidence = "Hybrid", "High"
    elif has_bearer:
        model, confidence = "JWT", "High" if primary else "Medium"
    elif cookie_session:
        model, confidence = "Cookie", "High"
    else:
        model, confidence = "Unknown", "Low"
    return {"model": model, "uses": uses, "confidence": confidence}


def _token_storage_location(artifacts: list[dict]) -> str | None:
    by_kind = _artifacts_by_kind(artifacts)
    for kind, label in (("local_storage", "localStorage"), ("session_storage", "sessionStorage")):
        for a in by_kind.get(kind, []):
            if any(t in (a.get("name", "").lower()) for t in _TOKEN_NAMES):
                return label
    return None


def _storage(artifacts: list[dict], primary: dict) -> dict:
    by_kind = _artifacts_by_kind(artifacts)
    token_loc = _token_storage_location(artifacts)
    if not token_loc and primary:
        token_loc = "Authorization header" if by_kind.get("authorization") else "—"

    session_cookies = sorted(
        a.get("name")
        for a in by_kind.get("cookie", [])
        if any(
            s in (a.get("name", "").lower()) for s in _KEYCLOAK_COOKIE_SIGS + _SESSION_COOKIE_SIGS
        )
    )
    refresh_loc = _refresh_location(artifacts)
    return {
        "access_token": token_loc or "—",
        "session_cookie": ", ".join(session_cookies) if session_cookies else "—",
        "authorization_header": "Observed" if by_kind.get("authorization") else "Not observed",
        "refresh_token": refresh_loc or "Not Observed",
    }


def _refresh_location(artifacts: list[dict]) -> str | None:
    for a in artifacts:
        name = (a.get("name") or "").lower()
        if any(r in name for r in _REFRESH_NAMES):
            kind = (a.get("kind") or "").lower()
            return {
                "local_storage": "localStorage",
                "session_storage": "sessionStorage",
                "cookie": "Cookie",
            }.get(kind, a.get("source") or "Observed")
    return None


def _refresh_token(artifacts: list[dict], primary: dict, storage: dict) -> dict:
    loc = _refresh_location(artifacts)
    if loc:
        return {"status": "Present", "storage": loc, "basis": "artifact", "confidence": "High"}
    offline = "offline_access" in (primary.get("roles") or [])
    if offline:
        return {
            "status": "Inferred",
            "storage": "—",
            "basis": "offline_access scope/role present",
            "confidence": "Medium",
        }
    return {"status": "Not Observed", "storage": "—", "basis": "—", "confidence": "—"}


def _risk_analysis(primary: dict, model: dict, storage: dict) -> list[dict]:
    risks: list[dict] = []
    if not primary:
        return risks
    if storage.get("access_token") in ("localStorage", "sessionStorage"):
        risks.append(
            {
                "title": f"JWT stored in {storage['access_token']}",
                "risk": "Access token is readable by any JavaScript on the page.",
                "impact": "Token theft via XSS / third-party script compromise.",
            }
        )
    if (primary.get("token_lifetime_seconds") or 0) > 3600:
        risks.append(
            {
                "title": "Long-lived access token",
                "risk": f"Access token lifetime is {primary.get('token_lifetime')}.",
                "impact": "Extended exposure window if the token is compromised.",
            }
        )
    if model.get("model") == "Hybrid":
        risks.append(
            {
                "title": "Hybrid authentication model",
                "risk": "Authentication relies on multiple artifacts (cookies + bearer token).",
                "impact": "All artifacts must be protected; broader attack surface.",
            }
        )
    if primary.get("trusted_applications", 0) > 1:
        risks.append(
            {
                "title": "Multi-application trust",
                "risk": f"Token is trusted by {primary['trusted_applications']} applications.",
                "impact": "A single token compromise affects multiple applications.",
            }
        )
    if primary.get("administrative_roles"):
        risks.append(
            {
                "title": "Administrative privileges",
                "risk": f"{len(primary['administrative_roles'])} administrative roles present.",
                "impact": "High-impact actions available if the session is abused.",
            }
        )
    return risks


def _pentest_priorities(app_access: list[dict]) -> list[dict]:
    out: list[dict] = []
    for i, app in enumerate(app_access[:5], start=1):
        if not app.get("admin_roles"):
            continue
        admin_names = app.get("admin_role_names") or []
        tests = ["Vertical Privilege Escalation", "Role Bypass", "IDOR", "Administrative Functions"]
        if any("CONFIG" in r.upper() for r in admin_names):
            tests.append("Configuration Tampering")
        out.append(
            {
                "priority": i,
                "application": app["application"],
                "admin_roles": admin_names[:8],
                "tests": tests,
            }
        )
    return out


def _discussion_points(
    primary: dict, model: dict, refresh: dict, app_access: list[dict], services: list[dict]
) -> list[str]:
    if not primary:
        return []
    storage = primary.get("user") or {}
    points: list[str] = []
    points.append(f"Access token stored in {model.get('model', 'unknown')} model.")
    if primary.get("token_lifetime"):
        points.append(f"Access token lifetime is {primary['token_lifetime']}.")
    if primary.get("trusted_applications", 0) > 1:
        points.append(f"Token trusted by {primary['trusted_applications']} applications.")
    if model.get("model") == "Hybrid":
        points.append("Hybrid authentication model detected (cookies + bearer token).")
    if primary.get("administrative_roles"):
        points.append(f"{len(primary['administrative_roles'])} administrative roles detected.")
    if refresh.get("status") in ("Present", "Inferred"):
        points.append(f"Refresh capability {refresh['status'].lower()} ({refresh.get('basis')}).")
    if storage.get("email_verified") is False:
        points.append("Email verification disabled for this account.")
    if services:
        points.append("Runtime configuration exposes authentication infrastructure.")
        points.append(f"{len(services)} internal services exposed via the gateway.")
    high_priv = [a["application"] for a in app_access if a.get("admin_roles")][:5]
    if high_priv:
        points.append("High-privilege access across: " + ", ".join(high_priv))
    return points


def _exec_summary(primary: dict, model: dict, app_access: list[dict], authz: dict) -> dict:
    if not primary:
        return {}
    user = primary.get("user") or {}
    highest = app_access[0]["application"] if app_access else None
    authentication = (
        f"{primary.get('identity_provider', '?')} {primary.get('authentication_type', '')}".strip()
    )
    return {
        "user": user.get("username") or "—",
        "authentication": authentication,
        "authentication_model": model.get("model"),
        "identity_provider": primary.get("identity_provider"),
        "realm": primary.get("realm"),
        "client": primary.get("client"),
        "applications": authz["applications"],
        "roles": authz["total_roles"],
        "administrative_roles": authz["administrative"],
        "security_sensitive_roles": authz["security_sensitive"],
        "token_lifetime": primary.get("token_lifetime"),
        "trusted_applications": primary.get("trusted_applications"),
        "highest_risk_application": highest,
    }
