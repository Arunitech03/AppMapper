"""Authentication Token Inventory & Token Intelligence Engine.

Discovers, classifies, safely decodes, correlates and risk-rates *all* authentication
token types found in already-collected, masked artifacts (HAR headers, cookies, browser
storage, JS findings) plus the decoded access token — so a tester understands the full
token ecosystem without inspecting payloads by hand.

Discovery / analysis only: JWTs are decoded locally (base64url); nothing is cracked,
brute-forced, decrypted, forged or signature-verified. Masked artifacts retain their
names + value prefixes, so every token is classifiable, but only raw-available tokens
(the access token + JS-embedded JWTs) are actually decoded. No raw tokens or unmasked
PII are emitted.
"""

from __future__ import annotations

# Classification keyword tables (matched case-insensitively against artifact names).
_SESSION_SIGS = (
    "auth_session_id",
    "keycloak_session",
    "jsessionid",
    "phpsessid",
    "asp.net_sessionid",
    "sessionid",
    "kc_restart",
)
_IDENTITY_SIGS = ("id_token", "idtoken", "keycloak_identity", "identity")
_REFRESH_SIGS = ("refresh_token", "refreshtoken", "refresh")
_CSRF_SIGS = ("csrf", "xsrf", "x-csrf-token", "x-xsrf-token", "_csrf")
_API_SIGS = ("x-api-key", "api_token", "apikey", "api-key", "service_token")
_ACCESS_SIGS = ("authorization", "access_token", "accesstoken", "bearer")
_THIRDPARTY_SIGS = (
    "mapbox",
    "esri",
    "arcgis",
    "googlemaps",
    "google_maps",
    "azuremaps",
    "launchdarkly",
    "datadog",
    "sentry",
    "segment",
    "amplitude",
)
# Storage keys that are not authentication-relevant.
_IGNORE = ("theme", "iconify", "gis-lang", "diagnostics", "isloginsuccess", "lang", "locale")

_STORAGE_LABEL = {
    "authorization": "Header",
    "cookie": "Cookie",
    "local_storage": "localStorage",
    "session_storage": "sessionStorage",
}
_SOURCE_LABEL = {
    "authorization": "Authorization Header",
    "cookie": "Cookie",
    "local_storage": "Browser Storage",
    "session_storage": "Browser Storage",
}

_PENTEST_VALUE = {
    "Access Token": ["Authorization Testing", "Privilege Escalation", "Role Abuse"],
    "Identity Token": ["Identity Enumeration", "User Correlation"],
    "Refresh Token": ["Session Persistence Analysis"],
    "Session Cookie": ["Session Management Review"],
    "Anti-CSRF Token": ["CSRF Protection Validation"],
    "API Token": ["API Authorization Testing"],
    "Third-Party Token": ["Trust Boundary Review"],
}


def build_token_inventory(report: dict) -> dict:
    """Build the token inventory / intelligence section from the assembled report."""
    artifacts = report.get("auth_artifacts") or []
    ji = report.get("jwt_intelligence") or {}
    primary = ji.get("primary") or {}
    auth = report.get("auth_intelligence") or {}
    model = (auth.get("authentication_model") or {}).get("model", "Unknown")
    refresh = auth.get("refresh_token") or {}
    authz = auth.get("authorization") or {}
    storage_facts = auth.get("storage") or {}
    token_storage = storage_facts.get("access_token", "—")

    rows: list[dict] = []
    seen_types: set[str] = set()

    def emit(ttype, name, kind, decoded, risk):
        seen_types.add(ttype)
        rows.append(
            {
                "type": ttype,
                "name": name,
                "source": _SOURCE_LABEL.get(kind, "Captured"),
                "storage": _STORAGE_LABEL.get(kind, "—"),
                "decoded": decoded,
                "risk": risk,
            }
        )

    for a in artifacts:
        name = (a.get("name") or "").strip()
        kind = (a.get("kind") or "").lower()
        low = name.lower()
        is_jwt = str(a.get("value_masked") or "").startswith("eyJ")
        if low in _IGNORE or not name:
            continue
        ttype, decoded, risk = _classify(low, kind, is_jwt, token_storage)
        if ttype:
            emit(ttype, name, kind, decoded, risk)

    # Refresh capability inferred via offline_access even without a discrete artifact.
    if "Refresh Token" not in seen_types and refresh.get("status") in ("Present", "Inferred"):
        seen_types.add("Refresh Token")
        rows.append(
            {
                "type": "Refresh Token",
                "name": "refresh (inferred)",
                "source": "offline_access scope",
                "storage": refresh.get("storage", "—"),
                "decoded": "No (Inferred)",
                "risk": "Medium",
            }
        )

    # Third-party integration tokens (from service inventory / domain intel).
    for tp in _third_party_tokens(report):
        if tp not in {r["name"] for r in rows}:
            emit("Third-Party Token", tp, "javascript", "N/A", "Informational")

    detail_cards = _detail_cards(primary, ji, refresh)
    correlation = _correlation(seen_types, model, primary, authz, artifacts)
    graph = _relationship_graph(seen_types, primary, report)
    points = _developer_points(seen_types, primary, refresh, model)
    pentest = {t: _PENTEST_VALUE[t] for t in sorted(seen_types) if t in _PENTEST_VALUE}

    return {
        "tokens": _sorted_rows(rows),
        "detail_cards": detail_cards,
        "correlation": correlation,
        "relationship_graph": graph,
        "developer_points": points,
        "pentest_value": pentest,
    }


# ---------------------------------------------------------------------------


def _classify(low: str, kind: str, is_jwt: bool, token_storage: str):
    """Return (type, decoded, risk) for an artifact, or (None, ...) to skip."""
    if any(s in low for s in _REFRESH_SIGS):
        return "Refresh Token", "No (Opaque)", "Medium"
    if any(s in low for s in _CSRF_SIGS):
        return "Anti-CSRF Token", "N/A", "Positive"
    if any(s in low for s in _API_SIGS):
        return "API Token", ("No (Opaque)" if not is_jwt else "Yes"), "Informational"
    if any(s in low for s in _THIRDPARTY_SIGS):
        return "Third-Party Token", "N/A", "Informational"
    if any(s in low for s in _IDENTITY_SIGS):
        decoded = "No (masked — JWT format)" if is_jwt else "N/A"
        return "Identity Token", decoded, "Medium"
    if any(s in low for s in _SESSION_SIGS):
        return "Session Cookie", "N/A", "Medium"
    if (
        kind == "authorization"
        or any(s in low for s in _ACCESS_SIGS)
        or (is_jwt and low in ("token", "access_token"))
    ):
        # The access token is decoded via jwt_intelligence (raw available).
        risk = "High" if token_storage in ("localStorage", "sessionStorage") else "Medium"
        return "Access Token", "Yes", risk
    return None, None, None


def _third_party_tokens(report: dict) -> list[str]:
    out: list[str] = []
    for h in report.get("domain_intelligence", {}).get("third_party", []) or []:
        host = h.get("host") if isinstance(h, dict) else h
        if host and any(s in str(host).lower() for s in _THIRDPARTY_SIGS):
            out.append(str(host))
    return out


def _detail_cards(primary: dict, ji: dict, refresh: dict) -> list[dict]:
    cards: list[dict] = []
    if primary:
        cards.append(
            {
                "title": "Access Token",
                "type": "Access Token",
                "storage": "localStorage",
                "issuer": primary.get("issuer"),
                "realm": primary.get("realm"),
                "client": primary.get("client"),
                "applications": len(primary.get("applications") or []),
                "roles": primary.get("total_roles", 0),
                "lifetime": primary.get("token_lifetime"),
                "risk": "High" if (primary.get("trusted_applications") or 0) > 1 else "Medium",
            }
        )
    # Identity token contents (from the decoded access token's identity claims).
    user = primary.get("user") or {}
    if user.get("username") or user.get("email"):
        contains = [
            k
            for k in ("username", "email", "name", "locale")
            if user.get(k) or user.get("display_name")
        ]
        cards.append(
            {
                "title": "Identity Token",
                "type": "Identity Token",
                "contains": contains or ["username", "email"],
                "risk": "Identity Information Exposure",
            }
        )
    if refresh.get("status") in ("Present", "Inferred"):
        cards.append(
            {
                "title": "Refresh Token",
                "type": "Refresh Token",
                "observed": "Yes",
                "storage": refresh.get("storage", "—"),
                "decoded": "No",
                "reason": refresh.get("basis") or "Opaque Token Format",
                "risk": "Refresh Capability Present",
            }
        )
    return cards


def _correlation(seen: set, model: str, primary: dict, authz: dict, artifacts: list) -> dict:
    observed = [
        t
        for t in (
            "Access Token",
            "Refresh Token",
            "Identity Token",
            "Session Cookie",
            "Anti-CSRF Token",
        )
        if t in seen
    ]
    confidence = "High" if len(observed) >= 3 else "Medium" if observed else "Low"

    # Identity consistency: identity present in the access token + a session-storage username.
    id_sources = []
    if (primary.get("user") or {}).get("username"):
        id_sources.append("Access Token")
    if any(
        (a.get("kind") == "session_storage" and (a.get("name") or "").lower() == "username")
        for a in artifacts
    ):
        id_sources.append("Session Storage")
    if "Identity Token" in seen:
        id_sources.append("Identity Token")

    return {
        "authentication_model": model,
        "observed_tokens": observed,
        "confidence": confidence,
        "identity_consistency": {
            "sources": id_sources,
            "confidence": "High" if len(id_sources) >= 2 else "Medium" if id_sources else "Low",
        },
        "authorization_summary": {
            "applications": authz.get("applications", 0),
            "roles": authz.get("total_roles", 0),
            "administrative": authz.get("administrative", 0),
            "security_sensitive": authz.get("security_sensitive", 0),
        },
    }


def _relationship_graph(seen: set, primary: dict, report: dict) -> list[str]:
    order = ["Access Token", "Refresh Token", "Identity Token", "Session Cookie", "Anti-CSRF Token"]
    present = [t for t in order if t in seen]
    if not present:
        return []
    lines = ["Browser"]
    for i, t in enumerate(present):
        lines.append(("└── " if i == len(present) - 1 else "├── ") + t)
    idp = primary.get("identity_provider") or "Identity Provider"
    lines += ["↓", idp, "↓", "Gateway", "↓", "Applications"]
    return lines


def _developer_points(seen: set, primary: dict, refresh: dict, model: str) -> list[str]:
    pts: list[str] = []
    if "Access Token" in seen:
        pts.append("Access token stored in localStorage.")
    if refresh.get("status") in ("Present", "Inferred"):
        pts.append("Refresh capability observed.")
    if "Identity Token" in seen or (primary.get("user") or {}).get("email"):
        pts.append("Identity token contains email and username.")
    if (primary.get("trusted_applications") or 0) > 1:
        pts.append(f"Token trusted by {primary['trusted_applications']} applications.")
    if primary.get("administrative_roles"):
        pts.append(f"{len(primary['administrative_roles'])} administrative roles detected.")
    if model == "Hybrid":
        pts.append("Hybrid authentication model detected.")
    if "Session Cookie" in seen and "Access Token" in seen:
        pts.append("Session cookies and bearer tokens used simultaneously.")
    return pts


_RISK_RANK = {"High": 0, "Medium": 1, "Informational": 2, "Positive": 3}
_TYPE_RANK = {
    "Access Token": 0,
    "Identity Token": 1,
    "Refresh Token": 2,
    "Session Cookie": 3,
    "Anti-CSRF Token": 4,
    "API Token": 5,
    "Third-Party Token": 6,
}


def _sorted_rows(rows: list[dict]) -> list[dict]:
    # De-duplicate by (type, name); order by token-type importance.
    uniq: dict[tuple, dict] = {}
    for r in rows:
        uniq.setdefault((r["type"], r["name"]), r)
    return sorted(uniq.values(), key=lambda r: (_TYPE_RANK.get(r["type"], 9), r["name"]))
