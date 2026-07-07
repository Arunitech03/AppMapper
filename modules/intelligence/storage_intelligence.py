"""Feature 8: Storage Intelligence.

Classifies client-side storage observed during capture — localStorage,
sessionStorage and cookies (from ``auth_artifacts``) — into meaningful categories
(JWT/token, role, user object, tenant id, feature flag, API URL) and flags
security-relevant patterns such as role information held client-side.

Values are already MASKED in ``auth_artifacts`` (the explorer masks them); this
module only classifies the key names + masked samples. Pure/offline.
"""

from __future__ import annotations

import re

from modules.intelligence.confidence import HIGH, LOW, MEDIUM

# key-name pattern -> (classification, finding note or None)
_CLASSIFIERS: list[tuple] = [
    (
        re.compile(r"(?i)(jwt|access[_\-]?token|id[_\-]?token|bearer)"),
        "JWT / Access Token",
        "Access token stored client-side",
    ),
    (re.compile(r"(?i)refresh[_\-]?token"), "Refresh Token", "Refresh token stored client-side"),
    (
        re.compile(r"(?i)(role|authorities|permission|scope)"),
        "Role / Permission",
        "Role information stored client-side",
    ),
    (re.compile(r"(?i)(tenant|org|company|customer)[_\-]?id"), "Tenant / Org ID", None),
    (re.compile(r"(?i)(user|profile|account|currentuser)"), "User Object", None),
    (re.compile(r"(?i)(feature|flag|toggle|experiment)"), "Feature Flag", None),
    (re.compile(r"(?i)(url|uri|endpoint|host|base)"), "API / Config URL", None),
    (re.compile(r"(?i)(session|sid)"), "Session Identifier", None),
]
_STORAGE_KINDS = {"local_storage", "session_storage", "cookie"}
_KIND_LABEL = {
    "local_storage": "Local Storage",
    "session_storage": "Session Storage",
    "cookie": "Cookie",
}


def _classify(name: str) -> tuple[str, str | None]:
    for rx, label, note in _CLASSIFIERS:
        if rx.search(name or ""):
            return label, note
    return "Other", None


def analyze_storage(data: dict) -> dict:
    """Return ``{items:[…], notes:[…]}`` for client-side storage intelligence.

    ``items``: ``{storage, role, key, classification, value_masked}``.
    ``notes``: security-relevant observations (e.g. role stored client-side).
    """
    items: list[dict] = []
    notes: dict[str, None] = {}

    for a in data.get("auth_artifacts", []) or []:
        kind = (a.get("kind") or "").lower()
        if kind not in _STORAGE_KINDS:
            continue
        name = a.get("name", "")
        classification, note = _classify(name)
        items.append(
            {
                "storage": _KIND_LABEL.get(kind, kind),
                "role": a.get("role"),
                "key": name,
                "classification": classification,
                "value_masked": a.get("value_masked", ""),
            }
        )
        if note:
            notes.setdefault(f"{note} ({_KIND_LABEL.get(kind, kind)}: {name})", None)

    items.sort(key=lambda x: (x["storage"], x["classification"], x["key"]))
    return {"items": items, "notes": list(notes)}


# ---------------------------------------------------------------------------
# Sprint B6 — Browser Storage Intelligence (recursive decode + classification)
# ---------------------------------------------------------------------------

# Category keyword signatures (matched against the storage key name).
_AUTH_SIGS = (
    ("Access Token", ("access_token", "accesstoken", "authorization", "bearer")),
    ("ID Token", ("id_token", "idtoken", "id-token")),
    ("Refresh Token", ("refresh_token", "refreshtoken", "refresh")),
    ("CSRF Token", ("csrf", "xsrf", "antiforgery")),
    ("API Token", ("api_token", "apitoken", "api-key", "apikey", "x-api-key")),
    ("OAuth Token", ("oauth", "oidc.user", "adal.", "msal.")),
)
_IDENTITY_SIGS = (
    "user",
    "profile",
    "account",
    "currentuser",
    "email",
    "username",
    "displayname",
    "given_name",
    "family_name",
)
_TENANT_SIGS = ("tenant", "org", "organization", "company", "customer")
_AUTHZ_SIGS = ("role", "authorities", "permission", "scope", "privilege", "grant")
_CONFIG_SIGS = ("url", "uri", "endpoint", "host", "base", "gateway", "apiurl", "issuer", "config")
_FLAG_SIGS = ("feature", "flag", "toggle", "experiment", "enable", "module")
_STATE_SIGS = ("theme", "lang", "locale", "pref", "recent", "selected", "layout", "sidebar", "sort")
_SECRET_SIGS = (
    "secret",
    "password",
    "passwd",
    "pwd",
    "client_secret",
    "private_key",
    "privatekey",
    "connection",
    "connstring",
    "certificate",
)

# Identity fields we correlate out of decoded JSON / JWT claims.
_IDENTITY_FIELDS = {
    "username": ("username", "user_name", "preferred_username", "login", "user"),
    "email": ("email", "mail", "upn"),
    "display_name": ("name", "display_name", "displayname", "fullname"),
    "user_id": ("sub", "user_id", "userid", "uid", "oid"),
    "tenant": ("tenant", "tenant_id", "tenantid", "realm"),
    "organization": ("org", "organization", "company", "customer"),
    "locale": ("locale", "language", "lang"),
}
# Authorization field aliases (values are the authz model — not secret, shown).
_AUTHZ_FIELDS = {
    "roles": ("roles", "role", "authorities", "realm_access", "resource_access"),
    "groups": ("groups", "group", "memberof"),
    "scopes": ("scope", "scopes", "scp"),
    "permissions": ("permissions", "permission", "privileges", "grants"),
}
# Application-state "current X" selection fields.
_APP_STATE_FIELDS = {
    "current_device": ("device", "devicenumber", "deviceid", "meterid", "serial", "endpoint_id"),
    "current_meter": ("meter", "meternumber", "meterid"),
    "current_site": ("site", "siteid", "location", "region"),
    "current_tenant": ("tenant", "tenantid", "realm"),
    "current_customer": ("customer", "customerid", "account"),
    "current_project": ("project", "projectid"),
    "current_workspace": ("workspace", "workspaceid"),
    "current_organization": ("org", "organization", "company"),
    "current_alarm": ("alarm", "alarmid", "alert"),
    "current_dashboard": ("dashboard", "dashboardid"),
    "current_asset": ("asset", "assetid", "equipment"),
}


def _masked(value: str) -> bool:
    """True if a stored value already carries the secret mask marker."""
    return "…" in value or "***" in value


def _classify_storage(key: str, decode: dict, masked: bool) -> tuple[str, str, str]:
    """Return ``(category, subtype, severity)`` for one storage artifact.

    ``category`` is the top-level taxonomy bucket; ``subtype`` is the specific label;
    ``severity`` is the risk (High/Medium/Low/Info) of holding it client-side.
    """
    low = (key or "").lower()
    fields = decode.get("fields") or {}
    fkeys = " ".join(fields.keys()).lower()
    has_jwt = bool(decode.get("jwt"))

    # Secrets (highest priority).
    if any(s in low for s in _SECRET_SIGS):
        return "Secrets", "Secret / Credential", "High"

    # Authentication.
    if has_jwt:
        return "Authentication", "JWT" if not masked else "JWT (masked)", "High"
    for label, sigs in _AUTH_SIGS:
        if any(s in low for s in sigs):
            sev = "High" if label in ("Access Token", "Refresh Token", "ID Token") else "Medium"
            return "Authentication", label, sev
    if ("session" in low or low.endswith("sid")) and "sessionstorage" not in low:
        return "Authentication", "Session Identifier", "Medium"

    # Authorization.
    if any(s in low for s in _AUTHZ_SIGS) or any(
        s in fkeys for s in ("role", "authorities", "permission", "scope")
    ):
        return "Authorization", "Roles / Permissions", "High"

    # Identity.
    if (
        any(s in low for s in _IDENTITY_SIGS)
        or any(s in low for s in _TENANT_SIGS)
        or any(any(a in fkeys for a in al) for al in _IDENTITY_FIELDS.values())
    ):
        sub = "Tenant / Organization" if any(s in low for s in _TENANT_SIGS) else "User Identity"
        return "Identity", sub, "Medium"

    # Configuration.
    if any(s in low for s in _FLAG_SIGS):
        return "Configuration", "Feature Flag", "Medium"
    if any(s in low for s in _CONFIG_SIGS) or decode.get("decoded_type") == "URL":
        return "Configuration", "API / Config URL", "Medium"

    # Application state.
    if any(s in low for s in _STATE_SIGS):
        return "Application State", "Preference", "Low"

    if decode.get("decoded_type") in ("JSON", "XML/HTML"):
        return "Application State", "Structured Data", "Low"
    return "Other", "Value", "Info"


def _collect_identity(fields: dict, out: dict) -> None:
    """Merge identity fields from a decoded JSON object / JWT claims into ``out``."""
    lower = {str(k).lower(): v for k, v in (fields or {}).items()}
    for canonical, aliases in _IDENTITY_FIELDS.items():
        if out.get(canonical):
            continue
        for a in aliases:
            if lower.get(a) not in (None, "", [], {}):
                out[canonical] = lower[a]
                break


def _flatten(obj, out: dict, depth: int = 0) -> None:
    """Flatten a decoded JSON object into ``{lower_key: value}`` (nested, depth-capped)."""
    if depth > 4 or not isinstance(obj, dict):
        return
    for k, v in obj.items():
        lk = str(k).lower()
        if isinstance(v, dict):
            _flatten(v, out, depth + 1)
        else:
            out.setdefault(lk, v)


def _extract_authorization(flat: dict, jwt: dict | None) -> dict:
    authz: dict[str, list] = {}
    for canonical, aliases in _AUTHZ_FIELDS.items():
        vals: list = []
        for a in aliases:
            v = flat.get(a)
            if isinstance(v, list):
                vals += [str(x) for x in v]
            elif isinstance(v, str) and v:
                vals += v.split() if canonical == "scopes" else [v]
        if vals:
            authz[canonical] = sorted(set(vals))[:40]
    if jwt:
        roles = (jwt.get("roles") or []) + (jwt.get("administrative_roles") or [])
        if roles:
            authz["roles"] = sorted(set(authz.get("roles", []) + roles))[:40]
        if jwt.get("scopes"):
            authz["scopes"] = sorted(set(authz.get("scopes", []) + jwt["scopes"]))[:40]
    return authz


def _extract_app_state(key: str, flat: dict) -> dict:
    """Current-selection state from decoded object field names (exact alias match)."""
    state: dict[str, str] = {}
    for canonical, aliases in _APP_STATE_FIELDS.items():
        for a in aliases:
            v = flat.get(a)
            if v not in (None, "", [], {}) and isinstance(v, (str, int, float)):
                state[canonical] = str(v)[:80]
                break
    return state


def analyze_storage_value(kind: str, key: str, value, *, role: str | None = None) -> dict:
    """Analyze ONE storage value into a mask-safe intelligence record (B6.1 core unit).

    Pipeline: type-detect -> recursive decode -> parse -> extract identity/authz/config/
    app-state -> classify -> mask. Reused at capture, import and report time. ``value`` may
    be raw (full decode) or already-masked (name-classification fallback). Never returns a
    raw secret — leaves are masked by the decoder / mask helpers.
    """
    from modules.auth.masking import mask_secret
    from modules.intelligence.value_decoder import decode_value

    text = "" if value is None else str(value)
    masked_in = _masked(text)
    decode = {} if masked_in else decode_value(text)

    flat: dict = {}
    _flatten(decode.get("fields") or {}, flat)
    jwt = decode.get("jwt")
    if jwt:
        _flatten(jwt.get("user") or {}, flat)

    identity: dict = {}
    _collect_identity(flat, identity)
    if jwt:
        identity.setdefault("tenant", jwt.get("realm"))
    identity = {k: v for k, v in identity.items() if v}

    authorization = _extract_authorization(flat, jwt)
    app_state = _extract_app_state(key, flat)
    category, subtype, severity = _classify_storage(key, decode, masked_in)

    # "Contains" — decoded field names present (+ jwt-derived), for the report checklist.
    contains = sorted((decode.get("fields") or {}).keys())
    if jwt:
        contains = sorted(set(contains) | {"issuer", "realm", "client", "roles", "username"})

    original_type = "Masked" if masked_in else (decode.get("original_type") or "Text")
    decoded_type = "Masked" if masked_in else (decode.get("decoded_type") or original_type)
    chain = " → ".join(x["type"] for x in decode.get("layers") or []) or original_type
    decoded_ok = bool(decode.get("layers") or decode.get("fields") or jwt)
    confidence = HIGH if decoded_ok else (MEDIUM if not masked_in else LOW)

    preview = ""
    for layer in decode.get("layers") or []:
        if layer.get("preview"):
            preview = layer["preview"]

    return {
        "kind": kind,
        "storage": _KIND_LABEL.get(kind, kind),
        "key": key,
        "role": role,
        "detected_type": original_type,
        "decoded_type": decoded_type,
        "chain": chain,
        "category": category,
        "subtype": subtype,
        "classification": f"{category} — {subtype}",
        "contains": contains,
        "identity": identity,
        "authorization": authorization,
        "app_state": app_state,
        "config_urls": [
            v for v in flat.values() if isinstance(v, str) and v.lower().startswith("http")
        ]
        + ([text] if (not masked_in and text.lower().startswith("http")) else []),
        "jwt": jwt,
        "preview": preview,
        "fields": decode.get("fields") or {},
        "value_masked": text if masked_in else mask_secret(text),
        "confidence": confidence,
        "risk": severity,
    }


# Where correlated facts might already appear elsewhere in the report.
_CORRELATION_SOURCES = (
    "JWT Intelligence",
    "Cookie JWT Intelligence",
    "Runtime Configuration",
    "Authentication Intelligence",
    "DNS Intelligence",
    "Hidden APIs",
)


def _report_identity_pool(report: dict) -> dict:
    """Collect identity/host facts already known elsewhere, for cross-correlation."""
    pool = {
        "usernames": set(),
        "tenants": set(),
        "clients": set(),
        "hosts": set(),
        "services": set(),
    }
    jp = (report.get("jwt_intelligence") or {}).get("primary") or {}
    if jp:
        pool["usernames"].add(str((jp.get("user") or {}).get("username") or "").lower())
        pool["tenants"].add(str(jp.get("realm") or "").lower())
        pool["clients"].add(str(jp.get("client") or "").lower())
    ident = (report.get("cookie_jwt_intelligence") or {}).get("identity_summary") or {}
    for u in ident.get("users", []) or []:
        pool["usernames"].add(str(u).lower())
    for r in ident.get("realms", []) or []:
        pool["tenants"].add(str(r).lower())
    es = (report.get("auth_intelligence") or {}).get("exec_summary") or {}
    pool["usernames"].add(str(es.get("user") or "").lower())
    pool["tenants"].add(str(es.get("realm") or "").lower())
    ji = report.get("javascript_intelligence") or {}
    for s in ji.get("service_inventory", []) or []:
        if s.get("host"):
            pool["hosts"].add(str(s["host"]).lower())
        if s.get("service"):
            pool["services"].add(str(s["service"]).lower())
    for h in (report.get("dns_intelligence") or {}).get("host_inventory", []) or []:
        if h.get("host"):
            pool["hosts"].add(str(h["host"]).lower())
    return {k: {v for v in vs if v} for k, vs in pool.items()}


def _correlate(record: dict, pool: dict) -> list[str]:
    """Link a storage record's facts to matching facts elsewhere (no duplication)."""
    from urllib.parse import urlparse

    out: list[str] = []
    ident = record.get("identity") or {}
    u = str(ident.get("username") or "").lower()
    if u and u in pool["usernames"]:
        out.append(f"username '{ident['username']}' also seen in JWT / Authentication Intelligence")
    t = str(ident.get("tenant") or "").lower()
    if t and t in pool["tenants"]:
        out.append(f"tenant/realm '{ident['tenant']}' matches JWT / Runtime Configuration")
    for url in record.get("config_urls") or []:
        host = urlparse(url).hostname or ""
        if host and host.lower() in pool["hosts"]:
            out.append(f"host '{host}' is a known service (DNS / Service Inventory)")
            break
    return out


def build_storage_intelligence(report: dict, data: dict | None = None) -> dict:
    """Browser Storage Intelligence engine (B6.1).

    Consumes ``storage_intel`` findings (decoded from RAW values at import/capture, before
    masking) as the primary source; falls back to analyzing any still-raw ``auth_artifacts``
    and name-classifying masked ones. Correlates identity/tenant/host facts with the rest of
    the report. Pure/offline; masking already applied to every record leaf. Empty-safe.
    """
    data = data or {}
    findings = data.get("intel_findings") or report.get("intel_findings") or []
    records: list[dict] = [
        f["extra"] for f in findings if (f.get("kind") == "storage_intel") and f.get("extra")
    ]
    seen = {(r.get("kind"), r.get("key")) for r in records}

    # Fallback: analyze any stored storage artifacts not already covered by a finding.
    artifacts = data.get("auth_artifacts") or report.get("auth_artifacts") or []
    for a in artifacts:
        kind = (a.get("kind") or "").lower()
        if kind not in _STORAGE_KINDS:
            continue
        if (kind, a.get("name")) in seen:
            continue
        records.append(
            analyze_storage_value(
                kind, a.get("name", ""), a.get("value_masked"), role=a.get("role")
            )
        )

    cji = report.get("cookie_jwt_intelligence") or {}
    pool = _report_identity_pool(report)

    inventory: list[dict] = []
    decoded_cards: list[dict] = []
    identity: dict = {}
    app_state: dict = {}
    high_value: list[dict] = []
    notes: dict[str, None] = {}
    all_correlations: dict[str, None] = {}
    config_urls: list[str] = []
    cat_counts: dict[str, int] = {}
    kind_counts = {"cookie": 0, "local_storage": 0, "session_storage": 0}
    n_decoded = n_jwt = n_json = n_secret = n_identity = n_authz = n_config = n_state = 0

    # Cookie JWTs decoded in B5 — used to enrich cookie storage rows (the raw cookie value
    # is masked in artifacts, but its JWT was decoded from the HAR / capture).
    cookie_cards = {str(c.get("cookie") or "").lower(): c for c in (cji.get("cookie_cards") or [])}

    for r in records:
        kind = r.get("kind", "")
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
        # Enrich a masked cookie with its decoded cookie-JWT identity (correlate, don't dup).
        card = cookie_cards.get(str(r.get("key") or "").lower()) if kind == "cookie" else None
        if card:
            ident = card.get("identity") or {}
            r = dict(r)
            r["detected_type"] = "JWT"
            r["decoded_type"] = "JWT"
            r["category"], r["subtype"] = "Authentication", "Cookie JWT"
            r["classification"] = "Authentication — Cookie JWT"
            r["contains"] = ["username", "issuer", "realm", "client", "session_id", "roles"]
            r["identity"] = {
                k: v
                for k, v in {
                    "username": ident.get("username"),
                    "tenant": ident.get("realm"),
                }.items()
                if v
            }
            r.setdefault("_correlate_note", "decoded — see Cookie JWT Intelligence")
        cat = r.get("category", "Other")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
        decoded_type = r.get("decoded_type", "Text")
        if decoded_type not in ("Masked", "Text") or r.get("jwt"):
            n_decoded += 1
        if r.get("jwt"):
            n_jwt += 1
        if decoded_type == "JSON":
            n_json += 1
        n_secret += cat == "Secrets"
        n_authz += cat == "Authorization"
        if cat == "Identity":
            n_identity += 1
        for k, v in (r.get("identity") or {}).items():
            identity.setdefault(k, v)
        if r.get("app_state"):
            n_state += 1
            for k, v in r["app_state"].items():
                app_state.setdefault(k, v)
        config_urls += r.get("config_urls") or []
        if cat == "Configuration":
            n_config += 1

        corr = _correlate(r, pool)
        if r.get("_correlate_note"):
            corr = corr + [f"cookie '{r.get('key')}' {r['_correlate_note']}"]
        for c in corr:
            all_correlations.setdefault(c, None)

        inventory.append(
            {
                "storage": r.get("storage", kind),
                "key": r.get("key", ""),
                "detected_type": r.get("detected_type", "Text"),
                "decoded_type": decoded_type,
                "classification": r.get("classification", "Other — Value"),
                "contains": r.get("contains") or [],
                "confidence": r.get("confidence", LOW),
                "risk": r.get("risk", "Info"),
                "correlations": corr,
            }
        )
        if r.get("fields") or r.get("jwt") or r.get("preview"):
            decoded_cards.append(
                {
                    "storage": r.get("storage", kind),
                    "key": r.get("key", ""),
                    "classification": r.get("classification", ""),
                    "chain": r.get("chain", ""),
                    "contains": r.get("contains") or [],
                    "fields": r.get("fields") or {},
                    "jwt": r.get("jwt"),
                    "preview": r.get("preview", ""),
                    "risk": r.get("risk", "Info"),
                }
            )

        loc = f"{r.get('storage', kind)}: {r.get('key', '')}"
        if cat == "Secrets":
            high_value.append(
                {
                    "severity": "High",
                    "title": f"Secret material in browser storage: {r.get('key')}",
                    "detail": f"{loc} holds a credential/secret client-side.",
                }
            )
        elif cat == "Authorization":
            high_value.append(
                {
                    "severity": "High",
                    "title": f"Roles/permissions stored client-side: {r.get('key')}",
                    "detail": f"{loc} exposes the authorization model to the browser; "
                    f"enforce authorization server-side.",
                }
            )
            notes.setdefault(f"Role information stored client-side ({loc})", None)
        elif cat == "Authentication" and kind == "local_storage" and r.get("risk") == "High":
            high_value.append(
                {
                    "severity": "Medium",
                    "title": f"{r.get('subtype')} in localStorage: {r.get('key')}",
                    "detail": f"{loc} keeps a bearer credential in JS-readable storage "
                    f"(XSS-exfiltratable).",
                }
            )
        elif r.get("subtype") == "Tenant / Organization":
            high_value.append(
                {
                    "severity": "Medium",
                    "title": f"Tenant/organization identifier exposed: {r.get('key')}",
                    "detail": f"{loc} exposes multi-tenant scoping usable for horizontal "
                    f"access testing.",
                }
            )
        elif cat == "Configuration" and r.get("subtype") == "API / Config URL":
            notes.setdefault(f"Internal API/config URL in storage ({loc})", None)

    config_summary = _configuration_summary(decoded_cards, config_urls)
    identity = {k: v for k, v in identity.items() if v}

    auth_summary = {
        "authentication_cookies": (cji.get("summary") or {}).get("jwt_cookies", 0),
        "jwts": n_jwt + (cji.get("summary") or {}).get("jwt_cookies", 0),
        "access_tokens": sum(1 for i in inventory if i["classification"].endswith("Access Token")),
        "refresh_tokens": sum(1 for i in inventory if "Refresh Token" in i["classification"]),
        "session_tokens": sum(1 for i in inventory if "Session Identifier" in i["classification"]),
        "csrf_tokens": sum(1 for i in inventory if "CSRF Token" in i["classification"]),
    }
    authorization_summary = {
        "roles": sorted(
            {x for r in records for x in (r.get("authorization") or {}).get("roles", [])}
        ),
        "groups": sorted(
            {x for r in records for x in (r.get("authorization") or {}).get("groups", [])}
        ),
        "scopes": sorted(
            {x for r in records for x in (r.get("authorization") or {}).get("scopes", [])}
        ),
        "permissions": sorted(
            {x for r in records for x in (r.get("authorization") or {}).get("permissions", [])}
        ),
    }

    developer_points = _storage_developer_points(cat_counts, kind_counts, identity)
    if app_state:
        developer_points.append(
            "Application state (current device/site/tenant/selection) is persisted client-side."
        )
    if all_correlations:
        developer_points.append(
            "Storage artifacts correlate with identity/config seen elsewhere — findings are linked."
        )

    inventory.sort(key=lambda x: (x["storage"], x["classification"], x["key"]))
    high_risk = sum(1 for f in high_value if f["severity"] == "High")

    return {
        "inventory": inventory,
        "decoded_cards": decoded_cards,
        "identity_summary": identity,
        "authentication_summary": auth_summary,
        "authorization_summary": {k: v for k, v in authorization_summary.items() if v},
        "configuration_summary": config_summary,
        "application_state": app_state,
        "correlations": list(all_correlations),
        "high_value_findings": high_value,
        "developer_points": developer_points,
        "notes": list(notes),
        "summary": {
            "total_items": len(inventory),
            "cookies": kind_counts.get("cookie", 0),
            "local_storage_keys": kind_counts.get("local_storage", 0),
            "session_storage_keys": kind_counts.get("session_storage", 0),
            "decoded_values": n_decoded,
            "jwts": n_jwt,
            "json_objects": n_json,
            "config_objects": n_config,
            "secrets": n_secret,
            "identity_objects": n_identity,
            "app_state_objects": n_state,
            "client_side_roles": n_authz,
            "correlated": len(all_correlations),
            "high_risk": high_risk,
        },
    }


def _configuration_summary(cards: list[dict], plain_urls: list[str]) -> dict:
    """Pull API/gateway URLs, internal services, cloud storage and flags from decoded data."""
    from modules.intelligence.dns_intelligence import _CLOUD_SIGS
    from modules.intelligence.gateway_detector import service_of_path

    api_urls: dict[str, None] = {}
    services: dict[str, None] = {}
    cloud: dict[str, None] = {}
    flags: dict[str, None] = {}

    def _consider(text: str) -> None:
        if not isinstance(text, str) or "http" not in text.lower():
            return
        api_urls.setdefault(text[:200], None)
        for provider, sigs in _CLOUD_SIGS:
            if any(sig in text.lower() for sig in sigs):
                cloud.setdefault(provider, None)
        from urllib.parse import urlparse

        svc = service_of_path(urlparse(text).path or "")
        if svc:
            services.setdefault(svc, None)

    for url in plain_urls:
        _consider(url)
    for c in cards:
        for k, v in (c.get("fields") or {}).items():
            if any(s in k.lower() for s in _FLAG_SIGS):
                flags.setdefault(k, None)
            if isinstance(v, str):
                _consider(v)
            elif isinstance(v, dict):
                for vv in v.values():
                    _consider(vv if isinstance(vv, str) else "")

    return {
        "api_endpoints": list(api_urls)[:40],
        "internal_services": list(services)[:40],
        "cloud_storage": list(cloud),
        "feature_flags": list(flags)[:60],
    }


def _storage_developer_points(cat_counts: dict, kind_counts: dict, identity: dict) -> list[str]:
    points: list[str] = []
    if cat_counts.get("Secrets"):
        points.append(
            f"{cat_counts['Secrets']} secret/credential value(s) found in browser storage — "
            f"move secrets server-side; never persist them client-side."
        )
    if cat_counts.get("Authorization"):
        points.append(
            "Role/permission data is stored client-side — treat it as display-only and enforce "
            "authorization on the server (client state is attacker-controllable)."
        )
    if cat_counts.get("Authentication"):
        points.append(
            "Authentication tokens are held in web storage — prefer HttpOnly, Secure cookies so "
            "XSS cannot read them."
        )
    if identity.get("email") or identity.get("username"):
        points.append("User identity (username/email) is stored client-side and decodable.")
    if identity.get("tenant") or identity.get("organization"):
        points.append(
            "Tenant/organization identifiers are exposed in storage (multi-tenant scope)."
        )
    if cat_counts.get("Configuration"):
        points.append("Runtime configuration / internal API URLs are exposed in browser storage.")
    return points
