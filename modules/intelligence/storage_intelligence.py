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


def build_storage_intelligence(report: dict, data: dict | None = None) -> dict:
    """Browser Storage Intelligence: recursively decode + classify every storage artifact.

    Non-secret encoded values (base64/JSON/URL/gzip/hex/unicode) are decoded and
    pretty-printed with secret/PII leaves masked; token/secret values (already masked at
    capture) are classified by name; JWTs correlate with the decoded cookie/bearer
    findings. Pure/offline; never emits a raw secret. Empty-safe.
    """
    from modules.intelligence.value_decoder import decode_value

    data = data or {}
    artifacts = data.get("auth_artifacts") or report.get("auth_artifacts") or []
    storage = [a for a in artifacts if (a.get("kind") or "").lower() in _STORAGE_KINDS]

    inventory: list[dict] = []
    decoded_cards: list[dict] = []
    high_value: list[dict] = []
    notes: dict[str, None] = {}
    identity: dict = {}
    cat_counts: dict[str, int] = {}
    kind_counts = {"cookie": 0, "local_storage": 0, "session_storage": 0}
    n_decoded = n_jwt = n_json = n_config = n_secret = n_identity = n_authz = 0
    config_urls: list[str] = []

    # JWT summaries already decoded from cookies/bearer (for correlation).
    cji = report.get("cookie_jwt_intelligence") or {}

    for a in storage:
        kind = (a.get("kind") or "").lower()
        name = a.get("name", "")
        value = str(a.get("value_masked") or "")
        masked = _masked(value)
        kind_counts[kind] = kind_counts.get(kind, 0) + 1

        decode = {} if masked else decode_value(value)
        category, subtype, severity = _classify_storage(name, decode, masked)
        cat_counts[category] = cat_counts.get(category, 0) + 1

        original_type = "Masked" if masked else (decode.get("original_type") or "Text")
        decoded_type = "Masked" if masked else (decode.get("decoded_type") or original_type)
        if not masked and decode.get("layers"):
            n_decoded += 1
        if decode.get("jwt"):
            n_jwt += 1
        if decoded_type == "JSON":
            n_json += 1
        if category == "Configuration":
            n_config += 1
            if not masked and value.lower().startswith("http"):
                config_urls.append(value)
        if category == "Secrets":
            n_secret += 1
        if category == "Identity":
            n_identity += 1
            _collect_identity(decode.get("fields") or {}, identity)
        if category == "Authorization":
            n_authz += 1
        if decode.get("jwt"):
            _collect_identity((decode["jwt"].get("user") or {}), identity)

        inventory.append(
            {
                "storage": _KIND_LABEL.get(kind, kind),
                "key": name,
                "original_type": original_type,
                "decoded_type": decoded_type,
                "classification": f"{category} — {subtype}",
                "risk": severity,
            }
        )

        # Rich card for anything meaningfully decoded (JSON/JWT/URL/etc.).
        if not masked and (decode.get("fields") or decode.get("jwt") or decode.get("layers")):
            preview = ""
            for layer in decode.get("layers") or []:
                if layer.get("preview"):
                    preview = layer["preview"]
            decoded_cards.append(
                {
                    "storage": _KIND_LABEL.get(kind, kind),
                    "key": name,
                    "classification": f"{category} — {subtype}",
                    "chain": " → ".join(x["type"] for x in decode.get("layers") or [])
                    or original_type,
                    "fields": decode.get("fields") or {},
                    "jwt": decode.get("jwt"),
                    "preview": preview,
                    "risk": severity,
                }
            )

        # Findings.
        loc = f"{_KIND_LABEL.get(kind, kind)}: {name}"
        if category == "Secrets":
            high_value.append(
                {
                    "severity": "High",
                    "title": f"Secret material in browser storage: {name}",
                    "detail": f"{loc} holds a credential/secret client-side.",
                }
            )
        elif category == "Authorization":
            high_value.append(
                {
                    "severity": "High",
                    "title": f"Roles/permissions stored client-side: {name}",
                    "detail": f"{loc} exposes the authorization model to the browser; "
                    f"client-side role state is tamper-prone and must be enforced server-side.",
                }
            )
            notes.setdefault(f"Role information stored client-side ({loc})", None)
        elif category == "Authentication" and kind == "local_storage" and severity == "High":
            high_value.append(
                {
                    "severity": "Medium",
                    "title": f"{subtype} in localStorage: {name}",
                    "detail": f"{loc} keeps a bearer credential in JS-readable storage "
                    f"(XSS-exfiltratable). Prefer HttpOnly cookies.",
                }
            )
        elif subtype == "Tenant / Organization":
            high_value.append(
                {
                    "severity": "Medium",
                    "title": f"Tenant/organization identifier exposed: {name}",
                    "detail": f"{loc} exposes multi-tenant scoping usable for horizontal "
                    f"access testing.",
                }
            )
        elif category == "Configuration" and subtype == "API / Config URL":
            notes.setdefault(f"Internal API/config URL in storage ({loc})", None)

    # Configuration summary (URLs / cloud / flags surfaced from decoded values).
    config_summary = _configuration_summary(decoded_cards, config_urls)

    auth_summary = {
        "authentication_cookies": (cji.get("summary") or {}).get("jwt_cookies", 0),
        "jwts": n_jwt + (cji.get("summary") or {}).get("jwt_cookies", 0),
        "access_tokens": sum(1 for i in inventory if i["classification"].endswith("Access Token")),
        "refresh_tokens": sum(1 for i in inventory if "Refresh Token" in i["classification"]),
        "session_tokens": sum(1 for i in inventory if "Session Identifier" in i["classification"]),
        "csrf_tokens": sum(1 for i in inventory if "CSRF Token" in i["classification"]),
    }

    developer_points = _storage_developer_points(cat_counts, kind_counts, identity)

    inventory.sort(key=lambda x: (x["storage"], x["classification"], x["key"]))
    high_risk = sum(1 for f in high_value if f["severity"] == "High")

    return {
        "inventory": inventory,
        "decoded_cards": decoded_cards,
        "identity_summary": {k: v for k, v in identity.items() if v},
        "authentication_summary": auth_summary,
        "configuration_summary": config_summary,
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
            "client_side_roles": n_authz,
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
