"""Feature 5: Configuration Intelligence.

Extracts assigned configuration values from JS/HTML/JSON — base/API/auth/IdP/
Swagger/GraphQL/observability URLs and similar settings. These are non-secret
infrastructure pointers and are reported **verbatim** (they are the recon value).
Pure/offline string analysis.
"""

from __future__ import annotations

import re

from models.schemas import IntelFinding
from modules.intelligence.confidence import HIGH

# Config keys we care about -> friendly label.
_CONFIG_KEYS = {
    "baseurl": "Base URL",
    "apibaseurl": "API Base URL",
    "apiurl": "API URL",
    "apiendpoint": "API Endpoint",
    "gatewayurl": "API Gateway",
    "authurl": "Auth URL",
    "issuer": "OIDC Issuer",
    "keycloakurl": "Keycloak URL",
    "tokenurl": "Token URL",
    "redirecturi": "OAuth Redirect URI",
    "swaggerurl": "Swagger URL",
    "graphqlurl": "GraphQL URL",
    "graphqlendpoint": "GraphQL Endpoint",
    "sentryurl": "Sentry URL",
    "sentrydsn": "Sentry DSN",
    "datadogurl": "Datadog URL",
    "clientid": "OAuth Client ID",
    "realm": "Keycloak Realm",
}

# `key: "value"` or `key = "value"` (also tolerant of quoted keys).
_ASSIGN_RE = re.compile(r"""["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*[:=]\s*["']([^"'\n]{2,300})["']""")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def discover_config(corpus: list[dict]) -> list[IntelFinding]:
    """Return configuration findings ``IntelFinding(category='Configuration')``."""
    found: dict[tuple, IntelFinding] = {}
    for item in corpus:
        text = item.get("text") or ""
        if not text:
            continue
        location = (item.get("url") or "")[:200]
        source = item.get("source", "")
        for key, value in _ASSIGN_RE.findall(text):
            norm = key.lower().replace("_", "").replace("-", "")
            label = _CONFIG_KEYS.get(norm)
            if not label:
                continue
            # Only keep URL-ish or short scalar config; skip long blobs.
            v = value.strip()
            is_url = bool(_URL_RE.match(v))
            if not is_url and ("realm" not in norm and "clientid" not in norm):
                continue
            dedupe = (label, v)
            if dedupe in found:
                continue
            found[dedupe] = IntelFinding(
                kind="config",
                category="Configuration",
                name=label,
                value_masked=v,  # non-secret config — shown verbatim
                location=location,
                source=source,
                confidence=HIGH,
                severity="Informational",
            )
    return sorted(found.values(), key=lambda f: (f.name, f.value_masked or ""))
