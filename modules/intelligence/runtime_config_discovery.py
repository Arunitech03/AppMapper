"""Sprint B.1 Feature 2: Runtime Configuration Discovery from JS bundles.

SPAs embed their environment in a global object literal — typically in
``env-config.js`` or the main bundle:

    window.env = {
      REACT_APP_GATEWAY_URL: "https://gateway-proxy-qa.example.com",
      REACT_APP_KEYCLOAK_REALM: "demo_realm",
      REACT_APP_KEYCLOAK_CLIENT_ID: "demo-floods",
      REACT_APP_MAP_TOKEN: "eyJhbG...",
      REACT_APP_EWS_MODULE: true
    };

The fixed-key ``config_intelligence`` misses these. This module brace-matches the
global config object(s), extracts **every** key/value pair, and classifies each
into runtime config (URLs verbatim), Keycloak realm/client, feature flags, internal
apps, or secrets (masked). Pure/offline string analysis.
"""

from __future__ import annotations

import re

from models.schemas import IntelFinding
from modules.auth.masking import mask_secret

# Global config object holders, e.g. `window.env = {`, `window.__CONFIG__ = {`.
_GLOBAL_RE = re.compile(
    r"""(?:window\.)?(env|__ENV__|__CONFIG__|__RUNTIME_CONFIG__|appConfig|config|settings|runtimeConfig)\s*=\s*\{""",
    re.IGNORECASE,
)
# KEY: value pairs inside the object (string | bool | number). KEY may be quoted.
_PAIR_RE = re.compile(
    r"""["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*:\s*(?:"([^"]*)"|'([^']*)'|(true|false)|(-?\d+(?:\.\d+)?))""",
)

# Classification of a (normalized) config key.
_GATEWAY_RE = re.compile(r"(?i)(gateway|apigw|api[_-]?gw|proxy)")
_API_URL_RE = re.compile(
    r"(?i)(api[_-]?url|api[_-]?base|base[_-]?url|backend|service[_-]?url|graphql)"
)
_KEYCLOAK_REALM_RE = re.compile(r"(?i)(keycloak[_-]?realm|^realm$|oidc[_-]?realm)")
_KEYCLOAK_CLIENT_RE = re.compile(r"(?i)(client[_-]?id)")
_AUTH_URL_RE = re.compile(
    r"(?i)(keycloak[_-]?url|auth[_-]?url|oidc[_-]?url|issuer|sso[_-]?url|token[_-]?url)"
)
_THIRDPARTY_RE = re.compile(
    r"(?i)(mapbox|google[_-]?maps|map[_-]?token|sentry|datadog|maps?[_-]?key|maps?[_-]?url)"
)
_FEATURE_RE = re.compile(r"(?i)(module|feature|enable|monitoring|beta|flag|ews|anomaly)")
_SECRET_RE = re.compile(
    r"(?i)(secret|password|passwd|pwd|private[_-]?key|client[_-]?secret|access[_-]?key)"
)
_TOKEN_KEY_RE = re.compile(r"(?i)(token|jwt|api[_-]?key|apikey|key|credential)")
_URL_VAL_RE = re.compile(r"^https?://", re.IGNORECASE)


def _find_objects(text: str) -> list[tuple[str, str]]:
    """Return (global_name, object_body) for each global config literal."""
    out: list[tuple[str, str]] = []
    for m in _GLOBAL_RE.finditer(text):
        start = m.end() - 1  # at the '{'
        depth = 0
        for i in range(start, min(len(text), start + 20000)):
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    out.append((m.group(1), text[start : i + 1]))
                    break
    return out


def _pairs(body: str) -> list[tuple[str, object]]:
    pairs: list[tuple[str, object]] = []
    for m in _PAIR_RE.finditer(body):
        key = m.group(1)
        if m.group(2) is not None:
            val: object = m.group(2)
        elif m.group(3) is not None:
            val = m.group(3)
        elif m.group(4) is not None:
            val = m.group(4).lower() == "true"
        elif m.group(5) is not None:
            val = m.group(5)
        else:
            continue
        pairs.append((key, val))
    return pairs


def discover_runtime_config(corpus: list[dict], *, base_domain: str = "") -> list[IntelFinding]:
    """Extract + classify runtime-config object literals from a JS/HTML corpus."""
    findings: dict[tuple, IntelFinding] = {}

    def add(
        kind,
        category,
        name,
        *,
        value=None,
        location,
        source,
        confidence="high",
        severity="Informational",
        extra=None,
    ):
        key = (kind, name, str(value))
        if key not in findings:
            findings[key] = IntelFinding(
                kind=kind,
                category=category,
                name=name,
                value_masked=value,
                location=location,
                source=source,
                confidence=confidence,
                severity=severity,
                extra=extra or {},
            )

    for item in corpus:
        text = item.get("text") or ""
        if "window" not in text and "env" not in text and "config" not in text.lower():
            continue
        location = (item.get("url") or "")[:200]
        source = item.get("source", "JS")
        for global_name, body in _find_objects(text):
            for k, v in _pairs(body):
                _classify_pair(add, global_name, k, v, location, source)

    return sorted(findings.values(), key=lambda f: (f.category, f.name))


def _classify_pair(add, global_name, key, value, location, source) -> None:
    is_url = isinstance(value, str) and bool(_URL_VAL_RE.match(value))
    loc = f"{location} (window.{global_name})"

    # Booleans => feature flags.
    if isinstance(value, bool):
        add(
            "feature_flag",
            "Feature Flags",
            _humanize_flag(key),
            value=str(value),
            location=loc,
            source=source,
            extra={"enabled": value, "raw_key": key},
        )
        return

    sval = str(value)

    # Keycloak realm / client id (non-secret identifiers, verbatim).
    if _KEYCLOAK_REALM_RE.search(key):
        add(
            "runtime_config",
            "Runtime Config",
            "Keycloak Realm",
            value=sval,
            location=loc,
            source=source,
            extra={"raw_key": key, "kind": "keycloak_realm"},
        )
        return
    if _KEYCLOAK_CLIENT_RE.search(key):
        add(
            "runtime_config",
            "Runtime Config",
            "Keycloak Client ID",
            value=sval,
            location=loc,
            source=source,
            extra={"raw_key": key, "kind": "keycloak_client"},
        )
        return

    # Secrets first (tokens/keys/passwords) — mask the value.
    if _SECRET_RE.search(key) and not is_url:
        add(
            "secret",
            "Authentication",
            _secret_label(key),
            value=mask_secret(sval),
            location=loc,
            source=source,
            confidence="high",
            severity="High",
            extra={"raw_key": key, "scope": "runtime_config"},
        )
        return
    if _TOKEN_KEY_RE.search(key) and not is_url:
        sev = "Informational" if _THIRDPARTY_RE.search(key) else "Medium"
        add(
            "secret",
            "Authentication",
            _secret_label(key),
            value=mask_secret(sval),
            location=loc,
            source=source,
            confidence="high",
            severity=sev,
            extra={"raw_key": key, "scope": "runtime_config"},
        )
        return

    # URL-valued config -> classify the URL.
    if is_url:
        if _GATEWAY_RE.search(key):
            label = "API Gateway URL"
        elif _AUTH_URL_RE.search(key):
            label = "Authentication URL"
        elif _THIRDPARTY_RE.search(key):
            label = "Third-Party URL"
        elif _API_URL_RE.search(key):
            label = "API URL"
        else:
            label = "Service URL"
        add(
            "runtime_config",
            "Runtime Config",
            label,
            value=sval,
            location=loc,
            source=source,
            extra={"raw_key": key},
        )
        # A same-org-looking URL is also a related application candidate.
        add(
            "internal_app_ref",
            "Related Applications",
            sval,
            value=sval,
            location=loc,
            source=source,
            confidence="medium",
            extra={"raw_key": key},
        )
        # An API/Gateway URL's path is a referenced endpoint (feeds hidden-API diff).
        if label in {"API Gateway URL", "API URL"}:
            from urllib.parse import urlparse

            path = urlparse(sval).path or ""
            if path and path != "/":
                add(
                    "api_ref",
                    "Hidden API",
                    path,
                    location=path,
                    source="Runtime Config",
                    confidence="medium",
                    extra={"raw_key": key, "from_url": sval},
                )
        return

    # Feature-flaggy non-bool (e.g. "true" already handled) or generic config value.
    if _FEATURE_RE.search(key):
        add(
            "feature_flag",
            "Feature Flags",
            _humanize_flag(key),
            value=sval,
            location=loc,
            source=source,
            extra={"raw_key": key, "enabled": sval.lower() == "true"},
        )
        return
    # Generic short config scalar (region, env name, etc.).
    if len(sval) <= 64:
        add(
            "runtime_config",
            "Runtime Config",
            key,
            value=sval,
            location=loc,
            source=source,
            confidence="medium",
            extra={"raw_key": key},
        )


def _humanize_flag(key: str) -> str:
    k = re.sub(r"^(REACT_APP_|VITE_|NG_|NEXT_PUBLIC_|VUE_APP_)", "", key, flags=re.IGNORECASE)
    k = re.sub(r"_(MODULE|FEATURE|FLAG|ENABLED)$", "", k, flags=re.IGNORECASE)
    return k.replace("_", " ").title().strip() or key


def _secret_label(key: str) -> str:
    low = key.lower()
    if "map" in low:
        return "Map Token"
    if "client_secret" in low or "clientsecret" in low:
        return "OAuth Client Secret"
    if "refresh" in low:
        return "Refresh Token"
    if "access" in low:
        return "Access Token"
    return _humanize_flag(key) + " (secret)"
