"""Sprint B.1: JavaScript Intelligence aggregator + runtime correlation.

Assembles the report's JS-scoped sections from the JS-derived ``intel_findings``
(runtime config, feature flags, frontend secrets, internal-app references, hidden
APIs/routes, source maps) and correlates feature ↔ API ↔ route ↔ role into
high-confidence hidden-module findings. Pure/offline aggregation over already
captured/parsed data.
"""

from __future__ import annotations

from urllib.parse import urlparse

# Related-application categorization by host/url keywords (Feature 3).
# Order matters — more specific categories must precede generic ones.
_APP_CATEGORIES: list[tuple[tuple[str, ...], str]] = [
    (("auth", "keycloak", "sso", "login", "oidc", "identity"), "Authentication"),
    (("data-quality", "dataquality", "dqc", "dq-"), "Data Quality"),
    (("gis", "geoserver", "spatial", "wms", "wfs", "arcgis"), "GIS"),
    (("cctv", "camera", "surveillance", "monitor", "monitoring", "alarm"), "Monitoring"),
    (("report", "reporting", "dashboard", "bi-"), "Reporting"),
    (("analytic", "insight", "anomaly", "ml-"), "Analytics"),
    (("admin", "portal", "management", "console"), "Administration"),
    (
        (
            "sewer",
            "protect",
            "flood",
            "scada",
            "ops",
            "operation",
            "control",
            "device",
            "odour",
            "om-",
        ),
        "Operations",
    ),
]

# Frontend secret severity refinement (Feature 3).
_INFO_SECRETS = ("Map Token", "Google API Key", "Mapbox Token", "Sentry DSN")
_CRITICAL_SECRETS = ("Private Key Block", "Hardcoded Password")
_HIGH_SECRETS = (
    "OAuth Client Secret",
    "AWS Access Key ID",
    "Azure Storage Key",
    "Stripe Secret Key",
    "SendGrid API Key",
    "GitHub Token",
    "Slack Token",
)


def _storage_secrets(data: dict) -> list[dict]:
    """Browser-storage tokens (localStorage/sessionStorage) as frontend secrets (F1)."""
    import re

    out = []
    tok_re = re.compile(r"(?i)(jwt|token|bearer|auth|secret|key|credential)")
    for a in data.get("auth_artifacts", []) or []:
        kind = (a.get("kind") or "").lower()
        name = a.get("name", "")
        if kind in {"local_storage", "session_storage"} and tok_re.search(name):
            label = "JWT" if "token" in name.lower() or "jwt" in name.lower() else "Storage Secret"
            out.append(
                {
                    "name": label,
                    "value_masked": a.get("value_masked"),
                    "location": f"{kind}.{name}",
                    "source": "Browser Storage",
                    "severity": "Medium",
                    "confidence": "high",
                }
            )
    return out


def _by(data: dict, **match) -> list[dict]:
    out = []
    for f in data.get("intel_findings", []) or []:
        if all(f.get(k) == v for k, v in match.items()):
            out.append(f)
    return out


# Feature-flag keys that imply a routable module (not a plain toggle).
_MODULE_HINT = (
    "module",
    "monitoring",
    "anomaly",
    "ews",
    "whatif",
    "emergency",
    "forecast",
    "reporting",
    "billing",
    "admin",
)


def _inferred_routes(flags: list[dict]) -> list[str]:
    """Candidate SPA routes inferred from enabled feature-flag modules (F4)."""
    import re

    routes: set[str] = set()
    for fl in flags:
        if fl["enabled"] is not True:
            continue
        raw = (fl.get("raw_key") or fl["feature"]).lower()
        if not any(h in raw for h in _MODULE_HINT):
            continue
        slug = re.sub(r"[^a-z0-9]+", "-", fl["feature"].lower()).strip("-")
        slug = re.sub(r"-(module|monitoring)$", "", slug)
        if slug:
            routes.add("/" + slug)
    return sorted(routes)


def _categorize_app(url: str) -> str:
    low = url.lower()
    for needles, label in _APP_CATEGORIES:
        if any(n in low for n in needles):
            return label
    return "Operations"


def _severity_of(name: str, current: str) -> str:
    if any(s in name for s in _CRITICAL_SECRETS):
        return "Critical"
    if any(s in name for s in _HIGH_SECRETS):
        return "High"
    if any(s in name for s in _INFO_SECRETS):
        return "Informational"
    return current or "Medium"


def build_javascript_intelligence(data: dict) -> dict:
    """Assemble the JS-scoped report sections + runtime correlation."""
    from modules.intelligence.browser_security import build_browser_security
    from modules.intelligence.hidden_endpoint_discovery import find_hidden_endpoints
    from modules.intelligence.pentest_targets import top_targets
    from modules.intelligence.runtime_config_risks import build_runtime_config_risks

    # Runtime configuration (URLs + keycloak realm/client) from JS.
    runtime_config = [
        {"setting": f["name"], "value": f.get("value_masked"), "location": f.get("location")}
        for f in _by(data, kind="runtime_config")
    ]
    keycloak = {
        f["name"]: f.get("value_masked")
        for f in _by(data, kind="runtime_config")
        if "Keycloak" in f["name"]
    }

    # Feature flags (enabled / disabled).
    flags = []
    for f in _by(data, kind="feature_flag"):
        extra = f.get("extra") or {}
        flags.append(
            {
                "feature": f["name"],
                "enabled": extra.get("enabled"),
                "raw_key": extra.get("raw_key", ""),
                "location": f.get("location"),
            }
        )
    enabled = [f["feature"] for f in flags if f["enabled"] is True]
    disabled = [f["feature"] for f in flags if f["enabled"] is False]

    # Frontend secrets (scope=runtime_config or scope=browser/js) with severity tiers.
    secrets = []
    for f in data.get("intel_findings", []) or []:
        if f.get("category") in {"API Keys", "Authentication"} and f.get("kind") in {
            "secret",
            "api_key",
            "jwt",
            "dsn",
            "private_key",
        }:
            secrets.append(
                {
                    "name": f["name"],
                    "value_masked": f.get("value_masked"),
                    "location": f.get("location"),
                    "source": f.get("source"),
                    "severity": _severity_of(f["name"], f.get("severity", "Medium")),
                    "confidence": f.get("confidence", "medium"),
                }
            )
    # Also surface browser-storage tokens as frontend secrets (F1).
    secrets += _storage_secrets(data)
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Informational": 3}
    secrets.sort(key=lambda s: sev_order.get(s["severity"], 4))

    # Related applications inventory (categorized) — from JS-referenced internal URLs.
    related = _related_applications(data)

    # Canonical service registry — resolve path-only endpoints to full URLs (B.3).
    from modules.intelligence.service_registry import build_service_registry

    registry = build_service_registry(data)
    resolve = registry["resolve"]

    # Hidden APIs (referenced-not-observed) + hidden routes — each fully qualified.
    hidden = find_hidden_endpoints(data)
    hidden_apis = []
    for h in hidden:
        if _is_route(h["endpoint"]):
            continue
        meta = resolve(h["endpoint"]) or {}
        hidden_apis.append({**h, **meta})
    js_api_inventory = sorted({f["name"] for f in _by(data, kind="api_ref")})

    visited = {
        n.get("path") or urlparse(n.get("url", "")).path for n in data.get("crawl_endpoints", [])
    }
    # Routes referenced in JS (literal) + inferred from enabled feature-flag modules.
    route_candidates: dict[str, dict] = {}
    for f in _by(data, kind="route"):
        route_candidates.setdefault(
            f["name"], {"route": f["name"], "source": "JS literal", "confidence": "medium"}
        )
    for r in _inferred_routes(flags):
        route_candidates.setdefault(
            r, {"route": r, "source": "Feature flag", "confidence": "medium"}
        )
    routes = sorted(route_candidates)
    hidden_routes = [
        {**route_candidates[r], "reason": "Referenced but never visited"}
        for r in routes
        if r.split("#")[0] not in visited
    ]

    # Source maps.
    source_maps = sorted({f["name"] for f in _by(data, kind="sourcemap")})

    correlation = _correlate(data, flags, js_api_inventory, routes, resolve)

    high_risk_modules = [c["feature"] for c in correlation if c["confidence"] == "high"]

    summary = {
        "runtime_config_values": len(runtime_config),
        "keycloak_realm": keycloak.get("Keycloak Realm"),
        "keycloak_client": keycloak.get("Keycloak Client ID"),
        "feature_flags": len(flags),
        "enabled_features": enabled,
        "disabled_features": disabled,
        "frontend_secrets": len(secrets),
        "critical_high_secrets": sum(1 for s in secrets if s["severity"] in {"Critical", "High"}),
        "related_applications": len(related),
        "js_apis": len(js_api_inventory),
        "hidden_apis": len(hidden_apis),
        "hidden_routes": len(hidden_routes),
        "source_maps": len(source_maps),
        "hidden_modules": len(high_risk_modules),
    }

    # Runtime Intelligence Summary V2 — actionable lists, not bare counts (F12).
    summary_v2 = {
        "frontend_secrets": _dedupe([s["name"] for s in secrets]),
        "authentication": {
            "keycloak_realm": keycloak.get("Keycloak Realm"),
            "keycloak_client": keycloak.get("Keycloak Client ID"),
        },
        "related_applications": [f"{a['host']} ({a['category']})" for a in related],
        "hidden_routes": [r["route"] for r in hidden_routes],
        "hidden_apis": [h.get("full_url") or h["endpoint"] for h in hidden_apis],
        "high_risk_modules": high_risk_modules,
        "enabled_features": enabled,
        "disabled_features": disabled,
    }

    return {
        "summary": summary,
        "summary_v2": summary_v2,
        "runtime_config": runtime_config,
        "keycloak": keycloak,
        "feature_flags": flags,
        "frontend_secrets": secrets,
        "related_applications": related,
        "js_api_inventory": js_api_inventory,
        "hidden_apis": hidden_apis,
        "hidden_routes": hidden_routes,
        "source_maps": source_maps,
        "correlation": correlation,
        "service_inventory": registry["services"],
        "runtime_config_risks": build_runtime_config_risks(data),
        "browser_security": build_browser_security(data),
        "top_targets": _resolve_targets(top_targets(data, n=20), resolve),
    }


def _resolve_targets(targets: list[dict], resolve) -> list[dict]:
    """Attach the full URL to each pentest target where the host is known (B.3)."""
    out = []
    for t in targets:
        meta = resolve(t["endpoint"]) or {}
        out.append(
            {
                **t,
                "full_url": meta.get("full_url"),
                "host": meta.get("host"),
                "service": meta.get("service"),
                "source": meta.get("source"),
            }
        )
    return out


def _dedupe(seq: list) -> list:
    out, seen = [], set()
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _related_applications(data: dict) -> list[dict]:
    """Categorized related-application inventory from JS/config-referenced URLs."""
    from modules.intelligence.domain_classifier import registrable_domain

    target = data.get("target", {}) or {}
    base = target.get("domain") or urlparse(target.get("url", "")).hostname or ""
    base_reg = registrable_domain(base) if base else ""

    apps: dict[str, dict] = {}
    # From runtime-config internal-app references + JS-discovered URLs.
    urls: set[str] = {f["name"] for f in _by(data, kind="internal_app_ref")}
    for js in data.get("js_findings", []) or []:
        if js.get("kind") == "url":
            urls.add(js.get("value", ""))
    for url in urls:
        host = (urlparse(url).hostname or "").lower()
        if not host or host == base.lower():
            continue
        if base_reg and registrable_domain(host) != base_reg:
            continue  # only same-org related apps
        apps.setdefault(host, {"host": host, "url": url, "category": _categorize_app(url)})
    return sorted(apps.values(), key=lambda a: (a["category"], a["host"]))


def _correlate(data, flags, apis, routes, resolve) -> list[dict]:
    """Feature 7: feature ↔ API ↔ route ↔ role → fully-qualified hidden-module rows."""
    import re

    from modules.intelligence.response_analyzer import analyze_responses

    def norm(s):
        return re.sub(r"[^a-z0-9]", "", s.lower())

    # Role values from runtime config (e.g. WW_ER_ADMIN, RTWIF_AD_admin).
    role_values = [
        f.get("value_masked")
        for f in _by(data, kind="runtime_config")
        if "ROLE" in ((f.get("extra") or {}).get("raw_key") or "").upper()
        and isinstance(f.get("value_masked"), str)
    ]
    # Response keys by normalized endpoint path (for correlation v2).
    from modules.intelligence.path_normalizer import normalize_path

    keys_by_ep = {
        normalize_path(r["endpoint"]): r.get("json_keys", []) for r in analyze_responses(data)
    }

    rows = []
    for fl in flags:
        token = norm(fl["feature"].split()[0])
        if len(token) < 3:
            continue
        related_apis = [a for a in apis if token in norm(a)]
        related_routes = [r for r in routes if token in norm(r)]
        related_roles = [v for v in role_values if token[:4] in norm(v)]
        admin_roles = [v for v in related_roles if re.search(r"(?i)admin|supervisor", v)]
        signals = bool(related_apis) + bool(related_routes) + bool(related_roles)
        if signals == 0:
            continue
        if admin_roles and signals >= 2:
            result = "High Confidence Administrative Module"
        elif signals >= 2:
            result = "High Confidence Hidden Module"
        else:
            result = "Possible Module"
        # Fully-qualify the primary API for the v2 columns.
        primary = related_apis[0] if related_apis else None
        meta = (resolve(primary) if primary else None) or {}
        rows.append(
            {
                "feature": fl["feature"],
                "module": fl["feature"],
                "enabled": fl["enabled"],
                "apis": related_apis[:5],
                "full_url": meta.get("full_url") or primary,
                "service": meta.get("service"),
                "host": meta.get("host"),
                "source": meta.get("source"),
                "response_keys": keys_by_ep.get(normalize_path(primary or ""), [])[:6],
                "routes": related_routes[:5],
                "roles": sorted(set(related_roles))[:5],
                "result": result,
                "confidence": "high" if signals >= 2 else "medium",
            }
        )
    rows.sort(key=lambda r: r["confidence"] != "high")
    return rows


def _is_route(path: str) -> bool:
    low = path.lower()
    return not any(h in low for h in ("/api", "/svc", "/rest", "/graphql", "/v1/", "/v2/", "/v3/"))
