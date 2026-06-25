"""External Domain Intelligence & API Relationship Mapping.

Processes every captured request (exploration / HAR / Burp / authenticated crawl),
classifies each host it talks to, and derives the full domain-intelligence picture:
hostname inventory, internal APIs, third-party services, authentication
infrastructure, an application relationship map, role-based API visibility, and the
high-value attack surface.

Pure / offline analysis over already-stored request data — it makes no requests.
"""

from __future__ import annotations

from urllib.parse import urlparse

from modules.intelligence.function_detector import detect_functions

# ---------------------------------------------------------------------------
# Host classification signatures
# ---------------------------------------------------------------------------

AUTH_HOST_SIGS = (
    "login.microsoftonline.com",
    "login.windows.net",
    "sts.windows.net",
    ".okta.com",
    ".oktapreview.com",
    ".auth0.com",
    "accounts.google.com",
    ".pingidentity.com",
    "pingone.com",
    ".onelogin.com",
    "login.salesforce.com",
    "cloudflareaccess.com",
    "keycloak",
)
AUTH_PATH_SIGS = ("/realms/", "/auth/realms/", "/openid-connect/", "/oauth2/", "/adfs/", "/saml")
PAYMENT_SIGS = (
    "stripe.com",
    "paypal.com",
    "braintreegateway.com",
    "adyen.com",
    "squareup.com",
    "razorpay.com",
    "checkout.com",
    "worldpay",
    "authorize.net",
)
ANALYTICS_SIGS = (
    "google-analytics.com",
    "analytics.google.com",
    "googletagmanager.com",
    "segment.com",
    "segment.io",
    "mixpanel.com",
    "amplitude.com",
    "hotjar.com",
    "matomo",
    "plausible.io",
    "sentry.io",
    "datadoghq.com",
    "newrelic.com",
    "nr-data.net",
    "fullstory.com",
    "clarity.ms",
    "doubleclick.net",
    "intercom.io",
)
CDN_SIGS = (
    "cloudfront.net",
    "akamai",
    "akamaihd.net",
    "fastly.net",
    "jsdelivr.net",
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "gstatic.com",
    "fonts.googleapis.com",
    "bootstrapcdn.com",
    "code.jquery.com",
    "fontawesome.com",
    "cloudflareinsights.com",
)
MICROSERVICE_HINTS = ("gateway", "api-gw", "apigw", "svc", "-ms-", "service-", "mesh", "kong")

# Same-org classifications considered "internal" infrastructure.
INTERNAL_CLASSIFICATIONS = {"Primary Application", "Internal API", "Microservice", "API Gateway"}
INTERNAL_API_CLASSIFICATIONS = {"Internal API", "Microservice", "API Gateway"}

# Two-level public suffixes for registrable-domain detection (best-effort, no PSL dep).
_TWO_LEVEL_TLDS = {
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.in",
    "co.jp",
    "com.br",
    "co.nz",
    "co.za",
    "com.mx",
    "com.sg",
    "com.tr",
}

API_PATH_HINTS = ("/api", "/graphql", "/rest", "/v1/", "/v2/", "/v3/")
ACCESSIBLE_STATUSES = {200, 201, 202, 203, 204, 206}
DENIED_STATUSES = {401, 403}

# function-detector category -> high-value label
HIGH_VALUE_LABELS = {
    "Administrative": "Admin",
    "User Management": "User Management",
    "File Handling": "File Upload",
    "Data Operations": "Export",
    "Authentication": "Authentication",
}


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 (organizational domain) for a host."""
    labels = (host or "").lower().split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host or ""


def _backend_services(paths: set[str]) -> list[str]:
    """Distinct backend service names routed under this host's paths."""
    from modules.intelligence.gateway_detector import service_of_path

    return sorted({s for p in paths if (s := service_of_path(p))})


def classify_host(host: str, paths: set[str], base_host: str) -> tuple[str, str]:
    """Classify a host, returning (classification, evidence).

    Issue 6: a same-org host that fronts **multiple** backend services is an
    **API Gateway**; one backing service (or just a gateway-ish name) is a
    **Microservice**; otherwise an Internal API.
    """
    h = (host or "").lower()
    if not h:
        return "Unknown", ""
    if h == (base_host or "").lower():
        return "Primary Application", "base url"

    if any(sig.lstrip(".") in h for sig in AUTH_HOST_SIGS):
        return "Authentication Provider", f"host:{h}"
    if any(p in path for path in paths for p in AUTH_PATH_SIGS):
        return "Authentication Provider", "path:oidc/saml"
    if any(sig in h for sig in PAYMENT_SIGS):
        return "Payment Provider", f"host:{h}"
    if any(sig in h for sig in ANALYTICS_SIGS):
        return "Analytics", f"host:{h}"
    if any(sig in h for sig in CDN_SIGS):
        return "CDN", f"host:{h}"

    if registrable_domain(h) == registrable_domain(base_host):
        services = _backend_services(paths)
        if len(services) >= 2:
            shown = ", ".join(services[:4]) + ("…" if len(services) > 4 else "")
            return "API Gateway", f"{len(services)} backend services: {shown}"
        if len(services) == 1:
            return "Microservice", f"service:{services[0]}"
        if any(hint in h for hint in MICROSERVICE_HINTS):
            return "Microservice", f"name-hint:{h}"
        return "Internal API", f"same-org:{h}"
    return "Third Party Service", f"external:{h}"


def _iter_requests(data: dict):
    """Yield (host, path, method, role, status) across all request sources."""
    for ep in data.get("crawl_endpoints", []):
        u = urlparse(ep.get("url", ""))
        yield u.hostname or "", u.path or "/", ep.get("method", "GET"), ep.get("role"), ep.get(
            "status_code"
        )
    for r in data.get("har_requests", []):
        u = urlparse(r.get("url", ""))
        yield u.hostname or "", u.path or "/", r.get("method", "GET"), r.get("role"), r.get(
            "response_status"
        )
    for r in data.get("burp_requests", []):
        u = urlparse(r.get("url", ""))
        yield u.hostname or "", u.path or "/", r.get("method", "GET"), r.get("role"), r.get(
            "response_status"
        )


def _is_api(path: str) -> bool:
    low = path.lower()
    return any(h in low for h in API_PATH_HINTS)


def build_domain_intel(data: dict) -> dict:
    """Derive the full domain-intelligence structure from stored requests."""
    base_host = (
        (data.get("target", {}) or {}).get("domain")
        or urlparse((data.get("target", {}) or {}).get("url", "")).hostname
        or ""
    )

    # Aggregate per host.
    hosts: dict[str, dict] = {}
    for host, path, method, role, status in _iter_requests(data):
        if not host:
            continue
        hi = hosts.setdefault(
            host,
            {
                "paths": set(),
                "methods": set(),
                "roles": set(),
                "statuses": set(),
                "requests": 0,
                "endpoints": {},
            },
        )
        hi["requests"] += 1
        hi["paths"].add(path)
        hi["methods"].add(method)
        if role:
            hi["roles"].add(role)
        if status is not None:
            hi["statuses"].add(status)
        key = (method.upper(), path)
        hi["endpoints"].setdefault(key, set())
        if role:
            hi["endpoints"][key].add(role)

    # Classify + summarize each host.
    inventory: list[dict] = []
    for host, hi in sorted(hosts.items()):
        classification, evidence = classify_host(host, hi["paths"], base_host)
        roles = sorted(hi["roles"])
        api_count = sum(1 for (_m, p) in hi["endpoints"] if _is_api(p))
        auth_required = bool(hi["statuses"] & DENIED_STATUSES) or (
            bool(roles) and "anonymous" not in roles
        )
        internal = classification in INTERNAL_CLASSIFICATIONS
        external = registrable_domain(host) != registrable_domain(base_host)
        inventory.append(
            {
                "host": host,
                "classification": classification,
                "evidence": evidence,
                "confidence": "high" if classification == "API Gateway" else "medium",
                "requests": hi["requests"],
                "apis": api_count,
                "methods": sorted(hi["methods"]),
                "roles": roles,
                "auth_required": auth_required,
                "internal": internal,
                "external": external,
                "_endpoints": hi["endpoints"],
            }
        )

    # Internal APIs (same org, not the base host).
    internal_apis = []
    for h in inventory:
        if h["classification"] in INTERNAL_API_CLASSIFICATIONS:
            endpoints = [
                {"method": m, "path": p, "roles": sorted(r)}
                for (m, p), r in sorted(h["_endpoints"].items())
            ]
            internal_apis.append(
                {
                    "host": h["host"],
                    "count": len(endpoints),
                    "roles": h["roles"],
                    "endpoints": endpoints,
                }
            )

    # Third-party services (genuinely external organizations).
    third_party = [
        {
            "host": h["host"],
            "classification": h["classification"],
            "requests": h["requests"],
            "roles": h["roles"],
        }
        for h in inventory
        if h["external"] and h["classification"] != "Unknown"
    ]

    # Authentication infrastructure (idp_info + auth-classified hosts).
    idp = (data.get("idp_info") or [{}])[0]
    auth_hosts = [h["host"] for h in inventory if h["classification"] == "Authentication Provider"]
    auth_infra = {
        "identity_provider": idp.get("identity_provider", "Unknown"),
        "authentication_type": idp.get("authentication_type", "Unknown"),
        "evidence": ([idp.get("metadata_url")] if idp.get("metadata_url") else [])
        + [f"https://{h}" for h in auth_hosts],
        "hosts": auth_hosts,
    }

    # Relationship map: base -> each other host.
    edges = [
        {"to": h["host"], "kind": h["classification"]} for h in inventory if h["host"] != base_host
    ]
    relationships = {"base": base_host, "edges": edges}

    # Role-based API visibility (per host).
    api_visibility = [
        {
            "host": h["host"],
            "roles": h["roles"],
            "admin_only": h["roles"] == ["admin"] if h["roles"] else False,
        }
        for h in inventory
        if h["internal"]
    ]

    # High-value attack surface (sensitive functions on host+path, with role visibility).
    endpoint_recs = []
    host_of_path: dict[str, str] = {}
    for h in inventory:
        for (m, p), _roles in h["_endpoints"].items():
            endpoint_recs.append({"path": p, "role": None, "method": m})
            host_of_path[p] = h["host"]
    high_value: list[dict] = []
    seen_hv: set[tuple[str, str]] = set()
    for fn in detect_functions(endpoint_recs):
        label = HIGH_VALUE_LABELS.get(fn.category)
        if not label:
            continue
        host = host_of_path.get(fn.endpoint, base_host)
        roles = sorted(
            {
                r
                for h in inventory
                if h["host"] == host
                for (_m, p), rs in h["_endpoints"].items()
                if p == fn.endpoint
                for r in rs
            }
        )
        key = (host, fn.endpoint)
        if key in seen_hv:
            continue
        seen_hv.add(key)
        high_value.append(
            {
                "endpoint": f"{host}{fn.endpoint}",
                "host": host,
                "path": fn.endpoint,
                "classification": label,
                "roles": roles,
            }
        )
    # Payment endpoints/hosts are high-value too.
    for h in inventory:
        if h["classification"] == "Payment Provider":
            high_value.append(
                {
                    "endpoint": h["host"],
                    "host": h["host"],
                    "path": "",
                    "classification": "Payment",
                    "roles": h["roles"],
                }
            )

    # Infrastructure summary (structured; safe to hand to an LLM).
    by_class: dict[str, int] = {}
    for h in inventory:
        by_class[h["classification"]] = by_class.get(h["classification"], 0) + 1
    dependencies = sorted(
        {
            h["host"]
            for h in inventory
            if h["classification"]
            in {"Authentication Provider", "Payment Provider", "Third Party Service"}
        }
    )
    functional_areas = sorted({hv["classification"] for hv in high_value})
    infrastructure_summary = {
        "internal_apis": by_class.get("Internal API", 0)
        + by_class.get("Microservice", 0)
        + by_class.get("API Gateway", 0),
        "auth_providers": by_class.get("Authentication Provider", 0),
        "third_party": len(third_party),
        "analytics": by_class.get("Analytics", 0),
        "cdn": by_class.get("CDN", 0),
        "payment": by_class.get("Payment Provider", 0),
        "dependencies": dependencies,
        "functional_areas": functional_areas,
    }

    # Strip private aggregation keys from the public inventory.
    clean_inventory = [{k: v for k, v in h.items() if not k.startswith("_")} for h in inventory]

    return {
        "base_host": base_host,
        "hosts": clean_inventory,
        "internal_apis": internal_apis,
        "third_party": third_party,
        "auth_infra": auth_infra,
        "relationships": relationships,
        "api_visibility": api_visibility,
        "high_value": high_value,
        "infrastructure_summary": infrastructure_summary,
    }
