"""Issue 2 + 4 + 11: Unified asset inventory and infrastructure aggregation.

Consolidates the fragmented intelligence (JS, HAR, Burp, exploration, crawl,
Swagger) into one coherent view: a unified API inventory (with the sources each
endpoint was seen in — including JS-discovered APIs), a service inventory, and a
single ``build_asset_intelligence`` aggregator that assembles every Issue's output
into the structure the report and AI summary consume.
"""

from __future__ import annotations

from urllib.parse import urlparse

from modules.intelligence.attack_surface import score_attack_surface
from modules.intelligence.business_modules import detect_business_modules
from modules.intelligence.dependency_inventory import build_dependency_inventory
from modules.intelligence.domain_classifier import build_domain_intel
from modules.intelligence.gateway_detector import all_services, detect_gateways, service_of_path
from modules.intelligence.internal_apps import find_internal_apps
from modules.intelligence.path_normalizer import normalize_path
from modules.intelligence.response_analyzer import analyze_responses

API_HINTS = ("/api", "/graphql", "/rest", "/v1/", "/v2/", "/v3/")

# Issue 4: static assets and GIS/map resources are NOT application APIs.
STATIC_EXTENSIONS = (
    ".css",
    ".js",
    ".mjs",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".bmp",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
)
GIS_MARKERS = ("/tiles/", "/tile/", "wmts", "/wms", "/wfs", "basemap", "/mapserver", "/arcgis")


def _is_static(path: str) -> bool:
    return (path or "").lower().endswith(STATIC_EXTENSIONS)


def _is_gis(path: str) -> bool:
    low = (path or "").lower()
    if any(m in low for m in GIS_MARKERS):
        return True
    # Numeric tile triples like /18/130943/100204 (z/x/y) anywhere in the path.
    segs = [s for s in low.split("/") if s]
    for i in range(len(segs) - 2):
        if segs[i].isdigit() and segs[i + 1].isdigit() and segs[i + 2].isdigit():
            return True
    return False


def _is_api(path: str) -> bool:
    low = path.lower()
    return any(h in low for h in API_HINTS) or low.endswith(".json")


def _want(path: str, source: str | None = None) -> bool:
    """Whether a captured path belongs in the asset partition at all.

    Static/GIS paths are always taken (so they populate their own buckets); other
    paths are taken when they look like an API — by hint, by backing a named
    service (``/device-access/svc/...``), or because the source flagged them API.
    Plain HTML navigations are left out of the inventory.
    """
    if _asset_kind(path) != "api":
        return True
    return _is_api(path) or service_of_path(path) is not None or source == "api"


def _asset_kind(path: str) -> str:
    """Classify a path as 'static', 'gis', or 'api' (most specific first)."""
    if _is_static(path):
        return "static"
    if _is_gis(path):
        return "gis"
    return "api"


def partition_assets(data: dict) -> dict:
    """Partition every observed path into API / static / GIS buckets.

    The API bucket is keyed by the **normalized** path (``/zone/{id}``) so dynamic
    identifiers collapse into one endpoint with a hit count; static and GIS paths
    are listed (de-duplicated, normalized) but kept out of the API inventory.
    """
    apis: dict[str, dict] = {}
    static: set[str] = set()
    gis: set[str] = set()

    def add(raw_path: str, method: str, source: str) -> None:
        if not raw_path:
            return
        kind = _asset_kind(raw_path)
        norm = normalize_path(raw_path)
        if kind == "static":
            static.add(norm)
            return
        if kind == "gis":
            gis.add(norm)
            return
        rec = apis.setdefault(
            norm,
            {
                "path": norm,
                "methods": set(),
                "sources": set(),
                "service": service_of_path(norm),
                "hits": 0,
            },
        )
        if method:
            rec["methods"].add(method.upper())
        rec["sources"].add(source)
        rec["hits"] += 1

    # JS-discovered API endpoints (Issue 4: JS APIs included).
    for js in data.get("js_findings", []):
        if js.get("kind") == "api_endpoint":
            add(js.get("value", ""), "GET", "JS")
    # Swagger/OpenAPI discovery + analyzed APIs.
    for ep in data.get("api_endpoints", []):
        add(ep.get("path", ""), ep.get("method", "GET"), "Swagger")
    for ep in data.get("api_intel", []):
        add(ep.get("path", ""), "", "Swagger")
    # Exploration / crawl endpoints flagged as API (static/GIS still partitioned).
    for ep in data.get("crawl_endpoints", []):
        path = ep.get("path", "")
        if _want(path, ep.get("source")):
            add(path, ep.get("method", "GET"), "Exploration")
    # Captured traffic.
    for r in data.get("har_requests", []):
        path = urlparse(r.get("url", "")).path
        if _want(path):
            add(path, r.get("method", "GET"), "HAR")
    for r in data.get("burp_requests", []):
        path = urlparse(r.get("url", "")).path
        if _want(path):
            add(path, r.get("method", "GET"), "Burp")

    api_list = [
        {
            "path": a["path"],
            "methods": sorted(a["methods"]),
            "sources": sorted(a["sources"]),
            "service": a["service"],
            "hits": a["hits"],
        }
        for a in apis.values()
    ]
    api_list.sort(key=lambda x: x["path"])
    return {
        "apis": api_list,
        "static_assets": sorted(static),
        "gis_assets": sorted(gis),
    }


def unified_api_inventory(data: dict) -> list[dict]:
    """Normalized, noise-free API inventory (static + GIS excluded)."""
    return partition_assets(data)["apis"]


def build_asset_intelligence(data: dict) -> dict:
    """The single aggregator the report + AI summary consume."""
    di = build_domain_intel(data)
    gateways = detect_gateways(data)
    gateway_hosts = {g["host"] for g in gateways}
    services = all_services(data)
    # Related apps exclude the gateway hosts (shown in their own section).
    internal = [a for a in find_internal_apps(data) if a["host"] not in gateway_hosts]
    deps = build_dependency_inventory(data)
    base = di.get("base_host", "")

    infrastructure = {
        "primary_application": base,
        "identity_provider": di.get("auth_infra", {}).get("identity_provider", "Unknown"),
        "identity_realm": _idp_realm(data),
        "api_gateways": [g["host"] for g in gateways],
        "backend_services": services,
        "related_applications": [a["host"] for a in internal],
        "third_party_providers": [
            n for g in ("Mapping", "Analytics", "CDN") for n in deps.get(g, [])
        ],
        "cloud_storage": deps.get("Cloud Storage", []),
    }

    assets = partition_assets(data)
    return {
        "api_inventory": assets["apis"],
        "static_assets": assets["static_assets"],
        "gis_assets": assets["gis_assets"],
        "services": services,
        "gateways": gateways,
        "internal_apps": internal,
        "business_modules": detect_business_modules(data),
        "dependencies": deps,
        "response_intelligence": analyze_responses(data),
        "attack_surface": score_attack_surface(data),
        "infrastructure": infrastructure,
    }


def _idp_realm(data: dict) -> str | None:
    rows = data.get("idp_info") or []
    realm = rows[0].get("realm") if rows else None
    if realm:
        return realm
    # Fall back to analyzing captured artifacts (e.g. report-only over imported
    # data where the orchestrator IdP-reconcile phase never ran).
    from modules.auth.idp_analyzer import analyze_idp

    return analyze_idp(data).realm
