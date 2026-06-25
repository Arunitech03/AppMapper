"""Features 18-20: Browser Intelligence aggregation, correlation & hidden
functionality.

Reads the browser-resident findings persisted as ``intel_findings`` (Sprint B
ingestion) plus the existing role/response/secret intelligence, and assembles the
report's browser sections, a correlation view (role ↔ feature ↔ route ↔ API ↔
sensitive fields), a Browser Architecture Map, and a Hidden Functionality report.
Pure/offline aggregation over already-captured data.
"""

from __future__ import annotations

from urllib.parse import urlparse


def _by_kind(data: dict, kind: str) -> list[dict]:
    return [f for f in data.get("intel_findings", []) or [] if f.get("kind") == kind]


def _classify_route(path: str) -> str:
    low = path.lower()
    if any(k in low for k in ("admin", "manage", "console")):
        return "Admin"
    if any(k in low for k in ("config", "setting", "preference")):
        return "Configuration"
    if any(k in low for k in ("report", "billing", "export", "analytics")):
        return "Reporting"
    return "User"


def build_browser_intelligence(data: dict) -> dict:
    """Assemble every Sprint-B browser section the report renders."""
    from modules.intelligence.sensitive_schema import analyze_sensitive_schemas

    feature_flags = [
        {"feature": f["name"], "enabled": (f.get("extra") or {}).get("enabled")}
        for f in _by_kind(data, "feature_flag")
    ]
    routes = sorted({f["name"] for f in _by_kind(data, "route")})
    route_inventory = [{"route": r, "type": _classify_route(r)} for r in routes]
    forms = [
        {
            "action": f.get("location") or f["name"],
            "method": (f.get("extra") or {}).get("method", "GET"),
            "fields": (f.get("extra") or {}).get("fields", []),
        }
        for f in _by_kind(data, "form")
    ]
    websockets = [
        {
            "url": f["name"],
            "messageTypes": (f.get("extra") or {}).get("messageTypes", []),
            "fields": (f.get("extra") or {}).get("fields", []),
        }
        for f in _by_kind(data, "websocket")
    ]
    indexeddb = [
        {"database": f["name"], "stores": (f.get("extra") or {}).get("stores", [])}
        for f in _by_kind(data, "indexeddb")
    ]
    cache_storage = [
        {"cache": f["name"], "entries": (f.get("extra") or {}).get("entries", [])}
        for f in _by_kind(data, "cache_entry")
    ]
    service_workers = [
        {"scriptURL": f["name"], "scope": f.get("location")}
        for f in _by_kind(data, "service_worker")
    ]
    runtime_config = [
        {
            "global": (f.get("extra") or {}).get("global"),
            "key": f["name"],
            "value": f.get("value_masked"),
        }
        for f in _by_kind(data, "runtime_config")
    ]
    framework_state = [
        {"framework": f["name"], "keys": (f.get("extra") or {}).get("keys", [])}
        for f in _by_kind(data, "framework_state")
    ]
    csp = [
        {"url": f["name"], "directives": (f.get("extra") or {}).get("directives", {})}
        for f in _by_kind(data, "csp")
    ]
    cors = [{"host": f["name"], **(f.get("extra") or {})} for f in _by_kind(data, "cors")]
    manifest = [{"href": f["name"]} for f in _by_kind(data, "manifest")]
    cookies = [
        {"name": f["name"], **(f.get("extra") or {}), "value_masked": f.get("value_masked")}
        for f in _by_kind(data, "cookie_attr")
    ]
    browser_secrets = [
        f
        for f in data.get("intel_findings", []) or []
        if (f.get("extra") or {}).get("scope") == "browser"
    ]

    sensitive_models = analyze_sensitive_schemas(data)
    hidden = build_hidden_functionality(data, feature_flags, routes)
    arch = _architecture_map(data, csp, cors, runtime_config)

    summary = {
        "feature_flags": len(feature_flags),
        "disabled_flags": sum(1 for f in feature_flags if f["enabled"] is False),
        "routes": len(routes),
        "forms": len(forms),
        "websockets": len(websockets),
        "indexeddb_stores": sum(len(d["stores"]) for d in indexeddb),
        "cache_entries": sum(len(c["entries"]) for c in cache_storage),
        "service_workers": len(service_workers),
        "browser_secrets": len(browser_secrets),
        "sensitive_models": len(sensitive_models),
        "hidden_functions": len(hidden),
        "trusted_domains": len(arch.get("trusted_domains", [])),
    }

    return {
        "summary": summary,
        "cookies": cookies,
        "feature_flags": feature_flags,
        "routes": route_inventory,
        "forms": forms,
        "websockets": websockets,
        "indexeddb": indexeddb,
        "cache_storage": cache_storage,
        "service_workers": service_workers,
        "runtime_config": runtime_config,
        "framework_state": framework_state,
        "csp": csp,
        "cors": cors,
        "manifest": manifest,
        "browser_secrets": browser_secrets,
        "sensitive_models": sensitive_models,
        "hidden_functionality": hidden,
        "architecture_map": arch,
        "correlation": correlate_browser(data, feature_flags, route_inventory),
    }


def build_hidden_functionality(
    data: dict, feature_flags: list[dict], routes: list[str]
) -> list[dict]:
    """Feature 19: referenced-not-observed APIs/routes, disabled flags, hidden admin."""
    from modules.intelligence.hidden_endpoint_discovery import find_hidden_endpoints

    out: list[dict] = []
    for h in find_hidden_endpoints(data):
        out.append(
            {
                "item": h["endpoint"],
                "type": "Hidden API",
                "reason": "Referenced but never observed",
                "priority": h["priority"],
            }
        )
    # Routes referenced in the SPA but never navigated to.
    visited = {
        n.get("path") or urlparse(n.get("url", "")).path for n in data.get("crawl_endpoints", [])
    }
    for r in routes:
        if r.split("#")[0] not in visited:
            pri = "high" if _classify_route(r) == "Admin" else "medium"
            out.append(
                {
                    "item": r,
                    "type": "Hidden Route",
                    "reason": "Route present but never visited",
                    "priority": pri,
                }
            )
    # Disabled feature flags hint at gated functionality.
    for f in feature_flags:
        if f["enabled"] is False:
            out.append(
                {
                    "item": f["feature"],
                    "type": "Disabled Feature",
                    "reason": "Feature flag disabled",
                    "priority": "medium",
                }
            )
    order = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda x: order.get(x["priority"], 3))
    return out


def correlate_browser(
    data: dict, feature_flags: list[dict], route_inventory: list[dict]
) -> list[dict]:
    """Feature 18: correlate role ↔ feature ↔ route ↔ API ↔ sensitive fields."""
    from modules.intelligence.business_modules import detect_business_modules

    rows = []
    modules = detect_business_modules(data)
    flags_by_token = {f["feature"].lower(): f for f in feature_flags}
    for m in modules[:12]:
        token = m["module"].split()[0].lower()
        related_routes = [r["route"] for r in route_inventory if token in r["route"].lower()]
        related_flag = next((k for k in flags_by_token if token in k), None)
        rows.append(
            {
                "module": m["module"],
                "evidence": m.get("evidence", []),
                "routes": related_routes[:5],
                "feature_flag": related_flag,
                "confidence": "high" if (related_routes or related_flag) else "medium",
            }
        )
    return rows


def _architecture_map(
    data: dict, csp: list[dict], cors: list[dict], runtime_config: list[dict]
) -> dict:
    """Browser Architecture Map: trusted/3rd-party domains + gateway/auth URLs."""
    trusted: set[str] = set()
    for c in csp:
        for srcs in (c.get("directives") or {}).values():
            for s in srcs:
                if s.startswith("http"):
                    trusted.add(urlparse(s).hostname or s)
                elif "." in s and not s.startswith("'"):
                    trusted.add(s)
    cors_hosts = sorted({c["host"] for c in cors})
    config_urls = sorted(
        {
            c["value"]
            for c in runtime_config
            if isinstance(c.get("value"), str) and c["value"].startswith("http")
        }
    )
    return {
        "trusted_domains": sorted(d for d in trusted if d),
        "cors_hosts": cors_hosts,
        "config_urls": config_urls,
    }
