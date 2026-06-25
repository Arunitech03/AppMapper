"""Build the searchable knowledge inventory from all discovered data.

Each document is a flat record (kind, role, path, category, text) suitable for the
SQLite FTS5 index created in ``storage.database.Database``.
"""

from __future__ import annotations

from urllib.parse import urlparse


def build_documents(data: dict) -> list[dict]:
    """Flatten endpoints/functions/apis/js/captures into FTS documents."""
    docs: list[dict] = []

    def add(kind: str, path: str, *, role: str = "", category: str = "", text: str = "") -> None:
        docs.append(
            {
                "kind": kind,
                "role": role,
                "path": path,
                "category": category,
                "text": " ".join(filter(None, [path, category, text])),
            }
        )

    for d in data.get("directories", []):
        add("directory", d["path"], category=d.get("category", ""))

    for ep in data.get("crawl_endpoints", []):
        add(
            "endpoint",
            ep["path"],
            role=ep.get("role", ""),
            category=ep.get("source", ""),
            text=ep.get("title") or "",
        )

    for api in data.get("api_intel", []):
        methods = api.get("methods") or ""
        params = api.get("parameters") or ""
        flag = "authz-sensitive" if api.get("authz_sensitive") else ""
        add("api", api["path"], category="api", text=f"{methods} {params} {flag}")

    for fn in data.get("sensitive_functions", []):
        add(
            "function",
            fn["endpoint"],
            role=fn.get("role") or "",
            category=fn.get("category", ""),
            text=f"{fn.get('subcategory','')} {fn.get('category','')}",
        )

    for js in data.get("js_findings", []):
        add("js", js.get("value", ""), category=js.get("kind", ""), text=js.get("value", ""))

    for cap_key, kind in (("har_requests", "har"), ("burp_requests", "burp")):
        for r in data.get(cap_key, []):
            path = urlparse(r["url"]).path if r.get("url") else ""
            add(kind, path, role=r.get("role") or "", text=r.get("method", ""))

    # External domain intelligence: hosts + high-value endpoints become searchable.
    from modules.intelligence.domain_classifier import build_domain_intel

    di = build_domain_intel(data)
    for hh in di.get("hosts", []):
        add(
            "host",
            hh["host"],
            role=",".join(hh.get("roles", [])),
            category=hh["classification"],
            text=f"{hh['host']} {hh['classification']} {' '.join(hh.get('roles', []))}",
        )
    for hv in di.get("high_value", []):
        add(
            "high_value",
            hv.get("path") or hv.get("host", ""),
            role=",".join(hv.get("roles", [])),
            category=hv["classification"],
            text=f"{hv['endpoint']} {hv['classification']}",
        )

    # Unified asset intelligence: services, internal apps, dependencies, modules.
    from modules.intelligence.asset_inventory import build_asset_intelligence

    ai = build_asset_intelligence(data)
    for svc in ai.get("services", []):
        add("service", svc, category="backend service", text=f"{svc} service backend")
    for app in ai.get("internal_apps", []):
        add(
            "internal_app",
            app["host"],
            category=app["app_type"],
            text=f"{app['host']} {app['app_type']}",
        )
    for group, names in ai.get("dependencies", {}).items():
        for name in names:
            add("dependency", name, category=group, text=f"{name} {group} dependency")
    for m in ai.get("business_modules", []):
        add("business_module", m["module"], category="module", text=f"{m['module']} module")

    return docs
