"""Issue 6: Business module detection.

Infers the application's functional/business modules from URL paths, API/service
names, and navigation routes (crawl page titles) using a domain keyword map.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# module -> keywords (matched against normalized path/title text)
MODULE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "Emergency Response": ("emergency", "incident", "alert", "response", "alarm"),
    "Flood Prediction": ("flood", "prediction", "forecast", "rtwhatif", "whatif", "rainfall"),
    "Weather Intelligence": ("weather", "rain", "meteo", "precipitation", "storm"),
    "GIS": ("gis", "geo", "spatial", "layer", "hierarchy", "basemap", "cartography"),
    "Asset Management": ("asset", "equipment", "sensor", "device", "infrastructure"),
    "Work Orders": ("workorder", "work-order", "ticket", "task", "order", "maintenance"),
    "Hotspots": ("hotspot", "hot-spot"),
    "Scenario Planning": ("scenario", "simulation", "planning", "model"),
    "Reporting": ("report", "dashboard", "analytics", "export"),
    "User Management": ("user", "role", "permission", "account", "member", "group"),
    "Administration": ("admin", "config", "configuration", "settings", "system"),
}

_CAMEL = re.compile(r"([a-z0-9])([A-Z])")
_NONWORD = re.compile(r"[^a-z0-9]+")


def _tokens(text: str) -> str:
    spaced = _CAMEL.sub(r"\1 \2", text)
    return _NONWORD.sub(" ", spaced).lower()


def detect_business_modules(data: dict) -> list[dict]:
    """Return ranked business modules with evidence counts."""
    corpus: list[str] = []
    for src in ("har_requests", "burp_requests", "crawl_endpoints"):
        for r in data.get(src, []):
            corpus.append(_tokens(urlparse(r.get("url", "")).path or ""))
    for ep in data.get("crawl_endpoints", []):
        if ep.get("title"):
            corpus.append(_tokens(ep["title"]))
    for js in data.get("js_findings", []):
        if js.get("kind") in {"api_endpoint", "url"}:
            corpus.append(_tokens(js.get("value", "")))
    for api in data.get("api_intel", []):
        corpus.append(_tokens(api.get("path", "")))

    blob = "\n".join(corpus)
    modules = []
    for module, keywords in MODULE_KEYWORDS.items():
        hits = sum(blob.count(kw) for kw in keywords)
        if hits:
            matched = sorted({kw for kw in keywords if kw in blob})
            modules.append({"module": module, "score": hits, "evidence": matched})
    modules.sort(key=lambda m: (-m["score"], m["module"]))
    return modules
