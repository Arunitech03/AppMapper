"""Issue 3: Related internal application discovery.

Surfaces sibling applications hosted under the same organization (same registrable
domain) that the primary app references — typically found in JS (links to portals,
GIS, CCTV, etc.) and captured requests — and classifies each by name.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from modules.intelligence.domain_classifier import registrable_domain

# name keyword -> application type
APP_TYPES = (
    ("portal", "Portal"),
    ("gis", "GIS"),
    ("cctv", "CCTV"),
    ("odour", "Odour Management"),
    ("odor", "Odour Management"),
    ("sewer", "Sewer Protection"),
    ("data-quality", "Data Quality"),
    ("dataquality", "Data Quality"),
    ("flood", "Flood Management"),
    ("weather", "Weather"),
    ("asset", "Asset Management"),
    ("scada", "SCADA"),
    ("admin", "Administration"),
    ("gateway", "API Gateway"),
    ("proxy", "API Gateway"),
)
HOST_RE = re.compile(r"https?://([a-z0-9.\-]+)", re.IGNORECASE)


def _classify_app(host: str) -> str:
    low = host.lower()
    for needle, label in APP_TYPES:
        if needle in low:
            return label
    return "Internal Application"


def _candidate_hosts(data: dict) -> set[str]:
    hosts: set[str] = set()
    # From JS-discovered URLs.
    for js in data.get("js_findings", []):
        if js.get("kind") in {"url", "interesting"}:
            for m in HOST_RE.findall(js.get("value", "")):
                hosts.add(m.lower())
    # From captured requests.
    for src in ("har_requests", "burp_requests", "crawl_endpoints"):
        for r in data.get(src, []):
            h = urlparse(r.get("url", "")).hostname
            if h:
                hosts.add(h.lower())
    return hosts


def find_internal_apps(data: dict) -> list[dict]:
    """Return related internal applications (same org, not the base host)."""
    base = (
        (data.get("target", {}) or {}).get("domain")
        or urlparse((data.get("target", {}) or {}).get("url", "")).hostname
        or ""
    )
    base_reg = registrable_domain(base)

    apps: dict[str, dict] = {}
    for host in _candidate_hosts(data):
        if host == base or registrable_domain(host) != base_reg:
            continue
        apps.setdefault(host, {"host": host, "app_type": _classify_app(host)})
    return sorted(apps.values(), key=lambda a: a["host"])
