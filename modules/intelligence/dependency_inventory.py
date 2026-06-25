"""Issue 9: Third-party dependency intelligence.

Classifies external dependencies (from JS URLs + captured request hosts) into
functional groups — Mapping, Cloud Storage, Icons, Authentication, CDN, Analytics,
Other — with a friendly product name for each.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# (host substring, group, product name)
DEP_SIGNATURES = (
    # Mapping
    ("mapbox", "Mapping", "Mapbox"),
    ("maps.googleapis.com", "Mapping", "Google Maps"),
    ("maps.google.com", "Mapping", "Google Maps"),
    ("arcgis.com", "Mapping", "ArcGIS"),
    ("basemaps", "Mapping", "ArcGIS Basemaps"),
    ("openstreetmap", "Mapping", "OpenStreetMap"),
    ("here.com", "Mapping", "HERE Maps"),
    # Cloud storage
    ("blob.core.windows.net", "Cloud Storage", "Azure Blob Storage"),
    ("s3.amazonaws.com", "Cloud Storage", "AWS S3"),
    (".s3.", "Cloud Storage", "AWS S3"),
    ("storage.googleapis.com", "Cloud Storage", "Google Cloud Storage"),
    # Icons
    ("iconify", "Icons", "Iconify"),
    ("simplesvg", "Icons", "Iconify (SimpleSVG)"),
    # Authentication
    ("login.microsoftonline.com", "Authentication", "Azure AD"),
    (".okta.com", "Authentication", "Okta"),
    (".auth0.com", "Authentication", "Auth0"),
    ("keycloak", "Authentication", "Keycloak"),
    # CDN
    ("cloudflare", "CDN", "Cloudflare"),
    ("akamai", "CDN", "Akamai"),
    ("fastly", "CDN", "Fastly"),
    ("jsdelivr", "CDN", "jsDelivr"),
    ("cdnjs", "CDN", "cdnjs"),
    ("unpkg.com", "CDN", "unpkg"),
    ("gstatic.com", "CDN", "Google Static"),
    # Analytics
    ("google-analytics", "Analytics", "Google Analytics"),
    ("googletagmanager", "Analytics", "Google Tag Manager"),
    ("segment.", "Analytics", "Segment"),
    ("mixpanel", "Analytics", "Mixpanel"),
    ("hotjar", "Analytics", "Hotjar"),
    ("sentry.io", "Analytics", "Sentry"),
    ("datadoghq", "Analytics", "Datadog"),
)
HOST_RE = re.compile(r"https?://([a-z0-9.\-]+)", re.IGNORECASE)


def _all_hosts(data: dict) -> set[str]:
    hosts: set[str] = set()
    for js in data.get("js_findings", []):
        if js.get("kind") in {"url", "interesting"}:
            hosts.update(m.lower() for m in HOST_RE.findall(js.get("value", "")))
    for src in ("har_requests", "burp_requests", "crawl_endpoints"):
        for r in data.get(src, []):
            h = urlparse(r.get("url", "")).hostname
            if h:
                hosts.add(h.lower())
    return hosts


def build_dependency_inventory(data: dict) -> dict[str, list[str]]:
    """Return {group: [product names]} of detected third-party dependencies."""
    groups: dict[str, set[str]] = {}
    for host in _all_hosts(data):
        for needle, group, name in DEP_SIGNATURES:
            if needle.lstrip(".") in host or needle in host:
                groups.setdefault(group, set()).add(name)
    return {g: sorted(names) for g, names in sorted(groups.items())}
