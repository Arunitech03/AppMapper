"""Issue 5: API gateway detection.

Identifies API-gateway hosts (by name or by fronting multiple back-end services)
and the services routed behind them. A "service" is the leading path segment of an
API route, e.g. ``/floods-service/api/v1/...`` -> ``floods-service``.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

GATEWAY_NAME_HINTS = ("gateway", "proxy", "apigw", "api-gw", "kong", "gw-", "-gw")
# A service segment: hyphenated or service/api/rest/backend-flavored, not a version.
_SERVICE_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)+$", re.IGNORECASE)
_GENERIC = {"api", "rest", "v1", "v2", "v3", "auth", "static", "assets", "public", "ui"}
_SERVICE_HINTS = ("service", "api", "rest", "backend", "svc")


def service_of_path(path: str) -> str | None:
    """Extract the back-end service name from an API path's leading segment."""
    parts = [p for p in (path or "").split("/") if p]
    if not parts:
        return None
    seg = parts[0].lower()
    if seg in _GENERIC:
        # e.g. /api/floods-service/... -> look one deeper
        if len(parts) > 1:
            seg2 = parts[1].lower()
            if seg2 not in _GENERIC and (
                _SERVICE_RE.match(seg2) or any(h in seg2 for h in _SERVICE_HINTS)
            ):
                return seg2
        return None
    if _SERVICE_RE.match(seg) or any(h in seg for h in _SERVICE_HINTS):
        return seg
    return None


def detect_gateways(data: dict) -> list[dict]:
    """Return [{host, services:[...]}] for detected API-gateway hosts."""
    host_services: dict[str, set[str]] = {}
    for src in ("har_requests", "burp_requests", "crawl_endpoints"):
        for r in data.get(src, []):
            u = urlparse(r.get("url", ""))
            host = (u.hostname or "").lower()
            if not host:
                continue
            svc = service_of_path(u.path or "")
            if svc:
                host_services.setdefault(host, set()).add(svc)

    gateways = []
    for host, services in sorted(host_services.items()):
        is_named = any(h in host for h in GATEWAY_NAME_HINTS)
        if is_named or len(services) >= 2:
            gateways.append({"host": host, "services": sorted(services)})
    return gateways


def all_services(data: dict) -> list[str]:
    """All distinct back-end service names across captured requests."""
    services: set[str] = set()
    for src in ("har_requests", "burp_requests", "crawl_endpoints"):
        for r in data.get(src, []):
            svc = service_of_path(urlparse(r.get("url", "")).path or "")
            if svc:
                services.add(svc)
    return sorted(services)
