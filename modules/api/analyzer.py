"""Feature 5: API intelligence.

Aggregates discovered API endpoints into per-path intelligence (methods,
parameters, response content-types) and flags endpoints that expose object
identifiers (user/account/role/file ids, ``{id}`` templates, numeric/uuid path
segments) as *potentially authorization-sensitive*.

Classification only — it never sends requests and never attempts to exploit IDOR
or any authorization weakness.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from models.schemas import ApiIntel

# Identifier-like parameter names worth authorization review.
ID_PARAM_RE = re.compile(
    r"^(id|.*_id|.*id|uid|guid|uuid|user|userid|account|accountid|role|roleid|"
    r"file|fileid|fname|doc|docid|order|orderid|customer|customerid)$",
    re.IGNORECASE,
)
# Identifier-like path segments: {id}, :id, numeric, or uuid.
ID_SEGMENT_RE = re.compile(
    r"^(\{[^}]+\}|:[a-z_]+|\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
    re.IGNORECASE,
)
API_HINTS = ("/api", "/graphql", "/rest", "/v1/", "/v2/", "/v3/")


def _is_api_path(path: str, content_type: str | None = None) -> bool:
    low = path.lower()
    if any(h in low for h in API_HINTS):
        return True
    if low.endswith(".json"):
        return True
    return bool(content_type and "json" in content_type)


def _templatize(path: str) -> str:
    """Collapse identifier path segments to ``{id}`` so variants group together."""
    parts = []
    for seg in path.split("/"):
        parts.append("{id}" if seg and ID_SEGMENT_RE.match(seg) else seg)
    return "/".join(parts) or "/"


def _csv_to_list(value) -> list[str]:
    if isinstance(value, list):
        return value
    if isinstance(value, str) and value:
        return [v for v in value.split(",") if v]
    return []


def analyze_apis(data: dict) -> list[ApiIntel]:
    """Build per-path :class:`ApiIntel` from all API-bearing sources."""
    agg: dict[str, dict] = {}

    def bucket(path: str) -> dict:
        key = _templatize(path)
        return agg.setdefault(
            key,
            {
                "methods": set(),
                "parameters": set(),
                "response_types": set(),
                "raw_paths": set(),
                "hosts": set(),
            },
        )

    # OpenAPI/Swagger/GraphQL endpoints discovered in Tier 1 (spec-relative; no host).
    for ep in data.get("api_endpoints", []):
        b = bucket(ep["path"])
        b["methods"].add((ep.get("method") or "GET").upper())
        b["parameters"].update(_csv_to_list(ep.get("parameters")))
        b["raw_paths"].add(ep["path"])

    # Crawl endpoints that look like APIs (carry the full request URL → host).
    for ep in data.get("crawl_endpoints", []):
        if ep.get("source") == "api" or _is_api_path(ep["path"], ep.get("content_type")):
            b = bucket(ep["path"])
            b["methods"].add((ep.get("method") or "GET").upper())
            if ep.get("content_type"):
                b["response_types"].add(ep["content_type"])
            b["raw_paths"].add(ep["path"])
            b["hosts"].add(urlparse(ep.get("url") or "").netloc)

    # HAR / Burp captured requests against API paths.
    for r in data.get("har_requests", []):
        parsed = urlparse(r["url"])
        if _is_api_path(parsed.path, r.get("response_content_type")):
            b = bucket(parsed.path)
            b["methods"].add((r.get("method") or "GET").upper())
            b["parameters"].update(_csv_to_list(r.get("query_params")))
            b["hosts"].add(parsed.netloc)
            if r.get("response_content_type"):
                b["response_types"].add(r["response_content_type"])
    for r in data.get("burp_requests", []):
        parsed = urlparse(r["url"])
        if _is_api_path(parsed.path):
            b = bucket(parsed.path)
            b["methods"].add((r.get("method") or "GET").upper())
            b["parameters"].update(_csv_to_list(r.get("parameters")))
            b["hosts"].add(parsed.netloc)

    results: list[ApiIntel] = []
    for path, b in sorted(agg.items()):
        params = sorted(b["parameters"])
        id_params = [p for p in params if ID_PARAM_RE.match(p)]
        templated_ids = "{id}" in path or ":" in path
        authz = bool(id_params or templated_ids)
        reason = None
        if authz:
            bits = []
            if id_params:
                bits.append("identifier parameters: " + ", ".join(id_params))
            if templated_ids:
                bits.append("identifier path segment")
            reason = "Potential Authorization-Sensitive Endpoint (" + "; ".join(bits) + ")"
        results.append(
            ApiIntel(
                path=path,
                methods=sorted(b["methods"]),
                parameters=params,
                response_types=sorted(b["response_types"]),
                id_parameters=id_params,
                authz_sensitive=authz,
                sensitivity_reason=reason,
                hosts=sorted(h for h in b["hosts"] if h),
            )
        )
    return results
