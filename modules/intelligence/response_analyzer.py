"""Issue 1 + 10: Response Intelligence.

Aggregates per-endpoint response metadata captured during exploration / HAR
parsing: status, content type, size, and the **top-level JSON keys** the endpoint
returns. Keys only — response values are never stored or analyzed.

Endpoints are surfaced when *any* response metadata is observed (status /
content-type / size), not only when JSON keys were captured — many HAR exports
omit response bodies, so requiring keys produced an empty section. Each endpoint
carries a confidence: ``high`` when JSON keys were extracted, ``medium`` when only
metadata is known. Paths are normalized (``/zone/{id}``) so dynamic identifiers
collapse into one schema row.
"""

from __future__ import annotations

from urllib.parse import urlparse

from modules.intelligence.confidence import HIGH, MEDIUM
from modules.intelligence.path_normalizer import normalize_path


def _keys(value) -> list[str]:
    if isinstance(value, list):
        return value
    if isinstance(value, str) and value:
        return [k for k in value.split(",") if k]
    return []


def analyze_responses(data: dict) -> list[dict]:
    """Per-endpoint response intelligence from captured requests (keys only).

    Reads HAR-style requests plus exploration API calls; both carry
    ``response_status``/``response_content_type``/``response_size``/``response_keys``.
    """
    agg: dict[str, dict] = {}

    def consume(method: str, url: str, status, ctype, size, keys) -> None:
        keys = _keys(keys)
        if not (keys or status or ctype or size):
            return
        path = normalize_path(urlparse(url or "").path or "/")
        method = (method or "GET").upper()
        k = f"{method} {path}"
        a = agg.setdefault(
            k,
            {
                "endpoint": path,
                "method": method,
                "statuses": set(),
                "content_types": set(),
                "max_size": 0,
                "returns": set(),
            },
        )
        if status:
            a["statuses"].add(status)
        if ctype:
            a["content_types"].add(ctype.split(";")[0].strip())
        if size:
            try:
                a["max_size"] = max(a["max_size"], int(size))
            except (TypeError, ValueError):
                pass
        a["returns"].update(keys)

    for r in data.get("har_requests", []):
        consume(
            r.get("method"),
            r.get("url", ""),
            r.get("response_status"),
            r.get("response_content_type"),
            r.get("response_size"),
            r.get("response_keys"),
        )

    out = []
    for a in agg.values():
        returns = sorted(a["returns"])
        out.append(
            {
                "endpoint": a["endpoint"],
                "method": a["method"],
                "status": sorted(a["statuses"]),
                "content_type": sorted(a["content_types"]),
                "size": a["max_size"] or None,
                "json_keys": returns,  # KEYS ONLY — never values
                "confidence": HIGH if returns else MEDIUM,
            }
        )
    out.sort(key=lambda x: (x["endpoint"], x["method"]))
    return out
