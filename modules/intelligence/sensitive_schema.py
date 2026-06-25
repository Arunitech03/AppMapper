"""Issue 4: Sensitive Schema Intelligence.

Classifies the **response JSON keys** (already extracted keys-only by
``response_analyzer``) into sensitive data categories — Identity, Customer, Asset,
Location — and flags endpoints that expose sensitive fields behind an object
identifier as **Potential IDOR Targets**. Keys/field-names only; never values.
"""

from __future__ import annotations

import re

from modules.intelligence.confidence import HIGH, MEDIUM

# category -> field-name substrings (matched case-insensitively against keys)
SENSITIVE_FIELDS: dict[str, tuple[str, ...]] = {
    "Identity": (
        "user",
        "username",
        "email",
        "role",
        "permission",
        "group",
        "identity",
        "principal",
    ),
    "Customer": ("account", "customer", "billing", "subscription", "tenant", "company", "tariff"),
    "Asset": ("device", "meter", "serial", "asset", "equipment", "gateway", "endpointid"),
    "Location": (
        "address",
        "city",
        "state",
        "zip",
        "postal",
        "latitude",
        "longitude",
        "geo",
        "coordinate",
    ),
}

_CAMEL = re.compile(r"([a-z0-9])([A-Z])")


def _norm_key(k: str) -> str:
    return _CAMEL.sub(r"\1 \2", k).replace("_", " ").lower()


def _classify_key(key: str) -> str | None:
    low = _norm_key(key)
    for category, needles in SENSITIVE_FIELDS.items():
        if any(n in low.replace(" ", "") or f" {n}" in f" {low}" for n in needles):
            return category
    return None


def analyze_sensitive_schemas(data: dict) -> list[dict]:
    """Per-endpoint sensitive-field intelligence (keys only).

    Returns ``[{endpoint, method, categories, sensitive_fields, idor_candidate,
    confidence, risk}]`` for endpoints whose response schema exposes sensitive
    fields, highest-risk first.
    """
    from modules.intelligence.response_analyzer import analyze_responses

    out = []
    for r in analyze_responses(data):
        keys = r.get("json_keys", []) or []
        if not keys:
            continue
        cats: dict[str, list[str]] = {}
        for k in keys:
            c = _classify_key(k)
            if c:
                cats.setdefault(c, []).append(k)
        if not cats:
            continue
        endpoint = r["endpoint"]
        # IDOR candidate: sensitive fields returned behind an object id in the path.
        has_id = "{id}" in endpoint or "{uuid}" in endpoint or "{hash}" in endpoint
        sensitive_fields = sorted({f for fs in cats.values() for f in fs})
        idor = has_id and bool(sensitive_fields)
        out.append(
            {
                "endpoint": endpoint,
                "method": r.get("method", "GET"),
                "categories": sorted(cats),
                "sensitive_fields": sensitive_fields,
                "idor_candidate": idor,
                "confidence": HIGH if r.get("confidence") == HIGH else MEDIUM,
                "risk": "Potential IDOR Target" if idor else "Sensitive Data Exposure",
            }
        )
    # Browser-resident schemas: IndexedDB object stores (Sprint B, keys-only).
    for finding in data.get("intel_findings", []) or []:
        if finding.get("kind") != "indexeddb":
            continue
        db = finding.get("name", "db")
        for store in (finding.get("extra") or {}).get("stores", []):
            fields = store.get("fields") or []
            cats: dict[str, list[str]] = {}
            for k in fields:
                c = _classify_key(k)
                if c:
                    cats.setdefault(c, []).append(k)
            if not cats:
                continue
            sensitive_fields = sorted({f for fs in cats.values() for f in fs})
            out.append(
                {
                    "endpoint": f"IndexedDB:{db}/{store.get('name', 'store')}",
                    "method": "STORE",
                    "categories": sorted(cats),
                    "sensitive_fields": sensitive_fields,
                    "idor_candidate": False,
                    "confidence": HIGH,
                    "risk": "Sensitive Data Cached Client-Side",
                }
            )

    # IDOR candidates first, then by number of sensitive fields.
    out.sort(key=lambda x: (not x["idor_candidate"], -len(x["sensitive_fields"]), x["endpoint"]))
    return out


def sensitive_endpoints(data: dict) -> set[str]:
    """Set of endpoints (normalized) that expose sensitive fields — for scoring."""
    return {s["endpoint"] for s in analyze_sensitive_schemas(data)}
