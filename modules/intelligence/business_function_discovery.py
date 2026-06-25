"""Feature 9: Business Function Discovery.

Infers the business functions an application supports by combining evidence from
routes, API endpoints (observed + referenced), and response schema keys. Builds on
``business_modules`` but is framed as concrete *functions* a pentester maps to
authorization testing. Pure/offline.
"""

from __future__ import annotations

import re

# function -> indicator keywords (matched against the combined corpus of paths/keys)
_FUNCTIONS: dict[str, tuple[str, ...]] = {
    "User Management": ("user", "users", "account", "member", "profile", "identity"),
    "Role Management": ("role", "roles", "permission", "authority", "privilege", "acl"),
    "Billing": ("billing", "invoice", "payment", "charge", "subscription", "tariff"),
    "Reporting": ("report", "reports", "analytics", "dashboard", "export", "statistics"),
    "Device Management": ("device", "meter", "sensor", "asset", "equipment", "gateway"),
    "Alarm Management": ("alarm", "alert", "incident", "notification", "event"),
    "Configuration": ("config", "configuration", "setting", "preference", "template"),
    "Administration": ("admin", "administration", "manage", "console", "system"),
}

_CAMEL = re.compile(r"([a-z0-9])([A-Z])")
_NONWORD = re.compile(r"[^a-z0-9]+")


def _tokens(text: str) -> str:
    return _NONWORD.sub(" ", _CAMEL.sub(r"\1 \2", text)).lower()


def discover_business_functions(data: dict) -> list[dict]:
    """Return ``[{function, score, evidence}]`` ranked by evidence strength."""
    from modules.intelligence.asset_inventory import unified_api_inventory
    from modules.intelligence.hidden_endpoint_discovery import referenced_endpoints
    from modules.intelligence.response_analyzer import analyze_responses

    corpus: list[str] = []
    corpus += [_tokens(a["path"]) for a in unified_api_inventory(data)]
    corpus += [_tokens(p) for p in referenced_endpoints(data)]
    for r in analyze_responses(data):
        corpus += [_tokens(k) for k in r.get("json_keys", [])]
    for f in data.get("intel_findings", []) or []:
        if f.get("kind") == "route":
            corpus.append(_tokens(f.get("name", "")))

    blob = " " + " ".join(corpus) + " "
    out = []
    for func, kws in _FUNCTIONS.items():
        matched = sorted({kw for kw in kws if f" {kw} " in blob or f" {kw}s " in blob})
        if matched:
            score = sum(blob.count(f" {kw}") for kw in kws)
            out.append({"function": func, "score": score, "evidence": matched})
    out.sort(key=lambda x: (-x["score"], x["function"]))
    return out
