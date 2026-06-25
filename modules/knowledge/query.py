"""Translate natural-language-ish queries into FTS5 match expressions.

Supports free text plus a few canned queries the spec calls out.
"""

from __future__ import annotations

import re

# Friendly query -> FTS5 MATCH expression.
CANNED_QUERIES: dict[str, str] = {
    "upload endpoints": "upload OR import OR attachment",
    "admin functions": "admin OR settings OR configuration OR system",
    "export functionality": "export OR download OR csv OR report OR pdf OR excel",
    "user identifiers": "user OR users OR userid OR account OR profile",
    "authentication": "login OR logout OR register OR password OR mfa",
    # External domain intelligence
    "internal apis": '"Internal API" OR Microservice',
    "third party services": '"Third Party" OR Payment OR Analytics OR CDN',
    "authentication providers": '"Authentication Provider" OR Keycloak OR Okta OR Auth0 OR Azure',
    "payment providers": "Payment OR Stripe OR Paypal",
    "hosts": "host",
    "services": "service OR backend",
    "internal applications": "internal_app OR Portal OR GIS OR CCTV",
    "dependencies": "dependency OR Mapping OR Mapbox OR ArcGIS OR Azure",
    "business modules": "module OR GIS OR Emergency OR Flood OR Weather",
}

# Stop words stripped from "Show all X" style phrases before matching.
_STOP = {
    "show",
    "all",
    "me",
    "the",
    "find",
    "list",
    "endpoints",
    "containing",
    "with",
    "for",
    "function",
    "functionality",
}


def to_fts_query(phrase: str) -> str:
    """Map a phrase to an FTS5 MATCH expression.

    Exact canned phrases map to curated expressions; otherwise meaningful tokens
    are OR-combined (so "Show all upload endpoints" -> "upload").
    """
    normalized = phrase.strip().lower()
    if normalized in CANNED_QUERIES:
        return CANNED_QUERIES[normalized]

    # Match a canned key contained in the phrase (e.g. "show all upload endpoints").
    for key, expr in CANNED_QUERIES.items():
        head = key.split()[0]
        if head in normalized:
            return expr

    tokens = [t for t in re.split(r"[^a-z0-9]+", normalized) if t and t not in _STOP]
    if not tokens:
        return phrase.strip() or "*"
    return " OR ".join(tokens)
