"""JWT authentication helper (discovery-only).

Builds a Bearer header from a configured token and decodes the JWT header/claims
**without verifying the signature** — purely to surface discovery hints (issuer,
audience, expiry, authorized party) and to inform IdP detection. It never cracks,
forges, or validates tokens.
"""

from __future__ import annotations

import base64
import binascii
import json


def bearer_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_jwt(token: str) -> dict:
    """Return ``{"header": {...}, "claims": {...}}`` from a JWT, or ``{}`` on error.

    Signature is NOT verified — this is read-only inspection for discovery.
    """
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    try:
        header = json.loads(_b64url_decode(parts[0]))
        claims = json.loads(_b64url_decode(parts[1]))
    except (binascii.Error, ValueError, json.JSONDecodeError):
        return {}
    return {"header": header, "claims": claims}


def issuer_hint(token: str) -> str | None:
    """Best-effort issuer (``iss``) from the token claims, for IdP detection."""
    decoded = decode_jwt(token)
    claims = decoded.get("claims", {})
    return claims.get("iss") or claims.get("idp")
