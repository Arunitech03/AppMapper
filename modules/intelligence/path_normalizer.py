"""Issue 5: dynamic identifier normalization.

Collapses concrete resource identifiers in URL paths into stable templates so the
API inventory groups ``/zone/203749`` and ``/zone/203751`` as one endpoint
``/zone/{id}`` instead of hundreds of distinct rows. Pure / offline.

Recognized identifier shapes (checked most-specific first):
  * UUID / GUID                 -> ``{uuid}``
  * 24-char hex Mongo ObjectId  -> ``{id}``
  * long hex / hash-like tokens -> ``{hash}``
  * pure numeric segments       -> ``{id}``
  * numeric tile triples z/x/y  -> handled by callers as GIS noise
"""

from __future__ import annotations

import re

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_MONGO = re.compile(r"^[0-9a-f]{24}$", re.IGNORECASE)
_HEXHASH = re.compile(r"^[0-9a-f]{32,}$", re.IGNORECASE)  # md5/sha-like
_NUMERIC = re.compile(r"^\d+$")
# Long opaque tokens mixing letters+digits (e.g. base36/base64-ish ids).
_MIXED_ID = re.compile(r"^(?=.*\d)(?=.*[a-zA-Z])[A-Za-z0-9_-]{16,}$")


def _normalize_segment(seg: str) -> str:
    if _UUID.match(seg):
        return "{uuid}"
    if _MONGO.match(seg):
        return "{id}"
    if _HEXHASH.match(seg):
        return "{hash}"
    if _NUMERIC.match(seg):
        return "{id}"
    if _MIXED_ID.match(seg):
        return "{id}"
    return seg


def normalize_path(path: str) -> str:
    """Return ``path`` with dynamic identifier segments replaced by templates."""
    if not path:
        return path or "/"
    parts = path.split("/")
    out = [(_normalize_segment(p) if p else p) for p in parts]
    norm = "/".join(out)
    return norm or "/"


def is_dynamic(path: str) -> bool:
    """True if normalization changed the path (i.e. it carried an identifier)."""
    return normalize_path(path) != (path or "/")
