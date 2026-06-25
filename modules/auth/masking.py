"""Secret masking.

Authentication artifacts (tokens, cookies, storage values) are masked before they
are stored or reported. Raw secret values are never persisted. The mask keeps just
enough (a short prefix/suffix) to correlate an artifact across requests without
exposing the secret.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse

# Query-string parameter names whose VALUES are secrets and must be redacted from
# stored/reported URLs (the path is preserved for inventory/role analysis).
_SECRET_PARAMS = (
    "key",
    "api_key",
    "apikey",
    "access_token",
    "token",
    "id_token",
    "refresh_token",
    "password",
    "passwd",
    "pwd",
    "secret",
    "client_secret",
    "signature",
    "sig",
    "code",
    "auth",
    "authorization",
    "session",
    "sessionid",
    "jwt",
)
_SECRET_PARAM_RE = re.compile(
    r"(?i)([?&](?:" + "|".join(re.escape(p) for p in _SECRET_PARAMS) + r")=)([^&#]+)"
)


def redact_url(url: str | None) -> str:
    """Redact secret-bearing query-param VALUES in a URL, keeping scheme/host/path.

    e.g. ``…/maps/api/js?key=AIza…`` -> ``…/maps/api/js?key=REDACTED``. The path is
    untouched, so path-based inventory/role analysis is unaffected.
    """
    if not url or "?" not in url:
        return url or ""
    try:
        parts = urlparse(url)
    except ValueError:
        return url
    if not parts.query:
        return url
    redacted_q = _SECRET_PARAM_RE.sub(r"\1REDACTED", "?" + parts.query)[1:]
    return urlunparse(parts._replace(query=redacted_q))


def mask_secret(value: str | None, *, keep: int = 4) -> str:
    """Mask a secret, showing only the first/last ``keep`` characters.

    Short values (<= 2*keep) are fully masked. ``None``/empty -> ``""``.
    """
    if not value:
        return ""
    text = str(value)
    if len(text) <= keep * 2:
        return "*" * len(text)
    return f"{text[:keep]}…{text[-keep:]} ({len(text)} chars)"
