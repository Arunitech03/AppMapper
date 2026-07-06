"""Module 7: HAR parser.

Parses an HTTP Archive (``.har``) file into a normalized request inventory:
URLs, query parameters, headers, cookies and response content types. Pure
function over a file/dict — no network access.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from models.schemas import HarRequest
from modules.auth.masking import redact_url

# Body mime types worth scanning for content intelligence (text-like only).
_TEXT_MIME_HINTS = (
    "json",
    "javascript",
    "ecmascript",
    "html",
    "xml",
    "text/",
    "css",
    "graphql",
    "x-www-form-urlencoded",
)
# Skip clearly-binary bodies even if base64-decodable.
_BINARY_MIME_HINTS = ("image/", "font/", "video/", "audio/", "octet-stream", "application/pdf")


def parse_har(source: str | Path | dict) -> list[HarRequest]:
    """Parse a HAR file path, raw JSON string, or already-loaded dict.

    Returns one :class:`HarRequest` per logged entry.
    """
    data = _load(source)
    entries = data.get("log", {}).get("entries", [])
    requests: list[HarRequest] = []

    for entry in entries:
        req = entry.get("request", {})
        resp = entry.get("response", {})
        url = req.get("url")
        if not url:
            continue

        query_params = [q.get("name", "") for q in req.get("queryString", []) if q.get("name")]
        headers = {
            h.get("name", ""): h.get("value", "") for h in req.get("headers", []) if h.get("name")
        }
        cookies = {
            c.get("name", ""): c.get("value", "") for c in req.get("cookies", []) if c.get("name")
        }
        content = resp.get("content", {}) or {}
        mime = content.get("mimeType") or None
        size = content.get("size")
        # Response intelligence: top-level JSON KEYS only (never values).
        keys = _json_top_level_keys(content.get("text"), mime)
        redirect_url = _redirect_target(resp)

        requests.append(
            HarRequest(
                url=url,
                method=req.get("method", "GET"),
                query_params=query_params,
                headers=headers,
                cookies=cookies,
                response_status=resp.get("status") or None,
                response_content_type=mime,
                response_size=size if isinstance(size, int) and size >= 0 else None,
                response_keys=keys,
                redirect_url=redirect_url,
            )
        )
    return requests


def _redirect_target(resp: dict) -> str | None:
    """Redirect destination for a response (redacted), or None.

    Prefers the HAR-standard ``response.redirectURL``; falls back to the ``Location``
    response header. Secret-bearing query values are redacted before storage.
    """
    target = resp.get("redirectURL") or ""
    if not target:
        for h in resp.get("headers", []) or []:
            if (h.get("name", "") or "").lower() == "location":
                target = h.get("value", "") or ""
                break
    return redact_url(target) or None if target else None


def _is_text_mime(mime: str | None) -> bool:
    low = (mime or "").lower()
    if any(b in low for b in _BINARY_MIME_HINTS):
        return False
    return any(h in low for h in _TEXT_MIME_HINTS)


def _decode_body(content: dict, max_body: int) -> str:
    """Decode a HAR content/postData body to text (base64-aware), capped."""
    text = content.get("text")
    if not text:
        return ""
    if content.get("encoding") == "base64":
        try:
            text = base64.b64decode(text).decode("utf-8", errors="ignore")
        except (ValueError, TypeError):
            return ""
    return text[:max_body]


def parse_har_bodies(source: str | Path | dict, *, max_body: int = 2_000_000):
    """Yield text bodies from a HAR for content intelligence (capped per body).

    Yields ``{url, method, content_type, source, text}`` for each request/response
    that carries a text-like body (JS/HTML/JSON/XML/CSS/form/graphql). Binary bodies
    are skipped; each body is truncated to ``max_body`` bytes. Best-effort: malformed
    entries are skipped silently.
    """
    data = _load(source)
    for entry in data.get("log", {}).get("entries", []):
        req = entry.get("request", {}) or {}
        resp = entry.get("response", {}) or {}
        url = req.get("url") or ""
        method = req.get("method", "GET")

        # Response body.
        content = resp.get("content", {}) or {}
        rmime = content.get("mimeType")
        if _is_text_mime(rmime):
            body = _decode_body(content, max_body)
            if body:
                yield {
                    "url": url,
                    "method": method,
                    "content_type": rmime,
                    "source": "HAR response",
                    "text": body,
                }

        # Request body (postData) — GraphQL queries, form posts, etc.
        post = req.get("postData", {}) or {}
        pmime = post.get("mimeType")
        if post.get("text") and _is_text_mime(pmime):
            yield {
                "url": url,
                "method": method,
                "content_type": pmime,
                "source": "HAR request",
                "text": str(post["text"])[:max_body],
            }


def response_set_cookies(source: str | Path | dict) -> list[tuple[str, str]]:
    """``(name, value)`` pairs from every response ``Set-Cookie`` header in a HAR.

    Set-Cookie carries the freshly-issued cookie value (a JWT for token cookies) even
    when the browser later withholds it from request ``Cookie`` headers — e.g. an
    HttpOnly SSO-domain cookie like ``KEYCLOAK_IDENTITY`` that is only ever *set*, not
    echoed back. The value is the substring up to the first attribute ``;``. Pure
    function; malformed entries are skipped silently.
    """
    data = _load(source)
    out: list[tuple[str, str]] = []
    for entry in data.get("log", {}).get("entries", []):
        for h in entry.get("response", {}).get("headers", []) or []:
            if (h.get("name", "") or "").lower() != "set-cookie":
                continue
            # A HAR may fold multiple Set-Cookie headers into one newline-joined value.
            for line in (h.get("value", "") or "").split("\n"):
                nv = line.strip().split(";", 1)[0]
                name, sep, val = nv.partition("=")
                if sep and name.strip() and val.strip():
                    out.append((name.strip(), val.strip()))
    return out


def _json_top_level_keys(text: str | None, mime: str | None) -> list[str]:
    """Top-level keys of a JSON response body (KEYS ONLY — values are discarded)."""
    if not text or not mime or "json" not in mime.lower():
        return []
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return []
    if isinstance(obj, dict):
        return list(obj.keys())[:50]
    if isinstance(obj, list) and obj and isinstance(obj[0], dict):
        return list(obj[0].keys())[:50]  # keys of the first element for arrays
    return []


def endpoint_inventory(requests: list[HarRequest]) -> list[str]:
    """Distinct ``METHOD path`` strings, for a quick endpoint listing."""
    from urllib.parse import urlparse

    seen: dict[str, None] = {}
    for r in requests:
        key = f"{r.method} {urlparse(r.url).path or '/'}"
        seen.setdefault(key, None)
    return list(seen)


def _load(source: str | Path | dict) -> dict:
    if isinstance(source, dict):
        return source
    text: str
    if isinstance(source, Path) or (isinstance(source, str) and Path(source).exists()):
        text = Path(source).read_text(encoding="utf-8", errors="ignore")
    else:
        # A string that doesn't exist on disk but looks like a path (rather than
        # raw JSON content) is almost certainly a mistyped/missing file — surface
        # that clearly instead of trying to json.loads the path itself.
        candidate = str(source)
        stripped = candidate.lstrip()
        if not stripped.startswith(("{", "[")):
            raise FileNotFoundError(f"HAR file not found: {candidate}")
        text = candidate
    return json.loads(text)
