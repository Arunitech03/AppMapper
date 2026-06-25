"""Module 8: Burp Suite traffic parser.

Supports both Burp **XML** exports (``<items>`` with base64-encoded request /
response blocks) and **JSON** exports. Extracts requests, responses, parameters,
cookies and authentication tokens into normalized :class:`BurpRequest` records.
Pure parsing — no network access.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from models.schemas import BurpRequest
from modules.auth.masking import redact_url

_COOKIE_RE = re.compile(r"^Cookie:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_AUTH_RE = re.compile(r"^Authorization:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_CT_RE = re.compile(r"^Content-Type:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_LOCATION_RE = re.compile(r"^Location:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_STATUS_RE = re.compile(r"^HTTP/\d\.\d\s+(\d{3})")
_REQ_LINE_RE = re.compile(r"^([A-Z]+)\s+(\S+)\s+HTTP/\d\.\d")


def parse_burp(source: str | Path) -> list[BurpRequest]:
    """Parse a Burp export (XML or JSON), auto-detecting the format."""
    text = _read(source)
    stripped = text.lstrip()
    if stripped.startswith("<"):
        return _parse_xml(text)
    return _parse_json(text)


def _http_body(raw: str) -> str:
    """Body after the blank line of a raw HTTP message."""
    if not raw:
        return ""
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in raw:
            return raw.split(sep, 1)[1]
    return ""


def parse_burp_bodies(source: str | Path, *, max_body: int = 2_000_000):
    """Yield text bodies from a Burp export for content intelligence (capped).

    Yields ``{url, method, content_type, source, text}`` for request + response
    bodies of each item. Best-effort; mirrors :func:`parse_har_bodies`.
    """
    text = _read(source)
    stripped = text.lstrip()
    if stripped.startswith("<"):
        root = ET.fromstring(text)
        for item in root.iterfind(".//item"):
            url = (item.findtext("url") or "").strip()
            method = (item.findtext("method") or "GET").strip() or "GET"
            for el, label in (("request", "Burp request"), ("response", "Burp response")):
                raw = _decode(item.find(el))
                body = _http_body(raw)[:max_body]
                if body.strip():
                    yield {
                        "url": url,
                        "method": method,
                        "content_type": _content_type(raw),
                        "source": label,
                        "text": body,
                    }
    else:
        data = json.loads(text)
        items = data if isinstance(data, list) else (data.get("items") or data.get("history") or [])
        for entry in items:
            if not isinstance(entry, dict):
                continue
            url = entry.get("url") or entry.get("request", {}).get("url", "")
            method = entry.get("method") or "GET"
            for key, label in (("request", "Burp request"), ("response", "Burp response")):
                body = _http_body(_maybe_b64(entry.get(key)))[:max_body]
                if body.strip():
                    yield {
                        "url": url,
                        "method": method,
                        "content_type": None,
                        "source": label,
                        "text": body,
                    }


# ---------------------------------------------------------------------------
# XML
# ---------------------------------------------------------------------------


def _parse_xml(text: str) -> list[BurpRequest]:
    root = ET.fromstring(text)
    results: list[BurpRequest] = []

    for item in root.iterfind(".//item"):
        url = (item.findtext("url") or "").strip()
        method = (item.findtext("method") or "").strip() or "GET"
        status_text = (item.findtext("status") or "").strip()
        response_status = int(status_text) if status_text.isdigit() else None

        req_raw = _decode(item.find("request"))
        resp_raw = _decode(item.find("response"))

        if not url and req_raw:
            url = _url_from_request(req_raw)
        if not method and req_raw:
            method = _method_from_request(req_raw) or "GET"

        params = _params(url, req_raw)
        cookies = _cookies(req_raw)
        auth = _auth_tokens(req_raw)
        content_type = None
        redirect_url = None
        if resp_raw:
            response_status = response_status or _status(resp_raw)
            content_type = _content_type(resp_raw)
            redirect_url = _location(resp_raw)

        results.append(
            BurpRequest(
                url=url or "",
                method=method,
                parameters=params,
                cookies=cookies,
                auth_tokens=auth,
                response_status=response_status,
                response_content_type=content_type,
                redirect_url=redirect_url,
            )
        )
    return results


def _decode(el: ET.Element | None) -> str:
    if el is None or el.text is None:
        return ""
    text = el.text
    if (el.get("base64") or "").lower() == "true":
        try:
            return base64.b64decode(text).decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            return ""
    return text


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def _parse_json(text: str) -> list[BurpRequest]:
    data = json.loads(text)
    # Accept either a top-level list or {"items": [...]} / {"proxy": {"history": [...]}}
    if isinstance(data, dict):
        items = data.get("items") or data.get("history") or data.get("requests") or []
        if not items and "proxy" in data:
            items = data["proxy"].get("history", [])
    else:
        items = data

    results: list[BurpRequest] = []
    for entry in items:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url") or entry.get("request", {}).get("url", "")
        method = entry.get("method") or entry.get("request", {}).get("method", "GET")
        req_raw = _maybe_b64(entry.get("request"))
        resp_raw = _maybe_b64(entry.get("response"))

        params = _params(url, req_raw)
        cookies = _cookies(req_raw)
        auth = _auth_tokens(req_raw)
        results.append(
            BurpRequest(
                url=url,
                method=method,
                parameters=params,
                cookies=cookies,
                auth_tokens=auth,
                response_status=entry.get("status") or (_status(resp_raw) if resp_raw else None),
                response_content_type=_content_type(resp_raw) if resp_raw else None,
                redirect_url=_location(resp_raw) if resp_raw else None,
            )
        )
    return results


def _maybe_b64(value) -> str:
    if isinstance(value, dict):
        value = value.get("raw") or value.get("data") or ""
    if not isinstance(value, str):
        return ""
    # Heuristically base64-decode if it looks encoded and isn't already an HTTP message.
    if value and not value.upper().startswith(("GET", "POST", "PUT", "HTTP", "DELETE", "PATCH")):
        try:
            decoded = base64.b64decode(value, validate=True).decode("utf-8", errors="ignore")
            if decoded:
                return decoded
        except (binascii.Error, ValueError):
            pass
    return value


# ---------------------------------------------------------------------------
# Shared raw-HTTP helpers
# ---------------------------------------------------------------------------


def _url_from_request(req: str) -> str:
    line = req.splitlines()[0] if req else ""
    m = _REQ_LINE_RE.match(line)
    path = m.group(2) if m else ""
    host_m = re.search(r"^Host:\s*(.+)$", req, re.IGNORECASE | re.MULTILINE)
    host = host_m.group(1).strip() if host_m else ""
    if host and path:
        return f"http://{host}{path}"
    return path


def _method_from_request(req: str) -> str | None:
    line = req.splitlines()[0] if req else ""
    m = _REQ_LINE_RE.match(line)
    return m.group(1) if m else None


def _params(url: str, req_raw: str) -> list[str]:
    params: list[str] = []
    if url:
        params.extend(parse_qs(urlparse(url).query).keys())
    if req_raw:
        # Body parameters (last block after the blank line) for form posts.
        parts = req_raw.split("\r\n\r\n", 1) if "\r\n\r\n" in req_raw else req_raw.split("\n\n", 1)
        if len(parts) == 2 and "=" in parts[1] and "&" in parts[1] + "&":
            body = parts[1].strip()
            if body and "{" not in body[:1]:
                params.extend(parse_qs(body).keys())
    # de-dup preserving order
    seen: dict[str, None] = {}
    for p in params:
        seen.setdefault(p, None)
    return list(seen)


def _cookies(req_raw: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    m = _COOKIE_RE.search(req_raw or "")
    if m:
        for pair in m.group(1).split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()
    return cookies


def _auth_tokens(req_raw: str) -> list[str]:
    tokens: list[str] = []
    for m in _AUTH_RE.finditer(req_raw or ""):
        tokens.append(m.group(1).strip())
    # Surface session/JWT cookies as auth tokens too.
    cookies = _cookies(req_raw)
    for k, v in cookies.items():
        if re.search(r"token|jwt|session|auth", k, re.IGNORECASE):
            tokens.append(f"{k}={v}")
    return tokens


def _content_type(resp_raw: str) -> str | None:
    m = _CT_RE.search(resp_raw or "")
    return m.group(1).strip() if m else None


def _location(resp_raw: str) -> str | None:
    """Redirect target from a raw response's ``Location`` header (redacted)."""
    m = _LOCATION_RE.search(resp_raw or "")
    return (redact_url(m.group(1).strip()) or None) if m else None


def _status(resp_raw: str) -> int | None:
    line = resp_raw.splitlines()[0] if resp_raw else ""
    m = _STATUS_RE.match(line)
    return int(m.group(1)) if m else None


def _read(source: str | Path) -> str:
    if isinstance(source, Path) or (isinstance(source, str) and Path(source).exists()):
        return Path(source).read_text(encoding="utf-8", errors="ignore")
    return str(source)
