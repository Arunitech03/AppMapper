"""Tests for Module 8: Burp parser (XML + JSON)."""

from __future__ import annotations

import base64

from parsers.burp_parser import parse_burp

_REQ = (
    "POST /api/login HTTP/1.1\r\n"
    "Host: example.com\r\n"
    "Cookie: session=abc123; theme=dark\r\n"
    "Authorization: Bearer jwt.token.here\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "\r\n"
    "username=admin&password=secret"
)
_RESP = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def test_parse_burp_xml():
    xml = f"""<?xml version="1.0"?>
    <items>
      <item>
        <url>https://example.com/api/login</url>
        <method>POST</method>
        <status>200</status>
        <request base64="true">{_b64(_REQ)}</request>
        <response base64="true">{_b64(_RESP)}</response>
      </item>
    </items>"""

    items = parse_burp(xml)
    assert len(items) == 1
    item = items[0]
    assert item.method == "POST"
    assert item.url == "https://example.com/api/login"
    assert set(item.parameters) >= {"username", "password"}
    assert item.cookies["session"] == "abc123"
    assert any("Bearer jwt.token.here" in t for t in item.auth_tokens)
    assert any("session=abc123" in t for t in item.auth_tokens)
    assert item.response_content_type == "application/json"


def test_burp_extracts_redirect_location():
    resp = (
        "HTTP/1.1 302 Found\r\n"
        "Location: https://auth.example.com/realms/x?code=eyJsecret\r\n"
        "Content-Type: text/html\r\n\r\n"
    )
    req = _b64("GET /login HTTP/1.1\r\nHost: example.com\r\n\r\n")
    xml = f"""<?xml version="1.0"?>
    <items>
      <item>
        <url>https://example.com/login</url>
        <method>GET</method>
        <status>302</status>
        <request base64="true">{req}</request>
        <response base64="true">{_b64(resp)}</response>
      </item>
    </items>"""
    item = parse_burp(xml)[0]
    # Location captured, status is 3xx, and the secret query value is redacted.
    assert item.redirect_url == "https://auth.example.com/realms/x?code=REDACTED"
    assert item.response_status == 302


def test_parse_burp_json():
    data = (
        '{"items": [{"url": "https://example.com/api/items?q=1", '
        f'"method": "GET", "request": "{_b64(_REQ)}"}}]}}'
    )
    items = parse_burp(data)
    assert len(items) == 1
    assert items[0].url.startswith("https://example.com/api/items")
    assert "q" in items[0].parameters
