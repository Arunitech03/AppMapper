"""Tests for Module 7: HAR parser."""

from __future__ import annotations

from parsers.har_parser import endpoint_inventory, parse_har, response_set_cookies

HAR = {
    "log": {
        "entries": [
            {
                "request": {
                    "method": "GET",
                    "url": "https://example.com/api/items?page=2&sort=name",
                    "headers": [{"name": "Authorization", "value": "Bearer xyz"}],
                    "queryString": [
                        {"name": "page", "value": "2"},
                        {"name": "sort", "value": "name"},
                    ],
                    "cookies": [{"name": "sid", "value": "abc"}],
                },
                "response": {"status": 200, "content": {"mimeType": "application/json"}},
            },
            {
                "request": {"method": "POST", "url": "https://example.com/api/login"},
                "response": {"status": 302, "content": {"mimeType": "text/html"}},
            },
        ]
    }
}


def test_redirect_url_from_redirecturl_and_location():
    har = {
        "log": {
            "entries": [
                # HAR-standard redirectURL field.
                {
                    "request": {"method": "GET", "url": "https://example.com/"},
                    "response": {"status": 302, "redirectURL": "https://auth.example.com/login"},
                },
                # Falls back to the Location response header; secret value redacted.
                {
                    "request": {"method": "GET", "url": "https://example.com/go"},
                    "response": {
                        "status": 307,
                        "headers": [
                            {"name": "Location", "value": "https://x.example.com/n?token=eyJsecret"}
                        ],
                    },
                },
                # Non-redirect: no redirect_url.
                {
                    "request": {"method": "GET", "url": "https://example.com/ok"},
                    "response": {"status": 200, "content": {"mimeType": "text/html"}},
                },
            ]
        }
    }
    reqs = parse_har(har)
    assert reqs[0].redirect_url == "https://auth.example.com/login"
    assert reqs[1].redirect_url == "https://x.example.com/n?token=REDACTED"
    assert reqs[2].redirect_url is None


def test_parse_har_extracts_requests():
    reqs = parse_har(HAR)
    assert len(reqs) == 2
    first = reqs[0]
    assert first.method == "GET"
    assert set(first.query_params) == {"page", "sort"}
    assert first.headers["Authorization"] == "Bearer xyz"
    assert first.cookies["sid"] == "abc"
    assert first.response_content_type == "application/json"


def test_endpoint_inventory_dedupes():
    inv = endpoint_inventory(parse_har(HAR))
    assert "GET /api/items" in inv
    assert "POST /api/login" in inv


def test_response_set_cookies_extracts_name_value():
    har = {
        "log": {
            "entries": [
                {
                    "request": {"method": "GET", "url": "https://x.io/auth"},
                    "response": {
                        "status": 200,
                        "content": {},
                        "headers": [
                            {
                                "name": "Set-Cookie",
                                "value": "KEYCLOAK_IDENTITY=eyJhbGc.payload.sig; "
                                "Path=/; HttpOnly; Secure",
                            },
                            {"name": "Content-Type", "value": "text/html"},
                        ],
                    },
                }
            ]
        }
    }
    pairs = dict(response_set_cookies(har))
    assert pairs["KEYCLOAK_IDENTITY"] == "eyJhbGc.payload.sig"
    assert response_set_cookies(HAR) == []  # no Set-Cookie in the base fixture
