"""Tests for Module 5: JavaScript/frontend analysis."""

from __future__ import annotations

import httpx
import respx

from modules.frontend.js_analysis import JSAnalysisModule

PAGE = """
<html><head><script src="/static/app.js"></script></head>
<body>contact us at admin@example.com</body></html>
"""

APP_JS = """
// TODO: remove debug endpoint before release
const api = "/api/v1/users";
fetch("https://api.example.com/data");
const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcDEFghizyXmnopQRstuvWXyz012345";
const aws = "AKIAIOSFODNN7EXAMPLE";
"""


@respx.mock
async def test_js_extraction(ctx_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/static/app.js",):
            return httpx.Response(200, text=APP_JS)
        return httpx.Response(200, text=PAGE)

    respx.route(host="testserver.local").mock(side_effect=handler)

    ctx = ctx_factory(url="http://testserver.local")
    result = await JSAnalysisModule().run(ctx)
    data = result.data

    assert "admin@example.com" in data["emails"]
    assert any("/api/v1/users" in e for e in data["api_endpoints"])
    assert "https://api.example.com/data" in data["urls"]
    assert data["aws_keys"] == ["AKIAIOSFODNN7EXAMPLE"]
    assert len(data["jwts"]) == 1
    assert any("TODO" in c for c in data["comments"])
