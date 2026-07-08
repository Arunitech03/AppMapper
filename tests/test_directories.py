"""Tests for Module 2: directory enumeration."""

from __future__ import annotations

import httpx
import respx

from modules.recon.directories import DirectoryEnumModule


@respx.mock
async def test_directory_enum_detects_present_paths(ctx_factory):
    base = "http://testserver.local"

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/login":
            return httpx.Response(200, text="login", headers={"content-type": "text/html"})
        if path == "/admin":
            return httpx.Response(401)
        if path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *")
        return httpx.Response(404)

    respx.route(host="testserver.local").mock(side_effect=handler)

    ctx = ctx_factory(url=base)
    result = await DirectoryEnumModule().run(ctx)

    found = {d["path"]: d for d in result.data}
    assert "/login" in found and found["/login"]["status_code"] == 200
    assert "/admin" in found and found["/admin"]["status_code"] == 401
    assert "/robots.txt" in found
    assert "/this-does-not-exist" not in found


@respx.mock
async def test_directory_enum_probes_management_endpoints(ctx_factory):
    base = "http://testserver.local"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/actuator":
            return httpx.Response(200, headers={"content-type": "application/json"})
        if request.url.path == "/actuator/env":
            return httpx.Response(403)  # 403 still confirms the endpoint exists
        return httpx.Response(404)

    respx.route(host="testserver.local").mock(side_effect=handler)
    ctx = ctx_factory(url=base)
    result = await DirectoryEnumModule().run(ctx)

    found = {d["path"]: d for d in result.data}
    assert "/actuator" in found and found["/actuator"]["category"] == "management"
    assert "/actuator/env" in found and found["/actuator/env"]["status_code"] == 403
