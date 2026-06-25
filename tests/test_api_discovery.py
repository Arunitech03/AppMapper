"""Tests for Module 9: API discovery (OpenAPI/Swagger parsing)."""

from __future__ import annotations

import httpx
import respx

from modules.api.discovery import ApiDiscoveryModule

OPENAPI = {
    "openapi": "3.0.1",
    "paths": {
        "/api/users": {
            "get": {"summary": "List users", "parameters": [{"name": "page"}]},
            "post": {"operationId": "createUser"},
        },
        "/api/users/{id}": {"get": {"summary": "Get user"}},
    },
}


@respx.mock
async def test_parses_openapi_spec(ctx_factory):
    base = "http://testserver.local"
    # First probed path returns the spec; everything else 404.
    respx.get(f"{base}/swagger/v1/swagger.json").mock(
        return_value=httpx.Response(200, json=OPENAPI, headers={"content-type": "application/json"})
    )
    respx.route(host="testserver.local").mock(return_value=httpx.Response(404))

    result = await ApiDiscoveryModule().run(ctx_factory(url=base))
    eps = {(e["method"], e["path"]) for e in result.data}
    assert ("GET", "/api/users") in eps
    assert ("POST", "/api/users") in eps
    assert ("GET", "/api/users/{id}") in eps
    get_users = next(e for e in result.data if e["method"] == "GET" and e["path"] == "/api/users")
    assert "page" in get_users["parameters"]


@respx.mock
async def test_detects_graphql(ctx_factory):
    base = "http://testserver.local"
    respx.get(f"{base}/graphql").mock(
        return_value=httpx.Response(400, text='{"errors":[{"message":"must provide query"}]}')
    )
    respx.route(host="testserver.local").mock(return_value=httpx.Response(404))

    result = await ApiDiscoveryModule().run(ctx_factory(url=base))
    assert any(e["source"] == "graphql" for e in result.data)
