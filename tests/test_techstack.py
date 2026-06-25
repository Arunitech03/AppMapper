"""Tests for Module 3: tech-stack fingerprinting."""

from __future__ import annotations

import httpx
import respx

from modules.fingerprint.techstack import TechStackModule


@respx.mock
async def test_detects_aspnet_core_via_headers(ctx_factory):
    respx.get("http://testserver.local").mock(
        return_value=httpx.Response(
            200,
            headers={"Server": "Kestrel", "Set-Cookie": ".AspNetCore.Session=abc"},
            text="<html><body>hello</body></html>",
        )
    )
    ctx = ctx_factory(url="http://testserver.local")
    result = await TechStackModule().run(ctx)
    assert "ASP.NET Core" in result.data["backend"]
    assert any("Kestrel" in s for s in result.data["servers"])


@respx.mock
async def test_detects_angular_via_body(ctx_factory):
    respx.get("http://testserver.local").mock(
        return_value=httpx.Response(
            200, text='<html><app-root ng-version="17.0.0"></app-root></html>'
        )
    )
    ctx = ctx_factory(url="http://testserver.local")
    result = await TechStackModule().run(ctx)
    assert "Angular" in result.data["frontend"]


@respx.mock
async def test_detects_client_side_libraries(ctx_factory):
    html = """
    <html><head>
      <link href="https://cdn.example/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet"/>
      <link href="https://cdn.example/font-awesome/6.4.0/css/all.min.css" rel="stylesheet"/>
      <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
      <script src="https://cdn.example/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
    </head><body></body></html>
    """
    respx.get("http://testserver.local").mock(return_value=httpx.Response(200, text=html))
    ctx = ctx_factory(url="http://testserver.local")
    result = await TechStackModule().run(ctx)
    libs = set(result.data["libraries"])
    assert {"Bootstrap", "jQuery", "Font Awesome"} <= libs


@respx.mock
async def test_detects_spa_stack_from_bundle_contents(ctx_factory):
    """Client-rendered SPA: frameworks live inside a hashed bundle, not the markup."""
    shell = (
        '<html><head><script src="/assets/index-a1b2c3.js"></script>'
        '<link rel="manifest" href="/manifest.json"></head><body><div id="app"></div></body></html>'
    )
    # A minified-style bundle containing the content markers that survive minification.
    bundle = (
        "var x=__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED;"
        "/* lit-html */ const t=lit$1;"
        "core-js/modules;"
        "class WebGLRenderer{} THREE.REVISION='160';"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/assets/index-a1b2c3.js":
            return httpx.Response(
                200, text=bundle, headers={"content-type": "application/javascript"}
            )
        return httpx.Response(200, text=shell, headers={"content-type": "text/html"})

    respx.route(host="spa.local").mock(side_effect=handler)
    ctx = ctx_factory(url="http://spa.local")
    result = await TechStackModule().run(ctx)

    assert "React" in result.data["frontend"]
    libs = set(result.data["libraries"])
    assert {"lit", "core-js", "Three.js", "PWA"} <= libs
