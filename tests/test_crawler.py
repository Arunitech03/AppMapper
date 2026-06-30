"""Tests for Feature 1: authenticated crawler (discovery-only)."""

from __future__ import annotations

import httpx
import respx

from models.schemas import ScanContext, TargetInput, UserCredential
from modules.auth.crawler import AuthCrawlerModule

LOGIN_PAGE = """
<html><body>
  <form action="/login" method="post">
    <input name="user" type="text"/>
    <input name="pass" type="password"/>
  </form>
  <a href="/dashboard">Dashboard</a>
  <a href="/admin/users">Users</a>
  <a href="/api/data.json">data</a>
  <a href="/report.csv">export</a>
</body></html>
"""


@respx.mock
async def test_crawler_logs_in_and_discovers(ctx_factory):
    posted = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path == "/login":
            posted["count"] += 1
            return httpx.Response(200, headers={"set-cookie": "session=abc"})
        if path in ("/", "/dashboard", "/admin/users"):
            return httpx.Response(200, text=LOGIN_PAGE, headers={"content-type": "text/html"})
        if path == "/api/data.json":
            return httpx.Response(
                200, json={"ok": True}, headers={"content-type": "application/json"}
            )
        if path == "/report.csv":
            return httpx.Response(200, text="a,b", headers={"content-type": "text/csv"})
        return httpx.Response(404)

    respx.route(host="app.local").mock(side_effect=handler)

    target = TargetInput(
        url="http://app.local",
        domain="app.local",
        users=[UserCredential(role="user", username="u", password="p")],
    )
    ctx = ScanContext(
        target=target,
        timeout=2.0,
        max_concurrency=4,
        verify_tls=False,
        options={"max_pages": 30, "max_depth": 2},
    )

    result = await AuthCrawlerModule().run(ctx)
    endpoints = result.data["endpoints"]
    forms = result.data["forms"]

    assert posted["count"] >= 1  # a login was attempted with configured creds
    paths = {e["path"] for e in endpoints}
    assert {"/", "/dashboard", "/admin/users"} <= paths
    # API + file classification
    assert any(e["source"] == "api" for e in endpoints)
    assert any(e["source"] == "file" for e in endpoints)
    # Forms are discovered (not submitted)
    assert any(f["action"].endswith("/login") for f in forms)
    # Anonymous role is also crawled
    assert {e["role"] for e in endpoints} >= {"user", "anonymous"}


# Base page has NO password form (only search); the login form lives on /login.jsp.
HOME_NO_LOGIN = """
<html><body>
  <form action="/search" method="get"><input name="q" type="text"/></form>
  <a href="/login.jsp">Sign in</a>
  <a href="/bank/main.jsp">Account</a>
</body></html>
"""
LOGIN_JSP = """
<html><body>
  <form action="doLogin" method="post">
    <input name="uid" type="text"/>
    <input name="passw" type="password"/>
  </form>
</body></html>
"""


@respx.mock
async def test_crawler_auto_probes_common_login_paths(ctx_factory):
    posted = {"url": None}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path == "/doLogin":
            posted["url"] = str(request.url)
            return httpx.Response(200, headers={"set-cookie": "JSESSIONID=abc"})
        if path == "/login.jsp":
            return httpx.Response(200, text=LOGIN_JSP, headers={"content-type": "text/html"})
        if path in ("/", "/bank/main.jsp"):
            return httpx.Response(200, text=HOME_NO_LOGIN, headers={"content-type": "text/html"})
        return httpx.Response(404)

    respx.route(host="app.local").mock(side_effect=handler)
    target = TargetInput(
        url="http://app.local",
        domain="app.local",
        users=[UserCredential(role="user", username="u", password="p")],
    )
    ctx = ScanContext(
        target=target, timeout=2.0, max_concurrency=4, verify_tls=False, options={"max_pages": 30}
    )

    result = await AuthCrawlerModule().run(ctx)
    # Form on /login.jsp was found by probing; action 'doLogin' resolved correctly
    # to /doLogin (NOT /login.jsp/doLogin).
    assert posted["url"] == "http://app.local/doLogin"
    # post-login page reachable from the home page is crawled
    assert "/bank/main.jsp" in {e["path"] for e in result.data["endpoints"]}
