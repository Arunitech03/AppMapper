"""Tests for role-based access comparison (discovery-only)."""

from __future__ import annotations

import httpx
import respx

from models.schemas import RoleEndpointAccess, ScanContext, TargetInput, UserCredential
from modules.access.comparison import access_matrix, build_access_records, role_difference


def _records() -> list[RoleEndpointAccess]:
    return [
        RoleEndpointAccess(role="admin", path="/admin", status_code=200, accessible=True),
        RoleEndpointAccess(role="admin", path="/login", status_code=200, accessible=True),
        RoleEndpointAccess(role="user", path="/admin", status_code=403, accessible=False),
        RoleEndpointAccess(role="user", path="/login", status_code=200, accessible=True),
        RoleEndpointAccess(role="user", path="/profile", status_code=200, accessible=True),
    ]


def test_access_matrix():
    matrix = access_matrix(_records())
    assert matrix["GET /admin"] == {"admin": True, "user": False}
    assert matrix["GET /login"] == {"admin": True, "user": True}
    assert matrix["GET /profile"] == {"user": True}


def test_role_difference():
    diff = role_difference(_records())
    assert diff["roles"] == ["admin", "user"]
    assert diff["exclusive"]["admin"] == ["GET /admin"]
    assert diff["exclusive"]["user"] == ["GET /profile"]
    assert diff["shared"] == ["GET /login"]


@respx.mock
async def test_build_access_records_per_role(monkeypatch):
    """Each role is probed with its own auth; access differs per role."""

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        path = request.url.path
        if path == "/login":
            return httpx.Response(200)
        if path == "/admin":
            # Only the admin token can reach /admin; user is denied (403).
            return httpx.Response(200 if "admin-token" in auth else 403)
        return httpx.Response(404)

    respx.route(host="app.local").mock(side_effect=handler)

    target = TargetInput(
        url="http://app.local",
        domain="app.local",
        users=[
            UserCredential(role="admin", jwt_token="admin-token"),
            UserCredential(role="user", jwt_token="user-token"),
        ],
    )
    ctx = ScanContext(target=target, timeout=2.0, max_concurrency=5, verify_tls=False)

    records = await build_access_records(ctx)
    matrix = access_matrix(records)

    assert matrix["GET /admin"]["admin"] is True
    assert matrix["GET /admin"]["user"] is False
    assert matrix["GET /login"] == {"admin": True, "user": True}

    diff = role_difference(records)
    assert "GET /admin" in diff["exclusive"]["admin"]
    assert "GET /login" in diff["shared"]
