"""Shared async HTTP helpers built on ``httpx``.

A single factory produces a configured :class:`httpx.AsyncClient` so every module
uses consistent timeouts, user-agent, TLS-verification and (optional) auth
headers. All requests are read-only discovery requests (GET/HEAD) — this module
never sends payloads intended to alter target state.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx

from models.schemas import ScanContext


def build_client(ctx: ScanContext, *, follow_redirects: bool = True) -> httpx.AsyncClient:
    """Create an :class:`httpx.AsyncClient` configured from the scan context.

    The auth header comes from ``ctx.active_user`` when set (per-role access
    comparison), otherwise from the target's primary identity.
    """

    headers = {"User-Agent": ctx.user_agent}
    user = ctx.active_user or ctx.target.primary
    if user is not None:
        headers.update(user.auth_header())  # attach Bearer token if provided
    return httpx.AsyncClient(
        headers=headers,
        timeout=ctx.timeout,
        verify=ctx.verify_tls,
        follow_redirects=follow_redirects,
    )


@asynccontextmanager
async def client_for(
    ctx: ScanContext, *, follow_redirects: bool = True
) -> AsyncIterator[httpx.AsyncClient]:
    """Async context manager yielding a configured client."""
    client = build_client(ctx, follow_redirects=follow_redirects)
    try:
        yield client
    finally:
        await client.aclose()
