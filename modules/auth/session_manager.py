"""Browser-session reuse (Playwright ``storage_state``).

Loads a saved ``storage_state`` JSON (cookies + per-origin local/session storage),
and resolves it into a :class:`ResolvedSession` the httpx crawler can use: cookies
become the request jar, and bearer-looking tokens found in storage become an
``Authorization`` header. All artifact values are masked.

This module only *consumes* sessions captured by the user; it never creates,
forges, or manipulates them.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from models.schemas import AuthArtifact, ResolvedSession, SessionInfo
from modules.auth.cookie_auth import is_session_cookie
from modules.auth.masking import mask_secret

JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$")
TOKEN_KEY_RE = re.compile(r"access[_-]?token|id[_-]?token|refresh[_-]?token|\btoken\b|jwt", re.I)


def load_storage_state(path: str | Path) -> dict:
    """Load a Playwright storage_state JSON file."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _storage_entries(state: dict) -> list[tuple[str, str, str]]:
    """Yield (kind, name, value) for local/session storage entries."""
    out: list[tuple[str, str, str]] = []
    for origin in state.get("origins", []) or []:
        for entry in origin.get("localStorage", []) or []:
            out.append(("local_storage", entry.get("name", ""), entry.get("value", "")))
        for entry in origin.get("sessionStorage", []) or []:
            out.append(("session_storage", entry.get("name", ""), entry.get("value", "")))
    return out


def _classify_token(name: str) -> str:
    low = name.lower()
    if "refresh" in low:
        return "refresh_token"
    if "id_token" in low or low == "id":
        return "id_token"
    return "access_token"


def resolve_session(role: str, path: str | Path) -> ResolvedSession:
    """Resolve a storage_state file into cookies + headers + masked artifacts."""
    state = load_storage_state(path)
    cookies: dict[str, str] = {}
    artifacts: list[AuthArtifact] = []

    for c in state.get("cookies", []) or []:
        name = c.get("name", "")
        value = c.get("value", "")
        if not name:
            continue
        cookies[name] = value
        if is_session_cookie(name):
            artifacts.append(
                AuthArtifact(
                    role=role,
                    kind="cookie",
                    name=name,
                    value_masked=mask_secret(value),
                    source="session",
                )
            )

    headers: dict[str, str] = {}
    bearer: str | None = None
    for kind, name, value in _storage_entries(state):
        looks_token = bool(JWT_RE.match(value or "")) or TOKEN_KEY_RE.search(name or "")
        if looks_token and value:
            token_kind = _classify_token(name)
            artifacts.append(
                AuthArtifact(
                    role=role,
                    kind=token_kind,
                    name=name,
                    value_masked=mask_secret(value),
                    source="session",
                )
            )
            # Use the first access-token-like JWT as the Authorization bearer.
            if bearer is None and token_kind == "access_token" and JWT_RE.match(value):
                bearer = value
        else:
            artifacts.append(
                AuthArtifact(
                    role=role,
                    kind=kind,
                    name=name,
                    value_masked=mask_secret(value),
                    source="session",
                )
            )

    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"

    return ResolvedSession(
        role=role, cookies=cookies, headers=headers, artifacts=artifacts, source="session"
    )


def session_info(role: str, path: str | Path) -> SessionInfo:
    """Summarize a session file for the session inventory."""
    p = Path(path)
    if not p.exists():
        return SessionInfo(
            role=role, source="session_file", captured=False, detail="file not found"
        )
    state = load_storage_state(p)
    cookies = state.get("cookies", []) or []
    has_storage = bool(state.get("origins"))
    return SessionInfo(
        role=role,
        source="session_file",
        captured=True,
        cookie_count=len(cookies),
        has_storage=has_storage,
        detail=str(p),
    )
