"""Central authentication manager.

Resolves a role's :class:`UserCredential` into a concrete
:class:`ResolvedSession` (cookies + headers + masked artifacts) by dispatching on
an auth **strategy** (none | jwt | cookie | session | har | login). The strategy
registry is the extension point: future strategies (device-code, client-credentials,
service-account, api-key, certificate) are added as new resolver callables without
changing any caller.

All credential use is discovery-only: attach existing session material to read-only
requests. No brute forcing, bypass, IdP attacks, or token cracking.
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlparse

from core.logging import get_logger
from models.schemas import AuthArtifact, ResolvedSession, SessionInfo, UserCredential
from modules.auth import session_manager
from modules.auth.cookie_auth import is_session_cookie, parse_cookie_string
from modules.auth.jwt_auth import bearer_header
from modules.auth.masking import mask_secret
from parsers.burp_parser import parse_burp
from parsers.har_parser import parse_har

log = get_logger("auth")


class AuthManager:
    """Resolve credentials to sessions and collect (masked) auth artifacts."""

    def __init__(self) -> None:
        self._resolvers: dict[str, Callable[[UserCredential], ResolvedSession]] = {
            "none": self._resolve_none,
            "jwt": self._resolve_jwt,
            "cookie": self._resolve_cookie,
            "session": self._resolve_session,
            "har": self._resolve_har,
            "login": self._resolve_login,
        }

    def register(
        self, strategy: str, resolver: Callable[[UserCredential], ResolvedSession]
    ) -> None:
        """Register a new auth strategy resolver (future-compat extension point)."""
        self._resolvers[strategy] = resolver

    def resolve(self, user: UserCredential) -> ResolvedSession:
        strategy = user.strategy
        resolver = self._resolvers.get(strategy, self._resolve_none)
        try:
            return resolver(user)
        except Exception as exc:  # noqa: BLE001 - a bad session must not abort the scan
            log.warning("auth.resolve_failed", role=user.role, strategy=strategy, error=str(exc))
            return ResolvedSession(role=user.role, source=strategy)

    def session_info(self, user: UserCredential) -> SessionInfo:
        strategy = user.strategy
        if strategy == "session" and user.session_file:
            return session_manager.session_info(user.role, user.session_file)
        resolved = self.resolve(user)
        return SessionInfo(
            role=user.role,
            source=strategy,
            captured=bool(resolved.cookies or resolved.headers or strategy in {"jwt", "cookie"}),
            cookie_count=len(resolved.cookies),
            has_storage=False,
            detail=None,
        )

    # -- strategy resolvers ----------------------------------------------
    def _resolve_none(self, user: UserCredential) -> ResolvedSession:
        return ResolvedSession(role=user.role, source="none")

    def _resolve_jwt(self, user: UserCredential) -> ResolvedSession:
        artifacts = [
            AuthArtifact(
                role=user.role,
                kind="access_token",
                name="Authorization",
                value_masked=mask_secret(user.jwt_token),
                source="jwt",
            )
        ]
        return ResolvedSession(
            role=user.role,
            headers=bearer_header(user.jwt_token or ""),
            artifacts=artifacts,
            source="jwt",
        )

    def _resolve_cookie(self, user: UserCredential) -> ResolvedSession:
        jar = parse_cookie_string(user.cookie or "")
        artifacts = [
            AuthArtifact(
                role=user.role,
                kind="cookie",
                name=name,
                value_masked=mask_secret(value),
                source="cookie",
            )
            for name, value in jar.items()
            if is_session_cookie(name)
        ]
        return ResolvedSession(role=user.role, cookies=jar, artifacts=artifacts, source="cookie")

    def _resolve_session(self, user: UserCredential) -> ResolvedSession:
        if not user.session_file:
            return ResolvedSession(role=user.role, source="session")
        return session_manager.resolve_session(user.role, user.session_file)

    def _resolve_har(self, user: UserCredential) -> ResolvedSession:
        cookies, headers, artifacts = self._auth_from_captures(user)
        return ResolvedSession(
            role=user.role, cookies=cookies, headers=headers, artifacts=artifacts, source="har"
        )

    def _resolve_login(self, user: UserCredential) -> ResolvedSession:
        # The crawler performs the configured form login itself; nothing to pre-resolve.
        return ResolvedSession(role=user.role, source="login")

    # -- HAR/Burp authentication extraction ------------------------------
    def _auth_from_captures(
        self, user: UserCredential
    ) -> tuple[dict[str, str], dict[str, str], list[AuthArtifact]]:
        cookies: dict[str, str] = {}
        headers: dict[str, str] = {}
        artifacts: list[AuthArtifact] = []

        if user.har:
            try:
                for r in parse_har(user.har):
                    for name, value in (r.cookies or {}).items():
                        cookies[name] = value
                    auth = (r.headers or {}).get("Authorization") or (r.headers or {}).get(
                        "authorization"
                    )
                    if auth:
                        headers["Authorization"] = auth
            except (OSError, ValueError) as exc:
                log.warning("auth.har_failed", role=user.role, error=str(exc))

        if user.burp:
            try:
                for r in parse_burp(user.burp):
                    for name, value in (r.cookies or {}).items():
                        cookies[name] = value
                    for tok in r.auth_tokens or []:
                        if tok.lower().startswith("bearer "):
                            headers["Authorization"] = tok
            except (OSError, ValueError) as exc:
                log.warning("auth.burp_failed", role=user.role, error=str(exc))

        for name, value in cookies.items():
            if is_session_cookie(name):
                artifacts.append(
                    AuthArtifact(
                        role=user.role,
                        kind="cookie",
                        name=name,
                        value_masked=mask_secret(value),
                        source="har",
                    )
                )
        if "Authorization" in headers:
            artifacts.append(
                AuthArtifact(
                    role=user.role,
                    kind="authorization",
                    name="Authorization",
                    value_masked=mask_secret(headers["Authorization"]),
                    source="har",
                )
            )
        return cookies, headers, artifacts

    def collect_artifacts(
        self, user: UserCredential, resolved: ResolvedSession
    ) -> list[AuthArtifact]:
        """All masked artifacts for a role (from the resolved session + captures)."""
        artifacts = list(resolved.artifacts)
        if user.strategy != "har":  # avoid double-collecting for the har strategy
            _, _, cap = self._auth_from_captures(user)
            artifacts.extend(cap)
        return artifacts


def domain_of(url: str) -> str:
    return urlparse(url).hostname or ""
