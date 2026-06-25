"""Issue 1: Identity-provider detection from captured artifacts.

The live ``idp_detector`` inspects the server redirect chain — which misses IdPs
reached via a client-side (JS) redirect, as on the demo Keycloak SPA (the
server returns a 200 shell; the Keycloak adapter redirects in the browser). This
analyzer instead infers the IdP from data AppMapper already captured: auth-artifact
cookie names, request paths, and the hosts the app talked to. It also extracts the
Keycloak **realm**.

Discovery-only: it reads stored metadata; it never authenticates to the IdP.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from models.schemas import IdPInfo

KEYCLOAK_COOKIES = ("keycloak_identity", "keycloak_session", "auth_session_id", "kc_restart")
REALM_RE = re.compile(r"/realms/([^/]+)", re.IGNORECASE)

# host substring -> (provider, auth_type)
HOST_PROVIDERS = (
    ("login.microsoftonline.com", "Azure AD / Entra ID", "OpenID Connect"),
    ("login.windows.net", "Azure AD / Entra ID", "OpenID Connect"),
    (".okta.com", "Okta", "OpenID Connect"),
    (".oktapreview.com", "Okta", "OpenID Connect"),
    (".auth0.com", "Auth0", "OpenID Connect"),
    (".pingidentity.com", "PingFederate", "OpenID Connect"),
    ("pingone.com", "PingOne", "OpenID Connect"),
    (".onelogin.com", "OneLogin", "OpenID Connect"),
    ("accounts.google.com", "Google", "OpenID Connect"),
)


def _hosts_and_paths(data: dict):
    for src in ("har_requests", "burp_requests", "crawl_endpoints"):
        for r in data.get(src, []):
            u = urlparse(r.get("url", ""))
            yield (u.hostname or ""), (u.path or "")


def analyze_idp(data: dict) -> IdPInfo:
    """Infer the identity provider + realm from captured artifacts."""
    evidence: list[str] = []
    realm: str | None = None

    cookie_names = {a.get("name", "").lower() for a in data.get("auth_artifacts", [])}
    hosts = list(_hosts_and_paths(data))

    # Keycloak: cookies or /realms/<realm>/ + /protocol/openid-connect paths.
    keycloak_cookie = bool(cookie_names & set(KEYCLOAK_COOKIES))
    if keycloak_cookie:
        evidence += [f"cookie:{c}" for c in sorted(cookie_names & set(KEYCLOAK_COOKIES))]
    for host, path in hosts:
        m = REALM_RE.search(path)
        if m and realm is None:
            realm = m.group(1)
            evidence.append(f"path:/realms/{realm}")
        if "/protocol/openid-connect" in path:
            evidence.append("path:/protocol/openid-connect")
        if "keycloak" in host:
            evidence.append(f"host:{host}")
    if keycloak_cookie or realm or any("openid-connect" in e for e in evidence):
        return IdPInfo(
            identity_provider="Keycloak",
            authentication_type="OpenID Connect",
            realm=realm,
            evidence=sorted(set(evidence)),
        )

    # Hosted providers by host signature.
    for host, _path in hosts:
        for needle, provider, atype in HOST_PROVIDERS:
            if needle.lstrip(".") in host:
                return IdPInfo(
                    identity_provider=provider,
                    authentication_type=atype,
                    evidence=[f"host:{host}"],
                )

    # PingFederate: /pf/ path; generic SAML/ADFS.
    for _host, path in hosts:
        if "/pf/" in path:
            return IdPInfo(
                identity_provider="PingFederate",
                authentication_type="OAuth2/OIDC",
                evidence=["path:/pf/"],
            )
        if "/adfs/" in path:
            return IdPInfo(
                identity_provider="AD FS", authentication_type="SAML", evidence=["path:/adfs/"]
            )
        if "/saml" in path.lower():
            return IdPInfo(
                identity_provider="SAML IdP", authentication_type="SAML", evidence=["path:saml"]
            )

    return IdPInfo(identity_provider="Unknown", authentication_type="Unknown")


def effective_idp(data: dict) -> IdPInfo:
    """Best-known IdP at report time: stored ``idp_info`` reconciled with a fresh
    captured-artifact analysis. Lets report-only/imported runs (no orchestrator
    reconcile phase) still surface Keycloak/realm rather than ``Unknown``."""
    rows = data.get("idp_info") or []
    stored = None
    if rows:
        row = dict(rows[0])
        ev = row.get("evidence")
        if isinstance(ev, str):  # stored as CSV in the DB; coerce back to a list
            row["evidence"] = [e for e in ev.split(",") if e]
        elif not isinstance(ev, list):
            row["evidence"] = []
        stored = IdPInfo(
            identity_provider=row.get("identity_provider", "Unknown"),
            authentication_type=row.get("authentication_type", "Unknown"),
            realm=row.get("realm"),
            evidence=row["evidence"],
            metadata_url=row.get("metadata_url"),
        )
    captured = analyze_idp(data)
    # stored is the "live" result; prefer concrete captured over Unknown stored.
    return merge_idp(stored, captured)


def merge_idp(live: IdPInfo | None, captured: IdPInfo) -> IdPInfo:
    """Prefer a concrete captured result over an Unknown live result; merge realm."""
    if captured.identity_provider != "Unknown":
        if live and live.identity_provider == captured.identity_provider:
            captured.realm = captured.realm or live.realm
            captured.evidence = sorted(set(captured.evidence + live.evidence))
            captured.metadata_url = captured.metadata_url or live.metadata_url
        return captured
    return live or captured
