"""Identity-provider detection (discovery-only).

Determines which IdP and authentication type front an application by observing
public signals: the login redirect chain, response headers, login-page markers,
OAuth/SAML request parameters, and the OIDC discovery document
(``/.well-known/openid-configuration``). It only issues read-only GETs to public
endpoints — it never authenticates to or attacks the IdP.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

import httpx

from core.http import client_for
from core.logging import get_logger
from models.schemas import IdPInfo, ScanContext

log = get_logger("idp")

# host-substring -> (provider, auth_type)
HOST_SIGNATURES: list[tuple[str, str, str]] = [
    ("login.microsoftonline.com", "Azure AD / Entra ID", "OIDC"),
    ("login.windows.net", "Azure AD / Entra ID", "OIDC"),
    ("sts.windows.net", "Azure AD / Entra ID", "OIDC"),
    (".okta.com", "Okta", "OIDC"),
    (".oktapreview.com", "Okta", "OIDC"),
    (".auth0.com", "Auth0", "OIDC"),
    ("accounts.google.com", "Google", "OIDC"),
    ("github.com/login/oauth", "GitHub", "OAuth2"),
    ("facebook.com/dialog/oauth", "Facebook", "OAuth2"),
]
# path/body-substring -> (provider, auth_type)
PATH_SIGNATURES: list[tuple[str, str, str]] = [
    ("/auth/realms/", "Keycloak", "OIDC"),
    ("/realms/", "Keycloak", "OIDC"),
    ("/adfs/", "AD FS", "SAML"),
    ("/simplesaml/", "SimpleSAMLphp", "SAML"),
]
BODY_SIGNATURES: list[tuple[str, str, str]] = [
    ("keycloak", "Keycloak", "OIDC"),
    ("okta", "Okta", "OIDC"),
    ("auth0", "Auth0", "OIDC"),
    ("microsoftonline", "Azure AD / Entra ID", "OIDC"),
]


async def detect_idp(ctx: ScanContext) -> IdPInfo:
    """Detect the identity provider / auth type for the target."""
    evidence: list[str] = []
    provider = "Unknown"
    auth_type = "Unknown"
    metadata_url: str | None = None

    async with client_for(ctx) as client:
        # 1) Follow the base URL and inspect the redirect chain + final URL.
        try:
            resp = await client.get(ctx.target.url)
            chain = [str(h.url) for h in resp.history] + [str(resp.url)]
        except httpx.HTTPError as exc:
            log.warning("idp.fetch_failed", error=str(exc))
            chain, resp = [], None

        for url in chain:
            host = urlparse(url).hostname or ""
            for needle, prov, atype in HOST_SIGNATURES:
                if needle.lstrip(".") in host or needle in url:
                    provider, auth_type = prov, atype
                    evidence.append(f"redirect:{host}")
            for needle, prov, atype in PATH_SIGNATURES:
                if needle in url:
                    provider, auth_type = prov, atype
                    evidence.append(f"path:{needle}")
            # OAuth / OIDC / SAML request parameters in the redirect URL.
            qs = parse_qs(urlparse(url).query)
            if "SAMLRequest" in qs or "SAMLResponse" in qs:
                auth_type = "SAML"
                evidence.append("param:SAMLRequest")
            if "client_id" in qs and "response_type" in qs:
                auth_type = auth_type if auth_type != "Unknown" else "OIDC"
                evidence.append("param:oauth2")

        # 2) Body signatures on the final (login) page.
        if resp is not None and "html" in resp.headers.get("content-type", ""):
            body = (resp.text or "").lower()
            for needle, prov, atype in BODY_SIGNATURES:
                if needle in body:
                    if provider == "Unknown":
                        provider, auth_type = prov, atype
                    evidence.append(f"body:{needle}")
            if re.search(r"saml|samlrequest", body):
                evidence.append("body:saml")

        # 3) OIDC discovery document.
        meta = await _probe_oidc(client, ctx.target.url)
        if meta:
            metadata_url = meta["url"]
            auth_type = "OIDC"
            evidence.append(f"well-known:{meta['url']}")
            iss_host = urlparse(meta.get("issuer", "")).hostname or ""
            if provider == "Unknown":
                for needle, prov, _atype in HOST_SIGNATURES:
                    if needle.lstrip(".") in iss_host:
                        provider = prov
                        break
                if "/realms/" in (meta.get("issuer") or ""):
                    provider = "Keycloak"

    if provider == "Unknown" and auth_type == "Unknown":
        auth_type = "Form/None"

    return IdPInfo(
        identity_provider=provider,
        authentication_type=auth_type,
        evidence=sorted(set(evidence)),
        metadata_url=metadata_url,
    )


async def _probe_oidc(client: httpx.AsyncClient, base_url: str) -> dict | None:
    """Fetch the OIDC discovery document if present."""
    url = base_url.rstrip("/") + "/.well-known/openid-configuration"
    try:
        resp = await client.get(url)
        if resp.status_code == 200 and "json" in resp.headers.get("content-type", ""):
            data = resp.json()
            if "issuer" in data or "authorization_endpoint" in data:
                return {"url": url, **data}
    except (httpx.HTTPError, ValueError):
        return None
    return None
