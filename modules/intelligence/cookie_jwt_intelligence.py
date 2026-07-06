"""Cookie JWT Intelligence.

Authentication cookies are no longer treated as opaque values. Every captured auth
cookie is inspected for an embedded JWT; when present the token is decoded **offline**
(no signature verification — reusing the bearer-token engine) and turned into the same
authorization intelligence produced for ``Authorization: Bearer`` tokens: identity
provider, realm, client, lifetime, trusted applications, per-application roles, and the
administrative / write / read / security-sensitive role model. Each decoded cookie is
correlated with its security attributes (HttpOnly / Secure / SameSite / Domain / Path /
Expires) so the risk of *where* the token lives is surfaced alongside *what* it grants.

Discovery/analysis only: tokens are never validated, forged, modified, or replayed. PII
is masked (it is already masked in the decoded summaries). Cookie attributes that were
not captured are reported honestly as *"not observed"* — never fabricated.

The decoded summaries arrive via ``data["cookie_jwt_authorization"]`` (produced at the
``database.fetch_all`` boundary, where the raw cookie value still exists — only masked
summaries reach report time). This builder is a pure, empty-safe shaper over that data
plus the captured auth artifacts and cookie attributes.
"""

from __future__ import annotations

from modules.intelligence import confidence

# Cookie names that are session/opaque by convention (used only to label opaque cookies).
_SESSION_COOKIE_HINTS = ("session", "jsessionid", "phpsessid", "asp.net", "connect.sid", "sid")


def _lower_map(items, key) -> dict:
    """Index ``items`` by a lower-cased attribute, keeping the first seen."""
    out: dict[str, dict] = {}
    for it in items or []:
        name = str(it.get(key) or "").lower()
        if name and name not in out:
            out[name] = it
    return out


def _classify(summary: dict) -> str:
    """Classify a decoded cookie JWT: Access / ID / Refresh / Session / Unknown."""
    claims = summary.get("claims") or {}
    typ = str(claims.get("typ") or (summary.get("header") or {}).get("typ") or "").lower()
    if "refresh" in typ:
        return "Refresh Token"
    if typ == "id" or "serialized-id" in typ or claims.get("nonce") or claims.get("at_hash"):
        return "ID Token"
    if "bearer" in typ or summary.get("client") or summary.get("total_roles"):
        return "Access Token"
    if summary.get("session_state"):
        return "Session Token"
    return "Unknown"


def _attr(attrs: dict | None, key: str) -> str:
    """Render a boolean cookie attribute honestly (Yes / No / not observed)."""
    if not attrs:
        return "not observed"
    return "Yes" if attrs.get(key) else "No"


def _samesite(attrs: dict | None) -> str:
    if not attrs:
        return "not observed"
    return str(attrs.get("sameSite") or "not set")


def build_cookie_jwt_intelligence(report: dict, data: dict | None = None) -> dict:
    """Derive Cookie JWT Intelligence from decoded cookie tokens + captured artifacts.

    Reads ``data["cookie_jwt_authorization"]`` (decoded summaries), ``auth_artifacts``
    (to enumerate cookies + flag JWT-format-but-not-decoded vs opaque) and
    ``intel_findings`` of kind ``cookie_attr`` (browser-captured attributes). May upgrade
    ``report["auth_intelligence"]["authentication_model"]`` when a cookie carries a JWT.
    """
    data = data or {}
    auth_artifacts = data.get("auth_artifacts") or report.get("auth_artifacts") or []
    intel_findings = data.get("intel_findings") or report.get("intel_findings") or []

    # Decoded cookie-JWT summaries come from two places, both already masked:
    #   1. data["cookie_jwt_authorization"] — HAR-cookie harvest at the fetch boundary.
    #   2. intel_findings kind "cookie_jwt" — decoded at browser-exploration capture time
    #      (the common case; HAR exports typically strip the Cookie request header).
    decoded: list[dict] = list(data.get("cookie_jwt_authorization") or [])
    seen_tokens = {s.get("token_masked") for s in decoded if s.get("token_masked")}
    for f in intel_findings:
        if (f.get("kind") or "") == "cookie_jwt":
            summary = f.get("extra") or {}
            tok = summary.get("token_masked")
            if summary.get("cookie_name") and tok not in seen_tokens:
                seen_tokens.add(tok)
                decoded.append(summary)

    cookies = [a for a in auth_artifacts if (a.get("kind") or "").lower() == "cookie"]
    decoded_by_name = _lower_map(decoded, "cookie_name")
    attrs_by_name = {
        str(f.get("name") or "").lower(): (f.get("extra") or {})
        for f in intel_findings
        if (f.get("kind") or "") == "cookie_attr"
    }

    empty = {
        "cookie_cards": [],
        "jwt_cookies": [],
        "opaque_cookies": [],
        "session_intelligence": {},
        "identity_summary": {},
        "role_summary": {},
        "token_relationships": [],
        "risk_analysis": [],
        "correlation": [],
        "high_value_findings": [],
        "summary": {
            "cookies_analyzed": 0,
            "jwt_cookies": 0,
            "opaque_cookies": 0,
            "decoded": 0,
            "admin_cookie_jwts": 0,
            "high_risk": 0,
        },
        "developer_points": [],
        "authentication_model": None,
    }

    # Union of cookie names: captured artifacts + any cookie a JWT was decoded from.
    names: list[str] = []
    seen: set[str] = set()
    for a in cookies:
        low = str(a.get("name") or "").lower()
        if low and low not in seen:
            seen.add(low)
            names.append(a.get("name"))
    for s in decoded:
        low = str(s.get("cookie_name") or "").lower()
        if low and low not in seen:
            seen.add(low)
            names.append(s.get("cookie_name"))
    if not names:
        return empty

    artifact_by_name = _lower_map(cookies, "name")

    cookie_cards: list[dict] = []
    jwt_cookies: list[dict] = []
    opaque_cookies: list[dict] = []
    high_value: list[dict] = []
    correlation: list[str] = []
    high_risk = 0
    admin_cookie_jwts = 0

    for name in names:
        low = str(name or "").lower()
        summary = decoded_by_name.get(low)
        artifact = artifact_by_name.get(low) or {}
        attrs = attrs_by_name.get(low)
        masked = str(artifact.get("value_masked") or "")

        is_jwt_format = masked.startswith("eyJ")
        if not summary and not is_jwt_format:
            hint = "session id" if any(h in low for h in _SESSION_COOKIE_HINTS) else "value"
            opaque_cookies.append({"cookie": name, "note": f"Opaque {hint} (no embedded JWT)"})
            correlation.append(f"Cookie: {name}\n└── Opaque {hint} — not a JWT")
            continue

        httponly, secure, samesite = (
            _attr(attrs, "httpOnly"),
            _attr(attrs, "secure"),
            _samesite(attrs),
        )

        if not summary:
            # JWT-format but the raw value was never captured on a request → cannot decode.
            jwt_cookies.append(
                {
                    "cookie": name,
                    "type": "JWT (format only)",
                    "decoded": "No",
                    "httponly": httponly,
                    "secure": secure,
                    "samesite": samesite,
                    "roles": "not observed",
                    "risk": "Encoded token; decode not possible from capture",
                }
            )
            correlation.append(
                f"Cookie: {name}\n└── JWT format detected — not sent as a request header, "
                f"cannot decode"
            )
            continue

        token_type = _classify(summary)
        admins = summary.get("administrative_roles") or []
        if admins:
            admin_cookie_jwts += 1
        user = summary.get("user") or {}
        provider = summary.get("identity_provider") or "Unknown"
        realm = summary.get("realm")

        # --- per-cookie risk ---
        risks: list[str] = []
        if attrs is not None and not attrs.get("httpOnly"):
            risks.append("Readable by JavaScript (HttpOnly not set) — XSS token theft")
            high_value.append(
                {
                    "severity": "High",
                    "title": f"JWT in non-HttpOnly cookie: {name}",
                    "detail": (
                        f"Cookie '{name}' carries a decoded {token_type} "
                        f"({provider}{'/' + realm if realm else ''}) but HttpOnly is not set, "
                        f"so any XSS can read and exfiltrate the full token."
                    ),
                }
            )
            high_risk += 1
        if admins:
            risks.append(f"Carries {len(admins)} administrative role(s)")
            high_value.append(
                {
                    "severity": "High",
                    "title": f"Administrative roles carried in cookie JWT: {name}",
                    "detail": (
                        f"Cookie '{name}' embeds a token granting admin role(s): "
                        f"{', '.join(admins[:6])}"
                        f"{'…' if len(admins) > 6 else ''}. Session theft yields admin access."
                    ),
                }
            )
            high_risk += 1
        if attrs is not None and not attrs.get("secure"):
            risks.append("Secure flag not set — token may transit cleartext")
            high_value.append(
                {
                    "severity": "Medium",
                    "title": f"JWT cookie without Secure flag: {name}",
                    "detail": f"Cookie '{name}' carries a JWT but the Secure attribute is not set.",
                }
            )
        if attrs is not None and str(attrs.get("sameSite") or "").lower() in ("none", ""):
            risks.append("SameSite not restrictive — CSRF-rideable session")
            high_value.append(
                {
                    "severity": "Medium",
                    "title": f"JWT cookie with weak SameSite: {name}",
                    "detail": (
                        f"Cookie '{name}' carries a JWT with SameSite={_samesite(attrs)}; "
                        f"the authenticated session can be ridden cross-site."
                    ),
                }
            )
        if summary.get("lifetime_class") in ("Long", "Very Long"):
            risks.append(
                f"{summary.get('lifetime_class')}-lived token ({summary.get('token_lifetime')})"
            )
            high_value.append(
                {
                    "severity": "Medium",
                    "title": f"Long-lived cookie JWT: {name}",
                    "detail": (
                        f"Cookie '{name}' token lifetime is {summary.get('token_lifetime')} "
                        f"({summary.get('lifetime_class')}), widening the theft window."
                    ),
                }
            )
        risk_text = "; ".join(risks) if risks else "No cookie-storage risk observed"

        conf = confidence.HIGH if attrs is not None else confidence.MEDIUM

        card = {
            "cookie": name,
            "token_type": token_type,
            "confidence": conf,
            "header": summary.get("header") or {},
            "identity": {
                "identity_provider": provider,
                "realm": realm,
                "issuer": summary.get("issuer"),
                "client": summary.get("client"),
                "username": user.get("username"),
                "display_name": user.get("display_name"),
                "subject": user.get("subject"),
            },
            "session": {
                "session_state": summary.get("session_state"),
                "issued_at": summary.get("issued_at"),
                "expires_at": summary.get("expires_at"),
                "token_lifetime": summary.get("token_lifetime"),
                "lifetime_class": summary.get("lifetime_class"),
            },
            "authorization": {
                "applications": summary.get("applications") or [],
                "total_roles": summary.get("total_roles") or 0,
                "administrative_roles": admins,
                "write_roles": summary.get("write_roles") or [],
                "read_roles": summary.get("read_roles") or [],
                "security_sensitive_roles": summary.get("security_sensitive_roles") or [],
            },
            "trust_relationships": summary.get("trusted_application_list") or [],
            "attributes": {
                "httponly": httponly,
                "secure": secure,
                "samesite": samesite,
                "domain": (attrs or {}).get("domain") if attrs else "not observed",
                "path": (attrs or {}).get("path") if attrs else "not observed",
                "expires": (attrs or {}).get("expires") if attrs else "not observed",
            },
            "scopes": summary.get("scopes") or [],
            "risk": risk_text,
        }
        cookie_cards.append(card)

        jwt_cookies.append(
            {
                "cookie": name,
                "type": token_type,
                "decoded": "Yes",
                "httponly": httponly,
                "secure": secure,
                "samesite": samesite,
                "roles": str(summary.get("total_roles") or 0),
                "risk": risk_text,
            }
        )

        realm_txt = f"/{realm}" if realm else ""
        correlation.append(
            f"Cookie: {name}\n"
            f"├── {token_type} · {provider}{realm_txt}\n"
            f"├── Roles: {summary.get('total_roles') or 0} "
            f"(admin {len(admins)}, write {len(summary.get('write_roles') or [])})\n"
            f"├── Trusted apps: {summary.get('trusted_applications') or 0}\n"
            f"└── Cookie attrs: HttpOnly {httponly} · Secure {secure} · SameSite {samesite}"
        )

    # --- aggregates ---
    identity_summary: dict = {}
    if cookie_cards:
        providers = sorted({c["identity"]["identity_provider"] for c in cookie_cards})
        realms = sorted({c["identity"]["realm"] for c in cookie_cards if c["identity"]["realm"]})
        usernames = sorted(
            {c["identity"]["username"] for c in cookie_cards if c["identity"]["username"]}
        )
        identity_summary = {
            "identity_providers": providers,
            "realms": realms,
            "users": usernames,
        }

    role_summary: dict = {}
    if cookie_cards:
        role_summary = {
            "administrative": sorted(
                {r for c in cookie_cards for r in c["authorization"]["administrative_roles"]}
            ),
            "write": sorted({r for c in cookie_cards for r in c["authorization"]["write_roles"]}),
            "read": sorted({r for c in cookie_cards for r in c["authorization"]["read_roles"]}),
            "security_sensitive": sorted(
                {r for c in cookie_cards for r in c["authorization"]["security_sensitive_roles"]}
            ),
        }

    session_intelligence: dict = {}
    if cookie_cards:
        session_intelligence = {
            "sessions": [
                {
                    "cookie": c["cookie"],
                    "expires_at": c["session"]["expires_at"],
                    "lifetime": c["session"]["token_lifetime"],
                    "lifetime_class": c["session"]["lifetime_class"],
                    "session_state": c["session"]["session_state"],
                }
                for c in cookie_cards
            ]
        }

    token_relationships = sorted({app for c in cookie_cards for app in c["trust_relationships"]})

    risk_analysis = [
        {"title": f["title"], "risk": f["severity"], "impact": f["detail"]} for f in high_value
    ]

    # --- authentication-model upgrade ---
    auth_model_str: str | None = None
    if cookie_cards:
        ai = report.get("auth_intelligence") or {}
        model = ai.get("authentication_model") or {}
        uses = model.get("uses") or []
        has_bearer = "JWT Bearer Tokens" in uses or any(
            (a.get("kind") or "").lower() in ("authorization", "access_token", "bearer", "jwt")
            for a in auth_artifacts
        )
        auth_model_str = "Hybrid Cookie + JWT" if has_bearer else "Cookie-Carried JWT"
        if isinstance(model, dict):
            model["model"] = auth_model_str
            if "Cookie-Carried JWT" not in uses:
                uses = uses + ["Cookie-Carried JWT"]
            model["uses"] = uses
            model["confidence"] = "High"
            ai["authentication_model"] = model
            report["auth_intelligence"] = ai

    developer_points: list[str] = []
    if cookie_cards:
        developer_points.append(
            f"{len(cookie_cards)} authentication cookie(s) embed a decodable JWT — treat them as "
            f"bearer credentials: the same identity, roles, and trust relationships apply."
        )
        if admin_cookie_jwts:
            developer_points.append(
                f"{admin_cookie_jwts} cookie JWT(s) carry administrative roles; session theft "
                f"(XSS / network) is equivalent to admin credential theft."
            )
        non_httponly = [c["cookie"] for c in cookie_cards if c["attributes"]["httponly"] == "No"]
        if non_httponly:
            developer_points.append(
                f"JWT-carrying cookie(s) without HttpOnly ({', '.join(non_httponly)}) are readable "
                f"by JavaScript — set HttpOnly so XSS cannot exfiltrate the token."
            )
        if any(c["attributes"]["httponly"] == "not observed" for c in cookie_cards):
            developer_points.append(
                "Cookie attributes (HttpOnly/Secure/SameSite) were not captured for HAR-only "
                "runs; re-capture via browser exploration to correlate storage risk."
            )

    return {
        "cookie_cards": cookie_cards,
        "jwt_cookies": jwt_cookies,
        "opaque_cookies": opaque_cookies,
        "session_intelligence": session_intelligence,
        "identity_summary": identity_summary,
        "role_summary": role_summary,
        "token_relationships": token_relationships,
        "risk_analysis": risk_analysis,
        "correlation": correlation,
        "high_value_findings": high_value,
        "summary": {
            "cookies_analyzed": len(names),
            "jwt_cookies": len(jwt_cookies),
            "opaque_cookies": len(opaque_cookies),
            "decoded": len(cookie_cards),
            "admin_cookie_jwts": admin_cookie_jwts,
            "high_risk": high_risk,
        },
        "developer_points": developer_points,
        "authentication_model": auth_model_str,
    }
