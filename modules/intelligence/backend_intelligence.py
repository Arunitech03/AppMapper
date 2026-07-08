"""Backend Technology & Framework Intelligence (Sprint B7).

Passively fingerprints the backend stack — web framework, application server,
authentication framework, identity provider, API documentation, management endpoints
and cloud runtime — by CORRELATING evidence already gathered during reconnaissance
(the ``technologies`` fingerprint, session-cookie names, discovered management/API-doc
paths, identity-provider intelligence, response content-types and JSON error shapes).

Never relies on a single indicator: every framework detection carries a confidence and
an evidence list tagged with its source. Discovery/analysis only — no exploitation,
fuzzing, brute force, or vulnerability scanning; the engine reads already-captured data.
"""

from __future__ import annotations

from modules.intelligence import confidence as conf

# Each indicator: (kind, needle, weight, label). ``kind`` selects the evidence pool.
#   cookie  -> session-cookie names        server  -> Server-header tech names
#   tech    -> backend tech name/evidence  dir     -> a discovered path (200/401/403)
#   path    -> any observed path           content -> a response content-type
#   respkey -> a JSON error key set        idp     -> identity-provider name
_SIGNATURES: dict[str, list[tuple]] = {
    "Spring Boot": [
        ("tech", "spring boot", 3, "Spring Boot in tech fingerprint"),
        ("tech", "x-application-context", 3, "X-Application-Context header"),
        ("cookie", "jsessionid", 2, "JSESSIONID cookie"),
        ("cookie", "spring_security_context", 3, "SPRING_SECURITY_CONTEXT cookie"),
        ("server", "tomcat", 2, "Apache Tomcat server"),
        ("server", "jetty", 2, "Jetty server"),
        ("server", "undertow", 2, "Undertow server"),
        ("dir", "/actuator", 3, "Spring Boot Actuator endpoint"),
        ("path", "/v3/api-docs", 2, "springdoc /v3/api-docs"),
        ("content", "application/problem+json", 1, "RFC-7807 problem+json responses"),
        ("respkey", "timestamp|status|error|path", 2, "Spring Boot JSON error shape"),
        ("path", "/oauth2", 1, "Spring OAuth2 endpoints"),
    ],
    "ASP.NET Core": [
        ("cookie", ".aspnetcore", 3, ".AspNetCore.* cookie"),
        ("cookie", "__requestverificationtoken", 2, "Anti-forgery token cookie"),
        ("server", "kestrel", 3, "Kestrel server"),
        ("tech", "asp.net core", 3, "ASP.NET Core in tech fingerprint"),
        ("tech", "asp.net", 2, "ASP.NET in tech fingerprint"),
        ("server", "iis", 1, "IIS server"),
    ],
    "Django": [
        ("cookie", "csrftoken", 2, "csrftoken cookie"),
        ("cookie", "sessionid", 2, "sessionid cookie"),
        ("tech", "django", 3, "Django in tech fingerprint"),
        ("tech", "wsgiserver", 2, "WSGIServer banner"),
        ("dir", "/admin/login", 2, "Django admin portal"),
        ("server", "gunicorn", 1, "Gunicorn server"),
    ],
    "Flask": [
        ("server", "werkzeug", 3, "Werkzeug server"),
        ("tech", "flask", 3, "Flask in tech fingerprint"),
        ("tech", "jinja2", 1, "Jinja2 templating"),
    ],
    "Laravel": [
        ("cookie", "laravel_session", 3, "laravel_session cookie"),
        ("cookie", "xsrf-token", 2, "XSRF-TOKEN cookie"),
        ("tech", "laravel", 3, "Laravel in tech fingerprint"),
    ],
    "Node.js / Express": [
        ("cookie", "connect.sid", 3, "connect.sid cookie"),
        ("tech", "express", 3, "Express in tech fingerprint"),
        ("tech", "node.js", 2, "Node.js in tech fingerprint"),
    ],
    "Ruby on Rails": [
        ("cookie", "_authenticity_token", 3, "_authenticity_token cookie"),
        ("cookie", "_session_id", 2, "_session_id cookie"),
        ("server", "puma", 2, "Puma server"),
        ("tech", "rails", 3, "Rails in tech fingerprint"),
    ],
    "PHP": [
        ("cookie", "phpsessid", 3, "PHPSESSID cookie"),
        ("tech", "php", 3, "PHP in tech fingerprint (X-Powered-By)"),
        ("tech", "symfony", 2, "Symfony in tech fingerprint"),
        ("tech", "codeigniter", 2, "CodeIgniter in tech fingerprint"),
    ],
}

# Application servers, matched against Server-header tech names + cookies.
_APP_SERVERS = (
    ("Apache Tomcat", ("tomcat",)),
    ("Jetty", ("jetty",)),
    ("Undertow", ("undertow",)),
    ("JBoss / WildFly", ("jboss", "wildfly")),
    ("WebLogic", ("weblogic",)),
    ("WebSphere", ("websphere",)),
    ("Kestrel", ("kestrel",)),
    ("IIS", ("iis", "microsoft-iis")),
    ("Nginx", ("nginx",)),
    ("Apache HTTP Server", ("apache",)),
    ("Gunicorn", ("gunicorn",)),
    ("uWSGI", ("uwsgi",)),
    ("Puma", ("puma",)),
)

# Framework-specific manual-testing recommendations (spec-driven).
_TESTING_RECS: dict[str, list[str]] = {
    "Spring Boot": [
        "Spring Security configuration",
        "Spring Boot Actuator endpoints (env, beans, mappings, heapdump)",
        "Swagger / OpenAPI exposure",
        "H2 Console",
        "SpEL injection",
        "Spring Data REST",
        "Management / health endpoints",
    ],
    "ASP.NET Core": [
        "Swagger exposure",
        "SignalR hubs",
        "Blazor endpoints",
        "Health checks",
        "Hangfire dashboard",
        "Anti-forgery token handling",
    ],
    "Django": [
        "Admin portal (/admin)",
        "Debug toolbar / DEBUG=True",
        "CSRF handling",
        "Session handling",
    ],
    "Flask": ["Werkzeug debugger (PIN)", "Jinja2 SSTI", "Session cookie signing"],
    "Laravel": ["Ignition debug page", "Sanctum/CSRF", "APP_DEBUG / .env exposure"],
    "Node.js / Express": ["Error stack leakage", "Helmet headers", "Prototype pollution"],
    "Ruby on Rails": ["Mass assignment", "ActionDispatch error pages", "CSRF tokens"],
    "PHP": ["X-Powered-By version disclosure", "Session fixation", "Framework debug pages"],
}

_ACTUATOR_SENSITIVE = ("env", "beans", "configprops", "heapdump", "threaddump", "mappings")


def _pct(score: int, n_evidence: int) -> tuple[str, str]:
    """Map (evidence score, distinct-signal count) to (confidence level, percentage).

    Corroboration matters: multiple independent signals raise confidence, while a
    single indicator (even a strong one) is capped — the spec forbids relying on one.
    """
    if n_evidence >= 3 or score >= 6:
        return conf.HIGH, "95%"
    if n_evidence >= 2:
        return conf.HIGH, "80%"
    if score >= 3:
        return conf.MEDIUM, "60%"
    return conf.LOW, "35%"


def _pools(report: dict, data: dict) -> dict:
    """Assemble normalized evidence pools from the assembled report + raw data."""
    techs = data.get("technologies") or []
    ts = report.get("technology_stack") or {}
    servers_blob = " ".join(str(t.get("name", "")) for t in techs if t.get("category") == "server")
    servers_blob += " " + " ".join(ts.get("servers") or [])
    tech_blob = " ".join(
        f"{t.get('name', '')} {t.get('evidence', '')}"
        for t in techs
        if t.get("category") in ("backend", "server", "frontend")
    )
    tech_blob += " " + " ".join((ts.get("backend") or []) + (ts.get("libraries") or []))

    cookies = set()
    for a in data.get("auth_artifacts") or report.get("auth_artifacts") or []:
        if (a.get("kind") or "").lower() == "cookie":
            cookies.add(str(a.get("name", "")).lower())
    for f in data.get("intel_findings") or []:
        if (f.get("kind") or "") == "cookie_attr":
            cookies.add(str(f.get("name", "")).lower())

    directories = (
        data.get("directories") or (report.get("discovered_assets") or {}).get("directories") or []
    )
    dir_hits = [
        {
            "path": str(d.get("path", "")).lower(),
            "status": d.get("status_code"),
            "category": d.get("category", ""),
        }
        for d in directories
    ]
    api_paths = {str(e.get("path", "")).lower() for e in (data.get("api_endpoints") or [])}
    all_paths = (
        {d["path"] for d in dir_hits}
        | api_paths
        | {str(c.get("path", "")).lower() for c in (data.get("crawl_endpoints") or [])}
    )
    contents = {
        str(h.get("response_content_type") or "").lower() for h in (data.get("har_requests") or [])
    }
    respkeys: set[str] = set()
    for h in data.get("har_requests") or []:
        rk = h.get("response_keys")
        parts = rk.split(",") if isinstance(rk, str) else (rk or [])
        respkeys |= {str(p).strip().lower() for p in parts}

    dns = report.get("dns_intelligence") or {}
    idp = " ".join(
        str(x).lower()
        for x in (
            (dns.get("auth_infrastructure") or {}).get("provider"),
            (report.get("auth_intelligence") or {})
            .get("exec_summary", {})
            .get("identity_provider"),
            *[i.get("identity_provider") for i in (data.get("idp_info") or [])],
        )
        if x
    )
    cloud = (dns.get("cloud_provider") or {}).get("provider") or (
        report.get("domain_intelligence") or {}
    ).get("cloud_provider")

    return {
        "cookies_blob": " ".join(cookies),
        "cookies": cookies,
        "servers": servers_blob.lower(),
        "tech": tech_blob.lower(),
        "dir_hits": dir_hits,
        "paths": " ".join(all_paths),
        "contents": " ".join(contents),
        "respkeys": respkeys,
        "idp": idp,
        "cloud": cloud,
    }


def _match(kind: str, needle: str, pools: dict) -> bool:
    if kind == "cookie":
        # Exact / prefix match against cookie NAMES (not a loose substring over a blob),
        # so e.g. `_session_id` does not false-match `auth_session_id`.
        return any(
            c == needle or c.startswith(needle) or (needle.startswith(".") and needle in c)
            for c in pools["cookies"]
        )
    if kind == "server":
        return needle in pools["servers"]
    if kind == "tech":
        return needle in pools["tech"]
    if kind in ("dir", "path"):
        blob = " ".join(d["path"] for d in pools["dir_hits"]) + " " + pools["paths"]
        return needle in blob
    if kind == "content":
        return needle in pools["contents"]
    if kind == "respkey":
        required = set(needle.split("|"))
        return len(required & pools["respkeys"]) >= max(2, len(required) - 1)
    if kind == "idp":
        return needle in pools["idp"]
    return False


def build_backend_intelligence(report: dict, data: dict | None = None) -> dict:
    """Correlate captured evidence into a backend technology fingerprint."""
    data = data or {}
    pools = _pools(report, data)

    frameworks: list[dict] = []
    for name, indicators in _SIGNATURES.items():
        evidence: list[dict] = []
        score = 0
        max_weight = 0
        for kind, needle, weight, label in indicators:
            if _match(kind, needle, pools):
                source = {
                    "cookie": "Cookies",
                    "server": "Server Header",
                    "tech": "Tech Fingerprint",
                    "dir": "Management/Path Discovery",
                    "path": "API / Path Discovery",
                    "content": "Response Content-Type",
                    "respkey": "Response Body Shape",
                    "idp": "Authentication Intelligence",
                }.get(kind, kind)
                evidence.append({"sign": label, "source": source})
                score += weight
                max_weight = max(max_weight, weight)
        # Never name a framework on a single weak indicator (spec: never rely on one).
        # Require ≥2 corroborating signals OR one distinctive high-signal indicator.
        if len(evidence) >= 2 or max_weight >= 3:
            level, pct = _pct(score, len(evidence))
            frameworks.append(
                {
                    "name": name,
                    "confidence": level,
                    "confidence_pct": pct,
                    "score": score,
                    "evidence": evidence,
                }
            )
    frameworks.sort(key=lambda f: f["score"], reverse=True)

    # Application server.
    application_server = "—"
    for label, sigs in _APP_SERVERS:
        if any(s in pools["servers"] for s in sigs):
            application_server = label
            break
    if application_server == "—" and "jsessionid" in pools["cookies_blob"]:
        application_server = "Servlet container (Tomcat/Jetty likely)"

    # Management endpoints (from the bounded probe / captured paths).
    management_endpoints: list[dict] = []
    for d in pools["dir_hits"]:
        p = d["path"]
        if (
            d["category"] == "management"
            or p.startswith("/actuator")
            or p
            in (
                "/health",
                "/management",
                "/manage",
            )
        ):
            sensitive = any(s in p for s in _ACTUATOR_SENSITIVE)
            management_endpoints.append(
                {
                    "endpoint": p,
                    "status": d["status"],
                    "risk": "High" if sensitive else "Medium",
                    "confidence": conf.HIGH,
                }
            )

    # API documentation.
    api_docs = [
        d["path"]
        for d in pools["dir_hits"]
        if any(s in d["path"] for s in ("swagger", "api-docs", "openapi", "redoc"))
    ]
    api_docs += [p for p in ("/graphql",) if p in pools["paths"]]

    # Authentication stack + identity provider (correlate with existing intelligence).
    idp_name = _title_idp(pools["idp"])
    auth_model = (report.get("auth_intelligence") or {}).get("authentication_model") or {}
    auth_stack = []
    primary = frameworks[0]["name"] if frameworks else None
    if primary == "Spring Boot" and (
        "spring_security_context" in pools["cookies_blob"] or "jsessionid" in pools["cookies_blob"]
    ):
        auth_stack.append("Spring Security")
    if idp_name:
        auth_stack.append(idp_name)
    for kw, label in (("oauth2", "OAuth2"), ("oidc", "OIDC"), ("pkce", "PKCE")):
        if kw in pools["paths"] or kw in pools["idp"]:
            auth_stack.append(label)

    services = _backend_services(
        frameworks, application_server, auth_stack, idp_name, api_docs, management_endpoints
    )
    priority_findings, high_value = _findings(primary, management_endpoints, api_docs, pools)
    testing = {
        f["name"]: _TESTING_RECS[f["name"]] for f in frameworks if f["name"] in _TESTING_RECS
    }
    developer_points = _developer_points(
        frameworks, application_server, auth_stack, management_endpoints, api_docs
    )

    summary = {
        "primary_framework": primary or "Not identified",
        "framework_confidence": frameworks[0]["confidence_pct"] if frameworks else "—",
        "application_server": application_server,
        "authentication": ", ".join(dict.fromkeys(auth_stack)) or auth_model.get("model", "—"),
        "identity_provider": idp_name or "—",
        "api_documentation": ", ".join(dict.fromkeys(api_docs)) or "not observed",
        "management_endpoints": len(management_endpoints),
        "cloud_platform": pools["cloud"] or "—",
        "backend_services": len(services),
        "frameworks_detected": len(frameworks),
    }

    return {
        "summary": summary,
        "frameworks": frameworks,
        "backend_services": services,
        "application_server": application_server,
        "authentication_stack": list(dict.fromkeys(auth_stack)),
        "identity_provider": idp_name or "",
        "api_documentation": list(dict.fromkeys(api_docs)),
        "management_endpoints": management_endpoints,
        "testing_recommendations": testing,
        "priority_findings": priority_findings,
        "high_value_findings": high_value,
        "developer_points": developer_points,
    }


def _title_idp(idp_blob: str) -> str:
    for kw, label in (
        ("keycloak", "Keycloak"),
        ("auth0", "Auth0"),
        ("okta", "Okta"),
        ("azure", "Azure AD"),
        ("entra", "Azure AD"),
        ("cognito", "AWS Cognito"),
        ("ping", "PingIdentity"),
    ):
        if kw in idp_blob:
            return label
    return ""


def _backend_services(frameworks, app_server, auth_stack, idp, api_docs, mgmt) -> list[dict]:
    rows: list[dict] = []
    for f in frameworks:
        rows.append(
            {
                "technology": f["name"],
                "component": "Web Framework",
                "version": "—",
                "confidence": f["confidence"],
                "evidence": "; ".join(e["sign"] for e in f["evidence"][:4]),
            }
        )
    if app_server not in ("—", ""):
        rows.append(
            {
                "technology": app_server,
                "component": "Application Server",
                "version": "—",
                "confidence": conf.HIGH,
                "evidence": "Server header / cookie",
            }
        )
    for a in dict.fromkeys(auth_stack):
        rows.append(
            {
                "technology": a,
                "component": "Authentication",
                "version": "—",
                "confidence": conf.HIGH if a == idp else conf.MEDIUM,
                "evidence": "Authentication Intelligence",
            }
        )
    if api_docs:
        rows.append(
            {
                "technology": "Swagger / OpenAPI",
                "component": "API Documentation",
                "version": "—",
                "confidence": conf.HIGH,
                "evidence": ", ".join(api_docs[:3]),
            }
        )
    if any("/actuator" in m["endpoint"] for m in mgmt):
        rows.append(
            {
                "technology": "Spring Boot Actuator",
                "component": "Management",
                "version": "—",
                "confidence": conf.HIGH,
                "evidence": "/actuator probe",
            }
        )
    if any("prometheus" in m["endpoint"] for m in mgmt):
        rows.append(
            {
                "technology": "Prometheus",
                "component": "Metrics",
                "version": "—",
                "confidence": conf.MEDIUM,
                "evidence": "/actuator/prometheus",
            }
        )
    return rows


def _findings(primary, mgmt, api_docs, pools) -> tuple[list[dict], list[dict]]:
    prio: list[dict] = []
    high: list[dict] = []
    actuators = [m for m in mgmt if "/actuator" in m["endpoint"]]
    if actuators:
        sensitive = [m for m in actuators if m["risk"] == "High"]
        ev = ", ".join(m["endpoint"] for m in actuators[:5])
        prio.append(
            {
                "priority": "P1",
                "area": "Spring Boot Actuator",
                "reason": "Actuator management endpoints exposed",
                "evidence": ev,
                "tests": [
                    "Actuator Information Disclosure",
                    "Env/Heapdump Review",
                    "Sensitive Endpoint Access",
                ],
            }
        )
        high.append(
            {
                "severity": "High" if sensitive else "Medium",
                "title": "Spring Boot Actuator exposed",
                "detail": f"Management endpoints reachable: {ev}. Review exposure and "
                f"restrict /actuator in production.",
            }
        )
    public_docs = [d for d in api_docs if "graphql" not in d]
    if public_docs:
        prio.append(
            {
                "priority": "P1",
                "area": "API Documentation",
                "reason": "Swagger/OpenAPI documentation discoverable",
                "evidence": ", ".join(public_docs[:3]),
                "tests": ["API Documentation Review", "Undocumented Endpoint Testing"],
            }
        )
        high.append(
            {
                "severity": "Medium",
                "title": "API documentation exposed",
                "detail": f"API docs reachable at {', '.join(public_docs[:3])}.",
            }
        )
    other_mgmt = [m for m in mgmt if "/actuator" not in m["endpoint"]]
    if other_mgmt:
        prio.append(
            {
                "priority": "P2",
                "area": "Management Endpoints",
                "reason": "Health/management endpoints reachable",
                "evidence": ", ".join(m["endpoint"] for m in other_mgmt[:4]),
                "tests": ["Health Endpoint Review", "Information Disclosure"],
            }
        )
    if primary == "Spring Boot":
        prio.append(
            {
                "priority": "P2",
                "area": "Spring Security",
                "reason": "Spring Security configuration review",
                "evidence": "Spring Boot detected",
                "tests": ["Authorization Rules", "Method Security", "CSRF"],
            }
        )
    return prio, high


def _developer_points(frameworks, app_server, auth_stack, mgmt, api_docs) -> list[str]:
    pts: list[str] = []
    if frameworks:
        pts.append(
            f"{frameworks[0]['name']} detected ({frameworks[0]['confidence_pct']} confidence) "
            f"from correlated evidence."
        )
    if app_server not in ("—", ""):
        pts.append(f"Application server: {app_server}.")
    for a in dict.fromkeys(auth_stack):
        pts.append(f"Authentication stack includes {a}.")
    if any("/actuator" in m["endpoint"] for m in mgmt):
        pts.append("Spring Boot Actuator management endpoints are exposed.")
    if api_docs:
        pts.append(f"API documentation is discoverable ({', '.join(api_docs[:3])}).")
    return pts
