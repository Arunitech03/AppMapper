"""Backend Service Intelligence & Per-Service Fingerprinting (Sprint B7 / B7.1).

Passively fingerprints the backend stack by CORRELATING evidence already gathered during
reconnaissance (the ``technologies`` fingerprint, session-cookie names, discovered
management/API-doc paths, identity-provider intelligence, response content-types and JSON
error shapes). B7.1 runs the fingerprint engine INDEPENDENTLY for every discovered backend
service (a modern app is a frontend + gateway + many services on different stacks), scoping
evidence to each service by host + path-prefix, and draws the Frontend→Gateway→Services→
Authentication→External architecture.

Never relies on a single indicator: every detection carries confidence + evidence + source.
Discovery/analysis only — no exploitation, brute force, or vulnerability scanning; reads
already-captured data (management endpoints come from the bounded, offline-gated probe).
"""

from __future__ import annotations

from urllib.parse import urlparse

from modules.intelligence import confidence as conf
from modules.intelligence.gateway_detector import service_of_path

# Each indicator: (kind, needle, weight, label). ``kind`` selects the evidence pool.
#   cookie  -> session-cookie names        server  -> Server-header tech names
#   tech    -> backend tech name/evidence  dir     -> a discovered path (200/401/403)
#   path    -> any observed path           content -> a response content-type
#   respkey -> a JSON error key set        idp     -> identity-provider name
# Kinds dir/path/content/respkey are SERVICE-SPECIFIC (attributable to one service);
# cookie/server/tech/idp are shared app/gateway context (corroboration only).
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
_SERVICE_KINDS = {"dir", "path", "content", "respkey"}

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
# Likely app server when a framework is detected but no server banner was captured.
_APP_SERVER_BY_FRAMEWORK = {
    "Spring Boot": "Servlet container (Tomcat/Jetty likely)",
    "ASP.NET Core": "Kestrel (likely)",
    "Django": "WSGI (Gunicorn/uWSGI likely)",
    "Flask": "WSGI (Werkzeug/Gunicorn likely)",
    "Node.js / Express": "Node.js runtime",
    "Ruby on Rails": "Puma (likely)",
    "PHP": "PHP-FPM (likely)",
}

_TESTING_RECS: dict[str, list[str]] = {
    "Spring Boot": [
        "Review Spring Security",
        "Review Spring Boot Actuator (env, beans, mappings, heapdump)",
        "Review Swagger / OpenAPI",
        "Review H2 Console",
        "Review SpEL injection",
        "Review Spring Data REST",
        "Review Health Endpoints",
    ],
    "ASP.NET Core": [
        "Review Swagger",
        "Review SignalR",
        "Review Blazor",
        "Review Health Checks",
        "Review Hangfire",
        "Review Anti-Forgery Tokens",
    ],
    "Django": [
        "Review Admin Portal (/admin)",
        "Review Debug Toolbar / DEBUG=True",
        "Review CSRF handling",
        "Review Session handling",
    ],
    "Flask": ["Review Werkzeug debugger (PIN)", "Review Jinja2 SSTI", "Review session signing"],
    "Laravel": ["Review Ignition debug page", "Review Sanctum/CSRF", "Review .env exposure"],
    "Node.js / Express": [
        "Review error stack leakage",
        "Review Helmet headers",
        "Review prototype pollution",
    ],
    "Ruby on Rails": [
        "Review mass assignment",
        "Review ActionDispatch errors",
        "Review CSRF tokens",
    ],
    "PHP": ["Review version disclosure", "Review session fixation", "Review framework debug pages"],
}

_ACTUATOR_SENSITIVE = ("env", "beans", "configprops", "heapdump", "threaddump", "mappings")
_FRONTEND_FRAMEWORKS = ("React", "Angular", "Vue", "Svelte", "Next.js", "Nuxt")
_SOURCE_LABELS = {
    "cookie": "Cookies",
    "server": "Server Header",
    "tech": "Tech Fingerprint",
    "dir": "Management/Path Discovery",
    "path": "API / Path Discovery",
    "content": "Response Content-Type",
    "respkey": "Response Body Shape",
    "idp": "Authentication Intelligence",
}


def _pct(score: int, n_evidence: int) -> tuple[str, str]:
    """Map (evidence score, distinct-signal count) to (confidence level, percentage)."""
    if n_evidence >= 3 or score >= 6:
        return conf.HIGH, "95%"
    if n_evidence >= 2:
        return conf.HIGH, "80%"
    if score >= 3:
        return conf.MEDIUM, "60%"
    return conf.LOW, "35%"


def _match(kind: str, needle: str, pools: dict) -> bool:
    if kind == "cookie":
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


def _global_pools(report: dict, data: dict) -> dict:
    """Shared, app-level evidence pools + per-request/dir attribution data for scoping."""
    techs = data.get("technologies") or []
    ts = report.get("technology_stack") or {}
    servers = " ".join(str(t.get("name", "")) for t in techs if t.get("category") == "server")
    servers += " " + " ".join(ts.get("servers") or [])
    tech = " ".join(
        f"{t.get('name', '')} {t.get('evidence', '')}"
        for t in techs
        if t.get("category") in ("backend", "server", "frontend")
    )
    tech += " " + " ".join((ts.get("backend") or []) + (ts.get("libraries") or []))

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
    dir_hits = []
    for d in directories:
        url = str(d.get("url", ""))
        dir_hits.append(
            {
                "path": str(d.get("path", "")).lower(),
                "url": url,
                "host": (urlparse(url).hostname or "").lower(),
                "status": d.get("status_code"),
                "category": d.get("category", ""),
            }
        )

    reqs = []
    for h in data.get("har_requests") or []:
        u = urlparse(str(h.get("url", "")))
        rk = h.get("response_keys")
        parts = rk.split(",") if isinstance(rk, str) else (rk or [])
        reqs.append(
            {
                "host": (u.hostname or "").lower(),
                "path": (u.path or "").lower(),
                "ct": str(h.get("response_content_type") or "").lower(),
                "rk": {str(p).strip().lower() for p in parts},
            }
        )

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
        "cookies": cookies,
        "servers": servers.lower(),
        "tech": tech.lower(),
        "idp": idp,
        "cloud": cloud,
        "dir_hits": dir_hits,
        "reqs": reqs,
    }


def _in_service(path: str, host: str, svc: str, svc_host: str) -> bool:
    if svc_host and host and host != svc_host:
        return False
    return path.startswith(f"/{svc}") or service_of_path(path) == svc


def _scope(gp: dict, host: str, service: str) -> dict:
    """A `_match`-shaped pool scoped to one service (own dir/path/content/respkey)."""
    sd = [d for d in gp["dir_hits"] if _in_service(d["path"], d["host"], service, host)]
    sr = [r for r in gp["reqs"] if _in_service(r["path"], r["host"], service, host)]
    respkeys: set = set()
    for r in sr:
        respkeys |= r["rk"]
    return {
        "cookies": gp["cookies"],
        "servers": gp["servers"],
        "tech": gp["tech"],
        "idp": gp["idp"],
        "dir_hits": [{"path": d["path"]} for d in sd],
        "paths": " ".join(d["path"] for d in sd) + " " + " ".join(r["path"] for r in sr),
        "contents": " ".join(r["ct"] for r in sr),
        "respkeys": respkeys,
        "_dir_hits_full": sd,
    }


def _fingerprint(pools: dict, *, allow_shared_only: bool) -> list[dict]:
    """Run the signature engine over a (possibly scoped) pool. Returns ranked frameworks.

    Requires corroboration (≥2 signals or one distinctive strong signal). Per-service,
    a framework must have at least one SERVICE-SPECIFIC signal unless this is the lone
    backend (``allow_shared_only``), so a shared cookie never fans out onto every service.
    """
    out: list[dict] = []
    for name, indicators in _SIGNATURES.items():
        evidence: list[dict] = []
        score = max_weight = 0
        specific = False
        for kind, needle, weight, label in indicators:
            if _match(kind, needle, pools):
                evidence.append({"sign": label, "source": _SOURCE_LABELS.get(kind, kind)})
                score += weight
                max_weight = max(max_weight, weight)
                specific = specific or kind in _SERVICE_KINDS
        if not evidence:
            continue
        if not (len(evidence) >= 2 or max_weight >= 3):
            continue
        if not (specific or allow_shared_only):
            continue
        level, pct = _pct(score, len(evidence))
        out.append(
            {
                "name": name,
                "confidence": level,
                "confidence_pct": pct,
                "score": score,
                "evidence": evidence,
            }
        )
    out.sort(key=lambda f: f["score"], reverse=True)
    return out


def _app_server(pools: dict, framework: str) -> str:
    for label, sigs in _APP_SERVERS:
        if any(s in pools["servers"] for s in sigs):
            return label
    return _APP_SERVER_BY_FRAMEWORK.get(framework, "—")


def _service_row(gp: dict, svc: dict, *, lone: bool, idp_name: str) -> dict:
    host = (svc.get("host") or "").lower()
    service = svc.get("service") or ""
    scoped = _scope(gp, host, service)
    fws = _fingerprint(scoped, allow_shared_only=lone)
    primary = fws[0] if fws else None
    framework = primary["name"] if primary else "Not identified"

    mgmt = []
    for d in scoped["_dir_hits_full"]:
        p = d["path"]
        if d["category"] == "management" or p.startswith("/actuator") or p.endswith("/health"):
            mgmt.append(
                {
                    "endpoint": d["path"],
                    "status": d["status"],
                    "risk": "High" if any(s in p for s in _ACTUATOR_SENSITIVE) else "Medium",
                }
            )
    swagger = sorted(
        {
            d["path"]
            for d in scoped["_dir_hits_full"]
            if any(s in d["path"] for s in ("swagger", "api-docs", "openapi", "redoc"))
        }
    )
    return {
        "service": _pretty_name(service),
        "raw_service": service,
        "base_url": svc.get("base_url") or (f"https://{host}/{service}" if host else ""),
        "host": host,
        "framework": framework,
        "framework_confidence": primary["confidence_pct"] if primary else "—",
        "application_server": _app_server(scoped, framework) if primary else "—",
        "authentication": idp_name or "—",
        "identity_provider": idp_name or "—",
        "swagger": ", ".join(swagger) if swagger else "—",
        "management_endpoints": mgmt,
        "cloud": gp["cloud"] or "—",
        "confidence": primary["confidence"] if primary else conf.LOW,
        "evidence": (primary or {}).get("evidence", []),
        "testing_recommendations": _TESTING_RECS.get(framework, []),
    }


def _pretty_name(service: str) -> str:
    words = service.replace("-", " ").replace("_", " ").split()
    return " ".join(w.upper() if w.lower() in ("api", "gis") else w.capitalize() for w in words)


def build_backend_intelligence(report: dict, data: dict | None = None) -> dict:
    """Per-service backend fingerprint + architecture (B7.1)."""
    data = data or {}
    gp = _global_pools(report, data)
    idp_name = _title_idp(gp["idp"])

    from modules.intelligence.service_registry import build_service_registry

    registry = build_service_registry(data)
    svc_records = registry.get("services") or []
    gateway_host = registry.get("gateway_host")
    lone = len(svc_records) <= 1

    services = [_service_row(gp, s, lone=lone, idp_name=idp_name) for s in svc_records]

    # Frontend node (from the existing frontend tech fingerprint).
    frontend_fw = next(
        (
            f
            for f in (report.get("technology_stack") or {}).get("frontend") or []
            if any(k.lower() in f.lower() for k in _FRONTEND_FRAMEWORKS)
        ),
        None,
    )
    target = (report.get("target") or {}) if isinstance(report.get("target"), dict) else {}
    target_url = target.get("url") or ""
    target_host = (urlparse(target_url).hostname or "").lower()
    frontend = None
    if frontend_fw or target_host:
        frontend = {
            "service": "Frontend",
            "base_url": target_url,
            "host": target_host,
            "framework": frontend_fw or "—",
            "framework_confidence": "high" if frontend_fw else "—",
            "application_server": "—",
            "authentication": idp_name or "—",
            "identity_provider": idp_name or "—",
            "swagger": "—",
            "management_endpoints": [],
            "cloud": gp["cloud"] or "—",
            "confidence": conf.HIGH if frontend_fw else conf.LOW,
            "evidence": (
                [{"sign": f"{frontend_fw} in tech fingerprint", "source": "Tech Fingerprint"}]
                if frontend_fw
                else []
            ),
            "testing_recommendations": [],
        }

    # Authentication node.
    auth = None
    if idp_name:
        auth = {
            "service": "Authentication",
            "base_url": (report.get("dns_intelligence") or {})
            .get("auth_infrastructure", {})
            .get("host")
            or "",
            "host": (report.get("dns_intelligence") or {})
            .get("auth_infrastructure", {})
            .get("host")
            or "",
            "framework": idp_name,
            "framework_confidence": "high",
            "application_server": "—",
            "authentication": "OIDC / OAuth2",
            "identity_provider": idp_name,
            "swagger": "—",
            "management_endpoints": [],
            "cloud": gp["cloud"] or "—",
            "confidence": conf.HIGH,
            "evidence": [
                {"sign": f"{idp_name} identity provider", "source": "Authentication Intelligence"}
            ],
            "testing_recommendations": [
                "Review OIDC/OAuth2 flows",
                "Review token lifetimes",
                "Review PKCE",
            ],
        }

    inventory = ([frontend] if frontend else []) + services + ([auth] if auth else [])
    architecture = _architecture(frontend, gateway_host, services, auth, report)
    priority_findings, high_value = _findings(services)
    summary = _summary(services, idp_name, gp["cloud"], frontend_fw)
    developer_points = _developer_points(services, gateway_host, idp_name, gp["cloud"])
    testing = {
        s["framework"]: s["testing_recommendations"]
        for s in services
        if s["testing_recommendations"]
    }

    return {
        "services": inventory,
        "backend_services_list": services,
        "architecture": architecture,
        "summary": summary,
        "priority_findings": priority_findings,
        "high_value_findings": high_value,
        "testing_recommendations": testing,
        "developer_points": developer_points,
        # Back-compat top-level keys (aggregate view).
        "frameworks": [
            {
                "name": s["framework"],
                "confidence_pct": s["framework_confidence"],
                "confidence": s["confidence"],
                "evidence": s["evidence"],
            }
            for s in services
            if s["framework"] != "Not identified"
        ],
        "application_server": summary["application_server"],
        "authentication_stack": [idp_name] if idp_name else [],
        "identity_provider": idp_name,
        "management_endpoints": [m for s in services for m in s["management_endpoints"]],
    }


def _architecture(frontend, gateway_host, services, auth, report) -> list[str]:
    lines: list[str] = []
    if frontend:
        fw = f" ({frontend['framework']})" if frontend["framework"] != "—" else ""
        lines.append(f"Frontend: {frontend['host'] or frontend['base_url']}{fw}")
    if gateway_host:
        lines.append(f"└── Gateway: {gateway_host}")
    for s in services:
        fw = s["framework"] if s["framework"] != "Not identified" else "framework not identified"
        lines.append(f"    ├── {s['service']} — {fw}  [{s['base_url']}]")
    if auth:
        lines.append(
            f"Authentication: {auth['framework']}" + (f" @ {auth['host']}" if auth["host"] else "")
        )
    ext = [
        e.get("service")
        for e in (report.get("dns_intelligence") or {}).get("external_dependencies", [])
    ]
    if ext:
        lines.append("External: " + ", ".join([x for x in ext if x][:8]))
    return lines


def _findings(services: list[dict]) -> tuple[list[dict], list[dict]]:
    prio: list[dict] = []
    high: list[dict] = []
    for s in services:
        name = s["service"]
        actuators = [m for m in s["management_endpoints"] if "/actuator" in m["endpoint"]]
        if actuators:
            ev = ", ".join(f"{m['endpoint']} ({m['status']})" for m in actuators[:5])
            prio.append(
                {
                    "priority": "P1",
                    "area": f"{name} — Spring Boot Actuator",
                    "reason": "Actuator management endpoints detected",
                    "evidence": ev,
                    "tests": ["Actuator Information Disclosure", "Review Management Endpoints"],
                }
            )
            high.append(
                {
                    "severity": "High" if any(m["risk"] == "High" for m in actuators) else "Medium",
                    "title": f"{name}: Spring Boot Actuator detected",
                    "detail": f"Management endpoints on {name}: {ev}. Review exposure.",
                }
            )
        if s["swagger"] != "—":
            prio.append(
                {
                    "priority": "P1",
                    "area": f"{name} — API Documentation",
                    "reason": "Swagger/OpenAPI discoverable",
                    "evidence": s["swagger"],
                    "tests": ["Review API Documentation", "Undocumented Endpoint Testing"],
                }
            )
            high.append(
                {
                    "severity": "Medium",
                    "title": f"{name}: Swagger publicly accessible",
                    "detail": f"API docs on {name}: {s['swagger']}.",
                }
            )
        health = [m for m in s["management_endpoints"] if m["endpoint"].endswith("/health")]
        if health and not actuators:
            prio.append(
                {
                    "priority": "P2",
                    "area": f"{name} — Health Endpoint",
                    "reason": "Health/management endpoint reachable",
                    "evidence": ", ".join(m["endpoint"] for m in health[:3]),
                    "tests": ["Review Health Endpoints", "Information Disclosure"],
                }
            )
        if s["framework"] == "Spring Boot":
            prio.append(
                {
                    "priority": "P2",
                    "area": f"{name} — Spring Security",
                    "reason": "Spring Security configuration review",
                    "evidence": "Spring Boot detected",
                    "tests": ["Authorization Rules", "CSRF"],
                }
            )
    return prio, high


def _summary(services: list[dict], idp: str, cloud, frontend_fw) -> dict:
    def fam(name):
        return sum(1 for s in services if s["framework"] == name)

    identified = [s for s in services if s["framework"] != "Not identified"]
    frameworks = [s["framework"] for s in identified]
    primary = max(set(frameworks), key=frameworks.count) if frameworks else "Not identified"
    app_servers = [s["application_server"] for s in identified if s["application_server"] != "—"]
    return {
        "backend_services": len(services),
        "frameworks_detected": len(identified),
        "spring_services": fam("Spring Boot"),
        "aspnet_services": fam("ASP.NET Core"),
        "node_services": fam("Node.js / Express"),
        "auth_services": 1 if idp else 0,
        "management_endpoints": sum(len(s["management_endpoints"]) for s in services),
        "swagger_endpoints": sum(1 for s in services if s["swagger"] != "—"),
        "health_endpoints": sum(
            1
            for s in services
            for m in s["management_endpoints"]
            if m["endpoint"].endswith("/health")
        ),
        "cloud_services": 1 if cloud else 0,
        "primary_framework": primary,
        "framework_confidence": identified[0]["framework_confidence"] if identified else "—",
        "application_server": app_servers[0] if app_servers else "—",
        "identity_provider": idp or "—",
        "cloud_platform": cloud or "—",
        "frontend_framework": frontend_fw or "—",
    }


def _developer_points(services, gateway_host, idp, cloud) -> list[str]:
    pts: list[str] = []
    identified = [s for s in services if s["framework"] != "Not identified"]
    fw_by_service = {s["service"]: s["framework"] for s in identified}
    if len(services) > 1:
        pts.append(
            f"Frontend communicates with {len(services)} backend service(s) via the gateway."
        )
    for name, fw in fw_by_service.items():
        others = [f for f in fw_by_service.values() if f == fw]
        if len(others) == 1:
            pts.append(f"{fw} detected only on {name}.")
    if gateway_host and len({s["framework"] for s in identified}) > 1:
        pts.append(
            f"Gateway ({gateway_host}) proxies requests to heterogeneous backend frameworks."
        )
    for s in services:
        if any("/actuator" in m["endpoint"] for m in s["management_endpoints"]):
            pts.append(f"Management endpoints discovered on {s['service']}.")
        if s["swagger"] != "—":
            pts.append(f"Swagger exposed for {s['service']}.")
    if idp:
        pts.append(f"Authentication handled by {idp}.")
    if cloud:
        pts.append(f"Cloud platform: {cloud}.")
    return pts
