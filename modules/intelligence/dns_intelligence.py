"""DNS Intelligence & Infrastructure Discovery.

Consolidates a host inventory and derives the infrastructure picture — cloud provider,
authentication infrastructure, gateways, external dependencies, host relationships, DNS
security findings, and per-host pentest value — from already-collected data, enriched by
the opt-in passive DNS records (``--dns``).

Passive / discovery only: no active enumeration; resolves nothing here (DNS lookups happen
at scan time over discovered hosts only). Pure derivation over the assembled report.
"""

from __future__ import annotations

from modules.intelligence.domain_classifier import registrable_domain

_CLOUD_SIGS = (
    (
        "Microsoft Azure",
        (
            "azurefd.net",
            "azurewebsites.net",
            "blob.core.windows.net",
            "azureedge.net",
            "azure-api.net",
            "trafficmanager.net",
        ),
    ),
    ("AWS", ("amazonaws.com", "cloudfront.net", "elb.amazonaws.com", "awsglobalaccelerator.com")),
    ("Google Cloud", ("googleapis.com", "run.app", "appspot.com", "googleusercontent.com")),
    ("Cloudflare", ("cloudflare", "workers.dev", "pages.dev")),
)
_AUTH_SIGS = (
    ("Keycloak", ("keycloak", "/realms/", "/auth/realms/")),
    ("Auth0", (".auth0.com",)),
    ("Okta", (".okta.com", ".oktapreview.com")),
    ("Azure AD", ("login.microsoftonline.com", "login.windows.net", "sts.windows.net")),
    ("Ping Identity", (".pingidentity.com", "pingone.com")),
    ("ForgeRock", ("forgerock", "forgeblocks.com")),
    ("AWS Cognito", ("cognito-idp", "amazoncognito.com")),
)
_GATEWAY_SIGS = ("gateway-proxy", "gateway", "kong", "apigee", "api-management", "apim", "tyk")
_GIS_SIGS = ("gis", "geoserver", "geo", "arcgis", "map", "carto")
_DEP_SIGS = {
    "Mapbox": ("mapbox",),
    "ESRI / ArcGIS": ("esri", "arcgis"),
    "Google Maps": ("maps.google", "googleapis"),
    "Datadog": ("datadog",),
    "LaunchDarkly": ("launchdarkly",),
    "Sentry": ("sentry",),
    "Segment": ("segment.io", "segment.com"),
    "Amplitude": ("amplitude",),
    "New Relic": ("newrelic", "nr-data.net"),
    "Azure Monitor": ("applicationinsights", "monitor.azure"),
}
_PENTEST_VALUE = {
    "Authentication": ["Authentication Flows", "OIDC Configuration", "Session Management"],
    "API Gateway": ["API Discovery", "Authorization Testing"],
    "GIS Service": ["Data Exposure", "Function Abuse"],
    "Internal Service": ["Hidden APIs", "Authorization"],
    "Application": ["Authorization Testing"],
    "Third-Party Service": ["Trust Boundary Review"],
}


def build_dns_intelligence(report: dict, data: dict | None = None) -> dict:
    """Build the DNS / infrastructure intelligence section."""
    data = data or {}
    di = report.get("domain_intelligence") or {}
    base_host = (report.get("target") or {}).get("domain") or di.get("base_host") or ""
    services = (report.get("javascript_intelligence") or {}).get("service_inventory") or []
    dns_records = data.get("dns_records") or report.get("dns_records") or []
    auth_infra = di.get("auth_infra") or {}
    third_party = di.get("third_party") or []

    host_inventory = _host_inventory(di, services, base_host)
    cloud = _cloud_provider(host_inventory, dns_records)
    auth_infrastructure = _auth_infrastructure(report, auth_infra)
    gateways = _gateways(host_inventory, services)
    external = _external_dependencies(third_party, services)
    findings = _dns_security_findings(dns_records, base_host)
    relationship = _relationship_map(host_inventory, base_host)
    pentest = {
        purpose: _PENTEST_VALUE[purpose]
        for purpose in sorted({h["purpose"] for h in host_inventory})
        if purpose in _PENTEST_VALUE
    }

    summary = {
        "hosts": len(host_inventory),
        "internal_services": len(services),
        "gateways": len(gateways),
        "auth_providers": 1 if auth_infrastructure else 0,
        "cloud_providers": cloud.get("provider") if cloud else "—",
        "third_parties": len(external),
        "dns_findings": len(findings),
    }
    return {
        "host_inventory": host_inventory,
        "dns_records": dns_records,
        "cloud_provider": cloud,
        "auth_infrastructure": auth_infrastructure,
        "gateways": gateways,
        "external_dependencies": external,
        "relationship_map": relationship,
        "dns_security_findings": findings,
        "summary": summary,
        "developer_points": _developer_points(
            summary, cloud, auth_infrastructure, gateways, findings
        ),
        "pentest_value": pentest,
    }


# ---------------------------------------------------------------------------


def _purpose(host: str, classification: str) -> str:
    h = host.lower()
    if any(s in h for s in _GATEWAY_SIGS):
        return "API Gateway"
    if any(s in h for s in _GIS_SIGS):
        return "GIS Service"
    for _name, sigs in _AUTH_SIGS:
        if any(s.strip("/.") in h for s in sigs if "/" not in s):
            return "Authentication"
    if "auth" in h:
        return "Authentication"
    mapping = {
        "Authentication Provider": "Authentication",
        "API Gateway": "API Gateway",
        "Third Party Service": "Third-Party Service",
        "Primary Application": "Application",
    }
    if classification in mapping:
        return mapping[classification]
    if classification in ("Internal API", "Microservice"):
        return "Internal Service"
    return "Application"


def _host_inventory(di: dict, services: list, base_host: str) -> list[dict]:
    rows: dict[str, dict] = {}

    def add(host, source, observed, confidence, classification=""):
        host = (host or "").strip().lower().rstrip(".")
        if not host or "." not in host:
            return
        existing = rows.get(host)
        if existing is None:
            rows[host] = {
                "host": host,
                "purpose": _purpose(host, classification),
                "source": source,
                "observed": observed,
                "confidence": confidence,
            }
        elif observed and not existing["observed"]:
            existing["observed"] = True

    for h in di.get("hosts") or []:
        add(
            h.get("host"),
            "HAR",
            bool(h.get("requests")),
            h.get("confidence", "medium"),
            h.get("classification", ""),
        )
    for h in (di.get("auth_infra") or {}).get("hosts") or []:
        add(h, "Redirect / JWT", True, "high")
    for s in services:
        add(
            s.get("host"),
            s.get("source") or "Service Inventory",
            bool(s.get("observed")),
            s.get("confidence", "medium"),
        )
    return sorted(rows.values(), key=lambda r: (_PURPOSE_RANK.get(r["purpose"], 9), r["host"]))


_PURPOSE_RANK = {
    "Authentication": 0,
    "API Gateway": 1,
    "Internal Service": 2,
    "GIS Service": 3,
    "Application": 4,
    "Third-Party Service": 5,
}


def _cloud_provider(host_inventory: list, dns_records: list) -> dict:
    evidence: list[str] = []
    provider = None
    blobs = [r.get("value", "") for r in dns_records] + [h["host"] for h in host_inventory]
    for name, sigs in _CLOUD_SIGS:
        hits = [b for b in blobs if any(s in str(b).lower() for s in sigs)]
        if hits:
            provider = name
            evidence = sorted(set(hits))[:6]
            break
    if not provider:
        return {}
    confidence = (
        "High"
        if any("." in e and e in [r.get("value") for r in dns_records] for e in evidence)
        else "Medium"
    )
    return {"provider": provider, "confidence": confidence, "evidence": evidence}


def _auth_infrastructure(report: dict, auth_infra: dict) -> dict:
    jwt = (report.get("jwt_intelligence") or {}).get("primary") or {}
    provider = auth_infra.get("identity_provider") or jwt.get("identity_provider")
    host = (auth_infra.get("hosts") or [None])[0]
    realm = jwt.get("realm")
    if not provider or provider == "Unknown":
        # try issuer signature
        iss = (jwt.get("issuer") or "").lower()
        for name, sigs in _AUTH_SIGS:
            if any(s in iss for s in sigs):
                provider = name
                break
    if not provider or provider == "Unknown":
        return {}
    return {
        "provider": provider,
        "host": host,
        "realm": realm,
        "source": "JWT Issuer" if realm else "Redirect / Runtime Config",
    }


def _gateways(host_inventory: list, services: list) -> list[dict]:
    out: list[dict] = []
    seen = set()
    for h in host_inventory:
        if h["purpose"] == "API Gateway" and h["host"] not in seen:
            seen.add(h["host"])
            out.append(
                {
                    "host": h["host"],
                    "type": "API Gateway",
                    "confidence": "High",
                    "evidence": h["source"],
                }
            )
    return out


def _external_dependencies(third_party: list, services: list) -> list[dict]:
    out: list[dict] = []
    seen = set()
    candidates = [(h.get("host"), "HAR") for h in third_party if isinstance(h, dict)]
    candidates += [(s.get("host"), s.get("source")) for s in services]
    for host, source in candidates:
        if not host:
            continue
        low = str(host).lower()
        for name, sigs in _DEP_SIGS.items():
            if any(s in low for s in sigs) and name not in seen:
                seen.add(name)
                out.append(
                    {
                        "service": name,
                        "host": host,
                        "purpose": "Integration",
                        "observed": True,
                        "source": source or "HAR",
                    }
                )
    return out


def _relationship_map(host_inventory: list, base_host: str) -> list[str]:
    children = [h["host"] for h in host_inventory if h["host"] != base_host.lower()]
    if not (base_host and children):
        return []
    lines = [base_host]
    for i, c in enumerate(children[:12]):
        lines.append(("└── " if i == min(len(children), 12) - 1 else "├── ") + c)
    return lines


def _dns_security_findings(dns_records: list, base_host: str) -> list[dict]:
    findings: list[dict] = []
    by_host: dict[str, dict] = {}
    for r in dns_records:
        by_host.setdefault(r["host"], {}).setdefault(r["record_type"], []).append(r["value"])

    # Dangling CNAME: a CNAME exists but the host has no A/AAAA.
    for host, recs in by_host.items():
        if recs.get("CNAME") and not (recs.get("A") or recs.get("AAAA")):
            findings.append(
                {
                    "finding": "Potential dangling CNAME",
                    "detail": f"{host} → {recs['CNAME'][0]} (no A/AAAA)",
                    "risk": "Subdomain Takeover Candidate",
                    "severity": "High",
                }
            )

    # Email posture (root domain TXT records): SPF / DMARC.
    reg = registrable_domain(base_host) if base_host else ""
    txt_blob = " ".join(
        v
        for host, recs in by_host.items()
        if registrable_domain(host) == reg
        for v in recs.get("TXT", [])
    ).lower()
    dmarc_present = any(
        "v=dmarc1" in " ".join(recs.get("TXT", [])).lower()
        for host, recs in by_host.items()
        if host.startswith("_dmarc")
    )
    if reg and txt_blob:
        spf = "v=spf1" in txt_blob
        findings.append(
            {
                "finding": "Email security posture",
                "detail": f"SPF: {'Present' if spf else 'Missing'} · DMARC: "
                f"{'Present' if dmarc_present else 'Missing'}",
                "risk": "Email spoofing exposure" if not dmarc_present else "—",
                "severity": "Medium" if not dmarc_present else "Positive",
            }
        )
    return findings


def _developer_points(summary, cloud, auth, gateways, findings) -> list[str]:
    pts: list[str] = []
    if auth:
        pts.append("Authentication infrastructure exposed via runtime configuration.")
    if gateways:
        pts.append(f"{len(gateways)} API Gateway discovered.")
    if summary.get("internal_services"):
        pts.append(f"{summary['internal_services']} internal services identified.")
    if cloud:
        pts.append(f"{cloud['provider']} infrastructure identified.")
    if summary.get("third_parties"):
        pts.append("Multiple third-party integrations detected.")
    for f in findings:
        if "dangling" in f["finding"].lower():
            pts.append("Potential dangling CNAME identified.")
        if "wildcard" in f["finding"].lower():
            pts.append("DNS wildcard detected.")
    return pts
