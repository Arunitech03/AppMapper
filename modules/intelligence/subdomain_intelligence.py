"""Passive Subdomain Intelligence.

Correlates passively-enumerated subdomains (crt.sh / AlienVault OTX / BufferOver /
RapidDNS / SecurityTrails / VirusTotal — collected at scan time by
``modules.recon.subdomains``) with hosts already discovered at runtime (HAR, JS,
runtime-config, redirects, JWT issuer) into one host inventory with **source
attribution**, **confidence scoring**, and **cloud-provider detection**.

Pure derivation over the assembled report (no network here). Reuses the cloud
signatures / purpose classifier from :mod:`dns_intelligence` and
``registrable_domain`` from :mod:`domain_classifier` — no duplication.
"""

from __future__ import annotations

from urllib.parse import urlparse

from modules.intelligence.dns_intelligence import _CLOUD_SIGS, _PURPOSE_RANK, _purpose

# Provider display names emitted by modules.recon.subdomains (passive sources).
_PASSIVE_PROVIDERS = {
    "crt.sh",
    "AlienVault OTX",
    "BufferOver",
    "RapidDNS",
    "SecurityTrails",
    "VirusTotal",
}
_CONF_RANK = {"High": 0, "Medium": 1, "Low": 2}


def _split_sources(value: str | None) -> list[str]:
    return [s.strip() for s in (value or "").split(",") if s.strip()]


def _host_from_url(url: str) -> str:
    if not url:
        return ""
    netloc = urlparse(url if "//" in url else f"//{url}").netloc or url
    return netloc.split("@")[-1].split(":")[0].strip().lower()


def build_subdomain_intelligence(report: dict, data: dict | None = None) -> dict:
    """Build the Passive Subdomain Intelligence section."""
    data = data or {}
    di = report.get("domain_intelligence") or {}
    services = (report.get("javascript_intelligence") or {}).get("service_inventory") or []
    subdomains = data.get("subdomains") or report.get("subdomains") or []
    dns_records = data.get("dns_records") or report.get("dns_records") or []
    jwt = (report.get("jwt_intelligence") or {}).get("primary") or {}

    # host -> aggregated provenance
    agg: dict[str, dict] = {}

    def add(host, source, *, observed=False, resolved=False, classification=""):
        host = (host or "").strip().lower().rstrip(".").lstrip("*.")
        if not host or "." not in host:
            return
        row = agg.setdefault(
            host,
            {"sources": set(), "observed": False, "resolved": False, "classification": ""},
        )
        if source:
            row["sources"].add(source)
        row["observed"] = row["observed"] or observed
        row["resolved"] = row["resolved"] or resolved
        if classification and not row["classification"]:
            row["classification"] = classification

    # Passive subdomains (each carries comma-joined provider attribution).
    for s in subdomains:
        for src in _split_sources(s.get("source")) or ["crt.sh"]:
            add(s.get("name"), src, resolved=bool(s.get("resolved")))

    # Step-7 runtime hosts — same sources dns_intelligence consolidates.
    for h in di.get("hosts") or []:
        add(
            h.get("host"),
            "HAR",
            observed=bool(h.get("requests")),
            classification=h.get("classification", ""),
        )
    for h in (di.get("auth_infra") or {}).get("hosts") or []:
        add(h, "Redirect / JWT", observed=True)
    for s in services:
        add(s.get("host"), s.get("source") or "Service Inventory", observed=bool(s.get("observed")))
    add(_host_from_url(jwt.get("issuer", "")), "JWT Issuer", observed=True)

    # CNAME values per host (for per-host cloud attribution).
    cnames: dict[str, list[str]] = {}
    for r in dns_records:
        if r.get("record_type") == "CNAME":
            cnames.setdefault((r.get("host") or "").lower(), []).append(r.get("value", ""))

    hosts = [_finalize(h, row, cnames) for h, row in agg.items()]
    hosts.sort(
        key=lambda r: (_PURPOSE_RANK.get(r["purpose"], 9), _CONF_RANK[r["confidence"]], r["host"])
    )

    passive_sources = sorted(
        {src for row in agg.values() for src in row["sources"] if src in _PASSIVE_PROVIDERS}
    )
    summary = {
        "passive_sources": passive_sources,
        "subdomains_found": sum(1 for h in hosts if h["_passive"]),
        "resolved_hosts": sum(1 for h in hosts if h["resolved"]),
        "internal_services": sum(1 for h in hosts if h["purpose"] == "Internal Service"),
        "authentication_hosts": sum(1 for h in hosts if h["purpose"] == "Authentication"),
        "gateway_hosts": sum(1 for h in hosts if h["purpose"] == "API Gateway"),
    }
    # strip private fields from the public rows
    rows = [{k: v for k, v in h.items() if not k.startswith("_")} for h in hosts]
    return {
        "hosts": rows,
        "sources_queried": passive_sources,
        "summary": summary,
        "developer_points": _developer_points(hosts, passive_sources, summary),
    }


def _finalize(host: str, row: dict, cnames: dict) -> dict:
    sources = row["sources"]
    resolved, observed = row["resolved"], row["observed"]
    if observed or resolved:
        confidence = "High"
    elif len(sources) >= 2:
        confidence = "Medium"
    else:
        confidence = "Low"
    return {
        "host": host,
        "source": ", ".join(sorted(sources)),
        "resolved": resolved,
        "provider": _host_cloud(host, cnames.get(host, [])),
        "confidence": confidence,
        "purpose": _purpose(host, row["classification"]),
        "_passive": bool(sources & _PASSIVE_PROVIDERS),
    }


def _host_cloud(host: str, cname_values: list[str]) -> str:
    blob = [host, *cname_values]
    for name, sigs in _CLOUD_SIGS:
        if any(s in str(b).lower() for b in blob for s in sigs):
            return name
    return "—"


def _developer_points(hosts: list[dict], passive_sources: list[str], summary: dict) -> list[str]:
    pts: list[str] = []
    if passive_sources and "crt.sh" not in passive_sources:
        pts.append("crt.sh returned no results; alternative passive sources were used.")
    runtime_only = [h for h in hosts if not h["_passive"] and h["source"] not in ("", "JWT Issuer")]
    if runtime_only:
        pts.append("Runtime configuration exposed hosts not indexed by passive DNS.")
    if summary["authentication_hosts"]:
        pts.append("Authentication infrastructure identified.")
    if summary["gateway_hosts"]:
        pts.append("API Gateway identified.")
    if summary["internal_services"] >= 2:
        pts.append("Multiple internal services discovered.")
    providers = sorted({h["provider"] for h in hosts if h["provider"] != "—"})
    for p in providers:
        pts.append(f"{p}-hosted infrastructure detected.")
    return pts
