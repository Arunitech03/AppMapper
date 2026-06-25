"""Sprint B.3: Canonical Internal Service Registry + full-URL correlation.

Single source of truth for the backend services an application talks to, mapping
each service to its **full base URL / host / source** and whether it was
*referenced* (in JS/config) vs. *observed* (in captured traffic). Other sections
use ``resolve(path)`` to turn a path-only endpoint
(``/anomaly-detection-backend/api``) into a fully-qualified one
(``https://gateway-proxy-qa.example.com/anomaly-detection-backend/api``) with
host / service / source / confidence metadata. Pure/offline.
"""

from __future__ import annotations

from urllib.parse import urlparse

from modules.intelligence.confidence import strongest

_CONF_ORDER = {"high": 0, "medium": 1, "low": 2}


def _service_of(path: str) -> str | None:
    from modules.intelligence.gateway_detector import service_of_path

    return service_of_path(path or "")


def build_service_registry(data: dict) -> dict:
    """Build the canonical service registry + a path->full-URL resolver."""
    services: dict[str, dict] = {}

    def upsert(
        service,
        *,
        base_url=None,
        host=None,
        source=None,
        confidence="medium",
        referenced=False,
        observed=False,
    ):
        if not service:
            return
        rec = services.setdefault(
            service,
            {
                "service": service,
                "base_url": None,
                "host": None,
                "source": None,
                "confidence": "low",
                "referenced": False,
                "observed": False,
            },
        )
        # Prefer a base_url that includes the service path; keep the most specific.
        if base_url and (rec["base_url"] is None or len(base_url) > len(rec["base_url"])):
            rec["base_url"] = base_url
        if host and not rec["host"]:
            rec["host"] = host
        if source and not rec["source"]:
            rec["source"] = source
        rec["confidence"] = strongest(rec["confidence"], confidence)
        rec["referenced"] = rec["referenced"] or referenced
        rec["observed"] = rec["observed"] or observed

    gateway_host = _primary_gateway(data)

    # 1) Runtime-config full URLs (highest-context source, e.g. env-config.js).
    for f in data.get("intel_findings", []) or []:
        if f.get("kind") not in {"runtime_config", "internal_app_ref"}:
            continue
        val = f.get("value_masked")
        if not isinstance(val, str) or not val.startswith("http"):
            continue
        u = urlparse(val)
        path = u.path or ""
        svc = _service_of(path)
        src = _source_label(f.get("location"))
        if svc:
            upsert(
                svc, base_url=val, host=u.hostname, source=src, confidence="high", referenced=True
            )

    # 2) Observed traffic — confirms host + observed=True.
    for key in ("har_requests", "crawl_endpoints", "burp_requests"):
        for r in data.get(key, []) or []:
            u = urlparse(r.get("url", ""))
            if not u.hostname:
                continue
            svc = _service_of(u.path or "")
            if not svc:
                continue
            base = f"{u.scheme}://{u.hostname}/{svc}"
            upsert(
                svc,
                base_url=base,
                host=u.hostname,
                source="Observed traffic",
                confidence="high",
                observed=True,
            )

    # 3) Gateway fallback — services with no host inherit the single gateway host.
    if gateway_host:
        for rec in services.values():
            if not rec["host"]:
                rec["host"] = gateway_host
                rec["base_url"] = rec["base_url"] or f"https://{gateway_host}/{rec['service']}"
                rec["source"] = rec["source"] or "API Gateway"
                rec["confidence"] = strongest(rec["confidence"], "medium")

    records = sorted(services.values(), key=lambda r: r["service"])
    return {
        "services": records,
        "by_service": services,
        "gateway_host": gateway_host,
        "resolve": lambda path: _resolve(path, services, gateway_host),
    }


def resolve_path(registry: dict, path: str) -> dict | None:
    """Resolve a path to ``{full_url, host, service, source, confidence}`` or None."""
    return _resolve(path, registry.get("by_service", {}), registry.get("gateway_host"))


def _resolve(path: str, services: dict, gateway_host: str | None) -> dict | None:
    if not path or not path.startswith("/"):
        return None
    svc = _service_of(path)
    rec = services.get(svc) if svc else None
    if rec and rec.get("host"):
        host = rec["host"]
    elif svc and gateway_host:
        host = gateway_host  # a service-looking path under the known gateway
    else:
        return None  # navigation/unknown path — keep the path-only form
    scheme = "https"
    if rec and rec.get("base_url", "").startswith("http"):
        scheme = urlparse(rec["base_url"]).scheme or "https"
    return {
        "full_url": f"{scheme}://{host}{path}",
        "host": host,
        "service": svc,
        "source": (rec or {}).get("source") or "API Gateway",
        "confidence": (rec or {}).get("confidence") or "medium",
    }


def _primary_gateway(data: dict) -> str | None:
    """The single same-org API-gateway host, if unambiguous."""
    from modules.intelligence.domain_classifier import registrable_domain
    from modules.intelligence.gateway_detector import detect_gateways

    target = data.get("target", {}) or {}
    base = target.get("domain") or urlparse(target.get("url", "")).hostname or ""
    base_reg = registrable_domain(base) if base else ""
    gws = [
        g["host"]
        for g in detect_gateways(data)
        if not base_reg or registrable_domain(g["host"]) == base_reg
    ]
    # Prefer a gateway/proxy-named host; else the one fronting the most services.
    named = [h for h in gws if any(k in h.lower() for k in ("gateway", "proxy", "apigw"))]
    if named:
        return sorted(named)[0]
    return gws[0] if len(gws) == 1 else (sorted(gws)[0] if gws else None)


def _source_label(location: str | None) -> str:
    loc = (location or "").lower()
    if "env-config" in loc or "env_config" in loc:
        return "env-config.js"
    if "window." in loc:
        return "Runtime Config"
    if loc.endswith(".js") or "/main" in loc or "bundle" in loc:
        return "JS bundle"
    return "Runtime Config"
