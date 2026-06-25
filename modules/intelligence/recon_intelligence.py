"""Aggregator for Sprint A recon intelligence consumed by the report.

Assembles the secret/config/route/hidden-endpoint/storage/business-function/
correlation outputs into one structure from the stored ``data`` (content findings
were persisted by the orchestrator's content-intelligence phase). Pure/offline.
"""

from __future__ import annotations


def build_recon_intelligence(data: dict) -> dict:
    """Single structure the report renders for the Sprint-A / A.5 sections."""
    from modules.intelligence.business_function_discovery import discover_business_functions
    from modules.intelligence.correlation_engine import correlate, recon_targets
    from modules.intelligence.hidden_endpoint_discovery import find_hidden_endpoints
    from modules.intelligence.pentest_targets import target_queue, top_targets
    from modules.intelligence.risk_scoring import score_endpoints
    from modules.intelligence.sensitive_schema import analyze_sensitive_schemas
    from modules.intelligence.storage_intelligence import analyze_storage
    from modules.intelligence.telemetry_classifier import telemetry_inventory

    findings = data.get("intel_findings", []) or []

    # Group secret/config/etc. findings by category for the report.
    secret_groups: dict[str, list[dict]] = {}
    routes: list[str] = []
    hidden_apis: list[str] = []
    sourcemaps: list[str] = []
    config: list[dict] = []
    for f in findings:
        kind = f.get("kind")
        if kind == "route":
            routes.append(f.get("name", ""))
        elif kind == "api_ref":
            hidden_apis.append(f.get("name", ""))
        elif kind == "sourcemap":
            sourcemaps.append(f.get("name", ""))
        elif kind == "config":
            config.append(f)
        else:
            secret_groups.setdefault(f.get("category", "Other"), []).append(f)

    # Sprint A.5 precision/prioritization layers.
    hidden = find_hidden_endpoints(data)
    sensitive_models = analyze_sensitive_schemas(data)
    risk_surface = score_endpoints(data)
    targets = top_targets(data, n=10)
    queue = target_queue(data)
    telemetry = telemetry_inventory(data)

    summary = {
        "admin_only_endpoints": sum(1 for r in risk_surface if r["admin_only"]),
        "sensitive_data_endpoints": len(sensitive_models),
        "idor_candidates": sum(1 for s in sensitive_models if s["idor_candidate"]),
        "hidden_endpoints": len(hidden),
        "secrets": sum(len(v) for v in secret_groups.values()),
        "telemetry_endpoints": len(telemetry),
        "immediate_targets": len(queue.get("Immediate", [])),
        "headline_targets": [t["endpoint"] for t in targets[:5]],
    }

    return {
        "secret_findings": secret_groups,
        "secret_count": sum(len(v) for v in secret_groups.values()),
        "frontend_routes": sorted({r for r in routes if r}),
        "hidden_api_candidates": sorted({a for a in hidden_apis if a}),
        "source_maps": sorted({s for s in sourcemaps if s}),
        "configuration": config,
        "hidden_endpoints": hidden,
        "storage": analyze_storage(data),
        "business_functions": discover_business_functions(data),
        "correlation": correlate(data),
        "recon_targets": recon_targets(data),
        # A.5
        "summary": summary,
        "sensitive_data_models": sensitive_models,
        "risk_attack_surface": risk_surface,
        "top_targets": targets,
        "target_queue": queue,
        "telemetry_inventory": telemetry,
        "confidence_breakdown": _confidence_breakdown(data, risk_surface, sensitive_models, hidden),
    }


def _confidence_breakdown(data, risk_surface, sensitive_models, hidden) -> dict:
    """Count findings by confidence level across the precision findings (Issue 9)."""
    counts = {"high": 0, "medium": 0, "low": 0}

    def bump(level: str) -> None:
        if level in counts:
            counts[level] += 1

    for r in risk_surface:
        bump(r.get("confidence", "medium"))
    for s in sensitive_models:
        bump(s.get("confidence", "medium"))
    for _ in hidden:
        bump("medium")  # referenced-not-observed
    for f in data.get("intel_findings", []) or []:
        bump((f.get("confidence") or "medium").lower())
    for fn in data.get("sensitive_functions", []) or []:
        bump((fn.get("confidence") or "medium").lower())
    return counts
