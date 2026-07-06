"""JSON report generation.

Serializes the full stored dataset for a target into a single JSON document.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from models.schemas import RoleEndpointAccess, WorkflowEdge
from modules.access.comparison import access_matrix, role_difference
from modules.ai.app_summary import generate_summary
from modules.auth.idp_analyzer import effective_idp
from modules.intelligence.access_diff import analyze_access
from modules.intelligence.asset_inventory import build_asset_intelligence
from modules.intelligence.auth_intelligence import build_auth_intelligence
from modules.intelligence.authz_candidates import build_authz_candidates
from modules.intelligence.browser_intelligence import build_browser_intelligence
from modules.intelligence.dns_intelligence import build_dns_intelligence
from modules.intelligence.domain_classifier import build_domain_intel
from modules.intelligence.executive_summary import build_executive_intelligence
from modules.intelligence.file_intelligence import build_file_intelligence
from modules.intelligence.javascript_intelligence import build_javascript_intelligence
from modules.intelligence.jwt_intelligence import build_jwt_intelligence
from modules.intelligence.pentest_matrix import build_pentest_matrix
from modules.intelligence.pentest_plan import build_pentest_plan
from modules.intelligence.recon_intelligence import build_recon_intelligence
from modules.intelligence.redirect_intelligence import build_redirect_intelligence
from modules.intelligence.role_visibility import build_role_visibility
from modules.intelligence.session_inventory import build_session_inventory
from modules.intelligence.subdomain_intelligence import build_subdomain_intelligence
from modules.intelligence.token_inventory import build_token_inventory
from modules.intelligence.workflow_mapper import build_workflow, render_tree


def _redact_jwts(js_findings: list[dict]) -> list[dict]:
    """Mask any full JWT embedded in js_findings values (tokens must never render raw).

    A JWT decoded for intelligence is surfaced (masked) elsewhere; the raw value must
    not appear verbatim in any report. Returns a sanitized copy.
    """
    from modules.auth.masking import mask_secret
    from modules.intelligence.jwt_intelligence import find_jwts

    out: list[dict] = []
    for f in js_findings:
        value = f.get("value")
        if isinstance(value, str):
            for tok in find_jwts(value):
                value = value.replace(tok, mask_secret(tok))
            f = {**f, "value": value}
        out.append(f)
    return out


def build_report(
    data: dict[str, list[dict]], *, show_pii: bool = False, **summary_opts: Any
) -> dict[str, Any]:
    """Assemble the consolidated report structure (Tier 1 + Tier 2).

    ``summary_opts`` are forwarded to the AI summary provider (provider/base_url/
    model/api_key); defaults produce the offline template summary. ``show_pii`` is a
    named param (NOT forwarded to the provider) — when set, JWT name/email render
    unmasked (internal environments only).
    """
    target = data.get("target", {})
    technologies = data.get("technologies", [])
    frontend = [t["name"] for t in technologies if t["category"] == "frontend"]
    backend = [t["name"] for t in technologies if t["category"] == "backend"]
    servers = [t["name"] for t in technologies if t["category"] == "server"]
    libraries = [t["name"] for t in technologies if t["category"] == "library"]

    subdomains = data.get("subdomains", [])
    directories = data.get("directories", [])
    apis = data.get("api_endpoints", [])
    ssl_findings = data.get("ssl_findings", [])
    services = data.get("network_services", [])
    js = _redact_jwts(data.get("js_findings", []))
    har = data.get("har_requests", [])
    burp = data.get("burp_requests", [])
    users = data.get("users", [])
    role_access = data.get("role_access", [])

    # Tier 2 datasets
    crawl = data.get("crawl_endpoints", [])
    forms = data.get("forms", [])
    sensitive = data.get("sensitive_functions", [])
    api_intel = data.get("api_intel", [])
    checklist = data.get("checklist_items", [])
    auth_artifacts = data.get("auth_artifacts", [])
    sessions = data.get("sessions", [])
    workflow_edges = data.get("workflow_edges", []) or [
        e.model_dump() for e in build_workflow(data)
    ]

    eff_idp = effective_idp(data)
    jwt_intel = build_jwt_intelligence(data, show_pii=show_pii)
    # JS intel carries the canonical service inventory; build it before auth intel so the
    # authentication flow / discussion points can reference internal services.
    js_intel = build_javascript_intelligence(data)
    data["session_inventory"] = build_session_inventory(data)  # reused by auth dashboard cards
    auth_intel = build_auth_intelligence(
        data, jwt_intel, service_inventory=js_intel.get("service_inventory")
    )
    _jwt_primary = jwt_intel.get("primary") or {}
    # Only a captured session token (not a JS-embedded one) may refine the IdP block.
    _session_jwt = _jwt_primary if _jwt_primary.get("origin") == "session" else {}

    records = [RoleEndpointAccess(**r) for r in role_access]
    matrix = access_matrix(records)
    diff = role_difference(records)
    access_analysis = analyze_access(data)
    edge_objs = [WorkflowEdge(**e) for e in workflow_edges]
    workflow_tree = render_tree(edge_objs) if edge_objs else ""

    app_summary = generate_summary(data, **summary_opts)

    # Intelligence aggregators (computed once, reused for the executive front matter).
    asset_intel = build_asset_intelligence(data)
    recon_intel = build_recon_intelligence(data)
    browser_intel = build_browser_intelligence(data)
    redirect_intel = build_redirect_intelligence(data)
    executive_intel = build_executive_intelligence(
        data, eff_idp, asset_intel, recon_intel, browser_intel, js_intel
    )

    summary = {
        "subdomains": len(subdomains),
        "directories": len(directories),
        "technologies": len(technologies),
        "api_endpoints": len(apis),
        "ssl_findings": len(ssl_findings),
        "network_services": len(services),
        "js_findings": len(js),
        "har_requests": len(har),
        "burp_requests": len(burp),
        "roles": len(users),
        "crawl_endpoints": len(crawl),
        "forms": len(forms),
        "sensitive_functions": len(sensitive),
        "api_intel": len(api_intel),
        "checklist_items": len(checklist),
        "role_endpoints_mapped": len(matrix),
    }

    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "target": target,
        "executive_summary": summary,
        "technology_stack": {
            "frontend": frontend,
            "backend": backend,
            "servers": servers,
            "libraries": libraries,
        },
        "discovered_assets": {"subdomains": subdomains, "directories": directories},
        "apis": apis,
        "ssl_findings": ssl_findings,
        "network_services": services,
        "js_findings": js,
        "captured_traffic": {"har_requests": har, "burp_requests": burp},
        "users": users,
        "access_matrix": {"roles": diff["roles"], "endpoints": matrix},
        "role_difference": diff,
        # Redesigned role visibility derived from captured HAR/Burp traffic:
        # 4 states (observed/not_observed/denied/redirected), static assets and
        # third-party hosts excluded, split into Applications vs APIs.
        "role_visibility": build_role_visibility(data),
        # Tier 2
        "crawl_endpoints": crawl,
        "forms": forms,
        "workflow": {"edges": workflow_edges, "tree": workflow_tree},
        "sensitive_functions": sensitive,
        "api_intelligence": api_intel,
        "role_comparison": access_analysis,
        "checklist": checklist,
        "application_summary": app_summary.model_dump(),
        # Enterprise auth (reconciled: stored detection + captured-artifact analysis).
        "authentication": {
            # IdP/realm come from the reconciled detection over the actual session
            # (cookies/paths); a captured SESSION token may refine them, but a token
            # merely embedded in JS never overrides the session's realm.
            **{
                "identity_provider": _session_jwt.get("identity_provider")
                or eff_idp.identity_provider,
                "authentication_type": _session_jwt.get("authentication_type")
                or eff_idp.authentication_type,
                "realm": eff_idp.realm or _session_jwt.get("realm"),
                "evidence": eff_idp.evidence,
                "metadata_url": eff_idp.metadata_url,
            },
            # JWT-derived supplementary fields (from the primary decoded token).
            "client": _jwt_primary.get("client"),
            "token_lifetime": _jwt_primary.get("token_lifetime"),
            "roles": [u["role"] for u in users] + ["anonymous"],
        },
        # JWT Authorization Intelligence — decoded token: IdP/realm/client, role model,
        # application inventory, risk indicators (PII masked, no raw token).
        "jwt_intelligence": jwt_intel,
        # Authentication & Authorization Intelligence (Phase 2) — auth model, storage,
        # refresh, application access, authorization totals, risk, pentest priorities.
        "auth_intelligence": auth_intel,
        "sessions": sessions,
        # Issue 2: accurate per-role session inventory from captured artifacts.
        "session_inventory": build_session_inventory(data),
        "auth_artifacts": auth_artifacts,
        # External Domain Intelligence & API Relationship Mapping.
        "domain_intelligence": build_domain_intel(data),
        # Intelligence-first executive front matter (rendered at the TOP of the report).
        "executive_intelligence": executive_intel,
        # Unified Asset Intelligence (services, gateway, internal apps, deps, modules,
        # response intel, attack-surface prioritization, infrastructure).
        "asset_intelligence": asset_intel,
        # Pentester guidance (Issues 7 + 8) — recommendations only.
        "authz_candidates": build_authz_candidates(data),
        "pentest_plan": build_pentest_plan(data),
        # Sprint A — secret discovery & hidden-endpoint intelligence.
        "recon_intelligence": recon_intel,
        # Sprint B — browser-resident intelligence.
        "browser_intelligence": browser_intel,
        # Sprint B.1 — JavaScript / runtime-config intelligence.
        "javascript_intelligence": js_intel,
        # Redirect Intelligence — chains, auth/SSO flow, external + open-redirect flags.
        "redirect_intelligence": redirect_intel,
        "exploration": {
            "endpoints": sum(1 for e in crawl if e.get("source") == "explore"),
            "api_calls": sum(1 for e in crawl if e.get("source") == "api"),
            "uploads": sum(1 for e in crawl if e.get("source") == "upload"),
            "downloads": sum(1 for e in crawl if e.get("source") == "download"),
            "websockets": sum(1 for e in crawl if e.get("source") == "websocket"),
        },
    }
    # Derived consolidation sections (over the assembled intelligence above).
    report["token_inventory"] = build_token_inventory(report)
    report["subdomain_intelligence"] = build_subdomain_intelligence(report, data)
    report["dns_intelligence"] = build_dns_intelligence(report, data)
    report["file_intelligence"] = build_file_intelligence(report, data)
    # Surface file-handling high-value findings in the Critical Findings pipeline.
    fi_points = (report["file_intelligence"] or {}).get("high_value_findings") or []
    if fi_points:
        ei = report.setdefault("executive_intelligence", {})
        ei.setdefault("developer_discussion_points", []).extend(fi_points)
    report["pentest_matrix"] = build_pentest_matrix(report)
    return report


def write_json_report(
    data: dict[str, list[dict]],
    output_dir: str | Path,
    *,
    filename: str = "output.json",
    **opts: Any,
) -> Path:
    """Write the JSON report (default ``output.json``) and return its path."""
    report = build_report(data, **opts)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / filename
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return path
