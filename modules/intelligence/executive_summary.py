"""Intelligence-first executive front matter.

Assembles the "first two pages" view a developer / architect / pentester reads to
understand the application immediately: an Executive Intelligence Summary, auto
generated Developer Discussion Points, the exposed secrets, the application
architecture, the top pentest targets, and the hidden functionality. Pure
aggregation over already-built intelligence structures — no new analysis.
"""

from __future__ import annotations


def build_executive_intelligence(
    data: dict, eff_idp, asset_intel: dict, recon_intel: dict, browser_intel: dict, js_intel: dict
) -> dict:
    """Return the executive-summary structure rendered at the top of the report."""
    infra = asset_intel.get("infrastructure", {})
    js_summary = js_intel.get("summary_v2", {})
    recon_summary = recon_intel.get("summary", {})

    roles = sorted({u.get("role") for u in data.get("users", []) if u.get("role")})
    related_apps = [
        f"{a['host']} ({a['category']})" for a in js_intel.get("related_applications", [])
    ]
    internal_services = asset_intel.get("services", [])

    hidden_apis = [h.get("full_url") or h["endpoint"] for h in js_intel.get("hidden_apis", [])]
    hidden_routes = [r["route"] for r in js_intel.get("hidden_routes", [])]
    feature_modules = [
        c["feature"] for c in js_intel.get("correlation", []) if c.get("confidence") == "high"
    ]

    secrets = [
        {
            "type": s["name"],
            "location": s.get("location"),
            "severity": s["severity"],
            "source": s.get("source"),
            "value_masked": s.get("value_masked"),
        }
        for s in js_intel.get("frontend_secrets", [])
    ]

    # Top targets — prefer the JS Top-20 (carries full URLs via the service
    # registry), fall back to the precision Top-10.
    top_targets = js_intel.get("top_targets") or recon_intel.get("top_targets", [])

    summary = {
        "authentication_type": (
            f"{eff_idp.identity_provider} / {eff_idp.authentication_type}"
            if eff_idp.identity_provider != "Unknown"
            else "Unknown"
        ),
        "keycloak_realm": getattr(eff_idp, "realm", None),
        "roles": roles,
        "applications": related_apps,
        "internal_services": internal_services,
        "apis": len(asset_intel.get("api_inventory", [])),
        "hidden_apis": hidden_apis,
        "hidden_routes": hidden_routes,
        "secrets": len(secrets),
        "high_priority_targets": [
            f"{t.get('method', 'GET')} {t.get('full_url') or t['endpoint']}"
            for t in top_targets[:8]
        ],
    }

    return {
        "summary": summary,
        "developer_discussion_points": _developer_points(js_intel, browser_intel, recon_summary),
        "secrets": secrets,
        "architecture": {
            "authentication": {
                "provider": eff_idp.identity_provider,
                "type": eff_idp.authentication_type,
                "realm": getattr(eff_idp, "realm", None),
                "client": js_summary.get("authentication", {}).get("keycloak_client"),
                "gateways": infra.get("api_gateways", []),
            },
            "applications": related_apps,
            "internal_services": internal_services,
            "related_applications": infra.get("related_applications", []),
            "runtime_config_values": len(js_intel.get("runtime_config", [])),
        },
        "top_targets": top_targets[:10],
        "hidden_functionality": {
            "hidden_apis": hidden_apis,
            "hidden_routes": hidden_routes,
            "feature_gated_modules": feature_modules,
        },
    }


def _developer_points(js_intel: dict, browser_intel: dict, recon_summary: dict) -> list[dict]:
    """Auto-generate findings that warrant a developer conversation."""
    points: list[dict] = []

    def add(title, detail, severity):
        points.append({"title": title, "detail": detail, "severity": severity})

    # From browser-storage security findings (JWT in localStorage, etc.).
    for f in js_intel.get("browser_security", []):
        add(f["title"], f.get("risk", ""), f["severity"])

    # From runtime-config risks (auth/admin-roles/GIS/tenant/flags exposed).
    for r in js_intel.get("runtime_config_risks", []):
        ev = "; ".join(str(e) for e in r.get("evidence", [])[:3])
        add(r["title"], ev, r["severity"])

    # Internal applications exposed in frontend.
    apps = js_intel.get("related_applications", [])
    if apps:
        add(
            "Internal applications referenced in frontend code",
            f"{len(apps)} same-org applications are discoverable from JS/config: "
            + ", ".join(a["host"] for a in apps[:6]),
            "Informational",
        )

    # Critical/high secrets present — name each with where it was found.
    high = [
        s for s in js_intel.get("frontend_secrets", []) if s["severity"] in {"Critical", "High"}
    ]
    if high:
        by_name: dict[str, list[str]] = {}
        for s in high:
            by_name.setdefault(s["name"], []).append(s.get("location") or "")
        parts = []
        for name, locs in sorted(by_name.items()):
            seen_locs = [loc for loc in dict.fromkeys(locs) if loc]
            where = ""
            if seen_locs:
                where = f" @ {seen_locs[0]}" + (
                    f" (+{len(seen_locs) - 1} more)" if len(seen_locs) > 1 else ""
                )
            parts.append(f"{name}{where}")
        add(
            "High-severity secrets in frontend",
            "Secrets that should not ship to the browser — " + "; ".join(parts),
            "High",
        )

    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    # De-duplicate by title, strongest severity first.
    seen: dict[str, dict] = {}
    for p in points:
        if p["title"] not in seen or sev_order.get(p["severity"], 5) < sev_order.get(
            seen[p["title"]]["severity"], 5
        ):
            seen[p["title"]] = p
    out = list(seen.values())
    out.sort(key=lambda p: sev_order.get(p["severity"], 5))
    return out
