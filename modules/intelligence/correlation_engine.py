"""Feature 10: Intelligence Correlation Engine.

Joins the separate intelligence layers into one view per endpoint — API path ↔
response schema keys ↔ business module ↔ role visibility — and produces a ranked
**High Priority Recon Targets** list that answers "what should the pentester look
at next?". Pure/offline aggregation over already-derived data.
"""

from __future__ import annotations

from urllib.parse import urlparse

from modules.intelligence.path_normalizer import normalize_path

_MODULE_KEYWORDS = {
    "User Management": ("user", "account", "member", "profile"),
    "Role Management": ("role", "permission", "authority"),
    "Billing": ("billing", "invoice", "payment", "tariff"),
    "Reporting": ("report", "analytics", "dashboard", "export"),
    "Device Management": ("device", "meter", "asset", "sensor"),
    "Alarm Management": ("alarm", "alert", "incident"),
    "Configuration": ("config", "setting", "template", "preference"),
    "Administration": ("admin", "manage", "console", "system"),
}


def _module_for(path: str) -> str | None:
    low = path.lower()
    for module, kws in _MODULE_KEYWORDS.items():
        if any(k in low for k in kws):
            return module
    return None


def correlate(data: dict) -> list[dict]:
    """Per-endpoint correlation rows: API ↔ keys ↔ module ↔ roles."""
    from modules.intelligence.asset_inventory import unified_api_inventory
    from modules.intelligence.response_analyzer import analyze_responses
    from modules.intelligence.role_visibility import build_role_visibility

    # response keys by normalized endpoint
    keys_by_ep: dict[str, list[str]] = {}
    for r in analyze_responses(data):
        keys_by_ep.setdefault(normalize_path(r["endpoint"]), [])
        keys_by_ep[normalize_path(r["endpoint"])] = r.get("json_keys", [])

    # role visibility by normalized endpoint
    vis = build_role_visibility(data)
    roles_by_ep: dict[str, list[str]] = {}
    for api in vis.get("apis", []):
        ep = normalize_path(api["endpoint"])
        observed = [r for r, st in api["states"].items() if st == "observed"]
        if observed:
            roles_by_ep.setdefault(ep, observed)

    rows = []
    for a in unified_api_inventory(data):
        ep = a["path"]
        module = _module_for(ep)
        rows.append(
            {
                "endpoint": ep,
                "service": a.get("service"),
                "response_keys": keys_by_ep.get(ep, []),
                "business_module": module,
                "roles": sorted(roles_by_ep.get(ep, [])),
            }
        )
    rows.sort(key=lambda x: x["endpoint"])
    return rows


def recon_targets(data: dict) -> list[dict]:
    """Ranked **High Priority Recon Targets** with a reason for each."""
    from modules.intelligence.hidden_endpoint_discovery import find_hidden_endpoints

    targets: list[dict] = []

    # 1) Referenced-but-not-observed endpoints (hidden surface).
    for h in find_hidden_endpoints(data):
        reason = "Referenced in frontend code but never observed"
        if h["score"] >= 1:
            reason += " (sensitive keyword)"
        targets.append({"target": h["endpoint"], "reason": reason, "priority": h["priority"]})

    # 2) Admin/privileged endpoints that WERE observed (still worth authz testing).
    seen = {t["target"] for t in targets}
    for a in _admin_like(data):
        if a not in seen:
            targets.append(
                {"target": a, "reason": "Administrative / privileged function", "priority": "high"}
            )
            seen.add(a)

    order = {"high": 0, "medium": 1, "low": 2}
    targets.sort(key=lambda t: order.get(t["priority"], 3))
    return targets


def _admin_like(data: dict) -> list[str]:
    from modules.intelligence.asset_inventory import unified_api_inventory

    hits = []
    for a in unified_api_inventory(data):
        low = a["path"].lower()
        if any(k in low for k in ("admin", "role", "permission", "config", "manage")):
            hits.append(a["path"])
    return sorted(set(hits))


def _host_path(url: str) -> str:
    return urlparse(url).path or "/"
