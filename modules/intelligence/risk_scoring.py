"""Issue 5: Risk-Based Attack Surface scoring.

Replaces frequency-based ranking with an explicit, additive risk score per
endpoint built from real signals (role exclusivity, sensitive data, state change,
export capability, hidden surface, secret exposure; telemetry penalized). Static
assets are excluded entirely. The output drives the Risk-Based Attack Surface
section, the Top 10 Targets and the Target Queue. Pure/offline.
"""

from __future__ import annotations

from urllib.parse import urlparse

from modules.intelligence.classifiers import is_noise_path
from modules.intelligence.telemetry_classifier import is_telemetry

# Signal weights (Issue 5).
W_ADMIN_ONLY = 5
W_SENSITIVE = 4
W_STATE_CHANGING = 3
W_EXPORT = 3
W_HIDDEN = 5
W_SECRET = 4
W_TELEMETRY = -5

_STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_EXPORT_TOKENS = ("export", "download", "report", "csv", "pdf", "excel", "extract")


def score_endpoints(data: dict) -> list[dict]:
    """Return endpoints scored by risk, highest first.

    Each row: ``{endpoint, methods, score, signals, admin_only, sensitive,
    sensitive_fields, hidden, state_changing, export, telemetry, confidence}``.
    """
    from modules.intelligence.asset_inventory import unified_api_inventory
    from modules.intelligence.hidden_endpoint_discovery import find_hidden_endpoints
    from modules.intelligence.role_visibility import build_role_visibility
    from modules.intelligence.sensitive_schema import analyze_sensitive_schemas

    inventory = unified_api_inventory(data)

    # Admin-only endpoints (observed by a privileged role only) from role visibility.
    vis = build_role_visibility(data)
    from modules.intelligence.path_normalizer import normalize_path

    _NONADMIN = {"user", "anonymous", "guest", "viewer", "readonly"}
    # Role universe = configured users + roles seen in captured traffic.
    all_roles = {u.get("role") for u in data.get("users", []) if u.get("role")}
    all_roles |= set(vis.get("roles", []))
    nonadmin = {r for r in all_roles if (r or "").lower() in _NONADMIN}
    has_lower_priv = bool(nonadmin)  # an account to escalate *from* exists

    admin_only: set[str] = set()
    observed_roles: dict[str, list[str]] = {}
    for api in vis.get("apis", []):
        ep = normalize_path(api["endpoint"])
        obs = [r for r, st in api["states"].items() if st == "observed"]
        observed_roles[ep] = obs
        # Admin-only: observed by at least one role, none of them a lower-priv role.
        if obs and has_lower_priv and all(r not in nonadmin for r in obs):
            admin_only.add(ep)

    # Sensitive endpoints + their fields.
    sens = {s["endpoint"]: s for s in analyze_sensitive_schemas(data)}
    # Hidden (referenced-but-not-observed).
    hidden = {h["endpoint"] for h in find_hidden_endpoints(data)}
    # Endpoints with a secret finding located on them.
    secret_eps = _secret_endpoints(data)

    scored = []
    seen: set[str] = set()
    # Score observed inventory + hidden endpoints (union).
    candidates = [(a["path"], a.get("methods") or ["GET"]) for a in inventory]
    candidates += [(h, ["GET"]) for h in hidden]
    for ep, methods in candidates:
        if ep in seen or is_noise_path(ep):
            continue
        seen.add(ep)
        signals: list[str] = []
        score = 0
        telem = is_telemetry(ep)

        if ep in admin_only:
            score += W_ADMIN_ONLY
            signals.append("admin-only (+5)")
        s = sens.get(ep)
        if s:
            score += W_SENSITIVE
            signals.append(f"sensitive fields: {', '.join(s['sensitive_fields'][:4])} (+4)")
        if any(m in _STATE_METHODS for m in methods):
            score += W_STATE_CHANGING
            signals.append("state-changing (+3)")
        if any(t in ep.lower() for t in _EXPORT_TOKENS):
            score += W_EXPORT
            signals.append("export capability (+3)")
        if ep in hidden:
            score += W_HIDDEN
            signals.append("hidden / referenced-not-observed (+5)")
        if ep in secret_eps:
            score += W_SECRET
            signals.append("secret exposed (+4)")
        if telem:
            score += W_TELEMETRY
            signals.append("telemetry (-5)")

        if score <= 0:
            continue  # not worth ranking
        scored.append(
            {
                "endpoint": ep,
                "methods": methods,
                "score": score,
                "signals": signals,
                "admin_only": ep in admin_only,
                "sensitive": bool(s),
                "sensitive_fields": s["sensitive_fields"] if s else [],
                "idor_candidate": bool(s and s.get("idor_candidate")),
                "hidden": ep in hidden,
                "state_changing": any(m in _STATE_METHODS for m in methods),
                "export": any(t in ep.lower() for t in _EXPORT_TOKENS),
                "telemetry": telem,
                "roles": observed_roles.get(ep, []),
                "confidence": "high" if ep not in hidden else "medium",
            }
        )
    scored.sort(key=lambda x: (-x["score"], x["endpoint"]))
    return scored


def _secret_endpoints(data: dict) -> set[str]:
    """Normalized endpoints that have a secret finding located on them."""
    from modules.intelligence.path_normalizer import normalize_path

    eps: set[str] = set()
    for f in data.get("intel_findings", []) or []:
        if f.get("category") in {"API Keys", "Authentication"}:
            loc = f.get("location") or ""
            path = urlparse(loc).path if "://" in loc else loc
            if path.startswith("/"):
                eps.add(normalize_path(path))
    return eps
