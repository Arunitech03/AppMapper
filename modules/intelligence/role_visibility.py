"""Role visibility from captured traffic (redesigned Access Matrix).

The legacy access matrix re-probed an endpoint universe *live* and rendered a
single accessible/denied boolean. That was misleading: it could not tell "this
role never touched the endpoint" apart from "this role was denied", it was
swamped by static assets, and — because HAR-only roles share the same anonymous
live probe — it reported zero role-exclusive endpoints even when each role's HAR
clearly contained different applications.

This module instead derives visibility **directly from each role's captured
HAR/Burp traffic** (the requests that role's own authenticated session actually
made), classifying every endpoint into one of four states per role:

  * ``observed``      — the role's capture got a 2xx for it            (✓)
  * ``not_observed``  — the role's capture never requested it          (?)
  * ``denied``        — the role's capture got a 401/403 (or other 4xx/5xx)  (🚫)
  * ``redirected``    — the role's capture got a 3xx                   (↪)

Endpoints are split into **Applications** (business areas, grouped by the leading
path segment) and **APIs** (JSON / verb-style service calls). Static assets and
third-party hosts are excluded so the matrix focuses on business functionality.

Discovery/analysis only: this reads already-captured metadata; it makes no
requests and performs no authorization testing.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from modules.intelligence.domain_classifier import registrable_domain

# --- noise filtering ------------------------------------------------------

STATIC_EXTENSIONS = (
    ".css",
    ".js",
    ".mjs",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".bmp",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".mp4",
    ".webm",
    ".mp3",
    ".wasm",
)
# Path tokens that indicate fonts / static bundles even without an extension.
STATIC_TOKENS = ("/fonts/", "/font/", "/assets/", "/static/", "/sprite")


def _is_static(path: str) -> bool:
    low = (path or "").lower()
    return low.endswith(STATIC_EXTENSIONS) or any(tok in low for tok in STATIC_TOKENS)


# --- application vs API classification ------------------------------------

API_HINTS = ("/api/", "/api.", "/rest/", "/graphql", "/odata", "/v1/", "/v2/", "/v3/")
# camelCase / lower verb-style service calls: getUtilityConfig, listDevices, ...
_VERB_RE = re.compile(
    r"^(get|post|put|patch|delete|list|fetch|load|save|create|update|search|query|"
    r"find|count|all|read|add|remove|set|init|login|logout|auth|token|refresh)[a-z0-9]*$",
    re.IGNORECASE,
)


def _is_api(path: str, content_type: str | None) -> bool:
    low = (path or "").lower()
    if content_type and "json" in content_type.lower():
        return True
    if low.endswith(".json"):
        return True
    if any(h in low for h in API_HINTS):
        return True
    segs = [p for p in low.split("/") if p]
    return bool(segs) and bool(_VERB_RE.match(segs[-1]))


_CAMEL = re.compile(r"([a-z0-9])([A-Z])")


def _app_name(path: str) -> str:
    """Humanized business-area name from the leading path segment."""
    segs = [p for p in (path or "").split("/") if p]
    if not segs:
        return "Home"
    spaced = _CAMEL.sub(r"\1 \2", segs[0]).replace("-", " ").replace("_", " ")
    return " ".join(w.capitalize() for w in spaced.split()) or "Home"


def _app_key(path: str) -> str:
    """Normalized grouping key so spelling variants collapse together.

    e.g. ``device-access`` and ``deviceaccess`` map to the same application.
    """
    segs = [p for p in (path or "").split("/") if p]
    if not segs:
        return "home"
    return re.sub(r"[^a-z0-9]", "", segs[0].lower()) or "home"


# --- per-role state -------------------------------------------------------

OBSERVED = "observed"
NOT_OBSERVED = "not_observed"
DENIED = "denied"
REDIRECTED = "redirected"

# Higher wins when a role has several observations of the same endpoint: a
# success outranks a denial, which outranks a redirect, which outranks silence.
_PRECEDENCE = {OBSERVED: 3, DENIED: 2, REDIRECTED: 1, NOT_OBSERVED: 0}

STATE_SYMBOLS = {
    OBSERVED: "✓",
    NOT_OBSERVED: "?",
    DENIED: "🚫",
    REDIRECTED: "↪",
}
STATE_LABELS = {
    OBSERVED: "Observed",
    NOT_OBSERVED: "Not Observed",
    DENIED: "Access Denied",
    REDIRECTED: "Redirected",
}


def _status_state(status: int | None) -> str:
    if status is None:
        # The request is present in the role's capture but no status was recorded
        # (e.g. an exploration navigation) — the role demonstrably reached it.
        return OBSERVED
    if 200 <= status < 300:
        return OBSERVED
    if 300 <= status < 400:
        return REDIRECTED
    # 401/403/407 are explicit denials; other 4xx/5xx also mean "not reachable".
    return DENIED


def _merge(a: str, b: str) -> str:
    return a if _PRECEDENCE[a] >= _PRECEDENCE[b] else b


def _captured(data: dict):
    """Yield (role, method, path, status, content_type) for in-scope app traffic."""
    target = data.get("target", {}) or {}
    base = target.get("domain") or urlparse(target.get("url", "")).hostname or ""
    base_reg = registrable_domain(base) if base else ""

    for src in ("har_requests", "burp_requests"):
        for r in data.get(src, []):
            role = r.get("role")
            if not role:
                continue  # only role-attributed captures drive the comparison
            u = urlparse(r.get("url", ""))
            host = (u.hostname or "").lower()
            # Restrict to the application's own org (drops datadog/google/CDN noise).
            if base_reg and host and registrable_domain(host) != base_reg:
                continue
            path = u.path or "/"
            if _is_static(path):
                continue
            yield (
                role,
                (r.get("method") or "GET").upper(),
                path,
                r.get("response_status"),
                r.get("response_content_type"),
            )


def _exclusive_and_shared(items: list[dict], roles: list[str]):
    """From [{..., states}] compute role-exclusive and shared (by *observed*)."""
    exclusive: dict[str, list[str]] = {r: [] for r in roles}
    shared: list[str] = []
    for item in items:
        label = item.get("name") or item.get("endpoint", "")
        observed = [r for r in roles if item["states"].get(r) == OBSERVED]
        if len(observed) == 1:
            exclusive[observed[0]].append(label)
        elif len(observed) >= 2:
            shared.append(label)
    for r in roles:
        exclusive[r].sort()
    shared.sort()
    return exclusive, shared


def build_role_visibility(data: dict) -> dict:
    """Build the redesigned, HAR-derived role-visibility model.

    Returns::

        {
          "roles": [...],
          "applications": [{"name", "states": {role: state}}, ...],
          "apis":         [{"endpoint", "method", "states": {role: state}}, ...],
          "exclusive_apps": {role: [names]},
          "exclusive_apis": {role: [endpoints]},
          "shared_apps":  [names],
          "shared_apis":  [endpoints],
          "legend": {state: symbol},
        }
    """
    roles: set[str] = set()
    apps: dict[str, dict] = {}
    apis: dict[str, dict] = {}

    for role, method, path, status, ctype in _captured(data):
        roles.add(role)
        state = _status_state(status)
        if _is_api(path, ctype):
            key = f"{method} {path}"
            rec = apis.setdefault(key, {"endpoint": path, "method": method, "states": {}})
            rec["states"][role] = _merge(rec["states"].get(role, NOT_OBSERVED), state)
        else:
            key = _app_key(path)
            name = _app_name(path)
            rec = apps.setdefault(key, {"name": name, "states": {}})
            # Keep the most readable display variant (most word breaks).
            if name.count(" ") > rec["name"].count(" "):
                rec["name"] = name
            rec["states"][role] = _merge(rec["states"].get(role, NOT_OBSERVED), state)

    role_list = sorted(roles)

    applications = [
        {"name": rec["name"], "states": {r: rec["states"].get(r, NOT_OBSERVED) for r in role_list}}
        for _, rec in sorted(apps.items(), key=lambda kv: kv[1]["name"])
    ]
    api_list = [
        {
            "endpoint": rec["endpoint"],
            "method": rec["method"],
            "states": {r: rec["states"].get(r, NOT_OBSERVED) for r in role_list},
        }
        for _, rec in sorted(apis.items())
    ]

    excl_apps, shared_apps = _exclusive_and_shared(applications, role_list)
    excl_apis_pairs, shared_apis = _exclusive_and_shared(
        [{"name": f"{a['method']} {a['endpoint']}", "states": a["states"]} for a in api_list],
        role_list,
    )

    return {
        "roles": role_list,
        "applications": applications,
        "apis": api_list,
        "exclusive_apps": excl_apps,
        "exclusive_apis": excl_apis_pairs,
        "shared_apps": shared_apps,
        "shared_apis": shared_apis,
        "legend": dict(STATE_SYMBOLS),
    }
