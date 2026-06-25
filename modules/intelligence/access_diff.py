"""Feature 4: Role-based access analysis.

Compares the attack surface reachable by each role (including a synthetic
``anonymous`` baseline), combining live access-comparison probes
(``role_endpoint_access``) with authenticated-crawl reachability
(``crawl_endpoints``). Produces per-role endpoint counts and the role-difference
sets (role-only / shared). Analysis only — no requests are made here.
"""

from __future__ import annotations

ACCESSIBLE_STATUSES = {200, 201, 202, 203, 204, 206}


def _accessible_sets(data: dict) -> dict[str, set[str]]:
    """role -> set of accessible endpoint keys, merged across probes and crawl."""
    by_role: dict[str, set[str]] = {}

    for rec in data.get("role_access", []):
        if rec.get("accessible"):
            key = f"{rec.get('method', 'GET')} {rec['path']}"
            by_role.setdefault(rec["role"], set()).add(key)

    for ep in data.get("crawl_endpoints", []):
        status = ep.get("status_code")
        if status in ACCESSIBLE_STATUSES:
            key = f"{ep.get('method', 'GET')} {ep['path']}"
            by_role.setdefault(ep["role"], set()).add(key)

    return by_role


def analyze_access(data: dict) -> dict:
    """Return access analysis: counts, per-role-exclusive sets and shared set.

    Shape::

        {
          "roles": ["admin", "anonymous", "user"],
          "counts": {"admin": 180, "user": 120, "anonymous": 45},
          "exclusive": {"admin": [...], "user": [...]},
          "shared": [...],
          "matrix": {endpoint: {role: bool}},
        }
    """
    by_role = _accessible_sets(data)
    roles = sorted(by_role)
    counts = {r: len(by_role[r]) for r in roles}

    all_endpoints = sorted({e for s in by_role.values() for e in s})
    matrix = {ep: {r: (ep in by_role[r]) for r in roles} for ep in all_endpoints}

    exclusive: dict[str, list[str]] = {r: [] for r in roles}
    shared: list[str] = []
    authed_roles = [r for r in roles if r != "anonymous"]

    for ep in all_endpoints:
        can = [r for r in roles if ep in by_role[r]]
        if len(can) == 1:
            exclusive[can[0]].append(ep)
        elif authed_roles and all(ep in by_role[r] for r in authed_roles) and len(can) >= 2:
            shared.append(ep)

    return {
        "roles": roles,
        "counts": counts,
        "exclusive": {r: sorted(v) for r, v in exclusive.items()},
        "shared": sorted(shared),
        "matrix": matrix,
    }
