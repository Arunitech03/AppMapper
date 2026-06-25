"""Issue 2: accurate Session Inventory.

The old inventory reported ``captured: no / cookies: 0`` even when Authorization
tokens and cookies had clearly been captured, because it only reflected the
resolved login session, not what was actually observed. This rebuilds the
inventory from the stored (masked) ``auth_artifacts`` — the real evidence — so the
counts of cookies / local storage / session storage / auth tokens are accurate
per role.
"""

from __future__ import annotations

# Artifact kinds -> inventory bucket.
_KIND_BUCKET = {
    "cookie": "cookies",
    "local_storage": "local_storage",
    "session_storage": "session_storage",
    "authorization": "auth_tokens",
    "access_token": "auth_tokens",
    "bearer": "auth_tokens",
    "jwt": "auth_tokens",
}


def build_session_inventory(data: dict) -> list[dict]:
    """Per-role session inventory derived from captured auth artifacts.

    ``[{role, captured, cookies, local_storage, session_storage, auth_tokens}]``.
    """
    rows: dict[str, dict] = {}

    def row(role: str) -> dict:
        return rows.setdefault(
            role,
            {
                "role": role,
                "captured": False,
                "cookies": 0,
                "local_storage": 0,
                "session_storage": 0,
                "auth_tokens": 0,
            },
        )

    # Seed with configured roles + any session rows (so roles with no artifacts
    # still appear, accurately, as not captured).
    for u in data.get("users", []) or []:
        if u.get("role"):
            row(u["role"])
    for s in data.get("sessions", []) or []:
        if s.get("role"):
            row(s["role"])

    for a in data.get("auth_artifacts", []) or []:
        role = a.get("role") or "default"
        bucket = _KIND_BUCKET.get((a.get("kind") or "").lower())
        if not bucket:
            continue
        r = row(role)
        r[bucket] += 1
        r["captured"] = True

    return [rows[k] for k in sorted(rows)]
