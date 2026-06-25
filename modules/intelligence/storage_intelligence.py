"""Feature 8: Storage Intelligence.

Classifies client-side storage observed during capture — localStorage,
sessionStorage and cookies (from ``auth_artifacts``) — into meaningful categories
(JWT/token, role, user object, tenant id, feature flag, API URL) and flags
security-relevant patterns such as role information held client-side.

Values are already MASKED in ``auth_artifacts`` (the explorer masks them); this
module only classifies the key names + masked samples. Pure/offline.
"""

from __future__ import annotations

import re

# key-name pattern -> (classification, finding note or None)
_CLASSIFIERS: list[tuple] = [
    (
        re.compile(r"(?i)(jwt|access[_\-]?token|id[_\-]?token|bearer)"),
        "JWT / Access Token",
        "Access token stored client-side",
    ),
    (re.compile(r"(?i)refresh[_\-]?token"), "Refresh Token", "Refresh token stored client-side"),
    (
        re.compile(r"(?i)(role|authorities|permission|scope)"),
        "Role / Permission",
        "Role information stored client-side",
    ),
    (re.compile(r"(?i)(tenant|org|company|customer)[_\-]?id"), "Tenant / Org ID", None),
    (re.compile(r"(?i)(user|profile|account|currentuser)"), "User Object", None),
    (re.compile(r"(?i)(feature|flag|toggle|experiment)"), "Feature Flag", None),
    (re.compile(r"(?i)(url|uri|endpoint|host|base)"), "API / Config URL", None),
    (re.compile(r"(?i)(session|sid)"), "Session Identifier", None),
]
_STORAGE_KINDS = {"local_storage", "session_storage", "cookie"}
_KIND_LABEL = {
    "local_storage": "Local Storage",
    "session_storage": "Session Storage",
    "cookie": "Cookie",
}


def _classify(name: str) -> tuple[str, str | None]:
    for rx, label, note in _CLASSIFIERS:
        if rx.search(name or ""):
            return label, note
    return "Other", None


def analyze_storage(data: dict) -> dict:
    """Return ``{items:[…], notes:[…]}`` for client-side storage intelligence.

    ``items``: ``{storage, role, key, classification, value_masked}``.
    ``notes``: security-relevant observations (e.g. role stored client-side).
    """
    items: list[dict] = []
    notes: dict[str, None] = {}

    for a in data.get("auth_artifacts", []) or []:
        kind = (a.get("kind") or "").lower()
        if kind not in _STORAGE_KINDS:
            continue
        name = a.get("name", "")
        classification, note = _classify(name)
        items.append(
            {
                "storage": _KIND_LABEL.get(kind, kind),
                "role": a.get("role"),
                "key": name,
                "classification": classification,
                "value_masked": a.get("value_masked", ""),
            }
        )
        if note:
            notes.setdefault(f"{note} ({_KIND_LABEL.get(kind, kind)}: {name})", None)

    items.sort(key=lambda x: (x["storage"], x["classification"], x["key"]))
    return {"items": items, "notes": list(notes)}
