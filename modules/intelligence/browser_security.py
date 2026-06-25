"""Sprint B.2 Feature 9: Browser Storage Security Analysis.

Adds a security lens over client-side storage (localStorage / sessionStorage /
cookies / IndexedDB), turning the inventory into risk observations a tester acts
on: tokens reachable by JavaScript (XSS exposure), client-side role/permission
data (privilege analysis), and authentication state stored in the browser.
Reuses the storage classification; values stay masked. Pure/offline.
"""

from __future__ import annotations


def build_browser_security(data: dict) -> list[dict]:
    """Return browser-storage security findings ``[{title, risk, severity, evidence}]``."""
    from modules.intelligence.storage_intelligence import analyze_storage

    storage = analyze_storage(data)
    items = storage.get("items", [])
    by_class: dict[str, list[dict]] = {}
    for it in items:
        by_class.setdefault(it["classification"], []).append(it)

    findings: list[dict] = []

    def ev(cls: str) -> list[str]:
        return [f"{i['storage']}.{i['key']}" for i in by_class.get(cls, [])][:10]

    tokens = ev("JWT / Access Token") + ev("Refresh Token")
    local_tokens = [
        f"{i['storage']}.{i['key']}"
        for cls in ("JWT / Access Token", "Refresh Token")
        for i in by_class.get(cls, [])
        if i["storage"] in {"Local Storage", "Session Storage"}
    ]
    if local_tokens:
        findings.append(
            {
                "title": "Authentication token stored in browser storage",
                "risk": "Token is readable by JavaScript — exposed to theft via XSS or "
                "malicious dependency. Prefer HttpOnly cookies.",
                "severity": "Medium",
                "confidence": "high",
                "evidence": local_tokens[:10],
            }
        )
    elif tokens:
        findings.append(
            {
                "title": "Authentication token present client-side",
                "risk": "Session token observed in client storage.",
                "severity": "Low",
                "confidence": "high",
                "evidence": tokens[:10],
            }
        )

    if by_class.get("Role / Permission"):
        findings.append(
            {
                "title": "Role / permission information stored client-side",
                "risk": "Client-side role data reveals the RBAC model and is trivially "
                "modifiable — useful for privilege-escalation analysis.",
                "severity": "Low",
                "confidence": "high",
                "evidence": ev("Role / Permission"),
            }
        )

    if by_class.get("Tenant / Org ID"):
        findings.append(
            {
                "title": "Tenant / organization identifier stored client-side",
                "risk": "Tenant context exposed; informs multi-tenant isolation testing.",
                "severity": "Informational",
                "confidence": "high",
                "evidence": ev("Tenant / Org ID"),
            }
        )

    if by_class.get("User Object"):
        findings.append(
            {
                "title": "User / profile object stored client-side",
                "risk": "Authentication state available to the browser; session intelligence "
                "for an attacker.",
                "severity": "Informational",
                "confidence": "high",
                "evidence": ev("User Object"),
            }
        )

    # Sensitive data cached in IndexedDB (from sensitive_schema).
    from modules.intelligence.sensitive_schema import analyze_sensitive_schemas

    idb = [m for m in analyze_sensitive_schemas(data) if m["endpoint"].startswith("IndexedDB:")]
    if idb:
        findings.append(
            {
                "title": "Sensitive data cached in IndexedDB",
                "risk": "PII / business data persisted client-side, readable by JavaScript.",
                "severity": "Medium",
                "confidence": "high",
                "evidence": [
                    f"{m['endpoint']}: {', '.join(m['sensitive_fields'][:6])}" for m in idb
                ][:8],
            }
        )

    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 5))
    return findings
