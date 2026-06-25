"""Issue 10: High-value attack-surface scoring & prioritization.

Scores functional areas by sensitivity (admin / user-management / auth / file
upload / export / payment / configuration carry more weight) blended with the
detected business modules, and ranks them into a prioritized list for manual
testing. Prioritization only — it identifies *where to look*, not how to exploit.
"""

from __future__ import annotations

AREA_WEIGHTS = {
    "Admin": 5,
    "Configuration": 5,
    "User Management": 5,
    "Payment": 5,
    "Authentication": 4,
    "File Upload": 4,
    "Export": 3,
}
SENSITIVE_MODULES = {
    "Administration": 6,
    "User Management": 6,
    "Emergency Response": 5,
    "Scenario Planning": 4,
    "Flood Prediction": 3,
    "Asset Management": 3,
}


def score_attack_surface(data: dict) -> list[dict]:
    """Return a ranked list of high-value areas: [{area, score, count, endpoints}]."""
    from modules.intelligence.business_modules import detect_business_modules
    from modules.intelligence.domain_classifier import build_domain_intel

    merged: dict[str, dict] = {}

    def bump(area: str, score: int, count: int, endpoints: list[str]) -> None:
        e = merged.setdefault(area, {"area": area, "score": 0, "count": 0, "endpoints": []})
        e["score"] += score
        e["count"] += count
        for ep in endpoints:
            if ep and ep not in e["endpoints"]:
                e["endpoints"].append(ep)
        e["endpoints"] = e["endpoints"][:6]

    # High-value endpoints grouped by classification (area).
    di = build_domain_intel(data)
    for v in di.get("high_value", []):
        area = v["classification"]
        bump(area, AREA_WEIGHTS.get(area, 2), 1, [v["endpoint"]])

    # Sensitive business modules add weight (and surface as areas of their own).
    for m in detect_business_modules(data):
        weight = SENSITIVE_MODULES.get(m["module"])
        if weight:
            bump(m["module"], weight + min(m["score"], 5), m["score"], [])

    return sorted(merged.values(), key=lambda x: (-x["score"], x["area"]))
