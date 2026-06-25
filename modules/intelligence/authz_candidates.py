"""Issue 7: Authorization Test Candidate generator.

Turns the discovered sensitive endpoints into a concrete, prioritized list of
*authorization* tests a human pentester should perform — what to test, on which
endpoint, and why. **Recommendations only**: AppMapper performs none of these; it
issues no requests here and does no privilege/authorization testing itself.
"""

from __future__ import annotations

from modules.intelligence.confidence import MEDIUM, strongest
from modules.intelligence.function_detector import detect_functions

# Sensitive function categories worth authorization testing, with the test set
# each implies. Categories not listed (e.g. plain GIS) are not authz candidates.
CATEGORY_TESTS: dict[str, list[str]] = {
    "User Management": [
        "Horizontal Access Control (IDOR)",
        "Vertical Privilege Escalation",
        "Role Bypass",
    ],
    "Administrative": [
        "Privilege Escalation",
        "Unauthorized Modification",
        "Access Control Review",
    ],
    "Emergency Response": [
        "Privilege Escalation",
        "Unauthorized Action Trigger",
        "Access Control Review",
    ],
}
# A reason label per (category, subcategory) — falls back to the category.
MUTATION_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
MUTATION_TESTS = ["Authorization Check", "Object-Level Access (IDOR)"]


def build_authz_candidates(data: dict) -> list[dict]:
    """Return ranked authorization test candidates.

    Each item: ``{endpoint, method, reason, tests, confidence}``. Built from the
    normalized API inventory crossed with sensitive-function classification, plus
    any state-changing (POST/PUT/PATCH/DELETE) endpoint.
    """
    from modules.intelligence.asset_inventory import unified_api_inventory

    inventory = unified_api_inventory(data)

    # Exclude static assets + telemetry/monitoring traffic from candidates (A.5).
    from modules.intelligence.classifiers import is_noise_path
    from modules.intelligence.telemetry_classifier import is_telemetry

    inventory = [
        a for a in inventory if not is_noise_path(a["path"]) and not is_telemetry(a["path"])
    ]

    # Classify inventory paths into sensitive functions, indexed by endpoint.
    funcs = detect_functions(
        [{"path": api["path"], "method": (api.get("methods") or ["GET"])[0]} for api in inventory]
    )
    by_path: dict[str, list] = {}
    for f in funcs:
        by_path.setdefault(f.endpoint, []).append(f)

    candidates: dict[str, dict] = {}
    for api in inventory:
        path = api["path"]
        methods = api.get("methods") or ["GET"]
        matched = by_path.get(path, [])

        reasons: list[str] = []
        tests: set[str] = set()
        conf = "low"
        for fn in matched:
            if fn.category in CATEGORY_TESTS:
                label = f"{fn.category}"
                if fn.subcategory and fn.subcategory != fn.category:
                    label = f"{fn.category} ({fn.subcategory})"
                reasons.append(label)
                tests.update(CATEGORY_TESTS[fn.category])
                conf = strongest(conf, fn.confidence or MEDIUM)

        is_mutation = any(m in MUTATION_METHODS for m in methods)
        if is_mutation:
            reasons.append("State-changing operation")
            tests.update(MUTATION_TESTS)
            conf = strongest(conf, MEDIUM)

        if not tests:
            continue  # not an authorization candidate

        method = next((m for m in methods if m in MUTATION_METHODS), methods[0])
        candidates[path] = {
            "endpoint": path,
            "method": method,
            "service": api.get("service"),
            "reason": "; ".join(dict.fromkeys(reasons)),
            "tests": sorted(tests),
            "confidence": conf,
        }

    out = list(candidates.values())
    # Highest confidence first, then most tests, then path.
    order = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda c: (order.get(c["confidence"], 3), -len(c["tests"]), c["endpoint"]))
    return out
