"""Feature 2: Hidden Endpoint Discovery.

Builds two inventories and diffs them:
  * **Observed** — endpoints actually seen (exploration / HAR / Burp / crawl), from
    the unified API inventory.
  * **Referenced** — endpoints/routes referenced in frontend code (JS/HTML/source
    maps), surfaced by the content phase as ``intel_findings`` (kind ``api_ref`` /
    ``route``) plus ``js_findings`` API endpoints.

The difference — **referenced but never observed** — is the highest-value recon
output: functionality the app exposes that testing never exercised. Paths are
normalized (``/zone/{id}``) before diffing, and ranked by a sensitivity score.
Discovery-only: candidates are reported, never requested.
"""

from __future__ import annotations

from modules.intelligence.confidence import HIGH, LOW, MEDIUM
from modules.intelligence.path_normalizer import normalize_path

# Sensitive tokens that raise an endpoint's investigation priority.
_PRIORITY_TOKENS = (
    "admin",
    "user",
    "role",
    "permission",
    "billing",
    "config",
    "setting",
    "report",
    "export",
    "upload",
    "download",
    "internal",
    "manage",
    "account",
    "token",
    "secret",
    "key",
    "password",
    "delete",
)


def _score(path: str) -> int:
    low = path.lower()
    return sum(1 for t in _PRIORITY_TOKENS if t in low)


def _priority(score: int) -> str:
    if score >= 2:
        return HIGH
    if score == 1:
        return MEDIUM
    return LOW


def observed_endpoints(data: dict) -> set[str]:
    """Normalized set of endpoints actually observed (from the unified inventory)."""
    from modules.intelligence.asset_inventory import unified_api_inventory

    return {normalize_path(a["path"]) for a in unified_api_inventory(data)}


def referenced_endpoints(data: dict) -> set[str]:
    """Normalized set of API endpoints referenced in frontend code."""
    from urllib.parse import urlparse

    refs: set[str] = set()
    for f in data.get("intel_findings", []) or []:
        kind = f.get("kind")
        if kind in {"api_ref", "route"}:
            loc = f.get("location") or f.get("name") or ""
            if loc.startswith("/"):
                refs.add(normalize_path(loc))
        elif kind == "cache_entry":
            # Cached API URLs are offline/hidden APIs (Sprint B).
            for entry in (f.get("extra") or {}).get("entries", []):
                path = urlparse(entry).path if "://" in entry else entry
                if path.startswith("/") and any(
                    h in path.lower() for h in ("/api", "/svc", "/rest", "/graphql")
                ):
                    refs.add(normalize_path(path))
    for js in data.get("js_findings", []) or []:
        if js.get("kind") == "api_endpoint":
            v = js.get("value", "")
            if v.startswith("/"):
                refs.add(normalize_path(v))
    return refs


def find_hidden_endpoints(data: dict) -> list[dict]:
    """Return referenced-but-not-observed endpoints, ranked by priority."""
    observed = observed_endpoints(data)
    referenced = referenced_endpoints(data)
    hidden = referenced - observed

    out = []
    for path in hidden:
        score = _score(path)
        out.append(
            {
                "endpoint": path,
                "referenced": True,
                "observed": False,
                "priority": _priority(score),
                "score": score,
            }
        )
    order = {HIGH: 0, MEDIUM: 1, LOW: 2}
    out.sort(key=lambda x: (order[x["priority"]], -x["score"], x["endpoint"]))
    return out
