"""Features 3 + 4: Frontend route discovery + hidden API reference extraction.

Mines JS/HTML content for:
  * **routes** — Angular/React/Vue router definitions (``path: '…'`` / ``<Route path=…>``);
  * **API references** — endpoints called from ``fetch``/``axios``/``XMLHttpRequest``/
    Angular ``HttpClient``/Apollo, plus API-shaped path literals.

These feed the Frontend Route Inventory and the "referenced but not observed"
hidden-endpoint diff. Pure/offline string analysis — nothing is requested.
"""

from __future__ import annotations

import re

# Router path definitions across frameworks: `path: 'admin'`, `path: "/billing"`,
# JSX `<Route path="/admin/users">`.
_ROUTE_RE = re.compile(r"""path\s*[:=]\s*['"]([A-Za-z0-9_\-/:{}.~]*)['"]""")

# API calls: capture the first string argument of common HTTP call shapes.
_CALL_RE = re.compile(
    r"""(?:fetch|axios(?:\.(?:get|post|put|patch|delete|request))?|"""
    r"""\.(?:get|post|put|patch|delete)|open|HttpClient|httpClient|\$http\.\w+)"""
    r"""\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)
# API-shaped path literals anywhere (service/api/rest/graphql/versioned).
_API_LITERAL_RE = re.compile(
    r"""['"`](/(?:[A-Za-z0-9_\-]+/)*(?:api|rest|graphql|svc|v\d+)(?:/[A-Za-z0-9_\-./{}:]*)?)['"`]""",
    re.IGNORECASE,
)
_STATIC_SUFFIX = (".js", ".css", ".png", ".jpg", ".svg", ".woff", ".woff2", ".ico", ".map", ".json")


def _clean_route(raw: str) -> str | None:
    r = raw.strip()
    if not r or r in {"*", "**", "/", "/*", "/**"}:
        return None
    if r.startswith(("http://", "https://", "./", "../")) or "${" in r:
        return None
    if all(seg.startswith(":") for seg in r.split("/") if seg):  # only params
        return None
    if not r.startswith("/"):
        r = "/" + r
    return r


def extract_routes(corpus: list[dict]) -> list[str]:
    """Distinct frontend route paths referenced in JS/HTML content."""
    routes: dict[str, None] = {}
    for item in corpus:
        text = item.get("text") or ""
        if not text:
            continue
        for raw in _ROUTE_RE.findall(text):
            r = _clean_route(raw)
            if r:
                routes.setdefault(r, None)
    return sorted(routes)


# Non-HTTP pseudo-paths that JS/libraries reference (process streams, FS paths,
# protocol-relative noise). These are never application API endpoints.
_PSEUDO_PREFIXES = (
    "/dev/",
    "/proc/",
    "/sys/",
    "/etc/",
    "/var/",
    "/usr/",
    "/bin/",
    "/sbin/",
    "/tmp/",
    "/opt/",
    "/root/",
    "/home/",
    "/lib/",
    "/node_modules/",
    "/.",
    "//",
)
_PSEUDO_EXACT = {"/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/null"}


def _looks_like_api(path: str) -> bool:
    low = path.lower()
    if low in _PSEUDO_EXACT or low.startswith(_PSEUDO_PREFIXES):
        return False  # OS / filesystem pseudo-paths, not API endpoints
    if low.endswith(_STATIC_SUFFIX) and "/api" not in low:
        return False
    return path.startswith("/") and len([s for s in path.split("/") if s]) >= 1


def extract_api_refs(corpus: list[dict]) -> list[str]:
    """Distinct API endpoint paths referenced from JS call sites / literals."""
    refs: dict[str, None] = {}

    def add(path: str) -> None:
        path = (path or "").strip()
        if not path.startswith("/"):
            return
        path = path.split("?", 1)[0].split("#", 1)[0]
        if _looks_like_api(path):
            refs.setdefault(path, None)

    for item in corpus:
        text = item.get("text") or ""
        if not text:
            continue
        for m in _CALL_RE.findall(text):
            add(m)
        for m in _API_LITERAL_RE.findall(text):
            add(m)
    return sorted(refs)
