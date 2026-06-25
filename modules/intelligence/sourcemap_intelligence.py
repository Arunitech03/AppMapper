"""Feature 6: Source Map Intelligence.

Finds JavaScript source maps (``*.map`` bodies, or ``//# sourceMappingURL=``
references) in the corpus and, when the map JSON is present, extracts the original
source file paths and (if embedded in ``sourcesContent``) mines those originals for
routes and API references — surfacing structure minified bundles hide.

Pure/offline: it parses captured map content; it never fetches a map by URL.
"""

from __future__ import annotations

import json
import re

_SOURCEMAP_REF_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")


def analyze_sourcemaps(corpus: list[dict]) -> dict:
    """Return ``{maps:[…], sources:[…], routes:[…], api_refs:[…]}``.

    ``maps`` = source-map references/files seen; ``sources`` = original file paths;
    ``routes``/``api_refs`` = extracted from any embedded ``sourcesContent``.
    """
    from modules.intelligence.route_discovery import extract_api_refs, extract_routes

    maps: dict[str, None] = {}
    sources: dict[str, None] = {}
    inner_corpus: list[dict] = []

    for item in corpus:
        text = item.get("text") or ""
        url = item.get("url") or ""
        if not text:
            continue

        # 1) Reference to an external map.
        for ref in _SOURCEMAP_REF_RE.findall(text):
            maps.setdefault(ref, None)

        # 2) An actual source-map body (JSON with "sources"/"version").
        looks_like_map = url.lower().endswith(".map") or (
            '"sources"' in text[:4000] and '"version"' in text[:4000]
        )
        if not looks_like_map:
            continue
        try:
            obj = json.loads(text)
        except (ValueError, TypeError):
            continue
        if not isinstance(obj, dict) or "sources" not in obj:
            continue
        maps.setdefault(url or "(inline map)", None)
        for s in obj.get("sources", []) or []:
            sources.setdefault(_clean_source(s), None)
        for content in obj.get("sourcesContent", []) or []:
            if content:
                inner_corpus.append({"url": url, "source": "Source Map", "text": content})

    routes = extract_routes(inner_corpus) if inner_corpus else []
    api_refs = extract_api_refs(inner_corpus) if inner_corpus else []
    return {
        "maps": sorted(maps),
        "sources": sorted(s for s in sources if s),
        "routes": routes,
        "api_refs": api_refs,
    }


def _clean_source(s: str) -> str:
    s = (s or "").strip()
    # Strip webpack/rollup noise prefixes for readability.
    for prefix in ("webpack://", "webpack-internal:///", "ng://"):
        if s.startswith(prefix):
            s = s[len(prefix) :]
    return s
