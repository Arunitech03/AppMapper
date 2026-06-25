"""Feature 16: Browser Secret Discovery Engine.

Runs the existing secret-discovery patterns over **browser-resident** material —
local/session storage, runtime config, framework state, cache URLs, manifest,
service-worker scripts, cookies — that never appears in the HAR. Reuses
``secret_discovery.discover_secrets`` by assembling a text corpus from the
(already-masked) browser-intelligence block, so values are masked and full secrets
are never stored. Discovery-only.
"""

from __future__ import annotations

import json

from models.schemas import IntelFinding


def _corpus_from_browser(bi: dict) -> list[dict]:
    """Build ``{location, source, text}`` corpus items from a browser_intel block."""
    items: list[dict] = []

    def push(location: str, source: str, obj) -> None:
        if obj in (None, {}, []):
            return
        text = obj if isinstance(obj, str) else json.dumps(obj)
        if text and text not in {"{}", "[]"}:
            items.append({"url": location, "source": source, "text": text})

    push("localStorage", "Local Storage", bi.get("local_storage"))
    push("sessionStorage", "Session Storage", bi.get("session_storage"))
    for g, cfg in (bi.get("runtime_config") or {}).items():
        push(f"window.{g}", "Runtime Config", cfg)
    push("frameworkState", "Framework State", bi.get("framework_state"))
    push("manifest", "Manifest", bi.get("manifest"))
    for sw in bi.get("service_workers", []):
        push(sw.get("scriptURL", "service-worker"), "Service Worker", sw)
    # Cache entry URLs (internal hosts / debug / admin paths surface here).
    for cache in bi.get("cache_storage", []):
        push(cache.get("cache", "cache"), "Cache Storage", cache.get("entries"))
    return items


def discover_browser_secrets(role: str, bi: dict) -> list[IntelFinding]:
    """Return masked secret findings located in browser-resident storage/config."""
    from modules.intelligence.secret_discovery import discover_secrets

    if not bi:
        return []
    corpus = _corpus_from_browser(bi)
    findings = discover_secrets(corpus)
    # Tag the source group so the report can separate "browser" secrets.
    for f in findings:
        f.extra = {**(f.extra or {}), "scope": "browser", "role": role}
    return findings
