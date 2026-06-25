"""Ingest exploration.json into AppMapper's existing data model.

Captured exploration data (from ``auth explore``) is normalized into the SAME DTOs
the rest of the pipeline already consumes — crawl endpoints, forms, HAR-style
requests, and masked auth artifacts — all tagged with the configured role. Because
it lands in the same tables, exploration becomes a first-class input to workflow
mapping, role comparison, API analysis, attack-surface graph generation, and the
AI application summary, with no parallel pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from models.schemas import (
    AuthArtifact,
    CrawlEndpoint,
    DiscoveredForm,
    FormField,
    HarRequest,
    IntelFinding,
)

ACCESSIBLE = 200


# Individual Sprint-B browser file name -> browser_intelligence key.
_BROWSER_FILES = {
    "cookies.json": "cookies",
    "localstorage.json": "local_storage",
    "sessionstorage.json": "session_storage",
    "indexeddb.json": "indexeddb",
    "cache_storage.json": "cache_storage",
    "websocket.json": "websockets",
    "feature_flags.json": "feature_flags",
    "runtime_config.json": "runtime_config",
    "service_workers.json": "service_workers",
    "routes.json": "routes",
    "forms.json": "forms",
    "csp.json": "csp",
    "cors.json": "cors",
    "manifest.json": "manifest",
    "framework_state.json": "framework_state",
}
# Keys that mark a JSON object as a raw browser-intelligence block.
_BROWSER_BLOCK_KEYS = set(_BROWSER_FILES.values()) | {"role"}
# Keys that mark a full exploration.json.
_EXPLORATION_KEYS = {"navigations", "api_calls", "browser_intelligence", "endpoint_inventory"}


def load_exploration(path: str | Path) -> dict:
    """Load an exploration source — a full ``exploration.json``, a standalone
    ``browser_intelligence.json``, or a ``<role>_browser/`` directory of the
    individual Sprint-B files. Returns a dict in exploration.json shape."""
    p = Path(path)
    if p.is_dir():
        return {"browser_intelligence": _load_browser_dir(p)}
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return {}
    # Full exploration.json (has navigations/api_calls/browser_intelligence/…).
    if data.keys() & _EXPLORATION_KEYS:
        return data
    # A raw browser-intelligence block (the consolidated browser_intelligence.json).
    if data.keys() & _BROWSER_BLOCK_KEYS:
        return {"browser_intelligence": data}
    return data


def _load_browser_dir(directory: Path) -> dict:
    """Reconstruct a browser_intelligence block from a ``<role>_browser/`` folder."""
    # Prefer the consolidated file if present.
    consolidated = directory / "browser_intelligence.json"
    if consolidated.exists():
        try:
            return json.loads(consolidated.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    block: dict = {}
    for fname, key in _BROWSER_FILES.items():
        fp = directory / fname
        if fp.exists():
            try:
                block[key] = json.loads(fp.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                pass
    return block


def _path(url: str) -> str:
    return urlparse(url).path or "/"


def _redact(url: str) -> str:
    from modules.auth.masking import redact_url

    return redact_url(url)


def parse(role: str, source: str | Path | dict, *, show_pii: bool = False) -> dict:
    """Parse exploration data into role-tagged DTO lists.

    Returns ``{crawl_endpoints, forms, har_requests, artifacts, inventory}``.
    Everything is associated with ``role`` (the configured role).
    """
    data = source if isinstance(source, dict) else load_exploration(source)

    crawl: list[CrawlEndpoint] = []
    forms: list[DiscoveredForm] = []
    har: list[HarRequest] = []
    artifacts: list[AuthArtifact] = []

    # Navigations -> pages (crawl endpoints) + sequence-bearing HAR requests.
    for nav in data.get("navigations", []) or []:
        url = _redact(nav.get("url", ""))
        if not url:
            continue
        crawl.append(
            CrawlEndpoint(
                role=role,
                url=url,
                path=_path(url),
                method="GET",
                status_code=ACCESSIBLE,
                content_type="text/html",
                source="explore",
                title=nav.get("title"),
            )
        )
        har.append(HarRequest(url=url, method="GET", role=role))

    # API calls -> API-source endpoints + HAR requests (feeds API analyzer/workflow).
    for call in data.get("api_calls", []) or []:
        url = _redact(call.get("url", ""))
        if not url:
            continue
        method = call.get("method", "GET")
        crawl.append(
            CrawlEndpoint(
                role=role,
                url=url,
                path=_path(url),
                method=method,
                status_code=call.get("status"),
                content_type=call.get("response_content_type"),
                source="api",
            )
        )
        har.append(
            HarRequest(
                url=url,
                method=method,
                role=role,
                response_status=call.get("status"),
                response_content_type=call.get("response_content_type"),
                response_size=call.get("response_size"),
                response_keys=call.get("response_keys", []) or [],
            )
        )

    # Forms.
    for f in data.get("forms", []) or []:
        action = _redact(f.get("action", ""))
        if not action:
            continue
        forms.append(
            DiscoveredForm(
                role=role,
                page_url=f.get("page_url", action),
                action=action,
                method=f.get("method", "POST"),
                fields=[FormField(name=n) for n in f.get("fields", []) or []],
            )
        )

    # Uploads / downloads / websockets -> categorized crawl endpoints (so function
    # detection flags File Handling / Data Operations, and the graph includes them).
    for up in data.get("uploads", []) or []:
        url = _redact(up.get("url") or up.get("page_url") or "")
        if url:
            crawl.append(
                CrawlEndpoint(
                    role=role,
                    url=url,
                    path=_path(url),
                    method="POST",
                    status_code=ACCESSIBLE,
                    source="upload",
                )
            )
    for dn in data.get("downloads", []) or []:
        url = _redact(dn.get("url", ""))
        if url:
            crawl.append(
                CrawlEndpoint(
                    role=role,
                    url=url,
                    path=_path(url),
                    method="GET",
                    status_code=ACCESSIBLE,
                    source="download",
                    title=dn.get("filename"),
                )
            )
    for ws in data.get("websockets", []) or []:
        url = _redact(ws.get("url", ""))
        if url:
            crawl.append(
                CrawlEndpoint(
                    role=role,
                    url=url,
                    path=_path(url),
                    method="WS",
                    status_code=ACCESSIBLE,
                    source="websocket",
                )
            )

    # Masked auth artifacts (re-tagged with the configured role + exploration source).
    for a in data.get("artifacts", []) or []:
        artifacts.append(
            AuthArtifact(
                role=role,
                kind=a.get("kind", "cookie"),
                name=a.get("name", ""),
                value_masked=a.get("value_masked", ""),
                source="exploration",
            )
        )

    # Runtime-detected technologies (from the live authenticated browser) ->
    # (name, category, evidence) for merge into the technologies table.
    techs: list[tuple[str, str, str | None]] = []
    tech_block = data.get("technologies", {}) or {}
    versions = tech_block.get("versions", {}) or {}
    for name in tech_block.get("frontend", []) or []:
        v = versions.get(name)
        techs.append((name, "frontend", f"exploration{':' + v if v else ''}"))
    for name in tech_block.get("libraries", []) or []:
        v = versions.get(name)
        techs.append((name, "library", f"exploration{':' + v if v else ''}"))

    # Browser intelligence (Sprint B) -> generic intel findings + storage artifacts.
    bi = data.get("browser_intelligence") or {}
    intel_findings = browser_intel_to_findings(role, bi)
    artifacts += _storage_artifacts(role, bi)

    # JWT authorization intelligence: decode the access token FRESH from the sibling
    # capture.har (raw Authorization headers) on every import, so the summary always
    # reflects the current analysis (never a stale capture-time snapshot). Only the
    # masked summary is persisted — the raw token is not stored.
    intel_findings += _jwt_findings_from_har(role, source, show_pii=show_pii)

    inventory = data.get("endpoint_inventory") or sorted({f"{c.method} {c.path}" for c in crawl})
    return {
        "crawl_endpoints": crawl,
        "forms": forms,
        "har_requests": har,
        "artifacts": artifacts,
        "technologies": techs,
        "inventory": inventory,
        "intel_findings": intel_findings,
        "browser_intelligence": bi,
    }


def _jwt_findings_from_har(role: str, source, *, show_pii: bool = False) -> list[IntelFinding]:
    """Decode bearer JWTs from the sibling capture.har into jwt_authz findings.

    Re-decoded fresh on every import so the summary always reflects current analysis.
    PII is masked unless ``show_pii`` (internal environments) — only the summary is
    persisted, never the raw token.
    """
    if isinstance(source, dict):
        return []
    from modules.intelligence.content_sources import sibling_har
    from modules.intelligence.jwt_intelligence import harvest_jwt_summaries

    har_path = sibling_har(str(source))
    if not har_path:
        return []
    try:
        from parsers.har_parser import parse_har

        reqs = parse_har(har_path)
    except (OSError, ValueError):
        return []
    har_rows = [{"headers": r.headers, "role": role} for r in reqs]
    out: list[IntelFinding] = []
    for s in harvest_jwt_summaries(har_rows, [], show_pii=show_pii):
        s["origin"] = "session"  # decoded from the captured session's traffic
        label = f"{s.get('client') or 'jwt'}@{s.get('realm') or s.get('identity_provider') or '?'}"
        out.append(
            IntelFinding(
                kind="jwt_authz",
                category="Authorization",
                name=label,
                value_masked=s.get("token_masked"),
                source="exploration",
                confidence="high",
                severity="Informational",
                extra=s,
            )
        )
    return out


def _safe_mask(name, value):
    """Defense-in-depth: mask secret-ish values even if upstream masking was missed.

    Already-masked samples (containing the mask marker) and short non-secret config
    (roles, tenant ids, URLs) are kept; raw tokens/keys are masked.
    """
    from modules.auth.explorer import _mask_value

    if value is None:
        return None
    text = str(value)
    if "…" in text or "***" in text:  # already masked
        return text
    return _mask_value(name or "", text)


def _storage_artifacts(role: str, bi: dict) -> list[AuthArtifact]:
    """localStorage/sessionStorage keys -> masked auth artifacts (storage intel)."""
    out: list[AuthArtifact] = []
    for kind, store in (
        ("local_storage", bi.get("local_storage")),
        ("session_storage", bi.get("session_storage")),
    ):
        for name, value in (store or {}).items():
            out.append(
                AuthArtifact(
                    role=role,
                    kind=kind,
                    name=name,
                    value_masked=str(_safe_mask(name, value)),
                    source="exploration",
                )
            )
    return out


def browser_intel_to_findings(role: str, bi: dict) -> list[IntelFinding]:
    """Convert a browser_intelligence block into generic IntelFinding rows."""
    if not bi:
        return []
    f: list[IntelFinding] = []

    def add(
        kind,
        category,
        name,
        *,
        value=None,
        location=None,
        source="Browser",
        confidence="high",
        extra=None,
    ):
        f.append(
            IntelFinding(
                kind=kind,
                category=category,
                name=str(name)[:255],
                value_masked=value,
                location=location,
                source=source,
                confidence=confidence,
                severity="Informational",
                extra=extra or {},
            )
        )

    # JWT Authorization Intelligence: masked summaries decoded at capture time (where
    # the session token was still raw). Persisted as jwt_authz findings for report time.
    for s in bi.get("jwt_authorization", []) or []:
        add(
            "jwt_authz",
            "Authorization",
            f"{s.get('client') or 'jwt'}@{s.get('realm') or s.get('identity_provider') or '?'}",
            value=s.get("token_masked"),
            source="exploration",
            extra=s,
        )

    for flag in bi.get("feature_flags", []):
        add(
            "feature_flag",
            "Feature Flags",
            flag["feature"],
            value=str(flag.get("enabled")),
            source="Browser",
            extra={"enabled": flag.get("enabled")},
        )
    for r in bi.get("routes", []):
        add("route", "Routes", r, location=r, source="DOM", confidence="medium")
    for form in bi.get("forms", []):
        add(
            "form",
            "Forms",
            form.get("action") or "(no action)",
            location=form.get("action"),
            source="DOM",
            extra={"method": form.get("method"), "fields": form.get("fields", [])},
        )
    for ws in bi.get("websockets", []):
        add(
            "websocket",
            "Realtime",
            ws["url"],
            location=ws["url"],
            source="WebSocket",
            extra={"messageTypes": ws.get("messageTypes", []), "fields": ws.get("fields", [])},
        )
    for db in bi.get("indexeddb", []):
        add(
            "indexeddb",
            "Storage",
            db.get("database") or "(db)",
            source="IndexedDB",
            extra={"stores": db.get("stores", [])},
        )
    for cache in bi.get("cache_storage", []):
        add(
            "cache_entry",
            "Cache",
            cache.get("cache") or "(cache)",
            source="Cache Storage",
            extra={"entries": cache.get("entries", [])},
        )
    for sw in bi.get("service_workers", []):
        add(
            "service_worker",
            "Service Worker",
            sw.get("scriptURL") or "(sw)",
            location=sw.get("scope"),
            source="Service Worker",
            extra=sw,
        )
    for c in bi.get("csp", []):
        add(
            "csp",
            "CSP",
            c.get("url") or "(csp)",
            source="Header",
            extra={"directives": c.get("directives", {})},
        )
    for c in bi.get("cors", []):
        add(
            "cors",
            "CORS",
            c.get("host") or "(cors)",
            source="Header",
            extra={
                "allow_origin": c.get("allow_origin"),
                "allow_credentials": c.get("allow_credentials"),
            },
        )
    man = bi.get("manifest")
    if man and man.get("href"):
        add("manifest", "Manifest", man["href"], location=man["href"], source="DOM")
    for group, cfg in (bi.get("runtime_config") or {}).items():
        for k, v in cfg.items():
            mv = _safe_mask(k, v)
            add(
                "runtime_config",
                "Configuration",
                k,
                value=str(mv) if mv is not None else None,
                location=group,
                source="Runtime Config",
                confidence="high",
                extra={"global": group},
            )
    for fw, val in (bi.get("framework_state") or {}).items():
        keys = val if isinstance(val, list) else ([] if val is True else [])
        add(
            "framework_state",
            "Framework State",
            fw,
            source="Framework",
            confidence="medium",
            extra={"keys": keys},
        )
    for ck in bi.get("cookies", []):
        add(
            "cookie_attr",
            "Cookies",
            ck.get("name") or "(cookie)",
            source="Cookie",
            value=ck.get("value_masked"),
            extra={
                k: ck.get(k)
                for k in ("domain", "path", "secure", "httpOnly", "sameSite", "session_cookie")
            },
        )
    return f
