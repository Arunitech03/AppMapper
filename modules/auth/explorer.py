"""Exploration Capture Mode (Playwright, optional dependency).

Launches a real browser so the user can authenticate (Keycloak / OAuth / OIDC /
SAML / MFA / SSO — all by hand) and then **manually explore** the application,
while AppMapper continuously records:

  * page navigations
  * API requests and responses (XHR / fetch)
  * form submissions
  * file upload actions
  * download actions
  * WebSocket connections
  * authentication artifacts (masked)

On finish it writes ``exploration.json`` (structured capture), ``captured.har``
(a standard HAR), and a derived endpoint inventory — all tagged with the role.

**Passive observer.** AppMapper attaches event listeners and *watches*. During a
session it never navigates, reloads, closes/opens tabs, changes focus, injects
JavaScript, or otherwise touches the pages the user is driving — so SSO popups,
OIDC redirects and SPAs behave exactly as in a normal browser. The browser is
read only once, at the very end, after the user has finished (and only if it is
still open). ``safe_mode`` additionally disables that single end-of-session
JavaScript fingerprint, guaranteeing zero ``page.evaluate`` for the whole run.

Discovery-only: AppMapper merely observes what the user does. It performs no
login automation, no IdP/MFA attacks, and stores secrets only in masked form in
``exploration.json`` (the raw HAR is the user's own capture file).
"""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from urllib.parse import urlparse

from core.logging import get_logger
from modules.auth.cookie_auth import is_session_cookie
from modules.auth.masking import mask_secret
from modules.auth.playwright_auth import INSTALL_HINT, PlaywrightNotInstalled
from modules.fingerprint.runtime_fingerprint import detect_in_page

log = get_logger("explorer")

# Resource types Playwright reports for programmatic API traffic.
API_RESOURCE_TYPES = {"xhr", "fetch", "eventsource", "websocket"}
API_HINTS = ("/api", "/graphql", "/rest", "/v1/", "/v2/", "/v3/")

# Path markers for authentication flows (OIDC / OAuth2 / Keycloak / SAML / ADFS).
# Matching traffic is *tagged* for visibility only — never crawled, replayed,
# modified, or auto-followed during capture.
AUTH_FLOW_MARKERS = (
    "/oauth",
    "/oauth2",
    "/openid-connect",
    "/connect/",
    "/realms/",
    "/login-actions",
    "/auth/",
    "/saml",
    "/adfs",
    "/.well-known/openid",
)


# In-page browser-intelligence capture script (run once at end-of-session).
_BROWSER_INTEL_JS = (Path(__file__).parent / "browser_intel.js").read_text(encoding="utf-8")

# Storage/config keys whose values are non-secret and useful verbatim (URLs, flags).
_NONSECRET_KEY_RE = re.compile(
    r"(?i)(url|uri|endpoint|base|gateway|issuer|enable|flag|feature|env|region|tenant|locale|theme)"
)
_SECRETISH_KEY_RE = re.compile(
    r"(?i)(token|secret|password|passwd|pwd|key|jwt|auth|credential|session|pkce|signature|bearer)"
)


def is_auth_flow(url: str) -> bool:
    """True if the URL path looks like an IdP/SSO authentication flow."""
    path = urlparse(url).path.lower()
    return any(m in path for m in AUTH_FLOW_MARKERS)


def classify_request(method: str, url: str, resource_type: str, content_type: str | None) -> str:
    """Classify a captured request into an activity kind (pure / testable).

    Returns one of: api | upload | form | navigation | resource.
    """
    path = urlparse(url).path.lower()
    ct = (content_type or "").lower()
    rt = (resource_type or "").lower()

    if method.upper() == "POST" and "multipart/form-data" in ct:
        return "upload"
    if method.upper() in {"POST", "PUT", "PATCH"} and "x-www-form-urlencoded" in ct:
        return "form"
    if rt in API_RESOURCE_TYPES or any(h in path for h in API_HINTS) or "json" in ct:
        return "api"
    if rt == "document":
        return "navigation"
    return "resource"


def endpoint_inventory(api_calls: list[dict], navigations: list[dict]) -> list[str]:
    """Distinct ``METHOD path`` strings from captured API calls + navigations."""
    seen: dict[str, None] = {}
    for c in api_calls:
        seen.setdefault(f"{c.get('method', 'GET')} {urlparse(c.get('url', '')).path or '/'}", None)
    for n in navigations:
        seen.setdefault(f"GET {urlparse(n.get('url', '')).path or '/'}", None)
    return list(seen)


def _json_top_level_keys(text: str | None) -> list[str]:
    """Top-level keys of a JSON body (KEYS ONLY — values are discarded)."""
    if not text:
        return []
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return []
    if isinstance(obj, dict):
        return list(obj.keys())[:50]
    if isinstance(obj, list) and obj and isinstance(obj[0], dict):
        return list(obj[0].keys())[:50]
    return []


def _mask_headers(headers: dict) -> dict:
    """Mask sensitive request/response headers (Authorization, Cookie, etc.)."""
    masked = {}
    for k, v in (headers or {}).items():
        if k.lower() in {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}:
            masked[k] = mask_secret(v)
        else:
            masked[k] = v
    return masked


def _cookie_names(set_cookie: str) -> list[str]:
    """Cookie names from one or more ``Set-Cookie`` header values (names only)."""
    names: list[str] = []
    for line in (set_cookie or "").split("\n"):
        head = line.split(";", 1)[0]
        if "=" in head:
            name = head.split("=", 1)[0].strip()
            if name:
                names.append(name)
    return names


def _parse_csp(policy: str) -> dict:
    """Parse a CSP header into {directive: [sources]} (Feature 13)."""
    directives: dict[str, list[str]] = {}
    for part in (policy or "").split(";"):
        toks = part.split()
        if toks:
            directives[toks[0].lower()] = toks[1:]
    return directives


def _mask_value(key: str, value):
    """Mask secret-ish values; keep non-secret config (URLs/flags) verbatim."""
    if isinstance(value, bool) or value is None:
        return value
    text = str(value)
    if _SECRETISH_KEY_RE.search(key or "") and not _NONSECRET_KEY_RE.search(key or ""):
        return mask_secret(text)
    # Long opaque token-looking value under any key -> mask.
    if len(text) > 40 and " " not in text and "/" not in text and "." in text:
        return mask_secret(text)
    return value


def _mask_map(d: dict) -> dict:
    return {k: _mask_value(k, v) for k, v in (d or {}).items()}


def _ws_schema_from_frame(rec: dict, payload) -> None:
    """Record a WebSocket frame's top-level field names + type discriminator only."""
    if not isinstance(payload, (str, bytes)):
        return
    text = payload.decode("utf-8", "ignore") if isinstance(payload, bytes) else payload
    text = text.strip()
    if not text or text[0] not in "{[":
        return
    obj = json.loads(text)
    if isinstance(obj, list):
        obj = obj[0] if obj and isinstance(obj[0], dict) else None
    if not isinstance(obj, dict):
        return
    for disc in ("type", "event", "action", "messageType", "kind"):
        if isinstance(obj.get(disc), str) and len(obj[disc]) <= 64:
            rec["messageTypes"].add(obj[disc])
            break
    for k in list(obj.keys())[:50]:
        rec["fields"].add(k)


def _jwt_authorization(role, raw: dict) -> list[dict]:
    """Decode JWTs from raw localStorage/sessionStorage/runtime config (masked output)."""
    from modules.intelligence.jwt_intelligence import find_jwts, summarize_jwts

    blobs: list[str] = []
    for store in ("localStorage", "sessionStorage"):
        for value in (raw.get(store) or {}).values():
            blobs.append(str(value))
    for cfg in (raw.get("runtime_config") or {}).values():
        for value in (cfg or {}).values():
            blobs.append(str(value))
    return summarize_jwts(find_jwts(*blobs), role=role)


def _storage_analysis(role, raw: dict, raw_cookie_map: dict) -> list[dict]:
    """Deep-analyze RAW storage/cookie values before masking (B6.1).

    Runs the mask-safe storage analyzer over the fully-raw localStorage / sessionStorage /
    cookie values captured this session, so decoding happens before masking. Only mask-safe
    records are returned (no raw values).
    """
    from modules.intelligence.storage_intelligence import analyze_storage_value

    out: list[dict] = []
    for kind, store in (
        ("local_storage", (raw or {}).get("localStorage")),
        ("session_storage", (raw or {}).get("sessionStorage")),
    ):
        for name, value in (store or {}).items():
            out.append(analyze_storage_value(kind, name, value, role=role))
    for name, value in (raw_cookie_map or {}).items():
        out.append(analyze_storage_value("cookie", name, value, role=role))
    return out


def _build_browser_intel(role, raw, cookies, csp_seen, cors_seen, ws_schemas) -> dict:
    """Assemble the masked browser-intelligence dict from raw capture pieces."""
    raw = raw or {}
    runtime_config = {g: _mask_map(cfg) for g, cfg in (raw.get("runtime_config") or {}).items()}
    feature_flags = _extract_feature_flags(raw, runtime_config)
    return {
        "role": role,
        "cookies": cookies,
        # JWT authorization intelligence, decoded from the RAW storage values before
        # they are masked below. Only masked summaries are emitted (no raw token).
        "jwt_authorization": _jwt_authorization(role, raw),
        "local_storage": _mask_map(raw.get("localStorage") or {}),
        "session_storage": _mask_map(raw.get("sessionStorage") or {}),
        "indexeddb": raw.get("indexeddb") or [],
        "cache_storage": raw.get("cache_storage") or [],
        "service_workers": raw.get("service_workers") or [],
        "runtime_config": runtime_config,
        "feature_flags": feature_flags,
        "framework_state": raw.get("framework_state") or {},
        "forms": raw.get("forms") or [],
        "routes": raw.get("routes") or [],
        "manifest": raw.get("manifest"),
        "csp": list(csp_seen.values()),
        "cors": list(cors_seen.values()),
        "websockets": [
            {
                "url": v["url"],
                "messageTypes": sorted(v["messageTypes"]),
                "fields": sorted(v["fields"]),
            }
            for v in ws_schemas.values()
        ],
    }


_FLAG_KEY_RE = re.compile(r"(?i)^(enable|disable|allow|show|is|has|feature|beta|flag)")


def _extract_feature_flags(raw: dict, runtime_config: dict) -> list[dict]:
    """Boolean flags from localStorage + runtime config (Feature 8)."""
    flags: dict[str, bool] = {}

    def scan(d: dict) -> None:
        for k, v in (d or {}).items():
            if isinstance(v, bool) and _FLAG_KEY_RE.search(k):
                flags.setdefault(k, v)
            elif isinstance(v, str) and v.lower() in {"true", "false"} and _FLAG_KEY_RE.search(k):
                flags.setdefault(k, v.lower() == "true")

    scan(raw.get("localStorage") or {})
    for cfg in (runtime_config or {}).values():
        scan(cfg)
    return [{"feature": k, "enabled": v} for k, v in sorted(flags.items())]


def _write_browser_intel_files(out_json: Path, intel: dict) -> None:
    """Write the individual Sprint-B browser-intelligence files alongside the json."""
    base = out_json.with_name(out_json.stem + "_browser")
    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError:
        return
    files = {
        "cookies.json": intel.get("cookies"),
        "localstorage.json": intel.get("local_storage"),
        "sessionstorage.json": intel.get("session_storage"),
        "indexeddb.json": intel.get("indexeddb"),
        "cache_storage.json": intel.get("cache_storage"),
        "websocket.json": intel.get("websockets"),
        "feature_flags.json": intel.get("feature_flags"),
        "runtime_config.json": intel.get("runtime_config"),
        "service_workers.json": intel.get("service_workers"),
        "routes.json": intel.get("routes"),
        "forms.json": intel.get("forms"),
        "csp.json": intel.get("csp"),
        "cors.json": intel.get("cors"),
        "manifest.json": intel.get("manifest"),
        "framework_state.json": intel.get("framework_state"),
        "browser_intelligence.json": intel,
    }
    for name, payload in files.items():
        try:
            (base / name).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except OSError:
            pass


def explore(
    role: str,
    url: str,
    out_json: str | Path,
    har_path: str | Path,
    *,
    headless: bool = False,
    safe_mode: bool = False,
    debug_browser: bool = False,
    on_ready=None,
    poll_ms: int = 500,
    nav_timeout_ms: int = 60000,
    ignore_https_errors: bool = False,
) -> dict:
    """Run an interactive exploration capture and write exploration.json + HAR.

    Parameters
    ----------
    role: identity label all captured activity is associated with.
    url: application URL to open.
    out_json / har_path: output files.
    headless: run without a visible window (headless/CI; manual use is headed).
    safe_mode: strict passive mode — never inject JavaScript (no ``page.evaluate``
        at all, including the end-of-session technology fingerprint).
    debug_browser: log every browser event (tab created/closed, navigation,
        popup, download, websocket) with a timestamp + source.
    on_ready: optional callable ``(page) -> None`` for automation/tests. When given,
        it drives the page and the function finalizes when it returns (no manual
        wait). When ``None``, the function waits until the user closes the browser
        or presses Enter in the terminal.
    poll_ms: event-pump interval while waiting for the user.

    Returns the exploration dict. Raises :class:`PlaywrightNotInstalled` if missing.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # noqa: BLE001
        raise PlaywrightNotInstalled(INSTALL_HINT) from exc

    out_json = Path(out_json)
    har_path = Path(har_path)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    har_path.parent.mkdir(parents=True, exist_ok=True)

    navigations: list[dict] = []
    api_calls: list[dict] = []
    forms: list[dict] = []
    uploads: list[dict] = []
    downloads: list[dict] = []
    websockets: list[dict] = []
    artifacts: list[dict] = []
    tabs: list[dict] = []  # observed tabs/popups (logged, never manipulated)
    csp_seen: dict[str, dict] = {}  # url -> {policy, directives}
    cors_seen: dict[str, dict] = {}  # origin/host -> {allow_origin, allow_credentials}
    ws_schemas: dict[str, dict] = {}  # ws url -> {messageTypes, fields}

    seen_paths: set[str] = set()
    login_detected = {"v": False}
    cookies_seen: set[str] = set()

    def _dbg(event: str, **kw) -> None:
        if debug_browser:
            log.info("browser_event", kind=event, **kw)

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=headless)
        except Exception as exc:  # noqa: BLE001
            raise PlaywrightNotInstalled(INSTALL_HINT) from exc
        # Embed response bodies in the HAR so response *schemas* (top-level JSON
        # keys, keys-only) can be extracted after the session — without any live
        # body reads that would stall the page (keeps capture passive).
        context = browser.new_context(
            record_har_path=str(har_path),
            record_har_content="embed",
            ignore_https_errors=ignore_https_errors,
        )
        page = context.new_page()  # the user's primary tab
        tracked: list = [page]  # every page/popup we observe

        log.info("explore.session_started", role=role, url=url, safe_mode=safe_mode)

        def _note_endpoint(method: str, path: str) -> None:
            key = f"{method} {path}"
            if key not in seen_paths:
                seen_paths.add(key)
                log.debug("explore.endpoint_captured", endpoint=key)

        def on_request(request) -> None:
            try:
                ct = request.headers.get("content-type")
                kind = classify_request(request.method, request.url, request.resource_type, ct)
                auth_flow = is_auth_flow(request.url)
                if auth_flow and not login_detected["v"]:
                    login_detected["v"] = True
                    log.info("explore.login_flow_detected", url=urlparse(request.url).path)
                rec = {
                    "method": request.method,
                    "url": request.url,
                    "resource_type": request.resource_type,
                    "request_content_type": ct,
                    "headers": _mask_headers(request.headers),
                    "kind": kind,
                    "auth_flow": auth_flow,
                }
                if kind == "api":
                    api_calls.append(rec)
                    _note_endpoint(request.method, urlparse(request.url).path or "/")
                elif kind == "form":
                    forms.append(
                        {
                            "page_url": _frame_url(request),
                            "action": request.url,
                            "method": request.method,
                            "auth_flow": auth_flow,
                        }
                    )
                elif kind == "upload":
                    uploads.append({"page_url": _frame_url(request), "url": request.url})
                # Surface Authorization headers as masked artifacts.
                auth = request.headers.get("authorization")
                if auth:
                    artifacts.append(
                        {
                            "role": role,
                            "kind": "authorization",
                            "name": "Authorization",
                            "value_masked": mask_secret(auth),
                            "source": "exploration",
                        }
                    )
            except Exception:  # noqa: BLE001 - never let a listener crash the capture
                pass

        def on_response(response) -> None:
            # Header-only: status + content-type. We deliberately do NOT call
            # response.text() here — reading bodies synchronously inside the event
            # handler stalls the network pipeline. Response *keys* are extracted
            # later from the saved HAR (parsers.har_parser), keys-only.
            try:
                req = response.request
                ct = response.headers.get("content-type")
                key = f"{req.method} {response.url}"
                for rec in reversed(api_calls):
                    if f"{rec['method']} {rec['url']}" == key and "status" not in rec:
                        rec["status"] = response.status
                        rec["response_content_type"] = ct
                        break
                # CSP (Feature 13) + CORS (Feature 14) from response headers — passive.
                csp = response.headers.get("content-security-policy")
                if csp and response.url not in csp_seen:
                    csp_seen[response.url] = {
                        "url": response.url,
                        "directives": _parse_csp(csp),
                    }
                acao = response.headers.get("access-control-allow-origin")
                if acao:
                    host = urlparse(response.url).hostname or response.url
                    cors_seen.setdefault(
                        host,
                        {
                            "host": host,
                            "allow_origin": acao,
                            "allow_credentials": response.headers.get(
                                "access-control-allow-credentials"
                            ),
                        },
                    )
                # Passive session-cookie capture (survives an abrupt browser close).
                set_cookie = response.headers.get("set-cookie")
                if set_cookie:
                    for name in _cookie_names(set_cookie):
                        if is_session_cookie(name) and name not in cookies_seen:
                            cookies_seen.add(name)
                            artifacts.append(
                                {
                                    "role": role,
                                    "kind": "cookie",
                                    "name": name,
                                    "value_masked": mask_secret("set-via-response"),
                                    "source": "exploration",
                                }
                            )
                            log.debug("explore.cookie_captured", name=name)
            except Exception:  # noqa: BLE001 - never let a listener crash the capture
                pass

        def _frame_url(request) -> str:
            try:
                return request.frame.url
            except Exception:  # noqa: BLE001
                return ""

        def make_on_nav(pg):
            def on_nav(frame) -> None:
                try:
                    if frame == pg.main_frame:
                        navigations.append({"url": frame.url, "auth_flow": is_auth_flow(frame.url)})
                        _dbg("Navigation", url=frame.url)
                except Exception:  # noqa: BLE001
                    pass

            return on_nav

        def on_download(download) -> None:
            try:
                downloads.append({"url": download.url, "filename": download.suggested_filename})
                _dbg("Download", url=download.url)
            except Exception:  # noqa: BLE001
                pass

        def on_websocket(ws) -> None:
            try:
                websockets.append({"url": ws.url})
                ws_schemas.setdefault(
                    ws.url, {"url": ws.url, "messageTypes": set(), "fields": set()}
                )
                _dbg("WebSocket", url=ws.url)

                def on_frame(payload) -> None:
                    # Schema only: top-level field NAMES + a message-type discriminator.
                    # Never the payload values (Feature 6 privacy).
                    try:
                        _ws_schema_from_frame(ws_schemas[ws.url], payload)
                    except Exception:  # noqa: BLE001
                        pass

                ws.on("framereceived", on_frame)
                ws.on("framesent", on_frame)
            except Exception:  # noqa: BLE001
                pass

        def on_filechooser(_chooser) -> None:
            try:
                uploads.append({"page_url": page.url, "element": "file-input"})
            except Exception:  # noqa: BLE001
                pass

        def attach_page_listeners(pg) -> None:
            """Attach observe-only listeners to a page/popup. Never manipulates it."""
            pg.on("framenavigated", make_on_nav(pg))
            pg.on("download", on_download)
            pg.on("websocket", on_websocket)
            pg.on("filechooser", on_filechooser)
            pg.on("close", lambda *_: _dbg("Tab Closed", url=_safe_url(pg)))

        def on_new_page(new_page) -> None:
            # A popup / new tab opened (e.g. OAuth/Keycloak/Azure SSO window, help,
            # report). Observe it; do NOT close, navigate, reload, or focus it.
            try:
                u = _safe_url(new_page)
                tabs.append({"url": u, "auth_flow": is_auth_flow(u)})
                tracked.append(new_page)
                attach_page_listeners(new_page)
                log.info("explore.new_tab", url=u or "(blank)")
                _dbg("Tab Created", url=u or "(blank)", source="window.open/popup")
            except Exception:  # noqa: BLE001
                pass

        # Context-level request/response cover every page in the context, including
        # popups — so SSO-popup traffic is captured even before on_new_page fires.
        context.on("request", on_request)
        context.on("response", on_response)
        context.on("page", on_new_page)
        attach_page_listeners(page)

        # SPAs / OIDC redirects often never reach a quiet "load"; wait only for the
        # DOM and don't abort the capture on a slow first paint — the browser stays
        # open so the user can finish logging in. This is the ONLY navigation we
        # ever issue; everything after is the user's.
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

        page.set_default_navigation_timeout(nav_timeout_ms)
        try:
            page.goto(url, wait_until="domcontentloaded")
        except PlaywrightTimeoutError:
            print("  (page is still loading — that's fine, keep going; the browser stays open)")

        browser_closed = {"v": False}
        browser.on("disconnected", lambda *_: browser_closed.__setitem__("v", True))

        if on_ready is not None:
            on_ready(page)
        else:
            _wait_for_user(tracked, browser_closed, headless=headless, poll_ms=poll_ms, role=role)

        # ---- finalize (browser may already be closed) -------------------------
        browser_open = not browser_closed["v"] and not _is_closed(page)

        # Auth artifacts from the live browser state — read ONCE, only if still open.
        if browser_open:
            try:
                state = context.storage_state()
                artifacts.extend(_artifacts_from_state(role, state))
                log.info("explore.storage_read", origins=len(state.get("origins", [])))
            except BaseException:  # noqa: BLE001 - closing mid-read; rely on passive capture
                pass
            # sessionStorage isn't in storage_state — read it once (default mode only;
            # safe_mode injects no JavaScript). Values masked.
            if not safe_mode:
                try:
                    ss = page.evaluate("() => Object.fromEntries(Object.entries(sessionStorage))")
                    for name, value in (ss or {}).items():
                        artifacts.append(
                            {
                                "role": role,
                                "kind": "session_storage",
                                "name": name,
                                "value_masked": mask_secret(str(value)),
                                "source": "exploration",
                            }
                        )
                except BaseException:  # noqa: BLE001
                    pass

        # Single runtime technology fingerprint — default only, and only if the page
        # is still open. safe_mode never injects JavaScript.
        technologies = {"frontend": [], "libraries": [], "versions": {}}
        if browser_open and not safe_mode:
            try:
                tech = detect_in_page(page)
                technologies = {
                    "frontend": tech.get("frontend", []),
                    "libraries": tech.get("libraries", []),
                    "versions": tech.get("versions", {}),
                }
            except BaseException:  # noqa: BLE001
                pass

        # Cookies with attributes (Feature 3) — context.cookies() needs no JS, so it
        # runs even in safe_mode. Values are masked.
        cookies_intel: list[dict] = []
        raw_cookie_map: dict[str, str] = {}
        if browser_open:
            try:
                for c in context.cookies() or []:
                    name = c.get("name", "")
                    raw_cookie_map[name] = str(c.get("value", ""))
                    cookies_intel.append(
                        {
                            "name": name,
                            "domain": c.get("domain", ""),
                            "path": c.get("path", "/"),
                            "secure": bool(c.get("secure")),
                            "httpOnly": bool(c.get("httpOnly")),
                            "sameSite": c.get("sameSite"),
                            "expires": c.get("expires"),
                            "value_masked": mask_secret(str(c.get("value", ""))),
                            "session_cookie": is_session_cookie(name),
                        }
                    )
            except BaseException:  # noqa: BLE001
                pass

        # Cookie JWT authorization — decoded from the RAW cookie values captured above,
        # before they are masked (only masked summaries are emitted, never the raw token).
        from modules.intelligence.jwt_intelligence import harvest_cookie_jwts

        cookie_jwt_intel = (
            harvest_cookie_jwts([{"cookies": raw_cookie_map, "role": role}])
            if raw_cookie_map
            else []
        )

        # Browser intelligence — ONE end-of-session JS read (skipped in safe_mode).
        raw_intel: dict = {}
        if browser_open and not safe_mode:
            try:
                raw_intel = page.evaluate(_BROWSER_INTEL_JS) or {}
            except BaseException:  # noqa: BLE001
                raw_intel = {}
        browser_intelligence = _build_browser_intel(
            role, raw_intel, cookies_intel, csp_seen, cors_seen, ws_schemas
        )
        browser_intelligence["cookie_jwt_authorization"] = cookie_jwt_intel
        # Storage deep-intelligence, analyzed from the FULLY RAW values before masking
        # (B6.1). Only mask-safe records are stored; raw values are not persisted.
        browser_intelligence["storage_analysis"] = _storage_analysis(
            role, raw_intel, raw_cookie_map
        )

        # Build + WRITE the capture BEFORE closing, so it is never lost even if the
        # browser/context is already gone.
        exploration = {
            "role": role,
            "target_url": url,
            "navigations": navigations,
            "api_calls": api_calls,
            "forms": forms,
            "uploads": uploads,
            "downloads": downloads,
            "websockets": websockets,
            "tabs": tabs,
            "auth_flows": sum(1 for c in api_calls if c.get("auth_flow"))
            + sum(1 for n in navigations if n.get("auth_flow")),
            "artifacts": _dedupe_artifacts(artifacts),
            "technologies": technologies,
            "endpoint_inventory": endpoint_inventory(api_calls, navigations),
            "browser_intelligence": browser_intelligence,
        }
        out_json.write_text(json.dumps(exploration, indent=2), encoding="utf-8")
        # Also write the individual browser-intelligence files (Sprint B layout).
        _write_browser_intel_files(out_json, browser_intelligence)
        log.info(
            "explore.session_saved",
            navigations=len(navigations),
            api_calls=len(api_calls),
            tabs=len(tabs),
            auth_flows=exploration["auth_flows"],
            browser_intel=bool(raw_intel) or bool(cookies_intel),
        )

        # Best-effort flush of the HAR + teardown (the session is over).
        try:
            context.close()  # flushes the HAR file
        except BaseException:  # noqa: BLE001
            pass
        try:
            browser.close()
        except BaseException:  # noqa: BLE001
            pass

    # Response Intelligence: now that the HAR is flushed (browser gone = passive),
    # extract response schemas from it — top-level JSON KEYS only — and merge into
    # the captured API calls, then rewrite exploration.json.
    enriched = _enrich_responses_from_har(exploration, har_path)
    if enriched:
        out_json.write_text(json.dumps(exploration, indent=2), encoding="utf-8")
        log.info("explore.response_intel", endpoints=enriched)

    return exploration


def _enrich_responses_from_har(exploration: dict, har_path: str | Path) -> int:
    """Merge response status/content-type/size/keys (keys-only) from the saved HAR
    into the exploration's ``api_calls``. Returns the number of calls enriched."""
    try:
        from parsers.har_parser import parse_har

        records = parse_har(har_path)
    except Exception as exc:  # noqa: BLE001 - HAR missing/unreadable; skip silently
        log.debug("explore.har_enrich_failed", error=str(exc))
        return 0

    by_key: dict[str, object] = {}
    for r in records:
        by_key.setdefault(f"{r.method.upper()} {r.url}", r)

    enriched = 0
    for call in exploration.get("api_calls", []):
        rec = by_key.get(f"{call.get('method', 'GET').upper()} {call.get('url', '')}")
        if rec is None:
            continue
        if rec.response_status is not None:
            call["status"] = rec.response_status
        if rec.response_content_type:
            call["response_content_type"] = rec.response_content_type
        if rec.response_size is not None:
            call["response_size"] = rec.response_size
        if rec.response_keys:
            call["response_keys"] = rec.response_keys  # KEYS ONLY (never values)
        enriched += 1
    return enriched


def _safe_url(pg) -> str:
    try:
        return pg.url
    except Exception:  # noqa: BLE001
        return ""


def _is_closed(pg) -> bool:
    try:
        return pg.is_closed()
    except Exception:  # noqa: BLE001
        return True


def _wait_for_user(tracked, browser_closed, *, headless: bool, poll_ms: int, role: str) -> None:
    """Block (pumping browser events) until the user finishes.

    Finishes when EITHER the browser/all tabs close OR the user presses Enter in
    the terminal — whichever happens first. Pure waiting: it issues no navigation,
    reload, focus, or close on the user's pages.
    """
    print(
        f"\nExploration capture for role '{role}' started — AppMapper is observing only.\n"
        "Authenticate and explore the app freely (SSO / MFA / popups all fine).\n"
        "→ CLOSE THE BROWSER WINDOW when done, or press Enter here;\n"
        "  the capture saves automatically and the command exits.\n"
    )
    finish = {"v": False}
    if not headless:
        t = threading.Thread(target=_read_enter, args=(finish,), daemon=True)
        t.start()

    while True:
        if finish["v"] or browser_closed["v"]:
            break
        alive = [pg for pg in tracked if not _is_closed(pg)]
        if not alive:
            break
        try:
            alive[0].wait_for_timeout(poll_ms)  # pumps the event loop
        except BaseException:  # noqa: BLE001 - a page closed mid-wait; re-evaluate
            continue


def _read_enter(finish: dict) -> None:
    try:
        input()
    except Exception:  # noqa: BLE001 - stdin closed / non-interactive
        pass
    finish["v"] = True


def _artifacts_from_state(role: str, state: dict) -> list[dict]:
    out: list[dict] = []
    for c in state.get("cookies", []) or []:
        if c.get("name") and is_session_cookie(c["name"]):
            out.append(
                {
                    "role": role,
                    "kind": "cookie",
                    "name": c["name"],
                    "value_masked": mask_secret(c.get("value", "")),
                    "source": "exploration",
                }
            )
    for origin in state.get("origins", []) or []:
        # Capture ALL localStorage keys (masked) so Storage Intelligence can classify
        # roles / tenant ids / feature flags / config — not just token-ish names.
        for entry in (origin.get("localStorage", []) or [])[:200]:
            name = entry.get("name", "")
            if not name:
                continue
            out.append(
                {
                    "role": role,
                    "kind": "local_storage",
                    "name": name,
                    "value_masked": mask_secret(entry.get("value", "")),
                    "source": "exploration",
                }
            )
    return out


def _dedupe_artifacts(artifacts: list[dict]) -> list[dict]:
    seen: dict[tuple, dict] = {}
    for a in artifacts:
        seen.setdefault((a["role"], a["kind"], a["name"]), a)
    return list(seen.values())
