"""Stability tests for Exploration Capture Mode (passive observer).

These drive ``explorer.explore`` through a fake Playwright harness (no real
browser) that records every method call made on the browser/context/page objects,
then asserts the invariants the Critical Fix Sprint requires:

  * AppMapper never navigates (beyond the one initial goto), reloads, goes
    back/forward, brings-to-front, or closes the user's pages during a session.
  * No periodic JavaScript injection or storage reads during the session — at most
    one of each, at the very end, and only while the browser is still open.
  * ``safe_mode`` performs zero ``page.evaluate`` (no JS injection at all).
  * Popups / new tabs are tracked and captured, never closed or focused by us.
  * Authentication-flow traffic (OIDC/Keycloak/SAML) is tagged, not followed.
  * ``--debug-browser`` emits timestamped browser-event logs.

Scenarios 1-4 of the sprint (Keycloak, Azure+MFA, multi-tab, SPA) reduce to these
invariants: redirects (framenavigated), SSO popups (context "page"), and abrupt
browser close are all simulated here.
"""

from __future__ import annotations

import pytest

from modules.auth import explorer

# --- fake Playwright harness ----------------------------------------------


class _Emitter:
    def __init__(self):
        self._handlers: dict[str, list] = {}

    def on(self, event, handler):
        self._handlers.setdefault(event, []).append(handler)

    def emit(self, event, *args):
        for h in list(self._handlers.get(event, [])):
            h(*args)


class FakeFrame:
    def __init__(self, url):
        self.url = url


class FakeRequest:
    def __init__(self, method, url, *, rtype="xhr", headers=None, frame_url="https://app/"):
        self.method = method
        self.url = url
        self.resource_type = rtype
        self.headers = headers or {}
        self.frame = FakeFrame(frame_url)


class FakeResponse:
    def __init__(self, request, status=200, headers=None):
        self.request = request
        self.status = status
        self.url = request.url
        self.headers = headers or {}


class FakePage(_Emitter):
    def __init__(self, url, calls, context):
        super().__init__()
        self._url = url
        self._closed = False
        self.calls = calls
        self.context = context
        self.main_frame = FakeFrame(url)

    @property
    def url(self):
        return self._url

    def set_default_navigation_timeout(self, t):
        self.calls.append(("set_timeout", t))

    def goto(self, url, wait_until=None):
        self.calls.append(("goto", url))
        self._url = url
        self.main_frame = FakeFrame(url)

    def is_closed(self):
        return self._closed

    def wait_for_timeout(self, ms):
        self.calls.append(("wait_for_timeout", ms))

    def evaluate(self, *a, **k):
        self.calls.append(("evaluate",))
        return {"frontend": [], "libraries": [], "versions": {}}

    # Calls that would be "fighting the user" — must never be issued by us.
    def reload(self, *a, **k):
        self.calls.append(("reload",))

    def go_back(self, *a, **k):
        self.calls.append(("go_back",))

    def go_forward(self, *a, **k):
        self.calls.append(("go_forward",))

    def bring_to_front(self, *a, **k):
        self.calls.append(("bring_to_front",))

    def close(self):
        self.calls.append(("page_close",))
        self._closed = True
        self.emit("close", self)

    # --- test-only drivers (simulate the user / browser) ---
    def user_navigate(self, url):
        self._url = url
        self.main_frame = FakeFrame(url)
        self.emit("framenavigated", self.main_frame)

    def user_close(self):
        self._closed = True
        self.emit("close", self)


class FakeContext(_Emitter):
    def __init__(self, calls, browser):
        super().__init__()
        self.calls = calls
        self._browser = browser
        self.pages: list[FakePage] = []
        self.storage = {"cookies": [], "origins": []}

    def new_page(self):
        pg = FakePage("about:blank", self.calls, self)
        self.pages.append(pg)
        return pg

    def storage_state(self, path=None):
        self.calls.append(("storage_state",))
        return self.storage

    def close(self):
        self.calls.append(("context_close",))

    # --- test-only drivers ---
    def open_popup(self, url):
        pg = FakePage(url, self.calls, self)
        self.pages.append(pg)
        self.emit("page", pg)
        return pg


class FakeBrowser(_Emitter):
    def __init__(self, calls):
        super().__init__()
        self.calls = calls
        self.context = None

    def new_context(self, **kw):
        self.context = FakeContext(self.calls, self)
        return self.context

    def close(self):
        self.calls.append(("browser_close",))

    def disconnect(self):
        self.emit("disconnected")


class FakeChromium:
    def __init__(self, calls):
        self.calls = calls

    def launch(self, headless=False):
        return FakeBrowser(self.calls)


class FakePlaywright:
    def __init__(self, calls):
        self.chromium = FakeChromium(calls)


class FakeSP:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return FakePlaywright(self.calls)

    def __exit__(self, *a):
        return False


class FakeLog:
    def __init__(self):
        self.events: list[tuple[str, dict]] = []

    def info(self, event, **kw):
        self.events.append((event, kw))

    def debug(self, event, **kw):
        self.events.append((event, kw))

    def warning(self, *a, **k):
        pass


@pytest.fixture
def harness(monkeypatch):
    calls: list = []
    monkeypatch.setattr("playwright.sync_api.sync_playwright", lambda: FakeSP(calls))
    fake_log = FakeLog()
    monkeypatch.setattr(explorer, "log", fake_log)
    return calls, fake_log


def _run(tmp_path, driver, **kw):
    return explorer.explore(
        "admin",
        "https://app/",
        tmp_path / "e.json",
        tmp_path / "e.har",
        on_ready=driver,
        **kw,
    )


# --- invariant 1: no interference -----------------------------------------


def test_no_browser_interference(tmp_path, harness):
    calls, _ = harness

    def driver(page):
        # Simulate Keycloak/SPA: user navigates (redirects) + an API call.
        page.user_navigate("https://app/dashboard")
        req = FakeRequest("GET", "https://app/api/users")
        page.context.emit("request", req)
        page.context.emit("response", FakeResponse(req, 200, {"content-type": "application/json"}))

    data = _run(tmp_path, driver)

    forbidden = {"reload", "go_back", "go_forward", "bring_to_front", "page_close"}
    issued = {c[0] for c in calls}
    assert not (issued & forbidden), f"AppMapper issued user-hostile calls: {issued & forbidden}"
    # Exactly one navigation — the initial goto. Nothing re-navigates the user.
    assert sum(1 for c in calls if c[0] == "goto") == 1
    # No periodic polling: storage_state read once; any page.evaluate (end-of-session
    # tech fingerprint + sessionStorage read) happens only at finalize, after the
    # one goto — never during the session.
    assert sum(1 for c in calls if c[0] == "storage_state") == 1
    ev_idx = [i for i, c in enumerate(calls) if c[0] == "evaluate"]
    goto_idx = calls.index(("goto", "https://app/"))
    assert all(i > goto_idx for i in ev_idx)
    assert any(c["url"] == "https://app/api/users" for c in data["api_calls"])


# --- invariant 2: safe mode = zero JS injection ---------------------------


def test_safe_mode_never_injects_js(tmp_path, harness):
    calls, _ = harness

    def driver(page):
        req = FakeRequest("GET", "https://app/api/x")
        page.context.emit("request", req)

    _run(tmp_path, driver, safe_mode=True)
    assert sum(1 for c in calls if c[0] == "evaluate") == 0


# --- invariant 3: multi-tab popups tracked, never manipulated -------------


def test_popup_tracked_and_captured(tmp_path, harness):
    calls, _ = harness

    def driver(page):
        # OAuth/Keycloak SSO popup opens; its traffic flows on the context.
        popup = page.context.open_popup("https://idp/realms/acme/login")
        preq = FakeRequest("GET", "https://idp/realms/acme/api/whoami")
        page.context.emit("request", preq)
        assert not popup.is_closed()  # we must not have touched it

    data = _run(tmp_path, driver)

    assert any("idp/realms/acme/login" in t["url"] for t in data["tabs"])
    # popup is an auth-flow tab.
    assert any(t["auth_flow"] for t in data["tabs"])
    # popup traffic captured.
    assert any("whoami" in c["url"] for c in data["api_calls"])
    # we never closed a page.
    assert ("page_close",) not in calls


# --- invariant 4: auth-flow tagging (observe, never follow) ---------------


def test_auth_flow_tagging(tmp_path, harness):
    calls, _ = harness

    def driver(page):
        normal = FakeRequest("GET", "https://app/api/devices")
        page.context.emit("request", normal)
        token = FakeRequest("POST", "https://idp/realms/acme/protocol/openid-connect/token")
        page.context.emit("request", token)

    data = _run(tmp_path, driver)

    tagged = {c["url"]: c["auth_flow"] for c in data["api_calls"]}
    assert tagged["https://idp/realms/acme/protocol/openid-connect/token"] is True
    assert tagged["https://app/api/devices"] is False
    assert data["auth_flows"] >= 1


def test_is_auth_flow_helper():
    assert explorer.is_auth_flow("https://idp/realms/x/protocol/openid-connect/auth")
    assert explorer.is_auth_flow("https://login.microsoftonline.com/x/oauth2/v2.0/authorize")
    assert explorer.is_auth_flow("https://app/saml/acs")
    assert not explorer.is_auth_flow("https://app/api/devices")


# --- invariant 5: browser event debugger ----------------------------------


def test_debug_browser_logs_events(tmp_path, harness):
    calls, fake_log = harness

    def driver(page):
        page.user_navigate("https://app/home")
        popup = page.context.open_popup("https://help/")
        popup.user_close()

    _run(tmp_path, driver, debug_browser=True)

    kinds = {kw.get("kind") for ev, kw in fake_log.events if ev == "browser_event"}
    assert "Navigation" in kinds
    assert "Tab Created" in kinds
    assert "Tab Closed" in kinds


def test_no_debug_events_when_disabled(tmp_path, harness):
    calls, fake_log = harness

    def driver(page):
        page.user_navigate("https://app/home")

    _run(tmp_path, driver, debug_browser=False)
    assert not any(ev == "browser_event" for ev, _ in fake_log.events)


# --- abrupt close: state read skipped, capture still written --------------


def test_abrupt_close_skips_state_read_but_saves(tmp_path, harness):
    calls, _ = harness

    def driver(page):
        # Passive cookie capture happens during the session via Set-Cookie.
        req = FakeRequest("GET", "https://app/api/login")
        page.context.emit("request", req)
        page.context.emit(
            "response", FakeResponse(req, 200, {"set-cookie": "KEYCLOAK_SESSION=abc; Path=/"})
        )
        # User closes the whole browser before finishing.
        page.context._browser.disconnect()

    data = _run(tmp_path, driver)

    # Browser was gone at finalize -> no end-of-session reads attempted.
    assert sum(1 for c in calls if c[0] == "storage_state") == 0
    assert sum(1 for c in calls if c[0] == "evaluate") == 0
    # Capture still saved, with the passively-captured session cookie.
    assert (tmp_path / "e.json").exists()
    assert any(a["kind"] == "cookie" and a["name"] == "KEYCLOAK_SESSION" for a in data["artifacts"])
