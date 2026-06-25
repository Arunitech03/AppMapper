"""Tests for Sprint B — advanced browser intelligence capture & analysis.

Covers ingestion of a browser_intelligence block into intel_findings, the browser
secret engine (masked), sensitive IndexedDB schemas, hidden functionality (cached
APIs / unvisited routes / disabled flags), correlation, the architecture map, the
explorer browser-path capture (fake page), and safe-mode skipping JS injection.
"""

from __future__ import annotations

import json

import pytest

from modules.auth import explorer
from modules.auth.exploration_import import browser_intel_to_findings, parse
from modules.intelligence.browser_intelligence import build_browser_intelligence
from modules.intelligence.browser_secret_discovery import discover_browser_secrets


def _browser_block():
    return {
        "role": "admin",
        "cookies": [
            {
                "name": "KEYCLOAK_SESSION",
                "secure": True,
                "httpOnly": True,
                "sameSite": "Lax",
                "value_masked": "***",
                "session_cookie": True,
            }
        ],
        "local_storage": {
            "role": "admin",
            "tenant": "123",
            "apiBaseUrl": "https://gateway.company.com",
            "googleKey": "AIzaSyA1234567890abcdefghijklmnopqrstuv",
        },
        "session_storage": {"pkce": "v" * 44},
        "indexeddb": [
            {
                "database": "user-store",
                "stores": [
                    {
                        "name": "profiles",
                        "count": 12,
                        "fields": ["email", "role", "account", "address"],
                    }
                ],
            }
        ],
        "cache_storage": [
            {
                "cache": "runtime",
                "entries": [
                    "https://app.example.com/api/admin/users",
                    "https://app.example.com/assets/x.png",
                ],
            }
        ],
        "service_workers": [{"scriptURL": "https://app.example.com/sw.js", "scope": "/"}],
        "runtime_config": {
            "__CONFIG__": {
                "authUrl": "https://auth.company.com",
                "enableBilling": True,
                "enableDebug": False,
            }
        },
        "feature_flags": [
            {"feature": "enableBilling", "enabled": True},
            {"feature": "enableDebug", "enabled": False},
        ],
        "framework_state": {"redux": ["auth", "user", "billing"]},
        "forms": [
            {"action": "/api/user", "method": "POST", "fields": ["username", "role", "email"]}
        ],
        "routes": ["/admin", "/billing-access", "/dashboard"],
        "manifest": {"href": "https://app.example.com/manifest.webmanifest"},
        "csp": [
            {
                "url": "https://app.example.com/",
                "directives": {"connect-src": ["https://api.company.com"]},
            }
        ],
        "cors": [{"host": "api.company.com", "allow_origin": "*", "allow_credentials": "true"}],
        "websockets": [
            {
                "url": "wss://app.example.com/ws",
                "messageTypes": ["alarmUpdate"],
                "fields": ["deviceId", "status"],
            }
        ],
    }


def _data_from_block(block):
    bundle = parse(
        "admin",
        {
            "role": "admin",
            "browser_intelligence": block,
            "navigations": [{"url": "https://app.example.com/dashboard"}],
        },
    )
    data = {
        "target": {"domain": "app.example.com"},
        "intel_findings": [f.model_dump() for f in bundle["intel_findings"]],
        "crawl_endpoints": [{"path": "/dashboard", "source": "explore"}],
    }
    data["intel_findings"] += [f.model_dump() for f in discover_browser_secrets("admin", block)]
    return data


# --- ingestion ------------------------------------------------------------


def test_ingest_browser_block_to_findings():
    findings = browser_intel_to_findings("admin", _browser_block())
    kinds = {f.kind for f in findings}
    assert {
        "feature_flag",
        "route",
        "form",
        "websocket",
        "indexeddb",
        "cache_entry",
        "service_worker",
        "csp",
        "cors",
        "manifest",
        "runtime_config",
        "framework_state",
        "cookie_attr",
    } <= kinds


# --- F16 browser secrets (masked) -----------------------------------------


def test_browser_secret_masked():
    secs = discover_browser_secrets("admin", _browser_block())
    names = {s.name for s in secs}
    assert "Google API Key" in names
    g = next(s for s in secs if s.name == "Google API Key")
    assert "AIzaSyA1234567890abcdefghijklmnopqrstuv" not in (g.value_masked or "")
    assert g.extra.get("scope") == "browser"


# --- F17 sensitive IndexedDB schema ---------------------------------------


def test_indexeddb_sensitive_model():
    bi = build_browser_intelligence(_data_from_block(_browser_block()))
    models = {m["endpoint"]: m for m in bi["sensitive_models"]}
    idb = next((m for k, m in models.items() if k.startswith("IndexedDB:")), None)
    assert idb is not None
    assert "account" in idb["sensitive_fields"] and "address" in idb["sensitive_fields"]


# --- F19 hidden functionality ---------------------------------------------


def test_hidden_functionality():
    bi = build_browser_intelligence(_data_from_block(_browser_block()))
    items = {(h["type"], h["item"]) for h in bi["hidden_functionality"]}
    assert ("Hidden API", "/api/admin/users") in items  # cached but not observed
    assert ("Hidden Route", "/admin") in items  # route never visited
    assert ("Disabled Feature", "enableDebug") in items
    # /dashboard WAS visited -> not hidden
    assert ("Hidden Route", "/dashboard") not in items


# --- F18 correlation + architecture map -----------------------------------


def test_correlation_and_architecture():
    bi = build_browser_intelligence(_data_from_block(_browser_block()))
    arch = bi["architecture_map"]
    assert "api.company.com" in arch["trusted_domains"]
    assert "https://auth.company.com" in arch["config_urls"]
    assert bi["summary"]["browser_secrets"] >= 1
    assert bi["summary"]["disabled_flags"] == 1


def test_no_full_secret_leak_in_browser_report():
    bi = build_browser_intelligence(_data_from_block(_browser_block()))
    blob = json.dumps(bi)
    assert "AIzaSyA1234567890abcdefghijklmnopqrstuv" not in blob
    assert "v" * 44 not in blob  # pkce masked


# --- explorer browser-path capture (fake page) ----------------------------


class _FakeCtx:
    def __init__(self):
        self._cookies = [
            {
                "name": "SID",
                "value": "secretvalue",
                "domain": "x",
                "path": "/",
                "secure": True,
                "httpOnly": True,
                "sameSite": "Lax",
            }
        ]

    def cookies(self):
        return self._cookies


def test_build_browser_intel_masks_cookie_value():
    intel = explorer._build_browser_intel(
        "admin",
        {"localStorage": {"jwt": "a.b.c" + "x" * 60}},
        [
            {
                "name": "SID",
                "secure": True,
                "httpOnly": True,
                "value_masked": explorer.mask_secret("secretvalue"),
            }
        ],
        {},
        {},
        {},
    )
    assert "secretvalue" not in json.dumps(intel)
    assert intel["local_storage"]["jwt"] != "a.b.c" + "x" * 60  # masked


def test_ingest_from_browser_folder_and_consolidated_json(tmp_path):
    """A tester can feed just the <role>_browser/ folder or browser_intelligence.json."""
    from modules.auth.explorer import _write_browser_intel_files

    out_json = tmp_path / "admin.json"
    _write_browser_intel_files(out_json, _browser_block())
    folder = tmp_path / "admin_browser"

    # whole folder
    from_folder = parse("admin", folder)
    assert from_folder["browser_intelligence"]
    assert len(from_folder["intel_findings"]) >= 13

    # consolidated json alone
    from_json = parse("admin", folder / "browser_intelligence.json")
    assert len(from_json["intel_findings"]) == len(from_folder["intel_findings"])

    # an individual-file folder without the consolidated file still reconstructs
    (folder / "browser_intelligence.json").unlink()
    rebuilt = parse("admin", folder)
    assert rebuilt["browser_intelligence"].get("feature_flags")


def test_ws_schema_keys_only():
    rec = {"messageTypes": set(), "fields": set()}
    explorer._ws_schema_from_frame(
        rec, json.dumps({"type": "alarmUpdate", "deviceId": 5, "status": "ok"})
    )
    assert rec["messageTypes"] == {"alarmUpdate"}
    assert rec["fields"] == {"type", "deviceId", "status"}
    # values never captured
    assert 5 not in rec["fields"] and "ok" not in rec["fields"]


def test_safe_mode_skips_js(monkeypatch, tmp_path):
    """In safe-mode the explorer must not call browser_intel.js (zero JS injection)."""
    evaluated = []

    class FakeFrame:
        def __init__(self, url):
            self.url = url

    class FakeEmitter:
        def __init__(self):
            self._h = {}

        def on(self, ev, fn):
            self._h.setdefault(ev, []).append(fn)

    class FakePage(FakeEmitter):
        def __init__(self, ctx):
            super().__init__()
            self._url = "about:blank"
            self.context = ctx
            self.main_frame = FakeFrame("about:blank")

        @property
        def url(self):
            return self._url

        def set_default_navigation_timeout(self, t):
            pass

        def goto(self, url, wait_until=None):
            self._url = url

        def is_closed(self):
            return False

        def wait_for_timeout(self, ms):
            pass

        def evaluate(self, *a, **k):
            evaluated.append(a[0] if a else "")
            return {}

    class FakeContext(FakeEmitter):
        def __init__(self):
            super().__init__()
            self.pages = []

        def new_page(self):
            p = FakePage(self)
            self.pages.append(p)
            return p

        def cookies(self):
            return []

        def storage_state(self, **k):
            return {"cookies": [], "origins": []}

        def close(self):
            pass

    class FakeBrowser(FakeEmitter):
        def new_context(self, **k):
            return FakeContext()

        def close(self):
            pass

    class FakeChromium:
        def launch(self, headless=False):
            return FakeBrowser()

    class FakePW:
        def __init__(self):
            self.chromium = FakeChromium()

    class FakeSP:
        def __enter__(self):
            return FakePW()

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("playwright.sync_api.sync_playwright", lambda: FakeSP())
    explorer.explore(
        "admin",
        "https://app/",
        tmp_path / "e.json",
        tmp_path / "e.har",
        safe_mode=True,
        on_ready=lambda page: None,
    )
    # safe-mode: the big browser_intel.js must never be evaluated.
    assert not any("indexeddb" in str(e).lower() for e in evaluated)


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
