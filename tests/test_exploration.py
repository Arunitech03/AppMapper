"""Tests for Exploration Capture Mode: classification, ingestion, and that the
captured data flows into the existing intelligence model."""

from __future__ import annotations

import json

from models.schemas import TargetInput
from modules.auth import exploration_import
from modules.auth.explorer import classify_request, endpoint_inventory

SAMPLE = {
    "role": "qa",
    "target_url": "https://app.local",
    "navigations": [
        {"url": "https://app.local/dashboard", "title": "Dashboard"},
        {"url": "https://app.local/admin/users", "title": "Users"},
    ],
    "api_calls": [
        {
            "method": "GET",
            "url": "https://app.local/api/users/42",
            "status": 200,
            "response_content_type": "application/json",
        },
        {
            "method": "POST",
            "url": "https://app.local/api/orders",
            "status": 201,
            "response_content_type": "application/json",
        },
    ],
    "forms": [
        {
            "page_url": "https://app.local/login",
            "action": "https://app.local/login",
            "method": "POST",
            "fields": ["username", "password"],
        }
    ],
    "uploads": [
        {"page_url": "https://app.local/docs", "url": "https://app.local/documents/upload"}
    ],
    "downloads": [{"url": "https://app.local/reports/export.csv", "filename": "export.csv"}],
    "websockets": [{"url": "wss://app.local/ws/notifications"}],
    "artifacts": [
        {
            "role": "qa",
            "kind": "cookie",
            "name": "SESSION",
            "value_masked": "abcd…wxyz (40 chars)",
            "source": "exploration",
        }
    ],
    "technologies": {
        "frontend": ["React"],
        "libraries": ["core-js", "Tailwind CSS"],
        "versions": {"core-js": "3.26.0"},
    },
    "endpoint_inventory": ["GET /api/users/42", "POST /api/orders"],
}


def test_exploration_technologies_merge(memory_db):
    """Runtime tech detected during exploration merges into the technology stack."""
    from models.schemas import TechStack

    bundle = exploration_import.parse("qa", SAMPLE)
    names = {t[0] for t in bundle["technologies"]}
    assert {"React", "core-js", "Tailwind CSS"} <= names

    db = memory_db
    tid = db.upsert_target(TargetInput(url="https://app.local", domain="app.local"))
    db.save_techstack(tid, TechStack(frontend=["React"], libraries=["lit"]))  # static result
    db.merge_technologies(tid, bundle["technologies"])
    stack = {t["name"] for t in db.fetch_all(tid)["technologies"]}
    assert {"React", "lit", "core-js", "Tailwind CSS"} <= stack


def test_classify_request():
    assert classify_request("GET", "https://a/x", "xhr", "application/json") == "api"
    assert classify_request("POST", "https://a/u", "fetch", "multipart/form-data") == "upload"
    assert (
        classify_request("POST", "https://a/login", "document", "application/x-www-form-urlencoded")
        == "form"
    )
    assert classify_request("GET", "https://a/page", "document", "text/html") == "navigation"
    assert classify_request("GET", "https://a/api/v1/me", "xhr", None) == "api"


def test_endpoint_inventory():
    inv = endpoint_inventory(SAMPLE["api_calls"], SAMPLE["navigations"])
    assert "GET /api/users/42" in inv
    assert "GET /dashboard" in inv


def test_parse_into_dtos():
    bundle = exploration_import.parse("qa", SAMPLE)
    sources = {c.source for c in bundle["crawl_endpoints"]}
    assert {"explore", "api", "upload", "download", "websocket"} <= sources
    # All activity tagged with the configured role
    assert all(c.role == "qa" for c in bundle["crawl_endpoints"])
    # API calls become HAR requests (so the API analyzer/workflow consume them)
    assert any("/api/orders" in h.url for h in bundle["har_requests"])
    # Forms + masked artifacts carried through
    assert bundle["forms"][0].action.endswith("/login")
    assert bundle["artifacts"][0].value_masked.endswith("(40 chars)")


def test_exploration_feeds_pipeline(memory_db, tmp_path):
    """End-to-end (offline): ingest exploration -> tables -> intelligence sees it."""
    from modules.api.analyzer import analyze_apis
    from modules.intelligence.access_diff import analyze_access
    from modules.intelligence.function_detector import detect_functions

    f = tmp_path / "qa.json"
    f.write_text(json.dumps(SAMPLE))
    bundle = exploration_import.parse("qa", f)

    db = memory_db
    tid = db.upsert_target(TargetInput(url="https://app.local", domain="app.local"))
    db.save_crawl_endpoints(tid, bundle["crawl_endpoints"])
    db.save_forms(tid, bundle["forms"])
    db.save_har_requests(tid, bundle["har_requests"])
    data = db.fetch_all(tid)

    # Role comparison sees the explored endpoints for role qa.
    access = analyze_access(data)
    assert "qa" in access["roles"] and access["counts"]["qa"] > 0

    # API analyzer flags the id-bearing endpoint as authz-sensitive.
    intel = {a.path: a for a in analyze_apis(data)}
    assert any("{id}" in p or "/api/orders" in p for p in intel)

    # Function detector flags upload + download + admin/users from explored paths.
    fns = {
        (f.category, f.subcategory)
        for f in detect_functions(
            [{"path": e["path"], "role": e["role"]} for e in data["crawl_endpoints"]]
        )
    }
    assert ("File Handling", "Upload") in fns
    # The explored download (/reports/export.csv) lands under Data Operations.
    assert any(cat == "Data Operations" for cat, _ in fns)


def test_explorer_graceful_without_playwright(monkeypatch, tmp_path):
    import builtins

    from modules.auth import explorer
    from modules.auth.playwright_auth import PlaywrightNotInstalled

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("playwright"):
            raise ImportError("no playwright")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    try:
        explorer.explore("qa", "http://app", tmp_path / "e.json", tmp_path / "e.har")
        raise AssertionError("expected PlaywrightNotInstalled")
    except PlaywrightNotInstalled as exc:
        assert "pip install playwright" in str(exc)
