"""Tests for Option A: browser-runtime fingerprint merge + graceful degradation."""

from __future__ import annotations

from models.schemas import TargetInput, TechStack
from modules.fingerprint import runtime_fingerprint


def test_merge_technologies_augments_without_replacing(memory_db):
    db = memory_db
    tid = db.upsert_target(TargetInput(url="https://app.local", domain="app.local"))
    # Static fingerprint already found React + lit.
    db.save_techstack(tid, TechStack(frontend=["React"], libraries=["lit"]))

    # Runtime fingerprint adds core-js + Tailwind, and re-reports React (dup ignored).
    db.merge_technologies(
        tid,
        [
            ("React", "frontend", "runtime:18.2"),
            ("core-js", "library", "runtime:3.26"),
            ("Tailwind CSS", "library", "runtime:--tw-"),
        ],
    )

    data = db.fetch_all(tid)
    names = {t["name"] for t in data["technologies"]}
    assert {"React", "lit", "core-js", "Tailwind CSS"} <= names
    # React not duplicated.
    assert sum(1 for t in data["technologies"] if t["name"] == "React") == 1


def test_runtime_fingerprint_graceful_without_playwright(monkeypatch):
    import builtins

    from modules.auth.playwright_auth import PlaywrightNotInstalled

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("playwright"):
            raise ImportError("no playwright")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    try:
        runtime_fingerprint.fingerprint_runtime("http://app.local")
        raise AssertionError("expected PlaywrightNotInstalled")
    except PlaywrightNotInstalled as exc:
        assert "pip install playwright" in str(exc)
