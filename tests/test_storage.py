"""Tests for the SQLAlchemy storage layer (save + fetch roundtrip)."""

from __future__ import annotations

from models.schemas import (
    ApiEndpoint,
    DirectoryHit,
    JSFinding,
    Subdomain,
    TargetInput,
    TechStack,
)


def test_roundtrip(memory_db):
    db = memory_db
    target = TargetInput(url="https://example.com", domain="example.com")
    tid = db.upsert_target(target)
    assert tid == db.get_target_id("example.com")

    db.save_subdomains(
        tid, [Subdomain(name="api.example.com", resolved=True, ip_addresses=["1.2.3.4"])]
    )
    db.save_directories(
        tid,
        [
            DirectoryHit(
                path="/admin", url="https://example.com/admin", status_code=401, category="admin"
            )
        ],
    )
    db.save_techstack(tid, TechStack(frontend=["Angular"], backend=["ASP.NET Core"]))
    db.save_js_findings(tid, JSFinding(emails=["a@b.com"], aws_keys=["AKIA..."]))
    db.save_api_endpoints(tid, [ApiEndpoint(path="/api/users", method="GET", parameters=["page"])])

    data = db.fetch_all(tid)
    assert data["target"]["domain"] == "example.com"
    assert data["subdomains"][0]["name"] == "api.example.com"
    assert data["directories"][0]["status_code"] == 401
    assert {t["name"] for t in data["technologies"]} == {"Angular", "ASP.NET Core"}
    assert {f["kind"] for f in data["js_findings"]} == {"email", "aws_key"}
    assert data["api_endpoints"][0]["path"] == "/api/users"


def test_save_is_idempotent(memory_db):
    db = memory_db
    tid = db.upsert_target(TargetInput(url="https://example.com", domain="example.com"))
    subs = [Subdomain(name="a.example.com")]
    db.save_subdomains(tid, subs)
    db.save_subdomains(tid, subs)  # re-run replaces, not duplicates
    assert len(db.fetch_all(tid)["subdomains"]) == 1
