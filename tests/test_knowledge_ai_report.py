"""Tests for knowledge base (FTS), AI summary (template), and Tier-2 reporting."""

from __future__ import annotations

import json

from models.schemas import TargetInput
from modules.ai.app_summary import TemplateProvider, build_facts, generate_summary
from modules.knowledge.index import build_documents
from modules.knowledge.query import to_fts_query
from reporting import write_reports

SAMPLE = {
    "target": {"id": 1, "url": "http://app.local", "domain": "app.local"},
    "technologies": [
        {"name": "ASP.NET Core", "category": "backend", "evidence": None},
        {"name": "Bootstrap", "category": "library", "evidence": None},
    ],
    "users": [{"role": "admin"}, {"role": "user"}],
    "crawl_endpoints": [
        {
            "role": "admin",
            "url": "http://app.local/admin",
            "path": "/admin",
            "method": "GET",
            "status_code": 200,
            "content_type": "text/html",
            "source": "crawl",
            "title": "Admin",
        },
        {
            "role": "user",
            "url": "http://app.local/files/upload",
            "path": "/files/upload",
            "method": "GET",
            "status_code": 200,
            "content_type": "text/html",
            "source": "crawl",
            "title": None,
        },
    ],
    "sensitive_functions": [
        {
            "category": "File Handling",
            "subcategory": "Upload",
            "endpoint": "/files/upload",
            "role": "user",
        },
        {
            "category": "Administrative",
            "subcategory": "Admin",
            "endpoint": "/admin",
            "role": "admin",
        },
    ],
    "api_intel": [{"path": "/api/users/{id}", "methods": "GET,PUT", "authz_sensitive": True}],
}


def test_template_summary_sections():
    facts = build_facts(SAMPLE)
    assert "admin" in facts["roles"] and "anonymous" in facts["roles"]
    text = TemplateProvider().generate(facts)
    for header in [
        "Application Summary",
        "Technology:",
        "Roles:",
        "Major Functional Areas:",
        "High-Risk Areas For Manual Review:",
    ]:
        assert header in text
    assert "ASP.NET Core" in text


def test_summary_falls_back_to_template_on_bad_provider():
    # openai_compatible with no reachable base_url -> falls back to template.
    result = generate_summary(SAMPLE, provider="openai_compatible", base_url="http://127.0.0.1:1")
    assert result.provider == "template"
    assert "Application Summary" in result.text


def test_knowledge_index_and_query(memory_db):
    db = memory_db
    tid = db.upsert_target(TargetInput(url="http://app.local", domain="app.local"))
    db.index_knowledge(tid, build_documents(SAMPLE))
    hits = db.search_knowledge(tid, to_fts_query("Show all upload endpoints"))
    assert any("upload" in h["path"] for h in hits)
    admin_hits = db.search_knowledge(tid, to_fts_query("admin functions"))
    assert any("/admin" in h["path"] for h in admin_hits)


def test_write_reports_emits_all_formats(tmp_path):
    paths = write_reports(SAMPLE, tmp_path)
    for key in ["md", "html", "json", "graph_json", "graph_graphml", "graph_drawio"]:
        assert paths[key].exists()
    report = json.loads(paths["json"].read_text())
    assert "role_comparison" in report
    assert "application_summary" in report
    assert report["application_summary"]["text"]
    # HTML contains the summary heading and a table
    html = paths["html"].read_text()
    assert "<h2>" in html and "<table>" in html
    # report.md has Tier-2 sections
    md = paths["md"].read_text()
    assert "Sensitive Functions" in md and "Pentest Checklist" in md
