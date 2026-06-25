"""Tests for JSON + Markdown report generation."""

from __future__ import annotations

import json

from reporting.json_report import build_report, write_json_report
from reporting.markdown_report import render_markdown, write_markdown_report

SAMPLE = {
    "target": {"id": 1, "url": "https://example.com", "domain": "example.com"},
    "subdomains": [{"name": "api.example.com", "resolved": True, "ip_addresses": "1.2.3.4"}],
    "directories": [
        {
            "path": "/admin",
            "url": "x",
            "status_code": 401,
            "content_length": 0,
            "content_type": "text/html",
            "category": "admin",
        }
    ],
    "technologies": [
        {"name": "ASP.NET Core", "category": "backend", "evidence": "header:Kestrel"},
        {"name": "Angular", "category": "frontend", "evidence": "body:ng-version"},
    ],
    "ssl_findings": [],
    "js_findings": [{"kind": "email", "value": "a@b.com", "source": None}],
    "network_services": [
        {"port": 443, "protocol": "tcp", "service": "https", "version": None, "state": "open"}
    ],
    "api_endpoints": [
        {
            "path": "/api/users",
            "method": "GET",
            "source": "openapi",
            "parameters": "page",
            "summary": None,
        }
    ],
    "har_requests": [],
    "burp_requests": [],
}


def test_build_report_structure():
    report = build_report(SAMPLE)
    assert report["technology_stack"]["backend"] == ["ASP.NET Core"]
    assert report["technology_stack"]["frontend"] == ["Angular"]
    assert report["executive_summary"]["subdomains"] == 1
    assert report["executive_summary"]["api_endpoints"] == 1


def test_markdown_contains_sections():
    md = render_markdown(SAMPLE)
    for heading in [
        "# Attack Surface Assessment Report",
        "## Executive Intelligence Summary",
        "## Scan Metrics",
        "## Technology Stack",
        "## Discovered Assets",
        "## APIs",
        "## SSL Findings",
        "## Network Services",
        "## JS / Frontend Findings",
    ]:
        assert heading in md
    assert "ASP.NET Core" in md


def test_write_reports(tmp_path):
    json_path = write_json_report(SAMPLE, tmp_path)
    md_path = write_markdown_report(SAMPLE, tmp_path)
    assert json_path.exists() and md_path.exists()
    loaded = json.loads(json_path.read_text())
    assert loaded["target"]["domain"] == "example.com"
