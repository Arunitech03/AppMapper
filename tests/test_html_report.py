"""Tests for the redesigned HTML report (dashboard, collapse, nav, severity)."""

from __future__ import annotations

import base64
import json

from modules.intelligence.jwt_intelligence import analyze_jwt
from reporting.html_report import _split_sections, render_html
from tests.test_jwt_intelligence import PAYLOAD


def _b64(o) -> str:
    return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")


def _token() -> str:
    return f"{_b64({'alg': 'RS256', 'typ': 'JWT'})}.{_b64(PAYLOAD)}.SIG"


def _data():
    """A data dict exercising the JWT/auth + a couple of evidence sections."""
    return {
        "target": {"url": "https://app.example.com", "domain": "app.example.com"},
        # jwt_authorization is what database.fetch_all populates from captured tokens.
        "jwt_authorization": [dict(analyze_jwt(_token(), role="test1"), origin="session")],
        "auth_artifacts": [
            {"kind": "cookie", "name": "KEYCLOAK_SESSION", "source": "exploration"},
            {"kind": "authorization", "name": "Authorization", "source": "exploration"},
            {"kind": "local_storage", "name": "token", "source": "exploration"},
        ],
        "har_requests": [{"headers": {"Authorization": f"Bearer {_token()}"}, "role": "test1"}],
    }


def test_renders_without_error_on_empty_data():
    html = render_html({"target": {"url": "https://x.io", "domain": "x.io"}})
    assert "<html" in html and "Executive Intelligence Dashboard" in html


def test_dashboard_and_layout_present():
    html = render_html(_data())
    assert 'class="kpis"' in html and "Executive Intelligence Dashboard" in html
    assert 'class="kpi' in html
    # light theme + sticky sidebar nav + toolbar controls
    assert "data-theme='light'" in html
    assert 'nav class="side"' in html
    assert "Expand All Evidence" in html and "Collapse All Evidence" in html
    assert "--crit:" in html  # CSS severity palette embedded


def test_critical_findings_with_severity_classes():
    html = render_html(_data())
    assert "Critical Findings" in html
    # admin roles in the example token -> a High finding with the sev-high class.
    assert "sev-high" in html


def test_insight_expanded_evidence_collapsed():
    html = render_html(_data())
    # Insight section rendered as a plain <section>, not inside a collapsible <details>.
    assert '<section id="s-authentication-intelligence">' in html
    # Evidence divider present; evidence sections are collapsed <details class="ev">.
    assert 'id="s-evidence"' in html
    assert '<details class="ev"' in html


def test_split_sections():
    md = "# Title\n- lead\n\n## One\nbody1\n\n## Two (3)\nbody2"
    preamble, sections = _split_sections(md)
    assert "# Title" in preamble
    assert [t for t, _ in sections] == ["One", "Two (3)"]


def test_no_secret_or_pii_leak_in_html():
    html = render_html(_data())
    assert _token() not in html  # raw bearer token never rendered
    assert "Mercer" not in html  # surname masked (first name is kept by design)
    assert "user@example.com" not in html  # email masked by default


def test_v2_sections_present_and_ordered():
    html = render_html(_data())
    for sec in (
        "JWT Intelligence Deep Dive",
        "Authentication Artifacts Summary",
        "Role Intelligence",
    ):
        assert sec in html
    # Deep Dive appears before Application Access (insight ordering).
    assert html.index("JWT Intelligence Deep Dive") < html.index("Application Access Summary")
    # Auth dashboard cards prepended to the Authentication Intelligence section.
    auth_idx = html.index('id="s-authentication-intelligence"')
    assert html.index('class="authcards"', auth_idx) - auth_idx < 4000


def test_jwt_claims_collapsed_in_evidence():
    html = render_html(_data())
    # JWT Claims is rendered as a collapsed evidence <details>, not an expanded section.
    assert '<section id="s-jwt-claims">' not in html
    assert '<details class="ev" id="s-jwt-claims">' in html


def test_design_system_tokens_and_controls():
    html = render_html(_data())
    # design tokens
    assert "--fg:#0F172A" in html and "--auth:#9333EA" in html and "--radius:12px" in html
    # severity emoji + classes
    assert "🔴" in html or "🟠" in html
    assert "sev-high" in html
    # per-metric KPI color classes
    assert 'class="kpi blue"' in html and 'class="kpi red"' in html
    # tables: sticky header markup + zebra container
    assert "<thead>" in html and 'class="tablewrap"' in html
    # sidebar groups + scroll-spy + print CSS
    assert ">Overview<" in html and ">Intelligence<" in html and ">Evidence<" in html
    assert "IntersectionObserver" in html
    assert "table-header-group" in html and "print-color-adjust" in html
    # dark mode vars
    assert "[data-theme=dark]" in html


def test_architecture_snapshot_coloured_outline_boxes():
    html = render_html(_data())
    assert 'class="flow"' in html
    # each node is a coloured outline box (accent border via per-node class)
    assert '<span class="node n-blue">Browser</span>' in html
    assert 'class="node n-purple"' in html  # identity provider node
    assert ".flow .node{border:2px solid" in html  # outline-box CSS


def test_pentest_matrix_placement_and_badges():
    html = render_html(_data())
    assert "Pentest Prioritization Matrix" in html and "Pentester Quick Start" in html
    # placed after the dashboard and before Critical Findings
    assert (
        html.index("s-dashboard")
        < html.index("s-pentest-matrix")
        < html.index("s-critical-findings")
    )
    # priority badges + section link
    assert 'class="pbadge p1"' in html and "🔴 P1" in html
    assert 'href="#s-authentication-risk-analysis"' in html  # JWT Storage -> Auth Risk section


def test_token_inventory_section():
    html = render_html(_data())
    assert "Authentication Token Inventory" in html
    # placed before the JWT Intelligence Deep Dive section
    assert html.index("s-authentication-token-inventory") < html.index(
        "s-jwt-intelligence-deep-dive"
    )
    # inventory table risk badges (medium severity at least) + access token row
    assert "Access Token" in html and "sev-medium" in html


def test_dns_intelligence_section():
    # HAR requests with real hosts so the DNS host inventory populates.
    data = dict(
        _data(),
        har_requests=[
            {"url": "https://app.example.com/api/x", "method": "GET", "role": "test1"},
            {"url": "https://gateway-proxy.example.com/svc", "method": "GET", "role": "test1"},
        ],
    )
    html = render_html(data)
    assert "DNS Intelligence" in html and "Host Inventory" in html
    # placed before Redirect Intelligence / Internal Service Inventory (infra area)
    pos = html.index("s-dns-intelligence")
    for later in ("s-internal-service-inventory", "s-redirect-intelligence"):
        if later in html:
            assert pos < html.index(later)


def test_network_services_promoted_to_insight_and_kpi():
    data = dict(
        _data(),
        network_services=[
            {
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "version": "nginx",
                "state": "open",
            },
            {"port": 53, "protocol": "tcp", "service": "domain", "version": "", "state": "open"},
        ],
    )
    html = render_html(data)
    # Rendered as an expanded top-level insight <section>, not buried in evidence <details>.
    assert '<section id="s-network-services">' in html
    assert '<details class="ev" id="s-network-services">' not in html
    # The nmap port/service data is visible.
    assert "443" in html and "https" in html
    # Open Ports KPI card on the dashboard reflects the count.
    assert "Open Ports" in html


def test_passive_subdomain_intelligence_section():
    data = dict(
        _data(),
        subdomains=[
            {"name": "api.example.com", "resolved": True, "source": "AlienVault OTX, crt.sh"},
            {"name": "dev.example.com", "resolved": False, "source": "RapidDNS"},
        ],
    )
    html = render_html(data)
    # Expanded top-level insight section, not buried in evidence.
    assert '<section id="s-passive-subdomain-intelligence">' in html
    assert '<details class="ev" id="s-passive-subdomain-intelligence">' not in html
    # Placed before DNS Intelligence (infra ordering).
    pos = html.index("s-passive-subdomain-intelligence")
    if "s-dns-intelligence" in html:
        assert pos < html.index("s-dns-intelligence")
    # Summary cards prepended + source attribution visible in the table.
    assert html.index('class="authcards"', pos) - pos < 2500
    assert "AlienVault OTX" in html and "RapidDNS" in html


def test_access_matrix_promoted_to_insight():
    # The HAR-derived Access Matrix + role-visibility sections render expanded
    # (top-level insights), not collapsed in the Evidence accordion.
    from reporting.html_report import _insight_rank

    for title in (
        "Access Matrix — Role Visibility",
        "Application Visibility (8)",
        "API Visibility (28)",
        "Role Exclusive Applications",
        "Role Exclusive APIs",
        "Shared Applications (2)",
        "Shared APIs (8)",
    ):
        assert _insight_rank(title) is not None, title


def test_critical_findings_are_alert_panels():
    html = render_html(_data())
    assert '<div class="panel sev-high">' in html  # admin-roles finding -> High panel
    assert "Why it matters" in html


def test_identity_card_and_auth_flow_and_role_collapse():
    html = render_html(_data())
    assert 'class="idcard"' in html  # User Intelligence as identity card
    # Authentication Flow renders as the monospace text tree (not a box diagram).
    assert "Authentication Flow" in html and "├──" in html
    assert 'class="flowdiag"' not in html
    assert 'class="authcards"' in html  # auth dashboard cards
    # Role Intelligence: per-application collapsible
    assert '<details class="role">' in html


def test_jwt_embedded_in_js_findings_is_masked():
    # A full JWT embedded in a JS file must never render raw in any report format.
    from reporting.json_report import build_report

    data = dict(
        _data(), js_findings=[{"kind": "jwt", "value": f"token={_token()}", "source": "app.js"}]
    )
    report = build_report(data)
    rendered = json.dumps(report["js_findings"])
    assert _token() not in rendered
    assert "chars)" in rendered  # mask_secret leaves a "…xxxx (N chars)" marker
