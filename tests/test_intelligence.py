"""Tests for Tier-2 intelligence: functions, access diff, API analyzer, workflow,
checklist, graph builder."""

from __future__ import annotations

from modules.api.analyzer import analyze_apis
from modules.intelligence.access_diff import analyze_access
from modules.intelligence.checklist_generator import generate_checklist
from modules.intelligence.function_detector import detect_functions
from modules.intelligence.graph_builder import build_graph, export_graphml, write_graph
from modules.intelligence.workflow_mapper import build_workflow, render_tree


def test_function_detector_categories():
    eps = [
        {"path": "/File/FileUpload", "role": "admin"},
        {"path": "/account/export/csv", "role": "user"},
        {"path": "/admin/settings", "role": "admin"},
        {"path": "/auth/password/reset", "role": None},
    ]
    fns = detect_functions(eps)
    pairs = {(f.category, f.subcategory) for f in fns}
    assert ("File Handling", "Upload") in pairs
    assert ("Data Operations", "Export") in pairs
    assert ("Administrative", "Settings") in pairs
    assert ("Authentication", "Password Reset") in pairs


def test_access_diff_includes_anonymous_and_counts():
    data = {
        "role_access": [
            {"role": "admin", "method": "GET", "path": "/admin", "accessible": True},
            {"role": "user", "method": "GET", "path": "/admin", "accessible": False},
        ],
        "crawl_endpoints": [
            {"role": "admin", "method": "GET", "path": "/dashboard", "status_code": 200},
            {"role": "user", "method": "GET", "path": "/dashboard", "status_code": 200},
            {"role": "anonymous", "method": "GET", "path": "/login", "status_code": 200},
            {"role": "user", "method": "GET", "path": "/profile", "status_code": 200},
        ],
    }
    analysis = analyze_access(data)
    assert "anonymous" in analysis["roles"]
    assert analysis["counts"]["admin"] >= 2
    assert "GET /admin" in analysis["exclusive"]["admin"]
    assert "GET /profile" in analysis["exclusive"]["user"]
    assert "GET /dashboard" in analysis["shared"]


def test_api_analyzer_flags_authz_sensitive():
    data = {
        "api_endpoints": [
            {"path": "/api/users/123", "method": "GET", "parameters": []},
            {"path": "/api/users/456", "method": "PUT", "parameters": ["user_id"]},
            {"path": "/api/health", "method": "GET", "parameters": []},
        ],
        "crawl_endpoints": [],
        "har_requests": [],
        "burp_requests": [],
    }
    intel = {a.path: a for a in analyze_apis(data)}
    assert "/api/users/{id}" in intel
    users = intel["/api/users/{id}"]
    assert set(users.methods) == {"GET", "PUT"}
    assert users.authz_sensitive is True
    assert intel["/api/health"].authz_sensitive is False


def test_api_analyzer_records_host_from_full_url():
    data = {
        "api_endpoints": [],
        "crawl_endpoints": [
            {"url": "https://gw.example.com/api/orders", "path": "/api/orders", "source": "api"}
        ],
        "har_requests": [
            {"url": "https://cognito-identity.us-east-1.amazonaws.com/api/orders", "method": "POST"}
        ],
        "burp_requests": [],
    }
    orders = {a.path: a for a in analyze_apis(data)}["/api/orders"]
    # host captured from both the crawl URL and the HAR request URL
    assert orders.hosts == [
        "cognito-identity.us-east-1.amazonaws.com",
        "gw.example.com",
    ]
    # renderer builds a full URL for a single-host endpoint
    from reporting.markdown_report import _endpoint_url

    assert _endpoint_url({"path": "/x", "hosts": "gw.example.com"}) == "https://gw.example.com/x"
    assert _endpoint_url({"path": "/x", "hosts": "a.com,b.com"}) == "/x (2 hosts: a.com, b.com)"
    assert _endpoint_url({"path": "/spec-only", "hosts": ""}) == "/spec-only"


def test_workflow_and_tree():
    data = {
        "crawl_endpoints": [
            {"role": "admin", "path": "/"},
            {"role": "admin", "path": "/admin"},
            {"role": "admin", "path": "/admin/users"},
        ],
        "har_requests": [],
        "burp_requests": [],
    }
    edges = build_workflow(data)
    pairs = {(e.from_path, e.to_path) for e in edges}
    assert ("/admin", "/admin/users") in pairs
    tree = render_tree(edges)
    assert "/admin/users" in tree


def test_checklist_from_functions():
    fns = detect_functions([{"path": "/files/upload", "role": "admin"}])
    items = generate_checklist(fns)
    texts = {i.item for i in items}
    assert any("MIME" in t for t in texts)


def test_graph_export(tmp_path):
    data = {
        "users": [{"role": "admin"}],
        "crawl_endpoints": [
            {"role": "admin", "path": "/admin", "status_code": 200, "source": "crawl"}
        ],
        "api_intel": [{"path": "/api/x"}],
        "forms": [],
        "workflow_edges": [{"from_path": "/", "to_path": "/admin", "kind": "link"}],
    }
    nodes, edges = build_graph(data)
    assert any(n.kind == "role" for n in nodes)
    assert any(n.kind == "page" for n in nodes)
    gml = export_graphml(nodes, edges)
    assert gml.startswith("<?xml") and "<graphml" in gml
    paths = write_graph(data, tmp_path)
    assert paths["json"].exists() and paths["graphml"].exists() and paths["drawio"].exists()
