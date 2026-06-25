"""Tests for the redesigned, HAR-derived role visibility (Access Matrix).

Validates the four states, static-asset + third-party filtering, the
Application/API split, and the role-exclusive / shared breakdowns — including the
regression that admin-only applications are non-empty when the admin capture
contains areas the user capture never touched.
"""

from __future__ import annotations

from modules.intelligence.role_visibility import (
    DENIED,
    NOT_OBSERVED,
    OBSERVED,
    REDIRECTED,
    build_role_visibility,
)

BASE = "https://app.example.com"


def _req(role, path, status, ctype=None, method="GET", host="app.example.com"):
    return {
        "url": f"https://{host}{path}",
        "method": method,
        "role": role,
        "response_status": status,
        "response_content_type": ctype,
    }


def _data(reqs):
    return {
        "target": {"url": BASE + "/", "domain": "app.example.com"},
        "har_requests": reqs,
        "burp_requests": [],
    }


def _states(vis, kind, label):
    key = "name" if kind == "applications" else "endpoint"
    for row in vis[kind]:
        if row[key] == label:
            return row["states"]
    raise AssertionError(f"{label} not found in {kind}")


def test_four_states():
    vis = build_role_visibility(
        _data(
            [
                _req("admin", "/management/home", 200),  # observed
                _req("admin", "/billing/invoices", 403),  # denied
                _req("admin", "/legacy/page", 302),  # redirected
                _req("user", "/management/home", 200),  # user observes management too
                # user never touches /billing or /legacy -> not_observed
            ]
        )
    )
    assert vis["roles"] == ["admin", "user"]
    assert _states(vis, "applications", "Management") == {
        "admin": OBSERVED,
        "user": OBSERVED,
    }
    assert _states(vis, "applications", "Billing") == {
        "admin": DENIED,
        "user": NOT_OBSERVED,
    }
    assert _states(vis, "applications", "Legacy") == {
        "admin": REDIRECTED,
        "user": NOT_OBSERVED,
    }


def test_static_assets_filtered():
    vis = build_role_visibility(
        _data(
            [
                _req("admin", "/app.css", 200),
                _req("admin", "/bundle.js", 200),
                _req("admin", "/logo.png", 200),
                _req("admin", "/fonts/roboto.woff2", 200),
                _req("admin", "/main.js.map", 200),
                _req("admin", "/management/home", 200),
            ]
        )
    )
    names = {a["name"] for a in vis["applications"]}
    assert names == {"Management"}
    assert vis["apis"] == []


def test_third_party_hosts_excluded():
    vis = build_role_visibility(
        _data(
            [
                _req("admin", "/management/home", 200),
                _req("admin", "/v1/track", 200, "application/json", host="datadoghq.com"),
                _req("admin", "/maps/api", 200, host="maps.googleapis.com"),
            ]
        )
    )
    # Only the app's own host contributes.
    assert {a["name"] for a in vis["applications"]} == {"Management"}
    assert vis["apis"] == []


def test_application_vs_api_split():
    vis = build_role_visibility(
        _data(
            [
                _req("admin", "/device-access/overview", 200),  # app (HTML route)
                _req("admin", "/device-access/svc/getDevices", 200),  # api (verb)
                _req("admin", "/api/navigation/navdata", 200),  # api (/api/)
                _req("admin", "/report/data.json", 200),  # api (.json)
                _req("admin", "/billing/svc", 200, "application/json"),  # api (json ctype)
            ]
        )
    )
    assert {a["name"] for a in vis["applications"]} == {"Device Access"}
    api_eps = {a["endpoint"] for a in vis["apis"]}
    assert "/device-access/svc/getDevices" in api_eps
    assert "/api/navigation/navdata" in api_eps
    assert "/report/data.json" in api_eps
    assert "/billing/svc" in api_eps


def test_admin_only_applications_regression():
    """Bug #3: admin-only must be non-empty when admin HAR has unique areas."""
    vis = build_role_visibility(
        _data(
            [
                _req("admin", "/management/x", 200),
                _req("admin", "/billing/x", 200),
                _req("admin", "/alarm-insight/x", 200),
                _req("admin", "/device-access/x", 200),
                _req("user", "/device-access/x", 200),
            ]
        )
    )
    assert vis["exclusive_apps"]["admin"] == ["Alarm Insight", "Billing", "Management"]
    assert vis["exclusive_apps"]["user"] == []
    assert vis["shared_apps"] == ["Device Access"]


def test_spelling_variants_merge():
    vis = build_role_visibility(
        _data(
            [
                _req("admin", "/device-access/x", 200),
                _req("user", "/deviceaccess/y", 200),
            ]
        )
    )
    apps = {a["name"] for a in vis["applications"]}
    assert apps == {"Device Access"}  # one merged row, readable spelling kept
    assert vis["shared_apps"] == ["Device Access"]


def test_success_outranks_denial_for_same_role():
    # A role that sees both 200 and 403 for one area counts as observed.
    vis = build_role_visibility(
        _data(
            [
                _req("admin", "/billing/a", 403),
                _req("admin", "/billing/b", 200),
            ]
        )
    )
    assert _states(vis, "applications", "Billing")["admin"] == OBSERVED


def test_unattributed_requests_ignored():
    # Requests with no role must not pollute the comparison.
    vis = build_role_visibility(
        _data([{"url": f"{BASE}/management/home", "method": "GET", "response_status": 200}])
    )
    assert vis["roles"] == []
    assert vis["applications"] == []


def test_shared_api_breakdown():
    vis = build_role_visibility(
        _data(
            [
                _req("admin", "/svc/getProfile", 200),
                _req("user", "/svc/getProfile", 200),
                _req("admin", "/svc/getAdminPanel", 200),
            ]
        )
    )
    assert vis["shared_apis"] == ["GET /svc/getProfile"]
    assert vis["exclusive_apis"]["admin"] == ["GET /svc/getAdminPanel"]
    assert vis["exclusive_apis"]["user"] == []
