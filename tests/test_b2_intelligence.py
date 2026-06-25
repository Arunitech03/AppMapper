"""Tests for Sprint B.2 — secret intelligence, runtime risks, hidden functionality."""

from __future__ import annotations

from models.schemas import IntelFinding
from modules.intelligence.browser_security import build_browser_security
from modules.intelligence.javascript_intelligence import build_javascript_intelligence
from modules.intelligence.runtime_config_discovery import discover_runtime_config
from modules.intelligence.runtime_config_risks import build_runtime_config_risks

ENV_JS = """
window.env = {
  REACT_APP_GATEWAY_URL: "https://gateway-proxy-qa.example.com",
  REACT_APP_AD_API_URL: "https://gateway-proxy-qa.example.com/anomaly-detection-backend/api",
  REACT_APP_API_URL: "https://gateway-proxy-qa.example.com/floods-service/api/v1",
  REACT_APP_KEYCLOAK_REALM: "demo_realm",
  REACT_APP_KEYCLOAK_CLIENT_ID: "demo-floods",
  REACT_APP_ANOMALY_DETECTION_MODULE: true,
  REACT_APP_EWS_MODULE: true,
  REACT_APP_ROLES_EMERGENCY_RESPONSE_ADMIN: "WW_ER_ADMIN",
  REACT_APP_ROLES_EMERGENCY_RESPONSE_USER: "WW_ER_USER",
  REACT_APP_ROLES_FLOODS_GENERAL: "APP_FLOODS",
  REACT_APP_GEOSERVER_WORKSPACE: "dmd",
  REACT_APP_MULTITENANT_URL: "SINGLE_TENANT",
  REACT_APP_CCTV_URL: "https://cctv-qa.example.com",
  REACT_APP_DQC_URL: "https://data-quality-control-qa.example.com",
  REACT_APP_SEWER_URL: "https://sewerprotect-qa.example.com"
};
"""


def _data():
    rc = discover_runtime_config(
        [{"url": "/env-config.js", "source": "HAR response", "text": ENV_JS}]
    )
    return {
        "target": {"domain": "example.com"},
        "intel_findings": [f.model_dump() for f in rc],
        "crawl_endpoints": [],
        "har_requests": [],
    }


# --- F5 hidden APIs from runtime config URLs ------------------------------


def test_hidden_apis_from_runtime_config():
    ji = build_javascript_intelligence(_data())
    eps = {h["endpoint"] for h in ji["hidden_apis"]}
    assert "/anomaly-detection-backend/api" in eps
    assert "/floods-service/api/v1" in eps


# --- F4 hidden routes from feature flags ----------------------------------


def test_hidden_routes_from_feature_flags():
    ji = build_javascript_intelligence(_data())
    routes = {r["route"] for r in ji["hidden_routes"]}
    assert "/anomaly-detection" in routes
    assert "/ews" in routes
    # each carries source + reason
    r = next(r for r in ji["hidden_routes"] if r["route"] == "/ews")
    assert r["source"] and r["reason"]


# --- F2 runtime config risks ----------------------------------------------


def test_runtime_config_risks():
    risks = {r["title"]: r for r in build_runtime_config_risks(_data())}
    admin = next(t for t in risks if "Administrative roles" in t)
    assert "WW_ER_ADMIN" in risks[admin]["evidence"]
    assert risks[admin]["severity"] == "High"
    assert any("Authentication infrastructure" in t for t in risks)
    assert any("GIS infrastructure" in t for t in risks)
    assert any("Tenant configuration" in t for t in risks)


# --- F3 related app classification ----------------------------------------


def test_related_app_categories():
    ji = build_javascript_intelligence(_data())
    cats = {a["host"]: a["category"] for a in ji["related_applications"]}
    assert cats["cctv-qa.example.com"] == "Monitoring"
    assert cats["data-quality-control-qa.example.com"] == "Data Quality"
    assert cats["sewerprotect-qa.example.com"] == "Operations"


# --- F6 role-aware correlation --------------------------------------------


def test_correlation_admin_module():
    ji = build_javascript_intelligence(_data())
    corr = {c["feature"]: c for c in ji["correlation"]}
    anomaly = next((c for k, c in corr.items() if "anomaly" in k.lower()), None)
    assert anomaly is not None
    # anomaly feature linked to its API + route
    assert anomaly["apis"] and anomaly["routes"]
    assert anomaly["confidence"] == "high"


# --- F12 summary v2 lists names not counts --------------------------------


def test_summary_v2_actionable():
    ji = build_javascript_intelligence(_data())
    v2 = ji["summary_v2"]
    assert v2["authentication"]["keycloak_realm"] == "demo_realm"
    assert v2["authentication"]["keycloak_client"] == "demo-floods"
    assert any("/anomaly-detection-backend/api" in a for a in v2["hidden_apis"])
    assert any("/anomaly-detection" == r for r in v2["hidden_routes"])
    assert any("cctv" in a for a in v2["related_applications"])


# --- F9 browser security --------------------------------------------------


def test_browser_security_jwt_localstorage():
    data = {
        "auth_artifacts": [
            {
                "role": "admin",
                "kind": "local_storage",
                "name": "access_token",
                "value_masked": "ey***",
            },
            {"role": "admin", "kind": "local_storage", "name": "userRole", "value_masked": "ad***"},
        ]
    }
    findings = {f["title"]: f for f in build_browser_security(data)}
    assert any("token stored in browser storage" in t.lower() for t in findings)
    assert any("Role / permission" in t for t in findings)


# --- F11 top 20 + no leak --------------------------------------------------


def test_top_targets_present_and_no_leak():
    import json

    # add a sensitive observed endpoint so scoring has a target
    data = _data()
    data["har_requests"] = [
        {
            "url": "https://gateway-proxy-qa.example.com/floods-service/api/v1/user/getAll",
            "method": "GET",
            "role": "admin",
            "response_status": 200,
            "response_content_type": "application/json",
            "response_keys": ["id", "email", "role"],
        }
    ]
    data["users"] = [{"role": "admin"}, {"role": "user"}]
    ji = build_javascript_intelligence(data)
    assert isinstance(ji["top_targets"], list)
    # the env-config map token / secrets never leak in full
    blob = json.dumps(ji)
    assert "demo_realm" in blob  # non-secret realm kept
    assert not __import__("re").search(r"eyJ[A-Za-z0-9_\-]{40,}", blob)


def _idem():
    # adding an IntelFinding directly still works through the aggregator
    f = IntelFinding(
        kind="api_ref",
        category="Hidden API",
        name="/api/admin/users",
        location="/api/admin/users",
        source="JS",
    )
    return f
