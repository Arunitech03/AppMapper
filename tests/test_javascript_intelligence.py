"""Tests for Sprint B.1 — JavaScript intelligence & runtime config discovery."""

from __future__ import annotations

from modules.intelligence.javascript_intelligence import build_javascript_intelligence
from modules.intelligence.runtime_config_discovery import discover_runtime_config

ENV_JS = """
window.env = {
  REACT_APP_GATEWAY_URL: "https://gateway-proxy-qa.example.com",
  REACT_APP_KEYCLOAK_URL: "https://auth-qa.example.com/auth",
  REACT_APP_KEYCLOAK_REALM: "demo_realm",
  REACT_APP_KEYCLOAK_CLIENT_ID: "demo-floods",
  REACT_APP_MAP_TOKEN: "eyJhbGciOiJIUzI1NiJ9.payload1234567890.signature1234567890",
  REACT_APP_API_URL: "https://api-qa.example.com",
  REACT_APP_CLIENT_SECRET: "verysecretvalue0123456789abcdef",
  REACT_APP_EWS_MODULE: true,
  REACT_APP_ANOMALY_DETECTION_MODULE: true,
  REACT_APP_ERMONITORING: false,
  REACT_APP_CCTV_URL: "https://cctv-qa.example.com"
};
"""


def _corpus(text=ENV_JS, url="/env-config.js"):
    return [{"url": url, "source": "HAR response", "text": text}]


# --- Feature 2: runtime config object extraction --------------------------


def test_runtime_config_extracts_keycloak_and_urls_verbatim():
    findings = {f.name: f for f in discover_runtime_config(_corpus())}
    assert findings["Keycloak Realm"].value_masked == "demo_realm"
    assert findings["Keycloak Client ID"].value_masked == "demo-floods"
    assert findings["API Gateway URL"].value_masked == "https://gateway-proxy-qa.example.com"
    assert findings["Authentication URL"].value_masked == "https://auth-qa.example.com/auth"


def test_runtime_config_masks_secrets():
    findings = discover_runtime_config(_corpus())
    by_name = {f.name: f for f in findings}
    # Map token (public) -> masked, Informational severity.
    assert "Map Token" in by_name
    assert "eyJhbGciOiJIUzI1NiJ9.payload1234567890.signature1234567890" not in (
        by_name["Map Token"].value_masked or ""
    )
    assert by_name["Map Token"].severity == "Informational"
    # Client secret -> masked, High severity.
    sec = next(f for f in findings if "Secret" in f.name)
    assert "verysecretvalue0123456789abcdef" not in (sec.value_masked or "")
    assert sec.severity == "High"


def test_feature_flags_enabled_disabled():
    findings = discover_runtime_config(_corpus())
    flags = {f.name: (f.extra or {}).get("enabled") for f in findings if f.kind == "feature_flag"}
    assert flags.get("Ews") is True
    assert flags.get("Anomaly Detection") is True
    assert flags.get("Ermonitoring") is False


# --- aggregator: categorization, correlation, summary ---------------------


def _data():
    findings = discover_runtime_config(_corpus())
    # add a hidden API reference + an observed nothing
    from models.schemas import IntelFinding

    findings.append(
        IntelFinding(
            kind="api_ref",
            category="Hidden API",
            name="/anomaly-detection-backend/api/v1/getAll",
            location="/anomaly-detection-backend/api/v1/getAll",
            source="JS",
        )
    )
    return {
        "target": {"domain": "example.com"},
        "intel_findings": [f.model_dump() for f in findings],
        "crawl_endpoints": [],
        "har_requests": [],
    }


def test_related_applications_categorized():
    ji = build_javascript_intelligence(_data())
    cats = {a["host"]: a["category"] for a in ji["related_applications"]}
    assert cats.get("cctv-qa.example.com") == "Monitoring"
    assert any("gateway" in h for h in cats)


def test_summary_and_hidden_module_correlation():
    ji = build_javascript_intelligence(_data())
    s = ji["summary"]
    assert s["keycloak_realm"] == "demo_realm"
    assert s["keycloak_client"] == "demo-floods"
    assert "Ews" in s["enabled_features"] or "Anomaly Detection" in s["enabled_features"]
    assert s["hidden_apis"] >= 1
    # anomaly feature flag + anomaly API -> correlation row
    corr = {c["feature"]: c for c in ji["correlation"]}
    anomaly = next((c for k, c in corr.items() if "anomaly" in k.lower()), None)
    assert anomaly is not None
    assert anomaly["apis"]  # linked to the anomaly-detection-backend API


def test_no_secret_leak_in_js_report():
    import json

    blob = json.dumps(build_javascript_intelligence(_data()))
    assert "verysecretvalue0123456789abcdef" not in blob
    assert "eyJhbGciOiJIUzI1NiJ9.payload1234567890.signature1234567890" not in blob
