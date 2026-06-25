"""Tests for Sprint B.3 — canonical service registry & full-URL correlation."""

from __future__ import annotations

from modules.intelligence.javascript_intelligence import build_javascript_intelligence
from modules.intelligence.runtime_config_discovery import discover_runtime_config
from modules.intelligence.service_registry import build_service_registry, resolve_path

ENV_JS = """
window.env = {
  REACT_APP_GATEWAY_URL: "https://gateway-proxy-qa.example.com",
  REACT_APP_AD_API_URL: "https://gateway-proxy-qa.example.com/anomaly-detection-backend/api",
  REACT_APP_FLOODS_URL: "https://gateway-proxy-qa.example.com/floods-service/api/v1",
  REACT_APP_GAPORTAL_URL: "https://gateway-proxy-qa.example.com/gaportal-service/api/v1",
  REACT_APP_ANOMALY_DETECTION_MODULE: true
};
"""


def _data(with_observed=False):
    rc = discover_runtime_config(
        [{"url": "/env-config.js", "source": "HAR response", "text": ENV_JS}]
    )
    data = {
        "target": {"domain": "example.com"},
        "intel_findings": [f.model_dump() for f in rc],
        "har_requests": [],
        "crawl_endpoints": [],
    }
    if with_observed:
        data["har_requests"] = [
            {
                "url": "https://gateway-proxy-qa.example.com/floods-service/api/v1/user/getAll",
                "method": "GET",
                "role": "qa",
                "response_status": 200,
                "response_content_type": "application/json",
                "response_keys": ["email", "username"],
            }
        ]
    return data


def test_registry_records():
    reg = build_service_registry(_data())
    by = {r["service"]: r for r in reg["services"]}
    assert "anomaly-detection-backend" in by
    rec = by["anomaly-detection-backend"]
    assert rec["host"] == "gateway-proxy-qa.example.com"
    assert rec["source"] == "env-config.js"
    assert rec["referenced"] is True
    assert rec["observed"] is False
    assert rec["confidence"] == "high"


def test_resolve_path_full_url():
    reg = build_service_registry(_data())
    m = resolve_path(reg, "/anomaly-detection-backend/api")
    assert m["full_url"] == "https://gateway-proxy-qa.example.com/anomaly-detection-backend/api"
    assert m["host"] == "gateway-proxy-qa.example.com"
    assert m["service"] == "anomaly-detection-backend"
    assert m["source"] == "env-config.js"
    assert m["confidence"] == "high"


def test_resolve_navigation_path_stays_pathonly():
    reg = build_service_registry(_data())
    # /login is not a service-looking path -> not auto-qualified
    assert resolve_path(reg, "/login") is None


def test_observed_flips_flag():
    reg = build_service_registry(_data(with_observed=True))
    floods = next(r for r in reg["services"] if r["service"] == "floods-service")
    assert floods["observed"] is True
    assert floods["referenced"] is True


def test_hidden_apis_fully_qualified_in_js_intel():
    ji = build_javascript_intelligence(_data())
    urls = {h.get("full_url") for h in ji["hidden_apis"]}
    assert "https://gateway-proxy-qa.example.com/anomaly-detection-backend/api" in urls
    # every hidden API has host + service + source
    for h in ji["hidden_apis"]:
        assert h.get("host") and h.get("service") and h.get("source")


def test_service_inventory_in_output():
    ji = build_javascript_intelligence(_data())
    inv = {r["service"]: r for r in ji["service_inventory"]}
    assert "floods-service" in inv
    assert inv["floods-service"]["base_url"].startswith("https://gateway-proxy-qa.example.com")


def test_correlation_v2_full_url():
    ji = build_javascript_intelligence(_data(with_observed=True))
    corr = {c["feature"]: c for c in ji["correlation"]}
    anomaly = next((c for k, c in corr.items() if "anomaly" in k.lower()), None)
    assert anomaly is not None
    assert anomaly.get("full_url", "").startswith("https://gateway-proxy-qa.example.com")
    assert anomaly.get("service") == "anomaly-detection-backend"
    assert anomaly.get("host") == "gateway-proxy-qa.example.com"
