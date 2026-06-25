"""Tests for Sprint A.5 — precision, prioritization & recon intelligence.

Covers static/telemetry classifiers, sensitive-schema (IDOR) detection, risk
scoring ordering, Top-10 targets, the target queue, and the confidence breakdown.
"""

from __future__ import annotations

from modules.intelligence.classifiers import is_noise_path, is_static_path
from modules.intelligence.pentest_targets import target_queue, top_targets
from modules.intelligence.recon_intelligence import build_recon_intelligence
from modules.intelligence.risk_scoring import score_endpoints
from modules.intelligence.sensitive_schema import analyze_sensitive_schemas
from modules.intelligence.telemetry_classifier import classify_telemetry, is_telemetry

# --- I1: static classifier ------------------------------------------------


def test_static_classifier():
    for p in ("/x/ic_close.svg", "/a/main.css", "/b/app.js.map", "/c/font.woff2"):
        assert is_static_path(p)
    assert not is_static_path("/api/users")
    assert is_noise_path("/x/userMessage.directive.js")  # passive doc
    assert not is_noise_path("/device-access/svc/device/headerdetails/1")


# --- I3: telemetry classifier ---------------------------------------------


def test_telemetry_classifier():
    assert classify_telemetry("browser-intake-datadoghq.com", "/api/v2/rum") == "Datadog"
    assert classify_telemetry("app.example.com", "/v2/replay") == "Telemetry / RUM"
    assert is_telemetry("https://o123.ingest.sentry.io/123")
    assert not is_telemetry("/api/users")


# --- I4: sensitive schema + IDOR ------------------------------------------


def _data_with_response(path, keys, method="GET"):
    return {
        "har_requests": [
            {
                "url": f"https://app.example.com{path}",
                "method": method,
                "response_status": 200,
                "response_content_type": "application/json",
                "response_keys": keys,
            }
        ]
    }


def test_sensitive_schema_idor():
    data = _data_with_response(
        "/device-access/svc/device/headerdetails/1995608",
        ["account", "address", "deviceNumber", "user"],
    )
    models = analyze_sensitive_schemas(data)
    assert models, "expected a sensitive model"
    m = models[0]
    assert m["idor_candidate"] is True  # sensitive fields behind {id}
    assert set(m["categories"]) >= {"Customer", "Location", "Asset"}
    assert "account" in m["sensitive_fields"]


def test_non_sensitive_schema_not_flagged():
    data = _data_with_response("/api/health", ["status", "uptime"])
    assert analyze_sensitive_schemas(data) == []


# --- I5: risk scoring ordering --------------------------------------------


def test_risk_scoring_ranks_sensitive_above_noise():
    data = {
        "target": {"domain": "app.example.com"},
        "users": [{"role": "admin"}, {"role": "user"}],
        "har_requests": [
            # device header details: admin-only + sensitive fields
            {
                "url": "https://app.example.com/device-access/svc/device/headerdetails/1995608",
                "method": "GET",
                "role": "admin",
                "response_status": 200,
                "response_content_type": "application/json",
                "response_keys": ["account", "address", "deviceNumber"],
            },
            # telemetry — should be penalized / excluded
            {
                "url": "https://browser-intake-datadoghq.com/api/v2/rum",
                "method": "POST",
                "role": "admin",
            },
        ],
    }
    scored = score_endpoints(data)
    eps = [r["endpoint"] for r in scored]
    # device header details present and telemetry absent (negative score dropped)
    assert any("headerdetails" in e for e in eps)
    assert not any("rum" in e for e in eps)
    top = scored[0]
    assert "headerdetails" in top["endpoint"]
    assert top["sensitive"] and top["admin_only"]


def test_top_targets_and_queue_shape():
    data = {
        "target": {"domain": "app.example.com"},
        "users": [{"role": "admin"}, {"role": "user"}],
        "har_requests": [
            {
                "url": "https://app.example.com/billing-access/svc/api/reports/billing-cycles",
                "method": "POST",
                "role": "admin",
                "response_status": 200,
                "response_content_type": "application/json",
                "response_keys": ["account", "billing", "cycles"],
            },
        ],
    }
    targets = top_targets(data, n=10)
    assert targets
    t = targets[0]
    assert t["rank"] == 1
    assert t["tests"] and t["reason"] and t["risk"] in {"Critical", "High", "Medium", "Low"}
    q = target_queue(data)
    assert set(q) == {"Immediate", "High", "Medium", "Low"}
    # billing report: admin-only + sensitive + export/state-changing -> Immediate
    assert any("billing-cycles" in i["endpoint"] for i in q["Immediate"])


# --- I9: confidence breakdown ---------------------------------------------


def test_confidence_breakdown_present():
    data = {
        "target": {"domain": "app.example.com"},
        "har_requests": [
            {
                "url": "https://app.example.com/api/users/1",
                "method": "GET",
                "role": "admin",
                "response_status": 200,
                "response_content_type": "application/json",
                "response_keys": ["id", "email", "role"],
            }
        ],
    }
    ri = build_recon_intelligence(data)
    cb = ri["confidence_breakdown"]
    assert set(cb) == {"high", "medium", "low"}
    assert sum(cb.values()) >= 1
    assert "summary" in ri and "top_targets" in ri and "sensitive_data_models" in ri
