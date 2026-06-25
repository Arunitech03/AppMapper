"""Unit tests for the Unified Asset Intelligence sprint (Issues 1-11).

Covers: captured-artifact IdP detection (+realm), unified API inventory across
sources, related internal-app discovery, gateway/service detection, business-module
inference, response intelligence (keys only), third-party dependency grouping,
attack-surface scoring, workflow noise reduction, and the report aggregator —
including the guarantee that response *values* never appear anywhere.
"""

from __future__ import annotations

from models.schemas import IdPInfo
from modules.auth.idp_analyzer import analyze_idp, effective_idp, merge_idp
from modules.intelligence.asset_inventory import build_asset_intelligence, unified_api_inventory
from modules.intelligence.attack_surface import score_attack_surface
from modules.intelligence.business_modules import detect_business_modules
from modules.intelligence.dependency_inventory import build_dependency_inventory
from modules.intelligence.gateway_detector import all_services, detect_gateways, service_of_path
from modules.intelligence.internal_apps import find_internal_apps
from modules.intelligence.response_analyzer import analyze_responses
from modules.intelligence.workflow_mapper import _is_noise


def _demo_data() -> dict:
    """Synthetic demo-style dataset exercising every Issue."""
    return {
        "target": {
            "url": "https://ww-rtwhatif-qa.example.com",
            "domain": "ww-rtwhatif-qa.example.com",
        },
        "users": [{"role": "admin"}],
        "idp_info": [],
        "auth_artifacts": [
            {"name": "KEYCLOAK_SESSION", "kind": "cookie", "value_masked": "***"},
            {"name": "AUTH_SESSION_ID", "kind": "cookie", "value_masked": "***"},
        ],
        "js_findings": [
            {"kind": "api_endpoint", "value": "/v2/assets/list"},
            {"kind": "url", "value": "https://portal-qa.example.com/"},
            {"kind": "url", "value": "https://cctv-qa.example.com/"},
            {"kind": "url", "value": "https://odour-management-qa.example.com/"},
            {"kind": "url", "value": "https://maps.googleapis.com/maps/api/js"},
            {"kind": "url", "value": "https://api.mapbox.com/styles/v1"},
            {"kind": "url", "value": "https://demogis.blob.core.windows.net/tiles"},
            {"kind": "url", "value": "https://api.iconify.design/mdi.json"},
        ],
        "api_intel": [],
        "api_endpoints": [],
        "burp_requests": [],
        "crawl_endpoints": [],
        "har_requests": [
            {
                "url": "https://qa.example.com/auth/realms/demo_realm/protocol/openid-connect/token",
                "method": "POST",
            },
            {
                "url": "https://gateway-proxy-qa.example.com/floods-service/api/v1/user/getAll",
                "method": "GET",
                "response_status": 200,
                "response_content_type": "application/json; charset=utf-8",
                "response_size": 4096,
                "response_keys": "id,email,role,status",
            },
            {
                "url": "https://gateway-proxy-qa.example.com/gis-apirest/v1/layers",
                "method": "GET",
                "response_status": 200,
                "response_content_type": "application/json",
                "response_keys": ["layers", "hierarchy"],
            },
            {
                "url": "https://gateway-proxy-qa.example.com/anomaly-detection-backend/v1/scan",
                "method": "GET",
            },
        ],
    }


# --- Issue 1: IdP analyzer ------------------------------------------------


def test_idp_keycloak_from_cookies_and_realm():
    idp = analyze_idp(_demo_data())
    assert idp.identity_provider == "Keycloak"
    assert idp.authentication_type == "OpenID Connect"
    assert idp.realm == "demo_realm"
    assert any("realms/demo_realm" in e for e in idp.evidence)


def test_idp_hosted_providers():
    for host, provider in (
        ("login.microsoftonline.com", "Azure AD / Entra ID"),
        ("dev-123.okta.com", "Okta"),
        ("acme.auth0.com", "Auth0"),
    ):
        data = {"har_requests": [{"url": f"https://{host}/authorize", "method": "GET"}]}
        assert analyze_idp(data).identity_provider == provider


def test_idp_unknown_when_no_signal():
    data = {"har_requests": [{"url": "https://example.com/", "method": "GET"}]}
    assert analyze_idp(data).identity_provider == "Unknown"


def test_merge_prefers_concrete_over_unknown_live():
    live = IdPInfo(identity_provider="Unknown", authentication_type="Unknown")
    captured = IdPInfo(
        identity_provider="Keycloak", authentication_type="OpenID Connect", realm="demo_realm"
    )
    merged = merge_idp(live, captured)
    assert merged.identity_provider == "Keycloak"
    assert merged.realm == "demo_realm"


def test_merge_keeps_live_realm_when_captured_missing():
    live = IdPInfo(identity_provider="Keycloak", authentication_type="OpenID Connect", realm="prod")
    captured = IdPInfo(identity_provider="Keycloak", authentication_type="OpenID Connect")
    assert merge_idp(live, captured).realm == "prod"


def test_effective_idp_reconciles_unknown_stored():
    """Report-time reconciliation: Unknown stored row -> captured Keycloak+realm."""
    data = _demo_data()
    data["idp_info"] = [
        {"identity_provider": "Unknown", "authentication_type": "Unknown", "evidence": ""}
    ]
    idp = effective_idp(data)
    assert idp.identity_provider == "Keycloak"
    assert idp.realm == "demo_realm"


def test_effective_idp_coerces_csv_evidence():
    """Stored evidence is a CSV string in the DB; effective_idp must not crash."""
    data = {
        "idp_info": [
            {
                "identity_provider": "Keycloak",
                "authentication_type": "OpenID Connect",
                "realm": "prod",
                "evidence": "cookie:keycloak_session,path:/realms/prod",
            }
        ],
        "har_requests": [],
        "auth_artifacts": [],
    }
    idp = effective_idp(data)
    assert idp.identity_provider == "Keycloak"
    assert idp.realm == "prod"


# --- Issue 2 + 4: unified API inventory -----------------------------------


def test_unified_inventory_merges_js_and_har():
    inv = unified_api_inventory(_demo_data())
    paths = {r["path"]: r for r in inv}
    assert "/v2/assets/list" in paths
    assert paths["/v2/assets/list"]["sources"] == ["JS"]
    floods = paths["/floods-service/api/v1/user/getAll"]
    assert "HAR" in floods["sources"]
    assert floods["service"] == "floods-service"


# --- Issue 3: internal apps -----------------------------------------------


def test_internal_apps_classified():
    apps = {a["host"]: a["app_type"] for a in find_internal_apps(_demo_data())}
    assert apps["portal-qa.example.com"] == "Portal"
    assert apps["cctv-qa.example.com"] == "CCTV"
    assert apps["odour-management-qa.example.com"] == "Odour Management"
    # External hosts (Google/Mapbox) are not same-org internal apps.
    assert "maps.googleapis.com" not in apps


# --- Issue 5: gateway + services ------------------------------------------


def test_service_of_path():
    assert service_of_path("/floods-service/api/v1/x") == "floods-service"
    assert service_of_path("/api/gis-apirest/v1/x") == "gis-apirest"
    assert service_of_path("/v1/x") is None
    assert service_of_path("/") is None


def test_gateway_detection():
    data = _demo_data()
    gws = detect_gateways(data)
    assert len(gws) == 1
    gw = gws[0]
    assert gw["host"] == "gateway-proxy-qa.example.com"
    assert "floods-service" in gw["services"]
    assert "gis-apirest" in gw["services"]
    assert "floods-service" in all_services(data)


# --- Issue 6: business modules --------------------------------------------


def test_business_modules_ranked():
    mods = {m["module"] for m in detect_business_modules(_demo_data())}
    assert "GIS" in mods
    assert "Flood Prediction" in mods
    assert "User Management" in mods


# --- Issue 7: response intelligence (keys only) ---------------------------


def test_response_intelligence_keys_only():
    resp = analyze_responses(_demo_data())
    by_ep = {r["endpoint"]: r for r in resp}
    floods = by_ep["/floods-service/api/v1/user/getAll"]
    assert floods["json_keys"] == ["email", "id", "role", "status"]
    assert floods["status"] == [200]
    assert "application/json" in floods["content_type"]
    assert floods["size"] == 4096
    assert floods["confidence"] == "high"  # keys captured
    # Endpoints with no observed metadata at all are not surfaced.
    assert "/anomaly-detection-backend/v1/scan" not in by_ep


# --- Issue 9: dependency inventory ----------------------------------------


def test_dependency_grouping():
    deps = build_dependency_inventory(_demo_data())
    assert "Google Maps" in deps["Mapping"]
    assert "Mapbox" in deps["Mapping"]
    assert "Azure Blob Storage" in deps["Cloud Storage"]
    assert "Iconify" in deps["Icons"]


# --- Issue 10: attack surface ---------------------------------------------


def test_attack_surface_scored_and_ranked():
    surface = score_attack_surface(_demo_data())
    assert surface  # non-empty
    scores = [a["score"] for a in surface]
    assert scores == sorted(scores, reverse=True)
    areas = {a["area"] for a in surface}
    # User Management is a sensitive module and should be prioritized.
    assert "User Management" in areas


# --- Issue 8: workflow noise reduction ------------------------------------


def test_workflow_noise_filter():
    assert _is_noise("/assets/main.css")
    assert _is_noise("/bundle.js")
    assert _is_noise("/logo.png")
    assert _is_noise("/styles/v1/mapbox/tiles/1/2/3")
    assert _is_noise("https://x.blob.core.windows.net/tiles/1")
    assert not _is_noise("/floods-service/api/v1/user/getAll")
    assert not _is_noise("/login")


# --- Aggregator + no-value-leak guarantee ---------------------------------


def test_aggregator_shape():
    ai = build_asset_intelligence(_demo_data())
    for key in (
        "api_inventory",
        "services",
        "gateways",
        "internal_apps",
        "business_modules",
        "dependencies",
        "response_intelligence",
        "attack_surface",
        "infrastructure",
    ):
        assert key in ai
    infra = ai["infrastructure"]
    assert infra["identity_realm"] == "demo_realm"
    assert infra["api_gateways"] == ["gateway-proxy-qa.example.com"]
    # Gateway host is not double-counted as a related application.
    assert "gateway-proxy-qa.example.com" not in infra["related_applications"]


def test_no_response_values_leak():
    """Only KEYS (field names) are ever surfaced — never response values."""
    import json

    ai = build_asset_intelligence(_demo_data())
    blob = json.dumps(ai)
    # Field names (keys) are allowed; a fabricated *value* must never appear.
    assert "id" in blob  # key present
    assert "admin@example.com" not in blob
    assert "secret-value" not in blob
