"""Tests for Sprint A — Secret Discovery & Hidden Endpoint Intelligence.

Covers the secret engine (masking, grouping), route/hidden-API extraction, config
+ source-map intelligence, storage classification, hidden-endpoint diff + priority,
business-function inference, and the correlation engine / recon targets.
"""

from __future__ import annotations

from modules.auth.masking import redact_url
from modules.intelligence.business_function_discovery import discover_business_functions
from modules.intelligence.config_intelligence import discover_config
from modules.intelligence.correlation_engine import correlate, recon_targets
from modules.intelligence.hidden_endpoint_discovery import find_hidden_endpoints
from modules.intelligence.route_discovery import extract_api_refs, extract_routes
from modules.intelligence.secret_discovery import discover_secrets, group_findings
from modules.intelligence.sourcemap_intelligence import analyze_sourcemaps
from modules.intelligence.storage_intelligence import analyze_storage


def test_redact_url_strips_secret_query_values():
    u = "https://maps.googleapis.com/maps/api/js?v=3&key=AIzaSyCHsFLA7ZTquFwsNQH2&libraries=places"
    out = redact_url(u)
    assert "AIzaSyCHsFLA7ZTquFwsNQH2" not in out
    assert "key=REDACTED" in out
    assert "/maps/api/js" in out  # path preserved
    assert "libraries=places" in out  # non-secret param preserved
    # token/access_token/password redacted; URLs without query untouched
    assert (
        redact_url("https://x/cb?access_token=abc.def.ghi") == "https://x/cb?access_token=REDACTED"
    )
    assert redact_url("https://x/path") == "https://x/path"


def _corpus(text, url="/main.js", ctype="application/javascript", source="HAR response"):
    return [{"url": url, "content_type": ctype, "source": source, "text": text}]


# --- F1: secret discovery -------------------------------------------------


def test_secret_discovery_masks_and_groups():
    text = """
      const k = "AIzaSyA1234567890abcdefghijklmnopqrstuv";
      const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abcDEF123456_signature";
      const aws = "AKIAIOSFODNN7EXAMPLE";
      const stripe = "sk_live_0123456789abcdefABCDEF99";
      contact: "admin@corp.example.com"
    """
    findings = discover_secrets(_corpus(text))
    by_name = {f.name: f for f in findings}
    assert "Google API Key" in by_name
    # masked, never the full value
    assert "AIzaSyA1234567890abcdefghijklmnopqrstuv" not in by_name["Google API Key"].value_masked
    assert "…" in by_name["Google API Key"].value_masked
    assert "AWS Access Key ID" in by_name
    assert "JWT / Bearer Token" in by_name
    full_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abcDEF123456_signature"
    assert full_jwt not in by_name["JWT / Bearer Token"].value_masked
    # grouped
    groups = group_findings(findings)
    assert "API Keys" in groups and "Authentication" in groups and "Sensitive Data" in groups


def test_secret_discovery_no_full_value_anywhere():
    secret = "sk_live_SHOULDNEVERAPPEAR12345"
    findings = discover_secrets(_corpus(f'key="{secret}"'))
    for f in findings:
        assert secret not in (f.value_masked or "")


# --- F3 / F4: routes + hidden API refs ------------------------------------


def test_route_extraction_frameworks():
    angular = "const routes = [{ path: 'admin' }, { path: 'admin/users' }];"
    react = '<Route path="/billing-access" element={<B/>} />'
    vue = "{ path: '/device-access', component: Device }"
    routes = set(extract_routes(_corpus(angular + react + vue)))
    assert {"/admin", "/admin/users", "/billing-access", "/device-access"} <= routes


def test_api_ref_extraction():
    js = """
      axios.get('/api/admin/users');
      fetch("/floods-service/api/v1/getAll");
      this.http.post('/billing-access/svc/api/session', body);
      const x = '/assets/logo.png';
    """
    refs = set(extract_api_refs(_corpus(js)))
    assert "/api/admin/users" in refs
    assert "/billing-access/svc/api/session" in refs
    assert "/assets/logo.png" not in refs  # static excluded


def test_api_ref_excludes_pseudo_paths():
    js = """
      fetch('/dev/stdout'); fetch('/dev/stderr'); const a = '/dev/stdin';
      const b = '/proc/self/environ'; const c = '/node_modules/x/api/index.js';
      axios.get('/api/v1/users');
    """
    refs = set(extract_api_refs(_corpus(js)))
    assert "/api/v1/users" in refs
    assert not any(r.startswith(("/dev/", "/proc/", "/node_modules/")) for r in refs)


# --- F5: config intelligence ----------------------------------------------


def test_config_extraction_verbatim():
    js = (
        'const cfg = { apiBaseUrl: "https://gateway.company.com",'
        ' keycloakUrl: "https://kc.company.com/auth" };'
    )
    cfg = {c.name: c.value_masked for c in discover_config(_corpus(js))}
    assert cfg["API Base URL"] == "https://gateway.company.com"  # verbatim (non-secret)
    assert cfg["Keycloak URL"] == "https://kc.company.com/auth"


# --- F6: source maps ------------------------------------------------------


def test_sourcemap_extracts_sources_and_inner_refs():
    inner = 'const routes=[{path:\\"admin/secret\\"}]; axios.get(\\"/api/internal/reports\\")'
    sm = (
        '{"version":3,"sources":["webpack:///src/app/admin/admin.ts"],'
        '"sourcesContent":["' + inner + '"]}'
    )
    out = analyze_sourcemaps(
        [
            {
                "url": "main.js.map",
                "content_type": "application/json",
                "source": "HAR response",
                "text": sm,
            }
        ]
    )
    assert any("src/app/admin/admin.ts" in s for s in out["sources"])
    assert "/admin/secret" in out["routes"]
    assert "/api/internal/reports" in out["api_refs"]


# --- F8: storage intelligence ---------------------------------------------


def test_storage_classification_and_notes():
    data = {
        "auth_artifacts": [
            {"role": "admin", "kind": "local_storage", "name": "userRole", "value_masked": "ad***"},
            {
                "role": "admin",
                "kind": "local_storage",
                "name": "access_token",
                "value_masked": "ey***",
            },
            {
                "role": "admin",
                "kind": "session_storage",
                "name": "tenantId",
                "value_masked": "12***",
            },
        ]
    }
    out = analyze_storage(data)
    by_key = {i["key"]: i for i in out["items"]}
    assert by_key["userRole"]["classification"] == "Role / Permission"
    assert by_key["access_token"]["classification"] == "JWT / Access Token"
    assert by_key["tenantId"]["classification"] == "Tenant / Org ID"
    assert any("Role information stored client-side" in n for n in out["notes"])


# --- F2: hidden endpoint diff ---------------------------------------------


def test_hidden_endpoint_diff_and_priority():
    data = {
        "target": {"domain": "app.example.com"},
        # observed
        "har_requests": [
            {"url": "https://app.example.com/api/users/1", "method": "GET"},
        ],
        # referenced (as content findings)
        "intel_findings": [
            {"kind": "api_ref", "name": "/api/users/{id}", "location": "/api/users/55"},
            {"kind": "api_ref", "name": "/api/admin/roles", "location": "/api/admin/roles"},
            {"kind": "api_ref", "name": "/api/health", "location": "/api/health"},
        ],
    }
    hidden = find_hidden_endpoints(data)
    eps = {h["endpoint"]: h for h in hidden}
    # observed /api/users/{id} should NOT be hidden
    assert "/api/users/{id}" not in eps
    assert "/api/admin/roles" in eps
    assert eps["/api/admin/roles"]["priority"] == "high"  # admin + role
    assert eps["/api/health"]["priority"] == "low"


# --- F9: business functions -----------------------------------------------


def test_business_functions():
    data = {
        "target": {"domain": "app.example.com"},
        "har_requests": [
            {"url": "https://app.example.com/api/users/list", "method": "GET"},
            {"url": "https://app.example.com/billing-access/svc/api/invoice", "method": "GET"},
        ],
        "intel_findings": [
            {"kind": "api_ref", "name": "/api/alarm/list", "location": "/api/alarm/list"}
        ],
    }
    funcs = {f["function"] for f in discover_business_functions(data)}
    assert "User Management" in funcs
    assert "Billing" in funcs
    assert "Alarm Management" in funcs


# --- F10: correlation + recon targets -------------------------------------


def test_correlation_and_recon_targets():
    data = {
        "target": {"domain": "app.example.com"},
        "har_requests": [
            {
                "url": "https://app.example.com/api/users/getAll",
                "method": "GET",
                "role": "admin",
                "response_status": 200,
                "response_content_type": "application/json",
                "response_keys": ["id", "email", "role"],
            }
        ],
        "intel_findings": [
            {"kind": "api_ref", "name": "/api/admin/config", "location": "/api/admin/config"}
        ],
    }
    rows = {c["endpoint"]: c for c in correlate(data)}
    users = rows["/api/users/getAll"]
    assert users["business_module"] == "User Management"
    assert "email" in users["response_keys"]
    assert "admin" in users["roles"]

    targets = recon_targets(data)
    assert any(t["target"] == "/api/admin/config" for t in targets)
    assert targets[0]["priority"] == "high"
