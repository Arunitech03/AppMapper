"""Tests for External Domain Intelligence & API Relationship Mapping."""

from __future__ import annotations

from models.schemas import TargetInput
from modules.intelligence.domain_classifier import (
    build_domain_intel,
    classify_host,
    registrable_domain,
)

DATA = {
    "target": {"url": "https://portal.company.com", "domain": "portal.company.com"},
    "users": [{"role": "admin"}, {"role": "user"}],
    "idp_info": [
        {
            "identity_provider": "Keycloak",
            "authentication_type": "OIDC",
            "evidence": "path:/realms/",
            "metadata_url": "https://auth.company.com/realms/master/.well-known/openid-configuration",
        }
    ],
    "crawl_endpoints": [],
    "burp_requests": [],
    "har_requests": [
        {
            "url": "https://portal.company.com/",
            "method": "GET",
            "role": "admin",
            "response_status": 200,
        },
        {
            "url": "https://api.company.com/v1/users",
            "method": "GET",
            "role": "admin",
            "response_status": 200,
        },
        {
            "url": "https://api.company.com/v1/users",
            "method": "GET",
            "role": "user",
            "response_status": 200,
        },
        {
            "url": "https://api.company.com/v1/users/42",
            "method": "GET",
            "role": "admin",
            "response_status": 200,
        },
        {
            "url": "https://api.company.com/admin/settings",
            "method": "GET",
            "role": "admin",
            "response_status": 200,
        },
        {
            "url": "https://orders.company.com/v1/orders",
            "method": "POST",
            "role": "user",
            "response_status": 201,
        },
        {
            "url": "https://auth.company.com/realms/master/protocol/openid-connect/auth",
            "method": "GET",
            "role": "anonymous",
            "response_status": 200,
        },
        {
            "url": "https://api.stripe.com/v1/charges",
            "method": "POST",
            "role": "admin",
            "response_status": 200,
        },
        {
            "url": "https://www.google-analytics.com/collect",
            "method": "POST",
            "role": "admin",
            "response_status": 200,
        },
        {
            "url": "https://cdnjs.cloudflare.com/lib.js",
            "method": "GET",
            "role": None,
            "response_status": 200,
        },
    ],
}


def test_registrable_domain():
    assert registrable_domain("auth-eu-test.example.com") == "example.com"
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"


def test_classify_host():
    assert (
        classify_host("login.microsoftonline.com", set(), "portal.company.com")[0]
        == "Authentication Provider"
    )
    assert (
        classify_host("auth.company.com", {"/realms/m"}, "portal.company.com")[0]
        == "Authentication Provider"
    )
    assert classify_host("api.company.com", {"/v1/x"}, "portal.company.com")[0] == "Internal API"
    assert classify_host("gateway.company.com", set(), "portal.company.com")[0] == "Microservice"
    assert classify_host("api.stripe.com", set(), "portal.company.com")[0] == "Payment Provider"
    assert classify_host("www.google-analytics.com", set(), "portal.company.com")[0] == "Analytics"
    assert classify_host("cdnjs.cloudflare.com", set(), "portal.company.com")[0] == "CDN"
    assert (
        classify_host("portal.company.com", set(), "portal.company.com")[0] == "Primary Application"
    )


def test_build_domain_intel_sections():
    di = build_domain_intel(DATA)
    cls = {h["host"]: h["classification"] for h in di["hosts"]}
    assert cls["api.company.com"] == "Internal API"
    assert cls["api.stripe.com"] == "Payment Provider"
    assert cls["auth.company.com"] == "Authentication Provider"

    # Internal APIs grouped, with role visibility.
    ia = {a["host"]: a for a in di["internal_apis"]}
    assert "api.company.com" in ia and ia["api.company.com"]["count"] == 3
    assert set(ia["api.company.com"]["roles"]) == {"admin", "user"}

    # Third-party = external orgs only (same-org auth.company.com excluded).
    tp = {t["host"] for t in di["third_party"]}
    assert "api.stripe.com" in tp and "www.google-analytics.com" in tp
    assert "auth.company.com" not in tp

    # Auth infra from idp_info.
    assert di["auth_infra"]["identity_provider"] == "Keycloak"

    # High value: admin + user management endpoints.
    labels = {hv["classification"] for hv in di["high_value"]}
    assert {"Admin", "User Management", "Payment"} <= labels

    # Infrastructure summary counts.
    isum = di["infrastructure_summary"]
    assert isum["internal_apis"] == 2  # api.company.com + orders.company.com
    assert isum["auth_providers"] == 1
    assert isum["payment"] == 1


def test_hosts_are_searchable_in_knowledge(memory_db):
    from modules.knowledge.index import build_documents
    from modules.knowledge.query import to_fts_query

    db = memory_db
    tid = db.upsert_target(
        TargetInput(url="https://portal.company.com", domain="portal.company.com")
    )
    db.index_knowledge(tid, build_documents(DATA))

    hits = db.search_knowledge(tid, to_fts_query("third party services"))
    paths = {h["path"] for h in hits}
    assert "api.stripe.com" in paths
    internal = db.search_knowledge(tid, to_fts_query("internal apis"))
    assert any(h["path"] == "api.company.com" for h in internal)


def test_persist_hosts_and_edges(memory_db):
    db = memory_db
    tid = db.upsert_target(
        TargetInput(url="https://portal.company.com", domain="portal.company.com")
    )
    di = build_domain_intel(DATA)
    db.save_hosts(tid, di["hosts"])
    db.save_domain_edges(
        tid,
        [
            {"from_host": "portal.company.com", "to_host": e["to"], "kind": e["kind"]}
            for e in di["relationships"]["edges"]
        ],
    )
    data = db.fetch_all(tid)
    hosts = {h["host"]: h for h in data["hosts"]}
    assert hosts["api.company.com"]["classification"] == "Internal API"
    assert hosts["api.company.com"]["internal"] is True
    assert any(e["to_host"] == "api.stripe.com" for e in data["domain_edges"])
