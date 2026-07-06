"""Tests for File Upload & Download Intelligence (Sprint B4)."""

from __future__ import annotations

from modules.intelligence.file_intelligence import build_file_intelligence


def _report():
    return {
        "auth_intelligence": {"authentication_model": {"model": "Hybrid"}},
        "jwt_intelligence": {"primary": {"identity_provider": "Keycloak"}},
        "crawl_endpoints": [
            {
                "role": "user",
                "url": "https://app.example.com/api/attachments",
                "method": "POST",
                "source": "upload",
            },
            {
                "role": "user",
                "url": "https://app.example.com/api/documents/123/download",
                "method": "GET",
                "source": "download",
                "title": "report.pdf",
                "content_type": "application/pdf",
            },
        ],
        "forms": [
            {
                "role": "user",
                "page_url": "https://app.example.com/upload",
                "action": "/api/upload",
                "method": "POST",
                "fields": "title:text,file1:file",
            }
        ],
        "api_intelligence": [
            {"path": "/api/v1/import", "methods": "POST", "hosts": "app.example.com"},
            {
                "path": "/api/v1/export",
                "methods": "GET",
                "response_types": "text/csv",
                "hosts": "app.example.com",
            },
        ],
        "apis": [],
        "js_findings": [
            {"kind": "interesting_string", "value": "new FormData()", "source": "app.js"},
            {
                "kind": "interesting_string",
                "value": "Dropzone.autoDiscover=false",
                "source": "app.js",
            },
            {
                "kind": "url",
                "value": "https://acct.blob.core.windows.net/c/x?sv=2021&sig=abc&se=2030-01-01",
                "source": "app.js",
            },
        ],
        "javascript_intelligence": {
            "service_inventory": [
                {"service": "document-service", "host": "app.example.com", "observed": True}
            ]
        },
    }


def _data():
    return {
        "har_requests": [
            {
                "url": "https://app.example.com/api/upload",
                "method": "POST",
                "headers": {"Content-Type": "multipart/form-data; boundary=x"},
                "role": "user",
            },
            {
                "url": "https://files.example.com/download/report.pdf"
                "?X-Amz-Signature=abc&X-Amz-Expires=999999&X-Amz-Credential=y",
                "method": "GET",
                "response_content_type": "application/pdf",
                "role": "user",
            },
        ]
    }


def _by_endpoint(rows):
    return {r["endpoint"]: r for r in rows}


def test_upload_detection():
    fi = build_file_intelligence(_report(), _data())
    ups = _by_endpoint(fi["uploads"])
    # multipart HAR + source=upload crawl + api import path all detected
    assert any(p.endswith("/api/upload") for p in ups)
    assert any(p.endswith("/api/attachments") for p in ups)
    assert any("/api/v1/import" in p for p in ups)
    up = next(u for u in fi["uploads"] if u["endpoint"].endswith("/api/upload"))
    assert up["multipart"] is True
    assert fi["summary"]["upload_endpoints"] == 3


def test_download_detection_and_type():
    fi = build_file_intelligence(_report(), _data())
    dls = fi["downloads"]
    exp = next(d for d in dls if "/api/v1/export" in d["endpoint"])
    assert exp["download_type"] == "Export / Report"
    # the signed download rides an AWS presigned URL
    signed_dl = next(d for d in dls if "/download/report.pdf" in d["endpoint"])
    assert signed_dl["signed_url"] == "AWS"


def test_storage_and_signed_urls():
    fi = build_file_intelligence(_report(), _data())
    assert fi["storage"] and fi["storage"][0]["platform"] == "Azure Blob Storage"
    platforms = {s["platform"] for s in fi["signed_urls"]}
    assert "AWS" in platforms and "Azure SAS" in platforms
    aws = next(s for s in fi["signed_urls"] if s["platform"] == "AWS")
    assert aws["expiration"] == "999999"


def test_accepted_types_and_components():
    fi = build_file_intelligence(_report(), _data())
    assert "pdf" in fi["accepted_types"].get("Documents", [])
    comps = fi["upload_components"]
    assert "FormData" in comps and "Dropzone" in comps and "HTML file inputs" in comps


def test_high_value_findings():
    fi = build_file_intelligence(_report(), _data())
    titles = " ".join(f["title"] for f in fi["high_value_findings"])
    assert "Anonymous" in titles  # /api/v1/import has no auth signal
    assert "Sequential" in titles  # /api/documents/123/download
    assert "storage exposed" in titles
    assert any(f["severity"] == "High" for f in fi["high_value_findings"])


def test_correlation_and_pentest():
    fi = build_file_intelligence(_report(), _data())
    corr = "\n".join(fi["correlation"])
    assert "Upload:" in corr and "Storage backend: Azure Blob Storage" in corr
    assert "Upload Functionality" in fi["pentest_opportunities"]
    assert "MIME Type Bypass" in fi["pentest_opportunities"]["Upload Functionality"]


def test_empty_report_safe():
    fi = build_file_intelligence({})
    assert fi["uploads"] == [] and fi["downloads"] == []
    assert fi["summary"]["upload_endpoints"] == 0
