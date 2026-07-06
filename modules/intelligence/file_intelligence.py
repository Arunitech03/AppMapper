"""File Upload & Download Intelligence (Sprint B4).

Discovers, classifies and correlates the application's file-handling attack surface —
upload/download endpoints, storage backends, signed URLs, accepted file types, upload/
download components, and pentest opportunities — from **already-captured** data. Pure
derivation over the assembled report: no uploads, payloads, fuzzing, or bypass.

Honest by design: fields the platform doesn't capture passively (uploaded filename,
multipart boundary, request size, response Content-Disposition, file-input accept/multiple,
magic-byte/MIME/virus-scan validation) are reported as "not observed" — never invented.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from modules.auth.masking import redact_url
from modules.intelligence.confidence import HIGH, MEDIUM

# File-type classification (extension -> category).
_FILE_TYPES: dict[str, set[str]] = {
    "Images": {"png", "jpg", "jpeg", "gif", "bmp", "svg", "webp", "ico"},
    "Documents": {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "txt", "rtf"},
    "Archives": {"zip", "rar", "7z", "gz", "tar"},
    "Executables": {"exe", "dll", "apk", "ipa", "jar", "war", "ear"},
    "Scripts": {"php", "jsp", "jspx", "asp", "aspx", "cgi", "py", "pl", "sh", "js"},
    "Configuration": {"json", "xml", "yaml", "yml", "ini", "env", "conf"},
}
_EXT_CATEGORY = {ext: cat for cat, exts in _FILE_TYPES.items() for ext in exts}

# Object-storage / CDN signatures (host substring -> platform).
_STORAGE_SIGS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Azure Blob Storage", ("blob.core.windows.net", "dfs.core.windows.net")),
    ("AWS S3", ("s3.amazonaws.com", ".s3.", "s3-", "s3.dualstack")),
    ("Google Cloud Storage", ("storage.googleapis.com", "storage.cloud.google")),
    ("MinIO", ("minio",)),
    ("CDN", ("cloudfront.net", "akamai", "akamaiedge.net", "fastly.net")),
)

# Path keywords hinting at file handling.
_UPLOAD_HINTS = ("upload", "attachment", "/documents", "/document", "import", "/files", "/media")
_DOWNLOAD_HINTS = (
    "download",
    "export",
    "/report",
    "attachment",
    "/documents",
    "/document",
    "/files",
)

# Response content-types that indicate a file download.
_DL_CONTENT = (
    "application/octet-stream",
    "application/pdf",
    "text/csv",
    "application/zip",
    "application/x-zip",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats",
    "application/msword",
    "image/",
    "application/vnd.android.package",
)

# JavaScript component signals (substring -> label), grouped for the components section.
_JS_UPLOAD = {
    "FormData": ("formdata",),
    "FileReader": ("filereader",),
    "Blob upload": ("createobjecturl", "new blob"),
    "Dropzone": ("dropzone",),
    "Uppy": ("uppy",),
    "Tus (resumable)": ("tus",),
    "FineUploader": ("fineuploader",),
    "Chunked upload": ("chunk", "resumable"),
    "Drag & drop": ("ondrop", "dragover", "drag-drop", "dragdrop"),
}
_JS_DOWNLOAD = {
    "saveAs / blob download": ("saveas", "createobjecturl", "download("),
    "CSV export": ("export", "tocsv", ".csv"),
    "Excel export": ("xlsx", "excel"),
    "PDF export": ("jspdf", "topdf", ".pdf"),
}

_UPLOAD_TESTS = [
    "File Upload Validation",
    "MIME Type Bypass",
    "Magic Byte Bypass",
    "Double Extension",
    "Null Byte Injection",
    "SVG XSS",
    "Archive Upload",
    "Filename Injection",
    "Path Traversal",
    "File Overwrite",
    "Stored XSS",
    "Malware Upload",
    "Race Conditions",
]
_DOWNLOAD_TESTS = [
    "IDOR",
    "Forced Browsing",
    "Authorization",
    "Path Traversal",
    "Temporary URL Abuse",
    "Signed URL Validation",
    "Enumeration",
    "Sensitive File Exposure",
]


def build_file_intelligence(report: dict, data: dict | None = None) -> dict:
    """Build the File Upload & Download Intelligence section (pure, empty-safe)."""
    data = data or {}
    har = (
        data.get("har_requests") or (report.get("captured_traffic") or {}).get("har_requests") or []
    )
    crawl = report.get("crawl_endpoints") or data.get("crawl_endpoints") or []
    forms = report.get("forms") or data.get("forms") or []
    apis = report.get("api_intelligence") or []
    api_specs = report.get("apis") or []
    js = report.get("js_findings") or []
    js_blob = " ".join(str(f.get("value") or "") for f in js).lower()
    services = (report.get("javascript_intelligence") or {}).get("service_inventory") or []

    uploads = _uploads(har, crawl, apis, api_specs, forms)
    downloads = _downloads(har, crawl, apis, api_specs)
    all_urls = (
        [h.get("url") for h in har]
        + [c.get("url") for c in crawl]
        + [f.get("value") for f in js if f.get("kind") in (None, "url")]
    )
    storage = _storage(all_urls, apis)
    signed = _signed_urls(all_urls)
    accepted = _accepted_types(downloads, crawl)
    up_components = _upload_components(forms, js_blob)
    dl_components = _download_components(js_blob, downloads)
    validation = _validation(js_blob)

    for u in uploads:  # attach a storage backend to uploads when one is known
        u["storage"] = storage[0]["platform"] if storage else "—"
    for d in downloads:  # flag downloads that ride a signed URL
        d["signed_url"] = _signed_platform(d.get("_url", "")) or "No"

    findings = _high_value_findings(uploads, downloads, accepted, storage, signed, services)
    summary = {
        "upload_endpoints": len(uploads),
        "download_endpoints": len(downloads),
        "storage_platform": storage[0]["platform"] if storage else "—",
        "signed_urls": len(signed),
        "accepted_type_categories": sum(1 for v in accepted.values() if v),
        "upload_components": len(up_components),
        "download_components": len(dl_components),
        "high_risk_uploads": sum(1 for u in uploads if u.get("_high_risk")),
        "potential_idor_downloads": sum(1 for d in downloads if d.get("_idor")),
    }
    pentest = {}
    if uploads:
        pentest["Upload Functionality"] = _UPLOAD_TESTS
    if downloads or signed:
        pentest["Download Functionality"] = _DOWNLOAD_TESTS

    return {
        "uploads": [_public(u) for u in uploads],
        "downloads": [_public(d) for d in downloads],
        "storage": storage,
        "signed_urls": signed,
        "accepted_types": {k: sorted(v) for k, v in accepted.items() if v},
        "upload_components": up_components,
        "download_components": dl_components,
        "validation": validation,
        "correlation": _correlation(report, uploads, downloads, storage, services),
        "pentest_opportunities": pentest,
        "high_value_findings": findings,
        "summary": summary,
        "developer_points": _developer_points(uploads, downloads, storage, signed, validation),
    }


# --- helpers ---------------------------------------------------------------


def _public(row: dict) -> dict:
    return {k: v for k, v in row.items() if not k.startswith("_")}


def _host(url: str) -> str:
    return urlparse(url or "").netloc.lower()


def _path(url: str) -> str:
    return urlparse(url or "").path or (url or "")


def _ct(headers: dict | None) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == "content-type":
            return (v or "").lower()
    return ""


def _has_auth(headers: dict | None, role: str | None) -> str:
    for k in headers or {}:
        if k.lower() in ("authorization", "cookie"):
            return "Yes"
    if role and role.lower() not in ("anonymous", "none", ""):
        return f"Yes ({role})"
    return "Unknown"


def _uploads(har, crawl, apis, api_specs, forms) -> list[dict]:
    rows: dict[tuple, dict] = {}

    def add(url, method, *, multipart, auth, role, source, confidence):
        path = _path(url)
        key = ((method or "POST").upper(), path)
        row = rows.get(key)
        if row is None:
            row = {
                "_url": url,
                "endpoint": redact_url(url) if "://" in (url or "") else path,
                "method": (method or "POST").upper(),
                "auth": auth,
                "roles": set(),
                "multipart": multipart,
                "accepted_types": "not observed",
                "storage": "—",
                "confidence": confidence,
                "source": source,
            }
            rows[key] = row
        row["multipart"] = row["multipart"] or multipart
        if role:
            row["roles"].add(role)
        if auth != "Unknown" and row["auth"] == "Unknown":
            row["auth"] = auth

    # 1) Browser-observed uploads + multipart HAR requests (strongest signal).
    for c in crawl:
        if c.get("source") == "upload":
            add(
                c.get("url"),
                c.get("method"),
                multipart=True,
                auth=_has_auth(None, c.get("role")),
                role=c.get("role"),
                source="exploration",
                confidence=HIGH,
            )
    for h in har:
        if "multipart/form-data" in _ct(h.get("headers")):
            add(
                h.get("url"),
                h.get("method"),
                multipart=True,
                auth=_has_auth(h.get("headers"), h.get("role")),
                role=h.get("role"),
                source="HAR (multipart)",
                confidence=HIGH,
            )
    # 2) API paths that look like upload endpoints (weaker).
    for a in apis:
        methods = a.get("methods") or ""
        if any(m in str(methods).upper() for m in ("POST", "PUT")) and _hint(
            a.get("path"), _UPLOAD_HINTS
        ):
            host = (a.get("hosts") or "").split(",")[0] if a.get("hosts") else ""
            url = f"https://{host}{a.get('path')}" if host else a.get("path")
            add(
                url,
                str(methods).split(",")[0],
                multipart=False,
                auth="Unknown",
                role=None,
                source="API path",
                confidence=MEDIUM,
            )
    for a in api_specs:
        if (a.get("method") or "").upper() in ("POST", "PUT") and _hint(
            a.get("path"), _UPLOAD_HINTS
        ):
            add(
                a.get("path"),
                a.get("method"),
                multipart=False,
                auth="Unknown",
                role=None,
                source="API spec",
                confidence=MEDIUM,
            )

    for row in rows.values():
        row["_high_risk"] = row["auth"] == "Unknown" or not row["roles"]
    return sorted(rows.values(), key=lambda r: r["endpoint"])


def _downloads(har, crawl, apis, api_specs) -> list[dict]:
    rows: dict[tuple, dict] = {}

    def add(url, *, auth, role, ctype, source, confidence, filename=None):
        path = _path(url)
        key = path
        row = rows.get(key)
        if row is None:
            row = {
                "_url": url,
                "endpoint": redact_url(url) if "://" in (url or "") else path,
                "auth": auth,
                "content_type": ctype or "—",
                "download_type": _download_type(url, ctype, filename),
                "signed_url": "No",
                "confidence": confidence,
                "source": source,
            }
            rows[key] = row
        if role:
            row.setdefault("roles", set()).add(role)

    for c in crawl:
        if c.get("source") == "download":
            add(
                c.get("url"),
                auth=_has_auth(None, c.get("role")),
                role=c.get("role"),
                ctype=c.get("content_type"),
                source="exploration",
                confidence=HIGH,
                filename=c.get("title"),
            )
    for h in har:
        ct = (h.get("response_content_type") or "").lower()
        if any(sig in ct for sig in _DL_CONTENT):
            add(
                h.get("url"),
                auth=_has_auth(h.get("headers"), h.get("role")),
                role=h.get("role"),
                ctype=ct,
                source="HAR response",
                confidence=HIGH,
            )
    for a in apis:
        rt = (a.get("response_types") or "").lower()
        if _hint(a.get("path"), _DOWNLOAD_HINTS) or any(sig in rt for sig in _DL_CONTENT):
            host = (a.get("hosts") or "").split(",")[0] if a.get("hosts") else ""
            url = f"https://{host}{a.get('path')}" if host else a.get("path")
            add(
                url,
                auth="Unknown",
                role=None,
                ctype=rt or None,
                source="API path",
                confidence=MEDIUM,
            )
    for a in api_specs:
        if (a.get("method") or "GET").upper() == "GET" and _hint(a.get("path"), _DOWNLOAD_HINTS):
            add(
                a.get("path"),
                auth="Unknown",
                role=None,
                ctype=None,
                source="API spec",
                confidence=MEDIUM,
            )

    for row in rows.values():
        row["_idor"] = _has_numeric_id(row["_url"]) or row["auth"] == "Unknown"
    return sorted(rows.values(), key=lambda r: r["endpoint"])


def _hint(path: str | None, hints) -> bool:
    low = (path or "").lower()
    return any(h in low for h in hints)


def _has_numeric_id(url: str) -> bool:
    return any(seg.isdigit() for seg in _path(url).split("/") if seg)


def _download_type(url, ctype, filename) -> str:
    low = f"{_path(url)} {ctype or ''} {filename or ''}".lower()
    if "export" in low or "report" in low or "csv" in low or "xls" in low:
        return "Export / Report"
    if (ctype or "").startswith("image/") or _ext(low) in _FILE_TYPES["Images"]:
        return "Image"
    if _ext(low) in _FILE_TYPES["Documents"] or "pdf" in low or "document" in low:
        return "Document"
    if "attachment" in low:
        return "Attachment"
    if "blob" in low or "octet-stream" in (ctype or ""):
        return "Blob"
    return "File"


def _ext(text: str) -> str:
    text = text.split("?")[0].strip()
    return text.rsplit(".", 1)[-1].lower() if "." in text.rsplit("/", 1)[-1] else ""


def _storage(urls, apis) -> list[dict]:
    hosts: dict[str, tuple[str, str]] = {}  # host -> (platform, evidence)
    candidates = [(u, _host(u)) for u in urls if u]
    for a in apis:
        for h in str(a.get("hosts") or "").split(","):
            if h:
                candidates.append((h, h.lower()))
    for _evidence, host in candidates:
        if not host or host in hosts:
            continue
        for platform, sigs in _STORAGE_SIGS:
            if any(s in host for s in sigs):
                hosts[host] = (platform, host)
                break
    out = []
    for host, (platform, evidence) in sorted(hosts.items()):
        out.append(
            {
                "platform": platform,
                "host": host,
                "service": "—",
                "evidence": evidence,
                "confidence": HIGH,
            }
        )
    return out


def _signed_platform(url: str) -> str | None:
    q = urlparse(url or "").query
    if not q:
        return None
    params = {p.split("=", 1)[0].lower() for p in q.split("&") if p}
    if "x-amz-signature" in params or ({"awsaccesskeyid", "signature"} <= params):
        return "AWS"
    if "sig" in params and ({"se", "sp", "sr", "sv"} & params):
        return "Azure SAS"
    if (
        "x-goog-signature" in params
        or "goog-signature" in params
        or ({"googleaccessid", "signature"} <= params)
    ):
        return "Google Cloud Storage"
    return None


def _signed_urls(urls) -> list[dict]:
    out: dict[str, dict] = {}
    for url in urls:
        if not url:
            continue
        platform = _signed_platform(url)
        if not platform:
            continue
        q = parse_qs(urlparse(url).query)
        expiry = (q.get("X-Amz-Expires") or q.get("Expires") or q.get("se") or ["—"])[0]
        key = _path(url)
        out.setdefault(
            key,
            {"url": redact_url(url), "platform": platform, "expiration": expiry},
        )
    return list(out.values())


def _accepted_types(downloads, crawl) -> dict[str, set]:
    cats: dict[str, set] = {c: set() for c in _FILE_TYPES}
    cats["Unknown"] = set()

    def record(text):
        ext = _ext((text or "").lower())
        if not ext:
            return
        cat = _EXT_CATEGORY.get(ext)
        (cats[cat] if cat else cats["Unknown"]).add(ext)

    for d in downloads:
        record(d.get("_url"))
    for c in crawl:
        record(c.get("title"))
        record(c.get("url"))
    return cats


def _upload_components(forms, js_blob) -> dict[str, list[str]]:
    comps: dict[str, list[str]] = {}
    file_inputs = [
        f"{f.get('page_url')} ({fld.split(':', 1)[0]})"
        for f in forms
        for fld in str(f.get("fields") or "").split(",")
        if fld.endswith(":file")
    ]
    if file_inputs:
        comps["HTML file inputs"] = file_inputs[:20]
    for label, sigs in _JS_UPLOAD.items():
        if any(s in js_blob for s in sigs):
            comps[label] = ["JavaScript"]
    return comps


def _download_components(js_blob, downloads) -> dict[str, list[str]]:
    comps: dict[str, list[str]] = {}
    for label, sigs in _JS_DOWNLOAD.items():
        if any(s in js_blob for s in sigs):
            comps[label] = ["JavaScript"]
    exports = [d["endpoint"] for d in downloads if d["download_type"] == "Export / Report"]
    if exports:
        comps["Export endpoints"] = exports[:20]
    return comps


def _validation(js_blob) -> dict:
    client = []
    if "filereader" in js_blob:
        client.append("FileReader (client-side read)")
    if "accept=" in js_blob or ".type" in js_blob or "allowedextensions" in js_blob:
        client.append("extension/MIME check in JS")
    if "maxsize" in js_blob or "max_size" in js_blob or "maxfilesize" in js_blob:
        client.append("size check in JS")
    return {
        "client_side": client or ["not observed"],
        "server_side": "not observable (request/response bodies not captured)",
        "magic_byte": "not observable",
        "virus_scan": "not observed",
    }


def _correlation(report, uploads, downloads, storage, services) -> list[str]:
    if not (uploads or downloads):
        return []
    auth = report.get("auth_intelligence") or {}
    jwt = (report.get("jwt_intelligence") or {}).get("primary") or {}
    provider = (
        (auth.get("authentication_model") or {}).get("model")
        or jwt.get("identity_provider")
        or "Unknown"
    )
    role = (uploads or downloads)[0].get("roles")
    role = sorted(role)[0] if role else "—"
    svc = next(
        (
            s.get("service")
            for s in services
            if any(
                k in (s.get("service") or "").lower()
                for k in ("file", "doc", "attach", "media", "storage", "import", "export")
            )
        ),
        "—",
    )
    lines = []
    if uploads:
        lines.append(f"Upload: {uploads[0]['endpoint']}")
    if downloads:
        lines.append(f"Download: {downloads[0]['endpoint']}")
    lines += [
        f"  ↳ Authentication: {provider}",
        f"  ↳ Role: {role}",
        f"  ↳ Storage backend: {storage[0]['platform'] if storage else '—'}",
        f"  ↳ Internal service: {svc}",
    ]
    return lines


def _high_value_findings(uploads, downloads, accepted, storage, signed, services) -> list[dict]:
    out = []

    def add(sev, title, detail):
        out.append({"severity": sev, "title": title, "detail": detail})

    anon = [u for u in uploads if u["auth"] == "Unknown"]
    if anon:
        add(
            "High",
            "Anonymous / unauthenticated upload endpoint",
            f"{len(anon)} upload endpoint(s) observed without an auth signal: "
            + ", ".join(u["endpoint"] for u in anon[:3]),
        )
    dangerous = {
        e for cat, exts in accepted.items() if cat in ("Executables", "Scripts") for e in exts
    } | (accepted.get("Images", set()) & {"svg"})
    if dangerous and uploads:
        add(
            "High",
            "Executable/script/SVG file types observed",
            "File types that enable code execution or stored XSS: " + ", ".join(sorted(dangerous)),
        )
    if uploads and all("not observed" in u.get("accepted_types", "") for u in uploads):
        add(
            "High",
            "Upload endpoints with no observable validation",
            "No client-side upload validation was observed; server-side validation is not "
            "verifiable from passive capture — test extension/MIME/magic-byte handling manually.",
        )
    idor = [d for d in downloads if d.get("_idor") and _has_numeric_id(d.get("_url", ""))]
    if idor:
        add(
            "Medium",
            "Sequential/numeric document identifiers in downloads",
            f"{len(idor)} download endpoint(s) use numeric IDs — test for IDOR: "
            + ", ".join(d["endpoint"] for d in idor[:3]),
        )
    long_lived = [
        s
        for s in signed
        if str(s.get("expiration", "")).isdigit() and int(s["expiration"]) > 604800
    ]
    if long_lived:
        add(
            "Medium",
            "Long-lived signed download URL",
            f"{len(long_lived)} signed URL(s) valid for > 7 days.",
        )
    if storage:
        add(
            "Medium",
            "Object/blob storage exposed to the browser",
            f"{storage[0]['platform']} referenced from client traffic ({storage[0]['host']}).",
        )
    doc_svc = [
        s
        for s in services
        if any(
            k in (s.get("service") or "").lower()
            for k in ("document", "attachment", "file", "media")
        )
    ]
    if doc_svc:
        add(
            "Medium",
            "Internal document/file service identified",
            "Service(s): " + ", ".join(sorted({s.get("service") for s in doc_svc})[:4]),
        )
    return out


def _developer_points(uploads, downloads, storage, signed, validation) -> list[str]:
    pts = []
    if uploads:
        pts.append("File upload functionality identified.")
    if downloads:
        pts.append("File download functionality identified.")
    if storage:
        pts.append(f"{storage[0]['platform']} detected as a storage backend.")
    if signed:
        pts.append("Signed / temporary URLs observed.")
    if uploads and validation["client_side"] == ["not observed"]:
        pts.append("No client-side upload validation observed.")
    exports = [d for d in downloads if d["download_type"] == "Export / Report"]
    if exports:
        pts.append("Export/report functionality available.")
    if uploads or downloads:
        pts.append("File handling attack surface identified.")
    return pts
