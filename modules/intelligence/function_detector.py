"""Feature 3: Sensitive function discovery.

A keyword engine that classifies discovered endpoints into pentest-relevant
functional categories (Authentication, User Management, File Handling, Data
Operations, Administrative). Pure/offline analysis over already-discovered paths —
it does not make requests.
"""

from __future__ import annotations

import re

from models.schemas import SensitiveFunction
from modules.intelligence.confidence import level as confidence_level

# category -> {specific label -> [keywords]}.  Specific labels feed the checklist.
CATEGORY_KEYWORDS: dict[str, dict[str, list[str]]] = {
    "Authentication": {
        "Login": ["login", "signin", "logon", "auth"],
        "Logout": ["logout", "signout"],
        "Register": ["register", "signup", "registration"],
        "Password Reset": ["password", "reset", "forgot", "recover", "changepassword"],
        "MFA": ["mfa", "2fa", "otp", "totp", "verify", "verification"],
    },
    "User Management": {
        "Users": ["users", "user", "member", "members", "account", "accounts", "profile"],
        "Roles": ["role", "roles"],
        "Groups": ["group", "groups", "team", "teams"],
        "Permissions": ["permission", "permissions", "acl", "grant"],
    },
    "File Handling": {
        "Upload": ["upload", "import"],
        "Attachment": ["attachment", "attach"],
        "Document": ["document", "documents", "doc", "file", "files", "media"],
        "Avatar": ["avatar", "photo", "image"],
    },
    "Data Operations": {
        "Export": ["export"],
        "Download": ["download", "dload", "dloader"],
        "Report": ["report", "reports"],
        "CSV": ["csv"],
        "PDF": ["pdf"],
        "Excel": ["excel", "xls", "xlsx"],
    },
    "Administrative": {
        "Admin": ["admin", "administrator", "manage", "management", "console"],
        "Settings": ["settings", "setting", "preferences", "preference"],
        "Configuration": ["config", "configuration", "template", "templates"],
        "System": ["system", "sys"],
    },
    "Emergency Response": {
        "Emergency": ["emergency", "emergencyresponse"],
        "Alarm": ["alarm", "alarms"],
        "Alert": ["alert", "alerts"],
        "Incident": ["incident", "incidents"],
    },
    "GIS": {
        "Map": ["map", "maps", "basemap"],
        "Layer": ["layer", "layers"],
        "GeoServer": ["geoserver", "wfs", "wms", "wmts", "arcgis"],
        "Spatial": ["geo", "spatial", "hierarchy"],
    },
}


_CAMEL = re.compile(r"([a-z0-9])([A-Z])")
_NONWORD = re.compile(r"[^A-Za-z0-9]+")


def _normalize(path: str) -> str:
    """Split camelCase and punctuation into space-separated lowercase words.

    ``/File/FileUpload`` -> ``file file upload`` so ``upload`` matches on a word
    boundary without firing inside unrelated words (e.g. ``user`` in ``trueserver``).
    """
    spaced = _CAMEL.sub(r"\1 \2", path)
    return _NONWORD.sub(" ", spaced).strip().lower()


def _matches(path: str, keyword: str) -> bool:
    words = _normalize(path)
    # Whole-word match, allowing an optional trailing plural 's'.
    return re.search(rf"\b{re.escape(keyword)}s?\b", words) is not None


# API-behavior evidence: a real function (not a static doc) shows one of these.
_API_PATH_HINTS = ("/api", "/svc", "/rest", "/graphql", "/v1/", "/v2/", "/v3/")
_CRUD_VERBS = (
    "create",
    "update",
    "delete",
    "insert",
    "upsert",
    "set",
    "fetch",
    "get",
    "save",
    "add",
)
_STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _has_api_evidence(path: str, method: str) -> bool:
    """True if the endpoint shows behavioral (API) evidence, not just a keyword."""
    low = path.lower()
    if method.upper() in _STATE_METHODS:
        return True
    if any(h in low for h in _API_PATH_HINTS):
        return True
    words = _normalize(path).split()
    return any(v in words for v in _CRUD_VERBS)


def detect_functions(endpoints: list[dict]) -> list[SensitiveFunction]:
    """Classify endpoints — evidence-based, static assets excluded (Issues 1+2).

    ``endpoints`` is a list of ``{"path": str, "role": str|None, "method": str}``
    dicts. Static assets (svg/png/css/js/map…) are dropped entirely; a keyword hit
    is ``high`` confidence only with API evidence (state-changing method, API path,
    or a CRUD verb), otherwise ``low`` (keyword-only on a passive document).
    """
    from modules.intelligence.classifiers import is_passive_document, is_static_path

    seen: set[tuple[str, str, str]] = set()
    results: list[SensitiveFunction] = []

    for ep in endpoints:
        path = (ep.get("path") or "").strip()
        if not path or is_static_path(path):
            continue  # static assets are never behavioral functions (Issue 1)
        role = ep.get("role")
        method = ep.get("method") or "GET"
        api_evidence = _has_api_evidence(path, method)
        # A bare .js/.html document with no API evidence is not a function.
        if is_passive_document(path) and not api_evidence:
            continue
        for category, labels in CATEGORY_KEYWORDS.items():
            for label, keywords in labels.items():
                # Evidence-based: collect ALL matched indicators, not just the first.
                hits = [kw for kw in keywords if _matches(path, kw)]
                if not hits:
                    continue
                key = (category, label, path)
                if key in seen:
                    continue
                seen.add(key)
                # Confidence: keyword + API evidence = high; keyword-only = low.
                conf = confidence_level(len(hits) + (1 if api_evidence else 0))
                if not api_evidence:
                    conf = "low"
                results.append(
                    SensitiveFunction(
                        category=category,
                        subcategory=label,
                        endpoint=path,
                        evidence="indicators:"
                        + ",".join(hits)
                        + ("|api-evidence" if api_evidence else "|keyword-only"),
                        confidence=conf,
                        role=role,
                    )
                )
    results.sort(key=lambda r: (r.category, r.subcategory or "", r.endpoint))
    return results
