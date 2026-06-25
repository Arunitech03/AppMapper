"""Feature 1: Secret Discovery Engine.

Scans a content corpus (JS / HTML / JSON / HAR / Burp bodies, storage values) for
exposed secrets, credentials, sensitive data and infrastructure references using a
pattern library. Findings are **masked** — secrets and PII are recorded as type +
location + a masked sample + count, never as full values (consistent with the
platform's discovery-only, never-store-secrets posture).

Output groups: Authentication · API Keys · Sensitive Data · Infrastructure.
Discovery-only: it reads already-captured material and makes no requests.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from models.schemas import IntelFinding
from modules.auth.masking import mask_secret
from modules.intelligence.confidence import HIGH, MEDIUM

# --- pattern library --------------------------------------------------------
# Each entry: (kind, name, category, severity, compiled regex). Values matched by
# these patterns are MASKED before storage.

_PATTERNS: list[tuple] = [
    # ---- API keys / provider credentials ----
    (
        "api_key",
        "Google API Key",
        "API Keys",
        "Informational",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ),
    (
        "api_key",
        "Google OAuth Client ID",
        "API Keys",
        "Informational",
        re.compile(r"\b[0-9]+-[0-9a-z]{32}\.apps\.googleusercontent\.com\b"),
    ),
    (
        "api_key",
        "Firebase Cloud Messaging Key",
        "API Keys",
        "Informational",
        re.compile(r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,}\b"),
    ),
    (
        "api_key",
        "Stripe Secret Key",
        "API Keys",
        "High",
        re.compile(r"\bsk_(?:live|test)_[0-9a-zA-Z]{16,}\b"),
    ),
    (
        "api_key",
        "Stripe Publishable Key",
        "API Keys",
        "Low",
        re.compile(r"\bpk_(?:live|test)_[0-9a-zA-Z]{16,}\b"),
    ),
    ("api_key", "Twilio Account SID", "API Keys", "Medium", re.compile(r"\bAC[0-9a-fA-F]{32}\b")),
    ("api_key", "Twilio API Key", "API Keys", "Medium", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    (
        "api_key",
        "SendGrid API Key",
        "API Keys",
        "High",
        re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ),
    (
        "api_key",
        "Mapbox Token",
        "API Keys",
        "Informational",
        re.compile(r"\b(?:pk|sk)\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
    ),
    ("api_key", "Datadog API Key", "API Keys", "Medium", re.compile(r"\bdd[ap]i_[0-9a-f]{32,}\b")),
    (
        "dsn",
        "Sentry DSN",
        "API Keys",
        "Low",
        re.compile(r"https://[0-9a-f]{16,}@[A-Za-z0-9.\-]+/[0-9]+"),
    ),
    (
        "api_key",
        "AWS Access Key ID",
        "API Keys",
        "High",
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b"),
    ),
    (
        "api_key",
        "Azure Storage Key",
        "API Keys",
        "High",
        re.compile(r"DefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[^;\"']+"),
    ),
    (
        "api_key",
        "Slack Token",
        "API Keys",
        "High",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    ),
    ("api_key", "GitHub Token", "API Keys", "High", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b")),
    (
        "private_key",
        "Private Key Block",
        "API Keys",
        "High",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ),
    # ---- authentication artifacts ----
    (
        "jwt",
        "JWT / Bearer Token",
        "Authentication",
        "Medium",
        re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
    ),
    (
        "oauth_client_secret",
        "OAuth Client Secret",
        "Authentication",
        "High",
        re.compile(r"(?i)client[_\-]?secret[\"'`:=\s]{1,4}([A-Za-z0-9_\-]{16,})"),
    ),
    (
        "pkce",
        "PKCE code_verifier/challenge",
        "Authentication",
        "Low",
        re.compile(r"(?i)code_(?:verifier|challenge)[\"'`:=\s]{1,4}([A-Za-z0-9_\-]{20,})"),
    ),
    (
        "refresh_token",
        "Refresh Token",
        "Authentication",
        "High",
        re.compile(r"(?i)refresh[_\-]?token[\"'`:=\s]{1,4}([A-Za-z0-9._\-]{20,})"),
    ),
    # ---- sensitive data (PII) ----
    (
        "email",
        "Email Address",
        "Sensitive Data",
        "Informational",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "phone",
        "Phone Number",
        "Sensitive Data",
        "Informational",
        re.compile(r"(?<![\w.])(?:\+?\d{1,3}[ .\-]?)?\(?\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}(?![\w])"),
    ),
]

# Capture-group patterns return the secret in group(1); the rest in group(0).
_GROUPED_KINDS = {"oauth_client_secret", "pkce", "refresh_token"}

# Sensitive keys whose *values* (in JSON/JS) signal PII when present as identifiers.
_PII_KEY_RE = re.compile(
    r"(?i)\"(customerId|accountNumber|meterNumber|meterId|deviceId|userName|username|ssn|nationalId)\"\s*:"
)

# Internal hostnames / private IPs (Infrastructure).
_HOST_RE = re.compile(r"\bhttps?://([A-Za-z0-9.\-]+)(?::\d+)?", re.IGNORECASE)
_INTERNAL_HOST_RE = re.compile(
    r"(?i)\b([a-z0-9\-]+\.(?:internal|local|intranet|corp|svc|cluster\.local))\b"
)


def _is_private_ip(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def discover_secrets(corpus: list[dict], *, base_domain: str = "") -> list[IntelFinding]:
    """Scan corpus items ``{url, content_type, source, text}`` for findings.

    De-duplicates by (kind, masked-value, location). Returns masked findings.
    """
    findings: dict[tuple, IntelFinding] = {}

    def add(kind, name, category, severity, raw_value, location, source, *, masked=True):
        value = mask_secret(raw_value) if masked else raw_value
        key = (kind, value, location)
        if key in findings:
            return
        findings[key] = IntelFinding(
            kind=kind,
            category=category,
            name=name,
            value_masked=value,
            location=location,
            source=source,
            confidence=HIGH if kind in {"api_key", "jwt", "private_key", "dsn"} else MEDIUM,
            severity=severity,
        )

    for item in corpus:
        text = item.get("text") or ""
        if not text:
            continue
        location = _short_location(item.get("url", ""))
        source = item.get("source", "")

        for kind, name, category, severity, rx in _PATTERNS:
            for m in rx.finditer(text):
                raw = m.group(1) if (kind in _GROUPED_KINDS and m.groups()) else m.group(0)
                if not raw:
                    continue
                add(kind, name, category, severity, raw, location, source)

        # Infrastructure: internal hostnames + private IPs referenced *as URL hosts*
        # (scanning bare text catches minified-JS artifacts like `fn.local`).
        for host in set(_HOST_RE.findall(text)):
            h = host.lower()
            if _is_private_ip(h):
                add(
                    "internal_ip",
                    "Internal IP Address",
                    "Infrastructure",
                    "Low",
                    h,
                    location,
                    source,
                    masked=False,
                )
            elif _INTERNAL_HOST_RE.fullmatch(h):
                add(
                    "internal_host",
                    "Internal Hostname",
                    "Infrastructure",
                    "Low",
                    h,
                    location,
                    source,
                    masked=False,
                )

        # PII identifier *keys* present (flag exposure; value masked/omitted).
        for m in _PII_KEY_RE.finditer(text):
            field = m.group(1)
            add(
                "pii_field",
                f"PII field: {field}",
                "Sensitive Data",
                "Informational",
                field,
                location,
                source,
                masked=False,
            )

    return sorted(findings.values(), key=lambda f: (f.category, f.name, f.location or ""))


def _short_location(url: str) -> str:
    if not url:
        return ""
    p = urlparse(url)
    return (p.path or url)[:300] or url


def group_findings(findings: list[IntelFinding]) -> dict[str, list[IntelFinding]]:
    """Group findings by category for the report."""
    groups: dict[str, list[IntelFinding]] = {}
    for f in findings:
        groups.setdefault(f.category, []).append(f)
    return groups
