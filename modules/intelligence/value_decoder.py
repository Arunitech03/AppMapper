"""Recursive value decoder (Sprint B6).

Takes an opaque storage value (a cookie / localStorage / sessionStorage string) and
recursively detects and decodes its encodings — JSON, JWT, Base64, URL-encoding, GZIP,
hex, unicode-escape — until no further decode is possible or a depth cap is hit. The
result is a **mask-safe** decode tree: secret and PII leaves are masked, JWTs are
summarized via the (unverified) bearer-token engine, and object keys are always shown.

Discovery/analysis only: pure, offline, no network, no modification. Nothing here ever
emits a raw secret or raw token — masking is applied at every leaf.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import json
import re
from urllib.parse import parse_qs, unquote

from modules.auth.masking import mask_secret
from modules.intelligence.jwt_intelligence import _mask_email, analyze_jwt, find_jwts
from modules.intelligence.secret_discovery import _PATTERNS, _PRIVATE_KEY_RE

# Keys whose values are secret by name (mask regardless of content).
_SECRET_KEY_RE = re.compile(
    r"(?i)(token|secret|password|passwd|pwd|apikey|api[_\-]?key|credential|client[_\-]?secret"
    r"|private[_\-]?key|signature|bearer|pkce|connection[_\-]?string)"
)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]*")
_HEX_RE = re.compile(r"\A(?:[0-9a-fA-F]{2})+\Z")
_B64_RE = re.compile(r"\A[A-Za-z0-9+/=_\-]+\Z")
_PRINTABLE_RE = re.compile(r"\A[\x09\x0a\x0d\x20-\x7e]*\Z")

_MAX_STR = 20_000  # never process/echo more than this many chars


def _is_printable(text: str) -> bool:
    return bool(text) and bool(_PRINTABLE_RE.match(text))


def _looks_secret(value: str) -> bool:
    """True if a scalar value matches a known secret pattern (masks it)."""
    if _PRIVATE_KEY_RE.search(value):
        return True
    for *_meta, rx in _PATTERNS:
        if rx.search(value):
            return True
    return False


def mask_leaf(key: str, value):
    """Mask a decoded scalar leaf: emails, secret-named keys, and secret-looking values.

    Non-sensitive config/identity scalars (URLs, flags, tenant, theme, ids) pass through
    so a tester can read them. Keys are never masked — only values.
    """
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    text = str(value)
    if _EMAIL_RE.fullmatch(text.strip()):
        return _mask_email(text.strip())
    if _JWT_RE.fullmatch(text.strip()):
        return mask_secret(text)
    if _SECRET_KEY_RE.search(key or ""):
        return mask_secret(text)
    if _looks_secret(text):
        return mask_secret(text)
    # Long opaque high-entropy blob with no whitespace -> mask defensively.
    if len(text) > 80 and " " not in text and "\n" not in text:
        return mask_secret(text)
    return text if len(text) <= 400 else text[:400] + "…"


def _mask_json(obj, key: str = ""):
    """Recursively mask a decoded JSON structure (keys shown, secret/PII values masked)."""
    if isinstance(obj, dict):
        return {k: _mask_json(v, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask_json(v, key) for v in obj[:50]]
    return mask_leaf(key, obj)


def _try_gzip(text: str) -> str | None:
    raw = text.encode("latin-1", "ignore")
    if len(raw) < 2 or raw[0] != 0x1F or raw[1] != 0x8B:
        return None
    try:
        return gzip.decompress(raw).decode("utf-8", "ignore")
    except (OSError, EOFError, ValueError):
        return None


def _try_base64(text: str) -> str | None:
    s = text.strip()
    if len(s) < 8 or len(s) % 4 == 1 or not _B64_RE.match(s):
        return None
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None
    # Base64-wrapped GZIP (e.g. a compressed JSON blob) — unwrap in one step.
    if len(raw) >= 2 and raw[0] == 0x1F and raw[1] == 0x8B:
        try:
            return gzip.decompress(raw).decode("utf-8", "ignore") or None
        except (OSError, EOFError, ValueError):
            return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Require the decode to look like text and to actually differ / add signal.
    if not _is_printable(decoded) or decoded == s:
        return None
    return decoded


def _try_hex(text: str) -> str | None:
    s = text.strip()
    if len(s) < 8 or not _HEX_RE.match(s):
        return None
    try:
        decoded = bytes.fromhex(s).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return decoded if _is_printable(decoded) and decoded != s else None


def _try_url(text: str) -> str | None:
    if "%" not in text:
        return None
    decoded = unquote(text)
    return decoded if decoded != text else None


def _try_unicode_escape(text: str) -> str | None:
    if "\\u" not in text and "\\x" not in text:
        return None
    try:
        decoded = codecs.decode(text, "unicode_escape")
    except (UnicodeDecodeError, ValueError):
        return None
    return decoded if decoded != text and _is_printable(decoded) else None


def _sniff(text: str) -> str:
    """Best-effort content-type sniff for a decoded string leaf."""
    s = text.strip()
    if s[:1] in "{[" or s[-1:] in "}]":
        return "JSON"
    if s[:5].lower() == "<?xml" or (s[:1] == "<" and s[-1:] == ">"):
        return "XML/HTML"
    if s[:4].lower() in ("http",) or s[:2] == "//":
        return "URL"
    if "=" in s and "&" in s and " " not in s:
        return "Query String"
    return "Text"


def decode_value(value, *, max_depth: int = 6) -> dict:
    """Recursively decode ``value`` into a mask-safe decode tree.

    Returns ``{original_type, decoded_type, layers:[{type,note,preview}], fields, jwt,
    classification_hint}``. ``fields`` holds masked key/values from the deepest JSON layer
    (useful for identity/config correlation). ``jwt`` is an ``analyze_jwt`` summary when a
    JWT was found (masked, unverified). Everything returned is safe to render directly.
    """
    text = "" if value is None else str(value)
    empty = {
        "original_type": "Empty",
        "decoded_type": "Empty",
        "layers": [],
        "fields": {},
        "jwt": None,
        "classification_hint": None,
    }
    if not text or len(text) > _MAX_STR:
        return empty if not text else {**empty, "original_type": "Large", "decoded_type": "Large"}

    layers: list[dict] = []
    fields: dict = {}
    jwt_summary = None
    classification_hint = None
    original_type = None
    current = text
    depth = 0

    while depth < max_depth:
        depth += 1
        # 1) JWT (a full token, not merely base64) -> summarize + stop recursing it.
        m = _JWT_RE.fullmatch(current.strip())
        if not m:
            found = find_jwts(current)
            m = found[0] if found else None
            if isinstance(m, str):
                jwt_summary = analyze_jwt(m)
        else:
            jwt_summary = analyze_jwt(current.strip())
        if jwt_summary:
            original_type = original_type or "JWT"
            layers.append({"type": "JWT", "note": "decoded (unverified)", "preview": None})
            classification_hint = "Authentication"
            break

        # 2) JSON.
        stripped = current.strip()
        if stripped[:1] in "{[":
            try:
                obj = json.loads(stripped)
            except (ValueError, TypeError):
                obj = None
            if obj is not None:
                original_type = original_type or "JSON"
                masked = _mask_json(obj)
                if isinstance(obj, dict):
                    fields = masked if isinstance(masked, dict) else {}
                layers.append(
                    {
                        "type": "JSON",
                        "note": (
                            f"{len(obj)} keys" if isinstance(obj, dict) else f"{len(obj)} items"
                        ),
                        "preview": json.dumps(masked, indent=2)[:1500],
                    }
                )
                # Recurse into any JWT-looking string values inside the JSON.
                for v in (obj.values() if isinstance(obj, dict) else obj):
                    if isinstance(v, str) and _JWT_RE.fullmatch(v.strip()):
                        jwt_summary = jwt_summary or analyze_jwt(v.strip())
                if jwt_summary:
                    layers.append({"type": "JWT", "note": "nested in JSON", "preview": None})
                    classification_hint = "Authentication"
                break

        # 3) Transform layers — try each; the first that yields new text recurses.
        for name, fn in (
            ("GZIP", _try_gzip),
            ("URL-encoded", _try_url),
            ("Unicode-escaped", _try_unicode_escape),
            ("Base64", _try_base64),
            ("Hex", _try_hex),
        ):
            decoded = fn(current)
            if decoded is not None:
                original_type = original_type or name
                layers.append({"type": name, "note": "decoded", "preview": None})
                current = decoded
                break
        else:
            # No transform applied -> this is a terminal scalar.
            break

    if not layers:
        original_type = original_type or _sniff(text)
        return {
            "original_type": original_type,
            "decoded_type": original_type,
            "layers": [],
            "fields": {},
            "jwt": None,
            "classification_hint": classification_hint,
        }

    decoded_type = "JWT" if jwt_summary else _final_type(layers, current)
    return {
        "original_type": original_type or "Text",
        "decoded_type": decoded_type,
        "layers": layers,
        "fields": fields,
        "jwt": jwt_summary,
        "classification_hint": classification_hint,
    }


def _final_type(layers: list[dict], current: str) -> str:
    for layer in reversed(layers):
        if layer["type"] in ("JSON", "JWT", "XML/HTML"):
            return layer["type"]
    return _sniff(current)


def parse_query_fields(value: str) -> dict:
    """Masked key/values from a ``a=b&c=d`` query-string-style value."""
    try:
        raw = parse_qs(value, keep_blank_values=True)
    except (ValueError, UnicodeDecodeError):
        return {}
    return {k: mask_leaf(k, v[0] if v else "") for k, v in raw.items()}
