"""Shared path classifiers used across the intelligence modules.

Centralizes the "is this a static asset?" decision so static resources are never
classified as attack surface, authorization candidates, or pentest targets
(Sprint A.5, Issue 1). Pure/offline.
"""

from __future__ import annotations

from urllib.parse import urlparse

# Static-asset file extensions (Issue 1). Anything ending in one of these is a
# resource, never application behavior.
STATIC_EXTENSIONS = (
    ".svg",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".bmp",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".css",
    ".scss",
    ".map",
    ".mp4",
    ".webm",
    ".mp3",
    ".wasm",
)
# Static document/script extensions that are only attack surface with behavioral
# evidence (a bare .js/.html bundle path is not, by itself, a function).
_PASSIVE_DOC_EXTENSIONS = (".js", ".mjs", ".html", ".htm")


def _path_of(value: str) -> str:
    """Path component of a URL or a bare path."""
    if "://" in (value or ""):
        return urlparse(value).path or "/"
    return (value or "").split("?", 1)[0].split("#", 1)[0]


def is_static_path(value: str) -> bool:
    """True if the path/URL is a static asset (image/font/style/map/media)."""
    return _path_of(value).lower().endswith(STATIC_EXTENSIONS)


def is_passive_document(value: str) -> bool:
    """True for raw .js/.html bundle paths (functions only with API evidence)."""
    return _path_of(value).lower().endswith(_PASSIVE_DOC_EXTENSIONS)


def is_noise_path(value: str) -> bool:
    """Static asset OR passive document — excluded from attack-surface ranking."""
    return is_static_path(value) or is_passive_document(value)
