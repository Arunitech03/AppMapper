"""Assemble the content corpus the intelligence engines mine.

Report-time analyzers only receive the stored ``data`` dict (keys-only, no raw
bodies), so content mining (secrets, routes, hidden APIs, config, source maps)
runs at scan time where the capture files are known. This module builds one
in-memory corpus of ``{url, content_type, source, text}`` items from HAR/Burp
response+request bodies and the live JS/HTML corpus — each body capped — which the
engines then scan.

Discovery-only: it reads already-captured material; it makes no requests.
"""

from __future__ import annotations

from pathlib import Path

from core.logging import get_logger

log = get_logger("content")

MAX_BODY = 2_000_000  # per-body scan cap (bytes) — bounds memory on large HARs


def gather_content(
    *,
    har_paths: list[str] | tuple = (),
    burp_paths: list[str] | tuple = (),
    extra: list[dict] | tuple = (),
    max_body: int = MAX_BODY,
) -> list[dict]:
    """Return a corpus of ``{url, content_type, source, text}`` content items.

    ``har_paths`` / ``burp_paths`` are capture files to mine for bodies; ``extra``
    is pre-built corpus items (e.g. the live ``js_analysis`` fetch). All bodies are
    capped at ``max_body`` and binary content is skipped.
    """
    from parsers.burp_parser import parse_burp_bodies
    from parsers.har_parser import parse_har_bodies

    corpus: list[dict] = []
    seen_har: set[str] = set()
    for p in _unique(har_paths):
        rp = str(Path(p).resolve()) if Path(p).exists() else p
        if rp in seen_har:
            continue
        seen_har.add(rp)
        try:
            corpus.extend(parse_har_bodies(p, max_body=max_body))
        except Exception as exc:  # noqa: BLE001 - one bad capture must not abort
            log.warning("content.har_failed", path=str(p), error=str(exc))

    for p in _unique(burp_paths):
        try:
            corpus.extend(parse_burp_bodies(p, max_body=max_body))
        except Exception as exc:  # noqa: BLE001
            log.warning("content.burp_failed", path=str(p), error=str(exc))

    corpus.extend(extra or [])
    log.info("content.gathered", items=len(corpus))
    return corpus


def sibling_har(exploration_path: str) -> str | None:
    """The ``<name>.har`` next to an ``<name>.json`` exploration file, if present."""
    p = Path(exploration_path)
    cand = p.with_suffix(".har")
    return str(cand) if cand.exists() else None


def _unique(paths) -> list[str]:
    out, seen = [], set()
    for p in paths or ():
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out
