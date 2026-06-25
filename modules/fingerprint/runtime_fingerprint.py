"""Option A: browser-runtime technology fingerprinting (Playwright, optional).

Boots the page in a real (headless) browser so a client-rendered SPA fully loads,
then inspects the **live runtime** — JS globals, React fibers on DOM nodes, lit/
core-js version registries, Tailwind `--tw-` CSS variables, service worker — the
same evidence a browser extension like Wappalyzer uses. This closes the gap that
static fetching and bundle scanning leave (lazy-loaded chunks, Tailwind utility
CSS, runtime-only globals).

Discovery-only: it loads and observes the page (optionally with a captured
session so authenticated SPAs fully boot). It runs no exploits and changes nothing.
"""

from __future__ import annotations

from pathlib import Path

from core.logging import get_logger
from modules.auth.playwright_auth import INSTALL_HINT, PlaywrightNotInstalled

log = get_logger("runtime_fp")

# The in-page detection script (kept in a .js file so it stays readable/lintable).
_DETECT_JS = (Path(__file__).parent / "runtime_detect.js").read_text(encoding="utf-8")

_EMPTY = {"frontend": [], "libraries": [], "versions": {}, "evidence": [], "scripts": []}


def detect_in_page(page) -> dict:
    """Run the runtime detection script on an already-open Playwright page.

    Best-effort: returns the empty shape if the page is gone or evaluation fails.
    Lets callers that already have an authenticated browser (the explorer / capture)
    fingerprint the live app without launching a second browser.
    """
    try:
        return page.evaluate(_DETECT_JS)
    except Exception as exc:  # noqa: BLE001
        log.debug("runtime_fp.in_page_failed", error=str(exc))
        return dict(_EMPTY)


def fingerprint_runtime(
    url: str,
    *,
    storage_state: str | None = None,
    headless: bool = True,
    nav_timeout_ms: int = 60000,
    settle_ms: int = 4000,
) -> dict:
    """Boot the page in a browser and return runtime-detected technologies.

    ``storage_state``: optional Playwright storage_state path so an authenticated
    SPA fully boots (and doesn't bounce to the IdP login). Raises
    :class:`PlaywrightNotInstalled` if Playwright is unavailable.
    """
    try:
        from playwright.sync_api import TimeoutError as PWTimeout
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # noqa: BLE001
        raise PlaywrightNotInstalled(INSTALL_HINT) from exc

    result = {"frontend": [], "libraries": [], "versions": {}, "evidence": [], "scripts": []}
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=headless)
        except Exception as exc:  # noqa: BLE001
            raise PlaywrightNotInstalled(INSTALL_HINT) from exc
        ctx_kwargs = {"storage_state": storage_state} if storage_state else {}
        context = browser.new_context(**ctx_kwargs)
        page = context.new_page()
        page.set_default_navigation_timeout(nav_timeout_ms)
        try:
            page.goto(url, wait_until="domcontentloaded")
        except PWTimeout:
            pass
        # Let the SPA boot + load lazy chunks (core-js, etc.).
        try:
            page.wait_for_load_state("networkidle", timeout=settle_ms)
        except PWTimeout:
            pass
        page.wait_for_timeout(settle_ms)
        result = detect_in_page(page)
        try:
            context.close()
            browser.close()
        except Exception:  # noqa: BLE001
            pass
    log.info(
        "runtime_fp.done",
        frontend=result.get("frontend"),
        libraries=result.get("libraries"),
    )
    return result
