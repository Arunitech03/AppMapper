"""Manual browser-session capture via Playwright (optional dependency).

Launches a real browser so the user can complete ANY login flow by hand —
Keycloak, OAuth/OIDC, SAML, Azure AD/Entra, Okta, Auth0, social login, including
MFA — then saves the resulting authenticated browser state with Playwright's
``storage_state()`` for later reuse.

Playwright is an OPTIONAL dependency: this module imports it lazily and raises a
clear, actionable error when it is not installed. AppMapper never automates the
IdP/MFA flow itself — the human authenticates; we only persist the resulting state.
"""

from __future__ import annotations

from pathlib import Path

INSTALL_HINT = (
    "Playwright is required for `auth capture`. Install it with:\n"
    "    pip install playwright\n"
    "    playwright install chromium"
)


class PlaywrightNotInstalled(RuntimeError):
    """Raised when Playwright (or its browser) is unavailable."""


def is_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401

        return True
    except Exception:  # noqa: BLE001
        return False


def capture(
    role: str,
    url: str,
    out_path: str | Path,
    *,
    prompt=input,
    headless: bool = False,
    nav_timeout_ms: int = 60000,
) -> Path:
    """Open a browser, let the user log in, then save the session state.

    Parameters
    ----------
    role: label for the captured session (used in the default filename).
    url: application URL to open.
    out_path: where to write the storage_state JSON.
    prompt: callable used to wait for the user (overridable for tests).
    headless: run without a visible window (for headless/CI contexts; manual login
        normally needs a visible browser, so the default is headed).

    Returns the path written. Raises :class:`PlaywrightNotInstalled` if Playwright
    is missing.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # noqa: BLE001
        raise PlaywrightNotInstalled(INSTALL_HINT) from exc

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=headless)
        except Exception as exc:  # noqa: BLE001 - browser binary not installed
            raise PlaywrightNotInstalled(INSTALL_HINT) from exc
        context = browser.new_context()
        page = context.new_page()
        # Wait only for the DOM (SPAs/OIDC redirects rarely reach a quiet "load")
        # and tolerate a slow first paint — the browser stays open to log in.
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

        page.set_default_navigation_timeout(nav_timeout_ms)
        try:
            page.goto(url, wait_until="domcontentloaded")
        except PlaywrightTimeoutError:
            pass
        prompt(
            f"\nA browser window opened for role '{role}'.\n"
            "Log in (IdP / MFA / SSO all supported), reach the authenticated app, "
            "then press Enter here to save the session...\n"
        )
        # Fingerprint the live authenticated app's runtime stack while we're here.
        from modules.fingerprint.runtime_fingerprint import detect_in_page

        tech = detect_in_page(page)
        detected = (tech.get("frontend") or []) + (tech.get("libraries") or [])
        if detected:
            print(f"Detected technologies: {', '.join(detected)}")
        context.storage_state(path=str(out))
        browser.close()

    return out
