"""Issue 3: Telemetry / monitoring / analytics classifier.

Identifies observability + analytics traffic (Datadog/NewRelic/Sentry/Google
Analytics/Mixpanel/Amplitude/Segment, RUM/replay/intake endpoints) so it can be
excluded from authorization candidates, attack-surface scoring and pentest targets
— and surfaced in its own Telemetry & Monitoring Inventory. Pure/offline.
"""

from __future__ import annotations

from urllib.parse import urlparse

# host substring -> provider/label
_TELEMETRY_HOSTS = {
    "datadoghq.com": "Datadog",
    "datadog": "Datadog",
    "browser-intake": "Datadog",
    "newrelic.com": "New Relic",
    "nr-data.net": "New Relic",
    "sentry.io": "Sentry",
    "ingest.sentry": "Sentry",
    "google-analytics.com": "Google Analytics",
    "googletagmanager.com": "Google Tag Manager",
    "analytics.google": "Google Analytics",
    "mixpanel.com": "Mixpanel",
    "amplitude.com": "Amplitude",
    "segment.io": "Segment",
    "segment.com": "Segment",
    "hotjar.com": "Hotjar",
    "fullstory.com": "FullStory",
    "bugsnag.com": "Bugsnag",
    "logrocket.com": "LogRocket",
}
# path substrings that indicate telemetry even on first-party hosts
_TELEMETRY_PATHS = ("/rum", "/replay", "/intake", "/v2/rum", "/v2/replay", "/collect", "/telemetry")


def classify_telemetry(host: str, path: str) -> str | None:
    """Return the telemetry provider/label for a host+path, or None."""
    h = (host or "").lower()
    for needle, label in _TELEMETRY_HOSTS.items():
        if needle in h:
            return label
    p = (path or "").lower()
    if any(t in p for t in _TELEMETRY_PATHS):
        return "Telemetry / RUM"
    return None


def is_telemetry(url_or_path: str) -> bool:
    """True if a URL or path is telemetry/monitoring/analytics traffic."""
    if "://" in (url_or_path or ""):
        u = urlparse(url_or_path)
        return classify_telemetry(u.hostname or "", u.path or "") is not None
    return classify_telemetry("", url_or_path or "") is not None


def telemetry_inventory(data: dict) -> list[dict]:
    """Distinct telemetry endpoints observed, for the Telemetry Inventory section."""
    seen: dict[str, dict] = {}
    for src in ("har_requests", "burp_requests", "crawl_endpoints"):
        for r in data.get(src, []) or []:
            u = urlparse(r.get("url", ""))
            label = classify_telemetry(u.hostname or "", u.path or "")
            if not label:
                continue
            host = (u.hostname or "").lower()
            key = f"{label}|{host}"
            seen.setdefault(key, {"provider": label, "host": host, "paths": set()})
            if u.path:
                seen[key]["paths"].add(u.path)
    out = [
        {"provider": v["provider"], "host": v["host"], "paths": sorted(v["paths"])[:10]}
        for v in seen.values()
    ]
    out.sort(key=lambda x: (x["provider"], x["host"]))
    return out
