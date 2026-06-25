"""Redirect Intelligence Engine.

Reconstructs HTTP redirect chains (301/302/303/307/308) from captured traffic and
correlates them with authentication / SSO infrastructure, related internal
applications, and external/third-party services. Surfaces a redirect inventory, a
text flow diagram, the authentication redirect flow, an external redirect summary,
and passive risk flags (open-redirect candidates, cross-domain, third-party).

Pure / offline analysis over already-captured data — it makes no requests and never
follows or probes a redirect. All URLs are redacted at capture time; outputs are
re-redacted defensively.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

from modules.auth.masking import redact_url
from modules.intelligence.domain_classifier import (
    AUTH_HOST_SIGS,
    AUTH_PATH_SIGS,
    classify_host,
    registrable_domain,
)

# Query-param names that typically carry a redirect destination (open-redirect surface).
_REDIRECT_PARAMS = {
    "redirect",
    "redirect_uri",
    "redirecturl",
    "redirect_url",
    "return",
    "returnurl",
    "return_to",
    "returnto",
    "next",
    "url",
    "dest",
    "destination",
    "continue",
    "callback",
    "goto",
    "rurl",
    "target",
}

_MAX_ROWS = 500  # safety cap on inventory size


def build_redirect_intelligence(data: dict) -> dict:
    """Build the redirect-intelligence section from the assembled ``data`` dict."""
    target = data.get("target") or {}
    base_host = (target.get("domain") or _host(target.get("url", ""))).lower()
    base_reg = registrable_domain(base_host) if base_host else ""

    edges = _collect_edges(data)
    chains = _build_chains(edges, base_host, base_reg)

    inventory = [_edge_row(e, base_host, base_reg) for e in edges[:_MAX_ROWS]]
    auth_flow = [c for c in chains if c["is_auth"]]
    external_summary = _external_summary(edges, base_reg)
    flags = _flags(edges, base_host, base_reg)

    summary = {
        "total_redirects": len(edges),
        "total_chains": len(chains),
        "auth_redirects": len(auth_flow),
        "cross_domain": len(flags["cross_domain_redirects"]),
        "third_party": len(flags["third_party_redirects"]),
        "open_redirect_candidates": len(flags["open_redirect_candidates"]),
    }
    return {
        "summary": summary,
        "redirect_inventory": inventory,
        "chains": chains,
        "flow_diagram": [c["nodes"] for c in chains],
        "auth_redirect_flow": auth_flow,
        "external_redirect_summary": external_summary,
        "flags": flags,
    }


# ---------------------------------------------------------------------------
# Edge collection
# ---------------------------------------------------------------------------


def _collect_edges(data: dict) -> list[dict]:
    """One edge per observed redirect hop: ``{from, to, status, role, source}``."""
    edges: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(frm: str, to: str, status, role, source: str) -> None:
        frm, to = redact_url(frm), redact_url(to)
        if not frm or not to or frm == to:
            return
        key = (frm, to)
        if key in seen:
            return
        seen.add(key)
        edges.append({"from": frm, "to": to, "status": status, "role": role, "source": source})

    for r in data.get("har_requests", []) or []:
        if r.get("redirect_url"):
            add(r.get("url", ""), r["redirect_url"], r.get("response_status"), r.get("role"), "HAR")
    for r in data.get("burp_requests", []) or []:
        if r.get("redirect_url"):
            add(
                r.get("url", ""), r["redirect_url"], r.get("response_status"), r.get("role"), "Burp"
            )
    for ep in data.get("crawl_endpoints", []) or []:
        hops = _chain_list(ep.get("redirect_chain"))
        for a, b in zip(hops, hops[1:], strict=False):
            add(a, b, None, ep.get("role"), "crawl")
    return edges


def _chain_list(value) -> list[str]:
    """Crawl ``redirect_chain`` may arrive as a list (in-memory) or JSON text (DB)."""
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            return [str(v) for v in parsed] if isinstance(parsed, list) else []
        except ValueError:
            return []
    return []


# ---------------------------------------------------------------------------
# Chain reconstruction
# ---------------------------------------------------------------------------


def _build_chains(edges: list[dict], base_host: str, base_reg: str) -> list[dict]:
    by_from: dict[str, dict] = {}
    targets: set[str] = set()
    for e in edges:
        by_from.setdefault(e["from"], e)  # first edge wins per source
        targets.add(e["to"])

    roots = [e for e in edges if e["from"] not in targets]
    # Fall back to every edge source if the graph is fully cyclic (no clean root).
    if not roots and edges:
        roots = edges

    chains: list[dict] = []
    emitted: set[tuple[str, ...]] = set()
    for root in roots:
        hops = [root["from"]]
        role = root.get("role")
        cur = root
        visited = {root["from"]}
        while cur is not None:
            hops.append(cur["to"])
            role = role or cur.get("role")
            nxt = by_from.get(cur["to"])
            if nxt is None or nxt["to"] in visited:
                break
            visited.add(cur["to"])
            cur = nxt
        key = tuple(hops)
        if key in emitted:
            continue
        emitted.add(key)
        chains.append(_describe_chain(hops, role, base_host, base_reg))
    return chains


def _describe_chain(hops: list[str], role, base_host: str, base_reg: str) -> dict:
    terminal = hops[-1]
    thost, tpath = _host(terminal), _path(terminal)
    is_auth = any(_is_auth(_host(u), _path(u)) for u in hops)
    classification, _ = classify_host(thost, {tpath}, base_host)
    cross_domain = bool(base_reg) and bool(thost) and registrable_domain(thost) != base_reg

    if is_auth:
        purpose = _auth_purpose(hops)
        confidence = "High"
        lands_on = "Login Page"
    elif cross_domain:
        # Different registrable domain — an external / third-party hand-off.
        purpose = "External Service"
        confidence = "Medium"
        lands_on = "External Site"
    elif thost and thost != base_host.lower():
        # Same org, different host — a related internal application.
        purpose = "Related Application"
        confidence = "Medium"
        lands_on = None
    else:
        purpose = "Internal Redirect"
        confidence = "Low"
        lands_on = None

    nodes = list(hops)
    if lands_on:
        nodes.append(lands_on)
    return {
        "source_url": hops[0],
        "target_host": thost,
        "hops": hops,
        "nodes": nodes,
        "purpose": purpose,
        "confidence": confidence,
        "classification": classification,
        "is_auth": is_auth,
        "cross_domain": cross_domain,
        "role": role,
    }


# ---------------------------------------------------------------------------
# Correlation helpers
# ---------------------------------------------------------------------------


def _is_auth(host: str, path: str) -> bool:
    if any(sig.lstrip(".") in host for sig in AUTH_HOST_SIGS):
        return True
    return any(p in path for p in AUTH_PATH_SIGS)


def _auth_purpose(hops: list[str]) -> str:
    blob = " ".join(f"{_host(u)} {_path(u)}" for u in hops).lower()
    if "keycloak" in blob or "/realms/" in blob or "/auth/realms/" in blob:
        return "Keycloak Authentication"
    if "/openid-connect/" in blob or "/oauth2/" in blob:
        return "OIDC/OAuth2 SSO"
    if "/saml" in blob or "/adfs/" in blob:
        return "SAML SSO"
    return "Authentication"


def _edge_row(e: dict, base_host: str, base_reg: str) -> dict:
    thost, tpath = _host(e["to"]), _path(e["to"])
    classification, _ = classify_host(thost, {tpath}, base_host)
    return {
        "source_url": e["from"],
        "status": e["status"],
        "target_url": e["to"],
        "target_host": thost,
        "classification": classification,
        "purpose": _auth_purpose([e["to"]]) if _is_auth(thost, tpath) else classification,
        "confidence": "High" if _is_auth(thost, tpath) else "Medium",
        "cross_domain": bool(base_reg) and registrable_domain(thost) != base_reg,
        "role": e.get("role"),
        "source": e["source"],
    }


def _external_summary(edges: list[dict], base_reg: str) -> list[dict]:
    """Per external (cross-domain) target host: count, classification, sample paths."""
    groups: dict[str, dict] = {}
    for e in edges:
        thost, tpath = _host(e["to"]), _path(e["to"])
        if not thost or (base_reg and registrable_domain(thost) == base_reg):
            continue
        g = groups.setdefault(
            thost,
            {
                "host": thost,
                "registrable_domain": registrable_domain(thost),
                "classification": classify_host(thost, {tpath}, "")[0],
                "count": 0,
                "paths": [],
                "is_auth": _is_auth(thost, tpath),
            },
        )
        g["count"] += 1
        if tpath not in g["paths"] and len(g["paths"]) < 8:
            g["paths"].append(tpath)
    return sorted(groups.values(), key=lambda x: (-x["count"], x["host"]))


def _flags(edges: list[dict], base_host: str, base_reg: str) -> dict:
    cross_domain: list[dict] = []
    third_party: list[dict] = []
    open_candidates: list[dict] = []
    seen_open: set[str] = set()

    for e in edges:
        thost, tpath = _host(e["to"]), _path(e["to"])
        is_cross = bool(base_reg) and thost and registrable_domain(thost) != base_reg
        classification, _ = classify_host(thost, {tpath}, base_host)
        if is_cross:
            cross_domain.append(
                {"source_url": e["from"], "target_url": e["to"], "target_host": thost}
            )
            if classification == "Third Party Service":
                third_party.append(
                    {"source_url": e["from"], "target_url": e["to"], "target_host": thost}
                )
        # Open-redirect candidate (PASSIVE): a redirect-bearing query param on the
        # source whose redirect crosses to another registrable domain. Flag only —
        # AppMapper never actively tests the redirect.
        params = {p.lower() for p in parse_qs(urlparse(e["from"]).query)}
        risky = sorted(params & _REDIRECT_PARAMS)
        if risky and is_cross and e["from"] not in seen_open:
            seen_open.add(e["from"])
            open_candidates.append(
                {
                    "source_url": e["from"],
                    "target_url": e["to"],
                    "parameters": risky,
                    "note": "Redirect destination appears parameter-controlled and crosses domains "
                    "(candidate only — not tested).",
                }
            )
    return {
        "open_redirect_candidates": open_candidates,
        "cross_domain_redirects": cross_domain,
        "third_party_redirects": third_party,
    }


def _host(url: str) -> str:
    return (urlparse(url or "").hostname or "").lower()


def _path(url: str) -> str:
    return urlparse(url or "").path or "/"
