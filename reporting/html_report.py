"""HTML report generation.

Renders an executive- and pentester-friendly HTML report: a KPI dashboard, a Critical
Findings banner and an architecture snapshot up top, the insight sections expanded, and
all inventories / dumps / HAR / claims / JavaScript findings present but collapsed under
an "Evidence" divider — with sticky sidebar navigation, severity colors and a light theme.

Section bodies are produced by the Markdown renderer (the linear source of truth) and
reorganized here; the synthesized header components are built from the report dict.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reporting.html_assets import CSS, JS
from reporting.json_report import build_report
from reporting.markdown_report import render_markdown

# Insight sections — rendered expanded, in this order. Matched by title prefix.
# (Critical Findings + Architecture Snapshot are synthesized header components.)
_INSIGHT_ORDER = (
    "Executive Intelligence Summary",
    "Authentication Intelligence",
    "Authentication Token Inventory",
    "JWT Intelligence Deep Dive",
    "User Intelligence",
    "Authentication Artifacts Summary",
    "Role Intelligence",
    "Application Access Summary",
    "Authenticated Crawl Coverage",
    "Authorization Intelligence",
    "Authentication Flow",
    "Authentication Risk Analysis",
    "Passive Subdomain Intelligence",
    "DNS Intelligence",
    "Network Services",
    "Redirect Intelligence",
    "Internal Service Inventory",
    "Secrets & Sensitive Configuration",
    "High Value Pentest Targets",
    "Hidden Functionality",
    "Runtime Intelligence Summary",
    "Response Intelligence",
    "Developer Discussion Points",
    "Application Architecture Summary",
    "Application Summary",
)
_SEVERITIES = {"critical", "high", "medium", "low", "info", "informational"}


# ---------------------------------------------------------------------------
# Markdown -> HTML (small subset converter)
# ---------------------------------------------------------------------------


def _inline(text: str) -> str:
    text = escape(text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    return text


def _md_to_html(md: str) -> str:
    out: list[str] = []
    lines = md.split("\n")
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        if line.startswith("```"):
            block: list[str] = []
            i += 1
            while i < n and not lines[i].startswith("```"):
                block.append(lines[i])
                i += 1
            i += 1
            out.append("<pre><code>" + escape("\n".join(block)) + "</code></pre>")
            continue
        if line.startswith("### "):
            out.append(f"<h3>{_inline(line[4:])}</h3>")
            i += 1
            continue
        if line.startswith("## "):
            out.append(f"<h2>{_inline(line[3:])}</h2>")
            i += 1
            continue
        if line.startswith("# "):
            out.append(f"<h1>{_inline(line[2:])}</h1>")
            i += 1
            continue
        if line.startswith("|"):
            table: list[str] = []
            while i < n and lines[i].startswith("|"):
                table.append(lines[i])
                i += 1
            out.append(_render_table(table))
            continue
        if line.lstrip().startswith("- "):
            items: list[str] = []
            while i < n and lines[i].lstrip().startswith("- "):
                items.append(lines[i].lstrip()[2:])
                i += 1
            out.append("<ul>" + "".join(f"<li>{_inline(it)}</li>" for it in items) + "</ul>")
            continue
        if line.strip():
            out.append(f"<p>{_inline(line)}</p>")
        i += 1
    return "\n".join(out)


_SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
# status text -> (badge css class, emoji)
_STATUS_BADGES = {
    "observed": ("b-observed", "🟢"),
    "yes": ("b-observed", "🟢"),
    "true": ("b-observed", "🟢"),
    "✅": ("b-observed", "🟢"),
    "referenced": ("b-referenced", "🟡"),
    "hidden": ("b-hidden", "🔴"),
    "admin": ("b-admin", "🔴"),
    "write": ("b-write", "🟠"),
    "read": ("b-read", "🔵"),
    "internal": ("b-internal", "🟢"),
    "third party": ("b-thirdparty", "⚪"),
    "third-party": ("b-thirdparty", "⚪"),
}


def _sev_badge(sev: str, label: str | None = None) -> str:
    key = "info" if sev == "informational" else sev
    emoji = _SEV_EMOJI.get(key, "")
    return f'<span class="sev sev-{key}">{emoji} {escape(label or sev.title())}</span>'


def _cell_html(text: str) -> str:
    """Render a table cell, adding severity colors / status badges where recognized."""
    low = text.strip().lower()
    if low == "positive":
        return f'<td><span class="badge b-positive">🟢 {_inline(text)}</span></td>'
    if low in _SEVERITIES:
        return f"<td>{_sev_badge(low, text)}</td>"
    if low in _STATUS_BADGES:
        cls, emoji = _STATUS_BADGES[low]
        return f'<td><span class="badge {cls}">{emoji} {_inline(text or low)}</span></td>'
    return f"<td>{_inline(text)}</td>"


def _render_table(rows: list[str]) -> str:
    parsed = [[c.strip() for c in r.strip().strip("|").split("|")] for r in rows]
    body, header = parsed, None
    if len(parsed) >= 2 and all(set(c) <= set("-: ") for c in parsed[1]):
        header = parsed[0]
        body = parsed[2:]
    html = ['<div class="tablewrap"><table>']
    if header:
        html.append(
            "<thead><tr>" + "".join(f"<th>{_inline(c)}</th>" for c in header) + "</tr></thead>"
        )
    html.append("<tbody>")
    for row in body:
        html.append("<tr>" + "".join(_cell_html(c) for c in row) + "</tr>")
    html.append("</tbody></table></div>")
    return "\n".join(html)


# ---------------------------------------------------------------------------
# Section handling
# ---------------------------------------------------------------------------


def _split_sections(md: str) -> tuple[str, list[tuple[str, str]]]:
    """Return (preamble_md, [(title, body_md)]) splitting at ``## `` headings."""
    lines = md.split("\n")
    preamble: list[str] = []
    sections: list[tuple[str, list[str]]] = []
    cur: list[str] | None = None
    for line in lines:
        if line.startswith("## "):
            sections.append((line[3:].strip(), []))
            cur = sections[-1][1]
        elif cur is None:
            preamble.append(line)
        else:
            cur.append(line)
    return "\n".join(preamble), [(t, "\n".join(b)) for t, b in sections]


def _norm(title: str) -> str:
    return re.sub(r"\s*\(\d+\)\s*$", "", title).strip()


def _slug(title: str) -> str:
    return "s-" + re.sub(r"[^a-z0-9]+", "-", _norm(title).lower()).strip("-")


def _insight_rank(title: str) -> int | None:
    norm = _norm(title)
    for idx, key in enumerate(_INSIGHT_ORDER):
        if norm.startswith(key):
            return idx
    return None


# ---------------------------------------------------------------------------
# Synthesized header components (from the report dict)
# ---------------------------------------------------------------------------


def _kpi_cards(report: dict) -> str:
    ai = report.get("auth_intelligence") or {}
    es = ai.get("exec_summary") or {}
    ei = (report.get("executive_intelligence") or {}).get("summary") or {}
    di = report.get("domain_intelligence") or {}
    cards = [
        ("Applications", es.get("applications") or len(ei.get("applications", [])), "blue"),
        ("Internal Services", len(ei.get("internal_services", [])), "teal"),
        ("Roles", es.get("roles", 0), "purple"),
        ("Admin Roles", es.get("administrative_roles", 0), "orange"),
        ("Secrets", ei.get("secrets", 0), "red"),
        ("Hidden APIs", len(ei.get("hidden_apis", [])), "amber"),
        ("Sensitive Endpoints", len(report.get("sensitive_functions", [])), "red"),
        ("Open Ports", len(report.get("network_services", [])), "teal"),
        ("Third Parties", len(di.get("third_party", [])), "gray"),
    ]
    items = "".join(
        f'<div class="kpi {cls}"><div class="v">{v}</div>'
        f'<div class="l">{escape(label)}</div></div>'
        for label, v, cls in cards
    )
    return (
        '<section id="s-dashboard"><h2>Executive Intelligence Dashboard</h2>'
        f'<div class="kpis">{items}</div></section>'
    )


def _auth_cards(report: dict) -> str:
    """Authentication dashboard cards, prepended to the Authentication Intelligence section."""
    c = (report.get("auth_intelligence") or {}).get("auth_cards") or {}
    if not c:
        return ""
    cards = [
        ("Auth Type", c.get("authentication_type", "—")),
        ("Bearer Tokens", c.get("bearer_tokens", 0)),
        ("Cookies", c.get("cookies", 0)),
        ("Local Storage", c.get("local_storage", 0)),
        ("Session Storage", c.get("session_storage", 0)),
        ("Trusted Apps", c.get("trusted_apps", 0)),
        ("Roles", c.get("roles", 0)),
        ("Admin Roles", c.get("admin_roles", 0)),
    ]
    items = "".join(
        f'<div class="authcard"><div class="v">{escape(str(v))}</div>'
        f'<div class="l">{escape(label)}</div></div>'
        for label, v in cards
    )
    return f'<div class="authcards">{items}</div>'


def _subdomain_cards(report: dict) -> str:
    """Summary cards leading the Passive Subdomain Intelligence section."""
    si = report.get("subdomain_intelligence") or {}
    if not si.get("hosts"):
        return ""
    s = si.get("summary") or {}
    cards = [
        ("Sources Queried", len(si.get("sources_queried") or [])),
        ("Subdomains Found", s.get("subdomains_found", 0)),
        ("Resolved Hosts", s.get("resolved_hosts", 0)),
        ("Internal Services", s.get("internal_services", 0)),
        ("Auth Hosts", s.get("authentication_hosts", 0)),
        ("Gateway Hosts", s.get("gateway_hosts", 0)),
    ]
    items = "".join(
        f'<div class="authcard"><div class="v">{escape(str(v))}</div>'
        f'<div class="l">{escape(label)}</div></div>'
        for label, v in cards
    )
    return f'<div class="authcards">{items}</div>'


_PRIORITY = {"P1": ("🔴 P1", "p1"), "P2": ("🟠 P2", "p2"), "P3": ("🟡 P3", "p3")}


def _pentest_matrix(report: dict) -> str:
    """Pentester Quick Start + ranked prioritization matrix (after the dashboard)."""
    pm = report.get("pentest_matrix") or {}
    rows = pm.get("rows") or []
    if not rows:
        return ""
    qs = pm.get("quick_start") or {}
    qs_cards = [
        ("Authentication", qs.get("authentication", "—")),
        ("JWT Storage", qs.get("jwt_storage", "—")),
        ("Admin Roles", qs.get("admin_roles", 0)),
        ("Hidden APIs", qs.get("hidden_apis", 0)),
        ("Trusted Apps", qs.get("trusted_applications", 0)),
        ("Internal Services", qs.get("internal_services", 0)),
        ("Sensitive Endpoints", qs.get("sensitive_endpoints", 0)),
        ("Highest Risk", qs.get("highest_risk_area", "—")),
    ]
    cards = "".join(
        f'<div class="authcard"><div class="v">{escape(str(v))}</div>'
        f'<div class="l">{escape(label)}</div></div>'
        for label, v in qs_cards
    )
    tests = qs.get("top_recommended_tests") or []
    tests_html = "".join(f"<li>{escape(t)}</li>" for t in tests)
    quick = "<h3>Pentester Quick Start</h3>" f'<div class="authcards">{cards}</div>' + (
        f"<p><strong>Top Recommended Tests</strong></p><ol>{tests_html}</ol>" if tests else ""
    )

    body = [
        '<div class="tablewrap"><table><thead><tr>'
        "<th>Priority</th><th>Area</th><th>Reason</th><th>Evidence</th>"
        "<th>Recommended Tests</th><th>Evidence Section</th></tr></thead><tbody>"
    ]
    for r in rows:
        badge, cls = _PRIORITY.get(r["priority"], ("", ""))
        sec = r.get("section") or ""
        link = f'<a href="#{_slug(sec)}">{escape(sec)}</a>' if sec else "—"
        body.append(
            f'<tr class="{cls}"><td><span class="pbadge {cls}">{badge}</span></td>'
            f'<td><strong>{escape(r["area"])}</strong></td>'
            f'<td>{escape(r["reason"])}</td>'
            f'<td><code>{escape(str(r["evidence"]))}</code></td>'
            f'<td>{escape(", ".join(r["tests"]))}</td>'
            f"<td>{link}</td></tr>"
        )
    body.append("</tbody></table></div>")
    return (
        '<section id="s-pentest-matrix"><h2>Pentest Prioritization Matrix</h2>'
        f'{quick}{"".join(body)}</section>'
    )


def _critical_findings(report: dict) -> str:
    rows = _collect_findings(report)
    if not rows:
        return ""
    panels = "".join(
        f'<div class="panel sev-{sev}"><div class="title">{_sev_badge(sev, sev_label)} '
        f"{_inline(title)}</div>"
        f'<div class="meta"><strong>Why it matters:</strong> {_inline(why)}</div></div>'
        for sev, sev_label, title, why in rows
    )
    return (
        f'<section id="s-critical-findings"><h2>Critical Findings ({len(rows)})</h2>'
        f"{panels}</section>"
    )


def _collect_findings(report: dict) -> list[tuple[str, str, str, str]]:
    """(sev_class, sev_label, title, why) for High/Critical/Medium findings, ranked."""
    ei = report.get("executive_intelligence") or {}
    ai = report.get("auth_intelligence") or {}
    rank = {"critical": 0, "high": 1, "medium": 2}
    out: list[tuple[str, str, str, str]] = []

    for p in ei.get("developer_discussion_points", []):
        sev = (p.get("severity") or "").lower()
        if sev in rank:
            out.append((sev, p["severity"], p.get("title", ""), p.get("detail", "")))
    for s in ei.get("secrets", []):
        sev = (s.get("severity") or "").lower()
        if sev in rank:
            why = f"{s.get('type', 'secret')} · {s.get('location') or s.get('source') or ''}".strip(
                " ·"
            )
            out.append((sev, s["severity"], f"{s.get('type', 'Secret')} exposed", why))
    for r in ai.get("risk_analysis", []):
        title = r.get("title", "")
        sev = (
            "high"
            if any(k in title.lower() for k in ("localstorage", "administrative"))
            else "medium"
        )
        out.append((sev, sev.title(), title, r.get("impact") or r.get("risk") or ""))

    out.sort(key=lambda x: rank.get(x[0], 9))
    return out[:20]


def _architecture_snapshot(report: dict) -> str:
    ai = report.get("auth_intelligence") or {}
    es = ai.get("exec_summary") or {}
    ei = (report.get("executive_intelligence") or {}).get("summary") or {}
    di = report.get("domain_intelligence") or {}
    idp = es.get("identity_provider") or "Identity Provider"
    realm = es.get("realm")
    # (label, colour-class) — each node is a coloured outline box.
    nodes = [("Browser", "n-blue"), (f"{idp}" + (f" (realm {realm})" if realm else ""), "n-purple")]
    if ei.get("internal_services") or di.get("internal_apis"):
        nodes.append(("API Gateway", "n-teal"))
        nodes.append((f"Internal Services ({len(ei.get('internal_services', []))})", "n-green"))
    tp = di.get("third_party", [])
    if tp:
        nodes.append((f"Third Parties ({len(tp)})", "n-gray"))
    flow = '<span class="arr">→</span>'.join(
        f'<span class="node {cls}">{escape(label)}</span>' for label, cls in nodes
    )
    model = escape(str(es.get("authentication_model") or "—"))
    client = escape(str(es.get("client") or "—"))
    extra = (
        f"<p class='muted'>Authentication model: <strong>{model}</strong>"
        f" · Client: <strong>{client}</strong></p>"
    )
    return (
        '<section id="s-architecture"><h2>Architecture Snapshot</h2>'
        f'<div class="flow">{flow}</div>{extra}</section>'
    )


# ---------------------------------------------------------------------------
# Custom insight-section renderers (presentation over existing report fields)
# ---------------------------------------------------------------------------


def _identity_card(report: dict) -> str:
    user = ((report.get("jwt_intelligence") or {}).get("primary") or {}).get("user") or {}
    if not user:
        return ""
    rows = [
        ("Username", user.get("username")),
        ("Display Name", user.get("display_name") or user.get("name")),
        ("Email", user.get("email")),
        ("Locale", user.get("locale")),
        ("Email Verified", user.get("email_verified")),
        ("Subject", user.get("subject")),
    ]
    body = "".join(
        f'<div class="row"><span class="k">{escape(k)}</span>'
        f'<span class="val">{escape(str(v if v is not None else "—"))}</span></div>'
        for k, v in rows
    )
    return f'<div class="idcard">{body}</div>'


def _service_cards(report: dict) -> str:
    services = (report.get("javascript_intelligence") or {}).get("service_inventory") or []
    if not services:
        return ""
    cards = []
    for s in services:
        badges = []
        if s.get("observed"):
            badges.append('<span class="badge b-observed">🟢 Observed</span>')
        if s.get("referenced"):
            badges.append('<span class="badge b-referenced">🟡 Referenced</span>')
        if "config" in (s.get("source") or "").lower():
            badges.append('<span class="badge b-runtime">🔵 Runtime Config</span>')
        cards.append(
            f'<div class="svccard"><div class="name">{escape(s.get("service", "—"))}</div>'
            f'<div class="meta">Host: {escape(s.get("host", "—"))}</div>'
            f'<div class="meta">{escape(s.get("base_url", ""))}</div>'
            f'<div class="meta">Source: {escape(s.get("source", "—"))} · '
            f'Confidence: {escape(str(s.get("confidence", "—")))}</div>'
            f'<div class="badges">{"".join(badges)}</div></div>'
        )
    return f'<div class="svccards">{"".join(cards)}</div>'


def _dev_callouts(report: dict) -> str:
    points = (report.get("executive_intelligence") or {}).get("developer_discussion_points") or []
    if not points:
        return ""
    out = []
    for p in points:
        sev = (p.get("severity") or "info").lower()
        sev = "info" if sev == "informational" else sev
        detail = p.get("detail")
        meta = f'<div class="meta">{_inline(detail)}</div>' if detail else ""
        out.append(
            f'<div class="panel sev-{sev}"><div class="title">{_sev_badge(sev)} '
            f'{_inline(p.get("title", ""))}</div>{meta}</div>'
        )
    return "".join(out)


_SECRET_TIERS = (
    (
        "High-Value Secrets",
        "high",
        (
            "jwt",
            "oauth",
            "api_key",
            "apikey",
            "cloud",
            "credential",
            "password",
            "private_key",
            "aws",
            "database",
            "db_",
        ),
    ),
    ("Medium-Value Secrets", "medium", ("service", "internal", "token", "session")),
)


def _secrets_tiered(report: dict) -> str:
    secrets = (report.get("executive_intelligence") or {}).get("secrets") or []
    if not secrets:
        return ""

    def tier_of(s: dict) -> str:
        t = (s.get("type") or "").lower()
        for _name, key, kws in _SECRET_TIERS:
            if any(k in t for k in kws):
                return key
        return "info"

    groups: dict[str, list] = {"high": [], "medium": [], "info": []}
    for s in secrets:
        groups[tier_of(s)].append(s)

    out = []
    labels = {
        "high": "High-Value Secrets",
        "medium": "Medium-Value Secrets",
        "info": "Informational",
    }
    for key in ("high", "medium", "info"):
        items = groups[key]
        if not items:
            continue
        out.append(f'<div class="tier {key}">{escape(labels[key])} ({len(items)})</div>')
        rows = [
            '<div class="tablewrap"><table><thead><tr><th>Type</th><th>Location</th>'
            "<th>Severity</th><th>Source</th><th>Masked Value</th></tr></thead><tbody>"
        ]
        for s in items:
            sev = (s.get("severity") or "info").lower()
            rows.append(
                f'<tr><td>{_inline(s.get("type", "—"))}</td>'
                f'<td>{_inline(s.get("location") or "—")}</td>'
                f"<td>{_sev_badge(sev, s.get('severity'))}</td>"
                f'<td>{_inline(s.get("source") or "—")}</td>'
                f'<td><code>{_inline(s.get("value_masked") or "—")}</code></td></tr>'
            )
        rows.append("</tbody></table></div>")
        out.append("".join(rows))
    return "".join(out)


def _role_collapse(report: dict) -> str:
    ri = (report.get("auth_intelligence") or {}).get("role_intelligence") or {}
    breakdown = ri.get("application_breakdown") or []
    if not breakdown:
        return ""
    out = []
    # breakdown table
    out.append(
        '<div class="tablewrap"><table><thead><tr><th>Application</th><th>Total</th>'
        "<th>Admin</th><th>Write</th><th>Read</th></tr></thead><tbody>"
    )
    for a in breakdown:
        out.append(
            f'<tr><td>{escape(a["application"])}</td><td>{a["total_roles"]}</td>'
            f'<td>{a["admin_roles"]}</td><td>{a.get("write_roles", 0)}</td>'
            f'<td>{a.get("read_roles", 0)}</td></tr>'
        )
    out.append("</tbody></table></div>")
    # per-app admin roles, collapsible
    out.append("<h3>Administrative Roles by Application</h3>")
    for grp in ri.get("admin_by_app", []):
        roles = grp.get("roles", [])
        items = "".join(f'<span class="badge b-admin">🔴 {escape(r)}</span> ' for r in roles[:60])
        out.append(
            f'<details class="role"><summary>{escape(grp["application"])} '
            f"({len(roles)} admin roles)</summary>"
            f"<div style='padding:.5rem .8rem'>{items}</div></details>"
        )
    sens = ri.get("security_sensitive_roles") or []
    if sens:
        out.append(f"<h3>Security-Sensitive Roles ({len(sens)})</h3>")
        out.append(
            '<div style="margin:.4rem 0">'
            + "".join(f'<span class="badge b-write">{escape(r)}</span> ' for r in sens[:80])
            + "</div>"
        )
    ts = ri.get("test_suggestions") or []
    if ts:
        out.append("<h3>Authorization Test Suggestions</h3><ul>")
        out.extend(
            f"<li><strong>{escape(t['application'])}</strong>: {escape(', '.join(t['tests']))}</li>"
            for t in ts
        )
        out.append("</ul>")
    return "".join(out)


_CUSTOM_SECTIONS = {
    "User Intelligence": _identity_card,
    "Internal Service Inventory": _service_cards,
    # Authentication Flow intentionally falls back to the Markdown monospace tree.
    "Developer Discussion Points": _dev_callouts,
    "Secrets & Sensitive Configuration": _secrets_tiered,
    "Role Intelligence": _role_collapse,
}

# Summary-card blocks prepended (above the markdown body) for designated sections.
_PRE_CARDS = {
    "Authentication Intelligence": _auth_cards,
    "Passive Subdomain Intelligence": _subdomain_cards,
}


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def _js_summary_block(report: dict) -> str:
    js = report.get("javascript_intelligence") or {}
    summ = js.get("summary") or js.get("summary_v2") or {}
    if not summ:
        return ""
    bits = []
    for label, key in (
        ("Files Analyzed", "files_analyzed"),
        ("Internal APIs", "internal_apis"),
        ("Secrets", "secrets"),
        ("Hidden Routes", "hidden_routes"),
    ):
        if key in summ:
            val = summ[key]
            val = len(val) if isinstance(val, list) else val
            bits.append(f"<strong>{val}</strong> {escape(label)}")
    return ("<p>" + " · ".join(bits) + "</p>") if bits else ""


def render_html(data: dict[str, list[dict]], **opts: Any) -> str:
    report = build_report(data, **opts)
    md = render_markdown(data, _report=report, **opts)
    preamble_md, sections = _split_sections(md)

    # Synthesized header components (dashboard → prioritization matrix → critical → architecture).
    header = (
        _kpi_cards(report)
        + _pentest_matrix(report)
        + _critical_findings(report)
        + _architecture_snapshot(report)
    )

    # Classify + order sections.
    insight = sorted(
        ((r, t, b) for t, b in sections if (r := _insight_rank(t)) is not None),
        key=lambda x: x[0],
    )
    evidence = [(t, b) for t, b in sections if _insight_rank(t) is None]

    insight_html: list[str] = []
    for _, title, body in insight:
        norm = _norm(title)
        # Summary cards lead designated sections (Authentication / Passive Subdomain).
        pre = next((fn(report) for key, fn in _PRE_CARDS.items() if norm.startswith(key)), "")
        # Custom presentation renderer for designated sections (falls back to markdown).
        renderer = next((fn for key, fn in _CUSTOM_SECTIONS.items() if norm.startswith(key)), None)
        body_html = (renderer(report) if renderer else "") or _md_to_html(body)
        insight_html.append(
            f'<section id="{_slug(title)}"><h2>{_inline(title)}</h2>{pre}{body_html}</section>'
        )

    js_block = _js_summary_block(report)
    evidence_html: list[str] = [
        '<div class="evidence-divider" id="s-evidence">Evidence — collapsed by default</div>'
    ]
    for title, body in evidence:
        pre = js_block if _norm(title).startswith("JS / Frontend Findings") else ""
        evidence_html.append(
            f'<details class="ev" id="{_slug(title)}">'
            f'<summary class="sec">{_inline(title)}</summary>'
            f'<div class="body">{pre}{_md_to_html(body)}</div></details>'
        )

    nav = _sidebar(insight)
    toolbar = (
        '<div class="toolbar">'
        '<button class="btn" onclick="expandAll()">Expand All Evidence</button>'
        '<button class="btn" onclick="collapseAll()">Collapse All Evidence</button>'
        '<button class="btn" onclick="toggleTheme()">Toggle Theme</button>'
        "</div>"
    )
    main = (
        _md_to_html(preamble_md) + toolbar + header + "".join(insight_html) + "".join(evidence_html)
    )
    return (
        "<!DOCTYPE html><html lang='en' data-theme='light'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>AppMapper Report</title><style>{CSS}</style></head><body>"
        f'<div class="layout"><nav class="side">{nav}</nav><main>{main}</main></div>'
        f"<script>{JS}</script></body></html>"
    )


def _sidebar(insight: list[tuple[int, str, str]]) -> str:
    links = [
        '<div class="brand">AppMapper</div>',
        "<h4>Overview</h4>",
        '<a href="#s-dashboard">Dashboard</a>',
        '<a href="#s-pentest-matrix">Pentest Matrix</a>',
        '<a href="#s-critical-findings">Critical Findings</a>',
        '<a href="#s-architecture">Architecture</a>',
        "<h4>Intelligence</h4>",
    ]
    links += [f'<a href="#{_slug(t)}">{escape(_norm(t))}</a>' for _, t, _b in insight]
    links += [
        '<h4 class="ev">Evidence</h4>',
        '<a href="#s-evidence" class="muted">All evidence</a>',
    ]
    return "".join(links)


def write_html_report(
    data: dict[str, list[dict]],
    output_dir: str | Path,
    *,
    filename: str = "report.html",
    **opts: Any,
) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / filename
    path.write_text(render_html(data, **opts), encoding="utf-8")
    return path
