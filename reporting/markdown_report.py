"""Markdown report generation.

Renders the same dataset as the JSON report into a human-readable Markdown
document with the required sections.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reporting.json_report import build_report


def render_markdown(
    data: dict[str, list[dict]], *, _report: dict | None = None, **opts: Any
) -> str:
    report = _report if _report is not None else build_report(data, **opts)
    target = report["target"]
    lines: list[str] = []

    def h(level: int, text: str) -> None:
        lines.append(f"{'#' * level} {text}\n")

    h(1, "Attack Surface Assessment Report")
    lines.append(f"- **Target URL:** {target.get('url', 'n/a')}")
    lines.append(f"- **Domain:** {target.get('domain', 'n/a')}")
    lines.append(f"- **Generated:** {report['generated_at']}\n")

    # Intelligence-first front matter — the "first two pages" (sections 1-6).
    _render_executive_intelligence(report, h, lines)

    # File Upload & Download Intelligence (high-value attack surface, kept prominent).
    _render_file_intelligence(report, h, lines)

    # Application Summary + Pentest Checklist (page 3-4, right after the summary).
    _render_summary_and_checklist(report, h, lines)

    # ----- Detailed inventories (after the intelligence summary) -----
    h(2, "Scan Metrics")
    lines.append("| Category | Count |")
    lines.append("| --- | ---: |")
    for key, value in report["executive_summary"].items():
        lines.append(f"| {key.replace('_', ' ').title()} | {value} |")
    lines.append("")

    # Technology Stack
    h(2, "Technology Stack")
    stack = report["technology_stack"]
    lines.append(f"- **Frontend:** {', '.join(stack['frontend']) or '—'}")
    lines.append(f"- **Backend:** {', '.join(stack['backend']) or '—'}")
    lines.append(f"- **Servers:** {', '.join(stack['servers']) or '—'}")
    lines.append(f"- **Libraries:** {', '.join(stack.get('libraries', [])) or '—'}\n")

    # Discovered Assets
    h(2, "Discovered Assets")
    subs = report["discovered_assets"]["subdomains"]
    h(3, f"Subdomains ({len(subs)})")
    if subs:
        lines.append("| Subdomain | Resolved | IPs |")
        lines.append("| --- | :---: | --- |")
        for s in subs:
            resolved = "✅" if s["resolved"] else "—"
            ips = s.get("ip_addresses") or ""
            lines.append(f"| {s['name']} | {resolved} | {ips} |")
    else:
        lines.append("_None found._")
    lines.append("")

    dirs = report["discovered_assets"]["directories"]
    h(3, f"Directories & Files ({len(dirs)})")
    if dirs:
        lines.append("| Path | Status | Type | Category | Confidence | Validation |")
        lines.append("| --- | ---: | --- | --- | --- | --- |")
        for d in dirs:
            conf = d.get("confidence") or "—"
            mark = " ⚠️" if conf == "low" else ""
            lines.append(
                f"| {d['path']} | {d['status_code']} | "
                f"{(d.get('content_type') or '').split(';')[0]} | {d['category']} | "
                f"{conf}{mark} | {d.get('validation') or '—'} |"
            )
        if any((d.get("confidence") == "low") for d in dirs):
            lines.append("")
            lines.append(
                "_⚠️ low-confidence entries are likely SPA catch-all fallbacks "
                "(HTML returned for a non-HTML path), not genuinely exposed files._"
            )
    else:
        lines.append("_None found._")
    lines.append("")

    # APIs
    h(2, f"APIs ({len(report['apis'])})")
    if report["apis"]:
        lines.append("| Method | Path | Source | Parameters |")
        lines.append("| --- | --- | --- | --- |")
        for a in report["apis"]:
            lines.append(
                f"| {a['method']} | {a['path']} | {a['source']} | {a.get('parameters') or ''} |"
            )
    else:
        lines.append("_No API specifications discovered._")
    lines.append("")

    # SSL Findings
    h(2, f"SSL Findings ({len(report['ssl_findings'])})")
    if report["ssl_findings"]:
        for f in report["ssl_findings"]:
            lines.append(f"### {f['host']}:{f['port']} — severity: **{f['severity']}**")
            lines.append(f"- Issuer: {f.get('issuer')}")
            lines.append(f"- Valid: {f.get('not_before')} → {f.get('not_after')}")
            lines.append(
                f"- Expired: {f.get('is_expired')} · Self-signed: {f.get('is_self_signed')}"
            )
            lines.append(f"- TLS versions: {f.get('tls_versions')}")
            lines.append(f"- SAN: {f.get('san_entries')}")
            lines.append(f"- Summary: {f.get('summary')}\n")
    else:
        lines.append("_No SSL findings (target may be HTTP-only or unreachable)._")
    lines.append("")

    # Network Services
    h(2, f"Network Services ({len(report['network_services'])})")
    if report["network_services"]:
        lines.append("| Port | Proto | Service | Version |")
        lines.append("| ---: | --- | --- | --- |")
        for n in report["network_services"]:
            svc = n.get("service") or ""
            ver = n.get("version") or ""
            lines.append(f"| {n['port']} | {n['protocol']} | {svc} | {ver} |")
    else:
        lines.append("_No service-discovery results (nmap not run or unavailable)._")
    lines.append("")

    # Enterprise authentication overview + session inventory
    _render_auth(report, h, lines)

    # Authentication Redirect Flow + redirect risk flags (front-matter summary)
    _render_redirect_summary(report, h, lines)

    # Roles & access comparison
    _render_access(report, h, lines)

    # Authenticated crawl coverage (flags form-login roles with no post-login pages)
    _render_crawl_coverage(report, h, lines)

    # Passive Subdomain Intelligence (multi-source enumeration + correlation)
    _render_subdomain_intelligence(report, h, lines)

    # DNS Intelligence & Infrastructure Discovery
    _render_dns_intelligence(report, h, lines)

    # External domain intelligence & API relationship mapping
    _render_domain(report, h, lines)

    # Unified asset intelligence (services, gateway, modules, deps, response intel...)
    _render_asset_intel(report, h, lines)

    # Pentester guidance: authorization candidates + phased attack plan
    _render_pentest_guidance(report, h, lines)

    # Redirect Intelligence — inventory, flow diagram, external summary, flags
    _render_redirect_intel(report, h, lines)

    # Sprint B.1: JavaScript / runtime-config intelligence
    _render_javascript_intel(report, h, lines)

    # Sprint B: browser-resident intelligence
    _render_browser_intel(report, h, lines)

    # Sprint A.5: precision — recon summary, sensitive data, risk ranking, targets
    _render_precision(report, h, lines)

    # Sprint A: secret discovery & hidden-endpoint intelligence
    _render_recon_intelligence(report, h, lines)

    # Tier 2 intelligence sections
    _render_tier2(report, h, lines)

    # JS Findings
    h(2, f"JS / Frontend Findings ({len(report['js_findings'])})")
    js = report["js_findings"]
    if js:
        by_kind: dict[str, list[str]] = {}
        for item in js:
            by_kind.setdefault(item["kind"], []).append(item["value"])
        for kind, values in sorted(by_kind.items()):
            h(3, f"{kind} ({len(values)})")
            for v in values[:50]:
                lines.append(f"- `{v}`")
            lines.append("")
    else:
        lines.append("_No interesting strings extracted._")
    lines.append("")

    return "\n".join(lines)


def _render_executive_intelligence(report: dict, h, lines: list[str]) -> None:
    """Intelligence-first front matter: the first two pages (sections 1-6)."""
    ei = report.get("executive_intelligence") or {}
    s = ei.get("summary", {})
    if not s:
        return

    # 1) Executive Intelligence Summary.
    h(2, "Executive Intelligence Summary")
    es = (report.get("auth_intelligence") or {}).get("exec_summary") or {}
    if es:
        # Authorization-first summary derived from the decoded session token.
        lines.append(f"- **User:** {es.get('user', '—')}")
        lines.append(
            f"- **Authentication:** {es.get('authentication', '—')} "
            f"(model: {es.get('authentication_model', '—')})"
        )
        if es.get("realm"):
            lines.append(f"- **Realm:** {es['realm']} · **Client:** {es.get('client', '—')}")
        lines.append(
            f"- **Applications:** {es.get('applications', 0)} · "
            f"**Roles:** {es.get('roles', 0)} · "
            f"**Admin:** {es.get('administrative_roles', 0)} · "
            f"**Security-Sensitive:** {es.get('security_sensitive_roles', 0)}"
        )
        lines.append(
            f"- **Token Lifetime:** {es.get('token_lifetime', '—')} · "
            f"**Trusted Apps:** {es.get('trusted_applications', 0)} · "
            f"**Highest-Risk App:** {es.get('highest_risk_application') or '—'}"
        )
    lines.append(
        f"- **Authentication (detected):** {s.get('authentication_type', 'Unknown')}"
        + (f" · realm `{s['keycloak_realm']}`" if s.get("keycloak_realm") else "")
    )
    if not es:
        lines.append(f"- **Roles:** {', '.join(s.get('roles', [])) or '—'}")
    lines.append(f"- **Applications:** {', '.join(s.get('applications', [])) or '—'}")
    lines.append(f"- **Internal Services:** {', '.join(s.get('internal_services', [])) or '—'}")
    lines.append(
        f"- **APIs:** {s.get('apis', 0)} observed  ·  "
        f"**Hidden APIs:** {len(s.get('hidden_apis', []))}  ·  "
        f"**Hidden Routes:** {len(s.get('hidden_routes', []))}  ·  "
        f"**Secrets:** {s.get('secrets', 0)}"
    )
    if s.get("hidden_apis"):
        lines.append(f"- **Hidden APIs:** {', '.join('`' + a + '`' for a in s['hidden_apis'][:8])}")
    if s.get("hidden_routes"):
        lines.append(
            f"- **Hidden Routes:** {', '.join('`' + r + '`' for r in s['hidden_routes'][:8])}"
        )
    if s.get("high_priority_targets"):
        lines.append("- **High-Priority Targets:**")
        lines.extend(f"    - `{t}`" for t in s["high_priority_targets"])
    lines.append("")

    # Phase-2 authentication & authorization suite (immediately below the summary).
    _render_auth_suite(report, h, lines)

    # 2) Developer Discussion Points.
    points = ei.get("developer_discussion_points", [])
    h(2, f"Developer Discussion Points ({len(points)})")
    if points:
        lines.append("_Findings that warrant a developer / architect review._\n")
        lines.append("| Finding | Severity | Detail |")
        lines.append("| --- | --- | --- |")
        for p in points:
            lines.append(f"| {p['title']} | {p['severity']} | {p.get('detail', '')} |")
    else:
        lines.append("_No developer-review items._")
    lines.append("")

    # 3) Secrets & Sensitive Configuration.
    secrets = ei.get("secrets", [])
    h(2, f"Secrets & Sensitive Configuration ({len(secrets)})")
    if secrets:
        lines.append("| Secret Type | Location | Severity | Source | Masked Value |")
        lines.append("| --- | --- | --- | --- | --- |")
        for sec in secrets[:60]:
            lines.append(
                f"| {sec['type']} | {sec.get('location') or '—'} | {sec['severity']} | "
                f"{sec.get('source') or '—'} | `{sec.get('value_masked') or '—'}` |"
            )
    else:
        lines.append("_No secrets detected._")
    lines.append("")

    # 4) Application Architecture Summary.
    arch = ei.get("architecture", {})
    auth = arch.get("authentication", {})
    h(2, "Application Architecture Summary")
    realm = f" · realm `{auth['realm']}`" if auth.get("realm") else ""
    client = f" · client `{auth['client']}`" if auth.get("client") else ""
    lines.append(
        f"- **Authentication Architecture:** {auth.get('provider', 'Unknown')} "
        f"({auth.get('type', 'Unknown')}){realm}{client}"
    )
    if auth.get("gateways"):
        lines.append(f"- **API Gateways:** {', '.join(auth['gateways'])}")
    lines.append(f"- **Applications:** {', '.join(arch.get('applications', [])) or '—'}")
    lines.append(f"- **Internal Services:** {', '.join(arch.get('internal_services', [])) or '—'}")
    if arch.get("related_applications"):
        lines.append(f"- **Related Applications:** {', '.join(arch['related_applications'])}")
    lines.append(f"- **Runtime Configuration Values:** {arch.get('runtime_config_values', 0)}\n")

    # 5) High Value Pentest Targets (top ranked only).
    targets = ei.get("top_targets", [])
    h(2, f"High Value Pentest Targets ({len(targets)})")
    if targets:
        for t in targets:
            url = t.get("full_url") or t["endpoint"]
            lines.append(
                f"{t.get('rank', '•')}. **{t.get('method', 'GET')} `{url}`** "
                f"({t.get('risk', '—')}) — {t.get('reason', '')} · "
                f"_{t.get('visibility', '')}_ · tests: {', '.join(t.get('tests', []))}"
            )
    else:
        lines.append("_No prioritized targets._")
    lines.append("")

    # 6) Hidden Functionality.
    hf = ei.get("hidden_functionality", {})
    h(2, "Hidden Functionality")
    lines.append(
        "- **Hidden APIs:** " + (", ".join(f"`{a}`" for a in hf.get("hidden_apis", [])) or "—")
    )
    lines.append(
        "- **Hidden Routes:** " + (", ".join(f"`{r}`" for r in hf.get("hidden_routes", [])) or "—")
    )
    lines.append(
        "- **Feature-Gated Modules:** " + (", ".join(hf.get("feature_gated_modules", [])) or "—")
    )
    lines.append("")


def _render_crawl_coverage(report: dict, h, lines: list[str]) -> None:
    """Per-role authenticated-crawl coverage: flags form-login roles that captured
    no post-login pages, and lists the post-login pages each role unlocked."""
    from collections import Counter, defaultdict

    users = [
        u for u in (report.get("users") or []) if u.get("role") and u.get("role") != "anonymous"
    ]
    crawl = report.get("crawl_endpoints") or []
    counts = Counter(e.get("role") for e in crawl)
    pages_by_role: dict[str, set] = defaultdict(set)
    for e in crawl:
        if e.get("url"):
            pages_by_role[e.get("role")].add(e["url"])
    anon_pages = pages_by_role.get("anonymous", set())
    total_pages = sum(counts.values())
    # Skip when there's nothing meaningful to report (e.g. a pure HAR/offline scan
    # with no form-login role and no crawled pages).
    if not users or (total_pages == 0 and not any(u.get("has_password") for u in users)):
        return

    flagged = False
    rows: list[tuple[str, str, int, str]] = []
    for u in users:
        role = u["role"]
        pages = counts.get(role, 0)
        form_login = bool(u.get("has_password"))
        auth = "form login" if form_login else ("HAR" if u.get("har") else "session/token")
        if form_login and pages == 0:
            status, flagged = "⚠️ No authenticated pages captured", True
        else:
            status = "OK" if pages else "—"
        rows.append((role, auth, pages, status))

    h(2, "Authenticated Crawl Coverage")
    lines.append("| Role | Auth | Pages Captured | Status |")
    lines.append("| --- | --- | ---: | --- |")
    for role, auth, pages, status in rows:
        lines.append(f"| {role} | {auth} | {pages} | {status} |")
    lines.append("")
    if flagged:
        lines.append(
            "> ⚠️ **A form-login role captured no authenticated pages — the login likely "
            "failed.** Common causes: (1) the target serves an expired / self-signed TLS "
            "certificate — re-run with `--insecure`; (2) the credentials are invalid; "
            "(3) the login form is on a separate page or needs specific fields — set "
            "`login.url` / `login.username_field` / `login.password_field` in the config; "
            "or (4) the crawl was disabled (`--no-crawl` / `--offline`)."
        )
        lines.append("")

    # List the post-login pages each form-login role unlocked (those an anonymous
    # crawl did NOT reach), so authenticated surface is visible at a glance.
    for u in users:
        if not u.get("has_password"):
            continue
        role = u["role"]
        exclusive = sorted(pages_by_role.get(role, set()) - anon_pages)
        shown = exclusive or sorted(pages_by_role.get(role, set()))
        if not shown:
            continue
        label = "exclusive to this role" if exclusive else "captured for this role"
        h(3, f"Post-Login Pages — {role} ({len(shown)}, {label})")
        for url in shown[:40]:
            lines.append(f"- {url}")
        if len(shown) > 40:
            lines.append(f"- … and {len(shown) - 40} more")
        lines.append("")


def _render_access(report: dict, h, lines: list[str]) -> None:
    """Render the Roles table and the HAR-derived Role Visibility sections."""
    users = report.get("users", [])

    # Users / roles
    h(2, f"Roles ({len(users)})")
    if users:
        lines.append("| Role | Username | Password | Token | Captures |")
        lines.append("| --- | --- | :---: | :---: | --- |")
        for u in users:
            caps = ", ".join(c for c in [u.get("har"), u.get("burp")] if c) or "—"
            lines.append(
                f"| {u['role']} | {u.get('username') or '—'} | "
                f"{'✅' if u.get('has_password') else '—'} | "
                f"{'✅' if u.get('has_token') else '—'} | {caps} |"
            )
    else:
        lines.append("_No identities configured (anonymous scan)._")
    lines.append("")

    _render_role_visibility(report, h, lines)


def _render_role_visibility(report: dict, h, lines: list[str]) -> None:
    """Render the redesigned Access Matrix: per-role Application/API visibility
    (4 states from captured traffic) plus exclusive/shared breakdowns."""
    vis = report.get("role_visibility", {})
    roles = vis.get("roles", [])
    if not roles:
        return

    sym = vis.get("legend", {})

    def _grid(title: str, rows: list[dict], label_key: str) -> None:
        h(2, f"{title} ({len(rows)})")
        if not rows:
            lines.append("_None observed in captured traffic._\n")
            return
        lines.append("| " + label_key.title() + " | " + " | ".join(roles) + " |")
        lines.append("| --- |" + " :---: |" * len(roles))
        for row in rows:
            cells = " | ".join(sym.get(row["states"].get(r), "?") for r in roles)
            label = row.get(label_key, "")
            if label_key == "endpoint":
                label = f"`{row.get('method', 'GET')} {label}`"
            lines.append(f"| {label} | {cells} |")
        lines.append("")

    h(2, "Access Matrix — Role Visibility")
    lines.append(
        "Derived from each role's **captured traffic** (static assets and third-party "
        "hosts excluded). Legend: "
        f"{sym.get('observed', '✓')} Observed · {sym.get('not_observed', '?')} Not Observed · "
        f"{sym.get('denied', '🚫')} Access Denied · {sym.get('redirected', '↪')} Redirected.\n"
    )

    _grid("Application Visibility", vis.get("applications", []), "name")
    _grid("API Visibility", vis.get("apis", []), "endpoint")

    # Role-exclusive applications / APIs.
    excl_apps = vis.get("exclusive_apps", {})
    h(2, "Role Exclusive Applications")
    for role in roles:
        items = excl_apps.get(role, [])
        h(3, f"{role} only ({len(items)})")
        lines += [f"- {i}" for i in items] or ["- None"]
        lines.append("")

    excl_apis = vis.get("exclusive_apis", {})
    h(2, "Role Exclusive APIs")
    for role in roles:
        items = excl_apis.get(role, [])
        h(3, f"{role} only ({len(items)})")
        lines += [f"- `{i}`" for i in items] or ["- None"]
        lines.append("")

    shared_apps = vis.get("shared_apps", [])
    h(2, f"Shared Applications ({len(shared_apps)})")
    lines += [f"- {i}" for i in shared_apps] or ["- None"]
    lines.append("")

    shared_apis = vis.get("shared_apis", [])
    h(2, f"Shared APIs ({len(shared_apis)})")
    lines += [f"- `{i}`" for i in shared_apis] or ["- None"]
    lines.append("")


def _render_auth(report: dict, h, lines: list[str]) -> None:
    """Render Session Inventory and (masked) Authentication Artifacts.

    Identity-provider / JWT / authorization detail is rendered up front by
    ``_render_auth_suite`` (Authentication Intelligence); this section keeps the raw
    captured inventory.
    """
    artifacts = report.get("auth_artifacts", [])

    h(2, "Captured Sessions & Artifacts")

    # Issue 2: inventory reflects what was actually captured (from artifacts).
    inv = report.get("session_inventory", []) or []
    h(3, f"Session Inventory ({len(inv)})")
    if inv:
        lines.append(
            "| Role | Captured | Cookies | Local Storage | Session Storage | Auth Tokens |"
        )
        lines.append("| --- | :---: | ---: | ---: | ---: | ---: |")
        for s in inv:
            lines.append(
                f"| {s['role']} | {'✅' if s.get('captured') else '—'} | "
                f"{s.get('cookies', 0)} | {s.get('local_storage', 0)} | "
                f"{s.get('session_storage', 0)} | {s.get('auth_tokens', 0)} |"
            )
    else:
        lines.append("_No sessions configured._")
    lines.append("")

    expl = report.get("exploration", {})
    if expl and sum(expl.values()):
        h(3, "Exploration Capture")
        lines.append(
            f"- Navigations: {expl.get('endpoints', 0)} · API calls: {expl.get('api_calls', 0)} · "
            f"Uploads: {expl.get('uploads', 0)} · Downloads: {expl.get('downloads', 0)} · "
            f"WebSockets: {expl.get('websockets', 0)}\n"
        )

    h(3, f"Authentication Artifacts ({len(artifacts)}) — masked")
    if artifacts:
        lines.append("| Role | Kind | Name | Value (masked) | Source |")
        lines.append("| --- | --- | --- | --- | --- |")
        for a in artifacts[:100]:
            masked = a.get("value_masked", "")
            lines.append(
                f"| {a.get('role', '')} | {a.get('kind', '')} | {a.get('name', '')} | "
                f"`{masked}` | {a.get('source', '')} |"
            )
    else:
        lines.append("_No authentication artifacts collected._")
    lines.append("")


def _render_redirect_summary(report: dict, h, lines: list[str]) -> None:
    """Front-matter: Authentication Redirect Flow + redirect risk-flag counts."""
    ri = report.get("redirect_intelligence") or {}
    s = ri.get("summary") or {}
    if not s.get("total_redirects"):
        return

    auth_flow = ri.get("auth_redirect_flow") or []
    if auth_flow:
        h(3, "Authentication Redirect Flow")
        for c in auth_flow[:5]:
            lines.append("```")
            lines.append("\n→ ".join(c.get("nodes", [])))
            lines.append("```")
            lines.append(
                f"- **Purpose:** {c.get('purpose', '—')} · "
                f"**Confidence:** {c.get('confidence', '—')}\n"
            )

    lines.append(
        f"- **Redirects:** {s.get('total_redirects', 0)} "
        f"({s.get('total_chains', 0)} chains) · "
        f"**Auth/SSO:** {s.get('auth_redirects', 0)} · "
        f"**Cross-domain:** {s.get('cross_domain', 0)} · "
        f"**Third-party:** {s.get('third_party', 0)} · "
        f"**Open-redirect candidates:** {s.get('open_redirect_candidates', 0)}\n"
    )


def _render_redirect_intel(report: dict, h, lines: list[str]) -> None:
    """Detailed Redirect Intelligence: inventory, flow diagram, external summary, flags."""
    ri = report.get("redirect_intelligence") or {}
    s = ri.get("summary") or {}
    if not s.get("total_redirects"):
        return

    h(2, "Redirect Intelligence")
    lines.append(
        f"- **Total redirects:** {s.get('total_redirects', 0)} across "
        f"{s.get('total_chains', 0)} chain(s)\n"
    )

    # Redirect Flow Diagram (text)
    chains = ri.get("chains") or []
    if chains:
        h(3, "Redirect Flow Diagram")
        for c in chains[:40]:
            lines.append("```")
            lines.append("\n→ ".join(c.get("nodes", [])))
            lines.append("```")
            role = c.get("role") or "—"
            lines.append(
                f"- **Purpose:** {c.get('purpose', '—')} · "
                f"**Confidence:** {c.get('confidence', '—')} · "
                f"**Role:** {role}\n"
            )

    # Redirect Inventory
    inv = ri.get("redirect_inventory") or []
    h(3, f"Redirect Inventory ({len(inv)})")
    if inv:
        lines.append("| Source | Status | Target | Purpose | Confidence | Source |")
        lines.append("| --- | ---: | --- | --- | --- | --- |")
        for r in inv[:120]:
            status = r.get("status")
            lines.append(
                f"| `{_clip(r.get('source_url', ''))}` | {status if status else '—'} | "
                f"`{_clip(r.get('target_url', ''))}` | {r.get('purpose', '—')} | "
                f"{r.get('confidence', '—')} | {r.get('source', '—')} |"
            )
    else:
        lines.append("_No redirects captured._")
    lines.append("")

    # External Redirect Summary
    ext = ri.get("external_redirect_summary") or []
    if ext:
        h(3, f"External Redirect Summary ({len(ext)})")
        lines.append("| Host | Org Domain | Classification | Redirects | Sample Paths |")
        lines.append("| --- | --- | --- | ---: | --- |")
        for g in ext[:60]:
            paths = ", ".join(g.get("paths", [])[:4]) or "—"
            lines.append(
                f"| `{g.get('host', '')}` | {g.get('registrable_domain', '')} | "
                f"{g.get('classification', '—')} | {g.get('count', 0)} | {paths} |"
            )
        lines.append("")

    # Flags
    flags = ri.get("flags") or {}
    _render_redirect_flags(flags, h, lines)


def _render_redirect_flags(flags: dict, h, lines: list[str]) -> None:
    """Open-redirect candidates, cross-domain and third-party redirect flags."""
    opens = flags.get("open_redirect_candidates") or []
    third = flags.get("third_party_redirects") or []
    cross = flags.get("cross_domain_redirects") or []
    if not (opens or third or cross):
        return

    h(3, "Redirect Flags")
    if opens:
        lines.append(f"**Open Redirect Candidates ({len(opens)})** — passive flag, not tested")
        lines.append("| Source | Target | Parameters |")
        lines.append("| --- | --- | --- |")
        for o in opens[:60]:
            params = ", ".join(o.get("parameters", []))
            lines.append(
                f"| `{_clip(o.get('source_url', ''))}` | "
                f"`{_clip(o.get('target_url', ''))}` | `{params}` |"
            )
        lines.append("")
    if third:
        hosts = sorted({t.get("target_host", "") for t in third})
        lines.append(f"**Third-Party Redirects ({len(third)}):** {', '.join(hosts) or '—'}")
    if cross:
        hosts = sorted({c.get("target_host", "") for c in cross})
        lines.append(f"**Cross-Domain Redirects ({len(cross)}):** {', '.join(hosts) or '—'}")
    lines.append("")


def _clip(text: str, width: int = 70) -> str:
    text = text or ""
    return text if len(text) <= width else text[: width - 1] + "…"


def _render_subdomain_intelligence(report: dict, h, lines: list[str]) -> None:
    """Passive Subdomain Intelligence — multi-source enumeration + correlation."""
    si = report.get("subdomain_intelligence") or {}
    hosts = si.get("hosts") or []
    if not hosts:
        return

    h(2, "Passive Subdomain Intelligence")
    s = si.get("summary") or {}
    queried = ", ".join(si.get("sources_queried") or []) or "—"
    lines.append(
        f"- **Sources Queried:** {queried} · **Subdomains Found:** "
        f"{s.get('subdomains_found', 0)} · **Resolved Hosts:** {s.get('resolved_hosts', 0)} · "
        f"**Internal Services:** {s.get('internal_services', 0)} · **Auth Hosts:** "
        f"{s.get('authentication_hosts', 0)} · **Gateway Hosts:** {s.get('gateway_hosts', 0)}\n"
    )

    h(3, f"Host Inventory ({len(hosts)})")
    lines.append("| Host | Source | Resolved | Provider | Confidence |")
    lines.append("| --- | --- | :---: | --- | --- |")
    for hh in hosts:
        lines.append(
            f"| {hh['host']} | {hh['source']} | {'Yes' if hh['resolved'] else 'No'} | "
            f"{hh.get('provider', '—')} | {hh['confidence']} |"
        )
    lines.append("")

    points = si.get("developer_points") or []
    if points:
        lines.append("**Subdomain Discussion Points**")
        lines.extend(f"{i}. {pt}" for i, pt in enumerate(points, start=1))
        lines.append("")


def _render_file_intelligence(report: dict, h, lines: list[str]) -> None:
    """File Upload & Download Intelligence."""
    fi = report.get("file_intelligence") or {}
    uploads = fi.get("uploads") or []
    downloads = fi.get("downloads") or []
    if not (uploads or downloads or fi.get("storage") or fi.get("signed_urls")):
        return

    h(2, "File Upload & Download Intelligence")
    s = fi.get("summary") or {}
    lines.append(
        f"- **Upload Endpoints:** {s.get('upload_endpoints', 0)} · **Download Endpoints:** "
        f"{s.get('download_endpoints', 0)} · **Storage:** {s.get('storage_platform', '—')} · "
        f"**Signed URLs:** {s.get('signed_urls', 0)} · **High-Risk Uploads:** "
        f"{s.get('high_risk_uploads', 0)} · **Potential IDOR Downloads:** "
        f"{s.get('potential_idor_downloads', 0)}\n"
    )

    if uploads:
        h(3, f"Upload Inventory ({len(uploads)})")
        lines.append(
            "| Endpoint | Method | Auth | Roles | Multipart | Accepted Types | "
            "Storage | Confidence |"
        )
        lines.append("| --- | --- | --- | --- | :---: | --- | --- | --- |")
        for u in uploads:
            roles = ", ".join(sorted(u.get("roles") or [])) or "—"
            lines.append(
                f"| {u['endpoint']} | {u['method']} | {u['auth']} | {roles} | "
                f"{'Yes' if u['multipart'] else 'No'} | {u['accepted_types']} | "
                f"{u['storage']} | {u['confidence']} |"
            )
        lines.append("")

    if downloads:
        h(3, f"Download Inventory ({len(downloads)})")
        lines.append("| Endpoint | Auth | Content-Type | Download Type | Signed URL | Confidence |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for d in downloads:
            lines.append(
                f"| {d['endpoint']} | {d['auth']} | {d['content_type']} | "
                f"{d['download_type']} | {d['signed_url']} | {d['confidence']} |"
            )
        lines.append("")

    storage = fi.get("storage") or []
    if storage:
        h(3, f"File Storage ({len(storage)})")
        lines.append("| Platform | Host | Service | Evidence | Confidence |")
        lines.append("| --- | --- | --- | --- | --- |")
        for st in storage:
            lines.append(
                f"| {st['platform']} | {st['host']} | {st['service']} | "
                f"`{st['evidence']}` | {st['confidence']} |"
            )
        lines.append("")

    signed = fi.get("signed_urls") or []
    if signed:
        h(3, f"Signed / Temporary URLs ({len(signed)})")
        lines.append("| Platform | Expiration | URL |")
        lines.append("| --- | --- | --- |")
        for sg in signed[:60]:
            lines.append(f"| {sg['platform']} | {sg['expiration']} | `{sg['url']}` |")
        lines.append("")

    accepted = fi.get("accepted_types") or {}
    if accepted:
        h(3, "Accepted File Types")
        for cat, exts in accepted.items():
            lines.append(f"- **{cat}:** {', '.join(exts)}")
        lines.append("")

    for title, comps in (
        ("Upload Components", fi.get("upload_components") or {}),
        ("Download Components", fi.get("download_components") or {}),
    ):
        if comps:
            h(3, title)
            for label, evidence in comps.items():
                lines.append(f"- **{label}:** {', '.join(evidence)}")
            lines.append("")

    val = fi.get("validation") or {}
    if val:
        h(3, "Upload Validation")
        lines.append(f"- **Client-side:** {', '.join(val.get('client_side', []))}")
        lines.append(f"- **Server-side:** {val.get('server_side', '—')}")
        lines.append(
            f"- **Magic-byte:** {val.get('magic_byte', '—')} · **Virus scan:** "
            f"{val.get('virus_scan', '—')}\n"
        )

    corr = fi.get("correlation") or []
    if corr:
        h(3, "Correlation")
        lines.append("```")
        lines.extend(corr)
        lines.append("```\n")

    pentest = fi.get("pentest_opportunities") or {}
    if pentest:
        h(3, "Pentest Opportunities")
        for area, tests in pentest.items():
            lines.append(f"- **{area}:** {', '.join(tests)}")
        lines.append("")

    points = fi.get("developer_points") or []
    if points:
        lines.append("**File Handling Discussion Points**")
        lines.extend(f"{i}. {pt}" for i, pt in enumerate(points, start=1))
        lines.append("")


def _render_dns_intelligence(report: dict, h, lines: list[str]) -> None:
    """DNS Intelligence & Infrastructure Discovery."""
    dns = report.get("dns_intelligence") or {}
    hosts = dns.get("host_inventory") or []
    if not hosts:
        return

    h(2, "DNS Intelligence")
    s = dns.get("summary") or {}
    lines.append(
        f"- **Hosts:** {s.get('hosts', 0)} · **Internal Services:** "
        f"{s.get('internal_services', 0)} · **Gateways:** {s.get('gateways', 0)} · "
        f"**Auth Providers:** {s.get('auth_providers', 0)} · **Cloud:** "
        f"{s.get('cloud_providers', '—')} · **Third Parties:** {s.get('third_parties', 0)} · "
        f"**DNS Findings:** {s.get('dns_findings', 0)}\n"
    )

    h(3, f"Host Inventory ({len(hosts)})")
    lines.append("| Host | Purpose | Source | Observed | Confidence |")
    lines.append("| --- | --- | --- | :---: | --- |")
    for hh in hosts:
        lines.append(
            f"| {hh['host']} | {hh['purpose']} | {hh['source']} | "
            f"{'Yes' if hh['observed'] else 'No'} | {hh['confidence']} |"
        )
    lines.append("")

    records = dns.get("dns_records") or []
    if records:
        h(3, f"DNS Record Inventory ({len(records)})")
        lines.append("| Host | Record Type | Value |")
        lines.append("| --- | --- | --- |")
        for r in records[:120]:
            lines.append(f"| {r['host']} | {r['record_type']} | `{r['value']}` |")
        lines.append("")

    cloud = dns.get("cloud_provider") or {}
    if cloud:
        h(3, "Infrastructure Provider")
        lines.append(f"- **Provider:** {cloud.get('provider', '—')}")
        lines.append(f"- **Confidence:** {cloud.get('confidence', '—')}")
        lines.append(f"- **Evidence:** {', '.join(cloud.get('evidence', [])) or '—'}\n")

    ai = dns.get("auth_infrastructure") or {}
    if ai:
        h(3, "Authentication Infrastructure")
        lines.append(f"- **Provider:** {ai.get('provider', '—')}")
        lines.append(f"- **Host:** {ai.get('host') or '—'}")
        lines.append(f"- **Realm:** {ai.get('realm') or '—'}")
        lines.append(f"- **Source:** {ai.get('source', '—')}\n")

    gws = dns.get("gateways") or []
    if gws:
        h(3, f"Gateway Inventory ({len(gws)})")
        for g in gws:
            lines.append(
                f"- **{g['host']}** — {g['type']} (confidence: {g['confidence']}, "
                f"evidence: {g['evidence']})"
            )
        lines.append("")

    deps = dns.get("external_dependencies") or []
    if deps:
        h(3, f"External Dependencies ({len(deps)})")
        lines.append("| Service | Host | Purpose | Observed | Source |")
        lines.append("| --- | --- | --- | :---: | --- |")
        for d in deps:
            lines.append(
                f"| {d['service']} | {d['host']} | {d['purpose']} | "
                f"{'Yes' if d['observed'] else 'No'} | {d['source']} |"
            )
        lines.append("")

    rel = dns.get("relationship_map") or []
    if rel:
        h(3, "Host Relationship Map")
        lines.append("```")
        lines.extend(rel)
        lines.append("```\n")

    findings = dns.get("dns_security_findings") or []
    if findings:
        h(3, f"DNS Security Findings ({len(findings)})")
        lines.append("| Finding | Detail | Risk | Severity |")
        lines.append("| --- | --- | --- | --- |")
        for f in findings:
            lines.append(
                f"| {f['finding']} | {f['detail']} | {f.get('risk', '—')} | {f['severity']} |"
            )
        lines.append("")

    pv = dns.get("pentest_value") or {}
    if pv:
        h(3, "Infrastructure Pentest Value")
        for purpose, tests in pv.items():
            lines.append(f"- **{purpose}:** {', '.join(tests)}")
        lines.append("")

    points = dns.get("developer_points") or []
    if points:
        lines.append("**Infrastructure Discussion Points**")
        lines.extend(f"{i}. {pt}" for i, pt in enumerate(points, start=1))
        lines.append("")


def _render_token_inventory(report: dict, h, lines: list[str]) -> None:
    """Authentication Token Inventory — classify/decode/correlate all token types."""
    ti = report.get("token_inventory") or {}
    tokens = ti.get("tokens") or []
    if not tokens:
        return

    h(2, "Authentication Token Inventory")
    lines.append("| Token Type | Source | Storage | Decoded | Risk |")
    lines.append("| --- | --- | --- | --- | --- |")
    for t in tokens:
        lines.append(
            f"| {t['type']} | {t['source']} | {t['storage']} | " f"{t['decoded']} | {t['risk']} |"
        )
    lines.append("")

    for c in ti.get("detail_cards") or []:
        h(3, c.get("title", "Token"))
        for k in ("storage", "issuer", "realm", "client", "applications", "roles", "lifetime"):
            if c.get(k) is not None:
                lines.append(f"- **{k.title()}:** {c[k]}")
        if c.get("contains"):
            lines.append(f"- **Contains:** {', '.join(c['contains'])}")
        for k in ("observed", "decoded", "reason", "risk"):
            if c.get(k) is not None:
                lines.append(f"- **{k.title()}:** {c[k]}")
        lines.append("")

    corr = ti.get("correlation") or {}
    if corr:
        h(3, "Cross-Token Correlation")
        lines.append(f"- **Authentication Model:** {corr.get('authentication_model', '—')}")
        lines.append(f"- **Observed:** {', '.join(corr.get('observed_tokens', [])) or '—'}")
        lines.append(f"- **Confidence:** {corr.get('confidence', '—')}")
        ic = corr.get("identity_consistency") or {}
        if ic.get("sources"):
            lines.append(
                f"- **Identity consistent across:** {', '.join(ic['sources'])} "
                f"(confidence: {ic.get('confidence', '—')})"
            )
        az = corr.get("authorization_summary") or {}
        lines.append(
            f"- **Authorization:** {az.get('applications', 0)} applications · "
            f"{az.get('roles', 0)} roles · {az.get('administrative', 0)} admin · "
            f"{az.get('security_sensitive', 0)} security-sensitive\n"
        )

    graph = ti.get("relationship_graph") or []
    if graph:
        h(3, "Authentication Token Relationships")
        lines.append("```")
        lines.extend(graph)
        lines.append("```\n")

    pv = ti.get("pentest_value") or {}
    if pv:
        h(3, "Token Pentest Value")
        for ttype, tests in pv.items():
            lines.append(f"- **{ttype}:** {', '.join(tests)}")
        lines.append("")

    points = ti.get("developer_points") or []
    if points:
        lines.append("**Authentication Token Observations**")
        lines.extend(f"{i}. {pt}" for i, pt in enumerate(points, start=1))
        lines.append("")


def _render_auth_suite(report: dict, h, lines: list[str]) -> None:
    """Phase-2 authentication & authorization intelligence, rendered near the top."""
    ji = report.get("jwt_intelligence") or {}
    p = ji.get("primary") or {}
    ai = report.get("auth_intelligence") or {}
    if not p:
        return

    auth = report.get("authentication") or {}
    model = ai.get("authentication_model") or {}
    storage = ai.get("storage") or {}

    # --- Authentication Intelligence ---
    h(2, "Authentication Intelligence")
    if p.get("origin") == "embedded":
        lines.append(
            "> ⚠️ The decoded token was **embedded in client-side JavaScript** (not a captured "
            "session). Re-run `auth explore` to decode the interactive session token.\n"
        )
    lines.append(f"- **Identity Provider:** {p.get('identity_provider', '—')}")
    lines.append(f"- **Realm:** {auth.get('realm') or p.get('realm') or '—'}")
    lines.append(f"- **Client:** {p.get('client') or '—'}")
    lines.append(f"- **Authentication Type:** {p.get('authentication_type', '—')}")
    lines.append(
        f"- **Authentication Model:** {model.get('model', '—')} "
        f"(confidence: {model.get('confidence', '—')})"
    )
    if model.get("uses"):
        lines.append(f"- **Uses:** {', '.join(model['uses'])}")
    lines.append(
        f"- **Token Storage:** {storage.get('access_token', '—')} · "
        f"**Session Cookie:** {storage.get('session_cookie', '—')} · "
        f"**Authorization Header:** {storage.get('authorization_header', '—')}"
    )
    cards = ai.get("auth_cards") or {}
    if cards:
        lines.append(
            f"- **At a glance:** Type {cards.get('authentication_type', '—')} · "
            f"Bearer {cards.get('bearer_tokens', 0)} · Cookies {cards.get('cookies', 0)} · "
            f"localStorage {cards.get('local_storage', 0)} · "
            f"sessionStorage {cards.get('session_storage', 0)} · "
            f"Trusted Apps {cards.get('trusted_apps', 0)} · Roles {cards.get('roles', 0)} · "
            f"Admin {cards.get('admin_roles', 0)}"
        )
    lines.append("")

    # --- Authentication Token Inventory (all token types) ---
    _render_token_inventory(report, h, lines)

    # --- JWT Intelligence Deep Dive ---
    hdr = p.get("header") or {}
    h(2, "JWT Intelligence Deep Dive")
    lines.append(f"- **Token Type:** {hdr.get('typ', '—')}")
    lines.append(f"- **Algorithm:** {hdr.get('alg', '—')}")
    lines.append(f"- **Signature Model:** {hdr.get('signature_model', '—')}")
    lines.append(f"- **Key Rotation:** {hdr.get('key_rotation', '—')}")
    lines.append(f"- **Issuer:** {p.get('issuer') or '—'}")
    lines.append(f"- **Realm:** {p.get('realm') or '—'}")
    lines.append(f"- **Client:** {p.get('client') or '—'}")
    lines.append(f"- **Subject:** {(p.get('user') or {}).get('subject') or '—'}")
    lines.append(f"- **Session State:** {p.get('session_state') or '—'}")
    lines.append(f"- **Scopes:** {', '.join(p.get('scopes', [])) or '—'}\n")

    h(3, "JWT Lifetime Analysis")
    lines.append(f"- **Issued:** {p.get('issued_at') or '—'}")
    lines.append(f"- **Expires:** {p.get('expires_at') or '—'}")
    lines.append(
        f"- **Lifetime:** {p.get('token_lifetime') or '—'} "
        f"(**{p.get('lifetime_class') or '—'}**)\n"
    )

    h(3, "JWT Audience Analysis")
    lines.append(f"- **Trusted Applications:** {p.get('trusted_applications', 0)}")
    lines.extend(f"    - {a}" for a in (p.get("trusted_application_list") or []))
    if p.get("audience_observation"):
        lines.append(f"\n_{p['audience_observation']}_")
    lines.append("")

    # --- User Intelligence ---
    user = p.get("user") or {}
    h(2, "User Intelligence")
    lines.append(f"- **Username:** {user.get('username') or '—'}")
    lines.append(f"- **Display Name:** {user.get('display_name') or user.get('name') or '—'}")
    lines.append(f"- **Email:** {user.get('email') or '—'}")
    lines.append(f"- **Locale:** {user.get('locale') or '—'}")
    lines.append(f"- **Email Verified:** {user.get('email_verified')}\n")

    # --- Authentication Artifacts Summary ---
    summ = ai.get("artifacts_summary") or {}
    h(2, "Authentication Artifacts Summary")
    lines.append(f"- **Authentication Model:** {summ.get('authentication_model', '—')}")
    lines.append(f"- **Bearer Tokens:** {summ.get('bearer_tokens', 0)}")
    lines.append(f"- **Cookies:** {summ.get('cookies', 0)}")
    lines.append(f"- **Local Storage Items:** {summ.get('local_storage', 0)}")
    lines.append(f"- **Session Storage Items:** {summ.get('session_storage', 0)}")
    lines.append(f"- **Authorization Header:** {summ.get('authorization_header', '—')}")
    lines.append(f"- **Refresh Token:** {summ.get('refresh_token', '—')}")
    lines.append(f"- **Token Storage:** {summ.get('token_storage', '—')}")
    lines.append(f"- **Session Cookies:** {', '.join(summ.get('session_cookies', [])) or '—'}\n")

    # --- Role Intelligence ---
    ri = ai.get("role_intelligence") or {}
    h(2, "Role Intelligence")
    breakdown = ri.get("application_breakdown") or []
    if breakdown:
        lines.append("| Application | Total Roles | Admin Roles | Write Roles | Read Roles |")
        lines.append("| --- | ---: | ---: | ---: | ---: |")
        for a in breakdown:
            lines.append(
                f"| {a['application']} | {a['total_roles']} | {a['admin_roles']} | "
                f"{a.get('write_roles', 0)} | {a.get('read_roles', 0)} |"
            )
        lines.append("")
    if ri.get("admin_by_app"):
        h(3, "Administrative Roles by Application")
        for grp in ri["admin_by_app"]:
            lines.append(f"**{grp['application']}**")
            lines.extend(f"- {r}" for r in grp["roles"][:40])
            lines.append("")
    if ri.get("security_sensitive_roles"):
        h(3, f"Security-Sensitive Roles ({len(ri['security_sensitive_roles'])})")
        lines.extend(f"- {r}" for r in ri["security_sensitive_roles"][:60])
        lines.append("")
    if ri.get("test_suggestions"):
        h(3, "Authorization Test Suggestions")
        for ts in ri["test_suggestions"]:
            lines.append(f"- **{ts['application']}**: {', '.join(ts['tests'])}")
        lines.append("")

    # --- Application Access Summary ---
    aa = ai.get("application_access") or []
    h(2, f"Application Access Summary ({len(aa)})")
    if aa:
        lines.append("| Application | Total Roles | Admin Roles | User Roles |")
        lines.append("| --- | ---: | ---: | ---: |")
        for a in aa:
            lines.append(
                f"| {a['application']} | {a['total_roles']} | "
                f"{a['admin_roles']} | {a['user_roles']} |"
            )
    lines.append("")

    # --- Authorization Intelligence (totals + ranking + pentest priorities) ---
    az = ai.get("authorization") or {}
    h(2, "Authorization Intelligence")
    lines.append(
        f"- **Applications:** {az.get('applications', 0)} · "
        f"**Total Roles:** {az.get('total_roles', 0)}"
    )
    lines.append(
        f"- **Administrative:** {az.get('administrative', 0)} · "
        f"**Read:** {az.get('read', 0)} · **Write:** {az.get('write', 0)} · "
        f"**Security-Sensitive:** {az.get('security_sensitive', 0)}\n"
    )
    ranking = ai.get("application_ranking") or []
    if ranking:
        lines.append("**Highest-Value Applications**")
        for i, a in enumerate(ranking[:8], start=1):
            lines.append(
                f"{i}. {a['application']} — {a['total_roles']} roles " f"({a['admin_roles']} admin)"
            )
        lines.append("")
    priorities = ai.get("pentest_priorities") or []
    if priorities:
        lines.append("**Authorization Testing Priorities**")
        for pr in priorities:
            admin = ", ".join(pr.get("admin_roles", [])) or "—"
            lines.append(
                f"- **Priority {pr['priority']} — {pr['application']}** · "
                f"admin roles: {admin} · tests: {', '.join(pr['tests'])}"
            )
        lines.append("")

    # --- Authentication Flow (text tree) ---
    flow = ai.get("auth_flow") or {}
    if flow.get("browser") or flow.get("gateway"):
        h(2, "Authentication Flow")
        tree: list[str] = ["Browser"]
        branches = flow.get("browser") or []
        for idx, node in enumerate(branches):
            last = idx == len(branches) - 1
            stem = "└──" if last else "├──"
            tree.append(f"{stem} {node['label']}")
            cont = "    " if last else "│   "
            for child in node.get("children", []):
                tree.append(f"{cont}└── {child}")
        for nxt in (flow.get("gateway"), flow.get("service")):
            if nxt:
                tree.append("↓")
                tree.append(str(nxt))
        if flow.get("internal_apis"):
            tree.append("↓")
            tree.append(f"internal APIs ({flow['internal_apis']})")
        lines.append("```")
        lines.extend(tree)
        lines.append("```\n")

    # --- Authentication Risk Analysis (risks + refresh + discussion points) ---
    h(2, "Authentication Risk Analysis")
    refresh = ai.get("refresh_token") or {}
    lines.append(
        f"- **Refresh Token:** {refresh.get('status', '—')}"
        + (f" (storage: {refresh['storage']})" if refresh.get("storage") not in (None, "—") else "")
        + (f" — {refresh['basis']}" if refresh.get("basis") not in (None, "—") else "")
    )
    lines.append("")
    risks = ai.get("risk_analysis") or []
    if risks:
        for r in risks:
            lines.append(f"**{r['title']}**")
            lines.append(f"- Risk: {r['risk']}")
            if r.get("impact"):
                lines.append(f"- Impact: {r['impact']}")
            lines.append("")
    points = ai.get("discussion_points") or []
    if points:
        lines.append("**Authentication & Authorization Discussion Points**")
        lines.extend(f"{i}. {pt}" for i, pt in enumerate(points, start=1))
        lines.append("")

    # --- Internal Service Inventory (fully-qualified URLs only) ---
    services = (report.get("javascript_intelligence") or {}).get("service_inventory") or []
    h(2, f"Internal Service Inventory ({len(services)})")
    if services:
        lines.append("| Service | Host | Base URL | Source | Referenced | Observed | Confidence |")
        lines.append("| --- | --- | --- | --- | :---: | :---: | --- |")
        for s in services:
            lines.append(
                f"| {s.get('service', '—')} | {s.get('host', '—')} | "
                f"`{s.get('base_url', '—')}` | {s.get('source', '—')} | "
                f"{'Yes' if s.get('referenced') else 'No'} | "
                f"{'Yes' if s.get('observed') else 'No'} | {s.get('confidence', '—')} |"
            )
    else:
        lines.append("_No internal services resolved._")
    lines.append("")

    # --- JWT Claims (decoded payload, PII-masked) — lands in collapsed Evidence ---
    claims = p.get("claims")
    if claims:
        import json as _json

        h(2, "JWT Claims")
        lines.append("_Decoded payload (signature NOT verified; PII masked)._\n")
        lines.append("```json")
        lines.append(_json.dumps(claims, indent=2, default=str))
        lines.append("```\n")


def _render_summary_and_checklist(report: dict, h, lines: list[str]) -> None:
    """Application Summary + Pentest Checklist — surfaced near the front (page 3-4)."""
    # Application Summary (verbatim, fenced)
    summary = report.get("application_summary", {})
    if summary.get("text"):
        h(2, "Application Summary")
        lines.append(f"_Provider: {summary.get('provider', 'template')}_\n")
        lines.append("```")
        lines.append(summary["text"])
        lines.append("```")
        lines.append("")

    # Pentest checklist
    cl = report.get("checklist", [])
    h(2, f"Pentest Checklist ({len(cl)})")
    if cl:
        by_cat: dict[str, list[dict]] = {}
        for item in cl:
            by_cat.setdefault(item["category"], []).append(item)
        for cat, items in sorted(by_cat.items()):
            h(3, cat)
            for it in items:
                ep = f" ({it['endpoint']})" if it.get("endpoint") else ""
                lines.append(f"- [ ] {it['item']}{ep}")
            lines.append("")
    else:
        lines.append("_No checklist items (no sensitive functions detected)._")
    lines.append("")


def _render_tier2(report: dict, h, lines: list[str]) -> None:
    """Render Tier 2 sections: workflow, functions, API intel."""
    # Workflow tree
    wf = report.get("workflow", {})
    if wf.get("tree"):
        h(2, "Application Workflow")
        lines.append("```")
        lines.append(wf["tree"])
        lines.append("```")
        lines.append("")

    # Sensitive functions
    sf = report.get("sensitive_functions", [])
    h(2, f"Sensitive Functions ({len(sf)})")
    if sf:
        lines.append("| Category | Function | Endpoint |")
        lines.append("| --- | --- | --- |")
        for f in sf:
            lines.append(f"| {f['category']} | {f.get('subcategory') or ''} | {f['endpoint']} |")
    else:
        lines.append("_None detected._")
    lines.append("")

    # API intelligence
    ai = report.get("api_intelligence", [])
    h(2, f"API Inventory & Intelligence ({len(ai)})")
    if ai:
        lines.append("| Endpoint | Methods | Parameters | Authz-sensitive |")
        lines.append("| --- | --- | --- | :---: |")
        for a in ai:
            methods = a.get("methods") or ""
            params = a.get("parameters") or ""
            flag = "⚠️" if a.get("authz_sensitive") else ""
            lines.append(f"| {_endpoint_url(a)} | {methods} | {params} | {flag} |")
    else:
        lines.append("_No APIs discovered._")
    lines.append("")


def _endpoint_url(a: dict) -> str:
    """Full endpoint URL from an api_intel row: ``https://host/path``.

    ``hosts`` arrives as a comma-joined string (DB dump) or a list. Spec-only paths
    (no observed host) stay path-only; multi-host paths show the count + hosts.
    """
    raw = a.get("hosts") or []
    hosts = [h for h in (raw.split(",") if isinstance(raw, str) else raw) if h]
    path = a.get("path", "")
    if len(hosts) == 1:
        return f"https://{hosts[0]}{path}"
    if len(hosts) > 1:
        shown = ", ".join(hosts[:3]) + ("…" if len(hosts) > 3 else "")
        return f"{path} ({len(hosts)} hosts: {shown})"
    return path


def _render_asset_intel(report: dict, h, lines: list[str]) -> None:
    """Render the unified asset-intelligence sections (Issues 2-11)."""
    ai = report.get("asset_intelligence") or {}
    if not ai:
        return

    # Related Internal Applications
    apps = ai.get("internal_apps", [])
    h(2, f"Related Internal Applications ({len(apps)})")
    if apps:
        lines.append("| Host | Type |")
        lines.append("| --- | --- |")
        for a in apps:
            lines.append(f"| {a['host']} | {a['app_type']} |")
    else:
        lines.append("_None discovered._")
    lines.append("")

    # Unified API Inventory (normalized; static + GIS excluded)
    apis = ai.get("api_inventory", [])
    h(2, f"API Inventory ({len(apis)})")
    lines.append("_Normalized (dynamic IDs collapsed to `{id}`); static & GIS assets excluded._\n")
    if apis:
        lines.append("| Endpoint | Methods | Service | Hits | Sources |")
        lines.append("| --- | --- | --- | ---: | --- |")
        for a in apis[:200]:
            lines.append(
                f"| {a['path']} | {', '.join(a.get('methods', []))} | "
                f"{a.get('service') or '—'} | {a.get('hits', 0)} | "
                f"{', '.join(a.get('sources', []))} |"
            )
    else:
        lines.append("_No APIs discovered._")
    lines.append("")

    # Static Assets + GIS / Map Resources (separated noise, Issue 4)
    static = ai.get("static_assets", [])
    h(2, f"Static Assets ({len(static)})")
    if static:
        lines.append("_Excluded from the API inventory._\n")
        lines += [f"- `{s}`" for s in static[:25]]
        if len(static) > 25:
            lines.append(f"- … and {len(static) - 25} more")
    else:
        lines.append("_None._")
    lines.append("")

    gis = ai.get("gis_assets", [])
    h(2, f"GIS / Map Resources ({len(gis)})")
    if gis:
        lines.append("_Tiles / WMTS / map layers — excluded from the API inventory._\n")
        lines += [f"- `{g}`" for g in gis[:25]]
        if len(gis) > 25:
            lines.append(f"- … and {len(gis) - 25} more")
    else:
        lines.append("_None._")
    lines.append("")

    # API Gateway Analysis
    gws = ai.get("gateways", [])
    h(2, "API Gateway Analysis")
    if gws:
        for g in gws:
            services = g["services"]
            label = "API Gateway" if len(services) >= 2 else "Microservice"
            conf = "high" if len(services) >= 2 else "medium"
            h(3, f"{g['host']} — {label}")
            lines.append(f"_Confidence: {conf} — {len(services)} backend service(s)._\n")
            lines.append("Back-end services:\n")
            lines += [f"- {s}" for s in services]
            lines.append("")
    else:
        lines.append("_No API gateway detected._\n")

    # Business Modules
    bms = ai.get("business_modules", [])
    h(2, f"Business Modules ({len(bms)})")
    if bms:
        for m in bms:
            lines.append(f"- **{m['module']}** ({m['score']}) — {', '.join(m.get('evidence', []))}")
    else:
        lines.append("_None inferred._")
    lines.append("")

    # Response Intelligence (keys only)
    ri = ai.get("response_intelligence", [])
    h(2, f"Response Intelligence ({len(ri)})")
    if ri:
        lines.append("| Endpoint | Method | Status | Type | Size | JSON Keys | Confidence |")
        lines.append("| --- | --- | --- | --- | ---: | --- | --- |")
        for r in ri[:150]:
            keys = ", ".join(r.get("json_keys", []))
            lines.append(
                f"| {r['endpoint']} | {r.get('method', 'GET')} | "
                f"{', '.join(str(s) for s in r.get('status', []))} | "
                f"{', '.join(r.get('content_type', []))} | {r.get('size') or '—'} | "
                f"{keys or '—'} | {r.get('confidence', '—')} |"
            )
    else:
        lines.append("_No response schemas captured._")
    lines.append("")

    # Third-Party Dependencies (grouped)
    deps = ai.get("dependencies", {})
    h(2, "Third Party Dependencies")
    if deps:
        for group, names in deps.items():
            lines.append(f"**{group}:**")
            lines += [f"- {n}" for n in names]
            lines.append("")
    else:
        lines.append("_None detected._\n")

    # Infrastructure Architecture
    infra = ai.get("infrastructure", {})
    h(2, "Infrastructure Architecture")
    lines.append(f"- **Primary Application:** {infra.get('primary_application', '—')}")
    idp = infra.get("identity_provider", "Unknown")
    realm = f" (realm: {infra['identity_realm']})" if infra.get("identity_realm") else ""
    lines.append(f"- **Identity Provider:** {idp}{realm}")
    if infra.get("api_gateways"):
        lines.append(f"- **API Gateway:** {', '.join(infra['api_gateways'])}")
    if infra.get("backend_services"):
        lines.append("- **Backend Services:**")
        lines += [f"  - {s}" for s in infra["backend_services"]]
    if infra.get("related_applications"):
        lines.append("- **Related Applications:**")
        lines += [f"  - {a}" for a in infra["related_applications"]]
    if infra.get("third_party_providers"):
        lines.append(f"- **Third-Party Providers:** {', '.join(infra['third_party_providers'])}")
    if infra.get("cloud_storage"):
        lines.append(f"- **Cloud Storage:** {', '.join(infra['cloud_storage'])}")
    lines.append("")

    # Attack Surface Prioritization
    asu = ai.get("attack_surface", [])
    h(2, "Attack Surface Prioritization")
    if asu:
        for i, a in enumerate(asu[:12], 1):
            eps = f" — {', '.join(a['endpoints'][:3])}" if a.get("endpoints") else ""
            lines.append(f"{i}. **{a['area']}** (score {a['score']}){eps}")
    else:
        lines.append("_No prioritized attack surface._")
    lines.append("")


def _render_pentest_guidance(report: dict, h, lines: list[str]) -> None:
    """Render Authorization Test Candidates (Issue 7) + Pentest Attack Plan (Issue 8)."""
    cands = report.get("authz_candidates", []) or []
    h(2, f"Authorization Test Candidates ({len(cands)})")
    lines.append(
        "_Recommendations for a human tester — AppMapper performs no authorization tests._\n"
    )
    if cands:
        for c in cands[:60]:
            h(3, f"{c['method']} {c['endpoint']}")
            lines.append(f"- **Reason:** {c['reason']}")
            lines.append(f"- **Confidence:** {c.get('confidence', '—')}")
            lines.append(f"- **Tests:** {', '.join(c['tests'])}")
            lines.append("")
    else:
        lines.append("_No authorization candidates identified._\n")

    plan = report.get("pentest_plan", []) or []
    h(2, "Pentest Attack Plan")
    if plan:
        for ph in plan:
            h(3, f"Phase {ph['phase']} — {ph['title']}")
            lines += [f"- {it}" for it in ph.get("items", [])]
            lines.append("")
    else:
        lines.append("_No plan generated._\n")


def _render_javascript_intel(report: dict, h, lines: list[str]) -> None:
    """Sprint B.1: JavaScript / runtime-configuration intelligence."""
    ji = report.get("javascript_intelligence") or {}
    s = ji.get("summary", {})
    if not s or not any(v for v in s.values() if isinstance(v, int)):
        return

    # Runtime Intelligence Summary V2 — actionable lists, not bare counts (F12).
    v2 = ji.get("summary_v2", {})
    h(2, "Runtime Intelligence Summary")
    auth = v2.get("authentication", {})
    if auth.get("keycloak_realm") or auth.get("keycloak_client"):
        lines.append(
            f"**Authentication** — Keycloak realm `{auth.get('keycloak_realm') or '—'}`, "
            f"client `{auth.get('keycloak_client') or '—'}`"
        )

    def _bullets(title, items):
        if items:
            lines.append(f"\n**{title}**")
            lines.extend(f"- {i}" for i in items[:15])
            if len(items) > 15:
                lines.append(f"- … and {len(items) - 15} more")

    _bullets("Frontend Secrets", v2.get("frontend_secrets"))
    _bullets("Related Applications", v2.get("related_applications"))
    _bullets("Hidden Routes", [f"`{r}`" for r in v2.get("hidden_routes", [])])
    _bullets("Hidden APIs", [f"`{a}`" for a in v2.get("hidden_apis", [])])
    _bullets("High-Risk Modules", v2.get("high_risk_modules"))
    _bullets("Enabled Features", v2.get("enabled_features"))
    _bullets("Disabled Features", v2.get("disabled_features"))
    lines.append("")

    def _risk_table(title, rows):
        h(3, f"{title} ({len(rows)})")
        if rows:
            lines.append("| Finding | Severity | Confidence | Evidence |")
            lines.append("| --- | --- | --- | --- |")
            for r in rows:
                ev = "; ".join(str(e) for e in r.get("evidence", [])[:5])
                lines.append(f"| {r['title']} | {r['severity']} | {r['confidence']} | {ev} |")
        else:
            lines.append("_None._")
        lines.append("")

    _risk_table("Runtime Configuration Risks", ji.get("runtime_config_risks", []))

    def _table(title, rows, header, rowfn):
        h(3, f"{title} ({len(rows)})")
        if rows:
            lines.append("| " + " | ".join(header) + " |")
            lines.append("| " + " | ".join("---" for _ in header) + " |")
            for r in rows[:80]:
                lines.append("| " + " | ".join(rowfn(r)) + " |")
        else:
            lines.append("_None._")
        lines.append("")

    _table(
        "Runtime Configuration Discovery",
        ji.get("runtime_config", []),
        ["Setting", "Value", "Location"],
        lambda c: [c["setting"], f"`{c.get('value') or '—'}`", c.get("location") or "—"],
    )

    _table(
        "Frontend Secret Discovery",
        ji.get("frontend_secrets", []),
        ["Finding", "Sample (masked)", "Severity", "Location"],
        lambda x: [
            x["name"],
            f"`{x.get('value_masked') or '—'}`",
            x["severity"],
            x.get("location") or "—",
        ],
    )

    flags = ji.get("feature_flags", [])
    _table(
        "Feature Flag Intelligence",
        flags,
        ["Feature", "Enabled"],
        lambda f: [
            f["feature"],
            "✅" if f["enabled"] is True else ("❌" if f["enabled"] is False else "—"),
        ],
    )

    _table(
        "Related Applications Inventory",
        ji.get("related_applications", []),
        ["Application", "Category"],
        lambda a: [f"`{a['host']}`", a["category"]],
    )

    # Internal Service Inventory (canonical registry, full base URLs) — F4.
    _table(
        "Internal Service Inventory",
        ji.get("service_inventory", []),
        ["Service", "Base URL", "Host", "Source", "Referenced", "Observed"],
        lambda r: [
            r["service"],
            f"`{r.get('base_url') or '—'}`",
            r.get("host") or "—",
            r.get("source") or "—",
            "✅" if r.get("referenced") else "—",
            "✅" if r.get("observed") else "—",
        ],
    )

    apis = ji.get("js_api_inventory", [])
    h(3, f"JavaScript API Inventory ({len(apis)})")
    lines += [f"- `{a}`" for a in apis[:80]] or ["_None._"]
    lines.append("")

    # Hidden API Candidates — fully qualified (full URL / host / service / source).
    _table(
        "Hidden API Candidates",
        ji.get("hidden_apis", []),
        ["Endpoint", "Service", "Host", "Source", "Confidence", "Priority"],
        lambda x: [
            f"`{x.get('full_url') or x['endpoint']}`",
            x.get("service") or "—",
            x.get("host") or "—",
            x.get("source") or "—",
            x.get("confidence") or "—",
            x["priority"],
        ],
    )

    _table(
        "Hidden Route Candidates",
        ji.get("hidden_routes", []),
        ["Route", "Source", "Reason", "Confidence"],
        lambda r: [
            f"`{r['route']}`",
            r.get("source", "—"),
            r.get("reason", "—"),
            r.get("confidence", "—"),
        ],
    )

    sm = ji.get("source_maps", [])
    h(3, f"Source Map Intelligence ({len(sm)})")
    lines += [f"- `{m}`" for m in sm[:40]] or ["_None._"]
    lines.append("")

    # Intelligence Correlation Report v2 — fully-qualified (F7).
    corr = ji.get("correlation", [])
    h(3, f"Intelligence Correlation Report ({len(corr)})")
    if corr:
        lines.append(
            "| Module | Full URL | Service | Host | Source | Response Keys | Roles | Result |"
        )
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for c in corr:
            url = c.get("full_url") or (c["apis"][0] if c.get("apis") else "—")
            lines.append(
                f"| {c['feature']} | `{url}` | {c.get('service') or '—'} | "
                f"{c.get('host') or '—'} | {c.get('source') or '—'} | "
                f"{', '.join(c.get('response_keys', [])) or '—'} | "
                f"{', '.join(c.get('roles', [])) or '—'} | {c['result']} |"
            )
    else:
        lines.append("_No correlations._")
    lines.append("")

    # Browser Security Findings (F9).
    _risk_table("Browser Security Findings", ji.get("browser_security", []))

    # Top 20 Pentest Targets (F11).
    targets = ji.get("top_targets", [])
    h(3, f"Top {len(targets)} Pentest Targets")
    if targets:
        for t in targets:
            url = t.get("full_url") or t["endpoint"]
            lines.append(
                f"{t['rank']}. **{t['method']} `{url}`** ({t['risk']}) — "
                f"{t['reason']} · _{t['visibility']}_ · tests: {', '.join(t['tests'])}"
            )
    else:
        lines.append("_No prioritized targets._")
    lines.append("")


def _render_browser_intel(report: dict, h, lines: list[str]) -> None:
    """Sprint B: browser-resident intelligence sections."""
    bi = report.get("browser_intelligence") or {}
    s = bi.get("summary", {})
    if not s or not any(s.values()):
        return

    h(2, "Browser Intelligence Summary")
    lines.append(
        f"- **Feature flags:** {s.get('feature_flags', 0)} "
        f"({s.get('disabled_flags', 0)} disabled)  ·  "
        f"**Routes:** {s.get('routes', 0)}  ·  **Forms:** {s.get('forms', 0)}  ·  "
        f"**WebSockets:** {s.get('websockets', 0)}"
    )
    lines.append(
        f"- **IndexedDB stores:** {s.get('indexeddb_stores', 0)}  ·  "
        f"**Cache entries:** {s.get('cache_entries', 0)}  ·  "
        f"**Service workers:** {s.get('service_workers', 0)}  ·  "
        f"**Browser secrets:** {s.get('browser_secrets', 0)}"
    )
    lines.append(
        f"- **Sensitive data models:** {s.get('sensitive_models', 0)}  ·  "
        f"**Hidden functions:** {s.get('hidden_functions', 0)}  ·  "
        f"**Trusted domains:** {s.get('trusted_domains', 0)}\n"
    )

    def _table(title, rows, header, rowfn):
        h(3, f"{title} ({len(rows)})")
        if rows:
            lines.append("| " + " | ".join(header) + " |")
            lines.append("| " + " | ".join("---" for _ in header) + " |")
            for r in rows[:60]:
                lines.append("| " + " | ".join(rowfn(r)) + " |")
        else:
            lines.append("_None._")
        lines.append("")

    # Browser Secret Discovery.
    secs = bi.get("browser_secrets", [])
    _table(
        "Browser Secret Discovery",
        secs,
        ["Finding", "Sample (masked)", "Location", "Source"],
        lambda f: [
            f.get("name", ""),
            f"`{f.get('value_masked') or '—'}`",
            f.get("location") or "—",
            f.get("source") or "—",
        ],
    )

    # Hidden Functionality.
    hidden = bi.get("hidden_functionality", [])
    _table(
        "Hidden Functionality Report",
        hidden,
        ["Item", "Type", "Reason", "Priority"],
        lambda x: [f"`{x['item']}`", x["type"], x["reason"], x["priority"]],
    )

    # Feature flags.
    _table(
        "Feature Flag Intelligence",
        bi.get("feature_flags", []),
        ["Feature", "Enabled"],
        lambda f: [
            f["feature"],
            "✅" if f["enabled"] else ("❌" if f["enabled"] is False else "—"),
        ],
    )

    # Routes.
    _table(
        "Route Intelligence",
        bi.get("routes", []),
        ["Route", "Type"],
        lambda r: [f"`{r['route']}`", r["type"]],
    )

    # Forms.
    _table(
        "Form Intelligence",
        bi.get("forms", []),
        ["Action", "Method", "Fields"],
        lambda f: [f"`{f['action']}`", f["method"], ", ".join(f.get("fields", [])[:8])],
    )

    # WebSockets.
    _table(
        "WebSocket Intelligence",
        bi.get("websockets", []),
        ["URL", "Message Types", "Fields"],
        lambda w: [
            f"`{w['url']}`",
            ", ".join(w.get("messageTypes", [])[:5]) or "—",
            ", ".join(w.get("fields", [])[:8]) or "—",
        ],
    )

    # IndexedDB.
    h(3, f"IndexedDB Intelligence ({len(bi.get('indexeddb', []))})")
    for db in bi.get("indexeddb", []):
        for st in db.get("stores", []):
            lines.append(
                f"- `{db['database']} / {st.get('name')}` — {st.get('count')} records · "
                f"fields: {', '.join(st.get('fields', [])[:8]) or '—'}"
            )
    lines.append("") if bi.get("indexeddb") else lines.extend(["_None._", ""])

    # Cache storage.
    h(3, f"Cache Storage Intelligence ({len(bi.get('cache_storage', []))})")
    for c in bi.get("cache_storage", []):
        lines.append(f"- **{c['cache']}** ({len(c.get('entries', []))} entries)")
        lines += [f"    - `{e}`" for e in c.get("entries", [])[:15]]
    lines.append("") if bi.get("cache_storage") else lines.extend(["_None._", ""])

    # Service workers.
    _table(
        "Service Worker Intelligence",
        bi.get("service_workers", []),
        ["Script", "Scope"],
        lambda w: [f"`{w.get('scriptURL')}`", w.get("scope") or "—"],
    )

    # Runtime config.
    _table(
        "Runtime Configuration",
        bi.get("runtime_config", []),
        ["Global", "Key", "Value"],
        lambda c: [c.get("global") or "—", c["key"], f"`{c.get('value') or '—'}`"],
    )

    # Framework state.
    _table(
        "Framework State Intelligence",
        bi.get("framework_state", []),
        ["Framework", "State Keys"],
        lambda f: [f["framework"], ", ".join(f.get("keys", [])[:12]) or "—"],
    )

    # CSP.
    h(3, f"CSP Analysis ({len(bi.get('csp', []))})")
    for c in bi.get("csp", []):
        dirs = c.get("directives", {})
        domains = sorted({d for v in dirs.values() for d in v if "." in d})
        lines.append(f"- `{c['url']}` — trusted: {', '.join(domains[:10]) or '—'}")
    lines.append("") if bi.get("csp") else lines.extend(["_None._", ""])

    # CORS.
    _table(
        "CORS Analysis",
        bi.get("cors", []),
        ["Host", "Allow-Origin", "Credentials"],
        lambda c: [c.get("host", ""), str(c.get("allow_origin")), str(c.get("allow_credentials"))],
    )

    # Cookies (attributes).
    _table(
        "Authentication Cookie Inventory",
        bi.get("cookies", []),
        ["Name", "Secure", "HttpOnly", "SameSite", "Session"],
        lambda c: [
            c.get("name", ""),
            "✅" if c.get("secure") else "—",
            "✅" if c.get("httpOnly") else "—",
            str(c.get("sameSite") or "—"),
            "✅" if c.get("session_cookie") else "—",
        ],
    )

    # Manifest.
    _table(
        "Manifest Intelligence", bi.get("manifest", []), ["Manifest"], lambda m: [f"`{m['href']}`"]
    )

    # Architecture map.
    arch = bi.get("architecture_map", {})
    h(2, "Browser Architecture Map")
    lines.append(
        f"- **Trusted domains (CSP):** {', '.join(arch.get('trusted_domains', [])) or '—'}"
    )
    lines.append(f"- **CORS hosts:** {', '.join(arch.get('cors_hosts', [])) or '—'}")
    lines.append(f"- **Config URLs:** {', '.join(arch.get('config_urls', [])) or '—'}\n")

    # Correlation.
    corr = bi.get("correlation", [])
    h(2, f"Browser Intelligence Correlation ({len(corr)})")
    if corr:
        lines.append("| Module | Routes | Feature Flag | Confidence |")
        lines.append("| --- | --- | --- | --- |")
        for c in corr:
            lines.append(
                f"| {c['module']} | {', '.join(c['routes']) or '—'} | "
                f"{c.get('feature_flag') or '—'} | {c['confidence']} |"
            )
    else:
        lines.append("_No correlations._")
    lines.append("")


def _render_precision(report: dict, h, lines: list[str]) -> None:
    """Sprint A.5: the pentester-facing prioritization sections."""
    ri = report.get("recon_intelligence") or {}
    if not ri:
        return

    s = ri.get("summary", {})
    h(2, "Recon Intelligence Summary")
    lines.append(
        f"- **Admin-only endpoints:** {s.get('admin_only_endpoints', 0)}  ·  "
        f"**Sensitive-data endpoints:** {s.get('sensitive_data_endpoints', 0)}  ·  "
        f"**IDOR candidates:** {s.get('idor_candidates', 0)}"
    )
    lines.append(
        f"- **Hidden endpoints:** {s.get('hidden_endpoints', 0)}  ·  "
        f"**Secrets:** {s.get('secrets', 0)}  ·  "
        f"**Telemetry endpoints:** {s.get('telemetry_endpoints', 0)}  ·  "
        f"**Immediate targets:** {s.get('immediate_targets', 0)}"
    )
    if s.get("headline_targets"):
        lines.append("- **Start here:** " + ", ".join(f"`{t}`" for t in s["headline_targets"]))
    lines.append("")

    # Top 10 Pentest Targets.
    targets = ri.get("top_targets", [])
    h(2, f"Top {len(targets)} Pentest Targets")
    if targets:
        for t in targets:
            h(3, f"#{t['rank']} — {t['method']} `{t['endpoint']}`  ({t['risk']} risk)")
            lines.append(f"- **Why:** {t['reason']}")
            lines.append(f"- **Visibility:** {t['visibility']}")
            lines.append(f"- **Tests:** {', '.join(t['tests'])}")
            lines.append(f"- **Confidence:** {t['confidence']}")
            lines.append("")
    else:
        lines.append("_No prioritized targets (no captured behavioral evidence)._\n")

    # Pentest Target Queue.
    queue = ri.get("target_queue", {})
    h(2, "Pentest Target Queue")
    for band in ("Immediate", "High", "Medium", "Low"):
        items = queue.get(band, [])
        h(3, f"{band} ({len(items)})")
        if items:
            for it in items[:25]:
                lines.append(f"- `{it['endpoint']}` — {it['reason']} ({it['visibility']})")
            if len(items) > 25:
                lines.append(f"- … and {len(items) - 25} more")
        else:
            lines.append("_None._")
        lines.append("")

    # Sensitive Data Models.
    models = ri.get("sensitive_data_models", [])
    h(2, f"Sensitive Data Models ({len(models)})")
    if models:
        lines.append("| Endpoint | Sensitive Fields | Categories | Risk | Confidence |")
        lines.append("| --- | --- | --- | --- | --- |")
        for m in models[:80]:
            lines.append(
                f"| `{m['method']} {m['endpoint']}` | {', '.join(m['sensitive_fields'][:6])} | "
                f"{', '.join(m['categories'])} | {m['risk']} | {m['confidence']} |"
            )
    else:
        lines.append("_No sensitive response schemas captured._")
    lines.append("")

    # Risk-Based Attack Surface.
    surface = ri.get("risk_attack_surface", [])
    h(2, f"Risk-Based Attack Surface ({len(surface)})")
    if surface:
        lines.append("| Endpoint | Score | Signals |")
        lines.append("| --- | ---: | --- |")
        for r in surface[:60]:
            lines.append(f"| `{r['endpoint']}` | {r['score']} | {'; '.join(r['signals'])} |")
    else:
        lines.append("_No scored attack surface._")
    lines.append("")

    # Telemetry & Monitoring Inventory.
    telem = ri.get("telemetry_inventory", [])
    h(2, f"Telemetry & Monitoring Inventory ({len(telem)})")
    if telem:
        lines.append("_Excluded from attack surface / targets (observability, not app surface)._\n")
        lines.append("| Provider | Host | Paths |")
        lines.append("| --- | --- | --- |")
        for t in telem:
            lines.append(f"| {t['provider']} | {t['host']} | {', '.join(t['paths'][:4]) or '—'} |")
    else:
        lines.append("_No telemetry/monitoring traffic detected._")
    lines.append("")

    # Confidence Breakdown.
    cb = ri.get("confidence_breakdown", {})
    h(2, "Confidence Breakdown")
    lines.append(
        f"- **High:** {cb.get('high', 0)}  ·  **Medium:** {cb.get('medium', 0)}  ·  "
        f"**Low:** {cb.get('low', 0)}"
    )
    lines.append(
        "\n_High = observed + schema extracted · Medium = referenced/not observed · "
        "Low = keyword match only._"
    )
    lines.append("")


def _render_recon_intelligence(report: dict, h, lines: list[str]) -> None:
    """Sprint A: secrets, hidden endpoints/APIs, routes, config, source maps,
    storage, business functions, correlation, and high-priority recon targets."""
    ri = report.get("recon_intelligence") or {}
    if not ri:
        return

    # Secret Discovery Findings (grouped, masked).
    groups = ri.get("secret_findings", {})
    h(2, f"Secret Discovery Findings ({ri.get('secret_count', 0)})")
    if groups:
        for category in sorted(groups):
            items = groups[category]
            h(3, f"{category} ({len(items)})")
            lines.append("| Finding | Sample (masked) | Location | Source | Conf | Severity |")
            lines.append("| --- | --- | --- | --- | --- | --- |")
            for f in items[:80]:
                lines.append(
                    f"| {f.get('name', '')} | `{f.get('value_masked') or '—'}` | "
                    f"{f.get('location') or '—'} | {f.get('source') or '—'} | "
                    f"{f.get('confidence') or '—'} | {f.get('severity') or '—'} |"
                )
            lines.append("")
    else:
        lines.append("_No secrets/sensitive data detected in captured content._\n")

    # High Priority Recon Targets.
    targets = ri.get("recon_targets", [])
    h(2, f"High Priority Recon Targets ({len(targets)})")
    if targets:
        for i, t in enumerate(targets[:40], 1):
            lines.append(f"{i}. `{t['target']}` — _{t['reason']}_ ({t['priority']})")
    else:
        lines.append("_None._")
    lines.append("")

    # Hidden Endpoint Candidates (referenced but not observed).
    hidden = ri.get("hidden_endpoints", [])
    h(2, f"Hidden Endpoint Candidates ({len(hidden)})")
    if hidden:
        lines.append("| Endpoint | Referenced | Observed | Priority |")
        lines.append("| --- | :---: | :---: | --- |")
        for hcand in hidden[:120]:
            lines.append(f"| `{hcand['endpoint']}` | yes | no | {hcand['priority']} |")
    else:
        lines.append("_No referenced-but-unobserved endpoints._")
    lines.append("")

    # Hidden API Candidates.
    apis = ri.get("hidden_api_candidates", [])
    h(2, f"Hidden API Candidates ({len(apis)})")
    lines += [f"- `{a}`" for a in apis[:120]] or ["_None._"]
    lines.append("")

    # Frontend Route Inventory.
    routes = ri.get("frontend_routes", [])
    h(2, f"Frontend Route Inventory ({len(routes)})")
    lines += [f"- `{r}`" for r in routes[:120]] or [
        "_No routes extracted (minified bundle / no source maps)._"
    ]
    lines.append("")

    # Configuration Discovery.
    cfg = ri.get("configuration", [])
    h(2, f"Configuration Discovery ({len(cfg)})")
    if cfg:
        lines.append("| Setting | Value | Location |")
        lines.append("| --- | --- | --- |")
        for c in cfg[:60]:
            val = c.get("value_masked") or "—"
            loc = c.get("location") or "—"
            lines.append(f"| {c.get('name', '')} | `{val}` | {loc} |")
    else:
        lines.append("_No configuration values extracted._")
    lines.append("")

    # Source Map Analysis.
    maps = ri.get("source_maps", [])
    h(2, f"Source Map Analysis ({len(maps)})")
    lines += [f"- `{m}`" for m in maps[:60]] or ["_No source maps referenced._"]
    lines.append("")

    # Storage Intelligence.
    storage = ri.get("storage", {})
    items = storage.get("items", [])
    h(2, f"Storage Intelligence ({len(items)})")
    if items:
        lines.append("| Storage | Role | Key | Classification | Value (masked) |")
        lines.append("| --- | --- | --- | --- | --- |")
        for s in items[:80]:
            lines.append(
                f"| {s['storage']} | {s.get('role') or '—'} | {s['key']} | "
                f"{s['classification']} | `{s.get('value_masked') or '—'}` |"
            )
        for note in storage.get("notes", []):
            lines.append(f"\n- ⚠️ {note}")
    else:
        lines.append("_No client-side storage captured._")
    lines.append("")

    # Business Function Discovery.
    funcs = ri.get("business_functions", [])
    h(2, f"Business Function Discovery ({len(funcs)})")
    if funcs:
        for f in funcs:
            lines.append(f"- **{f['function']}** — {', '.join(f['evidence'])}")
    else:
        lines.append("_None inferred._")
    lines.append("")

    # Intelligence Correlation Report.
    corr = ri.get("correlation", [])
    h(2, f"Intelligence Correlation Report ({len(corr)})")
    rows = [c for c in corr if c.get("response_keys") or c.get("business_module") or c.get("roles")]
    if rows:
        lines.append("| Endpoint | Module | Response Keys | Roles |")
        lines.append("| --- | --- | --- | --- |")
        for c in rows[:120]:
            keys = ", ".join(c.get("response_keys", [])[:6])
            lines.append(
                f"| `{c['endpoint']}` | {c.get('business_module') or '—'} | "
                f"{keys or '—'} | {', '.join(c.get('roles', [])) or '—'} |"
            )
    else:
        lines.append("_No correlations available._")
    lines.append("")


def _render_domain(report: dict, h, lines: list[str]) -> None:
    """Render the 8 external-domain-intelligence sections."""
    di = report.get("domain_intelligence") or {}
    if not di.get("hosts"):
        return

    # 1. Hostname Inventory
    h(2, f"Hostname Inventory ({len(di['hosts'])})")
    lines.append("| Host | Classification | Requests | APIs | Auth | Roles |")
    lines.append("| --- | --- | ---: | ---: | :---: | --- |")
    for hh in di["hosts"]:
        auth = "🔒" if hh.get("auth_required") else "—"
        lines.append(
            f"| {hh['host']} | {hh['classification']} | {hh['requests']} | {hh['apis']} | "
            f"{auth} | {', '.join(hh.get('roles', [])) or '—'} |"
        )
    lines.append("")

    # 2. Internal APIs
    ia = di.get("internal_apis", [])
    h(2, f"Internal APIs ({len(ia)} hosts)")
    if ia:
        for api in ia:
            h(3, f"{api['host']} ({api['count']} endpoints)")
            lines.append(f"_Visible to: {', '.join(api.get('roles', [])) or '—'}_\n")
            lines.append("```")
            for ep in api["endpoints"][:60]:
                lines.append(f"{ep['method']:5} {ep['path']}")
            lines.append("```")
            lines.append("")
    else:
        lines.append("_No internal (same-organization) API hosts observed._\n")

    # 3. Third-Party Services
    tp = di.get("third_party", [])
    h(2, f"Third-Party Services ({len(tp)})")
    if tp:
        lines.append("| Host | Classification | Observed Requests | Visible Roles |")
        lines.append("| --- | --- | ---: | --- |")
        for t in tp:
            lines.append(
                f"| {t['host']} | {t['classification']} | {t['requests']} | "
                f"{', '.join(t.get('roles', [])) or '—'} |"
            )
    else:
        lines.append("_No external services observed._")
    lines.append("")

    # 4. Authentication Infrastructure
    ai = di.get("auth_infra", {})
    h(2, "Authentication Infrastructure")
    lines.append(f"- **Identity Provider:** {ai.get('identity_provider', 'Unknown')}")
    lines.append(f"- **Authentication Type:** {ai.get('authentication_type', 'Unknown')}")
    ev = ai.get("evidence", [])
    if ev:
        lines.append("- **Discovery Evidence:**")
        lines += [f"  - {e}" for e in ev if e]
    lines.append("")

    # 5. API Relationship Graph
    rel = di.get("relationships", {})
    h(2, "API Relationship Graph")
    lines.append("```")
    lines.append(rel.get("base", ""))
    edges = rel.get("edges", [])
    for i, e in enumerate(edges):
        branch = "└──" if i == len(edges) - 1 else "├──"
        lines.append(f" {branch} {e['to']}  ({e['kind']})")
    lines.append("```")
    lines.append("")

    # 6. Role-Based API Visibility
    av = di.get("api_visibility", [])
    h(2, "Role-Based API Visibility")
    if av:
        lines.append("| Host | Visible To |")
        lines.append("| --- | --- |")
        for v in av:
            vis = "Admin Only" if v.get("admin_only") else (", ".join(v.get("roles", [])) or "—")
            lines.append(f"| {v['host']} | {vis} |")
    else:
        lines.append("_No internal API visibility data._")
    lines.append("")

    # 7. High Value Attack Surface
    hv = di.get("high_value", [])
    h(2, f"High Value Attack Surface ({len(hv)})")
    if hv:
        lines.append("| Endpoint | Classification | Visible To |")
        lines.append("| --- | --- | --- |")
        for v in hv:
            lines.append(
                f"| {v['endpoint']} | {v['classification']} | "
                f"{', '.join(v.get('roles', [])) or '—'} |"
            )
    else:
        lines.append("_No high-value endpoints identified._")
    lines.append("")

    # 8. Infrastructure Summary
    isum = di.get("infrastructure_summary", {})
    h(2, "Infrastructure Summary")
    lines.append(
        f"- Internal APIs: {isum.get('internal_apis', 0)} · "
        f"Auth providers: {isum.get('auth_providers', 0)} · "
        f"Third-party: {isum.get('third_party', 0)} · "
        f"Analytics: {isum.get('analytics', 0)} · CDN: {isum.get('cdn', 0)} · "
        f"Payment: {isum.get('payment', 0)}"
    )
    if isum.get("dependencies"):
        lines.append(f"- **Primary dependencies:** {', '.join(isum['dependencies'])}")
    if isum.get("functional_areas"):
        lines.append(f"- **Functional areas:** {', '.join(isum['functional_areas'])}")
    lines.append("")


def write_markdown_report(
    data: dict[str, list[dict]], output_dir: str | Path, *, filename: str = "output.md", **opts: Any
) -> Path:
    """Write the Markdown report (default ``output.md``) and return its path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / filename
    path.write_text(render_markdown(data, **opts), encoding="utf-8")
    return path
