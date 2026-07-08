"""SQLite persistence via SQLAlchemy ORM.

The :class:`Database` wraps engine/session lifecycle and provides idempotent
``save_*`` repository helpers (one per data category) plus read helpers used by
reporting and the ``list-assets`` CLI command. Saves are upsert-like: re-running a
scan refreshes a target's rows rather than duplicating them.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from sqlalchemy import create_engine, delete, inspect, select, text
from sqlalchemy.orm import Session, sessionmaker

from models import db_models as db
from models.schemas import (
    ApiEndpoint,
    ApiIntel,
    AuthArtifact,
    BurpRequest,
    ChecklistItem,
    CrawlEndpoint,
    DirectoryHit,
    DiscoveredForm,
    HarRequest,
    IdPInfo,
    IntelFinding,
    JSFinding,
    NetworkService,
    RoleEndpointAccess,
    SensitiveFunction,
    SessionInfo,
    SSLFinding,
    Subdomain,
    TargetInput,
    TechStack,
    UserCredential,
    WorkflowEdge,
)


def _csv(values: Sequence[str] | None) -> str | None:
    return ",".join(values) if values else None


class Database:
    """Thin repository over the SQLAlchemy ORM."""

    def __init__(self, url: str = "sqlite:///asdf.db", *, echo: bool = False) -> None:
        self.engine = create_engine(url, echo=echo, future=True)
        self._session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.init_db()

    def init_db(self) -> None:
        """Create missing tables and add any columns added since the DB was made."""
        db.Base.metadata.create_all(self.engine)
        self._ensure_columns()
        self._ensure_fts()

    def _ensure_fts(self) -> None:
        """Create the FTS5 knowledge index (no-op if FTS5 is unavailable)."""
        with self.engine.begin() as conn:
            try:
                conn.execute(
                    text(
                        "CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5("
                        "target_id UNINDEXED, kind, role, path, category, text)"
                    )
                )
                self._fts_available = True
            except Exception:  # noqa: BLE001 - FTS5 not compiled in; degrade gracefully
                self._fts_available = False

    def _ensure_columns(self) -> None:
        """Lightweight forward-migration: add columns introduced on existing tables.

        ``create_all`` creates missing tables but never alters existing ones, so a
        database created by an older version is migrated here (SQLite-friendly
        ``ALTER TABLE ... ADD COLUMN``). New tables are handled by ``create_all``.
        """
        added_columns: dict[str, dict[str, str]] = {
            "har_requests": {
                "role": "VARCHAR(64)",
                "response_size": "INTEGER",
                "response_keys": "TEXT",
                "redirect_url": "VARCHAR(2048)",
            },
            "burp_requests": {"role": "VARCHAR(64)", "redirect_url": "VARCHAR(2048)"},
            "crawl_endpoints": {"redirect_chain": "TEXT"},
            "idp_info": {"realm": "VARCHAR(256)"},
            "sensitive_functions": {"confidence": "VARCHAR(16)"},
            "api_intel": {"hosts": "TEXT"},
            "directories": {
                "confidence": "VARCHAR(16)",
                "expected_content_type": "VARCHAR(128)",
                "validation": "VARCHAR(64)",
            },
        }
        insp = inspect(self.engine)
        tables = set(insp.get_table_names())
        with self.engine.begin() as conn:
            for table, columns in added_columns.items():
                if table not in tables:
                    continue
                existing = {c["name"] for c in insp.get_columns(table)}
                for column, ddl in columns.items():
                    if column not in existing:
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))

    def session(self) -> Session:
        return self._session_factory()

    # -- target -----------------------------------------------------------
    def upsert_target(self, target: TargetInput) -> int:
        """Insert or fetch the target row by domain, returning its id."""
        with self.session() as s:
            row = None
            if target.domain:
                row = s.scalar(select(db.Target).where(db.Target.domain == target.domain))
            if row is None:
                row = db.Target(url=target.url, domain=target.domain)
                s.add(row)
            else:
                row.url = target.url
            s.commit()
            return row.id

    def get_target_id(self, domain: str) -> int | None:
        with self.session() as s:
            return s.scalar(select(db.Target.id).where(db.Target.domain == domain))

    # -- generic replace helper ------------------------------------------
    def _replace(self, target_id: int, model: type[db.Base], rows: list[db.Base]) -> None:
        with self.session() as s:
            s.execute(delete(model).where(model.target_id == target_id))
            for r in rows:
                r.target_id = target_id
                s.add(r)
            s.commit()

    # -- save_* repositories ---------------------------------------------
    def save_subdomains(self, target_id: int, items: list[Subdomain]) -> None:
        rows = [
            db.Subdomain(
                name=i.name, resolved=i.resolved, ip_addresses=_csv(i.ip_addresses), source=i.source
            )
            for i in items
        ]
        self._replace(target_id, db.Subdomain, rows)

    def save_directories(self, target_id: int, items: list[DirectoryHit]) -> None:
        rows = [
            db.Directory(
                path=i.path,
                url=i.url,
                status_code=i.status_code,
                content_length=i.content_length,
                content_type=i.content_type,
                category=i.category,
                confidence=i.confidence,
                expected_content_type=i.expected_content_type,
                validation=i.validation,
            )
            for i in items
        ]
        self._replace(target_id, db.Directory, rows)

    def merge_directories(self, target_id: int, items: list[DirectoryHit]) -> None:
        """Add directory/probe hits that aren't already present (dedupe by url).

        Non-destructive counterpart to ``save_directories`` — used by the tier-2
        per-service backend probe to append management/API-doc hits without wiping the
        directory-enum results.
        """
        with self.session() as s:
            existing = {
                r[0]
                for r in s.execute(
                    select(db.Directory.url).where(db.Directory.target_id == target_id)
                )
            }
            for i in items:
                if i.url in existing:
                    continue
                existing.add(i.url)
                s.add(
                    db.Directory(
                        target_id=target_id,
                        path=i.path,
                        url=i.url,
                        status_code=i.status_code,
                        content_length=i.content_length,
                        content_type=i.content_type,
                        category=i.category,
                        confidence=i.confidence,
                        expected_content_type=i.expected_content_type,
                        validation=i.validation,
                    )
                )
            s.commit()

    def save_techstack(self, target_id: int, tech: TechStack) -> None:
        rows: list[db.Technology] = []
        for name in tech.frontend:
            rows.append(
                db.Technology(
                    name=name, category="frontend", evidence=_csv(tech.evidence.get(name))
                )
            )
        for name in tech.backend:
            rows.append(
                db.Technology(name=name, category="backend", evidence=_csv(tech.evidence.get(name)))
            )
        for name in tech.servers:
            rows.append(
                db.Technology(name=name, category="server", evidence=_csv(tech.evidence.get(name)))
            )
        for name in tech.libraries:
            rows.append(
                db.Technology(name=name, category="library", evidence=_csv(tech.evidence.get(name)))
            )
        self._replace(target_id, db.Technology, rows)

    def merge_technologies(self, target_id: int, items: list[tuple[str, str, str | None]]) -> None:
        """Add technologies (name, category, evidence) that aren't already present.

        Used to augment the static fingerprint with browser-runtime findings without
        wiping it. De-duplicates by name (the table's unique key per target).
        """
        with self.session() as s:
            existing = {
                r[0]
                for r in s.execute(
                    select(db.Technology.name).where(db.Technology.target_id == target_id)
                )
            }
            for name, category, evidence in items:
                if name in existing:
                    continue
                existing.add(name)
                s.add(
                    db.Technology(
                        target_id=target_id, name=name, category=category, evidence=evidence
                    )
                )
            s.commit()

    def save_ssl_findings(self, target_id: int, items: list[SSLFinding]) -> None:
        rows = [
            db.SSLFindingRow(
                host=i.host,
                port=i.port,
                issuer=i.issuer,
                subject=i.subject,
                not_before=i.not_before,
                not_after=i.not_after,
                san_entries=_csv(i.san_entries),
                tls_versions=_csv(i.tls_versions),
                is_expired=i.is_expired,
                is_self_signed=i.is_self_signed,
                severity=i.severity,
                summary=i.summary,
            )
            for i in items
        ]
        self._replace(target_id, db.SSLFindingRow, rows)

    def save_js_findings(self, target_id: int, finding: JSFinding) -> None:
        rows: list[db.JSFindingRow] = []
        buckets = {
            "api_endpoint": finding.api_endpoints,
            "email": finding.emails,
            "url": finding.urls,
            "jwt": finding.jwts,
            "aws_key": finding.aws_keys,
            "azure_key": finding.azure_keys,
            "google_api_key": finding.google_api_keys,
            "comment": finding.comments,
            "interesting": finding.interesting_strings,
        }
        for kind, values in buckets.items():
            for v in values:
                rows.append(db.JSFindingRow(kind=kind, value=v))
        self._replace(target_id, db.JSFindingRow, rows)

    def save_network_services(self, target_id: int, items: list[NetworkService]) -> None:
        rows = [
            db.NetworkServiceRow(
                port=i.port,
                protocol=i.protocol,
                service=i.service,
                version=i.version,
                state=i.state,
            )
            for i in items
        ]
        self._replace(target_id, db.NetworkServiceRow, rows)

    def save_api_endpoints(self, target_id: int, items: list[ApiEndpoint]) -> None:
        rows = [
            db.ApiEndpointRow(
                path=i.path,
                method=i.method,
                source=i.source,
                parameters=_csv(i.parameters),
                summary=i.summary,
            )
            for i in items
        ]
        self._replace(target_id, db.ApiEndpointRow, rows)

    def save_har_requests(self, target_id: int, items: list[HarRequest]) -> None:
        rows = [
            db.HarRequestRow(
                url=i.url,
                method=i.method,
                query_params=_csv(i.query_params),
                headers=json.dumps(i.headers) if i.headers else None,
                cookies=json.dumps(i.cookies) if i.cookies else None,
                response_status=i.response_status,
                response_content_type=i.response_content_type,
                response_size=i.response_size,
                response_keys=_csv(i.response_keys),
                redirect_url=i.redirect_url,
                role=i.role,
            )
            for i in items
        ]
        self._replace(target_id, db.HarRequestRow, rows)

    def save_burp_requests(self, target_id: int, items: list[BurpRequest]) -> None:
        rows = [
            db.BurpRequestRow(
                url=i.url,
                method=i.method,
                parameters=_csv(i.parameters),
                cookies=json.dumps(i.cookies) if i.cookies else None,
                auth_tokens=_csv(i.auth_tokens),
                response_status=i.response_status,
                response_content_type=i.response_content_type,
                redirect_url=i.redirect_url,
                role=i.role,
            )
            for i in items
        ]
        self._replace(target_id, db.BurpRequestRow, rows)

    def save_users(self, target_id: int, items: list[UserCredential]) -> None:
        rows = [
            db.UserRow(
                role=u.role,
                username=u.username,
                has_password=bool(u.password),
                has_token=bool(u.jwt_token),
                har=u.har,
                burp=u.burp,
            )
            for u in items
        ]
        self._replace(target_id, db.UserRow, rows)

    def save_role_access(self, target_id: int, items: list[RoleEndpointAccess]) -> None:
        rows = [
            db.RoleEndpointAccessRow(
                role=i.role,
                method=i.method,
                path=i.path,
                url=i.url,
                status_code=i.status_code,
                accessible=i.accessible,
                source=i.source,
            )
            for i in items
        ]
        self._replace(target_id, db.RoleEndpointAccessRow, rows)

    # -- Tier 2 repositories ---------------------------------------------
    def save_dns_records(self, target_id: int, items: list) -> None:
        rows = [
            db.DnsRecordRow(host=i.host, record_type=i.record_type, value=i.value) for i in items
        ]
        self._replace(target_id, db.DnsRecordRow, rows)

    def save_crawl_endpoints(self, target_id: int, items: list[CrawlEndpoint]) -> None:
        # De-duplicate by (role, method, path): distinct URLs can map to one path.
        unique: dict[tuple[str, str, str], CrawlEndpoint] = {}
        for i in items:
            unique.setdefault((i.role, i.method, i.path), i)
        rows = [
            db.CrawlEndpointRow(
                role=i.role,
                url=i.url,
                path=i.path,
                method=i.method,
                status_code=i.status_code,
                content_type=i.content_type,
                source=i.source,
                title=i.title,
                redirect_chain=json.dumps(i.redirect_chain) if i.redirect_chain else None,
            )
            for i in unique.values()
        ]
        self._replace(target_id, db.CrawlEndpointRow, rows)

    def save_forms(self, target_id: int, items: list[DiscoveredForm]) -> None:
        rows = [
            db.FormRow(
                role=i.role,
                page_url=i.page_url,
                action=i.action,
                method=i.method,
                fields=_csv([f"{f.name}:{f.type}" for f in i.fields]),
            )
            for i in items
        ]
        self._replace(target_id, db.FormRow, rows)

    def save_workflow_edges(self, target_id: int, items: list[WorkflowEdge]) -> None:
        rows = [
            db.WorkflowEdgeRow(role=i.role, from_path=i.from_path, to_path=i.to_path, kind=i.kind)
            for i in items
        ]
        self._replace(target_id, db.WorkflowEdgeRow, rows)

    def save_sensitive_functions(self, target_id: int, items: list[SensitiveFunction]) -> None:
        rows = [
            db.SensitiveFunctionRow(
                category=i.category,
                subcategory=i.subcategory,
                endpoint=i.endpoint,
                evidence=i.evidence,
                confidence=i.confidence,
                role=i.role,
            )
            for i in items
        ]
        self._replace(target_id, db.SensitiveFunctionRow, rows)

    def save_api_intel(self, target_id: int, items: list[ApiIntel]) -> None:
        rows = [
            db.ApiIntelRow(
                path=i.path,
                methods=_csv(i.methods),
                parameters=_csv(i.parameters),
                response_types=_csv(i.response_types),
                id_parameters=_csv(i.id_parameters),
                authz_sensitive=i.authz_sensitive,
                sensitivity_reason=i.sensitivity_reason,
                hosts=_csv(i.hosts),
            )
            for i in items
        ]
        self._replace(target_id, db.ApiIntelRow, rows)

    def save_checklist_items(self, target_id: int, items: list[ChecklistItem]) -> None:
        rows = [
            db.ChecklistItemRow(category=i.category, endpoint=i.endpoint, item=i.item, done=i.done)
            for i in items
        ]
        self._replace(target_id, db.ChecklistItemRow, rows)

    # -- enterprise auth -------------------------------------------------
    def save_idp_info(self, target_id: int, items: list[IdPInfo]) -> None:
        rows = [
            db.IdPInfoRow(
                identity_provider=i.identity_provider,
                authentication_type=i.authentication_type,
                realm=i.realm,
                evidence=_csv(i.evidence),
                metadata_url=i.metadata_url,
            )
            for i in items
        ]
        self._replace(target_id, db.IdPInfoRow, rows)

    def save_auth_artifacts(self, target_id: int, items: list[AuthArtifact]) -> None:
        # De-duplicate by (role, kind, name); store masked values only.
        unique: dict[tuple[str, str, str], AuthArtifact] = {}
        for i in items:
            unique.setdefault((i.role, i.kind, i.name), i)
        rows = [
            db.AuthArtifactRow(
                role=i.role,
                kind=i.kind,
                name=i.name,
                value_masked=i.value_masked,
                source=i.source,
            )
            for i in unique.values()
        ]
        self._replace(target_id, db.AuthArtifactRow, rows)

    def save_sessions(self, target_id: int, items: list[SessionInfo]) -> None:
        unique: dict[str, SessionInfo] = {}
        for i in items:
            unique[i.role] = i
        rows = [
            db.SessionRow(
                role=i.role,
                source=i.source,
                captured=i.captured,
                cookie_count=i.cookie_count,
                has_storage=i.has_storage,
                detail=i.detail,
            )
            for i in unique.values()
        ]
        self._replace(target_id, db.SessionRow, rows)

    # -- domain intelligence ---------------------------------------------
    def save_hosts(self, target_id: int, hosts: list[dict]) -> None:
        rows = [
            db.HostRow(
                host=h["host"],
                classification=h["classification"],
                requests=h.get("requests", 0),
                apis=h.get("apis", 0),
                auth_required=bool(h.get("auth_required")),
                internal=bool(h.get("internal")),
                roles=_csv(h.get("roles")),
            )
            for h in hosts
        ]
        self._replace(target_id, db.HostRow, rows)

    def save_domain_edges(self, target_id: int, edges: list[dict]) -> None:
        rows = [
            db.DomainEdgeRow(from_host=e["from_host"], to_host=e["to_host"], kind=e["kind"])
            for e in edges
        ]
        self._replace(target_id, db.DomainEdgeRow, rows)

    def save_intel_findings(self, target_id: int, items: list[IntelFinding]) -> None:
        rows = [
            db.IntelFindingRow(
                kind=i.kind,
                category=i.category,
                name=i.name,
                value_masked=i.value_masked,
                location=i.location,
                source=i.source,
                confidence=i.confidence,
                severity=i.severity,
                extra=json.dumps(i.extra) if i.extra else None,
            )
            for i in items
        ]
        self._replace(target_id, db.IntelFindingRow, rows)

    # -- knowledge base (FTS5) -------------------------------------------
    def index_knowledge(self, target_id: int, docs: list[dict]) -> None:
        """Replace this target's knowledge rows. Each doc: kind/role/path/category/text."""
        if not getattr(self, "_fts_available", False):
            return
        with self.engine.begin() as conn:
            conn.execute(text("DELETE FROM knowledge_fts WHERE target_id = :t"), {"t": target_id})
            for d in docs:
                conn.execute(
                    text(
                        "INSERT INTO knowledge_fts (target_id, kind, role, path, category, text) "
                        "VALUES (:target_id, :kind, :role, :path, :category, :text)"
                    ),
                    {
                        "target_id": target_id,
                        "kind": d.get("kind", ""),
                        "role": d.get("role", ""),
                        "path": d.get("path", ""),
                        "category": d.get("category", ""),
                        "text": d.get("text", ""),
                    },
                )

    def search_knowledge(self, target_id: int, query: str, limit: int = 50) -> list[dict]:
        """Full-text search the knowledge index for a target."""
        if not getattr(self, "_fts_available", False):
            return []
        with self.engine.begin() as conn:
            rows = conn.execute(
                text(
                    "SELECT kind, role, path, category, text FROM knowledge_fts "
                    "WHERE target_id = :t AND knowledge_fts MATCH :q LIMIT :lim"
                ),
                {"t": target_id, "q": query, "lim": limit},
            ).fetchall()
        return [
            {"kind": r[0], "role": r[1], "path": r[2], "category": r[3], "text": r[4]} for r in rows
        ]

    # -- read helpers (reporting / list-assets) --------------------------
    def fetch_all(self, target_id: int, *, show_pii: bool = False) -> dict[str, list[dict]]:
        """Return every stored row for a target as plain dicts, grouped by table.

        ``show_pii`` is forwarded to JWT decoding so name/email render unmasked
        (internal environments only); default keeps PII masked.
        """
        with self.session() as s:
            target = s.get(db.Target, target_id)
            if target is None:
                return {}

            def dump(rows: Sequence[db.Base], fields: list[str]) -> list[dict]:
                return [{f: getattr(r, f) for f in fields} for r in rows]

            result = {
                "target": {"id": target.id, "url": target.url, "domain": target.domain},
                "subdomains": dump(
                    target.subdomains, ["name", "resolved", "ip_addresses", "source"]
                ),
                "directories": dump(
                    target.directories,
                    [
                        "path",
                        "url",
                        "status_code",
                        "content_length",
                        "content_type",
                        "category",
                        "confidence",
                        "expected_content_type",
                        "validation",
                    ],
                ),
                "technologies": dump(target.technologies, ["name", "category", "evidence"]),
                "ssl_findings": dump(
                    target.ssl_findings,
                    [
                        "host",
                        "port",
                        "issuer",
                        "subject",
                        "not_before",
                        "not_after",
                        "san_entries",
                        "tls_versions",
                        "is_expired",
                        "is_self_signed",
                        "severity",
                        "summary",
                    ],
                ),
                "js_findings": dump(target.js_findings, ["kind", "value", "source"]),
                "network_services": dump(
                    target.network_services, ["port", "protocol", "service", "version", "state"]
                ),
                "api_endpoints": dump(
                    target.api_endpoints, ["path", "method", "source", "parameters", "summary"]
                ),
                "har_requests": dump(
                    target.har_requests,
                    [
                        "url",
                        "method",
                        "query_params",
                        "response_status",
                        "response_content_type",
                        "response_size",
                        "response_keys",
                        "redirect_url",
                        "role",
                    ],
                ),
                "burp_requests": dump(
                    target.burp_requests,
                    [
                        "url",
                        "method",
                        "parameters",
                        "auth_tokens",
                        "response_status",
                        "redirect_url",
                        "role",
                    ],
                ),
                "users": dump(
                    target.users, ["role", "username", "has_password", "has_token", "har", "burp"]
                ),
                "role_access": dump(
                    target.role_access,
                    ["role", "method", "path", "url", "status_code", "accessible", "source"],
                ),
                "crawl_endpoints": dump(
                    target.crawl_endpoints,
                    [
                        "role",
                        "url",
                        "path",
                        "method",
                        "status_code",
                        "content_type",
                        "source",
                        "title",
                        "redirect_chain",
                    ],
                ),
                "dns_records": dump(target.dns_records, ["host", "record_type", "value"]),
                "forms": dump(target.forms, ["role", "page_url", "action", "method", "fields"]),
                "workflow_edges": dump(
                    target.workflow_edges, ["role", "from_path", "to_path", "kind"]
                ),
                "sensitive_functions": dump(
                    target.sensitive_functions,
                    ["category", "subcategory", "endpoint", "evidence", "confidence", "role"],
                ),
                "api_intel": dump(
                    target.api_intel,
                    [
                        "path",
                        "methods",
                        "parameters",
                        "response_types",
                        "id_parameters",
                        "authz_sensitive",
                        "sensitivity_reason",
                        "hosts",
                    ],
                ),
                "checklist_items": dump(
                    target.checklist_items, ["category", "endpoint", "item", "done"]
                ),
                "idp_info": dump(
                    target.idp_info,
                    [
                        "identity_provider",
                        "authentication_type",
                        "realm",
                        "evidence",
                        "metadata_url",
                    ],
                ),
                "auth_artifacts": dump(
                    target.auth_artifacts, ["role", "kind", "name", "value_masked", "source"]
                ),
                "sessions": dump(
                    target.sessions,
                    ["role", "source", "captured", "cookie_count", "has_storage", "detail"],
                ),
                "hosts": dump(
                    target.hosts,
                    [
                        "host",
                        "classification",
                        "requests",
                        "apis",
                        "auth_required",
                        "internal",
                        "roles",
                    ],
                ),
                "domain_edges": dump(target.domain_edges, ["from_host", "to_host", "kind"]),
                "intel_findings": [
                    {
                        "kind": r.kind,
                        "category": r.category,
                        "name": r.name,
                        "value_masked": r.value_masked,
                        "location": r.location,
                        "source": r.source,
                        "confidence": r.confidence,
                        "severity": r.severity,
                        "extra": json.loads(r.extra) if r.extra else {},
                    }
                    for r in target.intel_findings
                ],
            }

            # JWT Authorization Intelligence: decode bearer tokens from captured HAR
            # headers / Burp auth tokens at the fetch boundary (headers are not part of
            # the dump). Only the MASKED authorization summary enters `data` — raw
            # tokens never leave the storage layer.
            from modules.intelligence.jwt_intelligence import harvest_jwt_summaries

            har_rows = [
                {"headers": json.loads(r.headers) if r.headers else {}, "role": r.role}
                for r in target.har_requests
            ]
            burp_rows = [
                {
                    "auth_tokens": (r.auth_tokens.split(",") if r.auth_tokens else []),
                    "role": r.role,
                }
                for r in target.burp_requests
            ]
            result["jwt_authorization"] = harvest_jwt_summaries(
                har_rows, burp_rows, show_pii=show_pii
            )

            # Cookie JWT Intelligence: decode JWTs carried inside captured cookies at
            # the same fetch boundary (cookie values are raw in har_requests.cookies but
            # not part of the dump). Only the MASKED summary enters `data`.
            from modules.intelligence.jwt_intelligence import harvest_cookie_jwts

            cookie_rows = [
                {"cookies": json.loads(r.cookies) if r.cookies else {}, "role": r.role}
                for r in target.har_requests
            ]
            result["cookie_jwt_authorization"] = harvest_cookie_jwts(cookie_rows, show_pii=show_pii)
            return result
