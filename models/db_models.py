"""SQLAlchemy 2.0 ORM models.

Schema: a parent ``targets`` row with nine child tables (one per data category),
each referencing ``targets.id``. These mirror the Pydantic DTOs in
``models.schemas`` but are persistence-only concerns.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    url: Mapped[str] = mapped_column(String(2048))
    domain: Mapped[str | None] = mapped_column(String(512), index=True, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    subdomains: Mapped[list[Subdomain]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    directories: Mapped[list[Directory]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    technologies: Mapped[list[Technology]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    ssl_findings: Mapped[list[SSLFindingRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    js_findings: Mapped[list[JSFindingRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    network_services: Mapped[list[NetworkServiceRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    api_endpoints: Mapped[list[ApiEndpointRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    har_requests: Mapped[list[HarRequestRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    burp_requests: Mapped[list[BurpRequestRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    users: Mapped[list[UserRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    role_access: Mapped[list[RoleEndpointAccessRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    crawl_endpoints: Mapped[list[CrawlEndpointRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    forms: Mapped[list[FormRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    workflow_edges: Mapped[list[WorkflowEdgeRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    sensitive_functions: Mapped[list[SensitiveFunctionRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    api_intel: Mapped[list[ApiIntelRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    checklist_items: Mapped[list[ChecklistItemRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    idp_info: Mapped[list[IdPInfoRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    auth_artifacts: Mapped[list[AuthArtifactRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    sessions: Mapped[list[SessionRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    hosts: Mapped[list[HostRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    domain_edges: Mapped[list[DomainEdgeRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    intel_findings: Mapped[list[IntelFindingRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    dns_records: Mapped[list[DnsRecordRow]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )


class _Child(Base):
    """Abstract mixin: every child table links back to a target."""

    __abstract__ = True

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class Subdomain(_Child):
    __tablename__ = "subdomains"
    __table_args__ = (UniqueConstraint("target_id", "name", name="uq_subdomain"),)

    name: Mapped[str] = mapped_column(String(512))
    resolved: Mapped[bool] = mapped_column(default=False)
    ip_addresses: Mapped[str | None] = mapped_column(Text)  # comma-separated
    source: Mapped[str] = mapped_column(String(64), default="crt.sh")

    target: Mapped[Target] = relationship(back_populates="subdomains")


class Directory(_Child):
    __tablename__ = "directories"
    __table_args__ = (UniqueConstraint("target_id", "url", name="uq_directory"),)

    path: Mapped[str] = mapped_column(String(2048))
    url: Mapped[str] = mapped_column(String(2048))
    status_code: Mapped[int] = mapped_column(Integer)
    content_length: Mapped[int | None] = mapped_column(Integer)
    content_type: Mapped[str | None] = mapped_column(String(256))
    category: Mapped[str] = mapped_column(String(32), default="common")
    confidence: Mapped[str | None] = mapped_column(String(16))
    expected_content_type: Mapped[str | None] = mapped_column(String(128))
    validation: Mapped[str | None] = mapped_column(String(64))

    target: Mapped[Target] = relationship(back_populates="directories")


class Technology(_Child):
    __tablename__ = "technologies"
    __table_args__ = (UniqueConstraint("target_id", "name", name="uq_technology"),)

    name: Mapped[str] = mapped_column(String(128))
    category: Mapped[str] = mapped_column(String(32))  # frontend | backend | server
    evidence: Mapped[str | None] = mapped_column(Text)

    target: Mapped[Target] = relationship(back_populates="technologies")


class SSLFindingRow(_Child):
    __tablename__ = "ssl_findings"

    host: Mapped[str] = mapped_column(String(512))
    port: Mapped[int] = mapped_column(Integer, default=443)
    issuer: Mapped[str | None] = mapped_column(Text)
    subject: Mapped[str | None] = mapped_column(Text)
    not_before: Mapped[datetime | None] = mapped_column(DateTime)
    not_after: Mapped[datetime | None] = mapped_column(DateTime)
    san_entries: Mapped[str | None] = mapped_column(Text)
    tls_versions: Mapped[str | None] = mapped_column(Text)
    is_expired: Mapped[bool] = mapped_column(default=False)
    is_self_signed: Mapped[bool] = mapped_column(default=False)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    summary: Mapped[str] = mapped_column(Text, default="")

    target: Mapped[Target] = relationship(back_populates="ssl_findings")


class JSFindingRow(_Child):
    __tablename__ = "js_findings"

    kind: Mapped[str] = mapped_column(String(32))  # api_endpoint | email | jwt | aws_key | ...
    value: Mapped[str] = mapped_column(Text)
    source: Mapped[str | None] = mapped_column(String(2048))

    target: Mapped[Target] = relationship(back_populates="js_findings")


class NetworkServiceRow(_Child):
    __tablename__ = "network_services"
    __table_args__ = (UniqueConstraint("target_id", "port", "protocol", name="uq_service"),)

    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    service: Mapped[str | None] = mapped_column(String(128))
    version: Mapped[str | None] = mapped_column(String(256))
    state: Mapped[str] = mapped_column(String(16), default="open")

    target: Mapped[Target] = relationship(back_populates="network_services")


class ApiEndpointRow(_Child):
    __tablename__ = "api_endpoints"

    path: Mapped[str] = mapped_column(String(2048))
    method: Mapped[str] = mapped_column(String(16), default="GET")
    source: Mapped[str] = mapped_column(String(32), default="openapi")
    parameters: Mapped[str | None] = mapped_column(Text)
    summary: Mapped[str | None] = mapped_column(Text)

    target: Mapped[Target] = relationship(back_populates="api_endpoints")


class HarRequestRow(_Child):
    __tablename__ = "har_requests"

    url: Mapped[str] = mapped_column(String(2048))
    method: Mapped[str] = mapped_column(String(16))
    query_params: Mapped[str | None] = mapped_column(Text)
    headers: Mapped[str | None] = mapped_column(Text)
    cookies: Mapped[str | None] = mapped_column(Text)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_content_type: Mapped[str | None] = mapped_column(String(256))
    response_size: Mapped[int | None] = mapped_column(Integer)
    response_keys: Mapped[str | None] = mapped_column(Text)  # csv of top-level JSON keys
    redirect_url: Mapped[str | None] = mapped_column(String(2048))  # 3xx Location (redacted)
    role: Mapped[str | None] = mapped_column(String(64))

    target: Mapped[Target] = relationship(back_populates="har_requests")


class BurpRequestRow(_Child):
    __tablename__ = "burp_requests"

    url: Mapped[str] = mapped_column(String(2048))
    method: Mapped[str] = mapped_column(String(16))
    parameters: Mapped[str | None] = mapped_column(Text)
    cookies: Mapped[str | None] = mapped_column(Text)
    auth_tokens: Mapped[str | None] = mapped_column(Text)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_content_type: Mapped[str | None] = mapped_column(String(256))
    redirect_url: Mapped[str | None] = mapped_column(String(2048))  # 3xx Location (redacted)
    role: Mapped[str | None] = mapped_column(String(64))

    target: Mapped[Target] = relationship(back_populates="burp_requests")


class UserRow(_Child):
    """A configured identity/role (credentials are NOT stored, only metadata)."""

    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("target_id", "role", name="uq_user_role"),)

    role: Mapped[str] = mapped_column(String(64))
    username: Mapped[str | None] = mapped_column(String(256))
    has_password: Mapped[bool] = mapped_column(default=False)
    has_token: Mapped[bool] = mapped_column(default=False)
    har: Mapped[str | None] = mapped_column(String(1024))
    burp: Mapped[str | None] = mapped_column(String(1024))

    target: Mapped[Target] = relationship(back_populates="users")


class RoleEndpointAccessRow(_Child):
    """Role-to-endpoint access mapping (the access matrix, row per role+endpoint)."""

    __tablename__ = "role_endpoint_access"
    __table_args__ = (
        UniqueConstraint("target_id", "role", "method", "path", name="uq_role_endpoint"),
    )

    role: Mapped[str] = mapped_column(String(64), index=True)
    method: Mapped[str] = mapped_column(String(16), default="GET")
    path: Mapped[str] = mapped_column(String(2048))
    url: Mapped[str | None] = mapped_column(String(2048))
    status_code: Mapped[int | None] = mapped_column(Integer)
    accessible: Mapped[bool] = mapped_column(default=False)
    source: Mapped[str] = mapped_column(String(16), default="live")

    target: Mapped[Target] = relationship(back_populates="role_access")


# ---------------------------------------------------------------------------
# Tier 2 tables
# ---------------------------------------------------------------------------


class DnsRecordRow(_Child):
    """A passively-resolved DNS record for a discovered host (opt-in --dns)."""

    __tablename__ = "dns_records"

    host: Mapped[str] = mapped_column(String(512), index=True)
    record_type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(2048))

    target: Mapped[Target] = relationship(back_populates="dns_records")


class CrawlEndpointRow(_Child):
    __tablename__ = "crawl_endpoints"
    __table_args__ = (
        UniqueConstraint("target_id", "role", "method", "path", name="uq_crawl_endpoint"),
    )

    role: Mapped[str] = mapped_column(String(64), index=True)
    url: Mapped[str] = mapped_column(String(2048))
    path: Mapped[str] = mapped_column(String(2048))
    method: Mapped[str] = mapped_column(String(16), default="GET")
    status_code: Mapped[int | None] = mapped_column(Integer)
    content_type: Mapped[str | None] = mapped_column(String(256))
    source: Mapped[str] = mapped_column(String(16), default="crawl")
    title: Mapped[str | None] = mapped_column(String(512))
    redirect_chain: Mapped[str | None] = mapped_column(Text)  # JSON list of redirect hops

    target: Mapped[Target] = relationship(back_populates="crawl_endpoints")


class FormRow(_Child):
    __tablename__ = "forms"

    role: Mapped[str | None] = mapped_column(String(64))
    page_url: Mapped[str] = mapped_column(String(2048))
    action: Mapped[str] = mapped_column(String(2048))
    method: Mapped[str] = mapped_column(String(16), default="GET")
    fields: Mapped[str | None] = mapped_column(Text)  # csv of name:type

    target: Mapped[Target] = relationship(back_populates="forms")


class WorkflowEdgeRow(_Child):
    __tablename__ = "workflow_edges"

    role: Mapped[str | None] = mapped_column(String(64))
    from_path: Mapped[str] = mapped_column(String(2048))
    to_path: Mapped[str] = mapped_column(String(2048))
    kind: Mapped[str] = mapped_column(String(16), default="link")

    target: Mapped[Target] = relationship(back_populates="workflow_edges")


class SensitiveFunctionRow(_Child):
    __tablename__ = "sensitive_functions"

    category: Mapped[str] = mapped_column(String(64), index=True)
    subcategory: Mapped[str | None] = mapped_column(String(64))
    endpoint: Mapped[str] = mapped_column(String(2048))
    evidence: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[str | None] = mapped_column(String(16))
    role: Mapped[str | None] = mapped_column(String(64))

    target: Mapped[Target] = relationship(back_populates="sensitive_functions")


class ApiIntelRow(_Child):
    __tablename__ = "api_intel"

    path: Mapped[str] = mapped_column(String(2048))
    methods: Mapped[str | None] = mapped_column(Text)
    parameters: Mapped[str | None] = mapped_column(Text)
    response_types: Mapped[str | None] = mapped_column(Text)
    id_parameters: Mapped[str | None] = mapped_column(Text)
    authz_sensitive: Mapped[bool] = mapped_column(default=False)
    sensitivity_reason: Mapped[str | None] = mapped_column(Text)

    target: Mapped[Target] = relationship(back_populates="api_intel")


class ChecklistItemRow(_Child):
    __tablename__ = "checklist_items"

    category: Mapped[str] = mapped_column(String(64), index=True)
    endpoint: Mapped[str | None] = mapped_column(String(2048))
    item: Mapped[str] = mapped_column(Text)
    done: Mapped[bool] = mapped_column(default=False)

    target: Mapped[Target] = relationship(back_populates="checklist_items")


# ---------------------------------------------------------------------------
# Enterprise authentication tables
# ---------------------------------------------------------------------------


class IdPInfoRow(_Child):
    __tablename__ = "idp_info"

    identity_provider: Mapped[str] = mapped_column(String(64))
    authentication_type: Mapped[str] = mapped_column(String(32))
    realm: Mapped[str | None] = mapped_column(String(256))
    evidence: Mapped[str | None] = mapped_column(Text)
    metadata_url: Mapped[str | None] = mapped_column(String(2048))

    target: Mapped[Target] = relationship(back_populates="idp_info")


class AuthArtifactRow(_Child):
    """Auth artifacts observed for a role. Values are stored MASKED only."""

    __tablename__ = "auth_artifacts"

    role: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(256))
    value_masked: Mapped[str] = mapped_column(String(256))
    source: Mapped[str] = mapped_column(String(16), default="session")

    target: Mapped[Target] = relationship(back_populates="auth_artifacts")


class SessionRow(_Child):
    __tablename__ = "sessions"
    __table_args__ = (UniqueConstraint("target_id", "role", name="uq_session_role"),)

    role: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(32))
    captured: Mapped[bool] = mapped_column(default=False)
    cookie_count: Mapped[int] = mapped_column(Integer, default=0)
    has_storage: Mapped[bool] = mapped_column(default=False)
    detail: Mapped[str | None] = mapped_column(Text)

    target: Mapped[Target] = relationship(back_populates="sessions")


class HostRow(_Child):
    """External-domain inventory entry (one per host the app communicates with)."""

    __tablename__ = "hosts"
    __table_args__ = (UniqueConstraint("target_id", "host", name="uq_host"),)

    host: Mapped[str] = mapped_column(String(512))
    classification: Mapped[str] = mapped_column(String(64), index=True)
    requests: Mapped[int] = mapped_column(Integer, default=0)
    apis: Mapped[int] = mapped_column(Integer, default=0)
    auth_required: Mapped[bool] = mapped_column(default=False)
    internal: Mapped[bool] = mapped_column(default=False)
    roles: Mapped[str | None] = mapped_column(Text)

    target: Mapped[Target] = relationship(back_populates="hosts")


class DomainEdgeRow(_Child):
    __tablename__ = "domain_edges"

    from_host: Mapped[str] = mapped_column(String(512))
    to_host: Mapped[str] = mapped_column(String(512))
    kind: Mapped[str] = mapped_column(String(64))

    target: Mapped[Target] = relationship(back_populates="domain_edges")


class IntelFindingRow(_Child):
    """Generic recon-intelligence finding (secrets, config, storage, routes…).

    Values are stored MASKED for secrets/PII; non-secret config/routes verbatim.
    """

    __tablename__ = "intel_findings"

    kind: Mapped[str] = mapped_column(String(64), index=True)  # api_key | jwt | route | config | …
    category: Mapped[str] = mapped_column(String(64), index=True)  # Authentication | API Keys | …
    name: Mapped[str] = mapped_column(String(256))  # human label / provider
    value_masked: Mapped[str | None] = mapped_column(Text)
    location: Mapped[str | None] = mapped_column(String(2048))  # where it was seen
    source: Mapped[str | None] = mapped_column(String(64))  # HAR response | JS | Local Storage | …
    confidence: Mapped[str | None] = mapped_column(String(16))
    severity: Mapped[str | None] = mapped_column(String(16))
    extra: Mapped[str | None] = mapped_column(Text)  # JSON blob for type-specific detail

    target: Mapped[Target] = relationship(back_populates="intel_findings")
