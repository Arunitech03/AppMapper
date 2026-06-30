"""Pydantic v2 DTOs used across the framework.

These are the in-memory data structures that modules produce and that the
storage layer persists. They are intentionally decoupled from the SQLAlchemy ORM
models (``models.db_models``) so modules never depend on the database.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------


class LoginConfig(BaseModel):
    """How to perform a form-based login for a role (Tier 2 authenticated crawl).

    All fields are optional: when omitted, the crawler auto-detects the login form
    on the target's base page (the first form containing a password input). Login
    uses the role's configured credentials only — never brute forcing or bypass.
    """

    url: str | None = None  # absolute or path; defaults to detected form action
    username_field: str | None = None
    password_field: str | None = None
    extra_fields: dict[str, str] = Field(default_factory=dict)
    success_status: int | None = None  # expected status on success (e.g. 302/200)
    success_contains: str | None = None  # text expected in a successful response


class UserCredential(BaseModel):
    """A single authenticated identity (role) used during assessment.

    Reusable user model: drives capture attribution, role-based access comparison,
    and Tier 2 authenticated crawling. Credentials are used ONLY to (a) parse
    already-authenticated captures, (b) attach an Authorization header / session
    cookie to read-only discovery requests, and (c) perform a single configured
    login POST for crawling — never to brute force, bypass auth, or escalate.
    """

    role: str = "default"
    username: str | None = None
    password: str | None = None
    jwt_token: str | None = None
    cookie: str | None = None  # raw "name=value; name2=value2" session cookie
    session_file: str | None = None  # Playwright storage_state JSON (browser session)
    auth_mode: str | None = None  # per-role override: none | jwt | session | cookie | har
    login: LoginConfig | None = None  # optional explicit login config
    har: str | None = None  # optional per-role HAR capture file
    burp: str | None = None  # optional per-role Burp export file
    exploration: str | None = None  # exploration.json from `auth explore` (manual capture)

    def auth_header(self) -> dict[str, str]:
        """Authorization header derived from this user's JWT (discovery use only)."""
        if self.jwt_token:
            return {"Authorization": f"Bearer {self.jwt_token}"}
        return {}

    @property
    def can_authenticate(self) -> bool:
        """True when this role can make authenticated requests (any credential form)."""
        return bool(
            self.jwt_token
            or self.cookie
            or self.session_file
            or self.har
            or self.burp
            or (self.username and self.password)
        )

    @property
    def strategy(self) -> str:
        """Resolved auth strategy for this role (explicit auth_mode wins)."""
        if self.auth_mode:
            return self.auth_mode
        if self.session_file:
            return "session"
        if self.jwt_token:
            return "jwt"
        if self.cookie:
            return "cookie"
        if self.har or self.burp:
            return "har"
        if self.username and self.password:
            return "login"
        return "none"


class TargetInput(BaseModel):
    """The target under assessment, plus the set of identities (roles) to use."""

    url: str
    domain: str | None = None
    auth_mode: str = "auto"  # none | jwt | session | har | auto
    crawl_start: list[str] = Field(default_factory=list)  # extra authenticated seed paths
    users: list[UserCredential] = Field(default_factory=list)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"target url must be an absolute http(s) URL, got: {value!r}")
        return value.rstrip("/")

    def model_post_init(self, __context: Any) -> None:  # noqa: D401
        # Derive domain from the URL when not explicitly provided.
        if not self.domain:
            object.__setattr__(self, "domain", urlparse(self.url).hostname)

    @property
    def host(self) -> str:
        """The hostname portion of the target URL."""
        return urlparse(self.url).hostname or (self.domain or "")

    @property
    def port(self) -> int:
        parsed = urlparse(self.url)
        if parsed.port:
            return parsed.port
        return 443 if parsed.scheme == "https" else 80

    @property
    def primary(self) -> UserCredential | None:
        """The first configured identity, used for single-auth discovery requests."""
        return self.users[0] if self.users else None

    def auth_header(self) -> dict[str, str]:
        """Authorization header from the primary identity (discovery use only)."""
        return self.primary.auth_header() if self.primary else {}


# ---------------------------------------------------------------------------
# Per-module result DTOs
# ---------------------------------------------------------------------------


class Subdomain(BaseModel):
    name: str
    resolved: bool = False
    ip_addresses: list[str] = Field(default_factory=list)
    source: str = "crt.sh"


class DirectoryHit(BaseModel):
    path: str
    url: str
    status_code: int
    content_length: int | None = None
    content_type: str | None = None
    category: str = "common"  # common | admin | backup | api
    confidence: str = "medium"  # high | medium | low
    expected_content_type: str | None = None  # what a real hit should return
    validation: str | None = None  # e.g. "SPA fallback suspected" | "verified"


class TechStack(BaseModel):
    frontend: list[str] = Field(default_factory=list)
    backend: list[str] = Field(default_factory=list)
    servers: list[str] = Field(default_factory=list)
    libraries: list[str] = Field(default_factory=list)  # client-side UI/JS libraries
    evidence: dict[str, list[str]] = Field(default_factory=dict)


class SSLFinding(BaseModel):
    host: str
    port: int = 443
    issuer: str | None = None
    subject: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    san_entries: list[str] = Field(default_factory=list)
    tls_versions: list[str] = Field(default_factory=list)
    is_expired: bool = False
    is_self_signed: bool = False
    severity: str = "info"  # info | low | medium | high
    summary: str = ""


class JSFinding(BaseModel):
    api_endpoints: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    jwts: list[str] = Field(default_factory=list)
    aws_keys: list[str] = Field(default_factory=list)
    azure_keys: list[str] = Field(default_factory=list)
    google_api_keys: list[str] = Field(default_factory=list)
    comments: list[str] = Field(default_factory=list)
    interesting_strings: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)


class NetworkService(BaseModel):
    port: int
    protocol: str = "tcp"
    service: str | None = None
    version: str | None = None
    state: str = "open"


class ApiEndpoint(BaseModel):
    path: str
    method: str = "GET"
    source: str = "openapi"  # openapi | swagger | graphql | har | burp
    parameters: list[str] = Field(default_factory=list)
    summary: str | None = None


class HarRequest(BaseModel):
    url: str
    method: str
    query_params: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    response_status: int | None = None
    response_content_type: str | None = None
    response_size: int | None = None
    response_keys: list[str] = Field(default_factory=list)  # top-level JSON keys ONLY
    redirect_url: str | None = None  # 3xx Location / HAR redirectURL (redacted)
    role: str | None = None  # which identity this capture belongs to


class BurpRequest(BaseModel):
    url: str
    method: str
    parameters: list[str] = Field(default_factory=list)
    cookies: dict[str, str] = Field(default_factory=dict)
    auth_tokens: list[str] = Field(default_factory=list)
    response_status: int | None = None
    response_content_type: str | None = None
    redirect_url: str | None = None  # 3xx Location header (redacted)
    role: str | None = None  # which identity this capture belongs to


class RoleEndpointAccess(BaseModel):
    """Whether a given role can reach a given endpoint (GET reachability).

    ``source`` records how the observation was made:
      - ``live``    : a read-only GET issued with the role's auth header
      - ``har``/``burp`` : observed in that role's captured traffic
    ``accessible`` is True for 2xx/3xx responses, False for 401/403 (denied).
    """

    role: str
    method: str = "GET"
    path: str
    url: str | None = None
    status_code: int | None = None
    accessible: bool = False
    source: str = "live"  # live | har | burp


# ---------------------------------------------------------------------------
# Tier 2: application intelligence DTOs
# ---------------------------------------------------------------------------


class FormField(BaseModel):
    name: str
    type: str = "text"


class DiscoveredForm(BaseModel):
    role: str | None = None
    page_url: str
    action: str
    method: str = "GET"
    fields: list[FormField] = Field(default_factory=list)


class DnsRecord(BaseModel):
    """A passively-resolved DNS record for a discovered host."""

    host: str
    record_type: str  # A | AAAA | CNAME | TXT | MX | NS | SOA
    value: str


class CrawlEndpoint(BaseModel):
    role: str
    url: str
    path: str
    method: str = "GET"
    status_code: int | None = None
    content_type: str | None = None
    source: str = "crawl"  # crawl | link | form | api | file
    title: str | None = None
    redirect_chain: list[str] = Field(default_factory=list)  # redirect hops (redacted URLs)


class WorkflowEdge(BaseModel):
    role: str | None = None
    from_path: str
    to_path: str
    kind: str = "link"  # link | nav | redirect | form | sequence


class SensitiveFunction(BaseModel):
    category: str  # Authentication | User Management | File Handling | ...
    subcategory: str | None = None
    endpoint: str
    evidence: str | None = None  # matched indicator(s), comma-separated
    confidence: str = "medium"  # high | medium | low (by indicator count)
    role: str | None = None


class ApiIntel(BaseModel):
    path: str
    methods: list[str] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)
    response_types: list[str] = Field(default_factory=list)
    id_parameters: list[str] = Field(default_factory=list)
    authz_sensitive: bool = False
    sensitivity_reason: str | None = None
    hosts: list[str] = Field(default_factory=list)  # hosts this path was observed on


class ChecklistItem(BaseModel):
    category: str
    endpoint: str | None = None
    item: str
    done: bool = False


class GraphNode(BaseModel):
    id: str
    label: str
    kind: str  # page | endpoint | api | role | form | file


class GraphEdge(BaseModel):
    source: str
    target: str
    kind: str = "links"


class AppSummary(BaseModel):
    provider: str
    text: str


# ---------------------------------------------------------------------------
# Enterprise authentication DTOs
# ---------------------------------------------------------------------------


class IdPInfo(BaseModel):
    """Detected identity provider / authentication type (discovery only)."""

    identity_provider: str = "Unknown"  # Keycloak | Okta | Auth0 | Azure AD | ...
    authentication_type: str = "Unknown"  # OIDC | OAuth2 | SAML | Form | None
    realm: str | None = None  # Keycloak realm (or tenant) when detectable
    evidence: list[str] = Field(default_factory=list)
    metadata_url: str | None = None


class AuthArtifact(BaseModel):
    """An authentication artifact observed for a role. Values are MASKED."""

    role: str
    # cookie | access_token | refresh_token | id_token | authorization |
    # local_storage | session_storage
    kind: str
    name: str
    value_masked: str
    source: str = "session"  # session | jwt | cookie | har | burp


class SessionInfo(BaseModel):
    """Per-role session inventory entry."""

    role: str
    source: str  # session_file | jwt | cookie | har | login | none
    captured: bool = False
    cookie_count: int = 0
    has_storage: bool = False
    detail: str | None = None


class ResolvedSession(BaseModel):
    """Runtime-only: the concrete cookies/headers a role's session resolves to.

    Never persisted; secrets here are raw (used to make requests). Only masked
    derivatives (``AuthArtifact``) are stored or reported.
    """

    role: str
    cookies: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    artifacts: list[AuthArtifact] = Field(default_factory=list)
    source: str = "none"


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


class ScanContext(BaseModel):
    """Everything a module needs to run, plus shared runtime configuration."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    target: TargetInput
    timeout: float = 10.0
    max_concurrency: int = 20
    user_agent: str = "ASDF-Framework/0.1 (+discovery-only)"
    verify_tls: bool = True
    wordlist_path: str | None = None
    # When set, HTTP clients use this identity's auth header instead of the
    # primary one. Drives per-role access comparison.
    active_user: UserCredential | None = None
    options: dict[str, Any] = Field(default_factory=dict)

    @property
    def users(self) -> list[UserCredential]:
        return self.target.users

    def for_user(self, user: UserCredential | None) -> ScanContext:
        """Return a copy of this context scoped to a specific identity."""
        return self.model_copy(update={"active_user": user})


class IntelFinding(BaseModel):
    """A recon-intelligence finding (secret, config, route, storage item, …).

    Secrets and PII are stored MASKED (``value_masked``); non-secret config/routes
    may be shown verbatim. ``extra`` carries type-specific JSON detail.
    """

    kind: str  # api_key | jwt | bearer | oauth_client_secret | email | route | config | …
    # Authentication | API Keys | Sensitive Data | Infrastructure | Routes | Config | Storage
    category: str
    name: str  # human label, e.g. "Google Maps API Key"
    value_masked: str | None = None
    location: str | None = None  # url/path/key where it was observed
    source: str | None = None  # HAR response | JS | Local Storage | …
    confidence: str = "medium"  # high | medium | low
    severity: str = "Informational"  # Informational | Low | Medium | High
    extra: dict = Field(default_factory=dict)


class ModuleResult(BaseModel):
    """A uniform envelope returned by every module."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    module: str
    ok: bool = True
    error: str | None = None
    # The payload type depends on the module; each module documents its shape.
    data: Any = None
    items: int = 0
