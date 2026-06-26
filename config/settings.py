"""Application settings and target-input loading.

Settings are environment-driven (via ``pydantic-settings``) and control
cross-cutting runtime behavior (timeouts, concurrency, logging). Target
information (the thing being assessed) is loaded separately from a YAML file or
CLI flags into a :class:`~models.schemas.TargetInput`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic_settings import BaseSettings, SettingsConfigDict

from models.schemas import TargetInput, UserCredential


class Settings(BaseSettings):
    """Runtime settings, overridable via ``ASDF_*`` environment variables."""

    model_config = SettingsConfigDict(env_prefix="ASDF_", env_file=".env", extra="ignore")

    # HTTP behavior
    http_timeout: float = 10.0
    http_max_concurrency: int = 20
    user_agent: str = "ASDF-Framework/0.1 (+discovery-only)"
    verify_tls: bool = True

    # Storage
    database_url: str = "sqlite:///asdf.db"

    # Reporting (logical folder under reports/, resolved by core.archive.resolve_report_dir)
    report_dir: str = "reports"

    # Tier 2: authenticated crawling
    crawl_enabled: bool = True
    max_pages: int = 60
    max_depth: int = 2

    # Tier 2: AI summary provider (env: ASDF_AI_PROVIDER, ASDF_AI_BASE_URL, ...)
    ai_provider: str = "template"  # template | ollama | openai_compatible
    ai_base_url: str | None = None
    ai_model: str | None = None
    ai_api_key: str | None = None

    # Passive subdomain intelligence: optional provider API keys
    # (env: ASDF_SECURITYTRAILS_API_KEY, ASDF_VIRUSTOTAL_API_KEY)
    securitytrails_api_key: str | None = None
    virustotal_api_key: str | None = None

    # Logging
    log_level: str = "INFO"
    log_json: bool = False


_USER_KEYS = (
    "role",
    "username",
    "password",
    "jwt_token",
    "cookie",
    "session_file",
    "auth_mode",
    "login",
    "har",
    "burp",
    "exploration",
)


def _users_from_config(data: dict[str, Any]) -> list[UserCredential]:
    """Build the users[] list from config, supporting the legacy single-user form.

    A per-user ``login:`` mapping is parsed into a ``LoginConfig`` (Tier 2 form
    login); pydantic coerces the nested dict automatically.
    """
    users: list[UserCredential] = []

    raw_users = data.get("users")
    if isinstance(raw_users, list):
        for entry in raw_users:
            if isinstance(entry, dict):
                users.append(UserCredential(**{k: entry.get(k) for k in _USER_KEYS if k in entry}))

    # Legacy single-user form: top-level username/password/jwt_token.
    if not users:
        legacy = {k: data.get(k) for k in ("username", "password", "jwt_token") if data.get(k)}
        if legacy:
            users.append(UserCredential(role=data.get("role", "default"), **legacy))

    return users


_CAPTURE_PATH_FIELDS = ("har", "burp", "exploration", "session_file")


def _resolve_capture_paths(users: list[UserCredential], base_dir: Path) -> None:
    """Resolve each user's relative capture paths against ``base_dir`` (the config dir).

    Absolute paths are left untouched; relative ones (e.g. ``captures/admin.har``,
    ``./exploration/admin.json``) become absolute paths anchored at the config file's
    directory, so an assessment runs the same regardless of the current directory.
    """
    for user in users:
        for field in _CAPTURE_PATH_FIELDS:
            value = getattr(user, field, None)
            if value and not Path(value).is_absolute():
                setattr(user, field, str((base_dir / value).resolve()))


def load_target(
    *,
    config_path: str | Path | None = None,
    url: str | None = None,
    domain: str | None = None,
    username: str | None = None,
    password: str | None = None,
    jwt_token: str | None = None,
    role: str | None = None,
    session: str | None = None,
    auth_mode: str | None = None,
    exploration: str | None = None,
) -> TargetInput:
    """Build a :class:`TargetInput` (with users[]) from YAML plus CLI overrides.

    The YAML may declare multiple identities under ``users:`` (each with ``role``,
    ``username``, ``password``, ``jwt_token``, ``har``, ``burp``), or a single
    legacy top-level ``username``/``password``/``jwt_token`` block. CLI single-user
    flags are used only when the config declares no ``users:`` list.
    """

    data: dict[str, Any] = {}
    if config_path is not None:
        raw = Path(config_path).read_text(encoding="utf-8")
        loaded = yaml.safe_load(raw) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"Config file {config_path} must contain a YAML mapping.")
        data.update(loaded)

    # Normalize the documented ``target_url`` key to our field name.
    if "target_url" in data and "url" not in data:
        data["url"] = data.pop("target_url")
    if url is not None:
        data["url"] = url
    if domain is not None:
        data["domain"] = domain

    if not data.get("url"):
        raise ValueError("A target URL is required (pass --url or set target_url in --config).")

    users = _users_from_config(data)

    # CLI single-user convenience: only when config declared no users.
    if not users and (username or password or jwt_token or session or exploration):
        users = [
            UserCredential(
                role=role or "default",
                username=username,
                password=password,
                jwt_token=jwt_token,
                session_file=session,
                exploration=exploration,
            )
        ]

    # Capture paths declared in a config file are resolved relative to that file's
    # directory, so each assessment under assessments/<name>/ is self-contained and
    # runnable from any working directory. CLI-supplied paths stay relative to CWD.
    if config_path is not None:
        _resolve_capture_paths(users, Path(config_path).resolve().parent)

    resolved_auth_mode = auth_mode or data.get("auth_mode", "auto")
    # auth_mode: none => unauthenticated discovery only (ignore any credentials).
    if resolved_auth_mode == "none":
        users = []

    crawl_start = data.get("crawl_start") or []
    if isinstance(crawl_start, str):
        crawl_start = [crawl_start]

    return TargetInput(
        url=data["url"],
        domain=data.get("domain"),
        auth_mode=resolved_auth_mode,
        crawl_start=list(crawl_start),
        users=users,
    )
