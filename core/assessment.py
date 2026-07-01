"""Active-assessment state.

`start <name>` scaffolds an assessment (``assessments/<name>/`` + ``<name>.db``) and
records it as the **active** assessment in ``.active_assessment.json``. Every command
that opens a database falls back to the active DB when ``--db`` is not given, so a
whole engagement shares one database without repeating ``--db`` each time.

Discovery/analysis only: this just manages local files and a pointer — no network.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

STATE_FILE = ".active_assessment.json"
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

_SCAFFOLD = """\
# Assessment: <name>
# Edit the target (and optionally credentials), then run:
#   python main.py scan --config assessments/<name>/target.yaml --report-dir <name>
# assessments/<name>/<name>.db is the active database (used after `start <name>`).
url: https://example.com
domain: example.com

# Drop HAR captures in assessments/<name>/captures/ and reference them per role.
users:
  - role: user
    # username: youruser
    # password: yourpass
    auth_mode: auto          # auto | login | har | session | jwt | cookie | none
    # login:                 # only if the form is NOT on the base URL
    #   url: /doLogin         # the form ACTION (POST target)
    #   username_field: uid
    #   password_field: passw
"""


def _root(root: str | Path | None = None) -> Path:
    return Path(root) if root else Path.cwd()


def _state_path(root: str | Path | None = None) -> Path:
    return _root(root) / STATE_FILE


def validate_name(name: str) -> str:
    """Return a safe assessment name or raise ValueError (no path traversal)."""
    name = (name or "").strip()
    if not _NAME_RE.match(name):
        raise ValueError(
            "assessment name must start alphanumeric and contain only letters, digits, "
            "'.', '-', '_' (max 64 chars)"
        )
    return name


def set_active(name: str, db: str, *, root: str | Path | None = None) -> None:
    _state_path(root).write_text(json.dumps({"name": name, "db": db}, indent=2) + "\n")


def _read(root: str | Path | None = None) -> dict:
    path = _state_path(root)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text()) or {}
    except (ValueError, OSError):
        return {}


def active_db(*, root: str | Path | None = None) -> str | None:
    """The active assessment's database path, or None when none is set."""
    return _read(root).get("db")


def active_name(*, root: str | Path | None = None) -> str | None:
    return _read(root).get("name")


def clear_active(*, root: str | Path | None = None) -> str | None:
    """Remove the active-assessment pointer. Returns the name that was cleared."""
    name = active_name(root=root)
    _state_path(root).unlink(missing_ok=True)
    return name


# Hosts ignored when inferring the target URL from captured traffic (telemetry/CDN/fonts).
_HOST_NOISE = (
    "datadoghq",
    "google-analytics",
    "googletagmanager",
    "gstatic",
    "fonts.googleapis",
    "doubleclick",
    "sentry",
    "newrelic",
)


def _role_from_filename(stem: str, name: str) -> str:
    """``user1_rni`` (assessment ``rni``) -> ``user1``; otherwise the stem unchanged."""
    if stem.endswith("_" + name) and len(stem) > len(name) + 1:
        return stem[: -len(name) - 1]
    return stem


def build_target_from_captures(name: str, *, root: str | Path | None = None):
    """Build a TargetInput from an assessment's captured inputs — HARs in
    ``captures/*.har`` (``auth_mode=har``) and exploration JSONs in
    ``exploration/*.json`` (from ``auth explore``). One role per file (role = filename,
    trailing ``_<name>`` stripped; exploration wins when a role has both). The target
    URL is inferred from the captured traffic. Returns None when there's nothing to
    discover.
    """
    base = _root(root)
    adir = base / "assessments" / name
    hars = sorted((adir / "captures").glob("*.har"))
    explorations = sorted((adir / "exploration").glob("*.json"))
    if not hars and not explorations:
        return None

    from collections import Counter
    from urllib.parse import urlparse

    from models.schemas import TargetInput, UserCredential
    from modules.intelligence.domain_classifier import registrable_domain
    from parsers.har_parser import parse_har

    hosts: Counter = Counter()

    def _count(har_path: Path) -> None:
        try:
            items = parse_har(str(har_path))
        except (OSError, ValueError):
            return
        for it in items:
            host = urlparse(it.url).netloc.lower()
            if host and not any(n in host for n in _HOST_NOISE):
                hosts[host] += 1

    by_role: dict[str, UserCredential] = {}
    for har in hars:
        _count(har)
        role = _role_from_filename(har.stem, name)
        by_role[role] = UserCredential(role=role, har=str(har), auth_mode="har")
    for expl in explorations:
        sibling = expl.with_suffix(".har")  # `auth explore` always writes a sibling HAR
        if sibling.is_file():
            _count(sibling)
        role = _role_from_filename(expl.stem, name)
        by_role[role] = UserCredential(role=role, exploration=str(expl))  # exploration wins

    if not hosts:
        return None
    top_host = hosts.most_common(1)[0][0]
    return TargetInput(
        url=f"https://{top_host}", domain=registrable_domain(top_host), users=list(by_role.values())
    )


def start_assessment(name: str, *, root: str | Path | None = None) -> dict:
    """Scaffold ``assessments/<name>/`` + ``<name>.db`` and set it active.

    Idempotent: re-running just re-activates; an existing ``target.yaml`` is kept.
    """
    name = validate_name(name)
    base = _root(root)
    folder = base / "assessments" / name
    (folder / "captures").mkdir(parents=True, exist_ok=True)

    target = folder / "target.yaml"
    created_target = not target.exists()
    if created_target:
        target.write_text(_SCAFFOLD.replace("<name>", name))

    # Keep the DB inside the assessment folder so the engagement is self-contained
    # and the repo root stays clean (asdf.db remains the only root DB).
    db = f"assessments/{name}/{name}.db"
    # Create the database file + schema up front so it exists immediately.
    from storage.database import Database

    Database(f"sqlite:///{base / db}")
    set_active(name, db, root=base)

    return {
        "name": name,
        "db": db,
        "folder": str(folder.relative_to(base)),
        "target": str(target.relative_to(base)),
        "created_target": created_target,
    }
