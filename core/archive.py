"""Assessment archive management & workspace cleanup.

Each engagement produces many artifacts (HARs, exploration JSON, browser/JS/runtime
intelligence, reports, screenshots, downloads, logs). To keep the repository clean
between engagements, an assessment can be archived into a self-contained, timestamped
folder under ``archives/`` — never ``tmp/`` (archive ops must not recurse into prior
archives). A ``current_assessment`` symlink (or ``current_assessment.txt`` on systems
without symlink support) points at the latest archive.

Discovery-only utility: it only moves the tester's own artifacts; it makes no requests.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from core.logging import get_logger

log = get_logger("archive")

# Source dirs (under the repo root) whose contents are moved into the archive.
# Each maps to the subfolder name inside the archive.
ARCHIVE_DIRS = (
    "captures",
    "exploration",
    "reports",
    "sessions",
    "screenshots",
    "downloads",
    "logs",
    "browser_intelligence",
    "js_intelligence",
    "runtime_config",
)
# Never touched by archiving (would recurse / are workspace infrastructure).
_PROTECTED = {
    "archives",
    "current_assessment",
    "current_assessment.txt",
    ".active_assessment.json",
    ".venv",
    ".git",
}

# The application's own database (state/metadata) is never archived or moved.
_PROTECTED_DB = "asdf.db"
_DB_SUFFIXES = (".db", ".sqlite", ".sqlite3")

# Report/artifact extensions counted for metadata.
_REPORT_EXTS = (".html", ".json", ".md", ".csv", ".xlsx")

# Report output is a managed workspace: callers pick a logical folder NAME, not a
# filesystem path. Only these characters are allowed in that name.
DEFAULT_REPORT_NAME = "default"
_REPORT_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def resolve_report_dir(name: str | None, *, repo_root: str | Path | None = None) -> Path:
    """Resolve a logical report-folder name to ``reports/<name>`` in the workspace.

    AppMapper manages where reports live: callers pass a logical folder name
    (e.g. ``rni``), never an arbitrary filesystem path. Returns ``reports/<name>``,
    defaulting to ``reports/default`` when no name is given. Raises ``ValueError``
    for anything that escapes the workspace — absolute paths, parent traversal, or
    characters outside ``[A-Za-z0-9_-]`` (which rejects ``/  \\  ..  ~  :``).
    """
    root = Path(repo_root or Path.cwd())
    reports = root / "reports"
    candidate = (name or "").strip()
    if not candidate:
        return reports / DEFAULT_REPORT_NAME
    if not _REPORT_NAME_RE.match(candidate):
        raise ValueError(
            f"Invalid --report-dir {name!r}: use a plain folder name made of "
            f"letters, digits, '-' or '_' (no '/', '\\', '..', '~' or ':'). "
            f"Reports are always written under reports/<name> inside the workspace."
        )
    return reports / candidate


def sanitize_target_name(target: str) -> str:
    """``https://ww-rtwhatif-qa.example.com`` -> ``ww-rtwhatif-qa``.

    Strips protocol + domain suffix, lowercases, and replaces filesystem-invalid
    characters. Falls back to ``assessment`` for empty/odd input.
    """
    if not target:
        return "assessment"
    host = urlparse(target).hostname if "://" in target else target.split("/")[0]
    host = (host or target).lower().strip()
    label = host.split(":")[0].split(".")[0]  # first DNS label, drop port
    safe = "".join(c if (c.isalnum() or c in "-_") else "-" for c in label).strip("-_")
    return safe or "assessment"


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def archive_assessment(
    target: str,
    *,
    roles: list[str] | None = None,
    repo_root: str | Path | None = None,
    config_path: str | Path | None = None,
    database_path: str | Path | None = None,
    assessment_name: str | None = None,
    extra_meta: dict | None = None,
) -> Path:
    """Move all assessment artifacts into ``archives/<name>_<ts>/`` and return its path.

    Writes ``assessment_metadata.json`` and updates the ``current_assessment`` pointer.
    Leaves the source folders empty (clean repository). Report outputs live in logical
    subfolders under ``reports/`` (e.g. ``reports/rni/``); the whole ``reports/`` tree
    is moved recursively, so no per-output-dir special handling is needed.

    Also sweeps the engagement's own files out of the repo root: the scan's
    ``database_path`` **and every stray root-level engagement DB** (``*.db`` /
    ``*.sqlite`` / ``*.sqlite3``, never ``asdf.db``) into ``databases/``, any stray
    root-level ``*.har`` into ``captures/``, and a **copy** of ``config_path`` into
    ``config_snapshot/`` (the definition stays reusable). ``assessment_name`` labels
    the engagement (defaults to the config folder name, else the sanitized target).
    """
    root = Path(repo_root or Path.cwd()).resolve()
    name = sanitize_target_name(target)
    archive_root = root / "archives"
    archive_root.mkdir(exist_ok=True)
    dest = archive_root / f"{name}_{_timestamp()}"
    dest.mkdir(parents=True, exist_ok=True)

    counts: dict[str, int] = {}
    for dirname in ARCHIVE_DIRS:
        src = root / dirname
        if dirname in _PROTECTED or not src.is_dir():
            counts[dirname] = 0
            continue
        target_dir = dest / dirname
        moved = _move_dir_contents(src, target_dir)
        counts[dirname] = moved

    # Sweep engagement-specific files out of the repo root.
    counts["captures"] += _archive_stray_hars(root, dest)
    database_files = _archive_database(root, dest, database_path)
    config_file = _snapshot_config(root, dest, config_path)

    now_iso = datetime.now().isoformat(timespec="seconds")
    report_count = sum(_count_files(dest / "reports", ext) for ext in _REPORT_EXTS)
    har_count = _count_files(dest / "captures", ".har")
    exploration_count = _count_files(dest / "exploration", ".json")
    metadata = {
        "target": target,
        "target_name": name,
        "assessment_name": assessment_name or _assessment_name(root, config_path, target),
        "config_file": config_file,
        "assessment_date": now_iso,
        "archive_timestamp": now_iso,
        "roles": roles or [],
        "database_files": database_files,
        # Original keys (kept for backward compatibility).
        "har_files": har_count,
        "exploration_files": exploration_count,
        "reports": report_count,
        "screenshots": counts.get("screenshots", 0),
        "downloads": counts.get("downloads", 0),
        "logs": counts.get("logs", 0),
        # Spec-aligned count aliases.
        "report_count": report_count,
        "har_count": har_count,
        "exploration_count": exploration_count,
        "session_count": counts.get("sessions", 0),
        "artifact_counts": counts,
        "generated_by": "AppMapper",
    }
    if extra_meta:
        metadata.update(extra_meta)
    (dest / "assessment_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    _update_current_pointer(root, dest)
    log.info("archive.created", path=str(dest.relative_to(root)), **{k: counts[k] for k in counts})
    return dest


def _archive_database(root: Path, dest: Path, database_path: str | Path | None) -> list[str]:
    """Move the scan's DB **and every stray engagement DB in the repo root** into
    ``databases/``; never touch ``asdf.db``.

    Returns the list of archived database filenames.
    """
    archives_dir = (root / "archives").resolve()
    candidates: list[Path] = []
    if database_path:  # the scan's own DB (may be absolute / outside root)
        candidates.append(Path(database_path))
    for suffix in _DB_SUFFIXES:  # any *.db / *.sqlite / *.sqlite3 sitting at the root
        candidates.extend(root.glob(f"*{suffix}"))

    target_dir = dest / "databases"
    moved: list[str] = []
    seen: set[Path] = set()
    for db in candidates:
        db = (db if db.is_absolute() else root / db).resolve()
        if db in seen or db.name == _PROTECTED_DB or not db.is_file():
            continue
        if db == dest or dest in db.parents or archives_dir in db.parents:
            continue  # never re-archive something already inside archives/
        seen.add(db)
        target_dir.mkdir(parents=True, exist_ok=True)
        try:
            shutil.move(str(db), str(target_dir / db.name))
            moved.append(db.name)
        except (OSError, shutil.Error) as exc:
            log.warning("archive.db_move_failed", db=str(db), error=str(exc))
    return moved


def _archive_stray_hars(root: Path, dest: Path) -> int:
    """Move any root-level ``*.har`` (outside ``captures/``) into the archive captures."""
    moved = 0
    for har in sorted(root.glob("*.har")):
        if not har.is_file():
            continue
        log.warning(
            "archive.stray_har",
            file=har.name,
            message="HAR file discovered outside captures directory. Archiving automatically.",
        )
        target_dir = dest / "captures"
        target_dir.mkdir(parents=True, exist_ok=True)
        try:
            shutil.move(str(har), str(target_dir / har.name))
            moved += 1
        except (OSError, shutil.Error) as exc:
            log.warning("archive.har_move_failed", file=str(har), error=str(exc))
    return moved


def _snapshot_config(root: Path, dest: Path, config_path: str | Path | None) -> str | None:
    """COPY the assessment config into ``config_snapshot/`` (definition stays reusable).

    Returns the source config path (relative to the repo root when possible).
    """
    if not config_path:
        return None
    cfg = Path(config_path)
    cfg_abs = (cfg if cfg.is_absolute() else root / cfg).resolve()
    if not cfg_abs.is_file():
        return None
    target_dir = dest / "config_snapshot"
    target_dir.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copy2(str(cfg_abs), str(target_dir / cfg_abs.name))
    except (OSError, shutil.Error) as exc:
        log.warning("archive.config_copy_failed", file=str(cfg_abs), error=str(exc))
        return None
    try:
        return str(cfg_abs.relative_to(root))
    except ValueError:
        return str(config_path)


def _assessment_name(root: Path, config_path: str | Path | None, target: str) -> str:
    """Engagement label: the ``assessments/<name>/`` folder name, else the target name."""
    if config_path:
        cfg = Path(config_path)
        cfg_abs = (cfg if cfg.is_absolute() else root / cfg).resolve()
        parent = cfg_abs.parent
        if parent.name and parent.parent.name == "assessments":
            return parent.name
    return sanitize_target_name(target)


def _move_dir_contents(src: Path, dest: Path) -> int:
    """Move every entry from ``src`` into ``dest``; return the count moved."""
    moved = 0
    dest.mkdir(parents=True, exist_ok=True)
    for entry in sorted(src.iterdir()):
        if entry.name in _PROTECTED:
            continue
        try:
            shutil.move(str(entry), str(dest / entry.name))
            moved += 1
        except (OSError, shutil.Error) as exc:  # noqa: PERF203 - per-entry resilience
            log.warning("archive.move_failed", entry=str(entry), error=str(exc))
    return moved


def _count_files(directory: Path, suffix: str) -> int:
    if not directory.is_dir():
        return 0
    return sum(1 for p in directory.rglob(f"*{suffix}") if p.is_file())


def _update_current_pointer(root: Path, dest: Path) -> None:
    """Point ``current_assessment`` at ``dest`` (symlink, or .txt fallback)."""
    rel = dest.relative_to(root)
    link = root / "current_assessment"
    txt = root / "current_assessment.txt"
    # Clear any prior pointer of either kind.
    for p in (link, txt):
        try:
            if p.is_symlink() or p.exists():
                p.unlink()
        except OSError:
            pass
    try:
        os.symlink(rel, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        # Windows / no-symlink filesystems: write a text pointer instead.
        txt.write_text(str(rel) + "\n", encoding="utf-8")


def latest_archive(repo_root: str | Path | None = None) -> Path | None:
    """Resolve the latest archive from the ``current_assessment`` pointer.

    Falls back to the most-recently-modified ``archives/*`` folder if the pointer
    is missing.
    """
    root = Path(repo_root or Path.cwd()).resolve()
    link = root / "current_assessment"
    txt = root / "current_assessment.txt"
    if link.is_symlink() or link.exists():
        target = (root / os.readlink(link)) if link.is_symlink() else link
        if target.is_dir():
            return target.resolve()
    if txt.exists():
        rel = txt.read_text(encoding="utf-8").strip()
        cand = root / rel
        if cand.is_dir():
            return cand.resolve()
    # Fallback: newest archive folder.
    arch = root / "archives"
    if arch.is_dir():
        folders = [p for p in arch.iterdir() if p.is_dir()]
        if folders:
            return max(folders, key=lambda p: p.stat().st_mtime).resolve()
    return None


def load_metadata(archive_path: Path) -> dict:
    meta = archive_path / "assessment_metadata.json"
    if meta.exists():
        try:
            return json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    return {}
