"""Workspace migration — reorganize a legacy repo root into the managed layout.

Historically assessment definitions (``targets*.yaml``) and assessment databases
lived directly in the repo root, mixed with source code. ``migrate_workspace``
relocates the reusable assessment definitions under ``assessments/<name>/target.yaml``
and reports the engagement databases / stray HARs it finds (without moving them — the
databases are swept into an archive on the next ``scan --archive``, and ``asdf.db`` is
never touched). It only moves the tester's own files; it makes no requests.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from core.archive import _DB_SUFFIXES, _PROTECTED_DB
from core.logging import get_logger

log = get_logger("workspace")


def _assessment_folder(yaml_name: str) -> str:
    """``targets.yaml`` -> ``default``; ``targets_rni.yaml`` -> ``rni``."""
    stem = Path(yaml_name).stem  # e.g. "targets_rni"
    if stem == "targets":
        return "default"
    if stem.startswith("targets_"):
        return stem[len("targets_") :] or "default"
    return stem or "default"


def migrate_workspace(repo_root: str | Path | None = None) -> dict:
    """Relocate root assessment definitions into ``assessments/`` and report the rest.

    Returns a report dict: ``configs_migrated`` (``[{from, to}]``), ``files_skipped``
    (``[{file, reason}]``), ``databases_detected`` (assessment DB filenames left in
    place), and ``stray_hars`` (root HAR filenames left for archive-time cleanup).
    """
    root = Path(repo_root or Path.cwd()).resolve()
    assessments = root / "assessments"
    assessments.mkdir(exist_ok=True)

    report: dict[str, list] = {
        "configs_migrated": [],
        "files_skipped": [],
        "databases_detected": [],
        "stray_hars": [],
    }

    # Assessment definitions: targets*.yaml -> assessments/<name>/target.yaml
    for cfg in sorted(root.glob("targets*.yaml")):
        if not cfg.is_file():
            continue
        folder = assessments / _assessment_folder(cfg.name)
        dest = folder / "target.yaml"
        if dest.exists():
            report["files_skipped"].append(
                {"file": cfg.name, "reason": f"{dest.relative_to(root)} already exists"}
            )
            continue
        folder.mkdir(parents=True, exist_ok=True)
        try:
            shutil.move(str(cfg), str(dest))
            report["configs_migrated"].append({"from": cfg.name, "to": str(dest.relative_to(root))})
            log.info("workspace.config_migrated", src=cfg.name, dest=str(dest.relative_to(root)))
        except (OSError, shutil.Error) as exc:
            report["files_skipped"].append({"file": cfg.name, "reason": str(exc)})

    # Assessment databases (left in place; archived later by `scan --archive`).
    for db in sorted(root.iterdir()):
        if db.is_file() and db.suffix in _DB_SUFFIXES and db.name != _PROTECTED_DB:
            report["databases_detected"].append(db.name)

    # Stray root HARs (cleaned up at archive time).
    for har in sorted(root.glob("*.har")):
        if har.is_file():
            report["stray_hars"].append(har.name)

    return report
