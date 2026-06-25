"""Tests for assessment archive management & workspace cleanup."""

from __future__ import annotations

import json

import pytest

from core.archive import (
    archive_assessment,
    latest_archive,
    load_metadata,
    resolve_report_dir,
    sanitize_target_name,
)


def test_sanitize_target_name():
    assert sanitize_target_name("https://ww-rtwhatif-qa.example.com") == "ww-rtwhatif-qa"
    assert sanitize_target_name("https://demo-prod.example.com:8443/x") == "demo-prod"
    assert sanitize_target_name("customerportal") == "customerportal"
    assert sanitize_target_name("") == "assessment"
    assert sanitize_target_name("https://a b!c.test.com").startswith("a-b")  # invalid chars


def _seed_workspace(root):
    (root / "captures").mkdir()
    (root / "captures" / "admin.har").write_text("{}")
    (root / "captures" / "user.har").write_text("{}")
    (root / "exploration").mkdir()
    (root / "exploration" / "admin.json").write_text("{}")
    (root / "exploration" / "admin_browser").mkdir()
    (root / "exploration" / "admin_browser" / "cookies.json").write_text("[]")
    (root / "reports").mkdir()
    for name in ("report.html", "report.md", "report.json", "graph.json"):
        (root / "reports" / name).write_text("x")
    (root / "screenshots").mkdir()
    (root / "screenshots" / "1.png").write_text("x")
    (root / "logs").mkdir()
    (root / "logs" / "run.log").write_text("x")


def test_archive_moves_artifacts_and_cleans(tmp_path):
    _seed_workspace(tmp_path)
    dest = archive_assessment(
        "https://ww-rtwhatif-qa.example.com", roles=["admin", "user"], repo_root=tmp_path
    )

    # Archive folder named <target>_<timestamp>.
    assert dest.parent.name == "archives"
    assert dest.name.startswith("ww-rtwhatif-qa_")

    # Artifacts moved into the archive.
    assert (dest / "captures" / "admin.har").exists()
    assert (dest / "exploration" / "admin.json").exists()
    assert (dest / "exploration" / "admin_browser" / "cookies.json").exists()
    assert (dest / "reports" / "report.html").exists()
    assert (dest / "screenshots" / "1.png").exists()
    assert (dest / "logs" / "run.log").exists()

    # Source folders are now clean (repository tidy).
    assert not any((tmp_path / "captures").iterdir())
    assert not any((tmp_path / "exploration").iterdir())
    assert not any((tmp_path / "reports").iterdir())


def test_metadata_written(tmp_path):
    _seed_workspace(tmp_path)
    dest = archive_assessment(
        "https://ww-rtwhatif-qa.example.com", roles=["admin", "user"], repo_root=tmp_path
    )
    meta = json.loads((dest / "assessment_metadata.json").read_text())
    assert meta["target"] == "https://ww-rtwhatif-qa.example.com"
    assert meta["target_name"] == "ww-rtwhatif-qa"
    assert meta["roles"] == ["admin", "user"]
    assert meta["har_files"] == 2
    assert meta["exploration_files"] == 2  # admin.json + admin_browser/cookies.json
    assert meta["reports"] == 4  # html, md, json, graph.json (json ext counted)
    assert meta["screenshots"] == 1
    assert meta["generated_by"] == "AppMapper"
    # Spec-aligned keys.
    assert meta["assessment_name"] == "ww-rtwhatif-qa"
    assert meta["config_file"] is None
    assert meta["database_files"] == []
    assert meta["report_count"] == 4
    assert meta["har_count"] == 2
    assert meta["exploration_count"] == 2
    assert meta["session_count"] == 0
    assert meta["archive_timestamp"] == meta["assessment_date"]


def test_archive_includes_database(tmp_path):
    _seed_workspace(tmp_path)
    (tmp_path / "demo.db").write_text("sqlite")
    (tmp_path / "asdf.db").write_text("app-state")
    dest = archive_assessment(
        "https://demo.example.com", repo_root=tmp_path, database_path="demo.db"
    )
    assert (dest / "databases" / "demo.db").exists()
    assert not (tmp_path / "demo.db").exists()  # swept out of root
    assert (tmp_path / "asdf.db").exists()  # app DB untouched
    meta = json.loads((dest / "assessment_metadata.json").read_text())
    assert meta["database_files"] == ["demo.db"]


def test_archive_protects_asdf_db(tmp_path):
    _seed_workspace(tmp_path)
    (tmp_path / "asdf.db").write_text("app-state")
    dest = archive_assessment("https://t1.example.com", repo_root=tmp_path, database_path="asdf.db")
    assert (tmp_path / "asdf.db").exists()  # never archived
    assert not (dest / "databases").exists()
    assert json.loads((dest / "assessment_metadata.json").read_text())["database_files"] == []


def test_config_snapshot_copied(tmp_path):
    _seed_workspace(tmp_path)
    cfg = tmp_path / "assessments" / "rni" / "target.yaml"
    cfg.parent.mkdir(parents=True)
    cfg.write_text("url: https://rni.example.com\n")
    dest = archive_assessment(
        "https://rni.example.com", repo_root=tmp_path, config_path="assessments/rni/target.yaml"
    )
    # COPIED, not moved: snapshot exists AND the reusable definition remains.
    assert (dest / "config_snapshot" / "target.yaml").exists()
    assert cfg.exists()
    meta = json.loads((dest / "assessment_metadata.json").read_text())
    assert meta["config_file"] == "assessments/rni/target.yaml"
    assert meta["assessment_name"] == "rni"


def test_stray_har_archived(tmp_path):
    _seed_workspace(tmp_path)
    (tmp_path / "qa.har").write_text("{}")  # stray HAR in repo root
    dest = archive_assessment("https://t1.example.com", repo_root=tmp_path)
    assert (dest / "captures" / "qa.har").exists()
    assert not (tmp_path / "qa.har").exists()


def test_sessions_archived(tmp_path):
    _seed_workspace(tmp_path)
    (tmp_path / "sessions" / "qa_browser").mkdir(parents=True)
    (tmp_path / "sessions" / "qa_browser" / "storage_state.json").write_text("{}")
    dest = archive_assessment("https://t1.example.com", repo_root=tmp_path)
    assert (dest / "sessions" / "qa_browser" / "storage_state.json").exists()
    assert not any((tmp_path / "sessions").iterdir())
    assert json.loads((dest / "assessment_metadata.json").read_text())["session_count"] == 1


def test_current_pointer_and_latest(tmp_path):
    _seed_workspace(tmp_path)
    dest = archive_assessment("https://t1.example.com", roles=["admin"], repo_root=tmp_path)

    # current_assessment pointer (symlink or .txt) resolves to the archive.
    found = latest_archive(repo_root=tmp_path)
    assert found is not None
    assert found.resolve() == dest.resolve()
    assert load_metadata(found)["target_name"] == "t1"


def test_does_not_recurse_into_archives(tmp_path):
    _seed_workspace(tmp_path)
    archive_assessment("https://t1.example.com", repo_root=tmp_path)
    # second engagement
    (tmp_path / "captures").mkdir(exist_ok=True)
    (tmp_path / "captures" / "new.har").write_text("{}")
    dest2 = archive_assessment("https://t2.example.com", repo_root=tmp_path)
    # the new archive must NOT contain the previous archive folder
    assert not (dest2 / "archives").exists()
    # two distinct archives exist
    assert len(list((tmp_path / "archives").iterdir())) == 2
    # latest points at the newest
    assert latest_archive(repo_root=tmp_path).name == dest2.name


def test_report_dir_resolves_under_reports(tmp_path):
    assert resolve_report_dir("rni", repo_root=tmp_path) == tmp_path / "reports" / "rni"
    assert resolve_report_dir("customer1", repo_root=tmp_path) == tmp_path / "reports" / "customer1"
    assert resolve_report_dir("demo-prod", repo_root=tmp_path) == (
        tmp_path / "reports" / "demo-prod"
    )
    # Omitted -> managed default folder.
    assert resolve_report_dir(None, repo_root=tmp_path) == tmp_path / "reports" / "default"
    assert resolve_report_dir("", repo_root=tmp_path) == tmp_path / "reports" / "default"


def test_report_dir_rejects_absolute_paths(tmp_path):
    for bad in ("/tmp/reports", "/Users/arun/Desktop/reports"):
        with pytest.raises(ValueError):
            resolve_report_dir(bad, repo_root=tmp_path)


def test_report_dir_rejects_parent_paths(tmp_path):
    for bad in ("../../tmp", "../reports", "./out", "~/reports", "reports/test", "a:b", "a\\b"):
        with pytest.raises(ValueError):
            resolve_report_dir(bad, repo_root=tmp_path)


def test_archive_moves_report_folder(tmp_path):
    # Reports written to a logical subfolder reports/rni/ are archived in place.
    _seed_workspace(tmp_path)
    rni = resolve_report_dir("rni", repo_root=tmp_path)
    rni.mkdir(parents=True)
    for name in ("report.html", "report.json", "report.md"):
        (rni / name).write_text("x")
    dest = archive_assessment("https://t1.example.com", repo_root=tmp_path)
    assert (dest / "reports" / "rni" / "report.html").exists()
    assert (dest / "reports" / "rni" / "report.json").exists()
    assert not any((tmp_path / "reports").iterdir())  # source cleaned


def test_txt_fallback_pointer(tmp_path, monkeypatch):
    _seed_workspace(tmp_path)

    # Force the symlink path to fail -> .txt fallback.
    import core.archive as arch_mod

    def _boom(*a, **k):
        raise OSError("no symlink support")

    monkeypatch.setattr(arch_mod.os, "symlink", _boom)
    archive_assessment("https://t1.example.com", repo_root=tmp_path)
    assert (tmp_path / "current_assessment.txt").exists()
    assert latest_archive(repo_root=tmp_path) is not None
