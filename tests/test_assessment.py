"""Tests for the active-assessment state + `start` scaffolding."""

from __future__ import annotations

import pytest

from core.assessment import (
    active_db,
    active_name,
    clear_active,
    set_active,
    start_assessment,
    validate_name,
)


def test_validate_name_rejects_traversal():
    assert validate_name("testfire") == "testfire"
    for bad in ("", "../x", "a/b", "with space", "x" * 65):
        with pytest.raises(ValueError):
            validate_name(bad)


def test_active_db_roundtrip(tmp_path):
    assert active_db(root=tmp_path) is None  # nothing set yet
    set_active("testfire", "testfire.db", root=tmp_path)
    assert active_db(root=tmp_path) == "testfire.db"
    assert active_name(root=tmp_path) == "testfire"


def test_start_assessment_scaffolds_and_activates(tmp_path):
    info = start_assessment("testfire", root=tmp_path)

    assert (tmp_path / "assessments" / "testfire" / "target.yaml").exists()
    assert (tmp_path / "assessments" / "testfire" / "captures").is_dir()
    # DB lives inside the assessment folder (root stays clean).
    assert (tmp_path / "assessments" / "testfire" / "testfire.db").exists()
    assert not (tmp_path / "testfire.db").exists()
    assert active_db(root=tmp_path) == "assessments/testfire/testfire.db"
    assert info["db"] == "assessments/testfire/testfire.db" and info["created_target"] is True

    # Idempotent: re-running keeps the existing config, stays active.
    (tmp_path / "assessments" / "testfire" / "target.yaml").write_text("url: https://kept\n")
    again = start_assessment("testfire", root=tmp_path)
    assert again["created_target"] is False
    assert "https://kept" in (tmp_path / "assessments" / "testfire" / "target.yaml").read_text()


def test_settings_falls_back_to_active_db(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from main import _settings

    # No active assessment -> default DB.
    assert _settings(None, None, "INFO", False).database_url.endswith("asdf.db")

    set_active("testfire", "testfire.db", root=tmp_path)
    # No --db -> active assessment DB is used.
    assert _settings(None, None, "INFO", False).database_url == "sqlite:///testfire.db"
    # Explicit --db always wins.
    assert _settings("other.db", None, "INFO", False).database_url == "sqlite:///other.db"


def test_clear_active(tmp_path):
    set_active("testfire", "testfire.db", root=tmp_path)
    assert clear_active(root=tmp_path) == "testfire"  # returns what it cleared
    assert active_name(root=tmp_path) is None and active_db(root=tmp_path) is None
    assert clear_active(root=tmp_path) is None  # idempotent / nothing to clear


def test_report_dir_defaults_to_active_assessment(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from main import _resolved_report

    set_active("testfire", "testfire.db", root=tmp_path)
    # No --report-dir -> reports land under the active assessment name.
    assert _resolved_report(None).replace("\\", "/").endswith("reports/testfire")
    # Explicit --report-dir still wins.
    assert _resolved_report("custom").replace("\\", "/").endswith("reports/custom")


def test_scan_archive_only_when_no_target(tmp_path, monkeypatch):
    """`scan --archive` with an active assessment but no real target archives + resets."""
    from typer.testing import CliRunner

    from main import app

    monkeypatch.chdir(tmp_path)
    # Don't let the CLI rebind global logging to CliRunner's captured (then-closed) stream.
    monkeypatch.setattr("main.configure_logging", lambda *a, **k: None)
    start_assessment("test1", root=tmp_path)  # scaffolds target.yaml (placeholder url) + test1.db

    result = CliRunner().invoke(app, ["scan", "--archive"])
    assert result.exit_code == 0
    # Engagement DB swept into an archive; active assessment cleared.
    assert not (tmp_path / "test1.db").exists()
    assert list(tmp_path.glob("archives/test1_*/databases/test1.db"))
    assert active_name(root=tmp_path) is None


def test_scan_no_target_no_archive_errors(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from main import app

    monkeypatch.chdir(tmp_path)  # no active assessment, no --url/--config
    monkeypatch.setattr("main.configure_logging", lambda *a, **k: None)
    result = CliRunner().invoke(app, ["scan"])
    assert result.exit_code == 2 and "target URL is required" in result.stdout


def test_stop_command_clears_without_archiving(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from main import app

    monkeypatch.chdir(tmp_path)
    start_assessment("rni", root=tmp_path)
    runner = CliRunner()

    out = runner.invoke(app, ["stop"]).stdout
    assert "Stopped assessment: rni" in out
    # Active pointer cleared, but the files are left in place (not archived/moved).
    assert active_name(root=tmp_path) is None
    assert (tmp_path / "assessments" / "rni" / "rni.db").exists()  # DB kept in the folder
    assert (tmp_path / "assessments" / "rni" / "target.yaml").exists()
    assert not (tmp_path / "archives").exists()
    # Idempotent.
    assert "No active assessment to stop" in runner.invoke(app, ["stop"]).stdout


def test_status_command(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from main import app

    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    out = runner.invoke(app, ["status"]).stdout
    assert "No active assessment" in out

    start_assessment("testfire", root=tmp_path)
    out = runner.invoke(app, ["status"]).stdout
    assert "Active assessment: testfire" in out and "testfire.db" in out
