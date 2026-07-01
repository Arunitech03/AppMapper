"""Tests for the active-assessment state + `start` scaffolding."""

from __future__ import annotations

from pathlib import Path

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


def _har_json(*urls):
    import json

    return json.dumps({"log": {"entries": [{"request": {"url": u}} for u in urls]}})


def test_build_target_from_captures_hars(tmp_path):
    from core.assessment import build_target_from_captures

    cap = tmp_path / "assessments" / "rni" / "captures"
    cap.mkdir(parents=True)
    body = _har_json(
        "https://app.sensus.com/a",
        "https://app.sensus.com/b",
        "https://browser-intake-datadoghq.com/rum",  # noise, filtered
    )
    (cap / "user1_rni.har").write_text(body)
    (cap / "user2_rni.har").write_text(body)

    t = build_target_from_captures("rni", root=tmp_path)
    assert t is not None
    # role = filename with the trailing "_rni" stripped; one role per HAR; auth_mode=har
    assert {u.role for u in t.users} == {"user1", "user2"}
    assert all(u.auth_mode == "har" and u.har.endswith(".har") for u in t.users)
    # URL inferred from the most-requested in-scope host (telemetry filtered out)
    assert t.url == "https://app.sensus.com" and t.domain == "sensus.com"

    # Nothing to discover -> None.
    assert build_target_from_captures("missing", root=tmp_path) is None


def test_build_target_from_captures_exploration(tmp_path):
    from core.assessment import build_target_from_captures

    exp = tmp_path / "assessments" / "rni" / "exploration"
    exp.mkdir(parents=True)
    (exp / "user1_rni.json").write_text("{}")  # exploration data (content irrelevant here)
    (exp / "user1_rni.har").write_text(_har_json("https://app.sensus.com/x"))  # sibling HAR

    t = build_target_from_captures("rni", root=tmp_path)
    assert t is not None
    u = next(u for u in t.users if u.role == "user1")
    assert u.exploration and u.exploration.endswith("exploration/user1_rni.json")
    assert u.har is None  # exploration role, not a HAR role
    assert t.url == "https://app.sensus.com"


def test_auth_out_dir_defaults_to_assessment(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from main import _auth_out_dir

    # No active assessment -> assessments/default/<subdir>/.
    d = _auth_out_dir("exploration")
    assert d == Path("assessments/default/exploration") and d.is_dir()

    # Active assessment -> its folder.
    set_active("rni", "assessments/rni/rni.db", root=tmp_path)
    d = _auth_out_dir("sessions")
    assert d == Path("assessments/rni/sessions") and d.is_dir()


def test_auth_explore_writes_into_assessment(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    import main

    monkeypatch.chdir(tmp_path)
    set_active("rni", "assessments/rni/rni.db", root=tmp_path)

    captured: dict[str, str] = {}

    def fake_explore(role, url, out_json, har_path, **kw):  # noqa: ANN001
        captured["out_json"] = str(out_json)
        captured["har"] = str(har_path)
        return dict.fromkeys(
            ("navigations", "api_calls", "forms", "uploads", "downloads", "websockets"), []
        ) | {"technologies": {}}

    monkeypatch.setattr("modules.auth.explorer.explore", fake_explore)
    result = CliRunner().invoke(main.app, ["auth", "explore", "--url", "https://x", "--role", "u1"])
    assert result.exit_code == 0
    assert captured["out_json"].endswith("assessments/rni/exploration/u1.json")
    assert captured["har"].endswith("assessments/rni/exploration/u1.har")


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
