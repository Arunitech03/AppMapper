"""Tests for workspace migration into the managed assessments/ layout."""

from __future__ import annotations

from core.workspace import migrate_workspace


def test_migrate_workspace(tmp_path):
    # Legacy root: two target configs + an assessment DB + the app DB.
    (tmp_path / "targets.yaml").write_text("url: https://default.example.com\n")
    (tmp_path / "targets_rni.yaml").write_text("url: https://rni.example.com\n")
    (tmp_path / "demo.db").write_text("sqlite")
    (tmp_path / "asdf.db").write_text("app-state")

    report = migrate_workspace(repo_root=tmp_path)

    # Configs relocated under assessments/<name>/target.yaml.
    assert (tmp_path / "assessments" / "default" / "target.yaml").exists()
    assert (tmp_path / "assessments" / "rni" / "target.yaml").exists()
    assert not (tmp_path / "targets.yaml").exists()
    assert not (tmp_path / "targets_rni.yaml").exists()
    froms = {m["from"] for m in report["configs_migrated"]}
    assert froms == {"targets.yaml", "targets_rni.yaml"}

    # Assessment DB reported but left in place; app DB untouched and not reported.
    assert report["databases_detected"] == ["demo.db"]
    assert (tmp_path / "demo.db").exists()
    assert (tmp_path / "asdf.db").exists()


def test_migrate_workspace_skips_existing(tmp_path):
    (tmp_path / "targets_rni.yaml").write_text("url: https://rni.example.com\n")
    dest = tmp_path / "assessments" / "rni" / "target.yaml"
    dest.parent.mkdir(parents=True)
    dest.write_text("url: https://existing.example.com\n")

    report = migrate_workspace(repo_root=tmp_path)

    # Existing definition is not overwritten; source is left for manual review.
    assert "url: https://existing.example.com" in dest.read_text()
    assert (tmp_path / "targets_rni.yaml").exists()
    assert report["configs_migrated"] == []
    assert report["files_skipped"] and report["files_skipped"][0]["file"] == "targets_rni.yaml"
