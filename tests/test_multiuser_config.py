"""Tests for multi-user YAML config loading and role/access persistence."""

from __future__ import annotations

import os

from config.settings import load_target
from models.schemas import RoleEndpointAccess, TargetInput, UserCredential

YAML = """
target_url: https://demo.testfire.net
domain: testfire.net
users:
  - role: admin
    username: admin
    password: admin123
    jwt_token: admintok
    har: captures/admin.har
  - role: user
    username: jsmith
    password: user123
"""

LEGACY_YAML = """
target_url: https://example.com
username: solo
password: pw
"""


def test_load_users_from_config(tmp_path):
    cfg = tmp_path / "target.yaml"
    cfg.write_text(YAML)
    target = load_target(config_path=cfg)

    assert target.domain == "testfire.net"
    assert [u.role for u in target.users] == ["admin", "user"]
    admin = target.primary
    assert admin.role == "admin"
    assert admin.auth_header() == {"Authorization": "Bearer admintok"}
    # Relative capture paths resolve against the config file's directory.
    assert os.path.isabs(admin.har)
    assert admin.har == str((tmp_path / "captures" / "admin.har").resolve())
    assert target.users[1].jwt_token is None  # no token (would log in via creds)


def test_capture_paths_resolve_relative_to_config_dir(tmp_path):
    sub = tmp_path / "assessments" / "rni"
    sub.mkdir(parents=True)
    cfg = sub / "target.yaml"
    cfg.write_text(
        "url: https://rni.example.com\n"
        "users:\n"
        "  - role: admin\n"
        "    exploration: exploration/admin.json\n"
        "  - role: ops\n"
        "    session_file: /abs/session.json\n"
    )
    # Run from a different CWD to prove resolution is config-relative, not CWD-relative.
    target = load_target(config_path=cfg)
    admin = target.users[0]
    assert admin.exploration == str((sub / "exploration" / "admin.json").resolve())
    # Absolute paths are left untouched.
    assert target.users[1].session_file == "/abs/session.json"


def test_legacy_single_user(tmp_path):
    cfg = tmp_path / "legacy.yaml"
    cfg.write_text(LEGACY_YAML)
    target = load_target(config_path=cfg)
    assert len(target.users) == 1
    assert target.users[0].role == "default"
    assert target.users[0].username == "solo"


def test_cli_single_user_when_no_config():
    target = load_target(
        url="https://x.io", domain="x.io", username="a", password="b", role="tester"
    )
    assert len(target.users) == 1
    assert target.users[0].role == "tester"


def test_persist_users_and_role_access(memory_db):
    db = memory_db
    tid = db.upsert_target(TargetInput(url="https://x.io", domain="x.io"))
    db.save_users(
        tid,
        [
            UserCredential(role="admin", username="admin", password="p", jwt_token="t"),
            UserCredential(role="user", username="u"),
        ],
    )
    db.save_role_access(
        tid,
        [
            RoleEndpointAccess(role="admin", path="/admin", status_code=200, accessible=True),
            RoleEndpointAccess(role="user", path="/admin", status_code=403, accessible=False),
        ],
    )

    data = db.fetch_all(tid)
    assert {u["role"] for u in data["users"]} == {"admin", "user"}
    admin_row = next(u for u in data["users"] if u["role"] == "admin")
    assert admin_row["has_password"] is True and admin_row["has_token"] is True
    assert len(data["role_access"]) == 2
