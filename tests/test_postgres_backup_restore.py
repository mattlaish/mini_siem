import hashlib
import json
from pathlib import Path
import sys
import types

import pytest

import backup_restore as br
from tools import postgres_backup_restore as pbr


class DummyConn:
    def close(self):
        pass


def _cfg(path: Path):
    path.write_text(json.dumps({
        "backend": "postgres",
        "postgres": {
            "host": "db.internal", "port": 5432, "dbname": "minisiem",
            "user": "", "password": "", "connect_timeout": 5,
        },
        "postgres_privilege_boundary": {"enabled": True, "owner_role": "minisiem_owner"},
    }))


def _manifest(path: Path, archive: Path):
    br.write_manifest(path, {
        "format": pbr.MANIFEST_FORMAT,
        "backend": "postgres",
        "archive": {"sha256": br.sha256_file(archive), "bytes": archive.stat().st_size},
        "source": {
            "database": "minisiem", "owner_role": "minisiem_owner",
            "server_version": "16.4",
            "schema_migration_versions": [1, 2, 3],
        },
    })


def test_manifest_helpers_are_checksum_and_atomic_json(tmp_path):
    data = tmp_path / "backup.dump"
    data.write_bytes(b"backup-bytes")
    expected = hashlib.sha256(b"backup-bytes").hexdigest()
    assert br.validate_backup(data, expected)
    manifest = tmp_path / "backup.json"
    br.write_manifest(manifest, {"sha256": expected})
    assert br.read_manifest(manifest)["sha256"] == expected
    assert (manifest.stat().st_mode & 0o777) == 0o600


def test_restore_refuses_checksum_mismatch_and_in_place_target(tmp_path, monkeypatch):
    cfg = tmp_path / "db-config.json"; _cfg(cfg)
    archive = tmp_path / "backup.dump"; archive.write_bytes(b"actual")
    manifest = tmp_path / "backup.json"
    br.write_manifest(manifest, {
        "format": pbr.MANIFEST_FORMAT,
        "backend": "postgres",
        "archive": {"sha256": hashlib.sha256(b"other").hexdigest(), "bytes": archive.stat().st_size},
        "source": {
            "database": "minisiem", "owner_role": "minisiem_owner",
            "server_version": "16.4", "schema_migration_versions": [1, 2, 3],
        },
    })
    with pytest.raises(RuntimeError, match="SHA-256"):
        pbr.restore_backup(cfg, archive, manifest, target_database="recovery", bootstrap_user="dba", bootstrap_password="x")

    _manifest(manifest, archive)
    with pytest.raises(RuntimeError, match="new database name"):
        pbr.restore_backup(cfg, archive, manifest, target_database="minisiem", bootstrap_user="dba", bootstrap_password="x")


def test_restore_creates_new_database_restores_and_verifies_without_persisting_credentials(tmp_path, monkeypatch):
    cfg = tmp_path / "db-config.json"; _cfg(cfg)
    archive = tmp_path / "backup.dump"; archive.write_bytes(b"archive")
    manifest = tmp_path / "backup.json"; _manifest(manifest, archive)
    restore_bin = tmp_path / "pg_restore"; restore_bin.write_text("#!/bin/sh\nexit 0\n"); restore_bin.chmod(0o755)
    monkeypatch.setenv(pbr.OWNER_PASSWORD_ENV, "owner-secret")
    monkeypatch.setitem(sys.modules, "psycopg2", types.SimpleNamespace())

    admin = DummyConn(); restored = DummyConn(); calls = []
    monkeypatch.setattr(pbr, "_connect", lambda *a, **k: admin if k.get("database") == "postgres" else restored)
    monkeypatch.setattr(pbr.bootstrap, "_bootstrap_preflight", lambda *a, **k: {"authorized": True})
    monkeypatch.setattr(pbr, "_db_exists", lambda *a, **k: False)
    monkeypatch.setattr(pbr, "_role_exists", lambda *a, **k: True)
    monkeypatch.setattr(pbr, "_create_database", lambda conn, database, owner: calls.append(("create", database, owner)))
    monkeypatch.setattr(pbr, "_verify_restored", lambda conn, versions: {"required_tables": 21, "schema_migration_versions": versions})

    class CP:
        returncode = 0; stdout = "ok"; stderr = ""
    monkeypatch.setattr(pbr.subprocess, "run", lambda cmd, **kwargs: calls.append(("run", cmd, kwargs.get("env", {}).get("PGPASSWORD"))) or CP())

    out = pbr.restore_backup(
        cfg, archive, manifest, target_database="minisiem_recovery",
        bootstrap_user="dba", bootstrap_password="dba-secret", pg_restore=str(restore_bin),
    )
    assert ("create", "minisiem_recovery", "minisiem_owner") in calls
    restore_calls = [c for c in calls if c[0] == "run" and "--single-transaction" in c[1]]
    assert restore_calls and restore_calls[0][2] == "owner-secret"
    assert "--no-owner" in restore_calls[0][1]
    assert "--no-privileges" in restore_calls[0][1]
    assert out["target_database"] == "minisiem_recovery"
    assert out["bootstrap_credential_persisted"] is False
    assert "owner-secret" not in json.dumps(out)
    assert "dba-secret" not in json.dumps(out)


def test_restore_failure_cleans_incomplete_new_database(tmp_path, monkeypatch):
    cfg = tmp_path / "db-config.json"; _cfg(cfg)
    archive = tmp_path / "backup.dump"; archive.write_bytes(b"archive")
    manifest = tmp_path / "backup.json"; _manifest(manifest, archive)
    restore_bin = tmp_path / "pg_restore"; restore_bin.write_text("#!/bin/sh\nexit 0\n"); restore_bin.chmod(0o755)
    monkeypatch.setenv(pbr.OWNER_PASSWORD_ENV, "owner-secret")
    monkeypatch.setitem(sys.modules, "psycopg2", types.SimpleNamespace())
    admin = DummyConn()
    monkeypatch.setattr(pbr, "_connect", lambda *a, **k: admin)
    monkeypatch.setattr(pbr.bootstrap, "_bootstrap_preflight", lambda *a, **k: {})
    monkeypatch.setattr(pbr, "_db_exists", lambda *a, **k: False)
    monkeypatch.setattr(pbr, "_role_exists", lambda *a, **k: True)
    monkeypatch.setattr(pbr, "_create_database", lambda *a, **k: None)
    dropped = []
    monkeypatch.setattr(pbr, "_drop_database", lambda conn, name: dropped.append(name))

    class CP:
        def __init__(self, rc): self.returncode=rc; self.stdout=""; self.stderr="restore failed"
    def fake_run(cmd, **kwargs):
        return CP(0) if cmd[1:2] == ["-l"] else CP(1)
    monkeypatch.setattr(pbr.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="pg_restore failed"):
        pbr.restore_backup(
            cfg, archive, manifest, target_database="broken_restore",
            bootstrap_user="dba", bootstrap_password="dba-secret", pg_restore=str(restore_bin),
        )
    assert dropped == ["broken_restore"]


def test_restore_manifest_is_strict_before_database_side_effects(tmp_path):
    archive = tmp_path / "backup.dump"; archive.write_bytes(b"archive")
    base = {
        "format": pbr.MANIFEST_FORMAT,
        "backend": "postgres",
        "archive": {"sha256": br.sha256_file(archive), "bytes": archive.stat().st_size},
        "source": {
            "database": "minisiem", "owner_role": "minisiem_owner",
            "server_version": "16.4", "schema_migration_versions": [1, 2, 3],
        },
    }
    assert pbr._validate_restore_manifest(base, archive)["database"] == "minisiem"

    missing_ledger = json.loads(json.dumps(base)); missing_ledger["source"].pop("schema_migration_versions")
    with pytest.raises(RuntimeError, match="migration ledger is missing"):
        pbr._validate_restore_manifest(missing_ledger, archive)

    gapped = json.loads(json.dumps(base)); gapped["source"]["schema_migration_versions"] = [1, 3]
    with pytest.raises(RuntimeError, match="has gaps"):
        pbr._validate_restore_manifest(gapped, archive)

    wrong_size = json.loads(json.dumps(base)); wrong_size["archive"]["bytes"] += 1
    with pytest.raises(RuntimeError, match="size does not match"):
        pbr._validate_restore_manifest(wrong_size, archive)


def test_restore_uses_current_deployment_owner_not_manifest_source_owner(tmp_path, monkeypatch):
    cfg = tmp_path / "db-config.json"; _cfg(cfg)
    archive = tmp_path / "backup.dump"; archive.write_bytes(b"archive")
    manifest = tmp_path / "backup.json"
    _manifest(manifest, archive)
    data = br.read_manifest(manifest)
    data["source"]["owner_role"] = "legacy_shared_owner"
    br.write_manifest(manifest, data)
    restore_bin = tmp_path / "pg_restore"; restore_bin.write_text("#!/bin/sh\nexit 0\n"); restore_bin.chmod(0o755)
    monkeypatch.setenv(pbr.OWNER_PASSWORD_ENV, "owner-secret")
    monkeypatch.setitem(sys.modules, "psycopg2", types.SimpleNamespace())

    admin = DummyConn(); restored = DummyConn(); calls = []
    monkeypatch.setattr(pbr, "_connect", lambda *a, **k: admin if k.get("database") == "postgres" else restored)
    monkeypatch.setattr(pbr.bootstrap, "_bootstrap_preflight", lambda *a, **k: {})
    monkeypatch.setattr(pbr, "_db_exists", lambda *a, **k: False)
    monkeypatch.setattr(pbr, "_role_exists", lambda conn, role: role == "minisiem_owner")
    monkeypatch.setattr(pbr, "_create_database", lambda conn, database, owner: calls.append((database, owner)))
    monkeypatch.setattr(pbr, "_verify_restored", lambda conn, versions: {"schema_migration_versions": versions})

    class CP:
        returncode = 0; stdout = "ok"; stderr = ""
    monkeypatch.setattr(pbr.subprocess, "run", lambda *a, **k: CP())

    out = pbr.restore_backup(
        cfg, archive, manifest, target_database="recovery",
        bootstrap_user="dba", bootstrap_password="bootstrap-secret", pg_restore=str(restore_bin),
    )
    assert calls == [("recovery", "minisiem_owner")]
    assert out["owner_role"] == "minisiem_owner"
    assert out["source_owner_role"] == "legacy_shared_owner"
    assert out["owner_remapped"] is True


def test_backup_refuses_archive_manifest_alias_and_existing_manifest(tmp_path, monkeypatch):
    cfg = tmp_path / "db-config.json"; _cfg(cfg)
    same = tmp_path / "same.dump"
    monkeypatch.setenv(pbr.OWNER_PASSWORD_ENV, "owner-secret")
    monkeypatch.setitem(sys.modules, "psycopg2", types.SimpleNamespace())
    monkeypatch.setattr(pbr, "_connect", lambda *a, **k: DummyConn())
    monkeypatch.setattr(pbr, "_server_metadata", lambda conn: {
        "server_version": "16.4", "database": "minisiem", "current_user": "minisiem_owner",
        "database_owner": "minisiem_owner", "schema_migration_versions": [1, 2, 3],
    })
    with pytest.raises(RuntimeError, match="different files"):
        pbr.create_backup(cfg, same, same)

    manifest = tmp_path / "backup.json"; manifest.write_text("{}")
    dump = tmp_path / "backup.dump"
    with pytest.raises(RuntimeError, match="manifest already exists"):
        pbr.create_backup(cfg, dump, manifest)


def test_historical_restore_verification_marks_migration_required_without_current_only_tables(monkeypatch):
    monkeypatch.setattr(pbr.db, "_migrations", lambda: ["x"] * 5)

    class Cursor:
        def __init__(self): self.query = ""
        def execute(self, query, params=()): self.query = query
        def fetchall(self):
            if "pg_tables" in self.query:
                return [("logs",), ("alerts",), ("app_config",), ("users",), ("schema_migrations",)]
            return [(1,), (2,), (3,)]
        def close(self): pass

    class Conn:
        def cursor(self): return Cursor()

    result = pbr._verify_restored(Conn(), [1, 2, 3])
    assert result["current_schema_ready"] is False
    assert result["migration_required"] is True
    assert result["restored_schema_version"] == 3
    assert result["current_schema_version"] == 5


def test_restore_manifest_rejects_schema_newer_than_current_source(tmp_path, monkeypatch):
    archive = tmp_path / "backup.dump"; archive.write_bytes(b"archive")
    monkeypatch.setattr(pbr.db, "_migrations", lambda: ["x"] * 3)
    data = {
        "format": pbr.MANIFEST_FORMAT,
        "backend": "postgres",
        "archive": {"sha256": br.sha256_file(archive), "bytes": archive.stat().st_size},
        "source": {
            "database": "minisiem", "owner_role": "minisiem_owner",
            "server_version": "17.1", "schema_migration_versions": [1, 2, 3, 4],
        },
    }
    with pytest.raises(RuntimeError, match="newer than this source supports"):
        pbr._validate_restore_manifest(data, archive)
