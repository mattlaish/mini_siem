import json
from pathlib import Path
import tempfile

import pytest

import db


def _base_config(path: Path, *, password=""):
    payload = {
        "backend": "postgres",
        "postgres": {
            "host": "db.internal",
            "port": 5432,
            "dbname": "minisiem",
            "user": "",
            "password": password,
        },
        "postgres_privilege_boundary": {"enabled": True},
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_component_credentials_overlay_only_user_and_password():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        base = root / "db-config.json"
        cred = root / "db-dashboard-credentials.json"
        _base_config(base)
        cred.write_text(json.dumps({
            "identity": "dashboard",
            "postgres": {"user": "minisiem_dashboard", "password": "secret"},
        }), encoding="utf-8")

        cfg = db.load_config(str(base), credentials_path=str(cred))
        assert cfg["backend"] == "postgres"
        assert cfg["postgres"]["host"] == "db.internal"
        assert cfg["postgres"]["dbname"] == "minisiem"
        assert cfg["postgres"]["user"] == "minisiem_dashboard"
        assert cfg["postgres"]["password"] == "secret"
        assert cfg["_credentials_identity"] == "dashboard"


def test_component_credentials_cannot_redirect_database():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        base = root / "db-config.json"
        cred = root / "bad.json"
        _base_config(base)
        cred.write_text(json.dumps({
            "identity": "dashboard",
            "postgres": {
                "user": "minisiem_dashboard",
                "password": "secret",
                "host": "attacker.example",
            },
        }), encoding="utf-8")

        with pytest.raises(RuntimeError, match="unexpected: host"):
            db.load_config(str(base), credentials_path=str(cred))


def test_secure_postgres_config_fails_without_component_credentials():
    with tempfile.TemporaryDirectory() as td:
        base = Path(td) / "db-config.json"
        _base_config(base)
        with pytest.raises(RuntimeError, match="no component credential file"):
            db.load_config(str(base))


class _Rows:
    def __init__(self, versions):
        self._versions = versions

    def fetchall(self):
        return [{"version": v} for v in self._versions]


class _FakeRuntimeConn:
    def __init__(self, versions):
        self.raw = object()
        self.versions = versions
        self.closed = False
        self.sql = []

    def execute(self, sql, params=()):
        self.sql.append(sql)
        assert sql.strip().startswith("SELECT version FROM schema_migrations")
        return _Rows(self.versions)

    def close(self):
        self.closed = True


def test_postgres_runtime_ready_validates_without_schema_ddl(monkeypatch):
    fake = _FakeRuntimeConn(range(1, len(db._migrations()) + 1))
    monkeypatch.setattr(db, "connect", lambda cfg: fake)
    monkeypatch.setattr(db, "postgres_required_tables_present", lambda raw, tables: [])

    db.ensure_runtime_ready({"backend": "postgres"})
    assert fake.closed
    assert len(fake.sql) == 1
    assert "CREATE " not in fake.sql[0].upper()
    assert "ALTER " not in fake.sql[0].upper()


def test_postgres_runtime_ready_fails_closed_on_pending_migration(monkeypatch):
    fake = _FakeRuntimeConn([])
    monkeypatch.setattr(db, "connect", lambda cfg: fake)
    monkeypatch.setattr(db, "postgres_required_tables_present", lambda raw, tables: [])

    with pytest.raises(RuntimeError, match="pending migrations"):
        db.ensure_runtime_ready({"backend": "postgres"})
    assert fake.closed
