import os
import tempfile

import db


def test_sqlite_initialize_and_test_connection():
    with tempfile.TemporaryDirectory() as td:
        cfg = db.config_from_path(os.path.join(td, "siem.db"))
        db.initialize(cfg)
        ok, detail = db.test_connection(cfg)
        assert ok, detail
        assert detail.startswith("Connected: sqlite://")
        ok, detail = db.integrity_check(cfg)
        assert ok, detail


def test_connection_placeholder_translation_is_sqlite_noop():
    cfg = db.config_from_path(":memory:")
    conn = db.connect(cfg)
    try:
        assert conn._sql("SELECT ?") == "SELECT ?"
    finally:
        conn.close()


def test_load_config_explicit_missing_path_fails_closed(tmp_path):
    missing = tmp_path / "does-not-exist.json"
    try:
        db.load_config(str(missing), sqlite_fallback=str(tmp_path / "fallback.db"))
    except RuntimeError as exc:
        assert "Database configuration not found" in str(exc)
    else:
        raise AssertionError("explicit missing db-config must not silently fall back to SQLite")


def test_load_config_explicit_invalid_json_fails_closed(tmp_path):
    bad = tmp_path / "db-config.json"
    bad.write_text("{not-json", encoding="utf-8")
    try:
        db.load_config(str(bad), sqlite_fallback=str(tmp_path / "fallback.db"))
    except RuntimeError as exc:
        assert "Invalid database configuration" in str(exc)
    else:
        raise AssertionError("invalid explicit db-config must not silently fall back to SQLite")


def test_postgres_initialize_executes_percent_ddl_as_raw_sql(monkeypatch):
    """Trusted PostgreSQL schema SQL containing % tokens must bypass psycopg2 params."""
    class Cursor:
        def __init__(self, rows=()):
            self.rows = list(rows)
        def fetchall(self):
            return list(self.rows)
        def fetchone(self):
            return self.rows[0] if self.rows else None
        def close(self):
            pass

    class Raw:
        def rollback(self):
            pass

    class FakeConn:
        backend = "postgres"
        raw = Raw()
        def __init__(self):
            self.raw_calls = []
            self.param_calls = []
        def execute(self, sql, params=()):
            self.param_calls.append((sql, params))
            if "%" in sql:
                raise AssertionError("static PostgreSQL DDL reached parameterized execute()")
            if sql.startswith("SELECT version FROM schema_migrations"):
                return Cursor([])
            if sql.startswith("INSERT INTO schema_migrations"):
                return Cursor([])
            return Cursor([])
        def execute_raw(self, sql):
            self.raw_calls.append(sql)
            if sql == "SELECT '100%'":
                return Cursor([])
            if sql == "SELECT '50%'":
                return Cursor([])
            return Cursor([])
        def commit(self):
            pass
        def close(self):
            pass

    fake = FakeConn()
    monkeypatch.setattr(db, "connect", lambda config: fake)
    monkeypatch.setattr(db, "_schema_statements", lambda backend: ["SELECT '100%'"])
    monkeypatch.setattr(db, "_migrations", lambda: ["SELECT '50%'"])
    monkeypatch.setattr(db, "ensure_log_fields_normalized_schema", lambda conn: None)
    monkeypatch.setattr(db, "ensure_schema_baseline", lambda conn, config: None)
    monkeypatch.setattr(db, "insert_returning_id", lambda *args, **kwargs: None, raising=False)

    import types
    fake_event_storage = types.SimpleNamespace(ensure_partitions_owner=lambda conn, months=3: 0)
    monkeypatch.setitem(__import__("sys").modules, "event_storage_v2", fake_event_storage)
    monkeypatch.setitem(__import__("sys").modules, "profiles", types.SimpleNamespace(seed_defaults=lambda conn: None))

    db.initialize({"backend": "postgres"})

    assert "SELECT '100%'" in fake.raw_calls
    assert "SELECT '50%'" in fake.raw_calls
    assert not any("%" in sql for sql, _ in fake.param_calls)
