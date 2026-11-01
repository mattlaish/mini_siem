import json
from pathlib import Path

import pytest

from tools import postgres_bootstrap as pb


def test_read_config_defaults_to_postgres_object(tmp_path):
    path = tmp_path / "db-config.json"
    data = pb._read_config(path)
    assert isinstance(data["postgres"], dict)


def test_secret_requires_env_when_noninteractive(monkeypatch):
    monkeypatch.delenv(pb.BOOTSTRAP_PASSWORD_ENV, raising=False)
    monkeypatch.setattr(pb.sys.stdin, "isatty", lambda: False)
    with pytest.raises(RuntimeError, match=pb.BOOTSTRAP_PASSWORD_ENV):
        pb._secret_from_env_or_prompt(pb.BOOTSTRAP_PASSWORD_ENV, "password: ")


def test_write_config_contains_no_bootstrap_credentials(tmp_path):
    path = tmp_path / "db-config.json"
    cfg = {
        "backend": "postgres",
        "postgres": {
            "host": "db.example",
            "port": 5544,
            "dbname": "events",
            "user": "",
            "password": "",
        },
    }
    pb._write_config(path, cfg)
    saved = json.loads(path.read_text())
    assert saved["postgres"]["user"] == ""
    assert saved["postgres"]["password"] == ""
    assert "bootstrap" not in json.dumps(saved).lower()


class FakeCursor:
    def __init__(self, rows):
        self.rows = list(rows)
        self.current = []

    def execute(self, query, params=None):
        text = str(query)
        if "FROM pg_database" in text:
            self.current = self.rows.pop(0)
        else:
            self.current = []

    def fetchone(self):
        return self.current[0] if self.current else None

    def fetchall(self):
        return list(self.current)

    def close(self):
        pass


class FakeConn:
    def __init__(self, rowsets):
        self.rowsets = rowsets
        self.closed = False

    def cursor(self):
        return FakeCursor(self.rowsets)

    def close(self):
        self.closed = True


def test_inspect_existing_reports_absent_database(monkeypatch):
    conn = FakeConn([[]])
    monkeypatch.setattr(pb, "_connect", lambda *a, **k: conn)
    report = pb.inspect_existing(
        psycopg2=object(), host="db", port=5432, bootstrap_db="postgres",
        bootstrap_user="admin", bootstrap_password="secret", target_db="minisiem",
        timeout=5,
    )
    assert report == {
        "database": "minisiem",
        "database_exists": False,
        "database_owner": None,
        "mutated": False,
    }
    assert conn.closed is True
