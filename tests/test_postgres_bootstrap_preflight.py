from pathlib import Path
import json

import pytest

from tools import postgres_bootstrap as pb


class Cursor:
    def __init__(self, row):
        self.row = row
        self.executed = []
    def execute(self, sql, params=None):
        self.executed.append((str(sql), params))
    def fetchone(self):
        return self.row
    def close(self):
        pass


class Conn:
    def __init__(self, row):
        self.cursor_obj = Cursor(row)
        self.closed = False
    def cursor(self):
        return self.cursor_obj
    def close(self):
        self.closed = True


def test_bootstrap_preflight_accepts_superuser():
    conn = Conn(("postgres", False, False, True))
    out = pb._bootstrap_preflight(
        conn, host="127.0.0.1", port=5432, bootstrap_db="postgres", requested_user="postgres"
    )
    assert out["rolsuper"] is True
    assert len(conn.cursor_obj.executed) == 1


def test_bootstrap_preflight_accepts_createdb_and_createrole():
    conn = Conn(("installer", True, True, False))
    out = pb._bootstrap_preflight(
        conn, host="db", port=5432, bootstrap_db="postgres", requested_user="installer"
    )
    assert out["rolcreatedb"] and out["rolcreaterole"]


@pytest.mark.parametrize(
    "row, missing",
    [
        (("installer", False, True, False), "CREATEDB"),
        (("installer", True, False, False), "CREATEROLE"),
        (("installer", False, False, False), "CREATEDB"),
    ],
)
def test_bootstrap_preflight_rejects_missing_privileges_before_ddl(row, missing):
    conn = Conn(row)
    with pytest.raises(pb.BootstrapPreflightError, match=missing):
        pb._bootstrap_preflight(
            conn, host="db", port=5432, bootstrap_db="postgres", requested_user="installer"
        )
    assert len(conn.cursor_obj.executed) == 1
    assert not any("CREATE " in sql.upper() for sql, _ in conn.cursor_obj.executed)


def test_fresh_bootstrap_connection_failure_is_plain_preflight_error(tmp_path):
    class Psy:
        @staticmethod
        def connect(**kwargs):
            raise OSError("connection refused")
    with pytest.raises(pb.BootstrapPreflightError, match="cannot connect/authenticate"):
        pb.fresh_bootstrap(
            psycopg2=Psy(), config_path=tmp_path / "db-config.json",
            host="127.0.0.1", port=5432, bootstrap_db="postgres",
            bootstrap_user="postgres", bootstrap_password="bad",
            target_db="minisiem", owner_user="minisiem_owner", owner_password="owner",
            timeout=2,
        )


def test_resume_secret_payload_is_stable_and_root_only(tmp_path):
    path = tmp_path / "resume-secrets.json"
    first = pb._resume_secret_payload(path, resume=False)
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600
    second = pb._resume_secret_payload(path, resume=True)
    assert second == first
    assert "owner_password" in first
    assert set(first["runtime_passwords"]) == {
        "minisiem_ingest", "minisiem_dashboard", "minisiem_maintenance"
    }


def test_fresh_bootstrap_preflight_failure_closes_admin_connection(tmp_path):
    conn = Conn(("installer", False, False, False))

    class Psy:
        @staticmethod
        def connect(**kwargs):
            return conn

    with pytest.raises(pb.BootstrapPreflightError, match="lacks required privileges"):
        pb.fresh_bootstrap(
            psycopg2=Psy(), config_path=tmp_path / "db-config.json",
            host="127.0.0.1", port=5432, bootstrap_db="postgres",
            bootstrap_user="installer", bootstrap_password="secret",
            target_db="minisiem", owner_user="minisiem_owner", owner_password="owner",
            timeout=2,
        )
    assert conn.closed is True


def test_resume_phase_helper_keeps_later_checkpoint_while_revalidating_earlier_phase(tmp_path):
    from tools import fresh_install_state as fis
    import shutil

    root = Path(__file__).resolve().parents[1]
    target = tmp_path / "target"
    target.mkdir()
    for rel in fis.FINGERPRINT_FILES:
        src = root / rel
        dst = target / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    cfg = target / "db-config.json"
    cfg.write_text(json.dumps({"backend":"postgres","postgres":{"host":"db","port":5432,"dbname":"minisiem"}}))
    state = target / ".fresh-install-state.json"
    fis.init(state, target=target, source=target, backend="postgres", config=cfg)
    fis.set_phase(state, "SCHEMA_VERIFIED")

    pb._phase(state, "OWNER_READY")
    assert fis.load(state)["phase"] == "SCHEMA_VERIFIED"
    pb._phase(state, "RUNTIME_CREDENTIALS_READY")
    assert fis.load(state)["phase"] == "RUNTIME_CREDENTIALS_READY"
