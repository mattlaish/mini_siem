import json
from pathlib import Path

import pytest

from tools import postgres_event_storage_v2 as esv2
from tools import postgres_upgrade_existing as pgue

ROOT = Path(__file__).resolve().parents[1]


def test_fresh_and_upgrade_are_separate_fail_closed_entrypoints():
    fresh = (ROOT / "fresh-install.sh").read_text()
    upgrade = (ROOT / "upgrade-existing.sh").read_text()
    low = (ROOT / "install-services.sh").read_text()

    assert "Use upgrade-existing.sh" in fresh
    assert "--bootstrap-postgres" in fresh
    assert "MINISIEM_INSTALL_ENTRYPOINT=fresh" in fresh
    assert "Existing runtime state detected" in fresh

    assert "No existing mini-SIEM installation found" in upgrade
    assert "postgres_upgrade_existing.py" in upgrade
    assert "postgres-pre-upgrade.dump" in upgrade
    assert "runtime credentials" in upgrade
    assert "--bootstrap-postgres" not in upgrade
    assert "MINISIEM_INSTALL_ENTRYPOINT=upgrade" in upgrade
    assert "--recover-interrupted" in upgrade
    assert ".existing-upgrade-state.json" in upgrade
    assert "old-code rollback is unsafe" in upgrade

    assert "--bootstrap-postgres is an internal fresh-install path" in low
    assert "Use: sudo ./fresh-install.sh" in low


def test_owner_config_can_use_nonsecret_split_role_base(tmp_path, monkeypatch):
    cfg_path = tmp_path / "db-config.json"
    cfg_path.write_text(json.dumps({
        "backend": "postgres",
        "postgres": {
            "host": "db.internal",
            "port": 5432,
            "dbname": "minisiem",
            "user": "",
            "password": "",
        },
        "postgres_privilege_boundary": {
            "enabled": True,
            "owner_role": "minisiem_owner",
        },
    }))
    monkeypatch.setenv(esv2.OWNER_PASSWORD_ENV, "owner-secret")
    out = esv2._owner_config(cfg_path, "")
    assert out["postgres"]["user"] == "minisiem_owner"
    assert out["postgres"]["password"] == "owner-secret"
    # Source config remains non-secret.
    saved = json.loads(cfg_path.read_text())
    assert saved["postgres"]["password"] == ""


def test_upgrade_existing_requires_split_role_credentials(tmp_path, monkeypatch):
    cfg_path = tmp_path / "db-config.json"
    cfg_path.write_text(json.dumps({
        "backend": "postgres",
        "postgres": {"host": "db", "port": 5432, "dbname": "minisiem", "user": "", "password": ""},
        "postgres_privilege_boundary": {
            "enabled": True,
            "owner_role": "minisiem_owner",
            "runtime_role": "minisiem_runtime",
            "ingest_role": "minisiem_ingest",
            "dashboard_role": "minisiem_dashboard",
            "maintenance_role": "minisiem_maintenance",
        },
    }))
    monkeypatch.setenv(esv2.OWNER_PASSWORD_ENV, "owner-secret")
    cfg = esv2._owner_config(cfg_path, "")
    with pytest.raises(RuntimeError, match="credential files are missing"):
        pgue._require_existing_split_state(cfg_path, cfg)

    for identity, filename in pgue.CREDENTIAL_FILES.items():
        role = {
            "listener": "minisiem_ingest",
            "dashboard": "minisiem_dashboard",
            "maintenance": "minisiem_maintenance",
        }[identity]
        (tmp_path / filename).write_text(json.dumps({
            "identity": identity,
            "postgres": {"user": role, "password": "kept-secret"},
        }))
    roles = pgue._require_existing_split_state(cfg_path, cfg)
    assert roles["owner_role"] == "minisiem_owner"
    assert roles["ingest_role"] == "minisiem_ingest"


def test_upgrade_owner_discovery_uses_existing_runtime_and_no_fresh_owner_guess():
    upgrade = (ROOT / "upgrade-existing.sh").read_text()
    helper = (ROOT / "tools" / "postgres_upgrade_existing.py").read_text()

    # Existing upgrades discover the real database owner through the already
    # working installed dashboard runtime; system Python is not required to
    # import psycopg2 for discovery.
    assert "installed dashboard runtime credential" in upgrade
    assert 'PYTHONPATH="$TARGET" "$TARGET_PYTHON"' in upgrade
    assert 'db-dashboard-credentials.json' in upgrade
    discovery_block = upgrade.split('set_stage "postgres-owner-discovery"', 1)[1].split('PYTHON_BIN=""', 1)[0]
    assert "import psycopg2" not in discovery_block

    # Existing upgrade must not invent the fresh-install-only owner name.
    assert 'or "minisiem_owner"' not in helper

    # Both normal cutover and rollback reconcile services from the restored /
    # installed target cwd so `python -c "import db"` resolves the target tree.
    assert upgrade.count('(cd "$TARGET" && ./install-services.sh)') >= 2


def test_upgrade_backup_selects_server_compatible_pg_dump_and_verifies_archive():
    upgrade = (ROOT / "upgrade-existing.sh").read_text()
    assert "PostgreSQL server version" in upgrade
    assert "LOCAL_MAJOR >= SERVER_MAJOR" in upgrade
    assert "using PostgreSQL container pg_dump" in upgrade
    assert "docker exec -e PGPASSWORD" in upgrade
    assert "postgres-pg-dump.stderr" in upgrade
    assert "postgres-backup-verify" in upgrade
    assert "pg_restore -l" in upgrade


def test_legacy_split_role_owner_can_be_existing_database_owner(tmp_path):
    cfg_path = tmp_path / "db-config.json"
    cfg_path.write_text(json.dumps({
        "backend": "postgres",
        "postgres": {
            "host": "db",
            "port": 5432,
            "dbname": "minisiem",
            "user": "minisiem",
            "password": "owner-secret",
        },
        "postgres_privilege_boundary": {
            "enabled": True,
            "runtime_role": "minisiem_runtime",
            "ingest_role": "minisiem_ingest",
            "dashboard_role": "minisiem_dashboard",
            "maintenance_role": "minisiem_maintenance",
        },
    }))
    for identity, filename in pgue.CREDENTIAL_FILES.items():
        role = {
            "listener": "minisiem_ingest",
            "dashboard": "minisiem_dashboard",
            "maintenance": "minisiem_maintenance",
        }[identity]
        (tmp_path / filename).write_text(json.dumps({
            "identity": identity,
            "postgres": {"user": role, "password": "kept-secret"},
        }))

    cfg = json.loads(cfg_path.read_text())
    roles = pgue._require_existing_split_state(cfg_path, cfg)
    assert roles["owner_role"] == "minisiem"


def test_existing_upgrade_uses_ledger_pipeline_not_generic_initialize(monkeypatch):
    executed = []
    commits = []

    class FakeConn:
        backend = "postgres"
        def execute(self, sql, params=()):
            executed.append((sql, params))
            class Cursor:
                def fetchall(self_inner):
                    if sql.startswith("SELECT version FROM schema_migrations"):
                        return [{"version": i} for i in range(1, 27)]
                    return []
            return Cursor()
        def commit(self):
            commits.append(True)
        def rollback(self):
            pass
        def close(self):
            pass

    monkeypatch.setattr(pgue.db, "connect", lambda cfg: FakeConn())
    monkeypatch.setattr(pgue.db, "_migrations", lambda: ["SELECT 1"] * 41)
    monkeypatch.setattr(pgue.db, "ensure_log_fields_normalized_schema", lambda conn: executed.append(("NORMALIZE", ())))
    monkeypatch.setattr(pgue, "postgres_schema_statements", lambda: ["SELECT 'EV1'", "SELECT 'EV2'"])

    versions = pgue._upgrade_existing_owner_schema({"backend": "postgres"})

    # Existing DB starts at 26 and is advanced explicitly, not implicitly baselined.
    for version in range(27, 42):
        assert version in versions
    assert ("NORMALIZE", ()) in executed
    assert any(sql == "SELECT 'EV1'" for sql, _ in executed)
    assert any(sql == "SELECT 'EV2'" for sql, _ in executed)
    inserted_versions = [params[0] for sql, params in executed if sql.startswith("INSERT INTO schema_migrations")]
    assert inserted_versions == list(range(27, 42))
    assert commits

    helper = (ROOT / "tools" / "postgres_upgrade_existing.py").read_text()
    assert "db.initialize(cfg)" not in helper
    assert "Fresh install continues to use db.initialize()" in helper


def test_fresh_install_requires_preconfigured_database_intent_and_does_not_reconfigure():
    fresh = (ROOT / "fresh-install.sh").read_text()
    assert "Run: python3 configure-db.py" in fresh
    assert 'SOURCE_CONFIG="$SOURCE_REAL/db-config.json"' in fresh
    assert 'install -m 0640 "$SOURCE_CONFIG" "$TARGET_CONFIG"' in fresh
    assert "Removing stale packaged database configuration" not in fresh
    assert '"$TARGET/configure-db.py"' not in fresh
    assert "Starting database setup (SQLite or PostgreSQL)." not in fresh
    assert "or 'sqlite'" not in fresh


def test_fresh_install_postgres_branch_never_falls_back_to_sqlite():
    fresh = (ROOT / "fresh-install.sh").read_text()
    postgres_branch = fresh.split("  postgres)", 1)[1].split("  sqlite)", 1)[0]
    assert "--bootstrap-postgres" in postgres_branch
    assert "MINISIEM_INSTALL_ENTRYPOINT=fresh" in postgres_branch
    assert "sqlite" not in postgres_branch.lower()
