import json
from pathlib import Path
import sys
import types

import pytest

from tools import postgres_legacy_split_migration as legacy


class DummyConn:
    def close(self):
        pass


def _legacy_config(path: Path):
    path.write_text(json.dumps({
        "backend": "postgres",
        "postgres": {
            "host": "db.internal",
            "port": 5432,
            "dbname": "minisiem",
            "user": "legacy_owner",
            "password": "legacy-secret",
            "connect_timeout": 5,
        },
    }))


def test_legacy_state_requires_unsplit_postgres_and_finds_existing_owner_secret(tmp_path, monkeypatch):
    cfg = tmp_path / "db-config.json"
    _legacy_config(cfg)
    base, owner, password = legacy._legacy_state(cfg)
    assert owner == "legacy_owner"
    assert password == "legacy-secret"
    assert base["backend"] == "postgres"

    raw = json.loads(cfg.read_text())
    raw["postgres_privilege_boundary"] = {"enabled": True}
    cfg.write_text(json.dumps(raw))
    with pytest.raises(RuntimeError, match="already enabled"):
        legacy._legacy_state(cfg)


def test_candidate_config_scrubs_shared_owner_password_and_enables_split_boundary(tmp_path):
    cfg = tmp_path / "db-config.json"
    _legacy_config(cfg)
    base = json.loads(cfg.read_text())
    out = legacy._candidate_config(base, "legacy_owner")
    assert out["postgres"]["user"] == ""
    assert out["postgres"]["password"] == ""
    pb = out["postgres_privilege_boundary"]
    assert pb["enabled"] is True
    assert pb["owner_role"] == "legacy_owner"
    assert pb["ingest_role"] == "minisiem_ingest"
    assert pb["dashboard_role"] == "minisiem_dashboard"
    assert pb["maintenance_role"] == "minisiem_maintenance"


def test_run_commits_config_and_credentials_only_after_candidate_verification(tmp_path, monkeypatch):
    cfg = tmp_path / "db-config.json"
    _legacy_config(cfg)
    monkeypatch.setitem(sys.modules, "psycopg2", types.SimpleNamespace())
    conns = [DummyConn(), DummyConn()]
    monkeypatch.setattr(legacy, "_connect", lambda *a, **k: conns.pop(0))
    monkeypatch.setattr(legacy, "_verify_legacy_owner", lambda *a, **k: {
        "owner_role": "legacy_owner", "database_owner": "legacy_owner", "wrong_owners": []
    })
    monkeypatch.setattr(legacy.bootstrap, "_bootstrap_preflight", lambda *a, **k: {
        "effective_user": "dba", "authorized": True
    })
    passwords = {
        "minisiem_ingest": "ingest-secret",
        "minisiem_dashboard": "dash-secret",
        "minisiem_maintenance": "maint-secret",
    }
    monkeypatch.setattr(legacy.boundary, "_provision_runtime_roles", lambda *a, **k: passwords)
    monkeypatch.setattr(legacy.boundary, "harden_owner_default_privileges", lambda *a, **k: None)
    monkeypatch.setattr(legacy.existing_upgrade, "_migration_versions", lambda *a, **k: [1, 2, 3])
    monkeypatch.setattr(legacy.existing_upgrade, "_upgrade_existing_owner_schema", lambda *a, **k: [1, 2, 3])
    monkeypatch.setattr(legacy.esv2, "backfill", lambda *a, **k: {"inserted": 0})
    monkeypatch.setattr(legacy.db, "connect", lambda *a, **k: DummyConn())
    monkeypatch.setattr(legacy.boundary, "_apply_grants", lambda *a, **k: {})
    verified = {
        "listener": {"role": "minisiem_ingest", "can_read_events_v2": True, "can_insert_events_v2": True, "can_delete_events_v2": False},
        "dashboard": {"role": "minisiem_dashboard", "can_read_events_v2": True, "can_insert_events_v2": False, "can_delete_events_v2": False},
        "maintenance": {"role": "minisiem_maintenance", "can_read_events_v2": True, "can_insert_events_v2": False, "can_delete_events_v2": True},
    }
    monkeypatch.setattr(legacy, "_verify_candidate", lambda *a, **k: verified)

    report = legacy.run(cfg, bootstrap_user="dba", bootstrap_password="dba-secret")
    saved = json.loads(cfg.read_text())
    assert saved["postgres"]["user"] == ""
    assert saved["postgres"]["password"] == ""
    assert saved["postgres_privilege_boundary"]["owner_role"] == "legacy_owner"
    assert report["owner_password_persisted_in_runtime_config"] is False
    assert report["bootstrap_credential_persisted"] is False

    for identity, filename in legacy.CREDENTIAL_FILES.items():
        payload = json.loads((tmp_path / filename).read_text())
        assert payload["identity"] == identity
        assert payload["postgres"]["user"] == legacy.ROLE_BY_IDENTITY[identity]
        assert "legacy-secret" not in (tmp_path / filename).read_text()
        assert "dba-secret" not in (tmp_path / filename).read_text()


def test_failed_candidate_verification_does_not_cut_over_runtime_files(tmp_path, monkeypatch):
    cfg = tmp_path / "db-config.json"
    _legacy_config(cfg)
    before = cfg.read_text()
    monkeypatch.setitem(sys.modules, "psycopg2", types.SimpleNamespace())
    conns = [DummyConn(), DummyConn()]
    monkeypatch.setattr(legacy, "_connect", lambda *a, **k: conns.pop(0))
    monkeypatch.setattr(legacy, "_verify_legacy_owner", lambda *a, **k: {})
    monkeypatch.setattr(legacy.bootstrap, "_bootstrap_preflight", lambda *a, **k: {})
    monkeypatch.setattr(legacy.boundary, "_provision_runtime_roles", lambda *a, **k: {
        "minisiem_ingest": "i", "minisiem_dashboard": "d", "minisiem_maintenance": "m"
    })
    monkeypatch.setattr(legacy.boundary, "harden_owner_default_privileges", lambda *a, **k: None)
    monkeypatch.setattr(legacy.existing_upgrade, "_migration_versions", lambda *a, **k: [1])
    monkeypatch.setattr(legacy.existing_upgrade, "_upgrade_existing_owner_schema", lambda *a, **k: [1])
    monkeypatch.setattr(legacy.esv2, "backfill", lambda *a, **k: {"inserted": 0})
    monkeypatch.setattr(legacy.db, "connect", lambda *a, **k: DummyConn())
    monkeypatch.setattr(legacy.boundary, "_apply_grants", lambda *a, **k: {})
    monkeypatch.setattr(legacy, "_verify_candidate", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("verify failed")))

    with pytest.raises(RuntimeError, match="verify failed"):
        legacy.run(cfg, bootstrap_user="dba", bootstrap_password="dba-secret")
    assert cfg.read_text() == before
    for filename in legacy.CREDENTIAL_FILES.values():
        assert not (tmp_path / filename).exists()


def test_upgrade_existing_integrates_legacy_conversion_after_verified_backup():
    text = (Path(__file__).resolve().parents[1] / "upgrade-existing.sh").read_text()
    assert "postgres_legacy_split_migration.py" in text
    assert "MINISIEM_PG_BOOTSTRAP_PASSWORD" in text
    assert "Legacy shared PostgreSQL owner/runtime deployment detected" in text
    assert text.index('set_stage "postgres-backup-verify"') < text.index('set_stage "postgres-legacy-split-role-migration"')
    assert text.index('postgres_legacy_split_migration.py') < text.index('postgres_upgrade_existing.py')
