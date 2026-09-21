from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_installer_fails_closed_without_postgres_boundary_contract():
    text = (ROOT / "install-services.sh").read_text()
    assert "PostgreSQL runtime privilege boundary is not enabled." in text
    assert "will not install services with a shared owner/runtime credential" in text
    assert "--mode inspect-existing" in text


def test_installer_has_explicit_fresh_postgres_bootstrap_and_readiness_gate():
    text = (ROOT / "install-services.sh").read_text()
    assert "--bootstrap-postgres" in text
    assert "tools/postgres_bootstrap.py" in text
    assert "db.ensure_runtime_ready(cfg)" in text
    assert "MINISIEM_PG_BOOTSTRAP_USER" in text


def test_configure_db_does_not_collect_or_persist_postgres_password():
    text = (ROOT / "configure-db.py").read_text()
    assert '"user": ""' in text
    assert '"password": ""' in text
    assert 'ask("Password"' not in text
    assert 'ask("Username"' not in text


def test_install_services_database_selection_is_fail_closed():
    text = (ROOT / "install-services.sh").read_text()
    assert "Missing ${SCRIPT_DIR}/db-config.json; run configure-db.py before installation." in text
    assert "Falls back to sqlite if db-config.json is absent/unreadable" not in text
    assert "|| echo sqlite" not in text
    assert 'DB_BACKEND="sqlite"' not in text
