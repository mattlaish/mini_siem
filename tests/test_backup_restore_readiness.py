from backup_restore import validate_backup

def test_backup_restore_checksum_contract(tmp_path):
    p=tmp_path/"backup.dump"
    p.write_bytes(b"backup")
    import hashlib
    assert validate_backup(str(p), hashlib.sha256(b"backup").hexdigest())
from pathlib import Path
import sqlite3

import pytest

import backup_restore as br


def _make_db(path: Path, value: str = "hello"):
    conn = sqlite3.connect(path)
    try:
        conn.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("INSERT INTO sample(value) VALUES (?)", (value,))
        conn.commit()
    finally:
        conn.close()


def test_sqlite_online_backup_is_verified_private_unique_and_rotated(tmp_path):
    source = tmp_path / "siem.db"
    _make_db(source)
    backup_dir = tmp_path / "backups"

    first = br.create_sqlite_backup(source, backup_dir, keep=1)
    second = br.create_sqlite_backup(source, backup_dir, keep=1)

    assert first["path"] != second["path"]
    assert second["verified"] is True
    assert len(second["sha256"]) == 64
    assert (Path(second["path"]).stat().st_mode & 0o777) == 0o600
    assert not Path(first["path"]).exists()
    assert Path(second["path"]).exists()

    conn = sqlite3.connect(second["path"])
    try:
        assert conn.execute("SELECT value FROM sample").fetchone()[0] == "hello"
    finally:
        conn.close()


def test_sqlite_backup_integrity_failure_is_not_reported_as_success(tmp_path, monkeypatch):
    source = tmp_path / "siem.db"
    _make_db(source)
    backup_dir = tmp_path / "backups"
    monkeypatch.setattr(br, "sqlite_integrity_check", lambda path: (False, "corrupt copy"))

    with pytest.raises(RuntimeError, match="integrity check failed"):
        br.create_sqlite_backup(source, backup_dir)
    assert list(backup_dir.glob("siem-*.db")) == []


def test_sqlite_backup_rejects_invalid_retention_before_copy(tmp_path):
    source = tmp_path / "siem.db"
    _make_db(source)
    with pytest.raises(RuntimeError, match="positive integer"):
        br.create_sqlite_backup(source, tmp_path / "backups", keep=0)


def test_web_backup_route_delegates_to_verified_backup_primitive():
    text = (Path(__file__).resolve().parents[1] / "web_blueprints" / "db_health.py").read_text()
    route = text.split('def api_db_backup():', 1)[1].split('\n\n', 1)[0]
    assert "backup_restore_mod.create_sqlite_backup" in route
    assert '"ok": True' in route
    assert "sqlite3.connect" not in route


def test_sqlite_maintenance_backup_is_private_unique_and_validates_retention():
    text = (Path(__file__).resolve().parents[1] / "db-maintenance.sh").read_text()
    assert "umask 077" in text
    assert 'siem-$stamp-$$.db' in text
    assert '[[ "$KEEP" =~ ^[1-9][0-9]*$ ]]' in text
    assert 'chmod 600 "$dest"' in text
