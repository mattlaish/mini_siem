import os
import tempfile

from werkzeug.security import check_password_hash, generate_password_hash

import auth
import db


def _fresh_conn():
    cfg = db.config_from_path(os.path.join(tempfile.mkdtemp(), "s.db"))
    db.initialize(cfg)
    return db.connect(cfg)


def _admin_row(conn):
    return conn.execute(
        "SELECT password_hash, must_change_password FROM users WHERE username='admin'"
    ).fetchone()


def _val(row, key, idx):
    return row[key] if isinstance(row, dict) else row[idx]


def test_seed_creates_default_admin_on_empty_db():
    conn = _fresh_conn()
    assert db.ensure_admin_bootstrap_safe(conn) is False
    auth.seed_default_admin(conn)
    assert db.ensure_admin_bootstrap_safe(conn) is True
    row = _admin_row(conn)
    # Default admin is created and forced to change its password.
    assert _val(row, "must_change_password", 1) == 1
    assert check_password_hash(_val(row, "password_hash", 0), "admin")


def test_seed_does_not_overwrite_existing_admin():
    conn = _fresh_conn()
    # An admin already exists (e.g. carried across during a backend migration)
    # with a real password and no forced change.
    conn.execute(
        """INSERT INTO users (username, password_hash, role, auth_source,
                              must_change_password, created_at)
           VALUES (?,?,?,?,?,?)""",
        ("admin", generate_password_hash("s3cret!"), "admin", "local", 0,
         "2026-01-01T00:00:00Z"),
    )
    conn.commit()

    auth.seed_default_admin(conn)

    row = _admin_row(conn)
    # The existing credentials and must_change flag are preserved untouched.
    assert check_password_hash(_val(row, "password_hash", 0), "s3cret!")
    assert _val(row, "must_change_password", 1) == 0
