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
