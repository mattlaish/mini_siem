from pathlib import Path

import pytest

import alert_workflow
import db

ROOT = Path(__file__).resolve().parents[1]


def test_alert_workflow_state_machine_supports_expected_lifecycle_and_reopen():
    current = "new"
    for target in ("acknowledged", "investigating", "resolved", "closed"):
        current, got = alert_workflow.validate_transition(current, target)
        assert got == target
        current = got
    current, got = alert_workflow.validate_transition("closed", "investigating")
    assert (current, got) == ("closed", "investigating")


def test_alert_workflow_rejects_invalid_jump_and_unknown_state():
    with pytest.raises(ValueError, match="new -> closed"):
        alert_workflow.validate_transition("new", "closed")
    with pytest.raises(ValueError, match="invalid alert workflow status"):
        alert_workflow.validate_transition("new", "bogus")


def test_alert_base_schema_and_migrations_include_workflow(tmp_path):
    cfg = db.config_from_path(str(tmp_path / "schema.db"))
    db.initialize(cfg)
    conn = db.connect(cfg)
    rows = conn.execute("PRAGMA table_info(alerts)").fetchall()
    cols = {r["name"] if isinstance(r, dict) else r[1] for r in rows}
    assert {"workflow_status","workflow_assignee","workflow_updated_at","workflow_updated_by","workflow_resolution_note"} <= cols
    assert conn.execute("SELECT COUNT(*) c FROM alert_workflow_events").fetchone()["c"] == 0
    conn.close()
    assert len(db._migrations()) == 41


def test_dashboard_exposes_alert_workflow_api_and_ui_contract():
    py = (ROOT / "dashboard.py").read_text()
    html = (ROOT / "templates" / "index.html").read_text()
    assert '/api/alerts/<int:alert_id>/workflow' in py
    assert '@analyst_required' in py
    assert 'INSERT INTO alert_workflow_events' in py
    assert 'alert_workflow_updated' in py
    assert '<th>Workflow</th>' in html
    assert 'class="alert-workflow"' in html
    assert 'class="alert-assign"' in html


def test_alert_workflow_postgres_schema_is_dialect_aware_not_sqlite_autoincrement():
    import inspect
    source = inspect.getsource(db.ensure_alert_workflow_schema)
    assert 'BIGSERIAL PRIMARY KEY' in source
    assert 'alert_id_type = "BIGINT"' in source
    assert 'INTEGER PRIMARY KEY AUTOINCREMENT' in source
    migrations = db._migrations()
    assert not any('alert_workflow_events (id INTEGER PRIMARY KEY' in stmt for stmt in migrations)
