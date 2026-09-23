import db
import workers


def _conn(tmp_path):
    cfg = db.config_from_path(str(tmp_path / "siem.db"))
    db.initialize(cfg)
    return db.connect(cfg)


def test_scheduled_playbook_report_findings_become_normal_alerts(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    report = {
        "id": 7,
        "trigger": "weekly",
        "results": [
            {
                "id": "scan_fanout", "name": "Scan fanout", "severity": "warning",
                "group_count": 1,
                "groups": [{"key":"10.0.0.9", "count":7, "log_ids":[11,12,13]}],
                "error": None,
            }
        ],
    }
    created = workers.alerts_from_playbook_report(conn, report)
    assert created == 1
    row = conn.execute("SELECT * FROM alerts").fetchone()
    assert row["rule_name"] == "playbook:scan_fanout"
    assert row["source_ip"] == "10.0.0.9"
    assert row["log_ids"] == "11,12,13"
    assert row["ai_status"] == "pending"
    assert row["workflow_status"] == "new"
    conn.close()


def test_manual_playbook_report_does_not_create_alerts(tmp_path):
    conn = _conn(tmp_path)
    report = {"id":8, "trigger":"manual", "results":[{"id":"x","name":"x","severity":"warning","group_count":1,"groups":[{"key":"10.0.0.1","log_ids":[1]}]}]}
    assert workers.alerts_from_playbook_report(conn, report) == 0
    assert conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"] == 0
    conn.close()


def test_report_scheduler_emits_alerts_only_when_due(tmp_path, monkeypatch):
    cfg = db.config_from_path(str(tmp_path / "siem.db"))
    db.initialize(cfg)

    report = {
        "id": 9, "created_at":"2026-09-23T00:00:00+00:00", "trigger":"weekly",
        "window_days":7, "summary":"1 finding", "findings":1,
        "results":[{"id":"pb","name":"PB","severity":"critical","group_count":1,"groups":[{"key":"host-a","count":1,"log_ids":[5]}],"error":None}],
    }
    monkeypatch.setattr(workers, "run_playbook_report", lambda conn, window_days, trigger: dict(report, trigger=trigger))
    scheduler = workers.ReportScheduler(lambda: db.connect(cfg), lambda: "weekly", check_interval=999)
    out = scheduler.run_if_due()
    assert out["alerts_created"] == 1
    conn = db.connect(cfg)
    row = conn.execute("SELECT * FROM alerts").fetchone()
    assert row["severity"] == "critical"
    assert row["source_ip"] is None
    conn.close()


def test_scheduled_playbook_alert_conversion_is_idempotent(tmp_path):
    conn = _conn(tmp_path)
    report = {
        "id": 77, "trigger": "weekly",
        "results": [{
            "id": "scan_fanout", "name": "Scan fanout", "severity": "warning",
            "group_count": 1, "groups": [{"key":"10.0.0.9","count":7,"log_ids":[11,12]}],
            "error": None,
        }],
    }
    assert workers.alerts_from_playbook_report(conn, report) == 1
    assert workers.alerts_from_playbook_report(conn, report) == 0
    assert conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"] == 1
    conn.close()


def test_scheduler_heals_committed_report_missing_alerts(tmp_path):
    cfg = db.config_from_path(str(tmp_path / "siem.db"))
    db.initialize(cfg)
    conn = db.connect(cfg)
    results = [{
        "id":"pb", "name":"PB", "severity":"warning", "group_count":1,
        "groups":[{"key":"10.0.0.8","count":2,"log_ids":[21,22]}], "error":None,
    }]
    from datetime import datetime, timezone
    import json
    conn.execute(
        """INSERT INTO reports (created_at,kind,trigger,window_days,summary,findings,results_json)
           VALUES (?,?,?,?,?,?,?)""",
        (datetime.now(timezone.utc).isoformat(), "playbooks", "weekly", 7, "1 finding", 1, json.dumps(results)),
    )
    conn.commit(); conn.close()

    scheduler = workers.ReportScheduler(lambda: db.connect(cfg), lambda: "weekly", check_interval=999)
    out = scheduler.run_if_due()
    assert out is not None
    assert out["alerts_created"] == 1

    conn = db.connect(cfg)
    assert conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"] == 1
    conn.close()
    # A second hourly check sees the same report but creates no duplicate.
    assert scheduler.run_if_due() is None
    conn = db.connect(cfg)
    assert conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"] == 1
    conn.close()
