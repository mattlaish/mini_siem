"""Playbooks read the whole window in pages and report what they covered."""
import contextlib
import io
from datetime import datetime, timedelta, timezone

import pytest

import correlations
import db
import workers
from listener import Storage, parse_syslog


@pytest.fixture()
def conn(tmp_path):
    cfg = db.config_from_path(str(tmp_path / "siem.db"))
    with contextlib.redirect_stdout(io.StringIO()):
        db.initialize(cfg)
        storage = Storage(db_config=cfg)
        now = datetime.now(timezone.utc)
        # 120 failed logins from one address spread over the last 2 hours,
        # then one success: the oldest failures are far outside a 50-row cap.
        for i in range(120):
            ev = parse_syslog(f"<38>Nov 14 10:00:00 web01 sshd[1]: Failed password for root from 203.0.113.9 port 22",
                              "10.0.0.5")
            ev["received_at"] = (now - timedelta(minutes=120 - i)).isoformat()
            storage.insert_log(ev)
        ok = parse_syslog("<38>Nov 14 10:00:00 web01 sshd[1]: Accepted password for root from 203.0.113.9 port 22",
                          "10.0.0.5")
        ok["received_at"] = now.isoformat()
        storage.insert_log(ok)
        storage.conn.commit()
    c = db.connect(cfg)
    yield c
    c.close()


def _threshold(threshold=100):
    return {"type": "threshold", "pattern": "failed password", "group_by": "source_ip",
            "threshold": threshold, "window_minutes": 180}


def test_pages_cover_the_whole_window(conn, monkeypatch):
    monkeypatch.setattr(correlations, "PAGE_ROWS", 7)          # many small pages
    out = correlations.run_correlation(conn, _threshold())
    assert out["group_count"] == 1
    group = out["groups"][0]
    assert group["key"] == "203.0.113.9" and group["count"] == 120
    assert out["coverage"]["complete"] is True and out["coverage"]["scanned"] == 121


def test_scan_limit_reads_newest_events_and_says_so(conn):
    out = correlations.run_correlation(conn, _threshold(threshold=1), scan_limit=50)
    cov = out["coverage"]
    assert cov["complete"] is False and cov["scanned"] == 50
    assert out["groups"][0]["count"] == 49                      # 49 failures + the success
    assert cov["scanned_from"] > cov["since"]


def test_evidence_ids_are_bounded_but_counts_exact(conn, monkeypatch):
    monkeypatch.setattr(correlations, "MAX_GROUP_IDS", 10)
    group = correlations.run_correlation(conn, _threshold())["groups"][0]
    assert group["count"] == 120 and len(group["log_ids"]) == 10 and group["log_ids_truncated"]


def test_sequence_detected_across_pages(conn, monkeypatch):
    monkeypatch.setattr(correlations, "PAGE_ROWS", 9)
    out = correlations.run_correlation(conn, {
        "type": "sequence", "pattern": "failed password", "pattern_b": "accepted password",
        "group_by": "source_ip", "min_a_count": 5, "max_gap_seconds": 900, "window_minutes": 180})
    assert out["group_count"] == 1 and out["groups"][0]["a_count"] == 15


def test_report_scans_once_and_flags_partial_coverage(conn, monkeypatch):
    calls = []
    real = correlations._scan_window

    def counting(*args, **kwargs):
        calls.append(args[1])
        return real(*args, **kwargs)

    monkeypatch.setattr(correlations, "_scan_window", counting)
    monkeypatch.setattr(correlations, "INTERACTIVE_SCAN_LIMIT", 50)
    report = workers.run_playbook_report(conn, window_days=1, trigger="manual")
    baseline_scans = sum(1 for pb in correlations.PLAYBOOKS if pb["params"]["type"] == "first_seen")
    assert len(calls) == 1 + baseline_scans                     # one shared scan, not one per playbook
    assert report["summary"].startswith("Partial")
    assert report["coverage"]["complete"] is False
    stored = conn.execute("SELECT summary FROM reports WHERE id=?", (report["id"],)).fetchone()["summary"]
    assert stored.startswith("Partial")
    assert all(r["error"] is None for r in report["results"])
    hit = next(r for r in report["results"] if r["id"] == "bruteforce_then_success")
    assert hit["group_count"] == 1


def test_resolved_identity_does_not_rewrite_the_raw_column():
    rows = [{"id": 1, "source_ip": "sophos", "message": ""}]

    class Conn:
        backend = "sqlite"

        def execute(self, sql, params):
            class R:
                def fetchall(self_inner):
                    return [{"log_id": 1, "field": "src", "value": "192.0.2.7"}]
            return R()

    correlations._resolve_identity(Conn(), rows, "source_ip", {"source_ip": ["src"]})
    assert rows[0]["source_ip"] == "sophos"
    assert correlations._key_of(rows[0], "source_ip") == "192.0.2.7"


def test_a_failing_check_does_not_stop_the_others(conn):
    good = correlations._prepare(_threshold())
    bad = correlations._prepare({"type": "fanout", "pattern": ".", "group_by": "source_ip",
                                 "distinct_field": "hostname", "threshold": 1, "window_minutes": 180})
    bad.feed = lambda row: (_ for _ in ()).throw(ValueError("boom"))
    status = correlations.run_checks(conn, [good, bad], good.p["since"], None, 1000)
    assert status[id(bad)]["error"] == "ValueError: boom" and status[id(good)]["error"] is None
    assert good.finish()[0]["count"] == 120
