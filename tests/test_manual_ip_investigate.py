import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

import ai_soc


ROOT = "10.20.30.40"
HOP1 = "10.20.30.41"
HOP2 = "10.20.30.42"
HOP3 = "10.20.30.43"
PASSIVE = "10.20.30.50"
ANCHOR = datetime(2026, 9, 23, 10, 0, tzinfo=timezone.utc)


def _conn(path=":memory:"):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY,
            received_at TEXT,
            source_ip TEXT,
            peer_ip TEXT,
            destination TEXT,
            hostname TEXT,
            app_name TEXT,
            severity TEXT,
            message TEXT
        );
        CREATE TABLE IF NOT EXISTS log_fields (
            id INTEGER PRIMARY KEY,
            log_id INTEGER NOT NULL,
            field TEXT NOT NULL,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            at TEXT,
            username TEXT,
            source_ip TEXT,
            action TEXT,
            target TEXT,
            detail TEXT
        );
        """
    )
    return conn


def _seed(conn):
    rows = [
        (1, "2026-09-23T09:40:00+00:00", ROOT, "fw", HOP1, "fw1", "CEF", "notice", "A contacts B"),
        (2, "2026-09-23T09:41:00+00:00", ROOT, "fw", PASSIVE, "fw1", "CEF", "notice", "A contacts passive destination"),
        (3, "2026-09-23T09:42:00+00:00", HOP1, "fw", HOP2, "fw1", "CEF", "warning", "B becomes source"),
        (4, "2026-09-23T09:43:00+00:00", HOP2, "fw", HOP3, "fw1", "CEF", "warning", "C becomes source"),
        (5, "2026-09-23T09:44:00+00:00", HOP3, "fw", "198.51.100.8", "fw1", "CEF", "warning", "D becomes source"),
        (6, "2026-09-23T09:45:00+00:00", "10.99.99.99", "fw", "198.51.100.9", "fw2", "CEF", "critical", "unrelated"),
    ]
    conn.executemany(
        "INSERT INTO logs (id,received_at,source_ip,peer_ip,destination,hostname,app_name,severity,message) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        rows,
    )
    conn.commit()


@pytest.mark.parametrize(
    "stage,minutes",
    [("short", 30), ("medium", 90), ("long", 300)],
)
def test_manual_window_slider_maps_to_concrete_retrospective_minutes(stage, minutes):
    conn = _conn()
    _seed(conn)
    result = ai_soc.gather_ip_investigation(conn, ROOT, stage=stage, max_depth=0, anchor=ANCHOR)
    assert result["stage"] == stage
    assert result["lookback_minutes"] == minutes
    assert result["requested_hops"] == 0
    assert result["investigation_entities"] == [ROOT]


def test_manual_hop_slider_controls_actual_bounded_entity_expansion():
    conn = _conn()
    _seed(conn)
    result = ai_soc.gather_ip_investigation(conn, ROOT, stage="medium", max_depth=2, anchor=ANCHOR)
    assert result["entity_expansion_max_depth"] == 2
    assert result["investigation_entities"] == [ROOT, HOP1, HOP2]
    assert PASSIVE not in result["investigation_entities"]
    assert HOP3 not in result["investigation_entities"]
    assert [(h["parent"], h["entity"], h["depth"]) for h in result["entity_hops"]] == [
        (ROOT, HOP1, 1),
        (HOP1, HOP2, 2),
    ]


def test_manual_four_hop_bound_is_accepted_but_five_is_rejected():
    conn = _conn()
    _seed(conn)
    result = ai_soc.gather_ip_investigation(conn, ROOT, stage="long", max_depth=4, anchor=ANCHOR)
    assert result["entity_expansion_max_depth"] == 4
    with pytest.raises(ValueError, match="between 0 and 4"):
        ai_soc.gather_ip_investigation(conn, ROOT, stage="long", max_depth=5, anchor=ANCHOR)


def test_manual_investigation_rejects_invalid_ip_and_stage():
    conn = _conn()
    with pytest.raises(ValueError, match="valid IPv4 or IPv6"):
        ai_soc.gather_ip_investigation(conn, "not-an-ip")
    with pytest.raises(ValueError, match="short, medium, or long"):
        ai_soc.gather_ip_investigation(conn, ROOT, stage="huge")


def test_dashboard_exposes_manual_investigate_api_contract():
    source = (Path(__file__).resolve().parents[1] / "dashboard.py").read_text()
    assert '@app.route("/api/investigate/ip", methods=["POST"])' in source
    assert "ai_soc.gather_ip_investigation" in source
    assert 'audit("manual_ip_investigation"' in source


def test_correlate_page_exposes_investigate_sliders_and_removes_manual_adhoc_panel():
    html = (Path(__file__).resolve().parents[1] / "templates" / "correlate.html").read_text()
    assert "<h2>Investigate</h2>" in html
    assert 'id="iIp"' in html
    assert 'id="iStage" min="0" max="2"' in html
    assert 'id="iHops" min="0" max="4"' in html
    assert "/api/investigate/ip" in html
    assert "A → B" in html
    assert "<h2>Ad-hoc correlation</h2>" not in html
    assert 'id="runAdhoc"' not in html


def test_existing_correlation_engine_remains_available_after_ui_upgrade():
    from correlations import run_correlation

    conn = _conn()
    _seed(conn)
    result = run_correlation(conn, {
        "type": "threshold",
        "since": "2026-09-23T09:30:00+00:00",
        "until": "2026-09-23T10:00:00+00:00",
        "group_by": "source_ip",
        "pattern": "contacts|becomes source",
        "threshold": 1,
    })
    assert result["type"] == "threshold"
    assert result["group_count"] >= 1
