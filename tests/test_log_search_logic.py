import sqlite3

import pytest
import dashboard


class MultiArgs:
    """Minimal repeated-query-parameter mapping used by dashboard helpers."""
    def __init__(self, pairs):
        self._pairs = list(pairs)

    def get(self, key, default=None):
        for k, value in self._pairs:
            if k == key:
                return value
        return default

    def getlist(self, key):
        return [value for k, value in self._pairs if k == key]

    def lists(self):
        seen = []
        for key, _ in self._pairs:
            if key not in seen:
                seen.append(key)
        for key in seen:
            yield key, self.getlist(key)

    def items(self):
        return [(key, self.get(key)) for key, _ in self.lists()]


SELECT_COLS = (
    "id, received_at, source_ip, peer_ip, severity, facility, hostname, "
    "destination, app_name, message"
)


def _open_db(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


@pytest.fixture()
def search_db(tmp_path, monkeypatch):
    path = tmp_path / "search.db"
    conn = _open_db(path)
    conn.executescript(
        """
        CREATE TABLE logs (
            id INTEGER PRIMARY KEY,
            received_at TEXT NOT NULL,
            source_ip TEXT,
            peer_ip TEXT,
            severity TEXT,
            facility TEXT,
            hostname TEXT,
            destination TEXT,
            app_name TEXT,
            message TEXT
        );
        CREATE TABLE log_fields (
            log_id INTEGER NOT NULL,
            field TEXT NOT NULL,
            value TEXT NOT NULL
        );
        CREATE INDEX idx_lf_field_value ON log_fields(field, value);
        CREATE INDEX idx_lf_log_id ON log_fields(log_id);
        """
    )
    conn.executemany(
        "INSERT INTO logs VALUES (?,?,?,?,?,?,?,?,?,?)",
        [
            (1, "2026-09-03T14:02:04Z", "sophos", "10.0.0.10", "informational", "user", "EHWS447", "cloud", "Sophos", "Update succeeded. Event ID 19"),
            (2, "2026-09-03T14:03:04Z", "sophos", "10.0.0.10", "warning", "user", "EHWS447", "quarantine", "Sophos", "Malware detected. Event ID 111"),
            (3, "2026-09-03T14:04:04Z", "firewall", "10.0.0.20", "notice", "local0", "FW01", "cloud", "Fortigate", "Update succeeded. Event ID 19"),
            (4, "2026-09-03T14:05:04Z", "collector", "10.0.0.30", "notice", "local0", "EHWS448", "archive", "Agent", "Agent heartbeat complete"),
        ],
    )
    conn.executemany(
        "INSERT INTO log_fields(log_id, field, value) VALUES (?,?,?)",
        [
            (1, "group", "UPDATING"), (1, "event_id", "19"),
            (2, "group", "MALWARE"), (2, "event_id", "111"),
            (3, "group", "UPDATING"), (3, "event_id", "19"),
            (4, "group", "HEALTH"), (4, "event_id", "7"),
        ],
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr(dashboard, "get_conn", lambda: _open_db(path))
    monkeypatch.setattr(dashboard.dbmod, "fts5_available", lambda _conn: False)
    monkeypatch.setattr(
        dashboard,
        "get_search_aliases",
        lambda: {"source": [], "host": [], "destination": []},
    )
    return path


def _ids(args):
    rows = dashboard._query_logs_extracted(
        MultiArgs(args), 100, SELECT_COLS, sort_cap=1000
    )
    return [row["id"] for row in rows]


def test_message_text_and_field_filter_are_conjunctive(search_db):
    assert _ids([("q", "Update"), ("fc", "group=UPDATING")]) == [3, 1]
    # This is the key regression guard: field filters must not be ORed with
    # message text merely because the field-chip operator is OR.
    assert _ids([
        ("q", "Malware"),
        ("fc", "group=UPDATING"),
        ("fc", "event_id=19"),
        ("fc_op", "or"),
    ]) == []


def test_field_or_preserves_duplicate_field_names(search_db):
    assert _ids([
        ("fc", "event_id=19"),
        ("fc", "event_id=111"),
        ("fc_op", "or"),
    ]) == [3, 2, 1]
    assert _ids([
        ("fc", "event_id=19"),
        ("fc", "event_id=111"),
    ]) == []


def test_source_or_is_scoped_to_source_and_other_filters_stay_and(search_db):
    assert _ids([
        ("source_ip", "sophos,firewall"),
        ("source_op", "or"),
    ]) == [3, 2, 1]
    assert _ids([
        ("source_ip", "sophos,firewall"),
        ("source_op", "or"),
        ("hostname", "EHWS447"),
    ]) == [2, 1]
    assert _ids([("source_ip", "sophos,firewall")]) == []


def test_host_and_destination_support_or(search_db):
    assert _ids([
        ("hostname", "EHWS447,FW01"),
        ("host_op", "or"),
    ]) == [3, 2, 1]
    assert _ids([
        ("destination", "cloud,archive"),
        ("destination_op", "or"),
    ]) == [4, 3, 1]


def test_negations_remain_conjunctive_in_or_mode(search_db):
    assert _ids([
        ("source_ip", "sophos,firewall,!firewall"),
        ("source_op", "or"),
    ]) == [2, 1]
    assert _ids([
        ("fc", "group=UPDATING"),
        ("fc", "group=MALWARE"),
        ("fc", "event_id=!111"),
        ("fc_op", "or"),
    ]) == [3, 1]
