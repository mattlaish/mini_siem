"""One alert when PostgreSQL events land in the DEFAULT partition."""
from datetime import datetime, timezone

import workers


class Result:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class FakePG:
    backend = "postgres"

    def __init__(self, first=None, dated_fields=False):
        self.first, self.dated_fields = first, dated_fields
        self.config, self.alerts, self.commits = {}, [], 0

    def execute(self, sql, params=()):
        if "security_events_default" in sql:
            return Result({"first": self.first, "last": self.first})
        if "to_regclass" in sql:
            return Result({"r": "log_fields_default"})
        if "log_fields_default" in sql:
            return Result({"present": self.dated_fields})
        if sql.startswith("SELECT value FROM app_config"):
            v = self.config.get(params[0])
            return Result({"value": v} if v is not None else None)
        if sql.startswith("DELETE FROM app_config"):
            self.config.pop(params[0], None)
        elif sql.startswith("INSERT INTO app_config"):
            self.config[params[0]] = params[1]
        return Result(None)

    def insert_returning_id(self, sql, params):
        self.alerts.append(params)
        return len(self.alerts)

    def commit(self):
        self.commits += 1


def test_sqlite_has_no_default_partition():
    class Lite:
        backend = "sqlite"
    assert workers.default_partition_rows(Lite()) is None


def test_one_alert_per_episode():
    conn = FakePG(first=datetime(2029, 1, 1, tzinfo=timezone.utc))
    assert workers.check_default_partitions(conn) == 1
    assert workers.check_default_partitions(conn) is None          # same episode: no repeat
    rule, severity = conn.alerts[0][1], conn.alerts[0][2]
    assert (rule, severity) == ("storage_default_partition", "warning")
    assert "2029-01-01T00:00:00+00:00" in conn.alerts[0][4]
    conn.first = None                                              # rows moved out
    assert workers.check_default_partitions(conn) is None
    assert workers.DEFAULT_PARTITION_STATE not in conn.config
    conn.dated_fields = True                                       # a new episode alerts again
    assert workers.check_default_partitions(conn) == 2
    assert "dated search-field rows" in conn.alerts[1][4]


def test_watcher_respects_the_lease():
    opened = []
    watcher = workers.StorageHealthWatcher(lambda: opened.append(1), lease=lambda: False)
    assert watcher._cycle() is None and not opened


def test_sqlite_top_values_for_one_field(tmp_path, monkeypatch):
    import contextlib
    import io

    import dashboard
    import db
    from listener import Storage, parse_syslog
    from normalize import FieldIndexer

    cfg = db.config_from_path(str(tmp_path / "siem.db"))
    with contextlib.redirect_stdout(io.StringIO()):
        db.initialize(cfg)
        storage = Storage(db_config=cfg)
        indexer = FieldIndexer(storage)
        for i, act in enumerate(["deny", "Deny", "allow", "deny"]):
            event = parse_syslog(f"<134>Nov  9 10:0{i}:00 fw app: act={act} src=10.0.0.{i}", "10.1.1.1")
            storage.insert_log(event, fields=indexer.extract(event))
        storage.conn.commit()
    monkeypatch.setattr(dashboard, "get_conn", lambda: db.connect(cfg))
    with dashboard.app.test_request_context("/api/logs/facets?field=act"):
        body = dashboard.api_logs_facets().get_json()
    assert body["field"] == "act"
    assert body["values"] == [{"value": "deny", "count": 3}, {"value": "allow", "count": 1}]
    with dashboard.app.test_request_context("/api/logs/facets?field="):
        response, status = dashboard.api_logs_facets()
    assert status == 400
