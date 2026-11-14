"""PostgreSQL *text* field filters: answer newest pages from recent events first."""
from datetime import datetime, timezone

from werkzeug.datastructures import MultiDict

import dashboard

COLS = "id, received_at, source_ip, severity, hostname, app_name, message"


class Result:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


class FakeConn:
    """Records SQL; answers the cutoff query and the page queries from a script."""
    backend = "postgres"

    def __init__(self, cutoff, guarded_rows, indexed_rows):
        self.cutoff, self.guarded, self.indexed = cutoff, guarded_rows, indexed_rows
        self.calls = []

    def execute(self, sql, params=()):
        params = list(params)
        assert sql.count("?") == len(params), (sql, params)   # placeholders stay aligned
        if sql.startswith("SELECT log_id, field, value"):
            return Result([])                                  # display values for the page
        self.calls.append((sql, params))
        if "LIMIT 1 OFFSET" in sql:
            return Result([] if self.cutoff is None else [{"event_time": self.cutoff, "id": 55}])
        if "strpos(" in sql:
            return Result(self.guarded)
        return Result(self.indexed)

    def close(self):
        pass


def _rows(n, start=1000):
    return [{"id": start - i} for i in range(n)]


def _run(monkeypatch, conn, args, limit=3, offset=0):
    monkeypatch.setattr(dashboard, "get_conn", lambda: conn)
    monkeypatch.setattr(dashboard, "get_search_aliases", lambda: {"source": [], "host": [], "destination": []})
    return dashboard._query_logs_extracted(MultiDict(args), limit, COLS, offset=offset)


CUT = datetime(2026, 11, 8, 12, tzinfo=timezone.utc)


def test_full_page_from_recent_events_skips_the_indexed_query(monkeypatch):
    conn = FakeConn(CUT, _rows(3), _rows(3, 500))
    rows = _run(monkeypatch, conn, [("f_url", "*login*"), ("f_act", "deny"), ("from", "2026-11-08T00:00:00Z")])
    assert [r["id"] for r in rows] == [1000, 999, 998]
    page = conn.calls[1][0]
    assert "strpos(fc.value_norm, ?) > 0" in page and "(l.event_time, l.id) >= (?, ?)" in page
    assert "JOIN log_fields f0" not in page                     # no trigram join on the guarded page
    assert "search_fields @>" in page                           # exact filters still apply
    assert conn.calls[1][1][-4:] == [CUT, 55, 3, 0]
    assert not any("JOIN log_fields f0" in sql for sql, _ in conn.calls)


def test_short_window_is_exact_without_a_cutoff(monkeypatch):
    conn = FakeConn(None, _rows(1), _rows(3, 500))
    rows = _run(monkeypatch, conn, [("f_url", "*login*")])
    assert [r["id"] for r in rows] == [1000]
    assert len(conn.calls) == 2 and "l.event_time >= ?" not in conn.calls[1][0]


def test_partial_page_falls_back_to_the_indexed_query(monkeypatch):
    conn = FakeConn(CUT, _rows(1), _rows(3, 500))
    rows = _run(monkeypatch, conn, [("f_url", "*login*"), ("f_user", "!svc*")])
    assert [r["id"] for r in rows] == [500, 499, 498]
    assert "JOIN log_fields f0" in conn.calls[-1][0] and "LIKE ?" in conn.calls[-1][0]


def test_guard_is_skipped_for_or_mode_sorts_and_deep_pages(monkeypatch):
    for args, offset in (([("f_url", "*a*"), ("f_app", "*b*"), ("fc_op", "or")], 0),
                         ([("f_url", "*a*"), ("sort", "source_ip")], 0),
                         ([("f_url", "*a*")], dashboard.CONTAINS_RECENT_EVENTS)):
        conn = FakeConn(CUT, _rows(3), _rows(3, 500))
        _run(monkeypatch, conn, args, offset=offset)
        assert not any("strpos(" in sql for sql, _ in conn.calls), args


def test_prefix_filters_stay_joined_on_the_guarded_page(monkeypatch):
    conn = FakeConn(CUT, _rows(3), [])
    _run(monkeypatch, conn, [("f_host", "web*"), ("f_url", "*login*")])
    page = conn.calls[1][0]
    assert "JOIN log_fields f0" in page and "JOIN log_fields f1" not in page


def _pg_config(monkeypatch):
    monkeypatch.setattr(dashboard, "_db_config", lambda: {"backend": "postgres"})


class StepConn(FakeConn):
    """Answers each search with the rows found since its 'from' bound."""

    def __init__(self, found_by_step):
        super().__init__(None, [], [])
        self.found_by_step = list(found_by_step)

    def execute(self, sql, params=()):
        if "LIMIT ? OFFSET ?" in sql and "strpos(" not in sql and self.found_by_step:
            self.calls.append((sql, list(params)))
            return Result(self.found_by_step.pop(0))
        return super().execute(sql, params)


def test_all_history_search_stops_at_the_first_full_step(monkeypatch):
    _pg_config(monkeypatch)
    conn = StepConn([_rows(1), _rows(3)])                     # 24 h: 1 match, 7 days: full page
    rows = _run(monkeypatch, conn, [("f_act", "deny"), ("scope", "all")])
    assert len(rows) == 3 and len(conn.calls) == 2
    assert all("l.event_time >= ?::timestamptz" in sql for sql, _ in conn.calls)


def test_all_history_search_ends_unbounded(monkeypatch):
    _pg_config(monkeypatch)
    steps = len(dashboard.HISTORY_STEP_HOURS)
    conn = StepConn([[]] * steps + [_rows(2)])
    rows = _run(monkeypatch, conn, [("f_act", "deny"), ("scope", "all")])
    assert len(rows) == 2 and len(conn.calls) == steps + 1
    assert "l.event_time >= ?::timestamptz" not in conn.calls[-1][0]


def test_steps_skip_bounded_sorted_and_id_searches(monkeypatch):
    _pg_config(monkeypatch)
    for args in ([("f_act", "deny"), ("from", "2026-11-01T00:00:00Z")],
                 [("f_act", "deny"), ("sort", "source_ip")],
                 [("f_act", "deny"), ("ids", "1,2")]):
        assert dashboard._history_steps(MultiDict(args), not any(k == "sort" for k, _ in args)) == []
