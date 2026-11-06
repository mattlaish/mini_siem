"""PostgreSQL search slice: upgrade-safe views and a hashable alias lookup.

Both were found by running owner initialization over a database created by
the previous release and by benchmarking on PostgreSQL 16; these checks run
without a PostgreSQL server."""
import dashboard
from event_storage_v2 import postgres_schema_statements


def test_context_view_is_rebuilt_not_replaced():
    # security_event_context selects e.*; a new security_events column lands
    # mid-list, which CREATE OR REPLACE VIEW rejects on an existing install.
    stmts = [s.strip() for s in postgres_schema_statements()]
    drop = stmts.index("DROP VIEW IF EXISTS security_event_context")
    create = next(i for i, s in enumerate(stmts) if s.startswith("CREATE OR REPLACE VIEW security_event_context"))
    base = next(i for i, s in enumerate(stmts) if s.startswith("CREATE OR REPLACE VIEW security_event_logs"))
    assert base < drop < create


def test_alias_lookup_uses_window_bounds_not_per_event_time():
    sql, params = dashboard._alias_match_clause(
        "host", "prefix", "host-12", ["computer", "device"], backend="postgres_v2",
        bounds=("2026-11-01T00:00:00+00:00", "2026-11-02T00:00:00+00:00"))
    assert "l.event_time" not in sql                        # correlation would force one lookup per event
    assert "hf.event_time >= ?::timestamptz AND hf.event_time <= ?::timestamptz" in sql
    assert "hf.event_time='-infinity'::timestamptz" in sql  # undated legacy rows still match
    assert params[:2] == ["2026-11-01T00:00:00+00:00", "2026-11-02T00:00:00+00:00"]
    unbounded, _ = dashboard._alias_match_clause("host", "prefix", "x", ["device"], backend="postgres_v2")
    assert "event_time" not in unbounded                    # no window: no time predicate at all
