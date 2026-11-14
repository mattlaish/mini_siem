#!/usr/bin/env python3
"""Measure Log Search on a running PostgreSQL deployment, read-only.

Step 0 of POSTGRES_SEARCH.md: what the real database holds and how the
searches people run actually execute, before changing the layout.

    python -B tools/postgres_search_measure.py --db-config db-config.json \\
        --db-credentials dashboard-credentials.json --out measure.json

Safety
* Every connection this process opens is read-only at the server
  (default_transaction_read_only via PGOPTIONS), with a per-statement time
  limit and a short lock wait. Nothing is created, changed or vacuumed.
* Searches run through the same code the dashboard uses (Flask test client
  in this process), so the SQL matches what the web console sends. Run it
  from the deployed source tree so it measures the deployed version.
* EXPLAIN ANALYZE executes each search once more; keep --repeats small on a
  busy server. Use a quiet hour for the --all-history searches.

Output: a summary on screen (no event values; safe to share) and a JSON
file with full plans. The JSON contains sample values taken from your logs
(addresses, host names, field values): review it before sharing.

Add the searches your team really runs by pasting their Log Search URLs:
    --search "https://siem.example/?f=act%3Ddeny&dst_port=53"
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
from statistics import median
import sys
from time import perf_counter
from urllib.parse import parse_qsl, urlsplit
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _read_only_env(timeout_ms):
    # libpq applies PGOPTIONS to every connection this process opens,
    # including the dashboard code's own connections.
    os.environ["PGOPTIONS"] = (f"-c default_transaction_read_only=on -c statement_timeout={int(timeout_ms)} "
                               "-c lock_timeout=2000 -c application_name=minisiem-measure")


def _rows(conn, sql, params=()):
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def _one(conn, sql, params=()):
    row = conn.execute(sql, params).fetchone()
    return dict(row) if row else {}


def _safe(conn, label, fn, notes):
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - report and continue
        conn.rollback()
        notes.append(f"{label}: {type(exc).__name__}: {str(exc).splitlines()[0][:160]}")
        return None


# ---------------------------------------------------------------- inventory

def inventory(conn, end, notes):
    out = {}
    out["server"] = _safe(conn, "server", lambda: {
        "version": _one(conn, "SELECT version() AS v")["v"],
        "read_only": _one(conn, "SELECT current_setting('transaction_read_only') AS v")["v"],
        **{r["name"]: r["setting"] + (r["unit"] or "") for r in _rows(conn, """
            SELECT name, setting, unit FROM pg_settings WHERE name IN
              ('shared_buffers','effective_cache_size','work_mem','random_page_cost','max_parallel_workers_per_gather',
               'jit','max_connections','checkpoint_timeout','max_wal_size')""")}}, notes)
    out["layout"] = _safe(conn, "layout", lambda: {
        "log_fields_partitioned": _one(conn, "SELECT relkind='p' AS p FROM pg_class WHERE oid='public.log_fields'::regclass")["p"],
        "security_events_partitions": _one(conn, """SELECT count(*) AS n FROM pg_inherits
                                                     WHERE inhparent='public.security_events'::regclass""")["n"],
        "partition_grain": _one(conn, """SELECT CASE WHEN bool_or(c.relname ~ '_day_') THEN 'day'
                                                     WHEN bool_or(c.relname ~ '_week_') THEN 'week' ELSE 'month' END AS g
                                           FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid
                                          WHERE i.inhparent='public.security_events'::regclass""")["g"],
        "search_columns_present": bool(_one(conn, """SELECT count(*) AS n FROM information_schema.columns
            WHERE table_name='security_events' AND column_name='search_fields'""")["n"]),
        "migrations_applied": _one(conn, "SELECT max(version) AS v FROM schema_migrations")["v"],
        "default_partition_rows_estimate": {r["relname"]: int(r["reltuples"]) for r in _rows(conn, """
            SELECT relname, greatest(reltuples, 0) AS reltuples FROM pg_class
             WHERE relname IN ('security_events_default','log_fields_default')""")},
    }, notes)
    out["sizes"] = _safe(conn, "sizes", lambda: _rows(conn, """
        WITH t AS (
          SELECT coalesce(p.relname, c.relname) AS table_name, c.oid
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            LEFT JOIN pg_inherits i ON i.inhrelid=c.oid LEFT JOIN pg_class p ON p.oid=i.inhparent
           WHERE n.nspname='public' AND c.relkind IN ('r','m'))
        SELECT table_name, count(*) AS partitions, sum(greatest(c.reltuples,0))::bigint AS rows_estimate,
               sum(pg_table_size(t.oid)) AS table_bytes, sum(pg_indexes_size(t.oid)) AS index_bytes
          FROM t JOIN pg_class c ON c.oid=t.oid GROUP BY table_name
        HAVING sum(pg_total_relation_size(t.oid)) >= 1048576
         ORDER BY sum(pg_total_relation_size(t.oid)) DESC LIMIT 15"""), notes)
    out["unused_indexes"] = _safe(conn, "unused indexes", lambda: _rows(conn, """
        SELECT coalesce(pi.relname, s.relname) AS table_name,
               regexp_replace(s.indexrelname, '_(day_|week_){0,1}[0-9][0-9_]*_', '_*_') AS index_pattern,
               count(*) AS copies, sum(pg_relation_size(s.indexrelid)) AS bytes
          FROM pg_stat_user_indexes s JOIN pg_index x ON x.indexrelid=s.indexrelid
          LEFT JOIN pg_inherits i ON i.inhrelid=s.relid LEFT JOIN pg_class pi ON pi.oid=i.inhparent
         WHERE s.idx_scan=0 AND NOT x.indisunique AND NOT x.indisprimary GROUP BY 1,2 HAVING sum(pg_relation_size(s.indexrelid)) > 1048576
         ORDER BY bytes DESC LIMIT 15"""), notes)
    since14 = (end - timedelta(days=14)).isoformat()
    out["rows_per_day"] = _safe(conn, "rows per day", lambda: _rows(conn, """
        SELECT to_char(date_trunc('day', ingested_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD') AS day, count(*) AS events
          FROM security_events WHERE event_time >= ?::timestamptz - interval '2 days' AND ingested_at >= ?::timestamptz
           AND ingested_at < ?::timestamptz GROUP BY 1 ORDER BY 1""", (since14, since14, end.isoformat())), notes)
    since1 = (end - timedelta(days=1)).isoformat()
    out["peak_last_24h"] = _safe(conn, "peak rate", lambda: _one(conn, """
        SELECT max(n) AS peak_events_per_minute, round(max(n)/60.0, 1) AS peak_events_per_second,
               round(avg(n)/60.0, 1) AS average_events_per_second
          FROM (SELECT date_trunc('minute', ingested_at) AS m, count(*) AS n FROM security_events
                 WHERE event_time >= ?::timestamptz - interval '2 days' AND ingested_at >= ?::timestamptz
                   AND ingested_at < ?::timestamptz GROUP BY 1) per_minute""",
        (since1, since1, end.isoformat())), notes)
    out["fields_per_log"] = _safe(conn, "fields per log", lambda: _one(conn, """
        SELECT round((sum(CASE WHEN starts_with(c.relname, 'log_fields') AND c.relkind='r'
                                THEN greatest(c.reltuples,0) END)
                      / nullif(sum(CASE WHEN c.relname='logs' THEN greatest(c.reltuples,0) END), 0))::numeric, 1) AS ratio
          FROM pg_class c WHERE c.relname='logs' OR starts_with(c.relname, 'log_fields')""")["ratio"], notes)
    return out


# ---------------------------------------------------------------- representative searches

def _window_ids(conn, start, end):
    row = _one(conn, """SELECT min(legacy_log_id) AS lo, max(legacy_log_id) AS hi, count(*) AS n
                          FROM security_events WHERE event_time >= ?::timestamptz AND event_time <= ?::timestamptz""",
               (start.isoformat(), end.isoformat()))
    return row.get("lo"), row.get("hi"), row.get("n") or 0


def pick_searches(conn, start, end, has_search_columns, notes):
    """Searches built from values that actually occur in the window."""
    lo, hi, n = _window_ids(conn, start, end)
    picks = {"window_events": n}
    if not n:
        notes.append("No events in the measured window; use --end to pick a busier day.")
        return picks, {}
    lo = max(lo, hi - 50000)             # sample at most the newest 50k events of the window
    pairs = _safe(conn, "field sample", lambda: _rows(conn, """
        SELECT field, value_norm, count(DISTINCT log_id) AS logs FROM log_fields
         WHERE log_id BETWEEN ? AND ? AND value_norm IS NOT NULL AND length(value_norm) BETWEEN 1 AND 80
         GROUP BY 1,2 ORDER BY 3 DESC LIMIT 400""", (lo, hi)), notes) or []
    sampled = max(1, hi - lo + 1)
    searches = {"recent (no filter)": {}}
    mid = [p for p in pairs if 0.01 <= p["logs"] / sampled <= 0.5]
    if mid:
        top = mid[0]
        searches["exact one field"] = {"f_" + top["field"]: top["value_norm"]}
        searches["exact one field, all history"] = {"f_" + top["field"]: top["value_norm"], "scope": "all"}
        searches["sort by extracted field"] = {"fields": top["field"], "sort": "x_" + top["field"]}
    row = _safe(conn, "multi-field sample", lambda: _one(conn, """
        SELECT log_id FROM log_fields WHERE log_id BETWEEN ? AND ? GROUP BY log_id HAVING count(*) >= 3
         ORDER BY log_id DESC LIMIT 1""", (lo, hi)), notes) or {}
    if row.get("log_id"):
        common = {(p["field"], p["value_norm"]): p["logs"] for p in pairs}
        mine = _rows(conn, "SELECT field, value_norm FROM log_fields WHERE log_id=? AND value_norm IS NOT NULL",
                     (row["log_id"],))
        mine.sort(key=lambda r: -common.get((r["field"], r["value_norm"]), 0))
        chosen = [r for r in mine if 0 < len(r["value_norm"]) <= 80][:3]
        if len(chosen) == 3:
            searches["three exact fields"] = {"f_" + r["field"]: r["value_norm"] for r in chosen}
    distinctish = {}
    for p in pairs:
        distinctish.setdefault(p["field"], set()).add(p["value_norm"])
    wide = sorted(distinctish, key=lambda f: -len(distinctish[f]))
    if wide and len(distinctish[wide[0]]) > 5:
        value = sorted(distinctish[wide[0]])[0]
        prefix = value[:max(2, min(4, len(value) - 1))]
        searches["field starts with"] = {"f_" + wide[0]: prefix + "*"}
        searches["field starts with, all history"] = {"f_" + wide[0]: prefix + "*", "scope": "all"}
    for field in ("query", "url"):
        values = sorted(distinctish.get(field, ()), key=len, reverse=True)
        if values and len(values[0]) >= 6:
            v = values[0]
            searches[f"{field} contains (common substring)"] = {"f_" + field: f"*{v[len(v)//3: len(v)//3 + 4]}*"}
            break
    others = [p for p in mid if p["field"] != (mid[0]["field"] if mid else None)]
    if mid and others:
        a, b = mid[0], others[0]
        search = {"f_" + a["field"]: a["value_norm"], "f_" + b["field"]: b["value_norm"], "fc_op": "or"}
        if wide and wide[0] not in (a["field"], b["field"]):
            search["f_" + wide[0]] = "!" + sorted(distinctish[wide[0]])[0][:3] + "*"
            searches["two fields OR, one excluded"] = search
        else:
            searches["two fields OR"] = search
    src = _safe(conn, "top source", lambda: _one(conn, """
        SELECT network(set_masklen(src_ip, 24))::text AS net FROM security_events
         WHERE event_time >= ?::timestamptz AND event_time <= ?::timestamptz AND family(src_ip)=4
         GROUP BY 1 ORDER BY count(*) DESC LIMIT 1""", (start.isoformat(), end.isoformat())), notes) or {}
    if src.get("net"):
        searches["source CIDR /24"] = {"source_ip": src["net"]}
    host = _safe(conn, "top host", lambda: _one(conn, """
        SELECT hostname FROM security_events WHERE event_time >= ?::timestamptz AND event_time <= ?::timestamptz
           AND hostname IS NOT NULL AND length(hostname) >= 3 GROUP BY 1 ORDER BY count(*) DESC LIMIT 1""",
                                                  (start.isoformat(), end.isoformat())), notes) or {}
    if host.get("hostname"):
        searches["host starts with"] = {"hostname": host["hostname"][:max(2, len(host["hostname"]) - 2)]}
    if has_search_columns:
        port = _safe(conn, "top port", lambda: _one(conn, """
            SELECT dst_port FROM security_events WHERE event_time >= ?::timestamptz AND event_time <= ?::timestamptz
               AND dst_port IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC LIMIT 1""",
                                                    (start.isoformat(), end.isoformat())), notes) or {}
        if port.get("dst_port") is not None:
            searches["destination port"] = {"dst_port": str(port["dst_port"])}
    msg = _safe(conn, "message word", lambda: _one(conn, """
        SELECT w FROM (SELECT regexp_split_to_table(lower(message), '[^a-z]+') AS w FROM security_events
                        WHERE event_time >= ?::timestamptz AND event_time <= ?::timestamptz LIMIT 2000) t
         WHERE length(w) >= 6 GROUP BY w ORDER BY count(*) LIMIT 1""", (start.isoformat(), end.isoformat())), notes) or {}
    if msg.get("w"):
        searches["message word (rare)"] = {"q": msg["w"]}
    return picks, searches


# Log Search page URL names -> /api/logs names (templates/index.html _syncUrl
# and currentFilterParams). Field chips are f=field=value in the page URL.
_PAGE_TO_API = {"src": "source_ip", "host": "hostname", "dest": "destination", "sev": "severity", "op": "fc_op"}


def page_url_to_api(raw):
    """A pasted Log Search page URL (or API query string) as API filters."""
    query = urlsplit(raw).query if "?" in raw or "://" in raw else raw
    out = {}
    for key, value in parse_qsl(query, keep_blank_values=True):
        if key in ("page", "limit", "offset", "snapshot"):
            continue
        if not value and not key.startswith(("feq_", "fne_")):
            continue
        if key == "f" and "=" in value:
            field, _, needle = value.partition("=")
            out["f_" + field.strip().lower()] = needle
            continue
        if key in ("from", "to") and len(value) == 16:          # page datetime-local, no zone
            value += ":00+00:00"
        out[_PAGE_TO_API.get(key, key)] = value
    return out


def _plan_summary(plan):
    root = plan["Plan"]
    relations, seq_scans = set(), []

    def visit(node):
        if node.get("Actual Loops", 0) and node.get("Relation Name"):
            relations.add(node["Relation Name"])
            if node["Node Type"] == "Seq Scan" and node.get("Actual Rows", 0) * node.get("Actual Loops", 1) > 1000:
                seq_scans.append(node["Relation Name"])
        for child in node.get("Plans", []):
            visit(child)
    visit(root)
    return {"execution_ms": round(plan["Execution Time"], 2), "planning_ms": round(plan["Planning Time"], 2),
            "blocks_hit": root.get("Shared Hit Blocks", 0), "blocks_read": root.get("Shared Read Blocks", 0),
            "partitions_touched": len(relations), "relations": sorted(relations), "large_seq_scans": seq_scans}


def run_searches(client, conn, searches, start, end, repeats, notes):
    from db import Connection
    original = Connection.execute
    results = {}
    for name, filters in searches.items():
        query = {"page": "1", "limit": "100", **filters}
        if filters.get("scope") != "all":
            query.setdefault("from", start.isoformat())
            query.setdefault("to", end.isoformat())
        calls, timings = [], []

        def track(self, sql, params=()):
            if sql.lstrip().upper().startswith("SELECT"):
                calls.append((sql, list(params)))
            return original(self, sql, params)
        status = None
        try:
            with patch.object(Connection, "execute", track):
                for _ in range(repeats):
                    calls.clear()
                    t0 = perf_counter()
                    resp = client.get("/api/logs", query_string=[(k, v) for k, vs in query.items()
                                                                 for v in (vs if isinstance(vs, list) else [vs])])
                    timings.append(1000 * (perf_counter() - t0))
                    status = resp.status_code
                    if status != 200:
                        break
        except Exception as exc:  # noqa: BLE001
            notes.append(f"search '{name}': {type(exc).__name__}: {str(exc).splitlines()[0][:160]}")
            conn.rollback()
            continue
        if status != 200:
            results[name] = {"status": status, "error": (resp.get_json(silent=True) or {}).get("error")}
            continue
        body = resp.get_json()
        items = body.get("items", body) if isinstance(body, dict) else body
        plans = []
        for sql, params in calls:
            try:
                row = conn.execute("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + sql, params).fetchone()
                plan = next(iter(dict(row).values()))[0]
                plans.append({"sql": sql, "params": params, **_plan_summary(plan), "plan": plan})
            except Exception as exc:  # noqa: BLE001
                conn.rollback()
                plans.append({"sql": sql, "error": f"{type(exc).__name__}: {str(exc).splitlines()[0][:160]}"})
        ordered = sorted(timings)
        results[name] = {"filters": filters, "rows": len(items), "first_ms": round(timings[0], 1),
                         "p50_ms": round(median(ordered), 1),
                         "max_ms": round(ordered[-1], 1), "statements": plans}
    return results


# ---------------------------------------------------------------- report

def _mb(n):
    return f"{(n or 0) / 2**20:,.0f} MB"


def summary(result):
    lines = []
    inv, lay = result["inventory"], result["inventory"].get("layout") or {}
    srv = inv.get("server") or {}
    lines.append(f"PostgreSQL     {str(srv.get('version', '?')).split(' on ')[0]} · read-only session: {srv.get('read_only')}")
    lines.append(f"Settings       shared_buffers {srv.get('shared_buffers')} · effective_cache_size {srv.get('effective_cache_size')}"
                 f" · work_mem {srv.get('work_mem')} · random_page_cost {srv.get('random_page_cost')}")
    lines.append(f"Layout         field table split by time: {lay.get('log_fields_partitioned')} · event partitions "
                 f"{lay.get('security_events_partitions')} ({lay.get('partition_grain')}) · search columns present: "
                 f"{lay.get('search_columns_present')} · migrations {lay.get('migrations_applied')}")
    default = lay.get("default_partition_rows_estimate") or {}
    if default:
        lines.append("DEFAULT parts  " + ", ".join(f"{k} ≈{v:,} rows" for k, v in default.items()))
    days = inv.get("rows_per_day") or []
    if days:
        counts = [d["events"] for d in days]
        lines.append(f"Volume         {len(days)} days: median {int(median(counts)):,}/day, max {max(counts):,}/day")
    peak = inv.get("peak_last_24h") or {}
    if peak:
        lines.append(f"Arrival rate   last 24 h: average {peak.get('average_events_per_second')}/s, "
                     f"peak minute {peak.get('peak_events_per_second')}/s")
    lines.append(f"Fields per log ≈{inv.get('fields_per_log')}")
    lines.append("Largest tables")
    for t in inv.get("sizes") or []:
        lines.append(f"  {t['table_name']:<34} {t['partitions']:>4} part  ≈{t['rows_estimate']:>14,} rows  "
                     f"table {_mb(t['table_bytes']):>10}  indexes {_mb(t['index_bytes']):>10}")
    if inv.get("unused_indexes"):
        lines.append("Indexes never used since statistics reset (write cost, no read benefit)")
        for u in inv["unused_indexes"]:
            lines.append(f"  {u['table_name']:<20} {u['index_pattern']:<48} x{u['copies']:<4} {_mb(u['bytes'])}")
    lines.append(f"\nSearches over {result['window']['from']} → {result['window']['to']} "
                 f"({result['picks'].get('window_events', 0):,} events in window)")
    lines.append(f"  {'search':<36} {'p50':>8} {'first':>8} {'rows':>5} {'SQL ms':>8} {'blocks':>9} {'from disk':>9} {'parts':>5}")
    for name, r in result["searches"].items():
        if "statements" not in r:
            lines.append(f"  {name:<36} HTTP {r.get('status')}: {r.get('error')}")
            continue
        st = [s for s in r["statements"] if "error" not in s]
        sql_ms = sum(s["execution_ms"] for s in st)
        hit = sum(s["blocks_hit"] for s in st)
        read = sum(s["blocks_read"] for s in st)
        parts = max((s["partitions_touched"] for s in st), default=0)
        flag = "  ← sequential scan: " + ",".join(sorted({x for s in st for x in s["large_seq_scans"]})) \
            if any(s["large_seq_scans"] for s in st) else ""
        lines.append(f"  {name:<36} {r['p50_ms']:>6.1f}ms {r['first_ms']:>6.1f}ms {r['rows']:>5} {sql_ms:>8.1f} "
                     f"{hit + read:>9,} {read:>9,} {parts:>5}{flag}")
    if result["notes"]:
        lines.append("\nNotes")
        lines += [f"  - {n}" for n in result["notes"]]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db-config", help="db-config.json of the deployment")
    ap.add_argument("--db-credentials", help="component credential file (user/password), e.g. the dashboard's")
    ap.add_argument("--host"); ap.add_argument("--port", type=int); ap.add_argument("--dbname"); ap.add_argument("--user")
    ap.add_argument("--end", help="end of the measured 24 h window (ISO time, default now)")
    ap.add_argument("--hours", type=int, default=24, help="window length (default 24)")
    ap.add_argument("--repeats", type=int, default=3, help="timed runs per search (default 3)")
    ap.add_argument("--timeout-seconds", type=int, choices=range(1, 61), default=60,
                    metavar="1–60", help="per-statement limit (default 60)")
    ap.add_argument("--search", action="append", default=[], help="a Log Search URL or query string to measure too")
    ap.add_argument("--skip-all-history", action="store_true", help="leave out the all-history searches")
    ap.add_argument("--out", type=Path, required=True, help="JSON output (must not exist)")
    args = ap.parse_args(argv)
    if not 1 <= args.repeats <= 20 or not 1 <= args.hours <= 24 * 31:
        ap.error("--repeats must be 1-20 and --hours 1-744")

    _read_only_env(args.timeout_seconds * 1000)
    import db
    if args.db_config:
        cfg = db.load_config(args.db_config, credentials_path=args.db_credentials)
    else:
        if not args.dbname:
            ap.error("give --db-config, or --host/--port/--dbname/--user (password from PGPASSWORD)")
        cfg = {"backend": "postgres", "postgres": {"host": args.host or "127.0.0.1", "port": args.port or 5432,
               "dbname": args.dbname, "user": args.user or "postgres",
               "password": os.environ.get("PGPASSWORD", ""), "connect_retries": 1}}
    if cfg.get("backend") != "postgres":
        ap.error("this measures PostgreSQL deployments; the configuration selects " + str(cfg.get("backend")))
    end = datetime.fromisoformat(args.end).astimezone(timezone.utc) if args.end else datetime.now(timezone.utc)
    start = end - timedelta(hours=args.hours)

    import dashboard                    # its own connections inherit the read-only PGOPTIONS
    cfg["postgres"]["dashboard_statement_timeout_ms"] = args.timeout_seconds * 1000
    dashboard.DB_CONFIG = cfg
    client = dashboard.app.test_client()
    conn = db.connect(cfg)
    notes = []
    try:
        conn.execute("SET TIME ZONE 'UTC'")
        inv = inventory(conn, end, notes)
        has_cols = bool((inv.get("layout") or {}).get("search_columns_present"))
        picks, searches = pick_searches(conn, start, end, has_cols, notes)
        if args.skip_all_history:
            searches = {k: v for k, v in searches.items() if v.get("scope") != "all"}
        for i, raw in enumerate(args.search, 1):
            searches[f"your search {i}"] = page_url_to_api(raw)
        results = run_searches(client, conn, searches, start, end, args.repeats, notes)
    finally:
        conn.close()
    result = {"measured_at": datetime.now(timezone.utc).isoformat(), "source_version": _git_version(),
              "window": {"from": start.isoformat(), "to": end.isoformat()}, "inventory": inv,
              "picks": picks, "searches": results, "notes": notes}
    with args.out.open("x", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    print(summary(result))
    print(f"\nFull plans: {args.out} (contains sample values from your logs; review before sharing)")
    return 0


def _git_version():
    head = ROOT / ".git" / "HEAD"
    try:
        ref = head.read_text().strip()
        if ref.startswith("ref: "):
            return (ROOT / ".git" / ref[5:]).read_text().strip()[:12]
        return ref[:12]
    except OSError:
        return None


if __name__ == "__main__":
    sys.exit(main())
