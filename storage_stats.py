"""Read-side log counters and owner-only PostgreSQL source summary setup."""


def log_total(conn):
    """Return (count or None, approximate, has evidence). Never count PG logs."""
    if conn.backend != "postgres":
        count = conn.execute("SELECT COUNT(*) AS n FROM logs").fetchone()["n"]
        return count, False, bool(count)
    row = conn.execute(
        """SELECT reltuples::bigint AS n,
                  (SELECT MAX(id) FROM public.logs) IS NOT NULL AS present
             FROM pg_catalog.pg_class WHERE oid='public.logs'::regclass"""
    ).fetchone()
    present = bool(row["present"])
    return (max(0, row["n"]) or None) if present else 0, True, present


def silent_sources(conn, baseline_start, silence_cutoff):
    if conn.backend == "postgres":
        rows = conn.execute(
            """SELECT source_ip, COUNT(*) OVER () AS total
                 FROM public.log_source_last_seen
                WHERE last_seen >= ?::timestamptz AND last_seen < ?::timestamptz
                ORDER BY last_seen, source_ip LIMIT 10""",
            (baseline_start, silence_cutoff)).fetchall()
        return (int(rows[0]["total"]) if rows else 0), [r["source_ip"] for r in rows]
    rows = conn.execute(
        """SELECT DISTINCT source_ip FROM logs
           WHERE received_at >= ? AND received_at < ?
             AND source_ip IS NOT NULL AND source_ip != ''
             AND source_ip NOT IN (
                 SELECT DISTINCT source_ip FROM logs WHERE received_at >= ?)
           LIMIT 50""",
        (baseline_start, silence_cutoff, silence_cutoff)).fetchall()
    return len(rows), [r["source_ip"] for r in rows[:10]]


def postgres_schema_statements():
    """Idempotent statements; run only as owner, on fresh install or upgrade."""
    return [
        """CREATE TABLE IF NOT EXISTS public.log_source_last_seen (
               source_ip TEXT PRIMARY KEY,
               last_seen TIMESTAMPTZ NOT NULL
           )""",
        """CREATE INDEX IF NOT EXISTS idx_log_source_last_seen_at
               ON public.log_source_last_seen(last_seen, source_ip)""",
        # Ignore malformed receive timestamps, not database failures.
        """CREATE OR REPLACE FUNCTION public.minisiem_summary_timestamp(value TEXT)
           RETURNS TIMESTAMPTZ LANGUAGE plpgsql STABLE SET timezone='UTC' AS $fn$
           BEGIN
               RETURN value::timestamptz;
           EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow THEN
               RETURN NULL;
           END;
           $fn$""",
        """CREATE OR REPLACE FUNCTION public.minisiem_track_log_sources()
           RETURNS trigger LANGUAGE plpgsql
           SET search_path=pg_catalog, public
           SET timezone='UTC' AS $fn$
           BEGIN
               INSERT INTO public.log_source_last_seen(source_ip,last_seen)
               SELECT n.source_ip,n.last_seen
               FROM (
                   SELECT source_ip, date_trunc('minute',
                       MAX(public.minisiem_summary_timestamp(received_at))) AS last_seen
                   FROM inserted_logs WHERE source_ip IS NOT NULL AND source_ip <> ''
                   GROUP BY source_ip
               ) n
               WHERE isfinite(n.last_seen) AND NOT EXISTS (
                   SELECT 1 FROM public.log_source_last_seen s
                   WHERE s.source_ip=n.source_ip AND s.last_seen>=n.last_seen
               )
               ORDER BY n.source_ip
               ON CONFLICT (source_ip) DO UPDATE SET last_seen=excluded.last_seen
               WHERE log_source_last_seen.last_seen<excluded.last_seen;
               RETURN NULL;
           END;
           $fn$""",
        """DO $ddl$ BEGIN
               IF NOT EXISTS (SELECT 1 FROM pg_trigger
                   WHERE tgrelid='public.logs'::regclass
                     AND tgname='minisiem_track_log_sources' AND NOT tgisinternal) THEN
                   CREATE TRIGGER minisiem_track_log_sources AFTER INSERT ON public.logs
                       REFERENCING NEW TABLE AS inserted_logs FOR EACH STATEMENT
                       EXECUTE FUNCTION public.minisiem_track_log_sources();
                   INSERT INTO public.log_source_last_seen(source_ip,last_seen)
                   SELECT source_ip, date_trunc('minute', MAX(seen), 'UTC')
                   FROM (
                       SELECT source_ip,public.minisiem_summary_timestamp(received_at) AS seen
                       FROM public.logs
                       WHERE received_at >= to_char((now()-interval '15 days') AT TIME ZONE 'UTC',
                                                    'YYYY-MM-DD')
                         AND source_ip IS NOT NULL AND source_ip <> ''
                   ) s
                   WHERE isfinite(seen) AND seen >= now()-interval '14 days'
                   GROUP BY source_ip ORDER BY source_ip
                   ON CONFLICT (source_ip) DO UPDATE SET last_seen=excluded.last_seen
                   WHERE log_source_last_seen.last_seen<excluded.last_seen;
               END IF;
           END; $ddl$""",
    ]
