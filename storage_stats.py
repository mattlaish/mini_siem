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
    """Devices that sent logs in the baseline window but nothing since the cutoff."""
    if conn.backend == "postgres":
        rows = conn.execute(
            """SELECT source_ip, COUNT(*) OVER () AS total
                 FROM public.log_source_last_seen
                WHERE last_seen >= ?::timestamptz AND last_seen < ?::timestamptz
                ORDER BY last_seen, source_ip LIMIT 10""",
            (baseline_start, silence_cutoff)).fetchall()
        return (int(rows[0]["total"]) if rows else 0), [r["source_ip"] for r in rows]
    # Same meaning as the PostgreSQL summary: the sending device, else source_ip.
    rows = conn.execute(
        """SELECT DISTINCT COALESCE(NULLIF(peer_ip,''), source_ip) AS source_ip FROM logs
           WHERE received_at >= ? AND received_at < ?
             AND COALESCE(NULLIF(peer_ip,''), source_ip) IS NOT NULL
             AND COALESCE(NULLIF(peer_ip,''), source_ip) != ''
             AND COALESCE(NULLIF(peer_ip,''), source_ip) NOT IN (
                 SELECT DISTINCT COALESCE(NULLIF(peer_ip,''), source_ip) FROM logs
                 WHERE received_at >= ? AND COALESCE(NULLIF(peer_ip,''), source_ip) IS NOT NULL)
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
        # The summary is keyed by the device that sent the log (peer_ip),
        # falling back to source_ip for API/HTTP sources without a network
        # peer. source_ip alone is often the client or attacker address taken
        # from the message, which made "silent sources" list attackers that
        # stopped and grew the table by every address ever seen.
        """CREATE OR REPLACE FUNCTION public.minisiem_log_sender(peer_ip TEXT, source_ip TEXT)
           RETURNS TEXT LANGUAGE sql IMMUTABLE AS $fn$
               SELECT NULLIF(COALESCE(NULLIF(peer_ip,''), source_ip), '')
           $fn$""",
        # Writers never wait on each other here. An existing sender row that
        # another transaction is already updating is skipped (SKIP LOCKED);
        # the sender's next event records it, and the summary is per minute
        # for a multi-day silence check. A first sighting is inserted only by
        # the transaction holding that sender's advisory lock. Waiting on row
        # locks here let two batched writers deadlock and lose a whole batch.
        """CREATE OR REPLACE FUNCTION public.minisiem_track_log_sources()
           RETURNS trigger LANGUAGE plpgsql
           SET search_path=pg_catalog, public
           SET timezone='UTC' AS $fn$
           BEGIN
               WITH seen AS (
                   SELECT public.minisiem_log_sender(peer_ip, source_ip) AS sender,
                          date_trunc('minute', MAX(public.minisiem_summary_timestamp(received_at))) AS last_seen
                   FROM inserted_logs
                   GROUP BY 1
               ), due AS (
                   SELECT s.source_ip, seen.last_seen
                   FROM public.log_source_last_seen s
                   JOIN seen ON seen.sender = s.source_ip
                   WHERE isfinite(seen.last_seen) AND s.last_seen < seen.last_seen
                   ORDER BY s.source_ip
                   FOR UPDATE OF s SKIP LOCKED
               )
               UPDATE public.log_source_last_seen s SET last_seen = due.last_seen
               FROM due WHERE s.source_ip = due.source_ip;

               INSERT INTO public.log_source_last_seen(source_ip,last_seen)
               SELECT n.sender, n.last_seen
               FROM (
                   SELECT public.minisiem_log_sender(peer_ip, source_ip) AS sender,
                          date_trunc('minute', MAX(public.minisiem_summary_timestamp(received_at))) AS last_seen
                   FROM inserted_logs
                   GROUP BY 1
               ) n
               WHERE n.sender IS NOT NULL AND isfinite(n.last_seen)
                 AND NOT EXISTS (SELECT 1 FROM public.log_source_last_seen s WHERE s.source_ip = n.sender)
                 AND pg_try_advisory_xact_lock(hashtextextended('minisiem.log_source:' || n.sender, 0))
               ORDER BY n.sender
               ON CONFLICT (source_ip) DO NOTHING;
               RETURN NULL;
           END;
           $fn$""",
        # Daily maintenance removes senders older than the silence baseline.
        # Runtime roles cannot delete from the summary; the maintenance role
        # may only call this bounded function.
        """CREATE OR REPLACE FUNCTION public.minisiem_prune_log_sources(p_days INTEGER DEFAULT 15)
           RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER
           SET search_path = pg_catalog, public
           SET timezone = 'UTC' AS $fn$
           DECLARE
               removed INTEGER;
           BEGIN
               IF p_days < 15 OR p_days > 3650 THEN
                   RAISE EXCEPTION 'p_days must be between 15 and 3650';
               END IF;
               DELETE FROM public.log_source_last_seen
                WHERE last_seen < now() - make_interval(days => p_days);
               GET DIAGNOSTICS removed = ROW_COUNT;
               RETURN removed;
           END;
           $fn$""",
        "REVOKE ALL ON FUNCTION public.minisiem_prune_log_sources(INTEGER) FROM PUBLIC",
        """DO $ddl$ BEGIN
               IF NOT EXISTS (SELECT 1 FROM pg_trigger
                   WHERE tgrelid='public.logs'::regclass
                     AND tgname='minisiem_track_log_sources' AND NOT tgisinternal) THEN
                   CREATE TRIGGER minisiem_track_log_sources AFTER INSERT ON public.logs
                       REFERENCING NEW TABLE AS inserted_logs FOR EACH STATEMENT
                       EXECUTE FUNCTION public.minisiem_track_log_sources();
               END IF;
               -- Fill (or re-key a summary built by source_ip) from the last
               -- 14 days. Owner upgrade runs with services stopped.
               IF COALESCE(obj_description('public.log_source_last_seen'::regclass, 'pg_class'), '')
                      <> 'minisiem: keyed by sending device' THEN
                   DELETE FROM public.log_source_last_seen;
                   INSERT INTO public.log_source_last_seen(source_ip,last_seen)
                   SELECT sender, date_trunc('minute', MAX(seen), 'UTC')
                   FROM (
                       SELECT public.minisiem_log_sender(peer_ip, source_ip) AS sender,
                              public.minisiem_summary_timestamp(received_at) AS seen
                       FROM public.logs
                       WHERE received_at >= to_char((now()-interval '15 days') AT TIME ZONE 'UTC',
                                                    'YYYY-MM-DD')
                   ) s
                   WHERE sender IS NOT NULL AND isfinite(seen) AND seen >= now()-interval '14 days'
                   GROUP BY sender ORDER BY sender
                   ON CONFLICT (source_ip) DO UPDATE SET last_seen=excluded.last_seen
                   WHERE log_source_last_seen.last_seen<excluded.last_seen;
                   COMMENT ON TABLE public.log_source_last_seen IS 'minisiem: keyed by sending device';
               END IF;
           END; $ddl$""",
    ]
