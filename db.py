"""
mini-SIEM database abstraction
==============================
Lets the whole SIEM run on either SQLite (local, zero-setup, the
default) or PostgreSQL (external server, scales past SQLite's
single-writer ceiling) without any other module knowing the
difference.

Every other module writes SQL with '?' placeholders and dict-style row
access (row["col"]); this layer translates placeholders and normalizes
row access per backend, and centralizes the handful of genuine dialect
differences (auto-increment column type, INSERT ... RETURNING id).

Backend is chosen in db-config.json (see load_config), so the decision
is made before anything is installed — no code change to switch. Choose
it with the interactive configure-db.py, or edit db-config.json.

PostgreSQL needs the psycopg2 driver:  pip install psycopg2-binary
(imported lazily, so SQLite users don't need it installed).
"""

import json
import os
import sqlite3
import threading
import time

from sql_helpers import sqlite_integrity_pragma

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "backend": "sqlite",
    # Runtime defaults favor burst tolerance while bounding crash-loss exposure
    # to the max-delay window. Operators can override all four in db-config.json.
    "commit_batch_size": 100,
    "commit_max_delay_ms": 100,
    "ingest_workers": 4,
    "ingest_queue_size": 10000,
    "db_writer_queue_size": 20000,
    "db_writer_batch_size": 100,
    "db_writer_max_delay_ms": 75,
    "forward_queue_size": 10000,
    # Per-event stdout is intentionally off in production: journald/stdout I/O
    # can become an ingest bottleneck. Aggregate counters are emitted instead.
    "ingest_event_logging": False,
    "ingest_stats_interval_seconds": 10,
    # Message-search strategy. Environment variable MINISIEM_TEXT_SEARCH
    # overrides this at runtime. Values: auto, fts, trigram, like.
    "text_search": "auto",
    # Evidence lifecycle is archive-first: no time-based evidence deletion.
    # When enabled, eligible hot rows are copied into immutable archive
    # segments. ``mode=move`` evicts hot copies only after the segment is
    # committed, compacted, checksummed, cataloged, and re-open verified.
    # The archive remains searchable through the normal Log Search API.
    "archive": {
        "enabled": False,
        "directory": "archive",
        "hot_days": 30,
        "mode": "copy",
        "batch_rows": 500,
        "max_batches_per_cycle": 20,
        "run_interval_seconds": 3600,
        "verify_on_create": True,
    },
    # Non-destructive online SQLite housekeeping. This never deletes logs.
    "maintenance": {
        "wal_checkpoint_mb": 256,
        "incremental_vacuum_pages": 2000,
        "quick_check_interval_seconds": 86400,
    },
    "query_telemetry": {
        "max_samples": 512,
        "slow_ms": 250,
    },
    "overload": {
        "queue_warn_percent": 80,
        "queue_overload_percent": 95,
        "commit_p95_warn_ms": 50,
        "query_p95_warn_ms": 250,
        "telemetry_stale_seconds": 30,
    },
    "sqlite": {
        "path": "siem.db",
        # Conservative per-connection tuning. Negative cache_size values are
        # KiB in SQLite; the public config uses positive KiB for readability.
        "busy_timeout_ms": 5000,
        "cache_size_kib": 32768,
        "temp_store_memory": True,
        "mmap_size_mb": 128,
        "wal_autocheckpoint_pages": 1000,
        "optimize_interval_seconds": 3600,
        # Safe for fresh databases. Existing databases remain unchanged unless
        # operators explicitly rebuild them; Phase 5 never runs a full VACUUM.
        "auto_vacuum_incremental": True,
    },
    "postgres": {
        "host": "localhost",
        "port": 5432,
        "dbname": "minisiem",
        "user": "minisiem",
        "password": "",
        "pool_min": 1,
        "pool_max": 10,
        "connect_timeout_seconds": 5,
        "statement_timeout_ms": 15000,
        "lock_timeout_ms": 3000,
        "idle_in_transaction_session_timeout_ms": 30000,
        "application_name": "mini-siem",
    },
}


def config_from_path(sqlite_path: str) -> dict:
    """Build a sqlite config dict from a bare path (back-compat with the
    old --db flag)."""
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    cfg["backend"] = "sqlite"
    cfg["sqlite"]["path"] = sqlite_path or "siem.db"
    return cfg


def load_config(config_path: str = None, sqlite_fallback: str = "siem.db") -> dict:
    """Resolve DB config in priority order:
       1. explicit config_path (JSON) if given and present
       2. db-config.json next to the scripts, if present
       3. default sqlite at sqlite_fallback
    """
    candidates = []
    if config_path:
        candidates.append(config_path)
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(here, "db-config.json"))

    for path in candidates:
        if path and os.path.exists(path):
            with open(path) as f:
                user_cfg = json.load(f)
            merged = json.loads(json.dumps(DEFAULT_CONFIG))
            for k, v in user_cfg.items():
                if k in ("sqlite", "postgres", "archive", "maintenance", "query_telemetry", "overload") and isinstance(v, dict):
                    merged[k].update(v)
                else:
                    merged[k] = v
            return merged

    return config_from_path(sqlite_fallback)


def describe(config: dict) -> str:
    if config.get("backend") == "postgres":
        p = config["postgres"]
        return f"postgres://{p['user']}@{p['host']}:{p['port']}/{p['dbname']}"
    return f"sqlite://{config['sqlite']['path']}"


# --------------------------------------------------------------------------
# Connection wrapper — one interface over sqlite3 and psycopg2
# --------------------------------------------------------------------------

class Connection:
    """Normalizes both drivers to: execute(sql, params) -> cursor with
    fetchone()/fetchall() returning dict-like rows; commit(); close();
    and insert_returning_id() for auto-increment inserts.

    All callers use '?' placeholders; for postgres they're translated to
    '%s'. Rows are dict-like on both backends (sqlite3.Row / psycopg2
    RealDictRow), so row["col"] and dict(row) work everywhere."""

    def __init__(self, raw, backend: str, release=None):
        self.raw = raw
        self.backend = backend
        self._release = release
        self._closed = False

    def _sql(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.backend == "postgres" else sql

    def execute(self, sql: str, params=()):
        sql = self._sql(sql)
        if self.backend == "postgres":
            cur = self.raw.cursor()
            cur.execute(sql, params)
            return cur
        return self.raw.execute(sql, params)

    def executemany(self, sql: str, seq_of_params):
        """Execute one statement for many parameter rows on either backend."""
        sql = self._sql(sql)
        if self.backend == "postgres":
            cur = self.raw.cursor()
            cur.executemany(sql, seq_of_params)
            return cur
        return self.raw.executemany(sql, seq_of_params)

    def insert_returning_id(self, sql: str, params=()):
        """Run an INSERT and return the new row's integer id."""
        if self.backend == "postgres":
            cur = self.raw.cursor()
            returning_sql = self._sql(sql) + " RETURNING id"
            cur.execute(returning_sql, params)
            row = cur.fetchone()
            return row["id"] if isinstance(row, dict) else row[0]
        cur = self.raw.execute(sql, params)
        return cur.lastrowid

    def commit(self):
        self.raw.commit()

    def rollback(self):
        self.raw.rollback()

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._release is not None:
            self._release(self.raw)
        else:
            self.raw.close()


# --------------------------------------------------------------------------
# Schema (rendered per dialect)
# --------------------------------------------------------------------------

def _schema_statements(backend: str):
    pk = "BIGSERIAL PRIMARY KEY" if backend == "postgres" else "INTEGER PRIMARY KEY AUTOINCREMENT"
    stmts = [
        f"""CREATE TABLE IF NOT EXISTS logs (
            id            {pk},
            received_at   TEXT NOT NULL,
            source_ip     TEXT,
            peer_ip       TEXT,
            format        TEXT,
            priority      INTEGER,
            facility      TEXT,
            severity      TEXT,
            device_timestamp TEXT,
            hostname      TEXT,
            destination   TEXT,
            app_name      TEXT,
            proc_id       TEXT,
            msg_id        TEXT,
            message       TEXT,
            raw           TEXT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_logs_received_at ON logs(received_at)",
        "CREATE INDEX IF NOT EXISTS idx_logs_received_id ON logs(received_at, id)",
        "CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs(source_ip)",
        "CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity)",
        "CREATE INDEX IF NOT EXISTS idx_logs_hostname ON logs(hostname)",
        "CREATE INDEX IF NOT EXISTS idx_logs_destination ON logs(destination)",
        "CREATE INDEX IF NOT EXISTS idx_logs_peer_ip ON logs(peer_ip)",
        f"""CREATE TABLE IF NOT EXISTS alerts (
            id            {pk},
            created_at    TEXT NOT NULL,
            rule_name     TEXT NOT NULL,
            severity      TEXT NOT NULL,
            source_ip     TEXT,
            description   TEXT,
            log_ids       TEXT,
            ai_status     TEXT DEFAULT 'pending',
            ai_analysis   TEXT,
            ai_triaged_at TEXT,
            ai_attempts   INTEGER DEFAULT 0,
            ticket_status TEXT DEFAULT '',
            ticket_ref    TEXT,
            ticket_attempts INTEGER DEFAULT 0
        )""",
        "CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)",
        f"""CREATE TABLE IF NOT EXISTS forwarders (
            id              {pk},
            name            TEXT NOT NULL,
            host            TEXT NOT NULL,
            port            INTEGER NOT NULL,
            protocol        TEXT NOT NULL DEFAULT 'udp',
            enabled         INTEGER NOT NULL DEFAULT 1,
            filter_pattern  TEXT DEFAULT '',
            min_severity    TEXT DEFAULT '',
            forwarded_count INTEGER DEFAULT 0,
            last_forward_at TEXT,
            last_error      TEXT
        )""",
        f"""CREATE TABLE IF NOT EXISTS source_profiles (
            id           {pk},
            name         TEXT NOT NULL,
            match_type   TEXT DEFAULT 'source_ip',
            match_value  TEXT DEFAULT '',
            map_host     TEXT DEFAULT '',
            map_message  TEXT DEFAULT '',
            map_app      TEXT DEFAULT '',
            map_msgid    TEXT DEFAULT '',
            map_severity TEXT DEFAULT '',
            map_timestamp TEXT DEFAULT '',
            ts_format    TEXT DEFAULT '',
            priority     INTEGER DEFAULT 100,
            enabled      INTEGER NOT NULL DEFAULT 1
        )""",
        """CREATE TABLE IF NOT EXISTS app_config (
            key   TEXT PRIMARY KEY,
            value TEXT
        )""",
        f"""CREATE TABLE IF NOT EXISTS api_pollers (
            id              {pk},
            name            TEXT NOT NULL,
            auth_scheme     TEXT DEFAULT 'oauth2_client_credentials',
            token_url       TEXT NOT NULL DEFAULT '',
            events_url      TEXT NOT NULL,
            whoami_url      TEXT DEFAULT '',
            tenant_header   TEXT DEFAULT '',
            client_id       TEXT DEFAULT '',
            client_secret   TEXT DEFAULT '',
            api_key_header  TEXT DEFAULT '',
            secret_mode     TEXT DEFAULT 'encrypted',
            scope           TEXT DEFAULT '',
            interval_seconds INTEGER DEFAULT 60,
            initial_lookback_seconds INTEGER DEFAULT 86400,
            enabled         INTEGER NOT NULL DEFAULT 0,
            cursor          TEXT,
            pulled_count    INTEGER DEFAULT 0,
            last_poll_at    TEXT,
            last_error      TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS users (
            username             TEXT PRIMARY KEY,
            password_hash        TEXT,
            role                 TEXT DEFAULT 'admin',
            auth_source          TEXT DEFAULT 'local',
            must_change_password INTEGER DEFAULT 0,
            created_at           TEXT
        )""",
        f"""CREATE TABLE IF NOT EXISTS iocs (
            id          {pk},
            ioc_type    TEXT NOT NULL,
            value       TEXT NOT NULL,
            value_norm  TEXT NOT NULL,
            threat      TEXT,
            source      TEXT,
            severity    TEXT DEFAULT 'warning',
            enabled     INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_iocs_value_norm ON iocs(value_norm)",
        "CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type)",
        f"""CREATE TABLE IF NOT EXISTS ioc_matches (
            id          {pk},
            matched_at  TEXT NOT NULL,
            ioc_id      INTEGER,
            ioc_type    TEXT,
            ioc_value   TEXT,
            threat      TEXT,
            log_id      INTEGER,
            source_ip   TEXT,
            hostname    TEXT,
            message     TEXT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_ioc_matches_at ON ioc_matches(matched_at)",
        f"""CREATE TABLE IF NOT EXISTS reports (
            id           {pk},
            created_at   TEXT NOT NULL,
            kind         TEXT DEFAULT 'playbooks',
            trigger      TEXT DEFAULT 'manual',
            window_days  INTEGER,
            summary      TEXT,
            findings     INTEGER DEFAULT 0,
            results_json TEXT
        )""",
        f"""CREATE TABLE IF NOT EXISTS ioc_feeds (
            id             {pk},
            name           TEXT NOT NULL,
            url            TEXT NOT NULL,
            severity       TEXT DEFAULT 'warning',
            threat         TEXT DEFAULT '',
            default_type   TEXT DEFAULT '',
            refresh_hours  INTEGER DEFAULT 0,
            enabled        INTEGER NOT NULL DEFAULT 1,
            last_fetch_at  TEXT,
            last_status    TEXT,
            last_added     INTEGER DEFAULT 0,
            auth_scheme    TEXT DEFAULT 'none',
            header_name    TEXT DEFAULT '',
            header_prefix  TEXT DEFAULT '',
            query_param    TEXT DEFAULT '',
            basic_user     TEXT DEFAULT '',
            key_encrypted  TEXT DEFAULT ''
        )""",
        f"""CREATE TABLE IF NOT EXISTS audit_log (
            id         {pk},
            at         TEXT NOT NULL,
            username   TEXT,
            source_ip  TEXT,
            action     TEXT NOT NULL,
            target     TEXT,
            detail     TEXT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at)",
        "CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(username)",
        "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)",
        f"""CREATE TABLE IF NOT EXISTS log_fields (
            id         {pk},
            log_id     INTEGER NOT NULL,
            field      TEXT NOT NULL,
            value      TEXT,
            value_norm TEXT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_lf_field_value ON log_fields(field, value)",
        "CREATE INDEX IF NOT EXISTS idx_lf_log_id ON log_fields(log_id)",
        # API ingest keys: products that can only POST logs authenticate with
        # one of these. Only the hash is stored; the plaintext key is shown
        # once at creation and never again.
        f"""CREATE TABLE IF NOT EXISTS api_keys (
            id          {pk},
            name        TEXT NOT NULL,
            key_hash    TEXT NOT NULL,
            key_prefix  TEXT,
            enabled     INTEGER DEFAULT 1,
            created_at  TEXT NOT NULL,
            last_used   TEXT,
            use_count   INTEGER DEFAULT 0
        )""",
        "CREATE INDEX IF NOT EXISTS idx_apikeys_hash ON api_keys(key_hash)",
        """CREATE TABLE IF NOT EXISTS runtime_stats (
            key        TEXT PRIMARY KEY,
            value_num  BIGINT,
            value_text TEXT,
            updated_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS hourly_log_stats (
            bucket_hour TEXT NOT NULL,
            severity    TEXT NOT NULL,
            count       INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (bucket_hour, severity)
        )""",
        "CREATE INDEX IF NOT EXISTS idx_hourly_log_stats_hour ON hourly_log_stats(bucket_hour)",
        """CREATE TABLE IF NOT EXISTS source_last_seen (
            source_ip  TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen  TEXT NOT NULL,
            event_count INTEGER NOT NULL DEFAULT 0
        )""",
        "CREATE INDEX IF NOT EXISTS idx_source_last_seen_last ON source_last_seen(last_seen)",
        """CREATE TABLE IF NOT EXISTS archive_segments (
            segment_id       TEXT PRIMARY KEY,
            path             TEXT NOT NULL UNIQUE,
            manifest_path    TEXT NOT NULL,
            state            TEXT NOT NULL DEFAULT 'SEALED',
            mode             TEXT NOT NULL DEFAULT 'copy',
            created_at       TEXT NOT NULL,
            start_at         TEXT NOT NULL,
            end_at           TEXT NOT NULL,
            min_log_id       BIGINT NOT NULL,
            max_log_id       BIGINT NOT NULL,
            event_count      BIGINT NOT NULL DEFAULT 0,
            unique_payloads  BIGINT NOT NULL DEFAULT 0,
            duplicate_occurrences BIGINT NOT NULL DEFAULT 0,
            sha256           TEXT NOT NULL,
            bytes            BIGINT NOT NULL DEFAULT 0
        )""",
        "CREATE INDEX IF NOT EXISTS idx_archive_segments_time ON archive_segments(start_at,end_at)",
        "CREATE INDEX IF NOT EXISTS idx_archive_segments_ids ON archive_segments(min_log_id,max_log_id)",
        """CREATE TABLE IF NOT EXISTS archive_occurrence_catalog (
            log_id      BIGINT PRIMARY KEY,
            segment_id  TEXT NOT NULL,
            archived_at TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_archive_occurrence_segment ON archive_occurrence_catalog(segment_id)",
    ]
    # Canonical identity filters are usually exact/prefix searches scoped by
    # time.  Keep a case-insensitive composite index that can serve both the
    # predicate and the common recent-first time window.  SQLite needs a
    # NOCASE index for indexed prefix LIKE; PostgreSQL uses lower()+
    # text_pattern_ops for the same purpose.
    if backend == "postgres":
        stmts.extend([
            "CREATE INDEX IF NOT EXISTS idx_logs_source_time_ci ON logs (lower(source_ip) text_pattern_ops, received_at, id)",
            "CREATE INDEX IF NOT EXISTS idx_logs_host_time_ci ON logs (lower(hostname) text_pattern_ops, received_at, id)",
            "CREATE INDEX IF NOT EXISTS idx_logs_destination_time_ci ON logs (lower(destination) text_pattern_ops, received_at, id)",
        ])
    else:
        stmts.extend([
            "CREATE INDEX IF NOT EXISTS idx_logs_source_time_ci ON logs(source_ip COLLATE NOCASE, received_at, id)",
            "CREATE INDEX IF NOT EXISTS idx_logs_host_time_ci ON logs(hostname COLLATE NOCASE, received_at, id)",
            "CREATE INDEX IF NOT EXISTS idx_logs_destination_time_ci ON logs(destination COLLATE NOCASE, received_at, id)",
        ])
    return stmts


def _fts_schema_statements():
    """SQLite-only FTS5 objects. Kept separate so builds without FTS5 can
    still initialize and transparently fall back to LIKE message search."""
    return [
        "CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5("
        "message, content='logs', content_rowid='id', tokenize='unicode61')",
        "CREATE TRIGGER IF NOT EXISTS logs_ai AFTER INSERT ON logs BEGIN "
        "INSERT INTO logs_fts(rowid, message) VALUES (new.id, new.message); END",
        "CREATE TRIGGER IF NOT EXISTS logs_ad AFTER DELETE ON logs BEGIN "
        "INSERT INTO logs_fts(logs_fts, rowid, message) "
        "VALUES('delete', old.id, old.message); END",
        "CREATE TRIGGER IF NOT EXISTS logs_au AFTER UPDATE ON logs BEGIN "
        "INSERT INTO logs_fts(logs_fts, rowid, message) "
        "VALUES('delete', old.id, old.message); "
        "INSERT INTO logs_fts(rowid, message) VALUES (new.id, new.message); END",
    ]


def fts5_available(conn) -> bool:
    """Return True when this connection can query the mini-SIEM FTS5 index."""
    if getattr(conn, "backend", "sqlite") != "sqlite":
        return False
    try:
        conn.execute(
            "SELECT rowid FROM logs_fts WHERE logs_fts MATCH ? LIMIT 1",
            ("__fts_probe__",),
        ).fetchone()
        return True
    except Exception:
        return False


_TEXT_SEARCH_MODES = {"auto", "fts", "trigram", "like"}
_TEXT_SEARCH_STATUS_CACHE = {}
_TEXT_SEARCH_STATUS_LOCK = threading.Lock()
_TEXT_SEARCH_STATUS_TTL = 60.0


def text_search_configured(config: dict) -> str:
    """Return the persisted text-search mode from db-config.json."""
    mode = str(config.get("text_search", "auto") or "auto").strip().lower()
    return mode if mode in _TEXT_SEARCH_MODES else "auto"


def text_search_requested(config: dict) -> str:
    """Return the effective operator-selected message-search mode.

    MINISIEM_TEXT_SEARCH is an intentional runtime query override so an operator
    can force a safe fallback without rewriting db-config.json during an
    incident. Index provisioning follows the persisted config mode, not this
    per-process override. Invalid values fail closed to ``auto``.
    """
    value = os.environ.get("MINISIEM_TEXT_SEARCH")
    if value is None:
        return text_search_configured(config)
    mode = str(value or "auto").strip().lower()
    return mode if mode in _TEXT_SEARCH_MODES else "auto"


def _postgres_index_exists(conn, index_name: str) -> bool:
    try:
        row = conn.execute(
            "SELECT 1 AS ok FROM pg_indexes "
            "WHERE schemaname = ANY(current_schemas(false)) AND indexname=? LIMIT 1",
            (index_name,),
        ).fetchone()
        return bool(row)
    except Exception:
        return False


def _postgres_extension_exists(conn, extension_name: str) -> bool:
    try:
        row = conn.execute(
            "SELECT 1 AS ok FROM pg_extension WHERE extname=? LIMIT 1",
            (extension_name,),
        ).fetchone()
        return bool(row)
    except Exception:
        return False


_PG_SEARCH_INIT_DONE = set()
_PG_SEARCH_INIT_LOCK = threading.Lock()


def _postgres_identity(config: dict):
    p = config.get("postgres") or {}
    return (p.get("host"), p.get("port"), p.get("dbname"), p.get("user"))


def _ensure_postgres_text_search_once(conn, config: dict):
    """Run optional PostgreSQL search DDL at most once per process/database.

    db.initialize() is intentionally idempotent and is called from more than
    startup, so this guard prevents repeated CREATE EXTENSION/INDEX catalog work
    on ordinary dashboard requests. A process restart retries previously failed
    optional setup after an operator changes database privileges/extensions.
    """
    mode = text_search_configured(config)
    key = (_postgres_identity(config), mode)
    with _PG_SEARCH_INIT_LOCK:
        if key in _PG_SEARCH_INIT_DONE:
            return None
        result = _ensure_postgres_text_search(conn, mode)
        _PG_SEARCH_INIT_DONE.add(key)
        return result


def _ensure_postgres_text_search(conn, mode="auto"):
    """Best-effort native PostgreSQL search acceleration.

    The built-in tsvector/GIN index needs no extension. pg_trgm is optional and
    may require database-owner privileges, so each step commits independently
    and failures are rolled back without preventing core SIEM startup.
    """
    mode = mode if mode in _TEXT_SEARCH_MODES else "auto"
    if mode == "like":
        return {"skipped": True}

    statements = []
    if mode in ("auto", "fts"):
        statements.append((
            "CREATE INDEX IF NOT EXISTS idx_logs_message_fts ON logs "
            "USING GIN (to_tsvector('simple'::regconfig, "
            "COALESCE(message, ''::text)))",
            "fts",
        ))
    if mode in ("auto", "trigram"):
        statements.extend([
            ("CREATE EXTENSION IF NOT EXISTS pg_trgm", "trigram_extension"),
            (
                "CREATE INDEX IF NOT EXISTS idx_logs_message_trgm ON logs "
                "USING GIN (message gin_trgm_ops)",
                "trigram_index",
            ),
        ])
    results = {}
    for sql, key in statements:
        # A trigram index cannot be created if the extension step failed. Still
        # attempt it: it may already be installed even if CREATE EXTENSION was
        # denied to this account.
        try:
            conn.execute(sql)
            conn.commit()
            results[key] = True
        except Exception:
            try:
                conn.rollback()
            except Exception:
                try:
                    conn.raw.rollback()
                except Exception:
                    pass
            results[key] = False
    return results


def postgres_text_search_capabilities(conn) -> dict:
    """Inspect PostgreSQL search accelerators without exposing DB secrets."""
    if getattr(conn, "backend", None) != "postgres":
        return {"fts_index": False, "trigram_extension": False, "trigram_index": False}
    return {
        "fts_index": _postgres_index_exists(conn, "idx_logs_message_fts"),
        "trigram_extension": _postgres_extension_exists(conn, "pg_trgm"),
        "trigram_index": _postgres_index_exists(conn, "idx_logs_message_trgm"),
    }




def _text_search_cache_key(config: dict, backend: str, requested: str):
    if backend == "postgres":
        p = config.get("postgres") or {}
        identity = (p.get("host"), p.get("port"), p.get("dbname"), p.get("user"))
    else:
        sq = config.get("sqlite") or {}
        identity = (sq.get("path"),)
    return (backend, identity, requested)

def text_search_status(conn, config: dict, fresh: bool = False) -> dict:
    """Resolve the effective message-search backend for one connection.

    Returned ``engine`` values are consumed by dashboard.py's query builder.
    ``auto`` prefers an indexed native engine and always has a safe LIKE/ILIKE
    fallback. Capability probes are cached briefly so every 5-second log query
    does not issue extra PostgreSQL catalog lookups; the Stats endpoint can pass
    ``fresh=True`` to refresh the cache for operator visibility.
    """
    requested = text_search_requested(config)
    backend = getattr(conn, "backend", config.get("backend", "sqlite"))
    cache_key = _text_search_cache_key(config, backend, requested)
    now = time.monotonic()
    if not fresh:
        with _TEXT_SEARCH_STATUS_LOCK:
            cached = _TEXT_SEARCH_STATUS_CACHE.get(cache_key)
            if cached and now - cached[0] < _TEXT_SEARCH_STATUS_TTL:
                return dict(cached[1])

    if backend == "postgres":
        caps = postgres_text_search_capabilities(conn)
        if requested == "like":
            engine = "postgres_ilike"
        elif requested == "trigram":
            engine = "postgres_trigram" if caps["trigram_index"] else "postgres_ilike"
        elif requested == "fts":
            # PostgreSQL's native FTS functions exist even if the optional
            # index could not be created; explicit fts means use the semantics
            # the operator selected and report whether it is accelerated.
            engine = "postgres_fts"
        else:  # auto
            if caps["fts_index"]:
                engine = "postgres_fts"
            elif caps["trigram_index"]:
                engine = "postgres_trigram"
            else:
                engine = "postgres_ilike"
        accelerated = (
            engine == "postgres_fts" and caps["fts_index"]
        ) or (engine == "postgres_trigram" and caps["trigram_index"])
        result = {
            "requested": requested,
            "engine": engine,
            "accelerated": bool(accelerated),
            "fts_index": caps["fts_index"],
            "trigram_extension": caps["trigram_extension"],
            "trigram_index": caps["trigram_index"],
        }
    else:
        have_fts = fts5_available(conn)
        if requested == "like":
            engine = "sqlite_like"
        elif requested in ("fts", "auto") and have_fts:
            engine = "sqlite_fts5"
        else:
            # trigram has no SQLite equivalent in this project; use the portable
            # LIKE fallback rather than pretending it is accelerated.
            engine = "sqlite_like"
        result = {
            "requested": requested,
            "engine": engine,
            "accelerated": engine == "sqlite_fts5",
            "fts5": have_fts,
        }

    with _TEXT_SEARCH_STATUS_LOCK:
        _TEXT_SEARCH_STATUS_CACHE[cache_key] = (now, dict(result))
    return result


# --------------------------------------------------------------------------
# Connection factories
# --------------------------------------------------------------------------

def _sqlite_cfg_int(config: dict, key: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int((config.get("sqlite") or {}).get(key, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


_SQLITE_OPTIMIZE_LOCK = threading.Lock()
_SQLITE_LAST_OPTIMIZE = {}
_SQLITE_NUMERIC_PRAGMAS = frozenset({
    "busy_timeout", "cache_size", "mmap_size", "wal_autocheckpoint"
})


def _set_sqlite_numeric_pragma(raw, name: str, value: int):
    # PRAGMA assignment does not accept DB-API placeholders. Keep the tiny
    # dynamic surface strictly allow-listed and integer-only before execution.
    if name not in _SQLITE_NUMERIC_PRAGMAS:
        raise ValueError("unsupported SQLite pragma")
    statement = "PRAGMA " + name + "=" + str(int(value))
    raw.execute(statement)


def _maybe_sqlite_optimize(raw, config: dict):
    interval = _sqlite_cfg_int(config, "optimize_interval_seconds", 3600, 0, 86400)
    if interval <= 0:
        return
    path = os.path.abspath(str((config.get("sqlite") or {}).get("path") or "siem.db"))
    now = time.monotonic()
    with _SQLITE_OPTIMIZE_LOCK:
        last = _SQLITE_LAST_OPTIMIZE.get(path, 0.0)
        if last and now - last < interval:
            return
        # Mark before running so a burst of dashboard connections cannot all
        # enter PRAGMA optimize together. Failure is harmless and retried after
        # the interval rather than on every request.
        _SQLITE_LAST_OPTIMIZE[path] = now
    try:
        raw.execute("PRAGMA optimize")
    except sqlite3.Error:
        pass


def _connect_sqlite(config: dict) -> Connection:
    sqlite_cfg = config.get("sqlite") or {}
    path = sqlite_cfg.get("path") or "siem.db"
    busy_ms = _sqlite_cfg_int(config, "busy_timeout_ms", 5000, 0, 60000)
    raw = sqlite3.connect(
        path, check_same_thread=False, timeout=max(0.001, busy_ms / 1000.0)
    )
    raw.row_factory = sqlite3.Row
    # WAL journal: readers don't block the writer and commits are far cheaper.
    # The remaining PRAGMAs are deliberately bounded, per-connection tuning:
    # wait briefly for a writer instead of instantly failing, reserve a modest
    # page cache, keep temp work in memory, allow a bounded mmap window, and
    # checkpoint WAL at a predictable size.
    try:
        cache_kib = _sqlite_cfg_int(config, "cache_size_kib", 32768, 1024, 262144)
        mmap_mb = _sqlite_cfg_int(config, "mmap_size_mb", 128, 0, 2048)
        checkpoint_pages = _sqlite_cfg_int(config, "wal_autocheckpoint_pages", 1000, 100, 100000)
        if bool(sqlite_cfg.get("auto_vacuum_incremental", True)):
            # Takes effect automatically for a fresh database. Existing DBs
            # that were created with auto_vacuum=NONE are intentionally not
            # rewritten here because that would require a blocking full VACUUM.
            raw.execute("PRAGMA auto_vacuum=INCREMENTAL")
        raw.execute("PRAGMA journal_mode=WAL")
        raw.execute("PRAGMA synchronous=NORMAL")
        _set_sqlite_numeric_pragma(raw, "busy_timeout", busy_ms)
        _set_sqlite_numeric_pragma(raw, "cache_size", -cache_kib)
        if bool(sqlite_cfg.get("temp_store_memory", True)):
            raw.execute("PRAGMA temp_store=MEMORY")
        _set_sqlite_numeric_pragma(raw, "mmap_size", mmap_mb * 1024 * 1024)
        _set_sqlite_numeric_pragma(raw, "wal_autocheckpoint", checkpoint_pages)
        raw.execute("PRAGMA cell_size_check=ON")
    except sqlite3.Error:
        pass  # e.g. read-only media; fall back to driver/database defaults
    _maybe_sqlite_optimize(raw, config)
    return Connection(raw, "sqlite")


_PG_POOLS = {}
_PG_POOLS_LOCK = threading.Lock()


def _postgres_pool(config: dict):
    try:
        import psycopg2.extras
        from psycopg2.pool import ThreadedConnectionPool
    except ImportError as exc:
        raise RuntimeError(
            "PostgreSQL backend selected but psycopg2 is not installed. "
            "Run: pip install psycopg2-binary"
        ) from exc
    p = config["postgres"]
    minconn = max(1, min(int(p.get("pool_min", 1)), 50))
    maxconn = max(minconn, min(int(p.get("pool_max", 10)), 100))
    connect_timeout = max(1, min(int(p.get("connect_timeout_seconds", 5)), 60))
    application_name = str(p.get("application_name") or "mini-siem")[:63]
    key = (p.get("host"), int(p.get("port", 5432)), p.get("dbname"),
           p.get("user"), p.get("password"), minconn, maxconn,
           connect_timeout, application_name)
    with _PG_POOLS_LOCK:
        pool = _PG_POOLS.get(key)
        if pool is None:
            pool = ThreadedConnectionPool(
                minconn, maxconn, host=p["host"], port=p["port"],
                dbname=p["dbname"], user=p["user"], password=p["password"],
                connect_timeout=connect_timeout, application_name=application_name,
                cursor_factory=psycopg2.extras.RealDictCursor,
            )
            _PG_POOLS[key] = pool
    return pool


def _connect_postgres(config: dict) -> Connection:
    pool = _postgres_pool(config)
    raw = pool.getconn()
    p = config.get("postgres") or {}
    # Apply bounded session safety limits on every checkout so one expensive
    # dashboard search or a leaked transaction cannot monopolize a pooled
    # PostgreSQL connection indefinitely. Values are integer-only and clamped
    # before interpolation; no user query text is ever interpolated.
    try:
        statement_ms = max(100, min(int(p.get("statement_timeout_ms", 15000)), 300000))
        lock_ms = max(100, min(int(p.get("lock_timeout_ms", 3000)), 60000))
        idle_ms = max(1000, min(int(p.get("idle_in_transaction_session_timeout_ms", 30000)), 600000))
        cur = raw.cursor()
        # set_config() accepts bound values, avoiding dynamic SQL while still
        # applying PostgreSQL's session-level millisecond timeouts.
        cur.execute("SELECT set_config(%s, %s, false)",
                    ("statement_timeout", f"{statement_ms}ms"))
        cur.execute("SELECT set_config(%s, %s, false)",
                    ("lock_timeout", f"{lock_ms}ms"))
        cur.execute("SELECT set_config(%s, %s, false)",
                    ("idle_in_transaction_session_timeout", f"{idle_ms}ms"))
        raw.commit()
    except Exception:
        try:
            raw.rollback()
        except Exception:
            pass

    def release(connection):
        broken = bool(getattr(connection, "closed", False))
        if not broken:
            try:
                connection.rollback()  # never leak transaction state to the next borrower
            except Exception:
                broken = True
        pool.putconn(connection, close=broken)

    return Connection(raw, "postgres", release=release)


def connect(config: dict) -> Connection:
    if config.get("backend") == "postgres":
        return _connect_postgres(config)
    return _connect_sqlite(config)


def _migrations():
    """ALTER statements to bring an existing DB up to the current schema.
    Each is attempted and its 'column already exists' error ignored, so
    this is safe to run on both fresh and older databases, sqlite or pg."""
    return [
        "ALTER TABLE alerts ADD COLUMN ai_status TEXT DEFAULT 'pending'",
        "ALTER TABLE alerts ADD COLUMN ai_analysis TEXT",
        "ALTER TABLE alerts ADD COLUMN ai_triaged_at TEXT",
        "ALTER TABLE alerts ADD COLUMN ai_attempts INTEGER DEFAULT 0",
        "ALTER TABLE alerts ADD COLUMN ticket_status TEXT DEFAULT ''",
        "ALTER TABLE alerts ADD COLUMN ticket_ref TEXT",
        "ALTER TABLE alerts ADD COLUMN ticket_attempts INTEGER DEFAULT 0",
        # Per-destination origin preservation for the syslog relay:
        # 'off' (byte-faithful passthrough), 'hostname', 'sd', or 'both'.
        "ALTER TABLE forwarders ADD COLUMN origin_mode TEXT DEFAULT 'off'",
        # TCP framing: 'newline' (LF-delimited, non-transparent) or 'octet'
        # (RFC 6587 octet-counting, length-prefixed). Ignored for UDP.
        "ALTER TABLE forwarders ADD COLUMN tcp_framing TEXT DEFAULT 'newline'",
        # Sophos-style multi-tenancy discovery endpoint for API pollers.
        "ALTER TABLE api_pollers ADD COLUMN whoami_url TEXT DEFAULT ''",
        # Destination field: dst/target from firewall-style logs, kept separate
        # from hostname (the host that generated the log).
        "ALTER TABLE logs ADD COLUMN destination TEXT",
        # peer_ip: the true network sender (log source), preserved separately
        # from source_ip which may be overwritten by an explicit src= actor.
        "ALTER TABLE logs ADD COLUMN peer_ip TEXT",
        # Normalized extracted-field value used by exact/prefix filters.
        # The post-migration initializer backfills historical rows and adds
        # the covering (field,value_norm,log_id) index.
        "ALTER TABLE log_fields ADD COLUMN value_norm TEXT",
        "ALTER TABLE api_pollers ADD COLUMN auth_scheme TEXT DEFAULT 'oauth2_client_credentials'",
        "ALTER TABLE api_pollers ADD COLUMN tenant_header TEXT DEFAULT ''",
        "ALTER TABLE api_pollers ADD COLUMN api_key_header TEXT DEFAULT ''",
        # IOC feed authentication — covers the common threat-intel feed auth
        # patterns (static header key, raw Authorization key, query-param
        # key, HTTP basic auth). 'none' preserves today's unauthenticated
        # behavior for existing feeds.
        "ALTER TABLE ioc_feeds ADD COLUMN auth_scheme TEXT DEFAULT 'none'",
        "ALTER TABLE ioc_feeds ADD COLUMN header_name TEXT DEFAULT ''",
        "ALTER TABLE ioc_feeds ADD COLUMN header_prefix TEXT DEFAULT ''",
        "ALTER TABLE ioc_feeds ADD COLUMN query_param TEXT DEFAULT ''",
        "ALTER TABLE ioc_feeds ADD COLUMN basic_user TEXT DEFAULT ''",
        "ALTER TABLE ioc_feeds ADD COLUMN key_encrypted TEXT DEFAULT ''",
    ]


def _ensure_field_value_norm(conn: Connection):
    """Backfill the normalized extracted-field value once, then create the
    covering lookup index.  Kept post-migration so older databases that do not
    yet have value_norm never see an index DDL that references a missing column.
    """
    try:
        conn.execute(
            "UPDATE log_fields SET value_norm=LOWER(COALESCE(value, '')) "
            "WHERE value_norm IS NULL"
        )
        conn.commit()
        if conn.backend == "postgres":
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_lf_field_value_norm "
                "ON log_fields(field, value_norm text_pattern_ops, log_id)"
            )
        else:
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_lf_field_value_norm "
                "ON log_fields(field, value_norm COLLATE NOCASE, log_id)"
            )
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass



def _utc_now_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def runtime_stat_upsert(conn: Connection, key: str, value_num=None, value_text=None,
                        updated_at: str = None):
    """Portable upsert for a small cross-process runtime metric."""
    conn.execute(
        """INSERT INTO runtime_stats(key, value_num, value_text, updated_at)
           VALUES (?,?,?,?)
           ON CONFLICT(key) DO UPDATE SET
             value_num=excluded.value_num,
             value_text=excluded.value_text,
             updated_at=excluded.updated_at""",
        (key, value_num, value_text, updated_at or _utc_now_iso()),
    )


def runtime_stat_increment(conn: Connection, key: str, delta: int,
                           updated_at: str = None):
    """Increment a numeric runtime metric without a read/modify/write race."""
    conn.execute(
        """INSERT INTO runtime_stats(key, value_num, value_text, updated_at)
           VALUES (?,?,NULL,?)
           ON CONFLICT(key) DO UPDATE SET
             value_num=COALESCE(runtime_stats.value_num,0)+excluded.value_num,
             updated_at=excluded.updated_at""",
        (key, int(delta), updated_at or _utc_now_iso()),
    )


def read_runtime_stats(conn: Connection, keys=None) -> dict:
    params = []
    sql = "SELECT key, value_num, value_text, updated_at FROM runtime_stats"
    if keys:
        keys = list(keys)
        sql += " WHERE key IN (" + ",".join("?" for _ in keys) + ")"
        params.extend(keys)
    out = {}
    for row in conn.execute(sql, params).fetchall():
        out[row["key"]] = dict(row)
    return out



def update_log_rollups(conn: Connection, events):
    """Apply transactional log counters/hourly/source rollups for events.

    Caller owns commit/rollback. This helper is also used by the standalone
    HTTP-ingest fallback, while the dedicated DB writer uses equivalent
    batched aggregation in its hot path.
    """
    events = list(events or [])
    if not events:
        return
    now = _utc_now_iso()
    runtime_stat_increment(conn, "total_logs", len(events), updated_at=now)
    sources = {}
    hourly = {}
    for event in events:
        received = str(event.get("received_at") or "")
        src = str(event.get("source_ip") or "").strip()
        if src and received:
            old = sources.get(src)
            if old is None:
                sources[src] = [received, received, 1]
            else:
                old[0] = min(old[0], received)
                old[1] = max(old[1], received)
                old[2] += 1
        if received:
            bucket = received[:13] + ":00:00+00:00"
            sev = str(event.get("severity") or "").lower()
            hourly[(bucket, sev)] = hourly.get((bucket, sev), 0) + 1
    for src, (first_seen, last_seen, count) in sources.items():
        conn.execute(
            """INSERT INTO source_last_seen(source_ip, first_seen, last_seen, event_count)
               VALUES (?,?,?,?)
               ON CONFLICT(source_ip) DO UPDATE SET
                 first_seen=CASE WHEN excluded.first_seen < source_last_seen.first_seen
                                 THEN excluded.first_seen ELSE source_last_seen.first_seen END,
                 last_seen=CASE WHEN excluded.last_seen > source_last_seen.last_seen
                                THEN excluded.last_seen ELSE source_last_seen.last_seen END,
                 event_count=source_last_seen.event_count + excluded.event_count""",
            (src, first_seen, last_seen, count),
        )
    for (bucket, sev), count in hourly.items():
        conn.execute(
            """INSERT INTO hourly_log_stats(bucket_hour, severity, count)
               VALUES (?,?,?)
               ON CONFLICT(bucket_hour, severity) DO UPDATE SET
                 count=hourly_log_stats.count + excluded.count""",
            (bucket, sev, count),
        )

def recent_log_counts_from_rollups(conn: Connection, start_iso: str, end_iso: str) -> dict:
    """Return exact severity counts for ``[start_iso, end_iso]`` cheaply.

    Whole UTC hours come from ``hourly_log_stats``. Only the two partial
    boundary hours touch ``logs`` and both range scans are bounded by the
    ``received_at`` index. This keeps Dashboard 24-hour counts exact without
    returning to a full-day raw-table aggregation. ISO timestamps produced by
    mini-SIEM are required.
    """
    from datetime import datetime, timedelta, timezone

    def parse(value):
        text = str(value or "").strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    start = parse(start_iso)
    end = parse(end_iso)
    if end < start:
        return {}
    start_floor = start.replace(minute=0, second=0, microsecond=0)
    end_floor = end.replace(minute=0, second=0, microsecond=0)
    first_full = start_floor if start == start_floor else start_floor + timedelta(hours=1)

    counts = {}

    def add_rows(rows):
        for row in rows:
            sev = str(row["severity"] or "informational").lower()
            counts[sev] = counts.get(sev, 0) + int(row["c"] or 0)

    # A range contained in one UTC hour has no whole-hour rollup to use. It is
    # still bounded to <60 minutes by received_at and must be counted only once.
    if start_floor == end_floor:
        add_rows(conn.execute(
            "SELECT LOWER(COALESCE(severity,'')) severity, COUNT(*) c FROM logs "
            "WHERE received_at >= ? AND received_at <= ? "
            "GROUP BY LOWER(COALESCE(severity,''))",
            (start.isoformat(), end.isoformat()),
        ).fetchall())
        return counts

    # Full hours strictly inside the requested window. bucket_hour is stored as
    # a canonical UTC ISO hour, so lexical ordering is chronological.
    if first_full < end_floor or (first_full == end_floor and end == end_floor):
        add_rows(conn.execute(
            "SELECT severity, SUM(count) c FROM hourly_log_stats "
            "WHERE bucket_hour >= ? AND bucket_hour < ? GROUP BY severity",
            (first_full.isoformat(), end_floor.isoformat()),
        ).fetchall())

    # Partial leading hour (at most <60 minutes of indexed raw rows).
    lead_end = min(first_full, end)
    if start < lead_end:
        add_rows(conn.execute(
            "SELECT LOWER(COALESCE(severity,'')) severity, COUNT(*) c FROM logs "
            "WHERE received_at >= ? AND received_at < ? "
            "GROUP BY LOWER(COALESCE(severity,''))",
            (start.isoformat(), lead_end.isoformat()),
        ).fetchall())

    # Partial trailing hour. At an exact hour boundary this is intentionally
    # empty because the preceding full-hour rollups already cover the range.
    trail_start = max(end_floor, start)
    if trail_start < end:
        add_rows(conn.execute(
            "SELECT LOWER(COALESCE(severity,'')) severity, COUNT(*) c FROM logs "
            "WHERE received_at >= ? AND received_at <= ? "
            "GROUP BY LOWER(COALESCE(severity,''))",
            (trail_start.isoformat(), end.isoformat()),
        ).fetchall())
    return counts


def _ensure_rollup_baseline(conn: Connection):
    """One-time bootstrap for databases that predate Phase 4 rollups.

    The expensive historical scans run only when the corresponding rollup is
    empty. New ingest keeps these tables current transactionally. Hourly
    history is intentionally limited to the most recent 14 days so upgrading a
    very large installation does not rebuild years of analytics at startup.
    """
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc).isoformat()
    try:
        row = conn.execute("SELECT value_num FROM runtime_stats WHERE key='total_logs'").fetchone()
        if row is None:
            total = conn.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"]
            runtime_stat_upsert(conn, "total_logs", total, updated_at=now)
        row = conn.execute("SELECT value_num FROM runtime_stats WHERE key='total_alerts'").fetchone()
        if row is None:
            total = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
            runtime_stat_upsert(conn, "total_alerts", total, updated_at=now)

        have_sources = conn.execute("SELECT 1 FROM source_last_seen LIMIT 1").fetchone()
        if have_sources is None:
            conn.execute(
                """INSERT INTO source_last_seen(source_ip, first_seen, last_seen, event_count)
                   SELECT source_ip, MIN(received_at), MAX(received_at), COUNT(*)
                   FROM logs
                   WHERE source_ip IS NOT NULL AND source_ip != ''
                   GROUP BY source_ip
                   ON CONFLICT(source_ip) DO UPDATE SET
                     first_seen=excluded.first_seen,
                     last_seen=excluded.last_seen,
                     event_count=excluded.event_count"""
            )

        have_hourly = conn.execute("SELECT 1 FROM hourly_log_stats LIMIT 1").fetchone()
        if have_hourly is None:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=14)).isoformat()
            if conn.backend == "postgres":
                hourly_sql = """INSERT INTO hourly_log_stats(bucket_hour, severity, count)
                    SELECT SUBSTRING(received_at FROM 1 FOR 13) || ':00:00+00:00',
                           LOWER(COALESCE(severity,'')), COUNT(*)
                    FROM logs WHERE received_at >= ?
                    GROUP BY 1, 2
                    ON CONFLICT(bucket_hour, severity) DO UPDATE SET count=excluded.count"""
            else:
                hourly_sql = """INSERT INTO hourly_log_stats(bucket_hour, severity, count)
                    SELECT SUBSTR(received_at,1,13) || ':00:00+00:00',
                           LOWER(COALESCE(severity,'')), COUNT(*)
                    FROM logs WHERE received_at >= ?
                    GROUP BY 1, 2
                    ON CONFLICT(bucket_hour, severity) DO UPDATE SET count=excluded.count"""
            conn.execute(hourly_sql, (cutoff,))
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass


def initialize(config: dict):
    """Create all tables and indexes if missing, then apply migrations.
    Idempotent."""
    conn = connect(config)
    try:
        for stmt in _schema_statements(config.get("backend", "sqlite")):
            conn.execute(stmt)
        conn.commit()
        if config.get("backend") != "postgres":
            try:
                for stmt in _fts_schema_statements():
                    conn.execute(stmt)
                conn.commit()
            except Exception:
                # Some SQLite builds omit FTS5. Core logging must still start;
                # dashboard message search will detect this and use LIKE.
                try:
                    conn.raw.rollback()
                except Exception:
                    pass
        for stmt in _migrations():
            try:
                conn.execute(stmt)
                conn.commit()
            except Exception:
                # column already exists (or unsupported) — safe to ignore
                try:
                    conn.raw.rollback()
                except Exception:
                    pass
        _ensure_field_value_norm(conn)
        _ensure_rollup_baseline(conn)
        if config.get("backend") == "postgres":
            _ensure_postgres_text_search_once(conn, config)
        # seed default source profiles (Windows/NXLog, Sophos) if none exist
        try:
            import profiles as _profiles_mod
            _profiles_mod.seed_defaults(conn)
        except Exception:
            pass
        # one-time FTS backfill: if the logs_fts index is empty but logs
        # exist (existing DB predating FTS), populate it now so message
        # search works on historical rows. Uses the internal 'docsize' shadow
        # table to detect a truly-empty index (external-content FTS otherwise
        # reflects the content table and looks non-empty).
        if config.get("backend") != "postgres" and fts5_available(conn):
            try:
                have_logs = conn.execute("SELECT 1 FROM logs LIMIT 1").fetchone()
                indexed = 0
                try:
                    r = conn.execute("SELECT COUNT(*) AS n FROM logs_fts_docsize").fetchone()
                    indexed = r["n"] if r else 0
                except Exception:
                    # docsize shadow not present/queryable — fall back to a
                    # MATCH probe (empty index returns nothing)
                    try:
                        conn.execute("SELECT rowid FROM logs_fts WHERE logs_fts MATCH 'a*' LIMIT 1").fetchone()
                        indexed = 1  # query worked and (maybe) has data; skip backfill
                    except Exception:
                        indexed = 0
                if have_logs and indexed == 0:
                    conn.execute("INSERT INTO logs_fts(logs_fts) VALUES('rebuild')")
                    conn.commit()
            except Exception:
                pass
    finally:
        conn.close()


def rebuild_fts(config: dict, progress=None):
    """(Re)build the logs_fts full-text index from existing logs. Needed once
    on an existing DB that predates FTS, or to repair the index. sqlite-only;
    no-op on postgres. Returns the number of rows indexed."""
    if config.get("backend") == "postgres":
        return 0
    conn = connect(config)
    try:
        if not fts5_available(conn):
            return 0
        # 'rebuild' repopulates an external-content FTS table from its source
        try:
            conn.execute("INSERT INTO logs_fts(logs_fts) VALUES('rebuild')")
            conn.commit()
        except Exception:
            # fallback: manual repopulate if rebuild unsupported
            conn.execute("DELETE FROM logs_fts")
            conn.execute(
                "INSERT INTO logs_fts(rowid, message) SELECT id, message FROM logs")
            conn.commit()
        row = conn.execute("SELECT COUNT(*) AS n FROM logs").fetchone()
        return row["n"] if row else 0
    finally:
        conn.close()


def integrity_check(config: dict, quick: bool = True):
    """Run SQLite's self-verification. Returns (ok: bool, detail: str).
    For postgres, reports that the check is sqlite-only."""
    if config.get("backend") == "postgres":
        return True, "integrity_check is a SQLite feature; PostgreSQL manages its own integrity."
    try:
        conn = connect(config)
        pragma = sqlite_integrity_pragma(quick=quick)
        pragma_sql = "PRAGMA " + pragma
        rows = conn.execute(pragma_sql).fetchall()
        conn.close()
        results = []
        for r in rows:
            results.append(r[0] if not isinstance(r, dict) else list(r.values())[0])
        ok = len(results) == 1 and str(results[0]).lower() == "ok"
        return ok, ("ok" if ok else "; ".join(str(x) for x in results[:20]))
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def db_file_info(config: dict):
    """Size + WAL info for the sqlite DB, for monitoring display."""
    if config.get("backend") == "postgres":
        return {"backend": "postgres"}
    import os
    path = config["sqlite"]["path"]
    info = {"backend": "sqlite", "path": path}
    try:
        info["size_bytes"] = os.path.getsize(path)
    except OSError:
        info["size_bytes"] = None
    for suffix, key in (("-wal", "wal_bytes"), ("-shm", "shm_bytes")):
        try:
            info[key] = os.path.getsize(path + suffix)
        except OSError:
            info[key] = 0
    # Read-only fragmentation/maintenance indicators. Never run VACUUM here.
    try:
        uri = "file:" + os.path.abspath(path) + "?mode=ro"
        raw = sqlite3.connect(uri, uri=True, timeout=0.5)
        try:
            for sql, key in (("PRAGMA page_count", "page_count"),
                             ("PRAGMA freelist_count", "freelist_count"),
                             ("PRAGMA auto_vacuum", "auto_vacuum")):
                row = raw.execute(sql).fetchone()
                info[key] = int(row[0]) if row else 0
            page_size = raw.execute("PRAGMA page_size").fetchone()
            info["page_size"] = int(page_size[0]) if page_size else 0
            info["free_bytes_estimate"] = info.get("freelist_count", 0) * info.get("page_size", 0)
        finally:
            raw.close()
    except Exception:
        pass
    return info


def test_connection(config: dict):
    """Returns ``(ok, detail)`` after a minimal round-trip query."""
    conn = None
    try:
        conn = connect(config)
        conn.execute("SELECT 1")
        return True, f"Connected: {describe(config)}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
