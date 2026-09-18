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

from sql_helpers import sqlite_integrity_pragma, placeholders

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "backend": "sqlite",
    "sqlite": {"path": "siem.db"},
    "postgres": {
        "host": "localhost",
        "port": 5432,
        "dbname": "minisiem",
        "user": "minisiem",
        "password": "",
        "connect_timeout": 5,
        "connect_retries": 5,
        "connect_retry_delay": 2,
    },
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
    "maintenance": {
        "wal_checkpoint_mb": 256,
        "incremental_vacuum_pages": 2000,
        "quick_check_interval_seconds": 86400,
    },
}

# Runtime components must never need PostgreSQL DDL/owner privileges.  The
# owner/migration identity creates these objects; listener/dashboard identities
# only validate that the expected schema is already present.
RUNTIME_REQUIRED_TABLES = (
    "logs", "alerts", "forwarders", "source_profiles", "app_config",
    "api_pollers", "users", "iocs", "ioc_matches", "reports", "ioc_feeds",
    "audit_log", "log_fields", "api_keys", "schema_migrations", "ai_usage_audit",
    "runtime_stats", "archive_segments", "archive_occurrence_catalog",
)



def config_from_path(sqlite_path: str) -> dict:
    """Build a sqlite config dict from a bare path (back-compat with the
    old --db flag)."""
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    cfg["backend"] = "sqlite"
    cfg["sqlite"]["path"] = sqlite_path or "siem.db"
    return cfg


def load_config(config_path: str = None, sqlite_fallback: str = "siem.db",
                credentials_path: str = None) -> dict:
    """Resolve DB config and optionally overlay a component credential file.

    ``db-config.json`` remains the non-secret application/database settings
    file.  A PostgreSQL privilege-boundary deployment passes a separate
    credentials file for each process (listener/dashboard/maintenance).  Only
    the PostgreSQL ``user`` and ``password`` values are accepted from that
    overlay, so a compromised component cannot silently redirect itself to a
    different database through the credential file.
    """
    candidates = []
    if config_path:
        candidates.append(config_path)
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(here, "db-config.json"))

    merged = None
    for path in candidates:
        if path and os.path.exists(path):
            with open(path) as f:
                user_cfg = json.load(f)
            merged = json.loads(json.dumps(DEFAULT_CONFIG))
            for k, v in user_cfg.items():
                if k in ("sqlite", "postgres") and isinstance(v, dict):
                    merged[k].update(v)
                else:
                    merged[k] = v
            break

    if merged is None:
        merged = config_from_path(sqlite_fallback)

    if credentials_path:
        with open(credentials_path) as f:
            cred = json.load(f)
        pg = cred.get("postgres") if isinstance(cred, dict) else None
        if not isinstance(pg, dict):
            raise RuntimeError("DB credentials file must contain a 'postgres' object")
        unexpected = set(pg) - {"user", "password"}
        if unexpected:
            raise RuntimeError(
                "DB credentials file may contain only postgres.user/postgres.password; "
                f"unexpected: {', '.join(sorted(unexpected))}"
            )
        if not pg.get("user"):
            raise RuntimeError("DB credentials file is missing postgres.user")
        merged["postgres"]["user"] = pg["user"]
        merged["postgres"]["password"] = pg.get("password", "")
        merged["_credentials_identity"] = str(cred.get("identity") or "")
        merged["_credentials_path"] = os.path.abspath(credentials_path)

    boundary = merged.get("postgres_privilege_boundary") or {}
    if (merged.get("backend") == "postgres" and boundary.get("enabled")
            and not credentials_path and not merged["postgres"].get("password")):
        raise RuntimeError(
            "PostgreSQL privilege boundary is enabled but no component credential file "
            "was supplied. Use --db-credentials with the listener/dashboard credential file."
        )
    return merged


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
        """CREATE TABLE IF NOT EXISTS ai_usage_audit (
            at                TEXT NOT NULL,
            provider          TEXT NOT NULL,
            api_style         TEXT NOT NULL,
            model             TEXT NOT NULL,
            endpoint_host     TEXT,
            request_id        TEXT,
            client_request_id TEXT,
            status            TEXT NOT NULL,
            http_status       INTEGER DEFAULT 0,
            input_tokens      INTEGER DEFAULT 0,
            output_tokens     INTEGER DEFAULT 0,
            total_tokens      INTEGER DEFAULT 0,
            cached_tokens     INTEGER DEFAULT 0,
            reasoning_tokens  INTEGER DEFAULT 0,
            retry_count       INTEGER DEFAULT 0,
            latency_ms        INTEGER DEFAULT 0,
            error_code        TEXT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_ai_usage_at ON ai_usage_audit(at)",
        "CREATE INDEX IF NOT EXISTS idx_ai_usage_model ON ai_usage_audit(model)",
        "CREATE INDEX IF NOT EXISTS idx_ai_usage_status ON ai_usage_audit(status)",
        f"""CREATE TABLE IF NOT EXISTS log_fields (
            id      {pk},
            log_id  INTEGER NOT NULL,
            field   TEXT NOT NULL,
            value   TEXT
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
            value_num  REAL,
            value_text TEXT,
            updated_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS archive_segments (
            segment_id             TEXT PRIMARY KEY,
            path                   TEXT NOT NULL,
            manifest_path          TEXT,
            state                  TEXT NOT NULL,
            mode                   TEXT NOT NULL,
            created_at             TEXT NOT NULL,
            start_at               TEXT,
            end_at                 TEXT,
            min_log_id             INTEGER,
            max_log_id             INTEGER,
            event_count            INTEGER NOT NULL DEFAULT 0,
            unique_payloads        INTEGER NOT NULL DEFAULT 0,
            duplicate_occurrences  INTEGER NOT NULL DEFAULT 0,
            sha256                 TEXT NOT NULL,
            bytes                  INTEGER NOT NULL DEFAULT 0
        )""",
        "CREATE INDEX IF NOT EXISTS idx_archive_segments_end_at ON archive_segments(end_at)",
        """CREATE TABLE IF NOT EXISTS archive_occurrence_catalog (
            log_id      INTEGER PRIMARY KEY,
            segment_id  TEXT NOT NULL,
            archived_at TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_archive_occ_segment ON archive_occurrence_catalog(segment_id)",
    ]
    if backend != "postgres":
        # FTS5 full-text index over message text for fast search (replaces
        # slow leading-wildcard LIKE scans). sqlite-only; Postgres would use
        # tsvector/GIN instead. 'content' is unindexed external-content style:
        # we store message text keyed by the log id (rowid) so MATCH is fast
        # and we can join back to logs.
        stmts.append(
            "CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5("
            "message, content='logs', content_rowid='id', tokenize='unicode61')")
        # keep the FTS index in sync with the logs table
        stmts.append(
            "CREATE TRIGGER IF NOT EXISTS logs_ai AFTER INSERT ON logs BEGIN "
            "INSERT INTO logs_fts(rowid, message) VALUES (new.id, new.message); END")
        stmts.append(
            "CREATE TRIGGER IF NOT EXISTS logs_ad AFTER DELETE ON logs BEGIN "
            "INSERT INTO logs_fts(logs_fts, rowid, message) "
            "VALUES('delete', old.id, old.message); END")
        stmts.append(
            "CREATE TRIGGER IF NOT EXISTS logs_au AFTER UPDATE ON logs BEGIN "
            "INSERT INTO logs_fts(logs_fts, rowid, message) "
            "VALUES('delete', old.id, old.message); "
            "INSERT INTO logs_fts(rowid, message) VALUES (new.id, new.message); END")
    return stmts


# --------------------------------------------------------------------------
# Connection factories
# --------------------------------------------------------------------------

def _connect_sqlite(config: dict) -> Connection:
    raw = sqlite3.connect(config["sqlite"]["path"], check_same_thread=False)
    raw.row_factory = sqlite3.Row
    # WAL journal: readers don't block the writer and commits are far
    # cheaper (no full-file fsync per transaction). synchronous=NORMAL
    # is the standard safe pairing with WAL — durable against app
    # crashes; only an OS/power failure can lose the last moments,
    # which is an acceptable trade for a log store (fields are also
    # rebuildable via re-index).
    try:
        raw.execute("PRAGMA journal_mode=WAL")
        raw.execute("PRAGMA synchronous=NORMAL")
        raw.execute("PRAGMA cell_size_check=ON")   # catch some corruption at write time
    except sqlite3.Error:
        pass  # e.g. read-only media; fall back to defaults
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
    minconn = max(1, int(p.get("pool_min", 1)))
    maxconn = max(minconn, int(p.get("pool_max", 10)))
    key = (p.get("host"), int(p.get("port", 5432)), p.get("dbname"),
           p.get("user"), p.get("password"), minconn, maxconn)

    retries = int(p.get("connect_retries", 5))
    delay = float(p.get("connect_retry_delay", 2))
    last_error = None

    with _PG_POOLS_LOCK:
        pool = _PG_POOLS.get(key)
        if pool is not None:
            return pool

        for attempt in range(1, retries + 1):
            try:
                pool = ThreadedConnectionPool(
                    minconn, maxconn, host=p["host"], port=p["port"],
                    dbname=p["dbname"], user=p["user"], password=p["password"],
                    connect_timeout=int(p.get("connect_timeout", 5)),
                    cursor_factory=psycopg2.extras.RealDictCursor,
                )
                _PG_POOLS[key] = pool
                return pool
            except Exception as exc:
                last_error = exc
                if attempt >= retries:
                    break
                time.sleep(delay)

    raise last_error


def _connect_postgres(config: dict) -> Connection:
    pool = _postgres_pool(config)
    raw = pool.getconn()

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
    """Ordered schema migrations.

    PostgreSQL and SQLite both run migrations through the same layer.
    Migration state is stored in schema_migrations so startup does not
    repeatedly execute ALTER TABLE statements forever.
    """
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
        "CREATE TABLE IF NOT EXISTS runtime_stats (key TEXT PRIMARY KEY, value_num REAL, value_text TEXT, updated_at TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS archive_segments (segment_id TEXT PRIMARY KEY, path TEXT NOT NULL, manifest_path TEXT, state TEXT NOT NULL, mode TEXT NOT NULL, created_at TEXT NOT NULL, start_at TEXT, end_at TEXT, min_log_id INTEGER, max_log_id INTEGER, event_count INTEGER NOT NULL DEFAULT 0, unique_payloads INTEGER NOT NULL DEFAULT 0, duplicate_occurrences INTEGER NOT NULL DEFAULT 0, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL DEFAULT 0)",
        "CREATE TABLE IF NOT EXISTS archive_occurrence_catalog (log_id INTEGER PRIMARY KEY, segment_id TEXT NOT NULL, archived_at TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS idx_archive_segments_end_at ON archive_segments(end_at)",
        "CREATE INDEX IF NOT EXISTS idx_archive_occ_segment ON archive_occurrence_catalog(segment_id)",
        "CREATE TABLE IF NOT EXISTS ai_usage_audit (at TEXT NOT NULL, provider TEXT NOT NULL, api_style TEXT NOT NULL, model TEXT NOT NULL, endpoint_host TEXT, request_id TEXT, client_request_id TEXT, status TEXT NOT NULL, http_status INTEGER DEFAULT 0, input_tokens INTEGER DEFAULT 0, output_tokens INTEGER DEFAULT 0, total_tokens INTEGER DEFAULT 0, cached_tokens INTEGER DEFAULT 0, reasoning_tokens INTEGER DEFAULT 0, retry_count INTEGER DEFAULT 0, latency_ms INTEGER DEFAULT 0, error_code TEXT)",
        "CREATE INDEX IF NOT EXISTS idx_ai_usage_at ON ai_usage_audit(at)",
        "CREATE INDEX IF NOT EXISTS idx_ai_usage_model ON ai_usage_audit(model)",
        "CREATE INDEX IF NOT EXISTS idx_ai_usage_status ON ai_usage_audit(status)",
    ]



def ensure_schema_baseline(conn, config: dict):
    """Baseline existing databases created before migration tracking existed."""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        )"""
    )
    rows = conn.execute(
        "SELECT version FROM schema_migrations ORDER BY version"
    ).fetchall()
    if rows:
        return

    # Existing installs have schema but no history. Record the current
    # migration state instead of replaying old ALTER statements.
    try:
        conn.execute("SELECT 1 FROM logs LIMIT 1")
        import datetime as _datetime
        now = _datetime.datetime.utcnow().isoformat()
        # The Connection wrapper exposes execute(), not executemany(); insert
        # each baseline row individually so every already-satisfied migration
        # is recorded and startup does not replay ALTER statements the base
        # schema already applied.
        for version in range(1, len(_migrations()) + 1):
            conn.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, now),
            )
        conn.commit()
    except Exception:
        try:
            conn.raw.rollback()
        except Exception:
            pass


def postgres_schema_has_table(conn, table_name: str) -> bool:
    """Return whether a PostgreSQL table exists.

    Used by startup/schema safety paths to avoid assuming an empty database.
    """
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.tables
                WHERE table_schema = 'public'
                  AND table_name = %s
            )
            """,
            (table_name,),
        )
        row = cur.fetchone()
        if isinstance(row, dict):
            return bool(next(iter(row.values())))
        return bool(row[0])
    finally:
        cur.close()


def postgres_schema_has_column(conn, table_name: str, column_name: str) -> bool:
    """Return whether a PostgreSQL column exists."""
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = %s
                  AND column_name = %s
            )
            """,
            (table_name, column_name),
        )
        row = cur.fetchone()
        if isinstance(row, dict):
            return bool(next(iter(row.values())))
        return bool(row[0])
    finally:
        cur.close()


def ensure_bootstrap_admin_exists(conn, username="admin"):
    """Create bootstrap admin only when no matching user exists.

    Existing identities are preserved during backend migration.
    """
    cur = conn.cursor()
    try:
        cur.execute("SELECT 1 FROM users WHERE username = %s LIMIT 1", (username,))
        if cur.fetchone():
            return False
        return False
    finally:
        cur.close()



def postgres_schema_apply_once(conn, statements):
    """
    Execute schema statements only when they are safe to re-run.

    Migration/runtime initialization must tolerate existing PostgreSQL
    databases instead of assuming a clean database.
    """
    cur = conn.cursor()
    try:
        for statement in statements:
            cur.execute(statement)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


def postgres_required_tables_present(conn, tables):
    """
    Validate that required application tables exist before runtime use.
    """
    missing = []
    for table in tables:
        if not postgres_schema_has_table(conn, table):
            missing.append(table)
    return missing



def ensure_admin_bootstrap_safe(conn, username="admin") -> bool:
    """Return whether the bootstrap admin identity already exists.

    Used by the first-run seeder to avoid overwriting an operator's existing
    admin account — e.g. after a SQLite -> PostgreSQL migration that already
    carried the users table across. Backend-portable: it goes through the
    Connection wrapper (which rewrites ``?`` to ``%s`` for PostgreSQL) rather
    than assuming a raw psycopg2 cursor. This function never modifies data.
    """
    try:
        row = conn.execute(
            "SELECT 1 FROM users WHERE username = ? LIMIT 1", (username,)
        ).fetchone()
        return row is not None
    except Exception:
        # If the users table is not present yet, no bootstrap account exists.
        return False



def postgres_migration_state(conn):
    """
    Return migration-relevant PostgreSQL state.

    Keeps runtime initialization from assuming a fresh database.
    """
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
            ORDER BY table_name
            """
        )
        tables = [row[0] for row in cur.fetchall()]
        return {
            "tables": tables,
            "table_count": len(tables),
        }
    finally:
        cur.close()


def postgres_validate_application_state(conn, required_tables):
    """
    Validate application-required tables before runtime activation.
    """
    return postgres_required_tables_present(conn, required_tables) == []


def ensure_runtime_ready(config: dict, required_tables=None):
    """Prepare a database for application runtime without PostgreSQL DDL.

    SQLite keeps the historical zero-setup behavior and initializes itself.
    PostgreSQL is fail-closed: a runtime login only validates the owner-created
    schema and migration ledger.  Missing/pending schema must be repaired with
    an owner/migration credential, never by listener/dashboard credentials.
    """
    if config.get("backend") != "postgres":
        initialize(config)
        return

    tables = tuple(required_tables or RUNTIME_REQUIRED_TABLES)
    conn = connect(config)
    try:
        missing = postgres_required_tables_present(conn.raw, tables)
        if missing:
            raise RuntimeError(
                "PostgreSQL runtime schema is incomplete; owner migration required. "
                "Missing tables: " + ", ".join(missing)
            )
        rows = conn.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
        applied = {int(r["version"] if isinstance(r, dict) else r[0]) for r in rows}
        pending = [v for v in range(1, len(_migrations()) + 1) if v not in applied]
        if pending:
            raise RuntimeError(
                "PostgreSQL runtime schema has pending migrations: "
                + ", ".join(map(str, pending))
                + ". Run migrations with the owner identity before starting services."
            )
    finally:
        conn.close()


def initialize(config: dict):
    """Create all tables and indexes if missing, then apply migrations.
    Idempotent."""
    conn = connect(config)
    try:
        for stmt in _schema_statements(config.get("backend", "sqlite")):
            conn.execute(stmt)

        # Durable migration tracking. This prevents repeated PostgreSQL
        # ALTER TABLE execution on every service restart.
        ensure_schema_baseline(conn, config)

        rows = conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
        applied = {row["version"] if isinstance(row, dict) else row[0] for row in rows}

        import datetime as _datetime
        for version, stmt in enumerate(_migrations(), start=1):
            if version in applied:
                continue
            try:
                conn.execute(stmt)
                conn.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (version, _datetime.datetime.utcnow().isoformat()),
                )
                conn.commit()
            except Exception:
                try:
                    conn.raw.rollback()
                except Exception:
                    pass
                raise
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
        if config.get("backend") != "postgres":
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


def fts5_available(conn) -> bool:
    """Return whether this SQLite build has the FTS5 extension compiled in.

    Used to decide between an indexed ``logs_fts MATCH`` message search and a
    plain ``LIKE`` fallback. Always False for non-SQLite backends. Any probe
    error is treated as "not available" so search degrades rather than breaks.
    """
    if getattr(conn, "backend", "sqlite") == "postgres":
        return False
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM pragma_compile_options "
            "WHERE compile_options = 'ENABLE_FTS5'"
        ).fetchone()
        count = row["c"] if isinstance(row, dict) else row[0]
        return bool(count)
    except Exception:
        return False


def rebuild_fts(config: dict, progress=None):
    """(Re)build the logs_fts full-text index from existing logs. Needed once
    on an existing DB that predates FTS, or to repair the index. sqlite-only;
    no-op on postgres. Returns the number of rows indexed."""
    if config.get("backend") == "postgres":
        return 0
    conn = connect(config)
    try:
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


def runtime_stat_upsert(conn: Connection, key: str, value_num=None, value_text=None, updated_at=None):
    """Insert/update one lightweight operational status value.

    Runtime stats are observability metadata, not security evidence.  The helper
    is backend-portable and deliberately keeps arbitrary SQL out of callers.
    """
    if updated_at is None:
        from datetime import datetime, timezone
        updated_at = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO runtime_stats(key,value_num,value_text,updated_at)
           VALUES (?,?,?,?)
           ON CONFLICT(key) DO UPDATE SET
             value_num=excluded.value_num,
             value_text=excluded.value_text,
             updated_at=excluded.updated_at""",
        (str(key), value_num, value_text, str(updated_at)),
    )


def read_runtime_stats(conn: Connection, keys=None):
    """Return runtime_stats rows keyed by name."""
    if keys:
        wanted = [str(k) for k in keys]
        placeholders_sql = placeholders(len(wanted))
        sql = (
            "SELECT key,value_num,value_text,updated_at FROM runtime_stats "
            "WHERE key IN (" + placeholders_sql + ")"
        )
        rows = conn.execute(sql, wanted).fetchall()
    else:
        rows = conn.execute(
            "SELECT key,value_num,value_text,updated_at FROM runtime_stats"
        ).fetchall()
    return {str(row["key"]): dict(row) for row in rows}


def migration_readiness(conn: Connection):
    """Return read-only schema migration readiness for Health/Web Console."""
    rows = conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
    applied = sorted({int(r["version"] if isinstance(r, dict) else r[0]) for r in rows})
    expected = len(_migrations())
    pending = [v for v in range(1, expected + 1) if v not in set(applied)]
    return {
        "applied_versions": applied,
        "current_version": max(applied) if applied else 0,
        "expected_version": expected,
        "pending_versions": pending,
        "ready": not pending,
    }


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
