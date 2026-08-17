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
                if k in ("sqlite", "postgres") and isinstance(v, dict):
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

    def __init__(self, raw, backend: str):
        self.raw = raw
        self.backend = backend

    def _sql(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.backend == "postgres" else sql

    def execute(self, sql: str, params=()):
        sql = self._sql(sql)
        if self.backend == "postgres":
            cur = self.raw.cursor()
            cur.execute(sql, params)
            return cur
        return self.raw.execute(sql, params)

    def insert_returning_id(self, sql: str, params=()):
        """Run an INSERT and return the new row's integer id."""
        if self.backend == "postgres":
            cur = self.raw.cursor()
            cur.execute(self._sql(sql) + " RETURNING id", params)
            row = cur.fetchone()
            return row["id"] if isinstance(row, dict) else row[0]
        cur = self.raw.execute(sql, params)
        return cur.lastrowid

    def commit(self):
        self.raw.commit()

    def close(self):
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


def _connect_postgres(config: dict) -> Connection:
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError as exc:
        raise RuntimeError(
            "PostgreSQL backend selected but psycopg2 is not installed. "
            "Run: pip install psycopg2-binary"
        ) from exc
    p = config["postgres"]
    raw = psycopg2.connect(
        host=p["host"], port=p["port"], dbname=p["dbname"],
        user=p["user"], password=p["password"],
        cursor_factory=psycopg2.extras.RealDictCursor,
    )
    return Connection(raw, "postgres")


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


def initialize(config: dict):
    """Create all tables and indexes if missing, then apply migrations.
    Idempotent."""
    conn = connect(config)
    try:
        for stmt in _schema_statements(config.get("backend", "sqlite")):
            conn.execute(stmt)
        conn.commit()
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


def integrity_check(config: dict, quick: bool = True):
    """Run SQLite's self-verification. Returns (ok: bool, detail: str).
    For postgres, reports that the check is sqlite-only."""
    if config.get("backend") == "postgres":
        return True, "integrity_check is a SQLite feature; PostgreSQL manages its own integrity."
    try:
        conn = connect(config)
        pragma = "quick_check" if quick else "integrity_check"
        rows = conn.execute(f"PRAGMA {pragma}").fetchall()
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
    """Returns (ok: bool, detail: str)."""
    try:
        conn = connect(config)
        conn.execute("SELECT 1")
        conn.close()
        return True, f"Connected: {describe(config)}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
