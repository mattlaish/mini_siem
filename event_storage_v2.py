"""PostgreSQL Event Storage v2 for mini-SIEM.

This module deliberately keeps the historical ``logs`` / ``log_fields`` tables
as the raw evidence plane while adding a typed, partitioned PostgreSQL query
projection.  SQLite is unchanged.

Runtime invariants:
* raw evidence and the base typed projection are appended in the same DB
  transaction by the listener/storage path;
* normal runtime identities never run general DDL;
* partition creation is exposed only through a bounded owner-defined function;
* archived evidence remains authoritative even after the hot projection is
  evicted.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import re
from typing import Any


SEVERITY_SCORE = {
    "debug": 7,
    "informational": 6,
    "info": 6,
    "notice": 5,
    "warning": 4,
    "warn": 4,
    "error": 3,
    "err": 3,
    "critical": 2,
    "crit": 2,
    "alert": 1,
    "emergency": 0,
    "emerg": 0,
}

USER_FIELD_NAMES = (
    "user", "username", "user_name", "suser", "account", "account_name",
    "subjectusername", "targetusername", "principal",
)
SRC_PORT_FIELDS = ("src_port", "source_port", "sport", "spt")
DST_PORT_FIELDS = ("dst_port", "destination_port", "dport", "dpt")
EVENT_CODE_FIELDS = ("event_code", "event_id", "eventid", "signature_id", "sid")
EVENT_TYPE_FIELDS = ("event_type", "event_name", "action", "category", "type")


def postgres_schema_statements() -> list[str]:
    """Return idempotent owner-only PostgreSQL DDL for Event Storage v2."""
    return [
        """CREATE TABLE IF NOT EXISTS assets (
            id BIGSERIAL PRIMARY KEY,
            primary_ip INET UNIQUE,
            hostname TEXT,
            first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_seen TIMESTAMPTZ NOT NULL DEFAULT now()
        )""",
        "CREATE INDEX IF NOT EXISTS idx_assets_hostname_lower ON assets(lower(hostname))",
        """CREATE TABLE IF NOT EXISTS identities (
            id BIGSERIAL PRIMARY KEY,
            identity_key TEXT NOT NULL UNIQUE,
            user_name TEXT NOT NULL,
            first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_seen TIMESTAMPTZ NOT NULL DEFAULT now()
        )""",
        "CREATE INDEX IF NOT EXISTS idx_identities_user_lower ON identities(lower(user_name))",
        """CREATE TABLE IF NOT EXISTS security_events (
            id BIGINT GENERATED ALWAYS AS IDENTITY,
            legacy_log_id BIGINT NOT NULL,
            event_time TIMESTAMPTZ NOT NULL,
            ingested_at TIMESTAMPTZ NOT NULL,
            src_ip INET,
            dst_ip INET,
            peer_ip INET,
            src_port INTEGER,
            dst_port INTEGER,
            hostname TEXT,
            user_name TEXT,
            vendor TEXT,
            product TEXT,
            event_type TEXT,
            event_code TEXT,
            severity SMALLINT,
            severity_text TEXT,
            format TEXT,
            priority INTEGER,
            facility TEXT,
            device_timestamp TEXT,
            destination TEXT,
            app_name TEXT,
            proc_id TEXT,
            msg_id TEXT,
            message TEXT,
            raw_event TEXT,
            fields JSONB NOT NULL DEFAULT '{}'::jsonb,
            asset_id BIGINT REFERENCES assets(id),
            identity_id BIGINT REFERENCES identities(id),
            PRIMARY KEY (event_time, id)
        ) PARTITION BY RANGE (event_time)""",
        """CREATE TABLE IF NOT EXISTS security_events_default
            PARTITION OF security_events DEFAULT""",
        "CREATE INDEX IF NOT EXISTS idx_se_legacy_log_id ON security_events(legacy_log_id)",
        "CREATE INDEX IF NOT EXISTS idx_se_src_ip_time ON security_events(src_ip, event_time DESC)",
        "CREATE INDEX IF NOT EXISTS idx_se_dst_ip_time ON security_events(dst_ip, event_time DESC)",
        "CREATE INDEX IF NOT EXISTS idx_se_peer_ip_time ON security_events(peer_ip, event_time DESC)",
        "CREATE INDEX IF NOT EXISTS idx_se_asset_time ON security_events(asset_id, event_time DESC)",
        "CREATE INDEX IF NOT EXISTS idx_se_identity_time ON security_events(identity_id, event_time DESC)",
        "CREATE INDEX IF NOT EXISTS idx_se_type_time ON security_events(event_type, event_time DESC)",
        "CREATE INDEX IF NOT EXISTS idx_se_user_time ON security_events(lower(user_name), event_time DESC)",
        "CREATE INDEX IF NOT EXISTS idx_se_vendor_product_time ON security_events(vendor, product, event_time DESC)",
        "CREATE INDEX IF NOT EXISTS idx_se_code_time ON security_events(event_code, event_time DESC)",
        "CREATE INDEX IF NOT EXISTS idx_se_hostname_prefix_time ON security_events(lower(hostname) text_pattern_ops, event_time DESC)",
        "CREATE INDEX IF NOT EXISTS idx_se_destination_prefix_time ON security_events(lower(destination) text_pattern_ops, event_time DESC)",
        "CREATE INDEX IF NOT EXISTS idx_se_message_fts_gin ON security_events USING GIN(to_tsvector('simple', COALESCE(message,'')))",
        """CREATE OR REPLACE VIEW security_event_logs AS
            SELECT legacy_log_id AS id,
                   event_time,
                   ingested_at,
                   event_time::text AS received_at,
                   src_ip, src_ip::text AS source_ip,
                   dst_ip, peer_ip AS peer_ip_native, peer_ip::text AS peer_ip,
                   format, priority, facility,
                   severity_text AS severity,
                   device_timestamp, hostname, destination, app_name,
                   proc_id, msg_id, message, raw_event AS raw,
                   dst_ip::text AS destination_ip,
                   src_port, dst_port, user_name, vendor, product,
                   event_type, event_code, asset_id, identity_id, fields
              FROM security_events""",
        """CREATE OR REPLACE VIEW security_event_context AS
            SELECT e.*,
                   a.hostname AS asset_hostname,
                   a.primary_ip::text AS asset_primary_ip,
                   i.user_name AS identity_user_name
              FROM security_event_logs e
              LEFT JOIN assets a ON a.id=e.asset_id
              LEFT JOIN identities i ON i.id=e.identity_id""",
        """CREATE OR REPLACE FUNCTION public.minisiem_ensure_security_event_partitions(
                p_start TIMESTAMPTZ DEFAULT now(), p_months INTEGER DEFAULT 3)
            RETURNS INTEGER
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $fn$
            DECLARE
                i INTEGER;
                start_at TIMESTAMPTZ;
                end_at TIMESTAMPTZ;
                part_name TEXT;
                made INTEGER := 0;
            BEGIN
                IF p_months < 1 OR p_months > 24 THEN
                    RAISE EXCEPTION 'p_months must be between 1 and 24';
                END IF;
                start_at := date_trunc('month', p_start);
                FOR i IN 0..p_months-1 LOOP
                    end_at := start_at + INTERVAL '1 month';
                    part_name := 'security_events_' || to_char(start_at AT TIME ZONE 'UTC', 'YYYY_MM');
                    IF to_regclass('public.' || part_name) IS NULL THEN
                        EXECUTE format(
                            'CREATE TABLE public.%I PARTITION OF public.security_events FOR VALUES FROM (%L) TO (%L)',
                            part_name, start_at, end_at
                        );
                        made := made + 1;
                    END IF;
                    start_at := end_at;
                END LOOP;
                RETURN made;
            END
            $fn$""",
        "REVOKE ALL ON FUNCTION public.minisiem_ensure_security_event_partitions(TIMESTAMPTZ, INTEGER) FROM PUBLIC",
    ]


def _clean_ip(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _port(value: Any) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _field(fields: dict | None, names: tuple[str, ...]) -> str:
    if not fields:
        return ""
    lower = {str(k).lower(): v for k, v in fields.items()}
    for name in names:
        value = lower.get(name)
        if value not in (None, ""):
            return str(value)
    return ""


def _iso_time(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        # PostgreSQL accepts ISO-8601 text directly; validation here avoids
        # routing RFC3164 timestamps without year/tz as misleading event time.
        probe = text.replace("Z", "+00:00")
        dt = datetime.fromisoformat(probe)
        if dt.tzinfo is None:
            return None
        return dt.astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def normalized_projection(event: dict, fields: dict | None = None) -> dict:
    fields = dict(fields or {})
    received = _iso_time(event.get("received_at")) or datetime.now(timezone.utc).isoformat()
    event_time = _iso_time(event.get("device_timestamp")) or received
    dst_candidate = event.get("destination_ip") or event.get("destination") or _field(
        fields, ("dst", "dst_ip", "dstip", "destination_ip", "dest_ip")
    )
    user = event.get("username") or _field(fields, USER_FIELD_NAMES)
    vendor = event.get("device_vendor") or _field(fields, ("vendor", "device_vendor"))
    product = event.get("device_product") or _field(fields, ("product", "device_product"))
    event_type = event.get("event_name") or event.get("action") or _field(fields, EVENT_TYPE_FIELDS)
    event_code = event.get("signature_id") or _field(fields, EVENT_CODE_FIELDS) or event.get("msg_id")
    src_port = event.get("source_port") or _field(fields, SRC_PORT_FIELDS)
    dst_port = event.get("destination_port") or _field(fields, DST_PORT_FIELDS)
    sev_text = str(event.get("severity") or "").strip()
    sev_score = SEVERITY_SCORE.get(sev_text.lower())
    if sev_score is None and sev_text.isdigit():
        n = int(sev_text)
        sev_score = max(0, min(10, n))
    return {
        "event_time": event_time,
        "ingested_at": received,
        "src_ip": _clean_ip(event.get("source_ip")),
        "dst_ip": _clean_ip(dst_candidate),
        "peer_ip": _clean_ip(event.get("peer_ip")),
        "src_port": _port(src_port),
        "dst_port": _port(dst_port),
        "hostname": str(event.get("hostname") or "") or None,
        "user_name": str(user or "") or None,
        "vendor": str(vendor or "") or None,
        "product": str(product or "") or None,
        "event_type": str(event_type or "") or None,
        "event_code": str(event_code or "") or None,
        "severity": sev_score,
        "severity_text": sev_text or None,
        "format": str(event.get("format") or "") or None,
        "priority": event.get("priority"),
        "facility": str(event.get("facility") or "") or None,
        "device_timestamp": str(event.get("device_timestamp") or "") or None,
        "destination": str(event.get("destination") or "") or None,
        "app_name": str(event.get("app_name") or "") or None,
        "proc_id": str(event.get("proc_id") or "") or None,
        "msg_id": str(event.get("msg_id") or "") or None,
        "message": str(event.get("message") or ""),
        "raw_event": str(event.get("raw") or ""),
        "fields": fields,
    }


def _observe_asset(conn, projection: dict) -> int | None:
    # The network sender is the safest asset observation. source_ip may be an
    # actor extracted from the event payload and must not be mistaken for the
    # emitting asset.
    ip = projection.get("peer_ip")
    if not ip:
        return None
    row = conn.execute(
        """INSERT INTO assets(primary_ip,hostname,first_seen,last_seen)
           VALUES (?::inet, ?, ?::timestamptz, ?::timestamptz)
           ON CONFLICT(primary_ip) DO UPDATE SET
             hostname=COALESCE(NULLIF(excluded.hostname,''), assets.hostname),
             last_seen=GREATEST(assets.last_seen, excluded.last_seen)
           RETURNING id""",
        (ip, projection.get("hostname"), projection["event_time"], projection["event_time"]),
    ).fetchone()
    return int(row["id"] if isinstance(row, dict) else row[0])


def _observe_identity(conn, projection: dict) -> int | None:
    user = str(projection.get("user_name") or "").strip()
    if not user:
        return None
    key = user.casefold()
    row = conn.execute(
        """INSERT INTO identities(identity_key,user_name,first_seen,last_seen)
           VALUES (?, ?, ?::timestamptz, ?::timestamptz)
           ON CONFLICT(identity_key) DO UPDATE SET
             user_name=excluded.user_name,
             last_seen=GREATEST(identities.last_seen, excluded.last_seen)
           RETURNING id""",
        (key, user, projection["event_time"], projection["event_time"]),
    ).fetchone()
    return int(row["id"] if isinstance(row, dict) else row[0])


def append_projection(conn, log_id: int, event: dict, fields: dict | None = None) -> int:
    """Append the typed projection for one raw log using the caller transaction.

    Returns 1 when inserted, 0 when an idempotent backfill finds an existing
    projection for the legacy evidence id.
    """
    if getattr(conn, "backend", "sqlite") != "postgres":
        return 0
    p = normalized_projection(event, fields)
    asset_id = _observe_asset(conn, p)
    identity_id = _observe_identity(conn, p)
    payload = json.dumps(p["fields"], ensure_ascii=False, sort_keys=True)
    cur = conn.execute(
        """INSERT INTO security_events(
               legacy_log_id,event_time,ingested_at,src_ip,dst_ip,peer_ip,src_port,dst_port,
               hostname,user_name,vendor,product,event_type,event_code,severity,severity_text,
               format,priority,facility,device_timestamp,destination,app_name,proc_id,msg_id,
               message,raw_event,fields,asset_id,identity_id)
           SELECT ?,?::timestamptz,?::timestamptz,?::inet,?::inet,?::inet,?,?,
                  ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?::jsonb,?,?
            WHERE NOT EXISTS (
                SELECT 1 FROM security_events WHERE legacy_log_id=? LIMIT 1
            )""",
        (
            int(log_id), p["event_time"], p["ingested_at"], p["src_ip"], p["dst_ip"], p["peer_ip"],
            p["src_port"], p["dst_port"], p["hostname"], p["user_name"], p["vendor"], p["product"],
            p["event_type"], p["event_code"], p["severity"], p["severity_text"], p["format"],
            p["priority"], p["facility"], p["device_timestamp"], p["destination"], p["app_name"],
            p["proc_id"], p["msg_id"], p["message"], p["raw_event"], payload, asset_id, identity_id,
            int(log_id),
        ),
    )
    return max(0, int(getattr(cur, "rowcount", 0) or 0))


def update_projection_fields(conn, log_id: int, event: dict, fields: dict) -> None:
    """Refresh dynamic JSONB / typed derivatives after field extraction."""
    if getattr(conn, "backend", "sqlite") != "postgres":
        return
    p = normalized_projection(event, fields)
    identity_id = _observe_identity(conn, p)
    conn.execute(
        """UPDATE security_events
              SET fields=?::jsonb,
                  user_name=COALESCE(?, user_name),
                  identity_id=COALESCE(?, identity_id),
                  src_port=COALESCE(?, src_port),
                  dst_port=COALESCE(?, dst_port),
                  event_type=COALESCE(?, event_type),
                  event_code=COALESCE(?, event_code),
                  vendor=COALESCE(?, vendor),
                  product=COALESCE(?, product)
            WHERE legacy_log_id=?""",
        (
            json.dumps(fields or {}, ensure_ascii=False, sort_keys=True), p["user_name"], identity_id,
            p["src_port"], p["dst_port"], p["event_type"], p["event_code"], p["vendor"], p["product"],
            int(log_id),
        ),
    )


def ensure_partitions_owner(conn, months: int = 3) -> int:
    if getattr(conn, "backend", "sqlite") != "postgres":
        return 0
    row = conn.execute(
        "SELECT public.minisiem_ensure_security_event_partitions(date_trunc('month', now()), ?)",
        (int(months),),
    ).fetchone()
    if not row:
        return 0
    return int(next(iter(row.values())) if isinstance(row, dict) else row[0])
