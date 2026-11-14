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

from datetime import datetime, timedelta, timezone
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

RETIRED_EVENT_INDEXES = (
    "idx_se_src_cidr", "idx_se_dst_cidr", "idx_se_peer_ip_time", "idx_se_asset_time",
    "idx_se_identity_time", "idx_se_type_time", "idx_se_user_time",
    "idx_se_vendor_product_time", "idx_se_code_time",
)


def postgres_schema_statements() -> list[str]:
    """Return idempotent owner-only PostgreSQL DDL for Event Storage v2."""
    return [
        "ALTER TABLE logs ADD COLUMN IF NOT EXISTS projection_time TIMESTAMPTZ",
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
            device_event_time TIMESTAMPTZ,
            destination TEXT,
            app_name TEXT,
            proc_id TEXT,
            msg_id TEXT,
            message_terms TSVECTOR,
            fields JSONB NOT NULL DEFAULT '{}'::jsonb,
            asset_id BIGINT REFERENCES assets(id),
            identity_id BIGINT REFERENCES identities(id),
            PRIMARY KEY (event_time, id)
        ) PARTITION BY RANGE (event_time)""",
        """CREATE TABLE IF NOT EXISTS security_events_default
            PARTITION OF security_events DEFAULT""",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS search_fields JSONB",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS device_event_time TIMESTAMPTZ",
        "ALTER TABLE security_events ADD COLUMN IF NOT EXISTS message_terms TSVECTOR",
        "CREATE INDEX IF NOT EXISTS idx_se_search_fields_gin ON security_events USING GIN(search_fields jsonb_path_ops)",
        "CREATE INDEX IF NOT EXISTS idx_se_search_fields_pending ON security_events(event_time, legacy_log_id) WHERE search_fields IS NULL",
        "CREATE INDEX IF NOT EXISTS idx_se_src_port_time ON security_events(src_port,event_time DESC)",
        "CREATE INDEX IF NOT EXISTS idx_se_dst_port_time ON security_events(dst_port,event_time DESC)",
        "CREATE INDEX IF NOT EXISTS idx_se_legacy_log_id ON security_events(legacy_log_id)",
        "CREATE INDEX IF NOT EXISTS idx_se_src_ip_time ON security_events(src_ip, event_time DESC)",
        "CREATE INDEX IF NOT EXISTS idx_se_dst_ip_time ON security_events(dst_ip, event_time DESC)",
        "CREATE INDEX IF NOT EXISTS idx_se_hostname_prefix_time ON security_events(lower(hostname) text_pattern_ops, event_time DESC)",
        "CREATE INDEX IF NOT EXISTS idx_se_destination_prefix_time ON security_events(lower(destination) text_pattern_ops, event_time DESC)",
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
                   proc_id, msg_id,
                   COALESCE((SELECT l.message FROM logs l WHERE l.id=legacy_log_id),'') AS message,
                   COALESCE((SELECT l.raw FROM logs l WHERE l.id=legacy_log_id),'') AS raw,
                   dst_ip::text AS destination_ip,
                   src_port, dst_port, user_name, vendor, product,
                   event_type, event_code, asset_id, identity_id, fields, search_fields,
                   message_terms, device_event_time
              FROM security_events""",
        """DO $ddl$ BEGIN
            IF EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='public.security_events'::regclass
                       AND attname='message' AND NOT attisdropped) THEN
                IF EXISTS (
                    SELECT 1 FROM public.security_events e
                    LEFT JOIN public.logs l ON l.id=e.legacy_log_id
                    WHERE l.id IS NULL OR COALESCE(e.message,'') <> COALESCE(l.message,'')
                       OR COALESCE(e.raw_event,'') <> COALESCE(l.raw,'')
                ) THEN
                    RAISE EXCEPTION 'Event projection contains evidence missing from or different from logs';
                END IF;
                UPDATE public.security_events
                   SET message_terms=to_tsvector('simple', COALESCE(message,'')),
                       device_event_time=CASE WHEN device_timestamp ~ '[Tt ].*(Z|[+-][0-9]{2}:[0-9]{2})$'
                           THEN public.minisiem_summary_timestamp(device_timestamp) END;
                ALTER TABLE public.security_events DROP COLUMN message, DROP COLUMN raw_event;
            END IF;
        END $ddl$""",
        "CREATE INDEX IF NOT EXISTS idx_se_message_terms_gin ON security_events USING GIN(message_terms)",
        *(f"DROP INDEX IF EXISTS public.{name}" for name in RETIRED_EVENT_INDEXES),
        # e.* expands to the base view's columns, so a new security_events
        # column (search_fields) lands mid-list; CREATE OR REPLACE cannot do
        # that on an existing install. Rebuild it; grants are refreshed by
        # tools/postgres_privilege_boundary.py after owner initialization.
        "DROP VIEW IF EXISTS security_event_context",
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
            SET timezone = 'UTC'
            AS $fn$
            DECLARE
                start_at TIMESTAMPTZ;
                end_at TIMESTAMPTZ;
                stop_at TIMESTAMPTZ;
                part_name TEXT;
                field_name TEXT;
                layout TEXT;
                requested TEXT := nullif(current_setting('minisiem.partition_granularity', true), '');
                field_partitioned BOOLEAN;
                made INTEGER := 0;
            BEGIN
                IF p_months < 1 OR p_months > 24 THEN
                    RAISE EXCEPTION 'p_months must be between 1 and 24';
                END IF;
                PERFORM pg_advisory_xact_lock(hashtext('minisiem.event-partitions'));
                SELECT CASE
                    WHEN bool_or(c.relname ~ '^security_events_day_[0-9]+$') THEN 'day'
                    WHEN bool_or(c.relname ~ '^security_events_week_[0-9]+$') THEN 'week'
                    WHEN bool_or(c.relname <> 'security_events_default') THEN 'month'
                    ELSE NULL END
                INTO layout FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid
                WHERE i.inhparent='public.security_events'::regclass;
                IF requested IS NOT NULL AND requested NOT IN ('month','week','day') THEN
                    RAISE EXCEPTION 'partition granularity must be month, week, or day';
                END IF;
                IF layout IS NOT NULL AND requested IS NOT NULL AND layout <> requested THEN
                    RAISE EXCEPTION 'cannot change existing partition granularity in place';
                END IF;
                layout := coalesce(layout, requested, 'month');
                start_at := date_trunc('month', p_start);
                stop_at := start_at + make_interval(months => p_months);
                start_at := date_trunc(layout, start_at);
                SELECT relkind='p' INTO field_partitioned FROM pg_class WHERE oid='public.log_fields'::regclass;
                WHILE start_at < stop_at LOOP
                    end_at := start_at + CASE layout WHEN 'day' THEN INTERVAL '1 day'
                              WHEN 'week' THEN INTERVAL '1 week' ELSE INTERVAL '1 month' END;
                    part_name := 'security_events_' || CASE WHEN layout='month' THEN to_char(start_at,'YYYY_MM')
                                 ELSE layout || '_' || to_char(start_at,'YYYYMMDD') END;
                    IF to_regclass('public.' || part_name) IS NULL THEN
                        EXECUTE format(
                            'CREATE TABLE public.%I PARTITION OF public.security_events FOR VALUES FROM (%L) TO (%L)',
                            part_name, start_at, end_at
                        );
                        made := made + 1;
                    END IF;
                    IF field_partitioned THEN
                        field_name := replace(part_name, 'security_events_', 'log_fields_');
                        IF to_regclass('public.' || field_name) IS NULL THEN
                            EXECUTE format(
                                'CREATE TABLE public.%I PARTITION OF public.log_fields FOR VALUES FROM (%L) TO (%L)',
                                field_name, start_at, end_at
                            );
                        END IF;
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
    except (ValueError, OverflowError):
        return None


def _projection_times(event):
    received = _iso_time(event.get("received_at")) or datetime.now(timezone.utc).isoformat()
    device = _iso_time(event.get("device_timestamp"))
    effective = received
    if device:
        skew = datetime.fromisoformat(device) - datetime.fromisoformat(received)
        if timedelta(days=-30) <= skew <= timedelta(0):
            effective = device
    return effective, received, device


def projection_time(event):
    return _projection_times(event)[0]


def search_field_payload(fields):
    from normalize import normalized_field_rows
    payload = {}
    for key, _, norm in normalized_field_rows(fields or {}):
        values = payload.setdefault(key, [])
        if norm not in values:
            values.append(norm)
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def _first_ip(*candidates):
    return next((ip for ip in map(_clean_ip, candidates) if ip), None)


def normalized_projection(event: dict, fields: dict | None = None) -> dict:
    fields = dict(fields or {})
    event_time, received, device = _projection_times(event)
    source = _first_ip(*(_field(fields, (key,)) for key in ("src_ip", "src", "srcip", "source_ip", "endpoint_ip")),
                       event.get("source_ip"))
    destination = _first_ip(event.get("destination_ip"),
                            *(_field(fields, (key,)) for key in ("dst_ip", "dst", "dstip", "destination_ip", "dest_ip")),
                            event.get("destination"))
    user = fields.get("user.name") or event.get("username") or _field(fields, USER_FIELD_NAMES)
    vendor = event.get("device_vendor") or _field(fields, ("vendor", "device_vendor"))
    product = event.get("device_product") or _field(fields, ("product", "device_product"))
    event_type = fields.get("event.kind") or event.get("event_name") or event.get("action") or _field(fields, EVENT_TYPE_FIELDS)
    event_code = fields.get("event.id") or event.get("signature_id") or _field(fields, EVENT_CODE_FIELDS) or event.get("msg_id")
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
        "src_ip": source,
        "dst_ip": destination,
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
        "device_event_time": device,
        "destination": str(event.get("destination") or "") or None,
        "app_name": str(event.get("app_name") or "") or None,
        "proc_id": str(event.get("proc_id") or "") or None,
        "msg_id": str(event.get("msg_id") or "") or None,
        "message": str(event.get("message") or ""),
        "raw_event": str(event.get("raw") or ""),
        "fields": fields,
    }


def append_projection(conn, log_id: int, event: dict, fields: dict | None = None, *,
                      event_time=None, search_ready=False) -> int:
    """Append the typed projection for one raw log using the caller transaction.

    Returns 1 when inserted, 0 when an idempotent backfill finds an existing
    projection for the legacy evidence id.
    Keep typed IP/user values, but do not write shared entity rows per event.
    Existing entity links remain available on older projections.
    """
    if getattr(conn, "backend", "sqlite") != "postgres":
        return 0
    p = normalized_projection(event, fields)
    payload = json.dumps(p["fields"], ensure_ascii=False, sort_keys=True)
    sql = """INSERT INTO security_events(
               legacy_log_id,event_time,ingested_at,src_ip,dst_ip,peer_ip,src_port,dst_port,
               hostname,user_name,vendor,product,event_type,event_code,severity,severity_text,
               format,priority,facility,device_timestamp,device_event_time,destination,app_name,proc_id,msg_id,
               message_terms,fields,search_fields)
           SELECT ?,?::timestamptz,?::timestamptz,?::inet,?::inet,?::inet,?,?,
                  ?,?,?,?,?,?,?,?,?,?,?,?,?::timestamptz,?,?,?,?,
                  to_tsvector('simple',?),?::jsonb,?::jsonb"""
    params = (
            int(log_id), event_time or p["event_time"], p["ingested_at"], p["src_ip"], p["dst_ip"], p["peer_ip"],
            p["src_port"], p["dst_port"], p["hostname"], p["user_name"], p["vendor"], p["product"],
            p["event_type"], p["event_code"], p["severity"], p["severity_text"], p["format"],
            p["priority"], p["facility"], p["device_timestamp"], p["device_event_time"],
            p["destination"], p["app_name"], p["proc_id"], p["msg_id"], p["message"], payload,
            search_field_payload(fields) if search_ready else None,
    )
    # The main path just allocated this raw evidence ID in this transaction.
    # Checking it across all retained partitions is only needed for backfill.
    if not search_ready:
        sql += " WHERE NOT EXISTS (SELECT 1 FROM security_events WHERE legacy_log_id=? LIMIT 1)"
        params += (int(log_id),)
    cur = conn.execute(sql, params)
    return max(0, int(getattr(cur, "rowcount", 0) or 0))


def update_projection_fields(conn, log_id: int, event: dict, fields: dict, *, search_ready=False) -> None:
    """Refresh dynamic JSONB / typed derivatives after field extraction."""
    if getattr(conn, "backend", "sqlite") != "postgres":
        return
    p = normalized_projection(event, fields)
    conn.execute(
        """UPDATE security_events
              SET fields=?::jsonb, search_fields=?::jsonb,
                  user_name=COALESCE(?, user_name),
                  src_port=COALESCE(?, src_port),
                  dst_port=COALESCE(?, dst_port),
                  event_type=COALESCE(?, event_type),
                  event_code=COALESCE(?, event_code),
                  vendor=COALESCE(?, vendor),
                  product=COALESCE(?, product)
            WHERE legacy_log_id=?""",
        (
            json.dumps(fields or {}, ensure_ascii=False, sort_keys=True),
            search_field_payload(fields) if search_ready else None, p["user_name"],
            p["src_port"], p["dst_port"], p["event_type"], p["event_code"], p["vendor"], p["product"],
            int(log_id),
        ),
    )


def ensure_partitions_owner(conn, months: int = 3) -> int:
    if getattr(conn, "backend", "sqlite") != "postgres":
        return 0
    row = conn.execute(
        "SELECT public.minisiem_ensure_security_event_partitions(now(), ?)",
        (int(months),),
    ).fetchone()
    if not row:
        return 0
    return int(next(iter(row.values())) if isinstance(row, dict) else row[0])
