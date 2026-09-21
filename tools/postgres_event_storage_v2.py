#!/usr/bin/env python3
"""Owner-only migration/backfill/qualification for PostgreSQL Event Storage v2.

The tool never stores owner credentials. It creates the owner schema through
``db.initialize()``, pre-creates historical monthly partitions before
backfilling, projects legacy raw ``logs`` rows idempotently, and can run
read-only qualification checks/EXPLAIN against the resulting schema.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import getpass
import os
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import db
from event_storage_v2 import append_projection

OWNER_PASSWORD_ENV = "MINISIEM_PG_OWNER_PASSWORD"
OWNER_USER_ENV = "MINISIEM_PG_OWNER_USER"


def _owner_config(path: Path, owner_user: str) -> dict:
    raw = json.loads(path.read_text(encoding="utf-8"))
    cfg = json.loads(json.dumps(db.DEFAULT_CONFIG))
    for key, value in raw.items():
        if key in ("sqlite", "postgres") and isinstance(value, dict):
            cfg[key].update(value)
        else:
            cfg[key] = value
    if cfg.get("backend") != "postgres":
        raise SystemExit("PostgreSQL backend is required")
    boundary = cfg.get("postgres_privilege_boundary") or {}
    user = (owner_user or os.environ.get(OWNER_USER_ENV) or boundary.get("owner_role")
            or cfg["postgres"].get("user") or input("PostgreSQL owner user: ").strip())
    if not user:
        raise SystemExit("PostgreSQL owner user is required")
    password = (cfg["postgres"].get("password") or os.environ.get(OWNER_PASSWORD_ENV)
                or getpass.getpass(f"Password for PostgreSQL owner '{user}': "))
    cfg["postgres"]["user"] = user
    cfg["postgres"]["password"] = password
    return cfg


def _load_fields(conn, ids):
    if not ids:
        return {}
    ph = ",".join("?" * len(ids))
    out = {}
    rows = conn.execute(
        f"SELECT log_id,field,value FROM log_fields WHERE log_id IN ({ph}) ORDER BY log_id,id",
        list(ids),
    ).fetchall()
    for row in rows:
        out.setdefault(int(row["log_id"]), {})[row["field"]] = row["value"]
    return out


def _event_from_log(row):
    return {
        "received_at": row["received_at"],
        "source_ip": row["source_ip"] or "",
        "peer_ip": row["peer_ip"] or "",
        "format": row["format"] or "",
        "priority": row["priority"],
        "facility": row["facility"] or "",
        "severity": row["severity"] or "",
        "device_timestamp": row["device_timestamp"] or "",
        "hostname": row["hostname"] or "",
        "destination": row["destination"] or "",
        "app_name": row["app_name"] or "",
        "proc_id": row["proc_id"] or "",
        "msg_id": row["msg_id"] or "",
        "message": row["message"] or "",
        "raw": row["raw"] or "",
    }


def _precreate_historical_partitions(conn, batch_size=5000):
    months = set()
    last = 0
    while True:
        rows = conn.execute(
            "SELECT id,received_at,device_timestamp FROM logs WHERE id>? ORDER BY id LIMIT ?",
            (last, batch_size),
        ).fetchall()
        if not rows:
            break
        for row in rows:
            last = int(row["id"])
            for candidate in (row["device_timestamp"], row["received_at"]):
                try:
                    dt = datetime.fromisoformat(str(candidate or "").replace("Z", "+00:00"))
                    if dt.tzinfo is not None:
                        months.add((dt.year, dt.month))
                        break
                except ValueError:
                    continue
    for year, month in sorted(months):
        start = f"{year:04d}-{month:02d}-01T00:00:00+00:00"
        conn.execute(
            "SELECT public.minisiem_ensure_security_event_partitions(?::timestamptz,1)",
            (start,),
        )
        conn.commit()
    return len(months)


def backfill(conn, batch_size=1000, dry_run=False):
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM logs l WHERE NOT EXISTS (SELECT 1 FROM security_events e WHERE e.legacy_log_id=l.id)"
    ).fetchone()
    missing = int(row["n"] if isinstance(row, dict) else row[0])
    if dry_run or not missing:
        return {"missing_before": missing, "inserted": 0}
    _precreate_historical_partitions(conn)
    inserted = 0
    last = 0
    while True:
        rows = conn.execute(
            """SELECT id,received_at,source_ip,peer_ip,format,priority,facility,severity,
                      device_timestamp,hostname,destination,app_name,proc_id,msg_id,message,raw
                 FROM logs WHERE id>? ORDER BY id LIMIT ?""",
            (last, batch_size),
        ).fetchall()
        if not rows:
            break
        ids = [int(r["id"]) for r in rows]
        fields = _load_fields(conn, ids)
        try:
            for row in rows:
                last = int(row["id"])
                inserted += append_projection(conn, last, _event_from_log(row), fields.get(last, {}))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return {"missing_before": missing, "inserted": inserted}


def qualify(conn):
    result = {"types": {}, "partitioned": False, "indexes": [], "plans": {}}
    rows = conn.execute(
        """SELECT column_name,data_type,udt_name FROM information_schema.columns
             WHERE table_schema='public' AND table_name='security_events'
               AND column_name IN ('event_time','ingested_at','src_ip','dst_ip','src_port','dst_port','fields')"""
    ).fetchall()
    result["types"] = {r["column_name"]: (r["data_type"], r["udt_name"]) for r in rows}
    part = conn.execute(
        "SELECT EXISTS (SELECT 1 FROM pg_partitioned_table p JOIN pg_class c ON c.oid=p.partrelid WHERE c.relname='security_events') AS ok"
    ).fetchone()
    result["partitioned"] = bool(part["ok"])
    idx = conn.execute(
        "SELECT indexname FROM pg_indexes WHERE schemaname='public' AND tablename='security_events' ORDER BY indexname"
    ).fetchall()
    result["indexes"] = [r["indexname"] for r in idx]
    samples = conn.execute(
        "SELECT src_ip::text AS src,event_time FROM security_events WHERE src_ip IS NOT NULL ORDER BY event_time DESC LIMIT 1"
    ).fetchone()
    if samples:
        plans = {
            "src_ip_time": (
                "EXPLAIN (FORMAT TEXT) SELECT id FROM security_events WHERE src_ip=?::inet AND event_time>=?::timestamptz ORDER BY event_time DESC LIMIT 100",
                (samples["src"], samples["event_time"]),
            ),
            "event_type_time": (
                "EXPLAIN (FORMAT TEXT) SELECT id FROM security_events WHERE event_type IS NOT NULL AND event_time>=?::timestamptz ORDER BY event_time DESC LIMIT 100",
                (samples["event_time"],),
            ),
        }
        for name, (sql, params) in plans.items():
            rows = conn.execute(sql, params).fetchall()
            result["plans"][name] = [next(iter(r.values())) if isinstance(r, dict) else r[0] for r in rows]
    return result


def main():
    ap = argparse.ArgumentParser(description="Migrate/backfill PostgreSQL Event Storage v2")
    ap.add_argument("--db-config", default=str(ROOT / "db-config.json"))
    ap.add_argument("--owner-user", default="")
    ap.add_argument("--batch-size", type=int, default=1000)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--qualify", action="store_true")
    args = ap.parse_args()
    cfg = _owner_config(Path(args.db_config), args.owner_user)
    db.initialize(cfg)
    conn = db.connect(cfg)
    try:
        outcome = backfill(conn, max(100, min(args.batch_size, 10000)), dry_run=args.dry_run)
        payload = {"backfill": outcome}
        if args.qualify:
            payload["qualification"] = qualify(conn)
        print(json.dumps(payload, indent=2, default=str, sort_keys=True))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
