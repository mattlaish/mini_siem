#!/usr/bin/env python3
"""Disposable PostgreSQL Event Storage v2 planner/performance validation.

Unlike the historical harness, synthetic events enter through ``Storage`` so
raw ``logs`` / ``log_fields`` and the typed ``security_events`` projection are
committed together. The tool refuses ambiguous production-looking databases.
"""
from __future__ import annotations
import argparse, json, os, sys, uuid
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import db
from listener import Storage


def _guard_test_database(cfg, confirmed):
    name = str((cfg.get("postgres") or {}).get("dbname") or "").lower()
    if confirmed or any(token in name for token in ("test", "bench", "dev")):
        return
    raise SystemExit("Refusing synthetic writes to a DB that does not look test/bench/dev; use --confirm-test-db deliberately.")


def _plan(cur, label, sql, params):
    cur.execute("EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) " + sql, params)
    lines = [row[0] for row in cur.fetchall()]
    print(f"\n=== {label} ===\n" + "\n".join(lines))
    return {"label": label, "plan": lines}


def _event(base, i, tag):
    at = (base + timedelta(seconds=i)).isoformat()
    source = f"10.20.{(i // 256) % 64}.{i % 256}"
    host = f"ws-{i % 2000:04d}.corp"
    dest = f"srv-{i % 500:03d}.corp"
    event_id = "4625" if i % 7 == 0 else "4624"
    user = f"user{i % 5000}"
    needle = " phase5needle suspicious-command.exe" if i % 997 == 0 else " normal activity"
    message = f"Event ID {event_id} user={user}{needle} seq={i}"
    return ({
        "received_at": at, "source_ip": source, "peer_ip": source,
        "format": "rfc3164", "priority": 132, "facility": "auth",
        "severity": "warning" if i % 31 == 0 else "informational",
        "device_timestamp": at, "hostname": host, "destination": dest,
        "app_name": tag, "proc_id": "", "msg_id": event_id,
        "message": message, "raw": message,
    }, {"event_id": event_id, "user": user})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(ROOT, "db-config.json"))
    ap.add_argument("--rows", type=int, default=100000)
    ap.add_argument("--confirm-test-db", action="store_true")
    ap.add_argument("--keep-data", action="store_true")
    ap.add_argument("--json-out", default="")
    args = ap.parse_args()
    rows_n = max(1000, min(int(args.rows), 500000))
    cfg = db.load_config(args.config)
    if cfg.get("backend") != "postgres":
        raise SystemExit("db-config.json must select backend=postgres")
    _guard_test_database(cfg, args.confirm_test_db)
    db.initialize(cfg)
    storage = Storage(db_config=cfg)
    raw = storage.conn.raw
    tag = "phase5-bench-" + uuid.uuid4().hex[:10]
    base = datetime(2026, 9, 1, tzinfo=timezone.utc)
    results = {"tag": tag, "rows": rows_n, "plans": [], "ingest_path": "Storage.insert_log_batch+Event Storage v2"}
    try:
        batch = []
        for i in range(rows_n):
            batch.append(_event(base, i, tag))
            if len(batch) >= 1000:
                storage.insert_log_batch(batch); batch = []
        if batch:
            storage.insert_log_batch(batch)
        cur = raw.cursor()
        cur.execute("ANALYZE security_events"); cur.execute("ANALYZE log_fields"); raw.commit()
        settings = {}
        for name in ("statement_timeout", "lock_timeout", "idle_in_transaction_session_timeout", "application_name"):
            cur.execute("SHOW " + name)
            settings[name] = cur.fetchone()[0]
        results["session_settings"] = settings
        checkouts = []
        for _ in range(min(4, int((cfg.get("postgres") or {}).get("pool_max", 10)))):
            c = db.connect(cfg); c.execute("SELECT 1"); checkouts.append(c)
        for c in checkouts:
            c.close()
        results["pool_checkout_smoke"] = len(checkouts)
        cur.execute("SELECT MIN(event_time),MAX(event_time),MIN(id),MAX(id) FROM security_events WHERE app_name=%s", (tag,))
        min_at,max_at,min_id,max_id = cur.fetchone()
        checks = [
            ("source exact + time composite", "SELECT id FROM security_events WHERE app_name=%s AND src_ip=%s::inet AND event_time >= %s ORDER BY event_time DESC LIMIT 200", (tag,"10.20.1.1",min_at)),
            ("source CIDR + time", "SELECT id FROM security_events WHERE app_name=%s AND src_ip <<= %s::cidr AND event_time >= %s ORDER BY event_time DESC LIMIT 200", (tag,"10.20.1.0/24",min_at)),
            ("host prefix + time", "SELECT id FROM security_events WHERE app_name=%s AND lower(hostname) LIKE %s AND event_time >= %s ORDER BY event_time DESC LIMIT 200", (tag,"ws-001%",min_at)),
            ("destination prefix + time", "SELECT id FROM security_events WHERE app_name=%s AND lower(destination) LIKE %s AND event_time >= %s ORDER BY event_time DESC LIMIT 200", (tag,"srv-01%",min_at)),
            ("message FTS / GIN", "SELECT id FROM security_events WHERE app_name=%s AND to_tsvector('simple',COALESCE(message,'')) @@ to_tsquery('simple',%s)", (tag,"phase5needle:*")),
            ("field exact", "SELECT e.legacy_log_id FROM security_events e JOIN log_fields f ON f.log_id=e.legacy_log_id WHERE e.app_name=%s AND f.field='event_id' AND f.value_norm=%s", (tag,"4625")),
            ("field prefix", "SELECT e.legacy_log_id FROM security_events e JOIN log_fields f ON f.log_id=e.legacy_log_id WHERE e.app_name=%s AND f.field='user' AND f.value_norm LIKE %s", (tag,"user12%")),
            ("asset context join", "SELECT c.id FROM security_event_context c WHERE c.app_name=%s AND c.asset_id IS NOT NULL AND c.event_time >= %s ORDER BY c.event_time DESC LIMIT 200", (tag,min_at)),
        ]
        for label, sql, params in checks:
            results["plans"].append(_plan(cur,label,sql,params))
        caps = db.postgres_text_search_capabilities(storage.conn)
        results["text_search_capabilities"] = caps
        if args.json_out:
            with open(args.json_out,"w",encoding="utf-8") as fh: json.dump(results,fh,indent=2,default=str)
        print(f"\nValidated {rows_n} v2-aware synthetic events tagged {tag}.")
    finally:
        if not args.keep_data:
            try:
                cur = raw.cursor()
                cur.execute("DELETE FROM security_events WHERE app_name=%s", (tag,))
                cur.execute("DELETE FROM log_fields WHERE log_id IN (SELECT id FROM logs WHERE app_name=%s)", (tag,))
                cur.execute("DELETE FROM logs WHERE app_name=%s", (tag,))
                raw.commit()
            except Exception:
                raw.rollback()
        storage.close()


if __name__ == "__main__":
    main()
