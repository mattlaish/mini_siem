#!/usr/bin/env python3
"""Reproducible PostgreSQL planner/production-profile validation for mini-SIEM Performance Phases 4/5.

Run only against a disposable/test PostgreSQL database. The harness initializes
mini-SIEM schema/indexes, inserts a bounded synthetic dataset, ANALYZEs it,
prints EXPLAIN (ANALYZE, BUFFERS) for the important SIEM query shapes, and
removes its tagged synthetic rows unless --keep-data is supplied.
"""

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import db


def _guard_test_database(cfg, confirmed):
    name = str((cfg.get("postgres") or {}).get("dbname") or "").lower()
    if confirmed or any(token in name for token in ("test", "bench", "dev")):
        return
    raise SystemExit(
        "Refusing to write synthetic logs to a database that does not look like a "
        "test/bench/dev DB. Re-run with --confirm-test-db only after verifying the target."
    )


def _plan(cur, label, sql, params):
    cur.execute("EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) " + sql, params)
    lines = [row[0] for row in cur.fetchall()]
    print(f"\n=== {label} ===")
    print("\n".join(lines))
    return {"label": label, "plan": lines}


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

    try:
        import psycopg2.extras
    except ImportError as exc:
        raise SystemExit("psycopg2-binary is required for PostgreSQL validation") from exc

    db.initialize(cfg)
    conn = db.connect(cfg)
    raw = conn.raw
    tag = "phase5-bench-" + uuid.uuid4().hex[:10]
    base = datetime(2026, 9, 1, tzinfo=timezone.utc)
    results = {"tag": tag, "rows": rows_n, "plans": []}
    try:
        cur = raw.cursor()
        log_rows = []
        for i in range(rows_n):
            at = (base + timedelta(seconds=i)).isoformat()
            source = f"10.20.{(i // 256) % 64}.{i % 256}"
            host = f"ws-{i % 2000:04d}.corp"
            dest = f"srv-{i % 500:03d}.corp"
            needle = " phase5needle suspicious-command.exe" if i % 997 == 0 else " normal activity"
            message = f"Event ID {4625 if i % 7 == 0 else 4624} user=user{i % 5000}{needle} seq={i}"
            log_rows.append((
                at, source, source, "rfc3164", 132, "auth", "warning" if i % 31 == 0 else "informational",
                at, host, dest, tag, "", "", message, message,
            ))
        psycopg2.extras.execute_values(
            cur,
            """INSERT INTO logs(received_at,source_ip,peer_ip,format,priority,facility,severity,
                    device_timestamp,hostname,destination,app_name,proc_id,msg_id,message,raw)
               VALUES %s""",
            log_rows, page_size=5000,
        )
        raw.commit()

        cur.execute("SELECT id,message FROM logs WHERE app_name=%s ORDER BY id", (tag,))
        inserted = cur.fetchall()
        field_rows = []
        for log_id, message in inserted:
            event_id = "4625" if "Event ID 4625" in message else "4624"
            user = message.split("user=", 1)[1].split()[0]
            field_rows.append((log_id, "event_id", event_id, event_id))
            field_rows.append((log_id, "user", user, user.lower()))
        psycopg2.extras.execute_values(
            cur,
            "INSERT INTO log_fields(log_id,field,value,value_norm) VALUES %s",
            field_rows, page_size=10000,
        )
        raw.commit()
        cur.execute("ANALYZE logs")
        cur.execute("ANALYZE log_fields")
        raw.commit()

        caps = db.postgres_text_search_capabilities(conn)
        results["text_search_capabilities"] = caps
        print("Text-search capabilities:", json.dumps(caps, sort_keys=True))

        # Phase 5 production profile: verify pooled checkouts receive bounded
        # statement/lock/idle-transaction timeouts. SHOW is read-only.
        settings = {}
        for name in ("statement_timeout", "lock_timeout", "idle_in_transaction_session_timeout", "application_name"):
            cur.execute("SHOW " + name)
            settings[name] = cur.fetchone()[0]
        results["session_settings"] = settings
        print("Session settings:", json.dumps(settings, sort_keys=True))
        checkouts = []
        for _ in range(min(4, int((cfg.get("postgres") or {}).get("pool_max", 10)))):
            c = db.connect(cfg)
            c.execute("SELECT 1")
            checkouts.append(c)
        for c in checkouts:
            c.close()
        results["pool_checkout_smoke"] = len(checkouts)

        cur.execute("SELECT MIN(received_at), MAX(received_at), MIN(id), MAX(id) FROM logs WHERE app_name=%s", (tag,))
        min_at, max_at, min_id, max_id = cur.fetchone()
        middle_id = (int(min_id) + int(max_id)) // 2
        cur.execute("SELECT received_at FROM logs WHERE id=%s", (middle_id,))
        middle_at = cur.fetchone()[0]

        checks = [
            ("message FTS / GIN",
             "SELECT id FROM logs WHERE app_name=%s AND "
             "to_tsvector('simple'::regconfig,COALESCE(message,''::text)) @@ to_tsquery('simple'::regconfig,%s)",
             (tag, "phase5needle")),
            ("message substring / pg_trgm",
             "SELECT id FROM logs WHERE app_name=%s AND message ILIKE %s",
             (tag, "%suspicious-command.exe%")),
            ("field exact",
             "SELECT l.id FROM logs l JOIN log_fields f ON f.log_id=l.id "
             "WHERE l.app_name=%s AND f.field='event_id' AND f.value_norm=%s",
             (tag, "4625")),
            ("field prefix",
             "SELECT l.id FROM logs l JOIN log_fields f ON f.log_id=l.id "
             "WHERE l.app_name=%s AND f.field='user' AND f.value_norm LIKE %s",
             (tag, "user12%")),
            ("source exact",
             "SELECT id FROM logs WHERE app_name=%s AND lower(source_ip)=%s",
             (tag, "10.20.1.1")),
            ("source prefix",
             "SELECT id FROM logs WHERE app_name=%s AND lower(source_ip) LIKE %s",
             (tag, "10.20.1.%")),
            ("host prefix",
             "SELECT id FROM logs WHERE app_name=%s AND lower(hostname) LIKE %s",
             (tag, "ws-001%")),
            ("destination prefix",
             "SELECT id FROM logs WHERE app_name=%s AND lower(destination) LIKE %s",
             (tag, "srv-01%")),
            ("time + structured filter",
             "SELECT id FROM logs WHERE app_name=%s AND received_at >= %s AND lower(hostname) LIKE %s "
             "ORDER BY received_at DESC,id DESC LIMIT 200",
             (tag, min_at, "ws-00%")),
            ("text AND field semantics",
             "SELECT l.id FROM logs l JOIN log_fields f ON f.log_id=l.id "
             "WHERE l.app_name=%s AND "
             "to_tsvector('simple'::regconfig,COALESCE(l.message,''::text)) @@ to_tsquery('simple'::regconfig,%s) "
             "AND f.field='event_id' AND f.value_norm=%s",
             (tag, "phase5needle", "4625")),
            ("received_at + id keyset cursor",
             "SELECT id,received_at FROM logs WHERE app_name=%s AND "
             "(received_at > %s OR (received_at=%s AND id>%s)) "
             "ORDER BY received_at ASC,id ASC LIMIT 200",
             (tag, middle_at, middle_at, middle_id)),
        ]
        for label, sql, params in checks:
            results["plans"].append(_plan(cur, label, sql, params))

        if args.json_out:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                json.dump(results, fh, indent=2)
        print(f"\nValidated {rows_n} synthetic rows tagged {tag}.")
    finally:
        if not args.keep_data:
            try:
                cur = raw.cursor()
                cur.execute(
                    "DELETE FROM log_fields WHERE log_id IN (SELECT id FROM logs WHERE app_name=%s)",
                    (tag,),
                )
                cur.execute("DELETE FROM logs WHERE app_name=%s", (tag,))
                raw.commit()
            except Exception:
                raw.rollback()
        conn.close()


if __name__ == "__main__":
    main()
