#!/usr/bin/env python3
"""Read-only verification of mini-SIEM PostgreSQL privilege separation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import db


FILES = {
    "listener": "db-listener-credentials.json",
    "dashboard": "db-dashboard-credentials.json",
    "maintenance": "db-maintenance-credentials.json",
}


def inspect(config_path: Path, cred_path: Path, identity: str):
    cfg = db.load_config(str(config_path), credentials_path=str(cred_path))
    conn = db.connect(cfg)
    try:
        row = conn.execute(
            """
            SELECT current_user AS role,
                   has_table_privilege(current_user,'public.logs','SELECT') AS can_select,
                   has_table_privilege(current_user,'public.logs','DELETE') AS can_delete,
                   has_table_privilege(current_user,'public.logs','TRUNCATE') AS can_truncate,
                   has_column_privilege(current_user,'public.logs','received_at','INSERT') AS can_insert,
                   has_column_privilege(current_user,'public.logs','raw','UPDATE') AS can_update_raw,
                   has_table_privilege(current_user,'public.schema_migrations','SELECT') AS can_read_migrations,
                   has_table_privilege(current_user,'public.schema_migrations','UPDATE') AS can_edit_migrations,
                   has_table_privilege(current_user,'public.archive_segments','INSERT') AS can_insert_archive_catalog,
                   has_table_privilege(current_user,'public.archive_segments','UPDATE') AS can_update_archive_catalog,
                   has_table_privilege(current_user,'public.archive_segments','DELETE') AS can_delete_archive_catalog,
                   has_table_privilege(current_user,'public.archive_segments','TRUNCATE') AS can_truncate_archive_catalog
            """
        ).fetchone()
        trigger = conn.execute(
            """
            SELECT COUNT(*) AS c
              FROM pg_trigger t
              JOIN pg_class c ON c.oid=t.tgrelid
              JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname='public' AND c.relname='logs'
               AND t.tgname IN ('minisiem_logs_no_mutation','minisiem_logs_no_truncate')
               AND NOT t.tgisinternal AND t.tgenabled <> 'D'
            """
        ).fetchone()
        result = dict(row)
        result["guard_triggers"] = int(trigger["c"] if isinstance(trigger, dict) else trigger[0])
        result["identity"] = identity
        expected_delete = identity == "maintenance"
        expected_archive_write = identity == "maintenance"
        result["ok"] = bool(
            result["can_select"]
            and result["can_insert"]
            and bool(result["can_delete"]) == expected_delete
            and not result["can_truncate"]
            and not result["can_update_raw"]
            and result["can_read_migrations"]
            and not result["can_edit_migrations"]
            and bool(result["can_insert_archive_catalog"]) == expected_archive_write
            and bool(result["can_update_archive_catalog"]) == expected_archive_write
            and bool(result["can_delete_archive_catalog"]) == expected_archive_write
            and not result["can_truncate_archive_catalog"]
            and result["guard_triggers"] == 2
        )
        return result
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser(description="Verify mini-SIEM PostgreSQL privilege boundary")
    ap.add_argument("--db-config", default=str(ROOT / "db-config.json"))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    config_path = Path(args.db_config).resolve()
    results = []
    for identity, filename in FILES.items():
        cred = config_path.parent / filename
        if not cred.exists():
            raise SystemExit(f"missing credential file: {cred}")
        results.append(inspect(config_path, cred, identity))
    ok = all(r["ok"] for r in results)
    payload = {"ok": ok, "identities": results}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for r in results:
            print(
                f"{r['identity']:11s} role={r['role']} "
                f"select={bool(r['can_select'])} insert={bool(r['can_insert'])} "
                f"delete={bool(r['can_delete'])} update={bool(r['can_update_raw'])} "
                f"truncate={bool(r['can_truncate'])} guards={r['guard_triggers']} "
                f"=> {'PASS' if r['ok'] else 'FAIL'}"
            )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
