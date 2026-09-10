#!/usr/bin/env python3
"""
mini-SIEM Controlled Import Engine foundation.

Safety properties:
- dry-run by default
- no destructive operations
- no automatic user replacement
- no administrator recreation
- produces migration plan/report
"""
import argparse
import json
import sqlite3
from datetime import datetime, timezone

PROTECTED_TABLES = {
    "users",
    "api_keys",
    "app_config",
    "audit_log",
}


def inspect_sqlite(path):
    conn = sqlite3.connect(path)
    try:
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' ORDER BY name"
            )
        ]
        counts = {}
        for table in tables:
            counts[table] = conn.execute(
                f"SELECT COUNT(*) FROM '{table}'"
            ).fetchone()[0]
        return counts
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sqlite", required=True)
    parser.add_argument("--report", default="migration-report.json")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    counts = inspect_sqlite(args.sqlite)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "execute" if args.execute else "dry-run",
        "postgres_write": False,
        "protected_tables": sorted(PROTECTED_TABLES),
        "source_tables": counts,
        "status": "planning_only",
        "next_step": "validate PostgreSQL mapping before enabling writes",
    }

    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
