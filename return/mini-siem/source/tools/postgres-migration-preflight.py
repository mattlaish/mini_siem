#!/usr/bin/env python3
"""
mini-SIEM PostgreSQL migration preflight.

Provides migration safety checks:
- dry-run boundary
- source inventory capture
- execution readiness report

No database mutation is performed.
"""

import argparse
import json
import sqlite3
from datetime import datetime, timezone


def inventory(path):
    conn = sqlite3.connect(path)
    try:
        result = {}
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ):
            result[row[0]] = conn.execute(
                f"SELECT COUNT(*) FROM '{row[0]}'"
            ).fetchone()[0]
        return result
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sqlite", required=True)
    ap.add_argument("--report", default="migration-preflight.json")
    args = ap.parse_args()

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stage": "postgres_migration_preflight",
        "mutation": False,
        "checks": {
            "source_inventory": "completed",
            "postgres_connection": "pending",
            "target_schema": "pending",
            "backup_confirmation": "required",
            "rollback_test": "required",
        },
        "source_tables": inventory(args.sqlite),
        "ready_for_migration": False,
    }

    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
