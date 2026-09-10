#!/usr/bin/env python3
"""
mini-SIEM Controlled Table Import Engine.

Phase:
- controlled table planning
- explicit import order
- dry-run by default
- protected-table handling

This phase does not perform production PostgreSQL writes.
"""

import argparse
import json
import sqlite3
from datetime import datetime, timezone

IMPORT_ORDER = [
    "users",
    "app_config",
    "api_keys",
    "source_profiles",
    "forwarders",
    "logs",
    "alerts",
    "iocs",
    "ioc_matches",
    "reports",
    "audit_log",
]

PROTECTED_TABLES = {
    "users",
    "api_keys",
    "app_config",
    "audit_log",
}


def sqlite_inventory(path):
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
    parser.add_argument("--report", default="table-import-report.json")
    parser.add_argument("--execute", action="store_true",
                        help="reserved; not enabled in this phase")
    args = parser.parse_args()

    inventory = sqlite_inventory(args.sqlite)

    plan = []
    for table in IMPORT_ORDER:
        if table in inventory:
            plan.append({
                "table": table,
                "rows": inventory[table],
                "protected": table in PROTECTED_TABLES,
                "action": "review-required" if table in PROTECTED_TABLES else "planned",
            })

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "dry-run",
        "postgres_write": False,
        "execute_requested": args.execute,
        "plan": plan,
        "status": "planning_only",
    }

    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
