#!/usr/bin/env python3
"""
mini-SIEM Controlled PostgreSQL Write Importer foundation.

Safety design:
- explicit execution flag
- dry-run default
- transaction boundary placeholder
- duplicate/protected-data checks before future writes

This phase validates import preparation only.
Actual PostgreSQL INSERT is intentionally not enabled.
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


def inventory(path):
    conn = sqlite3.connect(path)
    try:
        result = {}
        tables = [
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table'"
            )
        ]
        for table in tables:
            result[table] = conn.execute(
                f"SELECT COUNT(*) FROM '{table}'"
            ).fetchone()[0]
        return result
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sqlite", required=True)
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--report", default="postgres-import-report.json")
    args = ap.parse_args()

    source = inventory(args.sqlite)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "requested_mode": "execute" if args.execute else "dry-run",
        "postgres_write_enabled": False,
        "transaction_started": False,
        "rollback_available": False,
        "tables": [],
        "status": "pre_write_validation",
    }

    for table in IMPORT_ORDER:
        if table in source:
            report["tables"].append({
                "name": table,
                "rows": source[table],
                "protected": table in PROTECTED_TABLES,
                "state": "requires_review"
                if table in PROTECTED_TABLES
                else "ready_for_future_import"
            })

    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
