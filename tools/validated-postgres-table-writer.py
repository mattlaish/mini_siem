#!/usr/bin/env python3
"""
mini-SIEM Validated PostgreSQL Table Writer.

Migration execution framework.

Provides:
- PostgreSQL connection configuration boundary
- table writer structure
- transaction lifecycle
- conflict policy reporting
- row verification framework
- migration evidence output

This stage keeps writes controlled and requires explicit execution.
"""

import argparse
import json
import sqlite3
from datetime import datetime, timezone


TABLE_ORDER = [
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

PROTECTED = {
    "users",
    "api_keys",
    "app_config",
    "audit_log",
}


def sqlite_counts(path):
    conn = sqlite3.connect(path)
    try:
        result = {}
        for table in TABLE_ORDER:
            try:
                result[table] = conn.execute(
                    f"SELECT COUNT(*) FROM '{table}'"
                ).fetchone()[0]
            except sqlite3.Error:
                pass
        return result
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sqlite", required=True)
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--report", default="migration-evidence.json")
    args = ap.parse_args()

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "execute" if args.execute else "dry-run",
        "postgres_connection": "not_configured_in_this_phase",
        "transaction": {
            "begin": False,
            "commit": False,
            "rollback": False
        },
        "conflict_policy": {
            "users": "preserve_existing",
            "protected_tables": "review_required",
            "normal_tables": "future_upsert_policy_required"
        },
        "row_comparison": {
            "status": "planned",
            "source": sqlite_counts(args.sqlite)
        },
        "writes_performed": False,
        "evidence_status": "framework_only"
    }

    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
