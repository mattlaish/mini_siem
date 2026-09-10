#!/usr/bin/env python3
"""
mini-SIEM Real Data Transfer Verification stage.

This stage introduces verification workflow:
- source snapshot
- expected row counts
- identity preservation checks
- migration evidence report

No destructive PostgreSQL operation is performed.
"""

import argparse
import json
import sqlite3
from datetime import datetime, timezone

IMPORTANT_TABLES = [
    "users",
    "app_config",
    "api_keys",
    "logs",
    "alerts",
    "iocs",
    "audit_log",
]

PROTECTED = {
    "users",
    "api_keys",
    "app_config",
    "audit_log",
}


def snapshot(sqlite_path):
    conn = sqlite3.connect(sqlite_path)
    try:
        result = {}
        for table in IMPORTANT_TABLES:
            try:
                result[table] = conn.execute(
                    f"SELECT COUNT(*) FROM '{table}'"
                ).fetchone()[0]
            except sqlite3.Error:
                result[table] = None
        return result
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sqlite", required=True)
    ap.add_argument("--report", default="migration-verification.json")
    args = ap.parse_args()

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stage": "data_transfer_verification",
        "postgres_write": False,
        "source_snapshot": snapshot(args.sqlite),
        "checks": {
            "row_count_verification": "pending",
            "admin_identity_preservation": "pending",
            "integrity_validation": "pending",
        },
        "protected_tables": sorted(PROTECTED),
    }

    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
