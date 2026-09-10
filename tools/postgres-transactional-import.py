#!/usr/bin/env python3
"""
mini-SIEM PostgreSQL Transactional Import.

Safety-first implementation stage.

Current behavior:
- connects only when explicitly configured
- requires --execute for write mode
- keeps transaction lifecycle explicit
- protected tables require review

This foundation does not automatically overwrite existing data.
"""

import argparse
import json
import sqlite3
from datetime import datetime, timezone

PROTECTED = {
    "users",
    "api_keys",
    "app_config",
    "audit_log",
}

ORDER = [
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


def inventory(sqlite_path):
    conn = sqlite3.connect(sqlite_path)
    try:
        result = {}
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ):
            table = row[0]
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
    ap.add_argument("--report", default="pg-import-result.json")
    args = ap.parse_args()

    source = inventory(args.sqlite)

    report = {
        "time": datetime.now(timezone.utc).isoformat(),
        "mode": "execute" if args.execute else "dry-run",
        "postgres_transaction": {
            "begin": False,
            "commit": False,
            "rollback": False,
        },
        "writes_performed": False,
        "protected_tables": sorted(PROTECTED),
        "tables": [
            {
                "table": t,
                "rows": source[t],
                "requires_review": t in PROTECTED,
            }
            for t in ORDER if t in source
        ],
        "status": "prepared_only",
    }

    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
