#!/usr/bin/env python3
"""
mini-SIEM PostgreSQL Data Transfer Execution foundation.

Safety:
- explicit execute mode required
- dry-run remains default
- protected tables require preservation checks
- migration evidence report generated

This phase provides execution framework only.
Production PostgreSQL INSERT implementation requires target mapping validation.
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


def snapshot(path):
    conn = sqlite3.connect(path)
    try:
        result = {}
        for t in TABLE_ORDER:
            try:
                result[t] = conn.execute(
                    f"SELECT COUNT(*) FROM '{t}'"
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
    ap.add_argument("--report", default="transfer-execution-report.json")
    args = ap.parse_args()

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "requested_mode": "execute" if args.execute else "dry-run",
        "postgres_write": False,
        "transaction": {
            "begin": False,
            "commit": False,
            "rollback": False
        },
        "status": "execution-framework-only",
        "source_snapshot": snapshot(args.sqlite),
        "protected_tables": sorted(PROTECTED),
        "next_required_step": "enable validated PostgreSQL table writers"
    }

    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
