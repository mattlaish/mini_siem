#!/usr/bin/env python3
"""
mini-SIEM Transactional Import + Verification foundation.

Planning only. No PostgreSQL writes.
"""
import argparse
import json
import sqlite3
from datetime import datetime, timezone

TABLES = [
    "users","app_config","api_keys","source_profiles","forwarders",
    "logs","alerts","iocs","ioc_matches","reports","audit_log"
]

PROTECTED = {"users","api_keys","app_config","audit_log"}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sqlite", required=True)
    ap.add_argument("--report", default="transaction-report.json")
    args = ap.parse_args()

    con = sqlite3.connect(args.sqlite)
    try:
        rows = {}
        for t in TABLES:
            try:
                rows[t] = con.execute(
                    f"SELECT COUNT(*) FROM '{t}'"
                ).fetchone()[0]
            except sqlite3.Error:
                pass
    finally:
        con.close()

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "postgres_write": False,
        "transaction": {
            "begin": False,
            "commit": False,
            "rollback": False
        },
        "verification": {
            "row_count": "planned",
            "identity": "planned",
            "integrity": "planned"
        },
        "tables": [
            {"table": t, "rows": rows[t], "protected": t in PROTECTED}
            for t in rows
        ]
    }

    with open(args.report, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
