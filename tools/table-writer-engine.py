#!/usr/bin/env python3
"""
mini-SIEM Table Writer Engine foundation.

Implements controlled writer workflow:
- table allow-list
- explicit writer ordering
- conflict decision boundary
- evidence generation

This stage does not execute PostgreSQL writes.
"""

import argparse
import json
from datetime import datetime, timezone

WRITABLE_ORDER = [
    "source_profiles",
    "forwarders",
    "logs",
    "alerts",
    "iocs",
    "ioc_matches",
    "reports",
]

PROTECTED = {
    "users",
    "api_keys",
    "app_config",
    "audit_log",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--report", default="table-writer-evidence.json")
    args = ap.parse_args()

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "execute" if args.execute else "dry-run",
        "writers": [
            {
                "table": table,
                "action": "writer_ready",
                "conflict_policy": "pending_validation",
            }
            for table in WRITABLE_ORDER
        ],
        "protected_tables": sorted(PROTECTED),
        "postgres_insert": False,
        "transaction": {
            "begin": False,
            "commit": False,
            "rollback": False,
        },
        "evidence": "framework_only",
    }

    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
