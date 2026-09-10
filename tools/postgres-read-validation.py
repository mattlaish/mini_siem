#!/usr/bin/env python3
"""
mini-SIEM PostgreSQL Read Validation and Migration Unlock Gate.

Read-only validation layer:
- PostgreSQL schema inspection boundary
- source/target row comparison
- duplicate detection report
- approval output
- execution unlock decision

No PostgreSQL mutation is performed.
"""

import argparse
import json
from datetime import datetime, timezone


TABLES = [
    "source_profiles",
    "forwarders",
    "logs",
    "alerts",
    "iocs",
    "ioc_matches",
    "reports",
]

PROTECTED = [
    "users",
    "api_keys",
    "app_config",
    "audit_log",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--approve", action="store_true")
    ap.add_argument("--report", default="postgres-validation-approval.json")
    args = ap.parse_args()

    checks = {
        "postgres_connection": "pending",
        "schema_inspection": "pending",
        "row_comparison": "pending",
        "duplicate_detection": "pending",
        "identity_validation": "pending",
    }

    passed = all(v == "passed" for v in checks.values())

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "read-only",
        "database_mutation": False,
        "schema_inspection": {
            "status": "pending",
            "tables_checked": TABLES,
        },
        "source_target_comparison": {
            "status": "pending",
            "tables": TABLES,
        },
        "duplicate_report": {
            "status": "pending",
            "duplicates": [],
        },
        "checks": checks,
        "approval": {
            "requested": args.approve,
            "migration_unlocked": False if not passed else args.approve,
            "reason": "validation evidence required",
        },
        "protected_tables": PROTECTED,
    }

    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
