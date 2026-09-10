#!/usr/bin/env python3
"""
SQLite -> PostgreSQL data migration foundation for mini-SIEM.

Safety goals:
- Never delete PostgreSQL data.
- Never overwrite existing users.
- Migration is explicit, not automatic.
- Schema initialization and data migration are separate operations.

Current mode:
- Inventory / plan only.
- No PostgreSQL writes are performed.
"""

import argparse
import json
import sqlite3

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sqlite", required=True)
    args = ap.parse_args()

    con = sqlite3.connect(args.sqlite)
    try:
        tables = [
            r[0]
            for r in con.execute(
                "select name from sqlite_master where type='table' order by name"
            )
        ]
    finally:
        con.close()

    print(json.dumps({
        "source": args.sqlite,
        "tables_found": tables,
        "mode": "plan_only",
        "note": "No PostgreSQL writes performed"
    }, indent=2))

if __name__ == "__main__":
    main()
