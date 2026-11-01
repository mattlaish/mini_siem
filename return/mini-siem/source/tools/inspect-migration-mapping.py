#!/usr/bin/env python3
"""
mini-SIEM SQLite to PostgreSQL migration mapping inspector.

This phase only inspects and reports. It does not modify databases.
"""
import argparse
import json
import sqlite3


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sqlite", required=True)
    args = ap.parse_args()

    conn = sqlite3.connect(args.sqlite)
    try:
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' ORDER BY name"
            )
        ]
        result = {}
        for table in tables:
            cols = [
                {"name": r[1], "type": r[2]}
                for r in conn.execute(f"PRAGMA table_info('{table}')")
            ]
            result[table] = cols
    finally:
        conn.close()

    print(json.dumps({
        "mode": "mapping_inspection_only",
        "tables": result,
        "postgres_write": False
    }, indent=2))


if __name__ == "__main__":
    main()
