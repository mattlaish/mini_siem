#!/usr/bin/env python3
"""
mini-SIEM database chooser
==========================
Run this ONCE before starting the SIEM to pick where logs are stored:

    python3 configure-db.py

It asks a few questions, writes db-config.json, and (for PostgreSQL)
tests the connection and creates the tables so you know it works before
you go live. Re-run it any time to switch backends.

  * SQLite   — default, zero setup, one file. Great for a handful to a
               few dozen devices. No server to run.
  * PostgreSQL — external server; real concurrent writes, scales much
               further. Needs a reachable Postgres and `psycopg2-binary`.

Switching backends does NOT copy existing data between them — it points
the SIEM at a different store. Decide up front (that's the point of
running this before installation).
"""

import json
import os
import sys

import db as dbmod

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "db-config.json")


def ask(prompt, default=""):
    val = input(f"{prompt} [{default}]: ").strip()
    return val or default


def main():
    print(__doc__)
    print("Which backend?")
    print("  1) SQLite (local, default)")
    print("  2) PostgreSQL (external server)")
    choice = ask("Enter 1 or 2", "1")

    if choice == "2":
        cfg = {
            "backend": "postgres",
            "sqlite": {"path": "siem.db"},
            "postgres": {
                "host": ask("Postgres host", "localhost"),
                "port": int(ask("Postgres port", "5432")),
                "dbname": ask("Database name", "minisiem"),
                "user": ask("Username", "minisiem"),
                "password": ask("Password", ""),
            },
        }
        print("\nChecking psycopg2 driver...")
        try:
            import psycopg2  # noqa: F401
            print("  psycopg2: OK")
        except ImportError:
            print("  psycopg2 is NOT installed. Install it first:")
            print("      pip install psycopg2-binary")
            print("  (config not written)")
            sys.exit(1)

        print("Testing connection and creating tables...")
        ok, detail = dbmod.test_connection(cfg)
        if not ok:
            print(f"  FAILED: {detail}")
            print("  Fix the connection details / Postgres server, then re-run. (config not written)")
            sys.exit(1)
        print(f"  {detail}")
        dbmod.initialize(cfg)
        print("  Tables created / verified.")
    else:
        path = ask("SQLite file path", "siem.db")
        cfg = {
            "backend": "sqlite",
            "sqlite": {"path": path},
            "postgres": {"host": "localhost", "port": 5432,
                         "dbname": "minisiem", "user": "minisiem", "password": ""},
        }
        dbmod.initialize(cfg)
        print(f"  SQLite ready at {path} (tables created / verified).")

    # --- syslog listen ports -------------------------------------------
    # Ask which port(s) the syslog listener should bind. Persisted into the
    # same config file so `siem.py` reads it at startup (the listener binds
    # ports before the web UI exists, so this belongs here, not in Setup).
    print("\nSyslog listen ports")
    print("  Which UDP/TCP port(s) should mini-SIEM receive syslog on?")
    print("  514 is the standard (needs root/CAP_NET_BIND on Linux).")
    print("  Add others comma-separated, e.g. a device that only sends to 10514.")
    ports_raw = ask("Listen port(s), comma-separated", "514")
    try:
        ports = [int(p.strip()) for p in ports_raw.split(",") if p.strip()]
        if not ports:
            ports = [514]
    except ValueError:
        print(f"  '{ports_raw}' isn't a valid port list; defaulting to 514.")
        ports = [514]
    cfg["listen_ports"] = ports
    print(f"  Will listen on: {', '.join(map(str, ports))}")

    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)
    print(f"\nWrote {CONFIG_PATH}")
    print(f"Backend set to: {dbmod.describe(cfg)}")
    print("Start the SIEM as usual (python3 siem.py) — it reads this file automatically.")


if __name__ == "__main__":
    main()
