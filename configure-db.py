#!/usr/bin/env python3
"""
mini-SIEM database chooser
==========================
Run this ONCE before starting the SIEM to pick where logs are stored:

    python3 configure-db.py

It asks a few questions and writes the non-secret database endpoint to
db-config.json. PostgreSQL schema creation and runtime-role provisioning are
performed later by the dedicated bootstrap flow; this chooser never stores a
customer DBA credential or uses a runtime account for DDL.

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
                "user": "",
                "password": "",
                "connect_timeout": 5,
            },
        }
        print("\nPostgreSQL endpoint recorded without credentials.")
        print("Connection validation, database/owner creation, schema migration, and split runtime")
        print("role provisioning are performed by tools/postgres_bootstrap.py.")
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
    if cfg.get("backend") == "postgres":
        print("\nRequired next step before starting services:")
        print("  MINISIEM_PG_BOOTSTRAP_USER=<customer-admin> sudo -E ./install-services.sh --bootstrap-postgres")
        print("For an existing database, run tools/postgres_bootstrap.py --mode inspect-existing first.")
        print("Customer DBA credentials are bootstrap-only and are not written to runtime configuration.")
    else:
        print("Start the SIEM as usual (python3 siem.py) — it reads this file automatically.")


if __name__ == "__main__":
    main()
