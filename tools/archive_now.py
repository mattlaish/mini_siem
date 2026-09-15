#!/usr/bin/env python3
"""Run one configured mini-SIEM archive/maintenance cycle on demand."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import db
from listener import Storage
from maintenance import run_maintenance_cycle


def main():
    ap = argparse.ArgumentParser(description="Run one mini-SIEM archive/maintenance cycle")
    ap.add_argument("--config", default="db-config.json")
    ap.add_argument("--db-credentials", default=None,
                    help="PostgreSQL maintenance credential overlay")
    args = ap.parse_args()
    cred = args.db_credentials
    if cred is None:
        try:
            raw = json.load(open(args.config, encoding="utf-8"))
            if ((raw.get("postgres_privilege_boundary") or {}).get("enabled")):
                candidate = Path(args.config).resolve().parent / "db-maintenance-credentials.json"
                if candidate.exists():
                    cred = str(candidate)
        except Exception:
            pass
    cfg = db.load_config(args.config, credentials_path=cred)
    if cfg.get("backend") == "postgres" and (cfg.get("postgres_privilege_boundary") or {}).get("enabled"):
        if cfg.get("_credentials_identity") != "maintenance":
            raise SystemExit("archive move requires the dedicated maintenance PostgreSQL identity")
    storage = Storage(db_config=cfg)
    try:
        result = run_maintenance_cycle(storage, cfg)
    finally:
        storage.close()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result.get("error") or (result.get("archive") or {}).get("error") else 0


if __name__ == "__main__":
    raise SystemExit(main())
