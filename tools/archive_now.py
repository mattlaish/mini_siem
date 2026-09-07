#!/usr/bin/env python3
"""Run one configured mini-SIEM archive/maintenance cycle on demand."""

import argparse
import json

import db
from listener import Storage
from maintenance import run_maintenance_cycle


def main():
    ap = argparse.ArgumentParser(description="Run one mini-SIEM archive/maintenance cycle")
    ap.add_argument("--config", default="db-config.json")
    args = ap.parse_args()
    cfg = db.load_config(args.config)
    storage = Storage(db_config=cfg)
    try:
        result = run_maintenance_cycle(storage, cfg)
    finally:
        storage.close()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result.get("error") or (result.get("archive") or {}).get("error") else 0


if __name__ == "__main__":
    raise SystemExit(main())
