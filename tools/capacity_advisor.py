#!/usr/bin/env python3
"""Scan this machine and recommend how many ingest processes to run.

    python tools/capacity_advisor.py                     # scan + measure, print report
    python tools/capacity_advisor.py --quick             # scan only (no measurement)
    python tools/capacity_advisor.py --json              # machine-readable
    python tools/capacity_advisor.py --write             # save to db-config.json "ingest"

The same scan runs inside the listener when db-config.json sets
"ingest": {"processes": "auto"}, and on System Health → Processing capacity.
Measurement starts one Python process (memory) and times parsing, field
extraction and rule checks for a few seconds; database writes are excluded.
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import capacity  # noqa: E402
import db as dbmod  # noqa: E402


def _ioc_count(db_config):
    try:
        conn = dbmod.connect(db_config)
        try:
            return int(conn.execute("SELECT COUNT(*) AS n FROM iocs WHERE enabled=1").fetchone()["n"])
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 - no database yet: plan without indicators
        return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db-config", default=None, help="path to db-config.json (default: next to the application)")
    ap.add_argument("--db", default="siem.db", help="SQLite path when no db-config.json exists")
    ap.add_argument("--quick", action="store_true", help="scan only; skip the memory probe and benchmark")
    ap.add_argument("--seconds", type=float, default=3.0, help="benchmark duration (default 3)")
    ap.add_argument("--json", action="store_true", help="print JSON instead of a report")
    ap.add_argument("--write", action="store_true", help='save the recommendation to db-config.json "ingest"')
    args = ap.parse_args(argv)

    config_path = args.db_config or os.path.join(ROOT, "db-config.json")
    db_config = dbmod.load_config(config_path if os.path.exists(config_path) else None, sqlite_fallback=args.db)
    scan = capacity.scan(db_config)
    process_mb = bench = None
    if not args.quick:
        process_mb = capacity.measure_process_memory()
        bench = capacity.benchmark(args.seconds)
    iocs = _ioc_count(db_config)
    rec = capacity.recommend(scan, process_mb, bench and bench["events_per_second"], ioc_count=iocs)
    result = {"scan": scan, "process_mb": process_mb, "benchmark": bench, "threat_indicators": iocs,
              "recommendation": rec}

    if args.write:
        saved = {"processes": rec["processes"], "threads": rec["threads"], "queue_size": rec["queue_size"]}
        cfg = {}
        if os.path.exists(config_path):
            with open(config_path, encoding="utf-8") as f:
                cfg = json.load(f)
        cfg["ingest"] = saved
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        result["written"] = {"path": config_path, "ingest": saved}

    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    cpu, mem, db = scan["cpu"], scan["memory"], scan["database"]
    print(f"Machine        {scan['host']} · {scan['platform']} · Python {scan['python']}")
    print(f"CPU            {cpu['effective']} usable of {cpu['logical']} logical"
          + (f" (container quota {cpu['container_quota']})" if cpu["container_quota"] else ""))
    print(f"Memory         {mem['available_mb']} MB available of {mem['total_mb']} MB"
          + (f" (container limit {mem['container_limit_mb']} MB)" if mem["container_limit_mb"] else ""))
    print(f"Load           {scan['load_average'] or 'n/a'}")
    print(f"Database       {db['backend']}" + (f" at {db.get('host')}" if db["backend"] == "postgres" else f" ({db.get('path')})"))
    print(f"Indicators     {iocs:,} enabled threat indicators")
    if process_mb is not None or bench:
        print(f"Measured       {process_mb} MB per process at start; "
              f"{bench['events_per_second']:,} events/s per process (CPU only, no database writes)")
    print()
    print(f"Recommended    {rec['processes']} ingest process(es)"
          + (f", {rec['threads']} worker threads" if rec["processes"] == 1 else "")
          + f", {rec['queue_size']} queued messages per process")
    for reason in rec["reasons"]:
        print(f"  - {reason}")
    for warning in rec["warnings"]:
        print(f"  ! {warning}")
    if args.write:
        print(f"\nSaved to {config_path}. Restart the log collection service to apply.")
    else:
        print('\nApply with --write, or set "ingest": {"processes": "auto"} in db-config.json to size at every start.')
    return 0


if __name__ == "__main__":
    sys.exit(main())
