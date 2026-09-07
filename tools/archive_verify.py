#!/usr/bin/env python3
"""Verify cataloged mini-SIEM archive segment checksums and readability."""

import argparse
import json
import sys

import archive
import db


def main():
    ap = argparse.ArgumentParser(description="Verify sealed mini-SIEM archive segments")
    ap.add_argument("--config", default="db-config.json")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args()

    cfg = db.load_config(args.config)
    db.initialize(cfg)
    conn = db.connect(cfg)
    try:
        results = archive.verify_catalog(conn)
        summary = archive.archive_summary(conn)
    finally:
        conn.close()
    ok = all(item.get("ok") for item in results)
    payload = {"ok": ok, "summary": summary, "segments": results}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"archive segments: {summary.get('segments', 0)}; archived events: {summary.get('archived_events', 0)}")
        for item in results:
            state = "OK" if item.get("ok") else "FAIL"
            line = f"{state} {item.get('segment_id')}"
            if item.get("error"):
                line += f" - {item['error']}"
            print(line)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
