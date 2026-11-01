#!/usr/bin/env python3
"""Verify cataloged mini-SIEM archive segment checksums and readability."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import archive
import db


def main():
    ap = argparse.ArgumentParser(description="Verify sealed mini-SIEM archive segments")
    ap.add_argument("--config", default="db-config.json")
    ap.add_argument("--db-credentials", default=None,
                    help="PostgreSQL read credential overlay (dashboard is sufficient)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args()

    cred = args.db_credentials
    if cred is None:
        try:
            raw = json.load(open(args.config, encoding="utf-8"))
            if ((raw.get("postgres_privilege_boundary") or {}).get("enabled")):
                from pathlib import Path
                candidate = Path(args.config).resolve().parent / "db-dashboard-credentials.json"
                if candidate.exists():
                    cred = str(candidate)
        except Exception:
            pass
    cfg = db.load_config(args.config, credentials_path=cred)
    db.ensure_runtime_ready(cfg)
    conn = db.connect(cfg)
    try:
        results = archive.verify_catalog(conn)
        summary = archive.archive_summary(conn)
        ok = all(item.get("ok") for item in results)
        payload = {"ok": ok, "summary": summary, "segments": results}
        status = {
            "ok": ok, "mode": "catalog_scan",
            "checked_segments": len(results),
            "failed_segments": sum(1 for item in results if not item.get("ok")),
        }
        try:
            db.runtime_stat_upsert(
                conn, "archive_verify_status",
                value_text=json.dumps(status, separators=(",", ":"), sort_keys=True),
            )
            conn.commit()
        except Exception:
            # Verification result is still printed even if operational-status
            # persistence is unavailable to the selected read identity.
            try:
                conn.rollback()
            except Exception:
                pass
    finally:
        conn.close()
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
