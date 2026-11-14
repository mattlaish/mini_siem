#!/usr/bin/env python3
"""Bounded runtime maintenance for PostgreSQL Event Storage v2 partitions.

This command is intended for the dedicated ``minisiem_maintenance`` database
identity.  It performs no direct CREATE/ALTER statements.  Instead it verifies
runtime schema readiness, then calls the owner-defined SECURITY DEFINER
``minisiem_ensure_security_event_partitions`` function whose argument is
bounded to 1..24 months by the function itself.

It also removes senders older than 15 days from the silent-source summary
through the bounded ``minisiem_prune_log_sources`` function. No partition
deletion/retention is performed here.  Evidence retention remains
an explicit archive/retention workflow rather than a hidden timer side effect.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import db


# Senders not seen for this many days leave the silent-source summary; the
# dashboard lists senders silent for 3 days within a 14-day baseline.
SOURCE_SUMMARY_DAYS = 15


def maintain(config_path: Path, credentials_path: Path, months: int) -> dict:
    if months < 1 or months > 24:
        raise ValueError("months must be between 1 and 24")
    cfg = db.load_config(str(config_path), credentials_path=str(credentials_path))
    if cfg.get("backend") != "postgres":
        raise RuntimeError("PostgreSQL backend is required")

    # Runtime maintenance is fail-closed: it may only run against a schema the
    # owner has already migrated to the current application version.
    db.ensure_runtime_ready(cfg)
    conn = db.connect(cfg)
    try:
        row = conn.execute(
            "SELECT current_user AS role, "
            "public.minisiem_ensure_security_event_partitions(now(), ?) AS created, "
            "public.minisiem_prune_log_sources(?) AS pruned",
            (months, SOURCE_SUMMARY_DAYS),
        ).fetchone()
        conn.commit()
        role = row["role"] if isinstance(row, dict) else row[0]
        created = int(row["created"] if isinstance(row, dict) else row[1])
        pruned = int(row["pruned"] if isinstance(row, dict) else row[2])
        return {"ok": True, "role": role, "months": months, "created": created,
                "pruned_sources": pruned}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="Pre-create bounded PostgreSQL Event Storage v2 partitions")
    ap.add_argument("--db-config", default=str(ROOT / "db-config.json"))
    ap.add_argument("--db-credentials", default=str(ROOT / "db-maintenance-credentials.json"))
    ap.add_argument("--months", type=int, default=3)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    result = maintain(Path(args.db_config).resolve(), Path(args.db_credentials).resolve(), args.months)
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            "Event Storage partition maintenance: PASS "
            f"role={result['role']} months={result['months']} created={result['created']} "
            f"pruned_sources={result['pruned_sources']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
