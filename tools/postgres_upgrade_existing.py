#!/usr/bin/env python3
"""Upgrade an existing split-role PostgreSQL mini-SIEM deployment in place.

This tool is deliberately different from fresh bootstrap:
- it never creates PostgreSQL roles;
- it never rotates existing runtime passwords;
- it tightens owner default privileges before creating new schema objects;
- it applies owner migrations, idempotent Event Storage v2 backfill and grants;
- it verifies the existing listener/dashboard/maintenance credential files.

The owner password is accepted only from MINISIEM_PG_OWNER_PASSWORD or a TTY
prompt and is never written to disk by this tool.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import db
from tools import postgres_event_storage_v2 as esv2
from tools import postgres_privilege_boundary as boundary
from event_storage_v2 import postgres_schema_statements

CREDENTIAL_FILES = {
    "listener": "db-listener-credentials.json",
    "dashboard": "db-dashboard-credentials.json",
    "maintenance": "db-maintenance-credentials.json",
}


def _raw_owner_connection(cfg):
    try:
        import psycopg2
    except ImportError as exc:
        raise SystemExit("psycopg2-binary is required") from exc
    p = cfg["postgres"]
    return psycopg2.connect(
        host=p["host"], port=p["port"], dbname=p["dbname"],
        user=p["user"], password=p.get("password", ""),
        connect_timeout=int(p.get("connect_timeout", 5)),
    )


def _require_existing_split_state(config_path: Path, cfg: dict):
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    pb = raw.get("postgres_privilege_boundary") or {}
    if not pb.get("enabled"):
        raise RuntimeError(
            "upgrade-existing requires an already split-role PostgreSQL deployment; "
            "legacy shared-role ownership must use the separate controlled legacy migration path"
        )
    missing = []
    for filename in CREDENTIAL_FILES.values():
        p = config_path.parent / filename
        if not p.is_file():
            missing.append(str(p))
    if missing:
        raise RuntimeError("existing split-role credential files are missing: " + ", ".join(missing))
    return {
        "runtime_role": pb.get("runtime_role") or boundary.DEFAULT_RUNTIME_ROLE,
        "ingest_role": pb.get("ingest_role") or boundary.DEFAULT_INGEST_ROLE,
        "dashboard_role": pb.get("dashboard_role") or boundary.DEFAULT_DASHBOARD_ROLE,
        "maintenance_role": pb.get("maintenance_role") or boundary.DEFAULT_MAINTENANCE_ROLE,
        "owner_role": pb.get("owner_role") or cfg["postgres"].get("user") or "",
    }


def _migration_versions(conn):
    try:
        rows = conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
    except Exception:
        return []
    return [int(r["version"] if isinstance(r, dict) else r[0]) for r in rows]




def _execute_upgrade_sql(conn, *, stage: str, statement: str):
    """Execute one owner-only upgrade statement with screen-visible context."""
    compact = " ".join(statement.strip().split())
    preview = compact[:180] + ("..." if len(compact) > 180 else "")
    print(f"[upgrade-sql] {stage}: {preview}", flush=True)
    try:
        conn.execute_raw(statement) if hasattr(conn, "execute_raw") else conn.execute(statement, ())
    except Exception as exc:
        try:
            conn.rollback()
        except Exception:
            pass
        print(f"[upgrade-sql] FAILED {stage}: {exc}", file=sys.stderr, flush=True)
        print(f"[upgrade-sql] statement: {statement}", file=sys.stderr, flush=True)
        raise RuntimeError(f"{stage} failed: {exc}") from exc


def _record_migration(conn, version: int):
    from datetime import datetime, timezone
    conn.execute(
        "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?) "
        "ON CONFLICT(version) DO NOTHING",
        (int(version), datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def _upgrade_existing_owner_schema(cfg: dict):
    """Apply only pending existing-deployment migrations.

    Existing upgrades must not call db.initialize(), because that is the generic
    bootstrap/current-schema path used by fresh/SQLite setup.  A production DB
    with a populated migration ledger is instead advanced in explicit order:
    legacy ledger migrations through v30, normalized-field repair, Event Storage
    v2 DDL, then boundary markers 31-33.
    """
    conn = db.connect(cfg)
    try:
        # The existing upgrade path requires a ledger.  Do not silently baseline
        # a production database because that can hide an unknown historical state.
        try:
            rows = conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
        except Exception as exc:
            raise RuntimeError(
                "existing PostgreSQL upgrade requires schema_migrations; "
                f"cannot read migration ledger: {exc}"
            ) from exc
        applied = {int(r["version"] if isinstance(r, dict) else r[0]) for r in rows}
        if not applied:
            raise RuntimeError("existing PostgreSQL upgrade has an empty migration ledger; refusing implicit baseline")

        migrations = db._migrations()
        for version in range(1, min(30, len(migrations)) + 1):
            if version in applied:
                continue
            _execute_upgrade_sql(
                conn,
                stage=f"migration-v{version}",
                statement=migrations[version - 1],
            )
            _record_migration(conn, version)
            applied.add(version)

        print("[upgrade-sql] normalized-log-fields: checking value_norm/index", flush=True)
        try:
            db.ensure_log_fields_normalized_schema(conn)
        except Exception as exc:
            try:
                conn.rollback()
            except Exception:
                pass
            raise RuntimeError(f"normalized-log-fields failed: {exc}") from exc

        statements = list(postgres_schema_statements())
        for index, statement in enumerate(statements, start=1):
            _execute_upgrade_sql(
                conn,
                stage=f"event-storage-v2-{index:02d}/{len(statements):02d}",
                statement=statement,
            )
        conn.commit()

        # 31-33 are readiness markers only.  Record them only after all required
        # normalized-field and Event Storage v2 DDL completed successfully.
        for version in (31, 32, 33):
            if version not in applied:
                _record_migration(conn, version)
                applied.add(version)
        return sorted(applied)
    finally:
        conn.close()


def run(config_path: Path, owner_user: str, batch_size: int, qualify: bool):
    cfg = esv2._owner_config(config_path, owner_user)
    roles = _require_existing_split_state(config_path, cfg)
    if not owner_user and not os.environ.get(esv2.OWNER_USER_ENV):
        cfg["postgres"]["user"] = roles["owner_role"]

    # Re-resolve password if the owner inferred from boundary metadata differs
    # from the initial default.  This still remains memory-only.
    if cfg["postgres"]["user"] != roles["owner_role"] and not owner_user:
        cfg = esv2._owner_config(config_path, roles["owner_role"])

    raw = _raw_owner_connection(cfg)
    try:
        boundary._validate_existing_runtime_roles(
            raw,
            runtime_role=roles["runtime_role"],
            ingest_role=roles["ingest_role"],
            dashboard_role=roles["dashboard_role"],
            maintenance_role=roles["maintenance_role"],
        )
        # Critical ordering rule: older deployments may still have broad owner
        # default privileges. Tighten them before Event Storage v2 creates any
        # table/partition.
        boundary.harden_owner_default_privileges(raw, runtime_role=roles["runtime_role"])
    finally:
        raw.close()

    before_conn = db.connect(cfg)
    try:
        versions_before = _migration_versions(before_conn)
    finally:
        before_conn.close()

    # Existing-deployment owner migration is explicit and ledger-driven.
    # Fresh install continues to use db.initialize(); do not route upgrades through it.
    _upgrade_existing_owner_schema(cfg)

    conn = db.connect(cfg)
    try:
        backfill = esv2.backfill(conn, max(100, min(batch_size, 10000)), dry_run=False)
        qualification = esv2.qualify(conn) if qualify else None
        versions_after = _migration_versions(conn)
    finally:
        conn.close()

    # Refresh object grants only. Existing login roles/passwords/membership are
    # validated and preserved; no CREATEROLE authority is needed here.
    raw = _raw_owner_connection(cfg)
    try:
        boundary._apply_grants(
            raw,
            runtime_role=roles["runtime_role"],
            ingest_role=roles["ingest_role"],
            dashboard_role=roles["dashboard_role"],
            maintenance_role=roles["maintenance_role"],
            preserve_existing_roles=True,
        )
    finally:
        raw.close()

    verify_base = {"_path": str(config_path)}
    verified = {}
    for identity, filename in CREDENTIAL_FILES.items():
        verified[identity] = boundary._verify_login(
            verify_base, config_path.parent / filename, identity
        )

    return {
        "mode": "upgrade-existing",
        "owner_password_persisted": False,
        "runtime_credentials_rotated": False,
        "runtime_roles_created": False,
        "migration_versions_before": versions_before,
        "migration_versions_after": versions_after,
        "backfill": backfill,
        "qualification": qualification,
        "verified_identities": {
            name: {
                "role": data["role"],
                "event_read": bool(data["can_read_events_v2"]),
                "event_insert": bool(data["can_insert_events_v2"]),
                "event_delete": bool(data["can_delete_events_v2"]),
            }
            for name, data in verified.items()
        },
    }


def main():
    ap = argparse.ArgumentParser(description="Upgrade an existing split-role PostgreSQL mini-SIEM deployment")
    ap.add_argument("--db-config", default=str(ROOT / "db-config.json"))
    ap.add_argument("--owner-user", default="")
    ap.add_argument("--batch-size", type=int, default=1000)
    ap.add_argument("--qualify", action="store_true")
    args = ap.parse_args()
    try:
        payload = run(Path(args.db_config).resolve(), args.owner_user, args.batch_size, args.qualify)
    finally:
        # Never leave an inherited owner password available to child processes
        # after the Python orchestration exits normally/abnormally.
        os.environ.pop(esv2.OWNER_PASSWORD_ENV, None)
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
