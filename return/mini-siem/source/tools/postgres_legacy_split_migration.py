#!/usr/bin/env python3
"""Convert a legacy shared-owner PostgreSQL deployment to split runtime roles.

The legacy database owner is intentionally retained as the dedicated schema /
migration owner.  This avoids a risky object/database ownership rename during
an operational upgrade while still removing the owner credential from runtime
configuration and moving listener/dashboard/maintenance onto least-privilege
component identities.

A temporary PostgreSQL role-administrator credential is required to create or
rotate the split runtime login roles.  It is read only from
MINISIEM_PG_BOOTSTRAP_PASSWORD (or a TTY prompt) and is never persisted.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import db
from tools import postgres_bootstrap as bootstrap
from tools import postgres_privilege_boundary as boundary
from tools import postgres_upgrade_existing as existing_upgrade
from tools import postgres_event_storage_v2 as esv2

BOOTSTRAP_PASSWORD_ENV = bootstrap.BOOTSTRAP_PASSWORD_ENV
OWNER_PASSWORD_ENV = boundary.OWNER_PASSWORD_ENV

CREDENTIAL_FILES = {
    "listener": "db-listener-credentials.json",
    "dashboard": "db-dashboard-credentials.json",
    "maintenance": "db-maintenance-credentials.json",
}
ROLE_BY_IDENTITY = {
    "listener": boundary.DEFAULT_INGEST_ROLE,
    "dashboard": boundary.DEFAULT_DASHBOARD_ROLE,
    "maintenance": boundary.DEFAULT_MAINTENANCE_ROLE,
}


def _read(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _atomic_json(path: Path, payload: dict, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def _connect(psycopg2, cfg: dict, *, user: str, password: str):
    p = cfg["postgres"]
    return psycopg2.connect(
        host=p.get("host") or "localhost",
        port=int(p.get("port") or 5432),
        dbname=p.get("dbname") or "minisiem",
        user=user,
        password=password,
        connect_timeout=int(p.get("connect_timeout") or 5),
    )


def _legacy_state(config_path: Path, owner_user: str = "") -> tuple[dict, str, str]:
    raw = _read(config_path)
    if raw.get("backend") != "postgres":
        raise RuntimeError("legacy split-role migration requires PostgreSQL backend")
    pb = raw.get("postgres_privilege_boundary") or {}
    if pb.get("enabled"):
        raise RuntimeError("PostgreSQL privilege boundary is already enabled; use normal upgrade-existing")
    pg = raw.get("postgres") or {}
    legacy_owner = owner_user or os.environ.get("MINISIEM_PG_OWNER_USER") or str(pg.get("user") or "")
    if not legacy_owner:
        raise RuntimeError("legacy PostgreSQL owner/runtime username is missing")
    owner_password = os.environ.get(OWNER_PASSWORD_ENV) or str(pg.get("password") or "")
    if not owner_password:
        raise RuntimeError(
            f"legacy owner password is required via {OWNER_PASSWORD_ENV} or the existing db-config.json"
        )
    return raw, legacy_owner, owner_password


def _verify_legacy_owner(raw_conn, owner_role: str) -> dict:
    cur = raw_conn.cursor()
    try:
        cur.execute("SELECT current_user, pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()")
        row = cur.fetchone()
        current_user, database_owner = (row.values() if isinstance(row, dict) else row)
        if current_user != owner_role:
            raise RuntimeError(f"legacy owner connection resolved as {current_user!r}, expected {owner_role!r}")
        if database_owner != owner_role:
            raise RuntimeError(
                f"legacy shared-role migration requires the configured owner/runtime role to own the database; "
                f"database owner is {database_owner!r}, configured legacy role is {owner_role!r}"
            )

        cur.execute("SELECT to_regclass('public.schema_migrations')")
        exists_row = cur.fetchone()
        exists = next(iter(exists_row.values())) if isinstance(exists_row, dict) else exists_row[0]
        if not exists:
            raise RuntimeError("legacy PostgreSQL deployment has no schema_migrations ledger; refusing implicit adoption")

        required = tuple(db.RUNTIME_REQUIRED_TABLES)
        cur.execute(
            """
            SELECT c.relname, r.rolname
              FROM pg_class c
              JOIN pg_namespace n ON n.oid=c.relnamespace
              JOIN pg_roles r ON r.oid=c.relowner
             WHERE n.nspname='public'
               AND (c.relname = ANY(%s) OR c.relname LIKE 'security_events_%%')
               AND c.relkind IN ('r','p','v','m','S')
               AND r.rolname <> %s
             ORDER BY c.relname
            """,
            (list(required), owner_role),
        )
        wrong = [dict(name=r[0], owner=r[1]) if not isinstance(r, dict) else dict(r) for r in cur.fetchall()]
        if wrong:
            raise RuntimeError(
                "legacy migration found application objects not owned by the configured shared owner: "
                + json.dumps(wrong, sort_keys=True)
            )
        return {"owner_role": owner_role, "database_owner": database_owner, "wrong_owners": wrong}
    finally:
        cur.close()


def _candidate_config(base: dict, owner_role: str) -> dict:
    out = json.loads(json.dumps(base))
    pg = out.setdefault("postgres", {})
    pg["user"] = ""
    pg["password"] = ""
    out["postgres_privilege_boundary"] = {
        "enabled": True,
        "owner_role": owner_role,
        "runtime_role": boundary.DEFAULT_RUNTIME_ROLE,
        "ingest_role": boundary.DEFAULT_INGEST_ROLE,
        "dashboard_role": boundary.DEFAULT_DASHBOARD_ROLE,
        "maintenance_role": boundary.DEFAULT_MAINTENANCE_ROLE,
    }
    return out


def _verify_candidate(config_path: Path, candidate: dict, passwords: dict) -> dict:
    root = config_path.parent
    temp_paths: list[Path] = []
    verified = {}
    try:
        fd, cfg_name = tempfile.mkstemp(prefix=".db-config.legacy-split-", suffix=".json", dir=str(root))
        os.close(fd)
        cfg_path = Path(cfg_name)
        temp_paths.append(cfg_path)
        boundary._write_json(cfg_path, candidate, mode=0o600)

        for identity, filename in CREDENTIAL_FILES.items():
            fd, cred_name = tempfile.mkstemp(prefix=f".{filename}.legacy-split-", suffix=".json", dir=str(root))
            os.close(fd)
            cred_path = Path(cred_name)
            temp_paths.append(cred_path)
            role = ROLE_BY_IDENTITY[identity]
            boundary._write_json(
                cred_path,
                boundary._component_config(candidate, role, passwords[role], identity),
                mode=0o600,
            )
            verified[identity] = boundary._verify_login({"_path": str(cfg_path)}, cred_path, identity)
        return verified
    finally:
        for path in temp_paths:
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def run(config_path: Path, *, bootstrap_user: str, bootstrap_password: str,
        owner_user: str = "") -> dict:
    base, legacy_owner, owner_password = _legacy_state(config_path, owner_user)
    try:
        import psycopg2
    except ImportError as exc:
        raise RuntimeError("psycopg2-binary is required for legacy PostgreSQL migration") from exc

    owner_raw = _connect(psycopg2, base, user=legacy_owner, password=owner_password)
    role_admin = _connect(psycopg2, base, user=bootstrap_user, password=bootstrap_password)
    try:
        legacy = _verify_legacy_owner(owner_raw, legacy_owner)
        p = base["postgres"]
        preflight = bootstrap._bootstrap_preflight(
            role_admin,
            host=str(p.get("host") or "localhost"),
            port=int(p.get("port") or 5432),
            bootstrap_db=str(p.get("dbname") or "minisiem"),
            requested_user=bootstrap_user,
        )
        # Create the split identities before owner DDL so owner default
        # privileges can be tightened *before* Event Storage v2 creates new
        # tables/partitions.  Passwords are generated in memory only.
        passwords = boundary._provision_runtime_roles(
            role_admin,
            runtime_role=boundary.DEFAULT_RUNTIME_ROLE,
            ingest_role=boundary.DEFAULT_INGEST_ROLE,
            dashboard_role=boundary.DEFAULT_DASHBOARD_ROLE,
            maintenance_role=boundary.DEFAULT_MAINTENANCE_ROLE,
        )
        boundary.harden_owner_default_privileges(
            owner_raw, runtime_role=boundary.DEFAULT_RUNTIME_ROLE
        )

        owner_cfg = json.loads(json.dumps(base))
        owner_cfg["postgres"]["user"] = legacy_owner
        owner_cfg["postgres"]["password"] = owner_password
        versions_before_conn = db.connect(owner_cfg)
        try:
            versions_before = existing_upgrade._migration_versions(versions_before_conn)
        finally:
            versions_before_conn.close()

        # Advance old ledgers (including pre-Event-Storage v2 deployments)
        # while the legacy shared role is still the schema owner.
        existing_upgrade._upgrade_existing_owner_schema(owner_cfg)
        backfill_conn = db.connect(owner_cfg)
        try:
            backfill = esv2.backfill(backfill_conn, 1000, dry_run=False)
            versions_after = existing_upgrade._migration_versions(backfill_conn)
        finally:
            backfill_conn.close()

        # The roles already exist with the generated in-memory passwords; now
        # apply the least-privilege object boundary without rotating them.
        boundary._apply_grants(
            owner_raw,
            runtime_role=boundary.DEFAULT_RUNTIME_ROLE,
            ingest_role=boundary.DEFAULT_INGEST_ROLE,
            dashboard_role=boundary.DEFAULT_DASHBOARD_ROLE,
            maintenance_role=boundary.DEFAULT_MAINTENANCE_ROLE,
            preserve_existing_roles=True,
        )
    finally:
        owner_raw.close()
        role_admin.close()

    candidate = _candidate_config(base, legacy_owner)
    verified = _verify_candidate(config_path, candidate, passwords)

    # Persist only after all generated runtime credentials have authenticated
    # and passed privilege verification.  The legacy owner password is thereby
    # removed from normal runtime configuration in the same commit window.
    for identity, filename in CREDENTIAL_FILES.items():
        role = ROLE_BY_IDENTITY[identity]
        _atomic_json(
            config_path.parent / filename,
            boundary._component_config(candidate, role, passwords[role], identity),
            0o600,
        )
    _atomic_json(config_path, candidate, 0o640)

    return {
        "mode": "legacy-shared-to-split",
        "legacy_owner_retained_as_migration_owner": True,
        "owner_role": legacy_owner,
        "owner_password_persisted_in_runtime_config": False,
        "bootstrap_credential_persisted": False,
        "runtime_credentials_generated": True,
        "legacy_state": legacy,
        "bootstrap_preflight": preflight,
        "migration_versions_before": versions_before,
        "migration_versions_after": versions_after,
        "backfill": backfill,
        "verified_identities": {
            identity: {
                "role": data["role"],
                "event_read": bool(data["can_read_events_v2"]),
                "event_insert": bool(data["can_insert_events_v2"]),
                "event_delete": bool(data["can_delete_events_v2"]),
            }
            for identity, data in verified.items()
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Convert legacy shared-role PostgreSQL mini-SIEM to split runtime identities")
    ap.add_argument("--db-config", default=str(ROOT / "db-config.json"))
    ap.add_argument("--bootstrap-user", required=True, help="temporary PostgreSQL role administrator")
    ap.add_argument("--owner-user", default="", help="legacy shared owner/runtime role; defaults to existing config")
    args = ap.parse_args()
    try:
        bootstrap_password = os.environ.get(BOOTSTRAP_PASSWORD_ENV) or getpass.getpass(
            f"PostgreSQL bootstrap password for {args.bootstrap_user!r}: "
        )
        payload = run(
            Path(args.db_config).resolve(),
            bootstrap_user=args.bootstrap_user,
            bootstrap_password=bootstrap_password,
            owner_user=args.owner_user,
        )
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return 0
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    finally:
        os.environ.pop(BOOTSTRAP_PASSWORD_ENV, None)
        os.environ.pop(OWNER_PASSWORD_ENV, None)


if __name__ == "__main__":
    raise SystemExit(main())
