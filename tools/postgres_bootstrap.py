#!/usr/bin/env python3
"""Safe PostgreSQL bootstrap for mini-SIEM.

This tool owns the *bootstrap boundary* only.  Customer PostgreSQL administrator
credentials are accepted through a prompt or environment variable, used in
memory, and never written to mini-SIEM configuration.  Runtime services are
provisioned with separate least-privilege credentials after the schema has been
created/migrated by the dedicated ``minisiem_owner`` identity.

Fresh installation is intentionally fail-closed when an existing target
contains application tables or is owned by an unexpected role.  Existing
installations can be inspected without mutation so a controlled legacy-to-split
upgrade can be planned without silently changing object ownership.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import secrets
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import db as dbmod
from tools import postgres_privilege_boundary as boundary

DEFAULT_OWNER = "minisiem_owner"
DEFAULT_BOOTSTRAP_DB = "postgres"
BOOTSTRAP_PASSWORD_ENV = "MINISIEM_PG_BOOTSTRAP_PASSWORD"
OWNER_PASSWORD_ENV = "MINISIEM_PG_OWNER_PASSWORD"


def _deepcopy_json(value: Any) -> Any:
    return json.loads(json.dumps(value))


def _read_config(path: Path) -> dict:
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
    else:
        data = _deepcopy_json(dbmod.DEFAULT_CONFIG)
    if not isinstance(data, dict):
        raise RuntimeError("db-config.json must contain a JSON object")
    data.setdefault("backend", "postgres")
    data.setdefault("postgres", {})
    return data


def _write_config(path: Path, data: dict, mode: int = 0o640) -> None:
    boundary._write_json(path, data, mode=mode)


def _secret_from_env_or_prompt(env_name: str, prompt: str, *, required: bool = True) -> str:
    value = os.environ.get(env_name, "")
    if not value and sys.stdin.isatty():
        value = getpass.getpass(prompt)
    if required and not value:
        raise RuntimeError(
            f"credential not supplied; set {env_name} or run interactively"
        )
    return value


def _connect(psycopg2, *, host: str, port: int, dbname: str, user: str, password: str, timeout: int):
    return psycopg2.connect(
        host=host,
        port=int(port),
        dbname=dbname,
        user=user,
        password=password,
        connect_timeout=int(timeout),
    )


def _role_exists(cur, role: str) -> bool:
    cur.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,))
    return cur.fetchone() is not None


def _database_owner(cur, dbname: str) -> str | None:
    cur.execute(
        """
        SELECT r.rolname
          FROM pg_database d
          JOIN pg_roles r ON r.oid=d.datdba
         WHERE d.datname=%s
        """,
        (dbname,),
    )
    row = cur.fetchone()
    return row[0] if row else None


def _ensure_owner_role(admin_conn, owner: str, owner_password: str, *, permit_existing: bool) -> bool:
    from psycopg2 import sql

    cur = admin_conn.cursor()
    try:
        exists = _role_exists(cur, owner)
        if exists and not permit_existing:
            raise RuntimeError(
                f"owner role {owner!r} already exists; refusing fresh bootstrap without "
                "--allow-existing-owner-role"
            )
        ident = sql.Identifier(owner)
        if exists:
            # Do not silently rotate an existing owner's password.  The caller
            # must provide its current credential through OWNER_PASSWORD_ENV.
            return False
        cur.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION NOBYPASSRLS PASSWORD {}"
            ).format(ident, sql.Literal(owner_password))
        )
        admin_conn.commit()
        return True
    except Exception:
        admin_conn.rollback()
        raise
    finally:
        cur.close()


def _ensure_database(admin_conn, dbname: str, owner: str) -> bool:
    from psycopg2 import sql

    cur = admin_conn.cursor()
    try:
        existing_owner = _database_owner(cur, dbname)
        if existing_owner:
            if existing_owner != owner:
                raise RuntimeError(
                    f"database {dbname!r} already exists and is owned by {existing_owner!r}; "
                    f"expected {owner!r}. Refusing destructive ownership change."
                )
            return False
        # CREATE DATABASE cannot run inside a transaction.
        admin_conn.commit()
        prior = getattr(admin_conn, "autocommit", False)
        admin_conn.autocommit = True
        try:
            cur.execute(
                sql.SQL("CREATE DATABASE {} OWNER {}").format(
                    sql.Identifier(dbname), sql.Identifier(owner)
                )
            )
        finally:
            admin_conn.autocommit = prior
        return True
    finally:
        cur.close()


def _inspect_target(conn) -> dict:
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT c.relname, r.rolname
              FROM pg_class c
              JOIN pg_namespace n ON n.oid=c.relnamespace
              JOIN pg_roles r ON r.oid=c.relowner
             WHERE n.nspname='public'
               AND c.relkind IN ('r','p','v','m','S')
             ORDER BY c.relname
            """
        )
        objects = [{"name": row[0], "owner": row[1]} for row in cur.fetchall()]
        tables = [o for o in objects if not o["name"].startswith("pg_")]
        cur.execute(
            "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='public'"
        )
        schema_row = cur.fetchone()
        public_schema_owner = schema_row[0] if schema_row else None
        versions: list[int] = []
        if any(o["name"] == "schema_migrations" for o in objects):
            cur.execute("SELECT version FROM public.schema_migrations ORDER BY version")
            versions = [int(row[0]) for row in cur.fetchall()]
        roles = {}
        for role in (
            DEFAULT_OWNER,
            boundary.DEFAULT_RUNTIME_ROLE,
            boundary.DEFAULT_INGEST_ROLE,
            boundary.DEFAULT_DASHBOARD_ROLE,
            boundary.DEFAULT_MAINTENANCE_ROLE,
        ):
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,))
            roles[role] = cur.fetchone() is not None
        return {
            "public_schema_owner": public_schema_owner,
            "public_objects": tables,
            "schema_migration_versions": versions,
            "roles": roles,
        }
    finally:
        cur.close()


def local_deployment_state(config_path: Path) -> dict:
    base = _read_config(config_path)
    boundary_cfg = base.get("postgres_privilege_boundary") or {}
    root = config_path.parent
    credentials = {}
    for name, filename in (
        ("listener", "db-listener-credentials.json"),
        ("dashboard", "db-dashboard-credentials.json"),
        ("maintenance", "db-maintenance-credentials.json"),
    ):
        path = root / filename
        credentials[name] = {
            "path": str(path),
            "exists": path.is_file(),
            "mode": oct(path.stat().st_mode & 0o777) if path.exists() else None,
        }
    units = {
        name: Path(f"/etc/systemd/system/{name}.service").is_file()
        for name in ("mini-siem-listener", "mini-siem-dashboard")
    }
    return {
        "configured_boundary_enabled": bool(boundary_cfg.get("enabled")),
        "credential_overlays": credentials,
        "systemd_units_present": units,
    }


def inspect_existing(*, psycopg2, host: str, port: int, bootstrap_db: str,
                     bootstrap_user: str, bootstrap_password: str, target_db: str,
                     timeout: int) -> dict:
    admin = _connect(
        psycopg2,
        host=host,
        port=port,
        dbname=bootstrap_db,
        user=bootstrap_user,
        password=bootstrap_password,
        timeout=timeout,
    )
    try:
        cur = admin.cursor()
        try:
            owner = _database_owner(cur, target_db)
        finally:
            cur.close()
    finally:
        admin.close()

    report = {
        "database": target_db,
        "database_exists": owner is not None,
        "database_owner": owner,
        "mutated": False,
    }
    if owner is None:
        return report

    target = _connect(
        psycopg2,
        host=host,
        port=port,
        dbname=target_db,
        user=bootstrap_user,
        password=bootstrap_password,
        timeout=timeout,
    )
    try:
        report.update(_inspect_target(target))
    finally:
        target.close()
    return report


def _verify_object_ownership(owner_conn, owner: str) -> list[dict]:
    cur = owner_conn.cursor()
    try:
        cur.execute(
            """
            SELECT c.relname, r.rolname
              FROM pg_class c
              JOIN pg_namespace n ON n.oid=c.relnamespace
              JOIN pg_roles r ON r.oid=c.relowner
             WHERE n.nspname='public'
               AND c.relkind IN ('r','p','S')
               AND c.relname NOT LIKE 'pg_%'
               AND c.relname NOT LIKE 'sql_%'
               AND r.rolname <> %s
             ORDER BY c.relname
            """,
            (owner,),
        )
        return [{"object": row[0], "owner": row[1]} for row in cur.fetchall()]
    finally:
        cur.close()


def fresh_bootstrap(*, psycopg2, config_path: Path, host: str, port: int,
                    bootstrap_db: str, bootstrap_user: str, bootstrap_password: str,
                    target_db: str, owner_user: str, owner_password: str,
                    timeout: int, allow_existing_owner_role: bool = False) -> dict:
    admin = _connect(
        psycopg2,
        host=host,
        port=port,
        dbname=bootstrap_db,
        user=bootstrap_user,
        password=bootstrap_password,
        timeout=timeout,
    )
    created_owner = False
    created_db = False
    try:
        cur = admin.cursor()
        try:
            existing_db_owner = _database_owner(cur, target_db)
            owner_preexists = _role_exists(cur, owner_user)
        finally:
            cur.close()

        if existing_db_owner and existing_db_owner != owner_user:
            raise RuntimeError(
                f"database {target_db!r} already exists with owner {existing_db_owner!r}; "
                "use --mode inspect-existing and a controlled upgrade instead"
            )
        if existing_db_owner:
            # Existing DB is allowed only when it has no application objects;
            # this covers an interrupted fresh bootstrap without treating an
            # operational deployment as a fresh install.
            probe = _connect(
                psycopg2,
                host=host,
                port=port,
                dbname=target_db,
                user=bootstrap_user,
                password=bootstrap_password,
                timeout=timeout,
            )
            try:
                state = _inspect_target(probe)
            finally:
                probe.close()
            if state.get("public_objects"):
                raise RuntimeError(
                    "target database already contains application/public objects; "
                    "fresh bootstrap refuses to recreate or adopt an operational database. "
                    "Use --mode inspect-existing."
                )

        if owner_preexists and not allow_existing_owner_role:
            raise RuntimeError(
                f"owner role {owner_user!r} already exists; use --allow-existing-owner-role "
                "only after confirming it is the intended mini-SIEM migration owner"
            )
        created_owner = _ensure_owner_role(
            admin,
            owner_user,
            owner_password,
            permit_existing=allow_existing_owner_role,
        )
        created_db = _ensure_database(admin, target_db, owner_user)
    finally:
        admin.close()

    owner_cfg = _deepcopy_json(dbmod.DEFAULT_CONFIG)
    owner_cfg["backend"] = "postgres"
    owner_cfg["postgres"].update(
        {
            "host": host,
            "port": int(port),
            "dbname": target_db,
            "user": owner_user,
            "password": owner_password,
            "connect_timeout": int(timeout),
        }
    )

    # DDL/migrations are performed only through the owner identity.
    dbmod.initialize(owner_cfg)

    owner_raw = _connect(
        psycopg2,
        host=host,
        port=port,
        dbname=target_db,
        user=owner_user,
        password=owner_password,
        timeout=timeout,
    )
    role_admin_raw = _connect(
        psycopg2,
        host=host,
        port=port,
        dbname=target_db,
        user=bootstrap_user,
        password=bootstrap_password,
        timeout=timeout,
    )
    try:
        wrong_owners = _verify_object_ownership(owner_raw, owner_user)
        if wrong_owners:
            raise RuntimeError(
                "fresh bootstrap found application objects not owned by the migration owner: "
                + json.dumps(wrong_owners, sort_keys=True)
            )
        passwords = boundary._apply_grants(
            owner_raw,
            role_admin_raw=role_admin_raw,
            runtime_role=boundary.DEFAULT_RUNTIME_ROLE,
            ingest_role=boundary.DEFAULT_INGEST_ROLE,
            dashboard_role=boundary.DEFAULT_DASHBOARD_ROLE,
            maintenance_role=boundary.DEFAULT_MAINTENANCE_ROLE,
        )
    finally:
        owner_raw.close()
        role_admin_raw.close()

    base = _read_config(config_path)
    base["backend"] = "postgres"
    pg = base.setdefault("postgres", {})
    pg.update(
        {
            "host": host,
            "port": int(port),
            "dbname": target_db,
            "user": "",
            "password": "",
            "connect_timeout": int(timeout),
        }
    )
    base["postgres_privilege_boundary"] = {
        "enabled": True,
        "owner_role": owner_user,
        "runtime_role": boundary.DEFAULT_RUNTIME_ROLE,
        "ingest_role": boundary.DEFAULT_INGEST_ROLE,
        "dashboard_role": boundary.DEFAULT_DASHBOARD_ROLE,
        "maintenance_role": boundary.DEFAULT_MAINTENANCE_ROLE,
    }
    _write_config(config_path, base, mode=0o640)

    cred_paths = {
        "listener": config_path.parent / "db-listener-credentials.json",
        "dashboard": config_path.parent / "db-dashboard-credentials.json",
        "maintenance": config_path.parent / "db-maintenance-credentials.json",
    }
    boundary._write_json(
        cred_paths["listener"],
        boundary._component_config(base, boundary.DEFAULT_INGEST_ROLE,
                                   passwords[boundary.DEFAULT_INGEST_ROLE], "listener"),
    )
    boundary._write_json(
        cred_paths["dashboard"],
        boundary._component_config(base, boundary.DEFAULT_DASHBOARD_ROLE,
                                   passwords[boundary.DEFAULT_DASHBOARD_ROLE], "dashboard"),
    )
    boundary._write_json(
        cred_paths["maintenance"],
        boundary._component_config(base, boundary.DEFAULT_MAINTENANCE_ROLE,
                                   passwords[boundary.DEFAULT_MAINTENANCE_ROLE], "maintenance"),
    )

    verify_base = {"_path": str(config_path)}
    verify = {
        name: boundary._verify_login(verify_base, path, name)
        for name, path in cred_paths.items()
    }

    return {
        "created_owner": created_owner,
        "created_database": created_db,
        "database": target_db,
        "database_owner": owner_user,
        "runtime_boundary": True,
        "component_credentials": {k: str(v) for k, v in cred_paths.items()},
        "runtime_verification": verify,
        "bootstrap_credential_persisted": False,
        "owner_credential_persisted": False,
    }


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="mini-SIEM PostgreSQL bootstrap/inspection")
    ap.add_argument("--mode", choices=("fresh", "inspect-existing"), required=True)
    ap.add_argument("--db-config", default=str(ROOT / "db-config.json"))
    ap.add_argument("--host", default="")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--database", default="")
    ap.add_argument("--bootstrap-database", default=DEFAULT_BOOTSTRAP_DB)
    ap.add_argument("--bootstrap-user", required=True)
    ap.add_argument("--owner-user", default=DEFAULT_OWNER)
    ap.add_argument("--allow-existing-owner-role", action="store_true")
    ap.add_argument("--connect-timeout", type=int, default=5)
    return ap


def main() -> int:
    args = _parser().parse_args()
    config_path = Path(args.db_config).resolve()
    base = _read_config(config_path)
    pg = base.setdefault("postgres", {})
    host = args.host or str(pg.get("host") or "localhost")
    port = args.port or int(pg.get("port") or 5432)
    target_db = args.database or str(pg.get("dbname") or "minisiem")

    try:
        import psycopg2
    except ImportError as exc:
        raise SystemExit("psycopg2-binary is required for PostgreSQL bootstrap") from exc

    bootstrap_password = _secret_from_env_or_prompt(
        BOOTSTRAP_PASSWORD_ENV,
        f"PostgreSQL bootstrap password for {args.bootstrap_user!r}: ",
    )
    try:
        if args.mode == "inspect-existing":
            report = inspect_existing(
                psycopg2=psycopg2,
                host=host,
                port=port,
                bootstrap_db=args.bootstrap_database,
                bootstrap_user=args.bootstrap_user,
                bootstrap_password=bootstrap_password,
                target_db=target_db,
                timeout=args.connect_timeout,
            )
            report["local_deployment_state"] = local_deployment_state(config_path)
            report["upgrade_safety"] = {
                "automatic_owner_transfer_performed": False,
                "automatic_database_recreation_performed": False,
                "backup_required_before_privilege_or_owner_migration": True,
            }
        else:
            owner_password = os.environ.get(OWNER_PASSWORD_ENV, "")
            if not owner_password:
                # New owner credentials are generated in memory by default. If
                # the role already exists, require an explicit known password;
                # do not silently rotate it.
                owner_password = secrets.token_urlsafe(36)
                if args.allow_existing_owner_role:
                    owner_password = _secret_from_env_or_prompt(
                        OWNER_PASSWORD_ENV,
                        f"Existing owner password for {args.owner_user!r}: ",
                    )
            report = fresh_bootstrap(
                psycopg2=psycopg2,
                config_path=config_path,
                host=host,
                port=port,
                bootstrap_db=args.bootstrap_database,
                bootstrap_user=args.bootstrap_user,
                bootstrap_password=bootstrap_password,
                target_db=target_db,
                owner_user=args.owner_user,
                owner_password=owner_password,
                timeout=args.connect_timeout,
                allow_existing_owner_role=args.allow_existing_owner_role,
            )
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
        return 0
    finally:
        # Reduce accidental reuse inside the process.  Parent-shell values are
        # unaffected, and no credential is written to disk by this tool.
        os.environ.pop(BOOTSTRAP_PASSWORD_ENV, None)
        os.environ.pop(OWNER_PASSWORD_ENV, None)


if __name__ == "__main__":
    raise SystemExit(main())
