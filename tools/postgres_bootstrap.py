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
from tools import fresh_install_state as install_state

DEFAULT_OWNER = "minisiem_owner"
DEFAULT_BOOTSTRAP_DB = "postgres"
BOOTSTRAP_PASSWORD_ENV = "MINISIEM_PG_BOOTSTRAP_PASSWORD"
OWNER_PASSWORD_ENV = "MINISIEM_PG_OWNER_PASSWORD"


class BootstrapPreflightError(RuntimeError):
    """Expected bootstrap connectivity/privilege failure with operator-safe text."""


def _first_line(exc: Exception) -> str:
    text = str(exc).strip().splitlines()
    return text[0] if text else type(exc).__name__


def _bootstrap_preflight(admin_conn, *, host: str, port: int, bootstrap_db: str, requested_user: str) -> dict:
    """Verify identity and create-role/create-db authority before any DDL."""
    cur = admin_conn.cursor()
    try:
        cur.execute(
            "SELECT current_user, rolcreatedb, rolcreaterole, rolsuper "
            "FROM pg_roles WHERE rolname=current_user"
        )
        row = cur.fetchone()
    finally:
        cur.close()
    if not row:
        raise BootstrapPreflightError(
            f"bootstrap user {requested_user!r} authenticated but PostgreSQL returned no role metadata"
        )
    if isinstance(row, dict):
        current = row.get("current_user") or row.get("rolname")
        createdb = bool(row.get("rolcreatedb"))
        createrole = bool(row.get("rolcreaterole"))
        superuser = bool(row.get("rolsuper"))
    else:
        current, createdb, createrole, superuser = row[:4]
        createdb, createrole, superuser = bool(createdb), bool(createrole), bool(superuser)
    if current != requested_user:
        raise BootstrapPreflightError(
            f"requested bootstrap user {requested_user!r} authenticated as PostgreSQL current_user {current!r}; "
            "refusing ambiguous bootstrap identity"
        )
    if not superuser and not (createdb and createrole):
        missing = []
        if not createdb:
            missing.append("CREATEDB")
        if not createrole:
            missing.append("CREATEROLE")
        raise BootstrapPreflightError(
            f"PostgreSQL bootstrap user {current!r} lacks required privileges: {', '.join(missing)}. "
            "Grant the missing privilege(s) or use a PostgreSQL superuser. No database changes were made."
        )
    return {
        "current_user": current,
        "rolcreatedb": createdb,
        "rolcreaterole": createrole,
        "rolsuper": superuser,
        "host": host,
        "port": int(port),
        "database": bootstrap_db,
    }


def _phase(state_path: Path | None, phase: str) -> None:
    """Advance a fresh-install checkpoint without regressing completed phases.

    Resume deliberately re-runs lightweight/idempotent validation for earlier
    phases.  If the checkpoint is already ahead of ``phase`` that validation
    is allowed to complete, while the durable checkpoint remains at the later
    phase.  Explicit state-tool regressions are still rejected by
    ``fresh_install_state.set_phase``.
    """
    if state_path is None:
        return
    state = install_state.load(state_path)
    current_i = install_state.PHASES.index(state["phase"])
    requested_i = install_state.PHASES.index(phase)
    if requested_i < current_i:
        return
    install_state.set_phase(state_path, phase)


def _resume_secret_payload(path: Path, *, resume: bool) -> dict:
    """Create/read root-only transient secrets used solely for interrupted fresh-install recovery."""
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
    else:
        if resume:
            raise RuntimeError(
                f"resume secret state is missing: {path}; refusing to rotate or invent credentials during --resume"
            )
        data = {
            "owner_password": secrets.token_urlsafe(36),
            "runtime_passwords": {
                boundary.DEFAULT_INGEST_ROLE: secrets.token_urlsafe(32),
                boundary.DEFAULT_DASHBOARD_ROLE: secrets.token_urlsafe(32),
                boundary.DEFAULT_MAINTENANCE_ROLE: secrets.token_urlsafe(32),
            },
        }
        boundary._write_json(path, data, mode=0o600)
    expected = {
        boundary.DEFAULT_INGEST_ROLE,
        boundary.DEFAULT_DASHBOARD_ROLE,
        boundary.DEFAULT_MAINTENANCE_ROLE,
    }
    runtime = data.get("runtime_passwords") or {}
    if not data.get("owner_password") or set(runtime) != expected or not all(runtime.values()):
        raise RuntimeError("fresh-install resume secret state is incomplete or invalid")
    return data


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
    if not value:
        # getpass itself knows how to use /dev/tty.  Do not reject an
        # interactive sudo session merely because stdin was redirected by a
        # wrapper script.
        try:
            value = getpass.getpass(prompt)
        except (EOFError, OSError):
            value = ""
    if required and not value:
        raise RuntimeError(
            f"credential not supplied; set {env_name} or run from an interactive terminal"
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
                    timeout: int, allow_existing_owner_role: bool = False,
                    resume: bool = False, state_path: Path | None = None,
                    runtime_passwords: dict | None = None) -> dict:
    try:
        admin = _connect(
            psycopg2,
            host=host,
            port=port,
            dbname=bootstrap_db,
            user=bootstrap_user,
            password=bootstrap_password,
            timeout=timeout,
        )
    except Exception as exc:
        raise BootstrapPreflightError(
            f"cannot connect/authenticate to PostgreSQL at {host}:{int(port)} as bootstrap user "
            f"{bootstrap_user!r}: {_first_line(exc)}. Check TCP reachability, password, and pg_hba.conf. "
            "No database changes were made."
        ) from exc
    try:
        preflight = _bootstrap_preflight(
            admin, host=host, port=port, bootstrap_db=bootstrap_db, requested_user=bootstrap_user
        )
    except Exception:
        admin.close()
        raise
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
            if state.get("public_objects") and not resume:
                raise RuntimeError(
                    "target database already contains application/public objects; "
                    "fresh bootstrap refuses to recreate or adopt an operational database. "
                    "Use --mode inspect-existing."
                )

        if owner_preexists and not (allow_existing_owner_role or resume):
            raise RuntimeError(
                f"owner role {owner_user!r} already exists; use --allow-existing-owner-role "
                "only after confirming it is the intended mini-SIEM migration owner"
            )
        created_owner = _ensure_owner_role(
            admin,
            owner_user,
            owner_password,
            permit_existing=(allow_existing_owner_role or resume),
        )
        _phase(state_path, "OWNER_READY")
        created_db = _ensure_database(admin, target_db, owner_user)
        _phase(state_path, "DATABASE_READY")
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
    _phase(state_path, "SCHEMA_MIGRATED")

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
        _phase(state_path, "SCHEMA_VERIFIED")
        passwords = boundary._apply_grants(
            owner_raw,
            role_admin_raw=role_admin_raw,
            runtime_role=boundary.DEFAULT_RUNTIME_ROLE,
            ingest_role=boundary.DEFAULT_INGEST_ROLE,
            dashboard_role=boundary.DEFAULT_DASHBOARD_ROLE,
            maintenance_role=boundary.DEFAULT_MAINTENANCE_ROLE,
            runtime_passwords=runtime_passwords,
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
    # Write credentials only after the complete bootstrap boundary has passed.
    # Previously a failure during post-bootstrap verification could leave
    # credential files behind even though database roles/bootstrap were
    # incomplete, creating a misleading half-installed state.
    credential_payloads = {
        "listener": boundary._component_config(
            base, boundary.DEFAULT_INGEST_ROLE,
            passwords[boundary.DEFAULT_INGEST_ROLE], "listener"
        ),
        "dashboard": boundary._component_config(
            base, boundary.DEFAULT_DASHBOARD_ROLE,
            passwords[boundary.DEFAULT_DASHBOARD_ROLE], "dashboard"
        ),
        "maintenance": boundary._component_config(
            base, boundary.DEFAULT_MAINTENANCE_ROLE,
            passwords[boundary.DEFAULT_MAINTENANCE_ROLE], "maintenance"
        ),
    }

    verify_base = {"_path": str(config_path)}
    verify = {}
    for name, payload in credential_payloads.items():
        verify[name] = {
            "role": payload["postgres"]["user"],
            "generated": True,
        }

    # Finalize credential files only after all bootstrap objects and grants are
    # complete.  Verification failures must prevent the files from becoming
    # an apparent installation success signal.
    for name, path in cred_paths.items():
        boundary._write_json(path, credential_payloads[name])

    verify = {
        name: boundary._verify_login(verify_base, path, name)
        for name, path in cred_paths.items()
    }
    _phase(state_path, "RUNTIME_CREDENTIALS_READY")

    return {
        "created_owner": created_owner,
        "created_database": created_db,
        "database": target_db,
        "database_owner": owner_user,
        "runtime_boundary": True,
        "component_credentials": {k: str(v) for k, v in cred_paths.items()},
        "runtime_verification": verify,
        "bootstrap_preflight": preflight,
        "resumed": bool(resume),
        "bootstrap_credential_persisted": False,
        "owner_credential_persisted_in_runtime_config": False,
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
    ap.add_argument("--resume", action="store_true", help="resume only a checkpointed interrupted fresh install")
    ap.add_argument("--state-file", default="")
    ap.add_argument("--resume-secrets", default="")
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

    try:
        bootstrap_password = _secret_from_env_or_prompt(
            BOOTSTRAP_PASSWORD_ENV,
            f"PostgreSQL bootstrap password for {args.bootstrap_user!r}: ",
        )
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
            state_path = Path(args.state_file).resolve() if args.state_file else None
            resume_secret_path = Path(args.resume_secrets).resolve() if args.resume_secrets else None
            resume_payload = None
            if args.resume:
                if state_path is None or resume_secret_path is None:
                    raise RuntimeError("--resume requires --state-file and --resume-secrets")
                checkpoint = install_state.load(state_path)
                if checkpoint.get("phase") == "OPERATIONAL":
                    raise RuntimeError("fresh-install checkpoint is already operational; use upgrade-existing.sh")
            if resume_secret_path is not None:
                resume_payload = _resume_secret_payload(resume_secret_path, resume=args.resume)
                owner_password = resume_payload["owner_password"]
                runtime_passwords = resume_payload["runtime_passwords"]
            else:
                runtime_passwords = None
                owner_password = os.environ.get(OWNER_PASSWORD_ENV, "")
                if not owner_password:
                    # Non-resumable direct tool use retains the historical in-memory secret behavior.
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
                resume=args.resume,
                state_path=state_path,
                runtime_passwords=runtime_passwords,
            )
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
        return 0
    except (BootstrapPreflightError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    finally:
        # Reduce accidental reuse inside the process.  Parent-shell values are
        # unaffected, and no credential is written to disk by this tool.
        os.environ.pop(BOOTSTRAP_PASSWORD_ENV, None)
        os.environ.pop(OWNER_PASSWORD_ENV, None)


if __name__ == "__main__":
    raise SystemExit(main())
