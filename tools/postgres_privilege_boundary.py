#!/usr/bin/env python3
"""Provision PostgreSQL least-privilege identities for mini-SIEM.

This is application security setup, not data migration.  It keeps the hot
``logs`` table append-only for normal listener/dashboard identities while
reserving DELETE to the dedicated maintenance identity.

Run as a PostgreSQL database owner/administrator after the application schema
has been initialized/migrated.  The tool generates component credential files
and scrubs the owner password from db-config.json.
"""

from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
import secrets
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import db as dbmod


DEFAULT_RUNTIME_ROLE = "minisiem_runtime"
DEFAULT_INGEST_ROLE = "minisiem_ingest"
DEFAULT_DASHBOARD_ROLE = "minisiem_dashboard"
DEFAULT_MAINTENANCE_ROLE = "minisiem_maintenance"

LOG_INSERT_COLUMNS = (
    "received_at", "source_ip", "peer_ip", "format", "priority", "facility",
    "severity", "device_timestamp", "hostname", "destination", "app_name",
    "proc_id", "msg_id", "message", "raw",
)


def _write_json(path: Path, payload: dict, mode: int = 0o600):
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(mode)
    except OSError:
        pass


def _role_exists(cur, name: str) -> bool:
    cur.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (name,))
    return cur.fetchone() is not None


def _ensure_group_role(cur, sql, name: str):
    ident = sql.Identifier(name)
    attrs = "NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
    if _role_exists(cur, name):
        cur.execute(sql.SQL("ALTER ROLE {} " + attrs).format(ident))
    else:
        cur.execute(sql.SQL("CREATE ROLE {} " + attrs).format(ident))


def _ensure_login_role(cur, sql, name: str, password: str):
    ident = sql.Identifier(name)
    pw = sql.Literal(password)
    attrs = "LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
    if _role_exists(cur, name):
        cur.execute(sql.SQL("ALTER ROLE {} " + attrs + " PASSWORD {}").format(ident, pw))
    else:
        cur.execute(sql.SQL("CREATE ROLE {} " + attrs + " PASSWORD {}").format(ident, pw))


def _assert_roles_do_not_own_protected_tables(cur, roles):
    cur.execute(
        """
        SELECT c.relname, r.rolname
          FROM pg_class c
          JOIN pg_namespace n ON n.oid=c.relnamespace
          JOIN pg_roles r ON r.oid=c.relowner
         WHERE n.nspname='public' AND c.relname IN ('logs','schema_migrations','ai_usage_audit')
        """
    )
    protected = cur.fetchall()
    bad = [(table, owner) for table, owner in protected if owner in roles]
    if bad:
        details = ", ".join(f"{table} owned by {owner}" for table, owner in bad)
        raise RuntimeError(
            "Refusing unsafe privilege boundary: runtime identities own protected tables: "
            + details
        )
    # Ownership can also be inherited through role membership. A runtime login
    # that can SET ROLE to the table owner could disable the guard trigger or
    # change grants, so reject that relationship as well.
    for table, owner in protected:
        for role in roles:
            cur.execute("SELECT pg_has_role(%s,%s,'member')", (role, owner))
            row = cur.fetchone()
            inherited = bool(row[0] if not isinstance(row, dict) else next(iter(row.values())))
            if inherited:
                raise RuntimeError(
                    f"Refusing unsafe privilege boundary: {role} inherits owner role {owner} for {table}"
                )


def _provision_runtime_roles(raw, *, runtime_role, ingest_role, dashboard_role, maintenance_role):
    """Create/rotate runtime identities using a PostgreSQL role administrator.

    This connection needs CREATEROLE (or equivalent DBA authority) but does not
    need to own mini-SIEM application tables.  Keeping this separate from
    object grants lets ``minisiem_owner`` remain NOCREATEROLE.
    """
    from psycopg2 import sql

    cur = raw.cursor()
    try:
        _ensure_group_role(cur, sql, runtime_role)
        passwords = {
            ingest_role: secrets.token_urlsafe(32),
            dashboard_role: secrets.token_urlsafe(32),
            maintenance_role: secrets.token_urlsafe(32),
        }
        for role, password in passwords.items():
            _ensure_login_role(cur, sql, role, password)

        runtime = sql.Identifier(runtime_role)
        ingest = sql.Identifier(ingest_role)
        dashboard = sql.Identifier(dashboard_role)
        maintenance = sql.Identifier(maintenance_role)
        cur.execute(sql.SQL("GRANT {} TO {}, {}, {}").format(
            runtime, ingest, dashboard, maintenance
        ))
        cur.execute(sql.SQL("REVOKE {} FROM {}, {}").format(
            maintenance, ingest, dashboard
        ))
        for role_name in (ingest_role, dashboard_role):
            cur.execute("SELECT pg_has_role(%s,%s,'member')", (role_name, maintenance_role))
            row = cur.fetchone()
            inherited = bool(row[0] if not isinstance(row, dict) else next(iter(row.values())))
            if inherited:
                raise RuntimeError(
                    f"{role_name} still inherits maintenance role {maintenance_role} through nested membership"
                )
        raw.commit()
        return passwords
    except Exception:
        raw.rollback()
        raise
    finally:
        cur.close()


def _apply_grants(raw, *, runtime_role, ingest_role, dashboard_role, maintenance_role,
                  role_admin_raw=None):
    """Apply the split-role boundary to owner-created application objects.

    ``raw`` is the schema-owner connection.  ``role_admin_raw`` may be a
    separate temporary customer DBA/CREATEROLE connection used only to create
    or rotate login roles.  When omitted, legacy behavior uses ``raw`` for both
    duties; that requires the caller to have CREATEROLE.
    """
    from psycopg2 import sql

    passwords = _provision_runtime_roles(
        role_admin_raw or raw,
        runtime_role=runtime_role,
        ingest_role=ingest_role,
        dashboard_role=dashboard_role,
        maintenance_role=maintenance_role,
    )

    cur = raw.cursor()
    try:
        _assert_roles_do_not_own_protected_tables(
            cur, {runtime_role, ingest_role, dashboard_role, maintenance_role}
        )

        runtime = sql.Identifier(runtime_role)
        ingest = sql.Identifier(ingest_role)
        dashboard = sql.Identifier(dashboard_role)
        maintenance = sql.Identifier(maintenance_role)

        # Dedicated mini-SIEM DB: runtime identities can use the schema and all
        # normal application tables, but cannot own/alter schema objects.
        cur.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
            sql.Identifier(raw.info.dbname), runtime
        ))
        cur.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(runtime))
        cur.execute(sql.SQL(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}"
        ).format(runtime))
        # Remove any legacy direct sequence privileges first; runtime receives
        # only nextval/currval-style access, never setval/ownership-like UPDATE.
        for role in (ingest, dashboard, maintenance):
            cur.execute(sql.SQL(
                "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM {}"
            ).format(role))
        cur.execute(sql.SQL(
            "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}"
        ).format(runtime))
        # These ALTER DEFAULT PRIVILEGES statements execute as the schema owner,
        # so future owner-created objects inherit the runtime baseline.
        cur.execute(sql.SQL(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
            "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}"
        ).format(runtime))
        cur.execute(sql.SQL(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
            "GRANT USAGE, SELECT ON SEQUENCES TO {}"
        ).format(runtime))

        # Evidence boundary: runtime is read+append on raw logs.  No UPDATE,
        # DELETE, or TRUNCATE.  Column-level INSERT also prevents choosing a
        # caller-controlled primary key.
        cur.execute(sql.SQL(
            "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE public.logs FROM {}"
        ).format(runtime))
        cols = sql.SQL(", ").join(sql.Identifier(c) for c in LOG_INSERT_COLUMNS)
        cur.execute(sql.SQL(
            "GRANT SELECT ON TABLE public.logs TO {}; "
            "GRANT INSERT ({}) ON TABLE public.logs TO {}"
        ).format(runtime, cols, runtime))

        # Runtime services may inspect, but never alter, the migration ledger.
        cur.execute(sql.SQL(
            "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE public.schema_migrations FROM {}; "
            "GRANT SELECT ON TABLE public.schema_migrations TO {}"
        ).format(runtime, runtime))

        # AI provider usage evidence is append-only from the dashboard process.
        # Other runtime identities may read it but cannot forge or rewrite rows.
        cur.execute(sql.SQL(
            "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE public.ai_usage_audit FROM {}; "
            "GRANT SELECT ON TABLE public.ai_usage_audit TO {}"
        ).format(runtime, runtime))
        for role in (ingest, dashboard, maintenance):
            cur.execute(sql.SQL(
                "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE public.ai_usage_audit FROM {}"
            ).format(role))
        cur.execute(sql.SQL(
            "GRANT INSERT ON TABLE public.ai_usage_audit TO {}"
        ).format(dashboard))

        # Remove legacy direct privileges that could otherwise override the
        # group-role REVOKE.
        for role in (ingest, dashboard):
            cur.execute(sql.SQL(
                "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE public.logs FROM {}; "
                "GRANT SELECT ON TABLE public.logs TO {}; "
                "GRANT INSERT ({}) ON TABLE public.logs TO {}"
            ).format(role, role, cols, role))
            cur.execute(sql.SQL(
                "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE public.schema_migrations FROM {}; "
                "GRANT SELECT ON TABLE public.schema_migrations TO {}"
            ).format(role, role))

        # Archive catalog is operational evidence. Listener/dashboard may read
        # it for search/health, but only the maintenance identity may mutate it.
        for table_name in ("archive_segments", "archive_occurrence_catalog"):
            table = sql.Identifier("public", table_name)
            cur.execute(sql.SQL(
                "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE {} FROM {}"
            ).format(table, runtime))
            cur.execute(sql.SQL("GRANT SELECT ON TABLE {} TO {}").format(table, runtime))
            for role in (ingest, dashboard):
                cur.execute(sql.SQL(
                    "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE {} FROM {}"
                ).format(table, role))
                cur.execute(sql.SQL("GRANT SELECT ON TABLE {} TO {}").format(table, role))
            cur.execute(sql.SQL(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {} TO {}"
            ).format(table, maintenance))
            cur.execute(sql.SQL("REVOKE TRUNCATE ON TABLE {} FROM {}").format(table, maintenance))

        # Only maintenance receives the hot-copy eviction capability.
        cur.execute(sql.SQL("GRANT DELETE ON TABLE public.logs TO {}").format(maintenance))

        # Defense in depth: even if DELETE/UPDATE is accidentally granted later,
        # the raw log table remains immutable unless DELETE is executed by a
        # member of the dedicated maintenance identity. UPDATE/TRUNCATE are never
        # accepted from application roles.
        maintenance_literal = sql.Literal(maintenance_role)
        cur.execute(sql.SQL(
            """
            CREATE OR REPLACE FUNCTION public.minisiem_guard_logs_mutation()
            RETURNS trigger
            LANGUAGE plpgsql
            SECURITY INVOKER
            SET search_path = pg_catalog, public
            AS $guard$
            BEGIN
                IF TG_OP = 'DELETE'
                   AND (current_user = {} OR pg_has_role(current_user, {}, 'member')) THEN
                    RETURN OLD;
                END IF;
                RAISE EXCEPTION 'mini-SIEM logs are append-only; operation % denied for role %',
                                TG_OP, current_user
                      USING ERRCODE = '42501';
            END
            $guard$;
            """
        ).format(maintenance_literal, maintenance_literal))
        cur.execute("DROP TRIGGER IF EXISTS minisiem_logs_no_mutation ON public.logs")
        cur.execute(
            "CREATE TRIGGER minisiem_logs_no_mutation "
            "BEFORE UPDATE OR DELETE ON public.logs "
            "FOR EACH ROW EXECUTE FUNCTION public.minisiem_guard_logs_mutation()"
        )
        cur.execute("DROP TRIGGER IF EXISTS minisiem_logs_no_truncate ON public.logs")
        cur.execute(
            "CREATE TRIGGER minisiem_logs_no_truncate "
            "BEFORE TRUNCATE ON public.logs "
            "FOR EACH STATEMENT EXECUTE FUNCTION public.minisiem_guard_logs_mutation()"
        )

        # PUBLIC must not be able to create shadow objects in the application
        # schema or invoke table privileges through accidental grants.
        cur.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        cur.execute("REVOKE ALL ON TABLE public.logs FROM PUBLIC")
        cur.execute("REVOKE ALL ON TABLE public.archive_segments FROM PUBLIC")
        cur.execute("REVOKE ALL ON TABLE public.archive_occurrence_catalog FROM PUBLIC")
        cur.execute("REVOKE ALL ON TABLE public.ai_usage_audit FROM PUBLIC")
        raw.commit()
        return passwords
    except Exception:
        raw.rollback()
        raise
    finally:
        cur.close()


def _component_config(base: dict, user: str, password: str, identity: str) -> dict:
    return {
        "identity": identity,
        "postgres": {"user": user, "password": password},
    }


def _verify_login(base_cfg: dict, cred_path: Path, identity: str):
    cfg = dbmod.load_config(str(base_cfg["_path"]), credentials_path=str(cred_path))
    if cfg.get("_credentials_identity") != identity:
        raise RuntimeError(f"credential identity mismatch for {cred_path.name}")
    conn = dbmod.connect(cfg)
    try:
        row = conn.execute(
            """
            SELECT current_user AS role,
                   has_table_privilege(current_user,'public.logs','SELECT') AS can_select,
                   has_table_privilege(current_user,'public.logs','DELETE') AS can_delete,
                   has_table_privilege(current_user,'public.logs','TRUNCATE') AS can_truncate,
                   has_column_privilege(current_user,'public.logs','received_at','INSERT') AS can_insert,
                   has_column_privilege(current_user,'public.logs','raw','UPDATE') AS can_update_raw,
                   has_table_privilege(current_user,'public.schema_migrations','SELECT') AS can_read_migrations,
                   has_table_privilege(current_user,'public.schema_migrations','UPDATE') AS can_edit_migrations,
                   has_table_privilege(current_user,'public.ai_usage_audit','SELECT') AS can_read_ai_usage,
                   has_table_privilege(current_user,'public.ai_usage_audit','INSERT') AS can_insert_ai_usage,
                   has_table_privilege(current_user,'public.ai_usage_audit','UPDATE') AS can_update_ai_usage,
                   has_table_privilege(current_user,'public.ai_usage_audit','DELETE') AS can_delete_ai_usage,
                   has_table_privilege(current_user,'public.ai_usage_audit','TRUNCATE') AS can_truncate_ai_usage
            """
        ).fetchone()
        data = dict(row)
        expected_delete = identity == "maintenance"
        if not data["can_select"] or not data["can_insert"]:
            raise RuntimeError(f"{identity} cannot read/append logs: {data}")
        if bool(data["can_delete"]) != expected_delete:
            raise RuntimeError(f"{identity} DELETE privilege mismatch: {data}")
        if data["can_truncate"] or data["can_update_raw"]:
            raise RuntimeError(f"{identity} has forbidden log mutation privilege: {data}")
        if not data["can_read_migrations"] or data["can_edit_migrations"]:
            raise RuntimeError(f"{identity} migration-ledger privilege mismatch: {data}")
        if not data["can_read_ai_usage"]:
            raise RuntimeError(f"{identity} cannot read AI usage audit evidence: {data}")
        expected_usage_insert = identity == "dashboard"
        if bool(data["can_insert_ai_usage"]) != expected_usage_insert:
            raise RuntimeError(f"{identity} AI usage INSERT privilege mismatch: {data}")
        if data["can_update_ai_usage"] or data["can_delete_ai_usage"] or data["can_truncate_ai_usage"]:
            raise RuntimeError(f"{identity} can mutate AI usage audit evidence: {data}")
        dbmod.ensure_runtime_ready(cfg)
        return data
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser(description="Provision mini-SIEM PostgreSQL privilege boundary")
    ap.add_argument("--db-config", default=str(Path(__file__).resolve().parents[1] / "db-config.json"))
    ap.add_argument("--owner-user", default="", help="DB owner/migration username (defaults to db-config user)")
    ap.add_argument("--runtime-role", default=DEFAULT_RUNTIME_ROLE)
    ap.add_argument("--ingest-role", default=DEFAULT_INGEST_ROLE)
    ap.add_argument("--dashboard-role", default=DEFAULT_DASHBOARD_ROLE)
    ap.add_argument("--maintenance-role", default=DEFAULT_MAINTENANCE_ROLE)
    args = ap.parse_args()

    base_path = Path(args.db_config).resolve()
    raw_base = json.loads(base_path.read_text(encoding="utf-8"))
    cfg = dbmod.load_config(str(base_path))
    if cfg.get("backend") != "postgres":
        raise SystemExit("PostgreSQL backend is required")

    owner_user = args.owner_user or cfg["postgres"].get("user") or ""
    owner_password = cfg["postgres"].get("password") or getpass.getpass(
        f"PostgreSQL password for owner '{owner_user}': "
    )
    if not owner_user:
        raise SystemExit("Owner/migration username is required")
    owner_cfg = json.loads(json.dumps(cfg))
    owner_cfg["postgres"]["user"] = owner_user
    owner_cfg["postgres"]["password"] = owner_password

    # Owner performs schema setup/migration once; runtime accounts never do DDL.
    dbmod.initialize(owner_cfg)

    try:
        import psycopg2
    except ImportError as exc:
        raise SystemExit("psycopg2-binary is required") from exc
    p = owner_cfg["postgres"]
    raw = psycopg2.connect(
        host=p["host"], port=p["port"], dbname=p["dbname"],
        user=p["user"], password=p.get("password", ""),
        connect_timeout=int(p.get("connect_timeout", 5)),
    )
    try:
        passwords = _apply_grants(
            raw,
            runtime_role=args.runtime_role,
            ingest_role=args.ingest_role,
            dashboard_role=args.dashboard_role,
            maintenance_role=args.maintenance_role,
        )
    finally:
        raw.close()

    root = base_path.parent
    paths = {
        "listener": root / "db-listener-credentials.json",
        "dashboard": root / "db-dashboard-credentials.json",
        "maintenance": root / "db-maintenance-credentials.json",
    }
    _write_json(paths["listener"], _component_config(raw_base, args.ingest_role, passwords[args.ingest_role], "listener"))
    _write_json(paths["dashboard"], _component_config(raw_base, args.dashboard_role, passwords[args.dashboard_role], "dashboard"))
    _write_json(paths["maintenance"], _component_config(raw_base, args.maintenance_role, passwords[args.maintenance_role], "maintenance"))

    # Base config becomes non-secret.  Operators should retain owner credentials
    # in their external secret store; they are intentionally not persisted here.
    pg = raw_base.setdefault("postgres", {})
    pg["user"] = ""
    pg["password"] = ""
    raw_base["postgres_privilege_boundary"] = {
        "enabled": True,
        "runtime_role": args.runtime_role,
        "ingest_role": args.ingest_role,
        "dashboard_role": args.dashboard_role,
        "maintenance_role": args.maintenance_role,
    }
    _write_json(base_path, raw_base, mode=0o640)

    verify_base = {"_path": str(base_path)}
    results = {
        name: _verify_login(verify_base, path, name)
        for name, path in paths.items()
    }

    print("PostgreSQL privilege boundary applied and verified.")
    print(f"Base config (non-secret): {base_path}")
    for name, path in paths.items():
        print(f"{name:11s}: {path}")
    print("Verification:")
    for name, result in results.items():
        print(f"  {name}: role={result['role']} delete_logs={bool(result['can_delete'])} "
              f"update_logs={bool(result['can_update_raw'])} truncate_logs={bool(result['can_truncate'])}")
    print("Re-run install-services.sh so systemd uses the component credential files.")


if __name__ == "__main__":
    main()
