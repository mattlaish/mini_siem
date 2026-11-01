#!/usr/bin/env python3
"""Controlled PostgreSQL backup and restore workflow for mini-SIEM.

Backups are custom-format pg_dump archives plus a SHA-256 manifest. Restore is
fail-closed into a *new* database by default; the tool never overwrites or drops
an existing target database. Bootstrap/admin credentials are used only to
create/clean the new database and are never written to disk.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import backup_restore as br
import db
from tools import postgres_bootstrap as bootstrap
from tools import postgres_privilege_boundary as boundary

OWNER_PASSWORD_ENV = boundary.OWNER_PASSWORD_ENV
BOOTSTRAP_PASSWORD_ENV = bootstrap.BOOTSTRAP_PASSWORD_ENV
MANIFEST_FORMAT = "mini-siem-postgresql-backup-v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        cfg = json.load(fh)
    if cfg.get("backend") != "postgres":
        raise RuntimeError("PostgreSQL backend is required")
    return cfg


def _owner(cfg: dict, owner_user: str = "") -> tuple[str, str]:
    pg = cfg.get("postgres") or {}
    pb = cfg.get("postgres_privilege_boundary") or {}
    user = owner_user or os.environ.get("MINISIEM_PG_OWNER_USER") or pb.get("owner_role") or pg.get("user") or ""
    password = os.environ.get(OWNER_PASSWORD_ENV) or pg.get("password") or ""
    if not user:
        raise RuntimeError("PostgreSQL owner/migration username is required")
    if not password:
        raise RuntimeError(f"PostgreSQL owner password is required via {OWNER_PASSWORD_ENV}")
    return str(user), str(password)


def _connect(psycopg2, cfg: dict, *, database: str | None = None, user: str, password: str):
    p = cfg["postgres"]
    return psycopg2.connect(
        host=p.get("host") or "localhost",
        port=int(p.get("port") or 5432),
        dbname=database or p.get("dbname") or "minisiem",
        user=user,
        password=password,
        connect_timeout=int(p.get("connect_timeout") or 5),
    )


def _server_metadata(conn) -> dict:
    cur = conn.cursor()
    try:
        cur.execute("SHOW server_version")
        row = cur.fetchone()
        version = next(iter(row.values())) if isinstance(row, dict) else row[0]
        cur.execute("SELECT current_database(), current_user, pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()")
        row = cur.fetchone()
        values = list(row.values()) if isinstance(row, dict) else list(row)
        cur.execute("SELECT version FROM public.schema_migrations ORDER BY version")
        versions = [int(next(iter(r.values())) if isinstance(r, dict) else r[0]) for r in cur.fetchall()]
        return {
            "server_version": str(version),
            "database": str(values[0]),
            "current_user": str(values[1]),
            "database_owner": str(values[2]),
            "schema_migration_versions": versions,
        }
    finally:
        cur.close()


def _major(text: str) -> int:
    m = re.search(r"(?:PostgreSQL\)?\s*)?(\d+)(?:\.\d+)?", text or "")
    if not m:
        m = re.search(r"\b(\d+)(?:\.\d+)?\b", text or "")
    return int(m.group(1)) if m else 0


def _tool(path_or_name: str) -> str:
    resolved = path_or_name if os.path.isabs(path_or_name) else shutil.which(path_or_name)
    if not resolved or not os.path.isfile(resolved) or not os.access(resolved, os.X_OK):
        raise RuntimeError(f"required PostgreSQL client tool not found/executable: {path_or_name}")
    return resolved


def _tool_version(tool: str) -> str:
    cp = subprocess.run([tool, "--version"], capture_output=True, text=True, check=True)
    return (cp.stdout or cp.stderr).strip()


def _env(password: str) -> dict:
    env = os.environ.copy()
    env["PGPASSWORD"] = password
    return env


def _endpoint_args(cfg: dict, *, database: str, user: str) -> list[str]:
    p = cfg["postgres"]
    return ["-h", str(p.get("host") or "localhost"), "-p", str(int(p.get("port") or 5432)), "-U", user, "-d", database]


def create_backup(config_path: Path, archive: Path, manifest: Path, *, owner_user: str = "",
                  pg_dump: str = "pg_dump", pg_restore: str = "pg_restore") -> dict:
    cfg = _load(config_path)
    archive = archive.resolve()
    manifest = manifest.resolve()
    if archive == manifest:
        raise RuntimeError("backup archive and manifest must be different files")
    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.exists():
        raise RuntimeError(f"backup archive already exists: {archive}")
    if manifest.exists():
        raise RuntimeError(f"backup manifest already exists: {manifest}")

    user, password = _owner(cfg, owner_user)
    try:
        import psycopg2
    except ImportError as exc:
        raise RuntimeError("psycopg2-binary is required") from exc
    conn = _connect(psycopg2, cfg, user=user, password=password)
    try:
        meta = _server_metadata(conn)
    finally:
        conn.close()
    if meta["current_user"] != user or meta["database_owner"] != user:
        raise RuntimeError("backup must run as the mini-SIEM database owner/migration identity")

    dump_bin = _tool(pg_dump)
    restore_bin = _tool(pg_restore)
    dump_version = _tool_version(dump_bin)
    restore_version = _tool_version(restore_bin)
    if _major(dump_version) < _major(meta["server_version"]):
        raise RuntimeError(
            f"pg_dump client is older than PostgreSQL server: client={dump_version!r} server={meta['server_version']!r}"
        )

    started = datetime.now(timezone.utc)
    cmd = [dump_bin, *_endpoint_args(cfg, database=meta["database"], user=user), "-Fc", "-f", str(archive)]
    cp = subprocess.run(cmd, env=_env(password), capture_output=True, text=True)
    if cp.returncode != 0:
        archive.unlink(missing_ok=True)
        raise RuntimeError(f"pg_dump failed: {(cp.stderr or cp.stdout).strip()}")
    os.chmod(archive, 0o600)
    if not archive.is_file() or archive.stat().st_size <= 0:
        raise RuntimeError("pg_dump produced an empty backup archive")

    listing = subprocess.run([restore_bin, "-l", str(archive)], capture_output=True, text=True)
    if listing.returncode != 0:
        archive.unlink(missing_ok=True)
        raise RuntimeError(f"pg_restore archive validation failed: {(listing.stderr or listing.stdout).strip()}")

    payload = {
        "format": MANIFEST_FORMAT,
        "backup_id": str(uuid.uuid4()),
        "created_at_utc": started.isoformat(),
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "backend": "postgres",
        "contains_sensitive_operational_data": True,
        "contains_bootstrap_or_owner_password": False,
        "archive": {
            "filename": archive.name,
            "bytes": archive.stat().st_size,
            "sha256": br.sha256_file(archive),
            "pg_dump_version": dump_version,
            "pg_restore_validation_version": restore_version,
        },
        "source": {
            "host": str(cfg["postgres"].get("host") or "localhost"),
            "port": int(cfg["postgres"].get("port") or 5432),
            "database": meta["database"],
            "owner_role": user,
            "server_version": meta["server_version"],
            "schema_migration_versions": meta["schema_migration_versions"],
        },
    }
    try:
        br.write_manifest(manifest, payload, mode=0o600)
    except Exception:
        # A dump without its validated manifest is not a usable P5 backup.
        # Do not leave an orphan that an operator could mistake for complete
        # recovery evidence.
        archive.unlink(missing_ok=True)
        raise
    return payload


def _validate_restore_manifest(data: dict, archive: Path) -> dict:
    """Validate all v1 fields that restore relies on before touching PostgreSQL."""
    if data.get("format") != MANIFEST_FORMAT:
        raise RuntimeError("unsupported PostgreSQL backup manifest format")
    if data.get("backend") != "postgres":
        raise RuntimeError("PostgreSQL backup manifest backend must be 'postgres'")

    archive_meta = data.get("archive")
    source = data.get("source")
    if not isinstance(archive_meta, dict) or not isinstance(source, dict):
        raise RuntimeError("PostgreSQL backup manifest is missing archive/source metadata")

    expected_sha = str(archive_meta.get("sha256") or "").lower()
    if not SHA256_RE.fullmatch(expected_sha):
        raise RuntimeError("PostgreSQL backup manifest has an invalid archive SHA-256")
    expected_bytes = archive_meta.get("bytes")
    if isinstance(expected_bytes, bool) or not isinstance(expected_bytes, int) or expected_bytes <= 0:
        raise RuntimeError("PostgreSQL backup manifest has an invalid archive byte count")
    if not archive.is_file():
        raise RuntimeError(f"backup archive not found: {archive}")
    if archive.stat().st_size != expected_bytes:
        raise RuntimeError(
            f"backup archive size does not match manifest: expected={expected_bytes} actual={archive.stat().st_size}"
        )
    if not br.validate_backup(archive, expected_sha):
        raise RuntimeError("backup archive SHA-256 does not match manifest")

    database = str(source.get("database") or "").strip()
    source_owner = str(source.get("owner_role") or "").strip()
    server_version = str(source.get("server_version") or "").strip()
    versions = source.get("schema_migration_versions")
    if not database or not source_owner or not server_version:
        raise RuntimeError("PostgreSQL backup manifest source identity is incomplete")
    if not isinstance(versions, list) or not versions:
        raise RuntimeError("PostgreSQL backup manifest migration ledger is missing")
    if any(isinstance(v, bool) or not isinstance(v, int) or v < 1 for v in versions):
        raise RuntimeError("PostgreSQL backup manifest migration ledger is invalid")
    if versions != sorted(set(versions)):
        raise RuntimeError("PostgreSQL backup manifest migration ledger must be sorted and unique")
    if versions != list(range(1, versions[-1] + 1)):
        raise RuntimeError("PostgreSQL backup manifest migration ledger has gaps")
    current_max = len(db._migrations())
    if versions[-1] > current_max:
        raise RuntimeError(
            f"backup schema version {versions[-1]} is newer than this source supports ({current_max})"
        )
    return {
        "sha256": expected_sha,
        "database": database,
        "source_owner_role": source_owner,
        "server_version": server_version,
        "schema_migration_versions": versions,
    }


def _db_exists(admin_conn, database: str) -> bool:
    cur = admin_conn.cursor()
    try:
        cur.execute("SELECT 1 FROM pg_database WHERE datname=%s", (database,))
        return cur.fetchone() is not None
    finally:
        cur.close()


def _role_exists(admin_conn, role: str) -> bool:
    cur = admin_conn.cursor()
    try:
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,))
        return cur.fetchone() is not None
    finally:
        cur.close()


def _create_database(admin_conn, database: str, owner: str) -> None:
    from psycopg2 import sql
    prior = getattr(admin_conn, "autocommit", False)
    admin_conn.commit()
    admin_conn.autocommit = True
    cur = admin_conn.cursor()
    try:
        cur.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(database), sql.Identifier(owner)))
    finally:
        cur.close()
        admin_conn.autocommit = prior


def _drop_database(admin_conn, database: str) -> None:
    from psycopg2 import sql
    prior = getattr(admin_conn, "autocommit", False)
    admin_conn.commit()
    admin_conn.autocommit = True
    cur = admin_conn.cursor()
    try:
        cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=%s AND pid<>pg_backend_pid()", (database,))
        cur.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(database)))
    finally:
        cur.close()
        admin_conn.autocommit = prior


def _verify_restored(conn, expected_versions: list[int]) -> dict:
    cur = conn.cursor()
    try:
        current_schema_version = len(db._migrations())
        restored_schema_version = max(expected_versions) if expected_versions else 0
        current_schema_ready = restored_schema_version == current_schema_version
        required_tables = tuple(db.RUNTIME_REQUIRED_TABLES) if current_schema_ready else (
            "logs", "alerts", "app_config", "users", "schema_migrations"
        )
        cur.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename = ANY(%s)",
            (list(required_tables),),
        )
        present = {next(iter(r.values())) if isinstance(r, dict) else r[0] for r in cur.fetchall()}
        missing = sorted(set(required_tables) - present)
        if missing:
            raise RuntimeError("restored database is missing required tables: " + ", ".join(missing))
        cur.execute("SELECT version FROM public.schema_migrations ORDER BY version")
        versions = [int(next(iter(r.values())) if isinstance(r, dict) else r[0]) for r in cur.fetchall()]
        if expected_versions and versions != [int(v) for v in expected_versions]:
            raise RuntimeError(
                f"restored schema migration ledger mismatch: expected={expected_versions} actual={versions}"
            )
        return {
            "required_tables": len(present),
            "schema_migration_versions": versions,
            "restored_schema_version": restored_schema_version,
            "current_schema_version": current_schema_version,
            "current_schema_ready": current_schema_ready,
            "migration_required": not current_schema_ready,
        }
    finally:
        cur.close()


def restore_backup(config_path: Path, archive: Path, manifest: Path, *, target_database: str,
                   bootstrap_user: str, bootstrap_password: str, owner_user: str = "",
                   pg_restore: str = "pg_restore", cleanup_on_failure: bool = True) -> dict:
    cfg = _load(config_path)
    data = br.read_manifest(manifest)
    validated = _validate_restore_manifest(data, archive)
    expected_sha = validated["sha256"]
    source_db = validated["database"]
    if not target_database or target_database == source_db:
        raise RuntimeError("restore target must be a new database name; in-place overwrite is not allowed")

    # The manifest's source owner is evidence, not authority over the recovery
    # deployment.  Restore under the owner configured for the current target
    # environment (or an explicit operator override).
    owner, owner_password = _owner(cfg, owner_user)
    restore_bin = _tool(pg_restore)
    listing = subprocess.run([restore_bin, "-l", str(archive)], capture_output=True, text=True)
    if listing.returncode != 0:
        raise RuntimeError(f"pg_restore archive validation failed: {(listing.stderr or listing.stdout).strip()}")

    try:
        import psycopg2
    except ImportError as exc:
        raise RuntimeError("psycopg2-binary is required") from exc

    admin = _connect(psycopg2, cfg, database="postgres", user=bootstrap_user, password=bootstrap_password)
    created = False
    try:
        p = cfg["postgres"]
        bootstrap._bootstrap_preflight(
            admin,
            host=str(p.get("host") or "localhost"),
            port=int(p.get("port") or 5432),
            bootstrap_db="postgres",
            requested_user=bootstrap_user,
        )
        if _db_exists(admin, target_database):
            raise RuntimeError(f"restore target database already exists: {target_database}")
        if not _role_exists(admin, owner):
            raise RuntimeError(f"restore owner role does not exist: {owner}")
        _create_database(admin, target_database, owner)
        created = True

        cmd = [
            restore_bin,
            *_endpoint_args(cfg, database=target_database, user=owner),
            "--exit-on-error",
            "--single-transaction",
            "--no-owner",
            "--no-privileges",
            str(archive),
        ]
        cp = subprocess.run(cmd, env=_env(owner_password), capture_output=True, text=True)
        if cp.returncode != 0:
            raise RuntimeError(f"pg_restore failed: {(cp.stderr or cp.stdout).strip()}")

        restored = _connect(psycopg2, cfg, database=target_database, user=owner, password=owner_password)
        try:
            verify = _verify_restored(restored, validated["schema_migration_versions"])
        finally:
            restored.close()
        return {
            "mode": "restore-new-database",
            "source_database": source_db,
            "target_database": target_database,
            "owner_role": owner,
            "source_owner_role": validated["source_owner_role"],
            "owner_remapped": owner != validated["source_owner_role"],
            "archive_sha256": expected_sha,
            "verified": verify,
            "bootstrap_credential_persisted": False,
            "owner_credential_persisted": False,
        }
    except Exception:
        if created and cleanup_on_failure:
            try:
                _drop_database(admin, target_database)
            except Exception as cleanup_exc:
                print(f"WARNING: failed to remove incomplete restore database {target_database!r}: {cleanup_exc}", file=sys.stderr)
        raise
    finally:
        admin.close()


def _secret(env_name: str, prompt: str) -> str:
    value = os.environ.get(env_name) or ""
    if value:
        return value
    if not sys.stdin.isatty():
        raise RuntimeError(f"set {env_name} for noninteractive execution")
    return getpass.getpass(prompt)


def main() -> int:
    ap = argparse.ArgumentParser(description="mini-SIEM controlled PostgreSQL backup/restore")
    sub = ap.add_subparsers(dest="command", required=True)
    b = sub.add_parser("backup")
    b.add_argument("--db-config", default=str(ROOT / "db-config.json"))
    b.add_argument("--archive", required=True)
    b.add_argument("--manifest", required=True)
    b.add_argument("--owner-user", default="")
    b.add_argument("--pg-dump", default="pg_dump")
    b.add_argument("--pg-restore", default="pg_restore")

    r = sub.add_parser("restore")
    r.add_argument("--db-config", default=str(ROOT / "db-config.json"))
    r.add_argument("--archive", required=True)
    r.add_argument("--manifest", required=True)
    r.add_argument("--target-database", required=True)
    r.add_argument("--bootstrap-user", required=True)
    r.add_argument("--owner-user", default="")
    r.add_argument("--pg-restore", default="pg_restore")
    r.add_argument("--keep-failed-target", action="store_true")

    args = ap.parse_args()
    try:
        if args.command == "backup":
            result = create_backup(
                Path(args.db_config).resolve(), Path(args.archive), Path(args.manifest),
                owner_user=args.owner_user, pg_dump=args.pg_dump, pg_restore=args.pg_restore,
            )
        else:
            bootstrap_password = _secret(
                BOOTSTRAP_PASSWORD_ENV,
                f"PostgreSQL bootstrap password for {args.bootstrap_user!r}: ",
            )
            result = restore_backup(
                Path(args.db_config).resolve(), Path(args.archive), Path(args.manifest),
                target_database=args.target_database,
                bootstrap_user=args.bootstrap_user,
                bootstrap_password=bootstrap_password,
                owner_user=args.owner_user,
                pg_restore=args.pg_restore,
                cleanup_on_failure=not args.keep_failed_target,
            )
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
        return 0
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    finally:
        os.environ.pop(BOOTSTRAP_PASSWORD_ENV, None)
        os.environ.pop(OWNER_PASSWORD_ENV, None)


if __name__ == "__main__":
    raise SystemExit(main())
