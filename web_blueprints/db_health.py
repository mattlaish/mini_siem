import json
import os
import sqlite3
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request, send_file

import archive as archive_mod
import db as dbmod
import health as health_mod
import operational_diagnostics as diagnostics_mod

bp = Blueprint("db_health_api", __name__)
_svc = None


def configure(services):
    global _svc
    _svc = services


@bp.get("/api/health")
def api_health():
    conn = _svc.get_conn()
    try:
        return jsonify(health_mod.collect(conn, _svc.db_config()))
    finally:
        conn.close()


@bp.get("/api/db/integrity")
def api_db_integrity():
    quick = request.args.get("full", "").lower() not in ("1", "true", "yes")
    ok, detail = dbmod.integrity_check(_svc.db_config(), quick=quick)
    return jsonify({"ok": ok, "detail": detail, "quick": quick, "file": dbmod.db_file_info(_svc.db_config())})


@bp.post("/api/db/backup")
def api_db_backup():
    denied = _svc.require_admin()
    if denied is not None:
        return denied
    cfg = _svc.db_config()
    if cfg.get("backend") != "sqlite":
        return jsonify({"error": "online backup endpoint is for the SQLite backend"}), 400
    src_path = cfg["sqlite"]["path"]
    backup_dir = _svc.cfg_get("db_backup_dir", "") or os.path.join(os.path.dirname(os.path.abspath(src_path)) or ".", "backups")
    try:
        os.makedirs(backup_dir, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        dest = os.path.join(backup_dir, f"siem-{stamp}.db")
        src = sqlite3.connect(src_path)
        dst = sqlite3.connect(dest)
        with dst:
            src.backup(dst)
        dst.close()
        src.close()
        ok, detail = dbmod.integrity_check(dbmod.config_from_path(dest), quick=False)
        size = os.path.getsize(dest)
        backups = sorted(f for f in os.listdir(backup_dir) if f.startswith("siem-") and f.endswith(".db"))
        removed = 0
        for old in backups[:-14]:
            try:
                os.remove(os.path.join(backup_dir, old))
                removed += 1
            except OSError:
                pass
        _svc.audit("db_backup", target=dest, detail=f"{size} bytes, integrity={'ok' if ok else detail}")
        return jsonify({"ok": True, "path": dest, "size_bytes": size, "verified": ok, "verify_detail": detail, "rotated_out": removed, "dir": backup_dir})
    except Exception as exc:
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500


def _postgres_security_status(conn, cfg):
    boundary = cfg.get("postgres_privilege_boundary") or {}
    result = {
        "backend": cfg.get("backend"),
        "boundary_enabled": bool(boundary.get("enabled")),
        "runtime_schema_management": "disabled" if cfg.get("backend") == "postgres" else "n/a",
        "migration_owner_required": cfg.get("backend") == "postgres",
    }
    if cfg.get("backend") != "postgres":
        result.update({"applicable": False, "status": "NOT_APPLICABLE"})
        return result

    row = conn.execute(
        """
        SELECT current_user AS role,
               has_table_privilege(current_user,'public.logs','SELECT') AS can_select_logs,
               has_column_privilege(current_user,'public.logs','received_at','INSERT') AS can_insert_logs,
               has_table_privilege(current_user,'public.logs','DELETE') AS can_delete_logs,
               has_table_privilege(current_user,'public.logs','TRUNCATE') AS can_truncate_logs,
               has_column_privilege(current_user,'public.logs','raw','UPDATE') AS can_update_logs,
               has_table_privilege(current_user,'public.schema_migrations','SELECT') AS can_read_migrations,
               has_table_privilege(current_user,'public.schema_migrations','INSERT') AS can_insert_migrations,
               has_table_privilege(current_user,'public.schema_migrations','UPDATE') AS can_update_migrations,
               has_table_privilege(current_user,'public.schema_migrations','DELETE') AS can_delete_migrations,
               has_table_privilege(current_user,'public.archive_segments','INSERT') AS can_insert_archive_catalog,
               has_table_privilege(current_user,'public.archive_segments','UPDATE') AS can_update_archive_catalog,
               has_table_privilege(current_user,'public.archive_segments','DELETE') AS can_delete_archive_catalog,
               has_table_privilege(current_user,'public.archive_segments','TRUNCATE') AS can_truncate_archive_catalog
        """
    ).fetchone()
    result.update(dict(row))
    trigger = conn.execute(
        """
        SELECT COUNT(*) AS c
          FROM pg_trigger t
          JOIN pg_class c ON c.oid=t.tgrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
         WHERE n.nspname='public' AND c.relname='logs'
           AND t.tgname IN ('minisiem_logs_no_mutation','minisiem_logs_no_truncate')
           AND NOT t.tgisinternal AND t.tgenabled <> 'D'
        """
    ).fetchone()
    result["guard_triggers"] = int(trigger["c"] if isinstance(trigger, dict) else trigger[0])
    maintenance_role = str(boundary.get("maintenance_role") or "minisiem_maintenance")
    member = conn.execute(
        "SELECT pg_has_role(current_user, ?, 'member') AS is_member", (maintenance_role,)
    ).fetchone()
    result["maintenance_role"] = maintenance_role
    result["dashboard_inherits_maintenance"] = bool(member["is_member"] if isinstance(member, dict) else member[0])
    readiness = dbmod.migration_readiness(conn)
    result["schema"] = readiness
    migration_write = any(bool(result.get(k)) for k in (
        "can_insert_migrations", "can_update_migrations", "can_delete_migrations"
    ))
    archive_catalog_write = any(bool(result.get(k)) for k in (
        "can_insert_archive_catalog", "can_update_archive_catalog",
        "can_delete_archive_catalog", "can_truncate_archive_catalog",
    ))
    result["can_write_migrations"] = migration_write
    result["can_write_archive_catalog"] = archive_catalog_write
    healthy = bool(
        result.get("can_select_logs")
        and result.get("can_insert_logs")
        and not result.get("can_delete_logs")
        and not result.get("can_truncate_logs")
        and not result.get("can_update_logs")
        and result.get("can_read_migrations")
        and not migration_write
        and not archive_catalog_write
        and result["guard_triggers"] == 2
        and not result["dashboard_inherits_maintenance"]
        and readiness["ready"]
    )
    result.update({"applicable": True, "healthy": healthy, "status": "HEALTHY" if healthy else "WARNING"})
    return result


@bp.get("/api/postgres/security-status")
def api_postgres_security_status():
    """Read-only effective privilege and schema-readiness observability."""
    denied = _svc.require_admin()
    if denied is not None:
        return denied
    conn = _svc.get_conn()
    try:
        return jsonify(_postgres_security_status(conn, _svc.db_config()))
    except Exception as exc:
        return jsonify({"backend": _svc.db_config().get("backend"), "status": "ERROR", "error": f"{type(exc).__name__}: {exc}"}), 500
    finally:
        conn.close()


def _decode_runtime(row):
    if not row or not row.get("value_text"):
        return None
    try:
        value = json.loads(row["value_text"])
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def _archive_status_data(conn, cfg):
    """Return read-only archive/maintenance evidence for API/diagnostics."""
    acfg = archive_mod._cfg(cfg)
    summary = archive_mod.archive_summary(conn)
    latest = conn.execute(
        """SELECT segment_id,state,mode,created_at,start_at,end_at,event_count,
                  unique_payloads,duplicate_occurrences,bytes,sha256
             FROM archive_segments
            WHERE state='SEALED'
            ORDER BY end_at DESC,created_at DESC LIMIT 1"""
    ).fetchone()
    latest = dict(latest) if latest else None
    stats = dbmod.read_runtime_stats(conn, ["archive_status", "maintenance_status", "archive_verify_status"])
    last_archive_meta = _decode_runtime(stats.get("archive_status"))
    maintenance = _decode_runtime(stats.get("maintenance_status"))
    verify_record = _decode_runtime(stats.get("archive_verify_status"))
    verify_state = "NO_SEGMENTS"
    verified_at = None
    if latest:
        if verify_record and verify_record.get("ok") is True:
            verify_state = "VERIFIED"
            verified_at = (stats.get("archive_verify_status") or {}).get("updated_at")
        elif verify_record and verify_record.get("ok") is False:
            verify_state = "FAILED"
            verified_at = (stats.get("archive_verify_status") or {}).get("updated_at")
        elif bool(acfg.get("verify_on_create", True)) and last_archive_meta and last_archive_meta.get("segment_id") == latest.get("segment_id"):
            verify_state = "VERIFIED_ON_CREATE"
            verified_at = (stats.get("archive_status") or {}).get("updated_at")
        elif bool(acfg.get("verify_on_create", True)):
            verify_state = "VERIFICATION_NOT_RECORDED"
        else:
            verify_state = "VERIFY_ON_CREATE_DISABLED"

    maintenance_error = str((maintenance or {}).get("error") or "")
    archive_error = str(((maintenance or {}).get("archive") or {}).get("error") or "")
    status = "HEALTHY"
    if maintenance_error or archive_error or verify_state in {"FAILED", "VERIFICATION_NOT_RECORDED"}:
        status = "WARNING"

    boundary = cfg.get("postgres_privilege_boundary") or {}
    dashboard_catalog_write = False
    if cfg.get("backend") == "postgres":
        prow = conn.execute(
            """SELECT
                 has_table_privilege(current_user,'public.archive_segments','INSERT') OR
                 has_table_privilege(current_user,'public.archive_segments','UPDATE') OR
                 has_table_privilege(current_user,'public.archive_segments','DELETE') OR
                 has_table_privilege(current_user,'public.archive_segments','TRUNCATE') AS can_write"""
        ).fetchone()
        dashboard_catalog_write = bool(prow["can_write"] if isinstance(prow, dict) else prow[0])
    return {
        "status": status,
        "policy": {
            "enabled": bool(acfg.get("enabled", False)),
            "mode": acfg.get("mode", "copy"),
            "hot_days": acfg.get("hot_days", 30),
            "verify_on_create": bool(acfg.get("verify_on_create", True)),
            "run_interval_seconds": acfg.get("run_interval_seconds", 3600),
        },
        "summary": summary,
        "latest_segment": latest,
        "seal_verification": {"status": verify_state, "verified_at": verified_at, "detail": verify_record},
        "last_maintenance": maintenance,
        "last_maintenance_at": (stats.get("maintenance_status") or {}).get("updated_at"),
        "errors": {"maintenance": maintenance_error, "archive": archive_error},
        "privilege_boundary": {
            "enabled": bool(boundary.get("enabled")),
            "maintenance_role": str(boundary.get("maintenance_role") or "minisiem_maintenance") if cfg.get("backend") == "postgres" else "n/a",
            "dashboard_has_maintenance_credential": False,
            "dashboard_can_write_archive_catalog": dashboard_catalog_write,
            "archive_execution_from_web": False,
        },
    }


@bp.get("/api/archive/status")
def api_archive_status():
    """Read-only archive/maintenance operational status."""
    denied = _svc.require_admin()
    if denied is not None:
        return denied
    cfg = _svc.db_config()
    conn = _svc.get_conn()
    try:
        return jsonify(_archive_status_data(conn, cfg))
    except Exception as exc:
        return jsonify({"status": "ERROR", "error": f"{type(exc).__name__}: {exc}"}), 500
    finally:
        conn.close()


def _diagnostic_snapshot():
    cfg = _svc.db_config()
    conn = _svc.get_conn()
    try:
        health = health_mod.collect(conn, cfg)
        try:
            postgres = _postgres_security_status(conn, cfg)
        except Exception as exc:
            postgres = {"backend": cfg.get("backend"), "status": "ERROR", "error": f"{type(exc).__name__}: {exc}"}
        try:
            archive = _archive_status_data(conn, cfg)
        except Exception as exc:
            archive = {"status": "ERROR", "error": f"{type(exc).__name__}: {exc}"}
        diagnostics = diagnostics_mod.build_diagnostics(health, postgres, archive)
        return health, postgres, archive, diagnostics
    finally:
        conn.close()


@bp.get("/api/diagnostics/status")
def api_diagnostics_status():
    denied = _svc.require_admin()
    if denied is not None:
        return denied
    try:
        return jsonify(_diagnostic_snapshot()[3])
    except Exception as exc:
        return jsonify({"overall": "FAILED", "error": f"{type(exc).__name__}: {exc}"}), 500


@bp.post("/api/diagnostics/run")
def api_diagnostics_run():
    denied = _svc.require_admin()
    if denied is not None:
        return denied
    try:
        diagnostics = _diagnostic_snapshot()[3]
        _svc.audit("DIAGNOSTIC_RUN", target="operational-readiness", detail=f"overall={diagnostics.get('overall')}")
        return jsonify(diagnostics)
    except Exception as exc:
        _svc.audit("DIAGNOSTIC_RUN", target="operational-readiness", detail=f"failed={type(exc).__name__}")
        return jsonify({"overall": "FAILED", "error": f"{type(exc).__name__}: {exc}"}), 500


@bp.post("/api/support/bundle")
def api_support_bundle():
    """Generate a bounded, secret-minimized support bundle in memory."""
    denied = _svc.require_admin()
    if denied is not None:
        return denied
    cfg = _svc.db_config()
    try:
        health, postgres, archive, diagnostics = _diagnostic_snapshot()
        schema = postgres.get("schema") or {}
        runtime = health.get("runtime") or {}
        boundary = {
            "backend": postgres.get("backend"),
            "boundary_enabled": postgres.get("boundary_enabled"),
            "status": postgres.get("status"),
            "runtime_schema_management": postgres.get("runtime_schema_management"),
            "can_delete_logs": postgres.get("can_delete_logs"),
            "can_update_logs": postgres.get("can_update_logs"),
            "can_truncate_logs": postgres.get("can_truncate_logs"),
            "can_write_migrations": postgres.get("can_write_migrations"),
            "can_write_archive_catalog": postgres.get("can_write_archive_catalog"),
            "guard_triggers": postgres.get("guard_triggers"),
        }
        payload, manifest = diagnostics_mod.build_support_bundle(
            health, diagnostics, postgres, archive, cfg,
            version_info={"product": "mini-SIEM", "artifact_slice": "operational-readiness-incident-diagnostics"},
            extra_files={
                "schema_status.json": json.dumps(schema, indent=2, sort_keys=True),
                "runtime_status.json": json.dumps(runtime, indent=2, sort_keys=True),
                "security_boundary_status.json": json.dumps(boundary, indent=2, sort_keys=True),
            },
        )
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        filename = f"mini-siem-support-{stamp}.tar.gz"
        _svc.audit("SUPPORT_BUNDLE_CREATED", target=filename, detail=f"bytes={len(payload)} files={len(manifest.get('files', {}))} contains_sensitive_data=false")
        import io
        return send_file(io.BytesIO(payload), mimetype="application/gzip", as_attachment=True, download_name=filename, max_age=0)
    except Exception as exc:
        _svc.audit("SUPPORT_BUNDLE_CREATED", target="failed", detail=f"failed={type(exc).__name__}")
        return jsonify({"error": f"Support bundle failed: {type(exc).__name__}"}), 500
