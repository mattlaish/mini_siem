import os
import sqlite3
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request
import db as dbmod
import health as health_mod

bp = Blueprint("db_health_api", __name__)
_svc = None

def configure(services):
    global _svc; _svc = services

@bp.get("/api/health")
def api_health():
    query_stats = _svc.query_telemetry().snapshot() if hasattr(_svc, "query_telemetry") else {}
    return jsonify(health_mod.collect(_svc.get_conn(), _svc.db_config(), query_stats=query_stats))

@bp.get("/api/db/integrity")
def api_db_integrity():
    quick = request.args.get("full", "").lower() not in ("1", "true", "yes")
    ok, detail = dbmod.integrity_check(_svc.db_config(), quick=quick)
    return jsonify({"ok": ok, "detail": detail, "quick": quick, "file": dbmod.db_file_info(_svc.db_config())})

@bp.post("/api/db/backup")
def api_db_backup():
    denied = _svc.require_admin()
    if denied is not None: return denied
    cfg = _svc.db_config()
    if cfg.get("backend") != "sqlite": return jsonify({"error": "online backup endpoint is for the SQLite backend"}), 400
    src_path = cfg["sqlite"]["path"]
    backup_dir = _svc.cfg_get("db_backup_dir", "") or os.path.join(os.path.dirname(os.path.abspath(src_path)) or ".", "backups")
    try:
        os.makedirs(backup_dir, exist_ok=True); stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"); dest = os.path.join(backup_dir, f"siem-{stamp}.db")
        src = sqlite3.connect(src_path); dst = sqlite3.connect(dest)
        with dst: src.backup(dst)
        dst.close(); src.close()
        ok, detail = dbmod.integrity_check(dbmod.config_from_path(dest), quick=False); size = os.path.getsize(dest)
        backups = sorted(f for f in os.listdir(backup_dir) if f.startswith("siem-") and f.endswith(".db")); removed = 0
        for old in backups[:-14]:
            try: os.remove(os.path.join(backup_dir, old)); removed += 1
            except OSError: pass
        _svc.audit("db_backup", target=dest, detail=f"{size} bytes, integrity={'ok' if ok else detail}")
        return jsonify({"ok": True, "path": dest, "size_bytes": size, "verified": ok, "verify_detail": detail, "rotated_out": removed, "dir": backup_dir})
    except Exception as exc:
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500
