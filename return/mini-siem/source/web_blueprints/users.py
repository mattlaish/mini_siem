from datetime import datetime, timezone
from flask import Blueprint, jsonify, request, session
from werkzeug.security import generate_password_hash
import auth

bp = Blueprint("users_api", __name__)
_svc = None

def configure(services):
    global _svc; _svc = services

@bp.get("/api/users")
def api_users_list():
    rows = [dict(r) for r in _svc.get_conn().execute("SELECT username, role, auth_source, must_change_password, created_at FROM users ORDER BY username").fetchall()]
    return jsonify(rows)

@bp.post("/api/users")
def api_users_create():
    denied = _svc.require_admin()
    if denied is not None: return denied
    body = request.get_json(force=True, silent=True) or {}; username = (body.get("username") or "").strip(); password = body.get("password") or ""; role = (body.get("role") or "admin").strip()
    if not username: return jsonify({"error": "username is required"}), 400
    if len(password) < 8: return jsonify({"error": "password must be at least 8 characters"}), 400
    conn = _svc.get_conn()
    if auth.get_user(conn, username): return jsonify({"error": "user already exists"}), 409
    conn.execute("""INSERT INTO users (username, password_hash, role, auth_source, must_change_password, created_at) VALUES (?,?,?,?,?,?)""", (username, generate_password_hash(password), role, "local", 0, datetime.now(timezone.utc).isoformat())); conn.commit()
    _svc.audit("user_created", target=username, detail=f"role: {role}"); return jsonify({"ok": True})

@bp.delete("/api/users/<username>")
def api_users_delete(username):
    denied = _svc.require_admin()
    if denied is not None: return denied
    if username == auth.current_user(): return jsonify({"error": "you cannot delete the account you're logged in as"}), 400
    conn = _svc.get_conn(); n = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone(); total = n["c"] if isinstance(n, dict) else n[0]
    if total <= 1: return jsonify({"error": "cannot delete the last remaining user"}), 400
    conn.execute("DELETE FROM users WHERE username=?", (username,)); conn.commit(); _svc.audit("user_deleted", target=username); return jsonify({"ok": True})

@bp.post("/api/users/password")
def api_users_password():
    if not auth.current_user(): return jsonify({"error": "not authenticated"}), 401
    body = request.get_json(force=True, silent=True) or {}; current = body.get("current_password") or ""; new = body.get("new_password") or ""; conn = _svc.get_conn(); user = auth.verify_local(conn, auth.current_user(), current)
    if not user: return jsonify({"error": "current password is incorrect"}), 400
    if len(new) < 8: return jsonify({"error": "new password must be at least 8 characters"}), 400
    if new == auth.DEFAULT_ADMIN_PASS: return jsonify({"error": "choose a password other than the default"}), 400
    auth.set_password(conn, auth.current_user(), new); session["must_change"] = False; _svc.audit("password_changed", detail="via Setup page"); return jsonify({"ok": True})
