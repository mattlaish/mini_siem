from flask import Blueprint, jsonify, request
import severity as severity_mod
import secretbox
import workers
bp=Blueprint("ioc_feeds_api",__name__); _svc=None
def configure(services):
    global _svc; _svc=services

def resolve_feed_key(feed_row):
    enc=feed_row.get("key_encrypted") or ""; return secretbox.decrypt(enc,_svc.secretbox_master()) if enc else ""
@bp.get("/api/ioc-feeds")
def list_feeds():
    rows=[dict(r) for r in _svc.get_conn().execute("SELECT * FROM ioc_feeds ORDER BY id DESC").fetchall()]
    for r in rows:r["has_key"]=bool(r.pop("key_encrypted",""))
    return jsonify(rows)
@bp.post("/api/ioc-feeds")
def create_feed():
    body=request.get_json(force=True,silent=True) or {}; name=(body.get("name") or "").strip(); url=(body.get("url") or "").strip()
    if not name or not url:return jsonify({"error":"name and url are required"}),400
    if not url.lower().startswith(("http://","https://")):return jsonify({"error":"url must start with http:// or https://"}),400
    sev=severity_mod.normalize(body.get("severity") or "warning") or "warning"; refresh=max(0,min(int(body.get("refresh_hours",0) or 0),720)); scheme=(body.get("auth_scheme") or "none").lower(); valid={"none","header","authorization","query_param","basic"}
    if scheme not in valid:return jsonify({"error":f"auth_scheme must be one of {sorted(valid)}"}),400
    key=(body.get("key") or "").strip(); enc=secretbox.encrypt(key,_svc.secretbox_master()) if key else ""; c=_svc.get_conn(); new_id=c.insert_returning_id("INSERT INTO ioc_feeds (name, url, severity, threat, default_type, refresh_hours, enabled, auth_scheme, header_name, header_prefix, query_param, basic_user, key_encrypted) VALUES (?,?,?,?,?,?,1,?,?,?,?,?,?)",(name,url,sev,(body.get("threat") or "").strip(),(body.get("default_type") or "").strip().lower(),refresh,scheme,(body.get("header_name") or "").strip(),(body.get("header_prefix") or "").strip(),(body.get("query_param") or "").strip(),(body.get("basic_user") or "").strip(),enc)); c.commit(); _svc.audit("ioc_feed_added",target=name,detail=url); return jsonify({"id":new_id,"ok":True})
@bp.post("/api/ioc-feeds/<int:fid>/fetch")
def fetch_feed(fid):
    c=_svc.get_conn(); row=c.execute("SELECT * FROM ioc_feeds WHERE id=?",(fid,)).fetchone()
    if not row:return jsonify({"error":"feed not found"}),404
    result=workers.fetch_feed(c,dict(row),resolve_key_fn=resolve_feed_key); return jsonify(result) if result.get("ok") else (jsonify(result),502)
@bp.put("/api/ioc-feeds/<int:fid>")
def update_feed(fid):
    body=request.get_json(force=True,silent=True) or {}; c=_svc.get_conn()
    if "enabled" in body:c.execute("UPDATE ioc_feeds SET enabled=? WHERE id=?",(1 if body["enabled"] else 0,fid))
    if "refresh_hours" in body:c.execute("UPDATE ioc_feeds SET refresh_hours=? WHERE id=?",(max(0,min(int(body["refresh_hours"] or 0),720)),fid))
    c.commit(); return jsonify({"ok":True})
@bp.delete("/api/ioc-feeds/<int:fid>")
def delete_feed(fid):
    denied=_svc.require_admin()
    if denied is not None:return denied
    c=_svc.get_conn(); c.execute("DELETE FROM ioc_feeds WHERE id=?",(fid,)); c.commit(); return jsonify({"ok":True})
