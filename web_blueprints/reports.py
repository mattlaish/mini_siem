import json
from flask import Blueprint, jsonify, request
import workers
bp = Blueprint("reports_api", __name__); _svc = None
def configure(services):
    global _svc; _svc = services
@bp.post("/api/reports/run")
def run():
    body=request.get_json(force=True,silent=True) or {}; days=max(1,min(int(body.get("window_days",7)),365)); report=workers.run_playbook_report(_svc.get_conn(),window_days=days,trigger="manual"); _svc.audit("report_run",target=f"{days}-day window",detail=report.get("summary","")); return jsonify(report)
@bp.get("/api/reports")
def list_reports():
    return jsonify([dict(r) for r in _svc.get_conn().execute("SELECT id, created_at, trigger, window_days, summary, findings FROM reports ORDER BY id DESC LIMIT 100").fetchall()])
@bp.get("/api/reports/<int:rid>")
def get_report(rid):
    row=_svc.get_conn().execute("SELECT * FROM reports WHERE id=?",(rid,)).fetchone()
    if not row:return jsonify({"error":"report not found"}),404
    d=dict(row); d["results"]=json.loads(d.pop("results_json") or "[]"); return jsonify(d)
@bp.delete("/api/reports/<int:rid>")
def delete_report(rid):
    denied=_svc.require_admin()
    if denied is not None:return denied
    c=_svc.get_conn(); c.execute("DELETE FROM reports WHERE id=?",(rid,)); c.commit(); return jsonify({"ok":True})
@bp.get("/api/reports/schedule")
def schedule_get(): return jsonify({"schedule":_svc.cfg_get("report_schedule","off")})
@bp.post("/api/reports/schedule")
def schedule_set():
    body=request.get_json(force=True,silent=True) or {}; sched=(body.get("schedule") or "off").lower()
    if sched not in ("off","weekly","monthly"):return jsonify({"error":"schedule must be off, weekly, or monthly"}),400
    _svc.cfg_set(report_schedule=sched); _svc.audit("report_schedule_changed",target=sched); return jsonify({"ok":True,"schedule":sched})
