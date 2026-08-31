import json
from flask import Blueprint, jsonify, request
import severity as severity_mod
import workers
bp=Blueprint("tickets_api",__name__); _svc=None
def configure(services):
    global _svc; _svc=services

def get_ticket_settings():
    try: headers=json.loads(_svc.cfg_get("ticket_headers","{}") or "{}")
    except Exception: headers={}
    return {"enabled":_svc.cfg_get("ticket_enabled","false")=="true","url":_svc.cfg_get("ticket_url",""),"method":_svc.cfg_get("ticket_method","POST") or "POST","headers":headers,"template":_svc.cfg_get("ticket_template","") or workers.DEFAULT_TICKET_TEMPLATE,"min_severity":_svc.cfg_get("ticket_min_severity","warning")}
@bp.get("/api/tickets/config")
def config_get():
    s=get_ticket_settings(); return jsonify({"enabled":s["enabled"],"url":s["url"],"method":s["method"],"header_names":sorted(s["headers"].keys()),"template":s["template"],"min_severity":s["min_severity"],"default_template":workers.DEFAULT_TICKET_TEMPLATE})
@bp.post("/api/tickets/config")
def config_set():
    denied=_svc.require_admin()
    if denied is not None:return denied
    body=request.get_json(force=True,silent=True) or {}; updates={}
    if "enabled" in body:updates["ticket_enabled"]="true" if body["enabled"] else "false"
    if "url" in body:updates["ticket_url"]=str(body["url"]).strip()
    if "method" in body:updates["ticket_method"]="PUT" if str(body["method"]).upper()=="PUT" else "POST"
    if "headers" in body:
        try: hdrs=body["headers"] if isinstance(body["headers"],dict) else json.loads(body["headers"] or "{}")
        except Exception:return jsonify({"error":"headers must be valid JSON (e.g. {\"Authorization\": \"Bearer ...\"})"}),400
        updates["ticket_headers"]=json.dumps(hdrs)
    if "template" in body:updates["ticket_template"]=str(body["template"]).strip()
    if "min_severity" in body:updates["ticket_min_severity"]=severity_mod.normalize(str(body["min_severity"])) or "warning"
    _svc.cfg_set(**updates); _svc.audit("ticket_config_changed",detail=", ".join("headers (updated)" if k=="ticket_headers" else k for k in updates)); return jsonify({"ok":True})
@bp.post("/api/tickets/test")
def test():
    ok,detail=workers.TicketWorker(_svc.get_conn,get_ticket_settings).send_test(); return jsonify({"ok":True,"detail":detail}) if ok else (jsonify({"ok":False,"error":detail}),502)
