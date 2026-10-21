"""Detection management, simulation and read-only evidence surfaces."""
import json
from datetime import datetime, timezone
from flask import Blueprint, jsonify, render_template, request
import auth
import detection
from detection_runtime import TELEMETRY_KEY, UNPROFILED_KEY
from windows_events import resolve_host_time

bp = Blueprint("detection_api", __name__)
_svc = None


def configure(services):
    global _svc
    _svc = services


@bp.get("/detection-rules")
@bp.get("/execution-windows")
def page():
    return render_template("detection.html", mode=request.path.strip("/"), can_edit=auth.is_admin())


@bp.get("/security-alerts")
def alert_queue():
    """Unified alert queue: every alert, not only detection-engine ones."""
    return render_template("alerts.html", can_triage=auth.current_role() in ("admin", "analyst"))


@bp.get("/api/detection/config")
def config_get():
    conn = _svc.get_conn()
    try:
        config, warning = detection.load_config_or_fallback(conn)
        if warning:
            # Shown by the UI; stripped again by validation when saved.
            config["load_warning"] = warning
        return jsonify(config)
    finally:
        conn.close()


@bp.put("/api/detection/config")
def config_put():
    denied = _svc.require_admin()
    if denied is not None:
        return denied
    if request.content_length and request.content_length > 256000:
        return jsonify(error="Configuration exceeds 256 KB"), 413
    conn = _svc.get_conn()
    try:
        result = detection.save_config(conn, request.get_json(silent=True), auth.current_user(), request.remote_addr or "")
        return jsonify(result)
    except detection.ConfigConflict as exc:
        return jsonify(error=str(exc)), 409
    except (ValueError, TypeError, KeyError) as exc:
        return jsonify(error=str(exc)), 400
    finally:
        conn.close()


@bp.post("/api/detection/simulate")
def simulate():
    """Run one synthetic event through the same parse -> normalize -> extract
    -> evaluate path as live ingest. Writes nothing.

    Body: {"event": {...JSON log object...}} or {"raw": "<syslog line>"},
    plus an optional draft "config".
    """
    if request.content_length and request.content_length > 256000:
        return jsonify(error="Simulation exceeds 256 KB"), 413
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="Supply a JSON event object or a raw log line under 64 KB"), 400
    if isinstance(body.get("raw"), str) and body["raw"].strip() and len(body["raw"]) <= 65536:
        line = body["raw"].strip()
    elif isinstance(body.get("event"), dict) and len(json.dumps(body["event"])) <= 65536:
        line = json.dumps(body["event"])
    else:
        return jsonify(error="Supply a JSON event object or a raw log line under 64 KB"), 400
    conn = _svc.get_conn()
    try:
        if "config" in body:
            config = detection.validate_config(body["config"])
        else:
            config = detection.load_config_or_fallback(conn)[0]
        import normalize
        from listener import parse_syslog
        event = parse_syslog(line, "simulation")
        event["received_at"] = datetime.now(timezone.utc).isoformat()
        windows = resolve_host_time(event, config)
        extracted = normalize.extract_fields(event.get("message"), normalize.load_patterns_from_conn(conn),
                                             json_obj=event.get("_json"))
        fields = {**detection.generic_fields(event, extracted), **(windows or {})}
        result = detection.evaluate(config, fields)
        note = ("Windows process/script event: all rules apply." if windows else
                "Not a Security 4688, Sysmon 1 or PowerShell 4104 event: only all-events field-match rules apply. "
                "Threshold rules need a real event sequence and are not simulated.")
        return jsonify(normalized=fields, windows_event=bool(windows), note=note, **result)
    except (ValueError, TypeError, KeyError) as exc:
        return jsonify(error=str(exc)), 400
    finally:
        conn.close()


@bp.get("/api/detection/telemetry")
def telemetry():
    conn = _svc.get_conn()
    try:
        row = conn.execute("SELECT value FROM app_config WHERE key=?", (TELEMETRY_KEY,)).fetchone()
        states = json.loads(row["value"]) if row else {}
        now = datetime.now(timezone.utc)
        for entry in states.values():
            checked = detection.timestamp(entry.get("checked_at"))
            if not checked or (now - checked).total_seconds() > 60:
                entry["status"] = "unknown: monitor heartbeat stale"
        return jsonify(states)
    finally:
        conn.close()


_NEAR_MISS_MAX_EVENTS = 20000


@bp.get("/api/detection/near-misses")
def near_misses():
    """"Why didn't this fire?" for repeated-activity (threshold) rules.

    Replays the live rule logic over recently stored events with the saved
    thresholds; read-only. Reports, per rule, each source's peak count inside
    the rule window against its threshold, including disabled rules.
    """
    from datetime import timedelta
    import rules as rules_mod
    try:
        minutes = max(5, min(1440, int(request.args.get("minutes", 60))))
    except ValueError:
        return jsonify(error="minutes must be a number from 5 to 1440"), 400
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    conn = _svc.get_conn()
    try:
        config = detection.load_config_or_fallback(conn)[0]
        # Newest events win when the window holds more than we replay.
        rows = [dict(r) for r in conn.execute(
            "SELECT id, received_at, source_ip, message FROM logs WHERE received_at >= ? ORDER BY id DESC LIMIT ?",
            (since, _NEAR_MISS_MAX_EVENTS + 1)).fetchall()]
    finally:
        conn.close()
    truncated = len(rows) > _NEAR_MISS_MAX_EVENTS
    rows = rows[:_NEAR_MISS_MAX_EVENTS]
    rows.sort(key=lambda r: (r["received_at"] or "", r["id"]))
    return jsonify(window_minutes=minutes, scanned=len(rows), truncated=truncated,
                   oldest_scanned=rows[0]["received_at"] if rows else None,
                   rules=rules_mod.replay_threshold_rules(rows, config["rules"]))


_FIELD_SAMPLE_ROWS = 50000
_FIELD_LIST_MAX = 100


@bp.get("/api/detection/fields")
def extracted_fields():
    """Extracted field names seen in recent logs, most common first, for the
    rule editor's field picker (usable in rules as field.<name>)."""
    conn = _svc.get_conn()
    try:
        top = conn.execute("SELECT MAX(id) AS m FROM log_fields").fetchone()["m"] or 0
        rows = conn.execute(
            "SELECT field, COUNT(*) AS n FROM log_fields WHERE id > ? "
            "GROUP BY field ORDER BY n DESC, field LIMIT ?",
            (top - _FIELD_SAMPLE_ROWS, _FIELD_LIST_MAX * 2)).fetchall()
    finally:
        conn.close()
    fields = [{"name": "field." + r["field"], "count": r["n"]} for r in rows
              if detection.EXTRACTED_FIELD.match("field." + str(r["field"]))]
    return jsonify({"fields": fields[:_FIELD_LIST_MAX]})


@bp.get("/api/detection/unprofiled-hosts")
def unprofiled_hosts():
    """Windows hosts recently sending process/script events with no host
    profile (by exact name or short-name/FQDN). Profiles still matching one
    of them are dropped here so the list reflects the current configuration."""
    conn = _svc.get_conn()
    try:
        row = conn.execute("SELECT value FROM app_config WHERE key=?", (UNPROFILED_KEY,)).fetchone()
        try:
            seen = json.loads(row["value"]) if row else {}
        except ValueError:
            seen = {}
        config = detection.load_config_or_fallback(conn)[0]
        from windows_events import find_host_profile
        rows = [{"hostname": h, **v} for h, v in (seen if isinstance(seen, dict) else {}).items()
                if isinstance(v, dict) and not find_host_profile(config["hosts"], h)]
        return jsonify(sorted(rows, key=lambda r: r.get("last_seen", ""), reverse=True))
    finally:
        conn.close()


@bp.get("/api/detection/alerts")
def alerts():
    conn = _svc.get_conn()
    try:
        # Bounded recent view. Full historical evidence remains in log search.
        rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 1000").fetchall()
        return jsonify([detection.describe_alert(dict(r)) for r in rows if
                        detection.EVIDENCE_MARKER in (r["description"] or "") or r["rule_name"] == "telemetry_silence"])
    finally:
        conn.close()


@bp.get("/api/detection/alerts/<int:alert_id>/evidence")
def evidence(alert_id):
    conn = _svc.get_conn()
    try:
        row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not row:
            return jsonify(error="Alert not found"), 404
        alert = detection.describe_alert(dict(row))
        ids = [int(i) for i in (row["log_ids"] or "").split(",") if i.isdigit()][:500]
        raw = []
        if ids:
            from sql_helpers import placeholders
            raw = [dict(r) for r in conn.execute("SELECT id,received_at,device_timestamp,hostname,raw FROM logs WHERE id IN (" + placeholders(len(ids)) + ") ORDER BY id", ids).fetchall()]
        return jsonify(alert=alert, events=raw, note="Archived evidence is available through archive-aware log search; this preview shows available hot rows.")
    finally:
        conn.close()
