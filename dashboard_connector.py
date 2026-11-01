"""Read-only Operator Workspace dashboard connector for mini-SIEM.

This module deliberately has its own machine authentication boundary.  Flask
browser sessions are neither accepted nor consulted by these routes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from flask import Blueprint, g, jsonify, request

from runtime_health import listener_snapshot_from_db


PREFIX = "/api/integrations/dashboard/v1"
CONTRACT = "operator-workspace.integration.v1"
SCHEMA_VERSION = "1.0"
SOURCE_PRODUCT = "SIEM"
MAX_LIMIT = 500
DEFAULT_LIMIT = 100
MAX_PAGE_BYTES = 4 * 1024 * 1024
MAX_RECORD_BYTES = 262_144
CURSOR_TTL_SECONDS = 86_400
TOKEN_MAX_DAYS = 90
TOKEN_DIGEST_DOMAIN = b"mini-siem/dashboard-reader-token/v1\0"
CURSOR_DOMAIN = b"mini-siem/dashboard-cursor/v1\0"

RESOURCE_CONFIG = {
    "alerts": ("ALERT", "dashboard:read:alerts", "HISTORY", 30),
    "incidents": ("INCIDENT", "dashboard:read:incidents", "STATE", 60),
    "assets": ("ASSET", "dashboard:read:assets", "STATE", 300),
    "health-observations": ("HEALTH", "dashboard:read:health-observations", "STATE", 60),
}
DISABLED_RESOURCES = {"events", "audit-events", "action-status"}
ALL_SCOPES = {cfg[1] for cfg in RESOURCE_CONFIG.values()} | {
    "dashboard:read:capabilities", "dashboard:read:health",
}

bp = Blueprint("dashboard_connector", __name__, url_prefix=PREFIX)
_services = None
_rate_lock = threading.Lock()
_requests = defaultdict(deque)
_active = defaultdict(int)
_global_active = 0


class SnapshotCapacityError(RuntimeError):
    pass


class CursorError(ValueError):
    pass


class RecordUnexportableError(RuntimeError):
    pass


SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def configure(services):
    global _services
    _services = services


def _now():
    return datetime.now(timezone.utc)


def _utc(value, fallback=None):
    if not value:
        dt = fallback or _now()
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            dt = dt.astimezone(timezone.utc)
        except (TypeError, ValueError):
            dt = fallback or _now()
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def _error(status, code, message, *, retry_after=None):
    body = {
        "contract": CONTRACT,
        "error": {
            "code": code,
            "message": message,
            "request_id": "req-" + uuid.uuid4().hex,
            "retryable": status in (429, 503),
            "retry_after_seconds": int(retry_after) if retry_after is not None else None,
        },
    }
    response = jsonify(body)
    response.status_code = status
    if retry_after is not None:
        response.headers["Retry-After"] = str(int(retry_after))
    return response


def token_digest(token):
    return hashlib.sha256(TOKEN_DIGEST_DOMAIN + token.encode("utf-8")).hexdigest()


def ensure_connector_configuration(conn):
    """Owner/setup operation: persist non-secret instance identity and cursor key."""
    values = {}
    for key, factory in (
        ("dashboard_source_instance_id", lambda: "mini-siem-" + uuid.uuid4().hex),
        ("dashboard_cursor_secret", lambda: secrets.token_urlsafe(48)),
    ):
        row = conn.execute("SELECT value FROM app_config WHERE key=?", (key,)).fetchone()
        value = row["value"] if row and row["value"] else factory()
        if not row or not row["value"]:
            conn.execute(
                "INSERT INTO app_config(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        values[key] = value
    conn.commit()
    return values


def create_reader_token(conn, principal_id, tenant_id, scopes=None, days=90,
                        source_instance_id=None, rotation_group=None):
    days = int(days)
    if days < 1 or days > TOKEN_MAX_DAYS:
        raise ValueError("token lifetime must be between 1 and 90 days")
    cfg = ensure_connector_configuration(conn)
    source_instance_id = source_instance_id or cfg["dashboard_source_instance_id"]
    for label, value in (("principal", principal_id), ("tenant", tenant_id),
                         ("source instance", source_instance_id)):
        if not SAFE_ID.fullmatch(str(value or "")):
            raise ValueError(f"{label} ID must use 1-128 safe ID characters")
    selected = sorted(set(scopes or ALL_SCOPES))
    invalid = set(selected) - ALL_SCOPES
    if invalid:
        raise ValueError("unsupported scope(s): " + ", ".join(sorted(invalid)))
    plain = "msdr_" + secrets.token_urlsafe(48)
    now = _now()
    token_id = uuid.uuid4().hex
    conn.execute(
        """INSERT INTO dashboard_reader_tokens
           (id,principal_id,tenant_id,source_instance_id,token_digest,token_prefix,
            scopes_json,created_at,expires_at,revoked_at,rotation_group,last_used_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (token_id, principal_id, tenant_id, source_instance_id,
         token_digest(plain), plain[:13], json.dumps(selected), _utc(now),
         _utc(now + timedelta(days=days)), None,
         rotation_group or uuid.uuid4().hex, None))
    conn.commit()
    return plain, token_id


def revoke_reader_token(conn, token_id):
    conn.execute("UPDATE dashboard_reader_tokens SET revoked_at=? WHERE id=?",
                 (_utc(_now()), token_id))
    conn.commit()


def rotate_reader_token(conn, token_id, days=90, overlap_hours=24):
    overlap_hours = int(overlap_hours)
    if overlap_hours < 0 or overlap_hours > 24:
        raise ValueError("rotation overlap must be between 0 and 24 hours")
    old = conn.execute("SELECT * FROM dashboard_reader_tokens WHERE id=?", (token_id,)).fetchone()
    if not old or old["revoked_at"]:
        raise ValueError("active token was not found")
    plain, new_id = create_reader_token(
        conn, old["principal_id"], old["tenant_id"],
        json.loads(old["scopes_json"] or "[]"), days,
        old["source_instance_id"], old["rotation_group"])
    cutoff = _now() + timedelta(hours=overlap_hours)
    old_expiry = datetime.fromisoformat(str(old["expires_at"]).replace("Z", "+00:00"))
    conn.execute("UPDATE dashboard_reader_tokens SET expires_at=? WHERE id=?",
                 (_utc(min(old_expiry, cutoff)), token_id))
    conn.commit()
    return plain, new_id


def _config_value(conn, key):
    row = conn.execute("SELECT value FROM app_config WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None


def _authenticate():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer ") or not header[7:].strip():
        return _error(401, "AUTH_REQUIRED", "A dashboard reader bearer token is required.")
    raw = header[7:].strip()
    conn = _services.get_conn()
    row = conn.execute(
        "SELECT * FROM dashboard_reader_tokens WHERE token_digest=?",
        (token_digest(raw),)).fetchone()
    if not row or row["revoked_at"]:
        return _error(401, "AUTH_REQUIRED", "The dashboard reader token is invalid, expired, or revoked.")
    try:
        expires = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
    except ValueError:
        expires = datetime.min.replace(tzinfo=timezone.utc)
    if expires <= _now():
        return _error(401, "AUTH_REQUIRED", "The dashboard reader token is invalid, expired, or revoked.")
    g.dashboard_principal = {
        "id": row["principal_id"], "tenant_id": row["tenant_id"],
        "source_instance_id": row["source_instance_id"],
        "scopes": set(json.loads(row["scopes_json"] or "[]")),
        "token_id": row["id"],
    }
    conn.execute("UPDATE dashboard_reader_tokens SET last_used_at=? WHERE id=?",
                 (_utc(_now()), row["id"]))
    conn.commit()
    return None


def _rate_enter():
    global _global_active
    ident = (g.dashboard_principal["tenant_id"], g.dashboard_principal["id"])
    per_minute = max(1, int(os.getenv("MINISIEM_DASHBOARD_RATE_PER_MINUTE", "120")))
    per_concurrency = max(1, int(os.getenv("MINISIEM_DASHBOARD_CONCURRENCY_PER_PRINCIPAL", "2")))
    global_concurrency = max(1, int(os.getenv("MINISIEM_DASHBOARD_GLOBAL_CONCURRENCY", "8")))
    now = time.monotonic()
    with _rate_lock:
        q = _requests[ident]
        while q and q[0] <= now - 60:
            q.popleft()
        if len(q) >= per_minute:
            return _error(429, "RATE_LIMITED", "Dashboard reader request rate exceeded.", retry_after=1)
        if _active[ident] >= per_concurrency or _global_active >= global_concurrency:
            return _error(429, "RATE_LIMITED", "Dashboard reader concurrency limit exceeded.", retry_after=1)
        q.append(now)
        _active[ident] += 1
        _global_active += 1
        g.dashboard_rate_identity = ident
    return None


def _rate_leave():
    global _global_active
    ident = getattr(g, "dashboard_rate_identity", None)
    if ident is None:
        return
    with _rate_lock:
        _active[ident] = max(0, _active[ident] - 1)
        _global_active = max(0, _global_active - 1)
    g.dashboard_rate_identity = None


@bp.before_request
def _machine_boundary():
    try:
        failure = _authenticate()
    except Exception:
        return _error(503, "TEMPORARY_UNAVAILABLE",
                      "Dashboard reader authentication is temporarily unavailable.",
                      retry_after=5)
    if failure:
        return failure
    return _rate_enter()


@bp.after_request
def _security_headers(response):
    _rate_leave()
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if response.is_json:
        response.headers["Content-Type"] = "application/json; charset=utf-8"
    return response


def _require_scope(scope):
    if scope not in g.dashboard_principal["scopes"]:
        return _error(403, "FORBIDDEN", "The dashboard reader token lacks the required scope.")
    return None


def _parse_limit():
    unknown = set(request.args) - {"limit", "cursor"}
    if unknown:
        raise ValueError("unknown query parameter(s): " + ", ".join(sorted(unknown)))
    raw = request.args.get("limit", str(DEFAULT_LIMIT))
    if not raw.isdigit() or not (1 <= int(raw) <= MAX_LIMIT):
        raise ValueError("limit must be an integer from 1 through 500")
    cursor = request.args.get("cursor")
    if cursor is not None and (not cursor or len(cursor) > 2048 or not all(c.isalnum() or c in "_-" for c in cursor)):
        raise ValueError("cursor must be 1-2048 base64url characters without padding")
    return int(raw), cursor


def _b64(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _cursor_secret(conn):
    value = _config_value(conn, "dashboard_cursor_secret")
    if not value:
        raise RuntimeError("dashboard connector has not been provisioned")
    return value.encode("utf-8")


def _encode_cursor(conn, payload):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(_cursor_secret(conn), CURSOR_DOMAIN + raw, hashlib.sha256).digest()
    return _b64(raw + sig)


def _decode_cursor(conn, encoded, lane):
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        body, sig = raw[:-32], raw[-32:]
        expected = hmac.new(_cursor_secret(conn), CURSOR_DOMAIN + body, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            raise ValueError("signature")
        payload = json.loads(body)
    except Exception as exc:
        raise CursorError("cursor is invalid") from exc
    principal = g.dashboard_principal
    expected_binding = (principal["tenant_id"], principal["id"], principal["source_instance_id"], lane)
    actual_binding = tuple(payload.get(k) for k in ("tenant", "principal", "source", "lane"))
    if actual_binding != expected_binding:
        raise CursorError("cursor does not belong to this principal, tenant, source, or resource")
    if payload.get("schema") != SCHEMA_VERSION or payload.get("visibility") != _visibility(principal):
        raise LookupError("cursor authorization or schema has changed")
    if int(payload.get("exp", 0)) <= int(time.time()):
        raise LookupError("cursor has expired")
    return payload


def _visibility(principal):
    return hashlib.sha256(json.dumps(sorted(principal["scopes"]), separators=(",", ":")).encode()).hexdigest()


def _ref(kind, external_id):
    return {"source_product": SOURCE_PRODUCT,
            "source_instance_id": g.dashboard_principal["source_instance_id"],
            "resource_kind": kind, "external_id": external_id}


def _asset_external(value):
    namespace = g.dashboard_principal["tenant_id"] + "/default"
    return "observed-asset-" + hashlib.sha256((namespace + "\0" + value).encode()).hexdigest()[:24]


def _severity(value):
    value = str(value or "").lower()
    if value in ("critical", "emergency", "alert"): return "CRITICAL"
    if value in ("high", "error", "err"): return "HIGH"
    if value in ("medium", "warning", "warn"): return "MEDIUM"
    if value in ("low", "notice"): return "LOW"
    if value in ("info", "informational", "debug"): return "INFO"
    return "UNKNOWN"


def _base_record(external_id, observed_at, updated_at, payload, derived=None, evidence=None):
    return {
        "external_id": external_id, "operation": "UPSERT",
        "source_observed_at": _utc(observed_at),
        "source_updated_at": _utc(updated_at) if updated_at else None,
        "provenance": {
            "origin": None, "origin_revision": "1", "origin_event_id": external_id,
            "forwarded_by": [], "derived_from": derived or [],
            "evidence_refs": evidence or [], "detail_path": None,
        },
        "payload": payload,
    }


def _native_alerts(conn):
    rows = conn.execute("SELECT * FROM alerts ORDER BY id").fetchall()
    out = []
    for row in rows:
        external = "alert-" + str(row["id"])
        observed = _utc(row["created_at"])
        status_raw = str(row["workflow_status"] or "new").lower()
        alert_status = {"new": "OPEN", "investigating": "OPEN", "acknowledged": "ACKNOWLEDGED",
                        "resolved": "RESOLVED", "closed": "RESOLVED"}.get(status_raw, "UNKNOWN")
        incident_status = {"new": "OPEN", "acknowledged": "OPEN", "investigating": "INVESTIGATING",
                           "resolved": "RESOLVED", "closed": "CLOSED"}.get(status_raw, "UNKNOWN")
        sev = _severity(row["severity"])
        source_ip = str(row["source_ip"] or "").strip()
        entity_refs = []
        if source_ip:
            entity_refs.append({"ref": _ref("ASSET", _asset_external(source_ip)), "role": "SUBJECT",
                                "observed_at": observed, "valid_until": None,
                                "network_namespace": g.dashboard_principal["tenant_id"] + "/default",
                                "confidence": 0.8})
        event_refs = []
        try:
            log_ids = json.loads(row["log_ids"] or "[]")
            if not isinstance(log_ids, list): log_ids = []
        except (TypeError, ValueError):
            log_ids = []
        for log_id in log_ids[:100]:
            event_refs.append(_ref("EVENT", "log-" + str(log_id)))
        evidence = [{"ref": ref, "revision": "1", "kind": "OBSERVATION",
                     "summary": "SIEM source event supporting this alert",
                     "detail_path": None} for ref in event_refs]
        native_rule = str(row["rule_name"])
        rule_id = native_rule if SAFE_ID.fullmatch(native_rule) else (
            "rule-" + hashlib.sha256(native_rule.encode("utf-8")).hexdigest()[:32])
        rule_label = native_rule[:512]
        summary = f"{rule_label} alert" + (f" for {source_ip[:512]}" if source_ip else "")
        attention = {"code": "SIEM.CORRELATED_SECURITY_ALERT", "severity": sev,
                     "confidence": 0.8, "status": alert_status,
                     "reason_codes": ["SIEM_RULE_MATCH"], "recommended_action_codes": []}
        alert_payload = {"entity_refs": entity_refs, "summary": summary, "attention": attention,
                         "rule_id": rule_id, "rule_version": None,
                         "severity": sev, "status": alert_status,
                         "source_case_ref": _ref("INCIDENT", "incident-alert-" + str(row["id"]))}
        rec = _base_record(external, row["created_at"], row["workflow_updated_at"], alert_payload,
                           event_refs, evidence)
        out.append(("alerts", rec))
        incident_external = "incident-alert-" + str(row["id"])
        incident_payload = {"entity_refs": entity_refs, "summary": summary,
                            "attention": attention,
                            "title": summary, "status": incident_status, "severity": sev,
                            "member_refs": [_ref("ALERT", external)], "opened_at": observed,
                            "closed_at": _utc(row["workflow_updated_at"]) if status_raw in ("closed", "resolved") and row["workflow_updated_at"] else None}
        out.append(("incidents", _base_record(incident_external, row["created_at"],
                                              row["workflow_updated_at"], incident_payload,
                                              [_ref("ALERT", external)], evidence)))
    return out


def _native_assets(conn):
    rows = conn.execute(
        """SELECT source_ip, hostname, MAX(received_at) AS last_seen
           FROM logs WHERE COALESCE(source_ip,'')<>'' OR COALESCE(hostname,'')<>''
           GROUP BY source_ip, hostname ORDER BY source_ip, hostname""").fetchall()
    out = []
    for row in rows:
        hostname = str(row["hostname"] or "").strip()
        ip = str(row["source_ip"] or "").strip()
        identity = ip or hostname
        if len(hostname) > 512 or len(ip) > 512:
            raise RecordUnexportableError("An observed asset identity exceeds the contract limit.")
        external = _asset_external(identity)
        identities = []
        observed = _utc(row["last_seen"])
        identity_base = {"namespace": g.dashboard_principal["tenant_id"] + "/default",
                         "observed_at": observed, "valid_until": None,
                         "assurance": "OBSERVED"}
        if hostname: identities.append(dict(identity_base, kind="HOSTNAME", value=hostname))
        if ip: identities.append(dict(identity_base, kind="IP", value=ip))
        payload = {
            "entity_refs": [], "summary": f"Observed SIEM asset {identity}", "attention": None,
            "asset_type": "HOST", "display_name": (hostname or ip)[:256], "identities": identities,
            "lifecycle": "ACTIVE", "criticality": "UNKNOWN", "last_seen_at": observed,
        }
        out.append(("assets", _base_record(external, row["last_seen"], row["last_seen"], payload)))
    return out


def _native_health(conn):
    health = listener_snapshot_from_db(conn)
    listener = str(health.get("listener") or "UNKNOWN").upper()
    state = "HEALTHY" if listener in ("RUNNING", "READY", "HEALTHY") else ("DEGRADED" if listener == "STALE" else "UNKNOWN")
    observed = health.get("heartbeat_at") or _utc(_now())
    reasons = [] if state == "HEALTHY" else ["COLLECTOR_" + listener]
    attention = None if state == "HEALTHY" else {
        "code": "SIEM.COLLECTOR_GAP", "severity": "MEDIUM", "confidence": 1.0,
        "status": "OPEN", "reason_codes": reasons, "recommended_action_codes": []}
    payload = {
        "entity_refs": [], "summary": "mini-SIEM listener and ingestion health",
        "attention": attention, "component": "listener", "state": state,
        "observed_at": _utc(observed), "reason_codes": reasons,
        "metrics": [{"name": k, "value": health.get(k, 0), "unit": "count",
                     "window_seconds": 60, "observed_at": _utc(observed),
                     "threshold": None, "threshold_operator": None,
                     "quality": "MEASURED"}
                    for k in ("queue_depth", "processed_events", "failed_events",
                              "dropped_events", "dropped_udp")],
    }
    return [("health-observations", _base_record("health-listener", observed, observed, payload))]


def _next_sequence(conn, tenant, lane):
    row = conn.execute("SELECT next_sequence FROM dashboard_export_counters WHERE tenant_id=? AND lane=?",
                       (tenant, lane)).fetchone()
    value = int(row["next_sequence"]) if row else 1
    conn.execute(
        "INSERT INTO dashboard_export_counters(tenant_id,lane,next_sequence) VALUES(?,?,?) "
        "ON CONFLICT(tenant_id,lane) DO UPDATE SET next_sequence=excluded.next_sequence",
        (tenant, lane, value + 1))
    return value


def _refresh_lane(conn, lane):
    tenant = g.dashboard_principal["tenant_id"]
    if lane in ("alerts", "incidents"):
        candidates = [r for candidate_lane, r in _native_alerts(conn) if candidate_lane == lane]
    elif lane == "assets":
        candidates = [r for _, r in _native_assets(conn)]
    else:
        candidates = [r for _, r in _native_health(conn)]
    for candidate in candidates:
        fingerprint = hashlib.sha256(json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        existing = conn.execute(
            "SELECT revision,fingerprint FROM dashboard_export_records WHERE tenant_id=? AND lane=? AND external_id=?",
            (tenant, lane, candidate["external_id"])).fetchone()
        if existing and existing["fingerprint"] == fingerprint:
            continue
        revision = int(existing["revision"]) + 1 if existing else 1
        sequence = _next_sequence(conn, tenant, lane)
        candidate["revision"] = str(revision)
        candidate["stream_sequence"] = str(sequence)
        candidate["provenance"]["origin"] = _ref(RESOURCE_CONFIG[lane][0], candidate["external_id"])
        candidate["provenance"]["origin_revision"] = str(revision)
        encoded = json.dumps(candidate, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > MAX_RECORD_BYTES:
            raise RecordUnexportableError("A source record exceeds the export record limit.")
        provenance_bytes = len(json.dumps(candidate["provenance"], separators=(",", ":")).encode("utf-8"))
        if provenance_bytes > 65_536:
            raise RecordUnexportableError("A source record provenance exceeds the export limit.")
        conn.execute(
            """INSERT INTO dashboard_export_records
               (tenant_id,lane,external_id,revision,stream_sequence,fingerprint,record_json,updated_at)
               VALUES(?,?,?,?,?,?,?,?)
               ON CONFLICT(tenant_id,lane,external_id) DO UPDATE SET
               revision=excluded.revision,stream_sequence=excluded.stream_sequence,
               fingerprint=excluded.fingerprint,record_json=excluded.record_json,updated_at=excluded.updated_at""",
            (tenant, lane, candidate["external_id"], revision, sequence, fingerprint, encoded, _utc(_now())))
    conn.commit()


def _new_snapshot(conn, lane):
    principal = g.dashboard_principal
    _refresh_lane(conn, lane)
    now = _now()
    conn.execute("DELETE FROM dashboard_export_snapshot_records WHERE snapshot_id IN (SELECT snapshot_id FROM dashboard_export_snapshots WHERE expires_at<?)", (_utc(now),))
    conn.execute("DELETE FROM dashboard_export_snapshots WHERE expires_at<?", (_utc(now),))
    active = conn.execute(
        "SELECT COUNT(*) AS c FROM dashboard_export_snapshots WHERE tenant_id=? AND principal_id=?",
        (principal["tenant_id"], principal["id"])).fetchone()
    max_active = max(1, int(os.getenv("MINISIEM_DASHBOARD_MAX_ACTIVE_SNAPSHOTS", "16")))
    if int(active["c"] or 0) >= max_active:
        conn.commit()
        raise SnapshotCapacityError("Active snapshot capacity is exhausted; resume an existing cursor or retry after expiry.")
    row = conn.execute(
        "SELECT COALESCE(MAX(stream_sequence),0) AS watermark FROM dashboard_export_records WHERE tenant_id=? AND lane=?",
        (principal["tenant_id"], lane)).fetchone()
    watermark = int(row["watermark"] or 0)
    size = conn.execute(
        "SELECT COUNT(*) AS c, COALESCE(SUM(LENGTH(record_json)),0) AS bytes FROM dashboard_export_records WHERE tenant_id=? AND lane=? AND stream_sequence<=?",
        (principal["tenant_id"], lane, watermark)).fetchone()
    max_records = max(1, int(os.getenv("MINISIEM_DASHBOARD_SNAPSHOT_MAX_RECORDS", "25000")))
    max_bytes = max(MAX_PAGE_BYTES, int(os.getenv("MINISIEM_DASHBOARD_SNAPSHOT_MAX_BYTES", str(64 * 1024 * 1024))))
    if int(size["c"] or 0) > max_records or int(size["bytes"] or 0) > max_bytes:
        conn.commit()
        raise SnapshotCapacityError("Snapshot exceeds the configured durable snapshot capacity.")
    records = conn.execute(
        "SELECT record_json FROM dashboard_export_records WHERE tenant_id=? AND lane=? AND stream_sequence<=? ORDER BY stream_sequence,external_id",
        (principal["tenant_id"], lane, watermark)).fetchall()
    snapshot_id = "snapshot-" + uuid.uuid4().hex
    conn.execute(
        """INSERT INTO dashboard_export_snapshots
           (snapshot_id,tenant_id,principal_id,source_instance_id,lane,watermark,created_at,expires_at,record_count)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        (snapshot_id, principal["tenant_id"], principal["id"], principal["source_instance_id"],
         lane, watermark, _utc(now), _utc(now + timedelta(seconds=CURSOR_TTL_SECONDS)), len(records)))
    conn.executemany(
        "INSERT INTO dashboard_export_snapshot_records(snapshot_id,position,record_json) VALUES(?,?,?)",
        [(snapshot_id, pos, row["record_json"]) for pos, row in enumerate(records)])
    conn.commit()
    return {"mode": "snapshot", "snapshot": snapshot_id, "pos": 0, "checkpoint": watermark,
            "tenant": principal["tenant_id"], "principal": principal["id"],
            "source": principal["source_instance_id"], "lane": lane,
            "schema": SCHEMA_VERSION, "visibility": _visibility(principal),
            "exp": int(time.time()) + CURSOR_TTL_SECONDS}


def _fit_page(rows, limit):
    selected = []
    used = 0
    budget = MAX_PAGE_BYTES - 16_384
    for row in rows[:limit]:
        size = len(row["record_json"].encode("utf-8")) + 1
        if selected and used + size > budget:
            break
        selected.append(row)
        used += size
    return selected, len(selected) < len(rows)


def _page_records(conn, lane, cursor_payload, limit):
    principal = g.dashboard_principal
    if cursor_payload["mode"] == "snapshot":
        snapshot = conn.execute("SELECT * FROM dashboard_export_snapshots WHERE snapshot_id=?",
                                (cursor_payload["snapshot"],)).fetchone()
        if not snapshot:
            raise LookupError("snapshot is no longer available")
        pos = int(cursor_payload.get("pos", 0))
        rows = conn.execute(
            "SELECT position,record_json FROM dashboard_export_snapshot_records WHERE snapshot_id=? AND position>=? ORDER BY position LIMIT ?",
            (cursor_payload["snapshot"], pos, limit + 1)).fetchall()
        page_rows, has_more = _fit_page(rows, limit)
        records = [json.loads(r["record_json"]) for r in page_rows]
        if has_more:
            nxt = dict(cursor_payload, pos=int(page_rows[-1]["position"]) + 1)
            mode, snapshot_id = "SNAPSHOT", cursor_payload["snapshot"]
        else:
            nxt = dict(cursor_payload, mode="incremental", checkpoint=int(cursor_payload["checkpoint"]))
            nxt.pop("snapshot", None); nxt.pop("pos", None)
            mode, snapshot_id = "SNAPSHOT", cursor_payload["snapshot"]
    else:
        _refresh_lane(conn, lane)
        checkpoint = int(cursor_payload.get("checkpoint", 0))
        rows = conn.execute(
            "SELECT stream_sequence,record_json FROM dashboard_export_records WHERE tenant_id=? AND lane=? AND stream_sequence>? ORDER BY stream_sequence LIMIT ?",
            (principal["tenant_id"], lane, checkpoint, limit + 1)).fetchall()
        page_rows, has_more = _fit_page(rows, limit)
        records = [json.loads(r["record_json"]) for r in page_rows]
        new_checkpoint = int(page_rows[-1]["stream_sequence"]) if page_rows else checkpoint
        nxt = dict(cursor_payload, checkpoint=new_checkpoint, exp=int(time.time()) + CURSOR_TTL_SECONDS)
        mode, snapshot_id = "INCREMENTAL", None
    return records, nxt, has_more, mode, snapshot_id


def _resource_page(lane):
    kind, scope, _, _ = RESOURCE_CONFIG[lane]
    failure = _require_scope(scope)
    if failure: return failure
    try:
        limit, encoded = _parse_limit()
        conn = _services.get_conn()
        cursor_payload = _decode_cursor(conn, encoded, lane) if encoded else _new_snapshot(conn, lane)
        records, nxt, has_more, mode, snapshot_id = _page_records(conn, lane, cursor_payload, limit)
        body = {
            "contract": CONTRACT, "schema_version": SCHEMA_VERSION,
            "source_product": SOURCE_PRODUCT,
            "source_instance_id": g.dashboard_principal["source_instance_id"],
            "resource_kind": kind, "sync_mode": mode,
            "source_snapshot_id": snapshot_id,
            "coverage": {"state": "COMPLETE", "reason_codes": []},
            "generated_at": _utc(_now()), "records": records,
            "next_cursor": _encode_cursor(conn, nxt), "has_more": has_more,
        }
        encoded_body = json.dumps(body, separators=(",", ":")).encode("utf-8")
        if len(encoded_body) > MAX_PAGE_BYTES:
            return _error(422, "RECORD_UNEXPORTABLE", "The generated page cannot be exported within transport limits.")
        return jsonify(body)
    except CursorError:
        return _error(400, "INVALID_CURSOR", "Cursor is invalid for this reader or resource.")
    except ValueError as exc:
        return _error(400, "INVALID_REQUEST", str(exc))
    except LookupError:
        return _error(409, "RESET_REQUIRED", "Cursor is no longer valid.")
    except SnapshotCapacityError:
        return _error(503, "TEMPORARY_UNAVAILABLE", "Durable snapshot capacity is temporarily unavailable.", retry_after=60)
    except RecordUnexportableError:
        return _error(422, "RECORD_UNEXPORTABLE", "A source record cannot be represented within contract limits.")
    except Exception:
        return _error(503, "TEMPORARY_UNAVAILABLE", "The dashboard reader is temporarily unavailable.", retry_after=5)


@bp.get("/health")
def health():
    failure = _require_scope("dashboard:read:health")
    if failure: return failure
    try:
        snapshot = listener_snapshot_from_db(_services.get_conn())
        ready = snapshot.get("database") == "READY"
        reason_codes = [] if ready else ["DATABASE_UNAVAILABLE"]
        return jsonify({"contract": CONTRACT, "schema_version": SCHEMA_VERSION,
                        "source_product": SOURCE_PRODUCT,
                        "source_instance_id": g.dashboard_principal["source_instance_id"],
                        "status": "READY" if ready else "UNAVAILABLE",
                        "observed_at": _utc(_now()), "export_ready": ready,
                        "reason_codes": reason_codes})
    except Exception:
        return _error(503, "TEMPORARY_UNAVAILABLE", "Health evidence is temporarily unavailable.", retry_after=5)


@bp.get("/capabilities")
def capabilities():
    failure = _require_scope("dashboard:read:capabilities")
    if failure: return failure
    resources = []
    for path, (kind, scope, sync, poll) in RESOURCE_CONFIG.items():
        operation = "HEALTH" if kind == "HEALTH" else "LIST_" + kind + "S"
        resources.append({"path": PREFIX + "/" + path, "resource_kind": kind,
                          "capability": operation, "enabled": True,
                          "qualification": "IMPLEMENTED_UNQUALIFIED",
                          "sync_modes": ["SNAPSHOT", "INCREMENTAL"],
                          "stream_semantics": sync,
                          "bootstrap_retention_days": 30 if kind == "ALERT" else None,
                          "cursor_ttl_seconds": CURSOR_TTL_SECONDS,
                          "max_page_size": MAX_LIMIT, "reason_codes": []})
    disabled_kinds = {
        "events": ("EVENT", "LIST_EVENTS", "HISTORY", 30),
        "audit-events": ("AUDIT_EVENT", "LIST_AUDIT_EVENTS", "HISTORY", 30),
        "action-status": ("ACTION_STATUS", "LIST_ACTIONS", "STATE", None),
    }
    for path in sorted(DISABLED_RESOURCES):
        kind, capability, stream_semantics, bootstrap_retention_days = disabled_kinds[path]
        resources.append({"path": PREFIX + "/" + path, "resource_kind": kind,
                          "capability": capability, "enabled": False,
                          "qualification": "NOT_IMPLEMENTED", "sync_modes": [],
                          "stream_semantics": stream_semantics,
                          "bootstrap_retention_days": bootstrap_retention_days,
                          "cursor_ttl_seconds": CURSOR_TTL_SECONDS,
                          "max_page_size": MAX_LIMIT, "reason_codes": ["NOT_IMPLEMENTED"]})
    return jsonify({"contract": CONTRACT, "schema_version": SCHEMA_VERSION,
                    "source_product": SOURCE_PRODUCT,
                    "source_instance_id": g.dashboard_principal["source_instance_id"],
                    "auth_profile": "opaque_bearer", "actions": [],
                    "resources": resources})


@bp.get("/<lane>")
def resource(lane):
    if lane in DISABLED_RESOURCES:
        return _error(501, "CAPABILITY_UNAVAILABLE", f"The {lane} resource is not enabled for mini-SIEM.")
    if lane not in RESOURCE_CONFIG:
        return _error(404, "NOT_FOUND", "The requested dashboard resource does not exist.")
    return _resource_page(lane)


@bp.route("/", defaults={"path": ""}, methods=["POST", "PUT", "PATCH", "DELETE"])
@bp.route("/<path:path>", methods=["POST", "PUT", "PATCH", "DELETE"])
def reject_mutation(path):
    return _error(403, "FORBIDDEN", "This connector does not expose mutation operations.")


@bp.get("/")
@bp.get("/<path:path>")
def not_found(path=""):
    return _error(404, "NOT_FOUND", "The requested dashboard resource does not exist.")
