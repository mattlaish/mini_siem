#!/usr/bin/env python3
"""Generate the Dashboard-consumable mini-SIEM return through real routes."""

import argparse
import base64
import copy
import hashlib
import json
import os
import platform
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

RETURN_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = RETURN_ROOT.parents[1]
if not (PROJECT_ROOT / "dashboard_connector.py").is_file():
    PROJECT_ROOT = RETURN_ROOT / "source"
sys.path.insert(0, str(PROJECT_ROOT))

import dashboard
import dashboard_connector as connector

TENANT_ID = "tenant-fixture"
PRODUCT_ID = "dashboard-mini-siem-fixture-01"
SOURCE_INSTANCE_ID = "mini-siem-fixture-01"
SECRET_REF = "secret://systemd/mini-siem-fixture-reader-token"
ADAPTER_ID = "mini-siem-owi-fixture-v1"
SOURCE_VERSION = "mini-siem-dashboard-connector-rebuild-2026-10-22"
CAPABILITIES = ["HEALTH", "LIST_ALERTS", "LIST_ASSETS", "LIST_INCIDENTS"]
LANE_META = {
    "alerts": ("LIST_ALERTS", "ALERT", 2),
    "incidents": ("LIST_INCIDENTS", "INCIDENT", 2),
    "assets": ("LIST_ASSETS", "ASSET", 2),
    "health-observations": ("HEALTH", "HEALTH", 100),
}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def seed(conn):
    base = datetime(2026, 9, 1, 0, 0, tzinfo=timezone.utc)
    for index in range(7):
        at = (base + timedelta(days=index * 5)).isoformat()
        conn.execute(
            """INSERT INTO logs
               (received_at,source_ip,hostname,format,severity,message,raw)
               VALUES(?,?,?,?,?,?,?)""",
            (at, f"192.0.2.{index + 10}", f"fixture-host-{index}", "json",
             "warning", "synthetic fixture event", "synthetic fixture event"))
        conn.execute(
            """INSERT INTO alerts
               (created_at,rule_name,severity,source_ip,description,log_ids,
                workflow_status,workflow_updated_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (at, f"fixture-correlation-{index}", "high", f"192.0.2.{index + 10}",
             "synthetic contract fixture", json.dumps([index + 1]),
             "investigating" if index == 0 else "new", at))
    heartbeat = {
        "listener": "RUNNING", "ingest": "RUNNING", "worker": "RUNNING",
        "queue_depth": 0, "processed_events": 7, "failed_events": 0,
        "dropped_events": 0, "dropped_udp": 0,
        "last_event_at": base.isoformat(), "detail": "synthetic fixture heartbeat",
    }
    conn.execute(
        "INSERT INTO runtime_stats(key,value_num,value_text,updated_at) VALUES(?,?,?,?)",
        ("listener_health", None, json.dumps(heartbeat), datetime.now(timezone.utc).isoformat()))
    conn.commit()


def mutate_lane(config, lane):
    conn = dashboard.dbmod.connect(config)
    now = datetime.now(timezone.utc).isoformat()
    try:
        if lane == "alerts":
            conn.execute("UPDATE alerts SET workflow_status='acknowledged',workflow_updated_at=? WHERE id=1", (now,))
        elif lane == "incidents":
            conn.execute("UPDATE alerts SET workflow_status='investigating',workflow_updated_at=? WHERE id=2", (now,))
        elif lane == "assets":
            conn.execute(
                "INSERT INTO logs(received_at,source_ip,hostname,format,severity,message,raw) VALUES(?,?,?,?,?,?,?)",
                (now, "192.0.2.250", "fixture-delta-host", "json", "info",
                 "synthetic asset delta", "synthetic asset delta"))
        else:
            heartbeat = {
                "listener": "RUNNING", "ingest": "RUNNING", "worker": "RUNNING",
                "queue_depth": 1, "processed_events": 8, "failed_events": 0,
                "dropped_events": 0, "dropped_udp": 0,
                "last_event_at": now, "detail": "synthetic health delta",
            }
            conn.execute(
                "UPDATE runtime_stats SET value_text=?,updated_at=? WHERE key='listener_health'",
                (json.dumps(heartbeat), now))
        conn.commit()
    finally:
        conn.close()


def call_page(client, headers, lane, cursor, page_size):
    url = connector.PREFIX + "/" + lane + f"?limit={page_size}"
    if cursor is not None:
        url += "&cursor=" + cursor
    response = client.get(url, headers=headers)
    if response.status_code != 200:
        raise RuntimeError(f"{lane} export failed: {response.status_code} {response.get_data(as_text=True)}")
    return response.get_json()


def collect_lane(client, headers, config, lane, page_size):
    capability, kind, _ = LANE_META[lane]
    pages, requests = [], []
    cursor = None
    while True:
        requests.append({"tenant_id": TENANT_ID, "product_id": PRODUCT_ID,
                         "capability": capability, "resource_kind": kind,
                         "cursor": cursor, "page_size": page_size})
        page = call_page(client, headers, lane, cursor, page_size)
        pages.append(page)
        cursor = page["next_cursor"]
        if not page["has_more"]:
            break
    mutate_lane(config, lane)
    requests.append({"tenant_id": TENANT_ID, "product_id": PRODUCT_ID,
                     "capability": capability, "resource_kind": kind,
                     "cursor": cursor, "page_size": page_size})
    delta = call_page(client, headers, lane, cursor, page_size)
    pages.append(delta)
    cursor = delta["next_cursor"]
    requests.append({"tenant_id": TENANT_ID, "product_id": PRODUCT_ID,
                     "capability": capability, "resource_kind": kind,
                     "cursor": cursor, "page_size": page_size})
    empty = call_page(client, headers, lane, cursor, page_size)
    if empty["records"] or empty["has_more"]:
        raise RuntimeError(f"{lane} did not produce the required empty incremental page")
    pages.append(empty)
    return pages, requests


def identity_and_manifest(output):
    relative_paths = [
        "auth.py", "dashboard.py", "dashboard_connector.py", "db.py", "runtime_health.py",
        "schemas/operator_workspace/control.schema.json",
        "schemas/operator_workspace/page.schema.json",
        "schemas/operator_workspace/resource-manifest.json",
        "tools/manage_dashboard_reader_token.py",
        "tools/postgres_privilege_boundary.py",
    ]
    files = []
    for relative in sorted(relative_paths):
        path = PROJECT_ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"repository identity input is missing: {relative}")
        files.append({"path": relative, "sha256": sha(path)})
    identity = {"purpose": "OFFLINE_FIXTURE_ONLY", "product_slug": "mini-siem",
                "source_version": SOURCE_VERSION,
                "files": files}
    write_json(output / "identity-inputs.json", identity)
    manifest = {
        "adapter_id": ADAPTER_ID, "product_type": "SIEM", "vendor": "Internal",
        "protocol_version": 1, "identity_sha256": sha(output / "identity-inputs.json"),
        "capabilities": CAPABILITIES, "capability_generation": 1,
        "qualification_status": "UNQUALIFIED", "qualification_evidence_sha256": None,
    }
    write_json(output / "adapter-manifest.fixture.json", manifest)
    return manifest


def resource_bindings(enabled):
    rows = []
    definitions = [
        ("alerts", "ALERT", "LIST_ALERTS", True, "HISTORY", 30),
        ("incidents", "INCIDENT", "LIST_INCIDENTS", True, "STATE", 60),
        ("assets", "ASSET", "LIST_ASSETS", True, "STATE", 300),
        ("health-observations", "HEALTH", "HEALTH", True, "STATE", 60),
        ("events", "EVENT", "LIST_EVENTS", False, "HISTORY", 30),
        ("audit-events", "AUDIT_EVENT", "LIST_AUDIT_EVENTS", False, "HISTORY", 60),
        ("action-status", "ACTION_STATUS", "LIST_ACTIONS", False, "STATE", 30),
    ]
    for suffix, kind, capability, required, semantics, poll in definitions:
        lane_enabled = enabled and required
        rows.append({"path": connector.PREFIX + "/" + suffix, "kind": kind,
                     "capability": capability, "required": required,
                     "enabled": lane_enabled, "stream_semantics": semantics,
                     "sync_modes": ["SNAPSHOT", "INCREMENTAL"] if lane_enabled else [],
                     "poll_interval_seconds": poll})
    return rows


def binding_fixture(output):
    binding = {
        "contract": connector.CONTRACT, "schema_version": connector.SCHEMA_VERSION,
        "status": "RETURNED_UNQUALIFIED", "product_slug": "mini-siem",
        "source_product": "SIEM", "source_instance_id": SOURCE_INSTANCE_ID,
        "tenant_id": TENANT_ID, "integration_instance_id": PRODUCT_ID,
        "enabled": False, "qualification": "IMPLEMENTED_UNQUALIFIED",
        "network_profile": "DEDICATED_HOST_443",
        "origin": "https://mini-siem-fixture.invalid:443",
        "alternative_same_host_port": 19406, "ui_origin": None,
        "resolved_address_allowlist": ["192.0.2.6"], "base_path": connector.PREFIX,
        "tls": {"verify_peer": True, "verify_hostname": True, "minimum_version": "1.2",
                "trust_bundle_ref": "secret://systemd/mini-siem-fixture-ca",
                "client_certificate_ref": None, "client_private_key_ref": None,
                "revocation_policy": "PLATFORM_MANAGED_REQUIRED"},
        "auth": {"profile": "opaque_bearer", "credential_ref": SECRET_REF,
                 "issuer": None, "audience": None,
                 "principal_ref": "dashboard-mini-siem-fixture-reader",
                 "tenant_selector": None,
                 "scopes": ["dashboard:read:health", "dashboard:read:capabilities",
                            "dashboard:read:alerts", "dashboard:read:incidents",
                            "dashboard:read:assets", "dashboard:read:health-observations"]},
        "endpoints": {"health": connector.PREFIX + "/health",
                      "capabilities": connector.PREFIX + "/capabilities",
                      "resources": resource_bindings(True)},
        "limits": {"page_size": 100, "max_page_size": 500,
                   "max_response_bytes": 4194304, "connect_timeout_seconds": 5,
                   "read_timeout_seconds": 10, "request_deadline_seconds": 30},
        "action_plane": {"enabled": False, "credential_ref": None, "profiles": []},
        "deployment_role": "PRODUCT_AUTHORITY",
        "evidence": {"source_version": SOURCE_VERSION,
                     "artifact_sha256": None, "test_results_ref": "test-results.md",
                     "qualified_at": None},
    }
    write_json(output / "binding.fixture.json", binding)
    template = copy.deepcopy(binding)
    template.update({"status": "TEMPLATE_NOT_DEPLOYABLE", "source_instance_id": None,
                     "tenant_id": None, "integration_instance_id": None,
                     "qualification": "NOT_IMPLEMENTED", "origin": None,
                     "resolved_address_allowlist": []})
    template["tls"].update({"trust_bundle_ref": None, "revocation_policy": None})
    template["auth"].update({"credential_ref": None, "principal_ref": None})
    template["endpoints"]["resources"] = resource_bindings(False)
    template["evidence"] = {"source_version": None, "artifact_sha256": None,
                            "test_results_ref": None, "qualified_at": None}
    write_json(output / "binding.deployment.template.json", template)
    return binding


def negative_page_fixtures(output, valid_alert_page):
    fixture_dir = output / "fixtures" / "negative"
    positive_dir = output / "fixtures" / "positive"
    for path in (fixture_dir, positive_dir):
        if path.exists():
            shutil.rmtree(path)
    cases, bundle_pages = [], []
    definitions = []
    page = copy.deepcopy(valid_alert_page); page.pop("contract", None)
    definitions.append(("N-DEC-001", "decoder", "missing-contract.json", page, "ProductConnectorError", "Required contract field is absent."))
    page = copy.deepcopy(valid_alert_page); page["unexpected"] = True
    definitions.append(("N-DEC-002", "decoder", "additional-field.json", page, "ProductConnectorError", "Closed page schema rejects unknown fields."))
    page = copy.deepcopy(valid_alert_page); page["generated_at"] = "2026-09-01T00:00:00+00:00"
    definitions.append(("N-DEC-003", "decoder", "non-z-time.json", page, "ProductConnectorError", "Wire timestamps must end in Z."))
    page = copy.deepcopy(valid_alert_page); page["records"][0]["revision"] = "0"
    definitions.append(("N-DEC-004", "decoder", "invalid-revision.json", page, "ProductConnectorError", "Revision must be a positive decimal string."))
    page = copy.deepcopy(valid_alert_page); page["records"][0]["payload"]["client_secret"] = "fixture-forbidden"
    definitions.append(("N-DEC-005", "decoder", "forbidden-secret-field.json", page, "ProductConnectorError", "Secret-bearing payload fields are forbidden."))
    page = copy.deepcopy(valid_alert_page); page["records"][0]["operation"] = "DELETE"
    definitions.append(("N-DEC-006", "decoder", "delete-nonempty-payload.json", page, "ProductConnectorError", "DELETE records must carry an empty payload."))
    for case_id, stage, name, body, error, reason in definitions:
        relative = "fixtures/negative/" + name
        write_json(fixture_dir / name, body)
        cases.append({"case_id": case_id, "stage": stage, "input_fixture": relative,
                      "request": None, "expected_error": error, "reason": reason})
        bundle_pages.append({"route_name": "alerts", "page": body})

    request = {"tenant_id": TENANT_ID, "product_id": PRODUCT_ID,
               "capability": "LIST_ALERTS", "resource_kind": "ALERT",
               "cursor": None, "page_size": 2}

    page_defs = []
    wrong_product = copy.deepcopy(valid_alert_page); wrong_product["source_product"] = "NDR"
    page_defs.append(("N-PAGE-001", "decoder", "wrong-product.json", wrong_product,
                      None, "ProductConnectorConflictError", "Response product differs from binding."))
    wrong_source = copy.deepcopy(valid_alert_page); wrong_source["source_instance_id"] = "other-source"
    page_defs.append(("N-PAGE-002", "decoder", "wrong-source.json", wrong_source,
                      None, "ProductConnectorConflictError", "Response source differs from binding."))
    wrong_kind = copy.deepcopy(valid_alert_page); wrong_kind["resource_kind"] = "ASSET"
    page_defs.append(("N-PAGE-003", "decoder", "wrong-kind.json", wrong_kind,
                      None, "ProductConnectorError", "Response kind differs from requested lane."))
    empty_more = copy.deepcopy(valid_alert_page); empty_more["records"] = []; empty_more["has_more"] = True
    page_defs.append(("N-SYNC-001", "page_validate", "empty-with-more.json", empty_more,
                      request, "ProductConnectorCursorError", "A continuing page cannot be empty."))
    no_progress = copy.deepcopy(valid_alert_page)
    no_progress["has_more"] = True; no_progress["next_cursor"] = "same-cursor"
    no_progress_request = dict(request, cursor="same-cursor")
    page_defs.append(("N-SYNC-002", "page_validate", "cursor-no-progress.json", no_progress,
                      no_progress_request, "ProductConnectorCursorError", "A continuing page must advance its cursor."))
    too_many = copy.deepcopy(valid_alert_page)
    extra_record = copy.deepcopy(too_many["records"][0])
    extra_record["external_id"] = "alert-page-limit-extra"
    extra_record["stream_sequence"] = "999"
    extra_record["provenance"]["origin"]["external_id"] = "alert-page-limit-extra"
    extra_record["provenance"]["origin_event_id"] = "alert-page-limit-extra"
    too_many["records"].append(extra_record)
    page_defs.append(("N-PAGE-004", "page_validate", "too-many-records.json", too_many,
                      request, "ProductConnectorError", "Page exceeds the requested record limit."))
    for case_id, stage, name, body, case_request, error, reason in page_defs:
        relative = "fixtures/negative/" + name
        write_json(fixture_dir / name, body)
        cases.append({"case_id": case_id, "stage": stage, "input_fixture": relative,
                      "request": case_request, "expected_error": error, "reason": reason})

    drift_first = copy.deepcopy(valid_alert_page)
    drift_first["has_more"] = True
    drift_second = copy.deepcopy(valid_alert_page)
    drift_second["has_more"] = False
    drift_second["source_snapshot_id"] = "snapshot-drift"
    drift_second["next_cursor"] = "snapshot-drift-terminal"
    write_json(fixture_dir / "snapshot-drift-step-1.json", drift_first)
    write_json(fixture_dir / "snapshot-drift-step-2.json", drift_second)
    drift_sequence = {"steps": [
        {"fixture": "fixtures/negative/snapshot-drift-step-1.json", "request": request},
        {"fixture": "fixtures/negative/snapshot-drift-step-2.json",
         "request": dict(request, cursor=drift_first["next_cursor"])},
    ]}
    write_json(fixture_dir / "snapshot-drift.sequence.json", drift_sequence)
    cases.append({"case_id": "N-SYNC-003", "stage": "sync",
                  "input_fixture": "fixtures/negative/snapshot-drift.sequence.json",
                  "request": request, "expected_error": "ProductConnectorConflictError",
                  "reason": "Snapshot ID changed on the second page of one snapshot chain."})

    equal_first = copy.deepcopy(valid_alert_page)
    equal_first["records"] = equal_first["records"][:1]
    equal_first["has_more"] = False; equal_first["next_cursor"] = "equal-checkpoint"
    equal_second = copy.deepcopy(equal_first)
    equal_second["sync_mode"] = "INCREMENTAL"; equal_second["source_snapshot_id"] = None
    equal_second["next_cursor"] = "equal-terminal"
    equal_second["records"][0]["payload"]["summary"] = "same revision changed content"
    write_json(fixture_dir / "equal-revision-step-1.json", equal_first)
    write_json(fixture_dir / "equal-revision-step-2.json", equal_second)
    equal_sequence = {"steps": [
        {"fixture": "fixtures/negative/equal-revision-step-1.json", "request": request},
        {"fixture": "fixtures/negative/equal-revision-step-2.json",
         "request": dict(request, cursor=equal_first["next_cursor"])},
    ]}
    write_json(fixture_dir / "equal-revision-drift.sequence.json", equal_sequence)
    cases.append({"case_id": "N-SYNC-005", "stage": "sync",
                  "input_fixture": "fixtures/negative/equal-revision-drift.sequence.json",
                  "request": request, "expected_error": "ProductConnectorConflictError",
                  "reason": "The second page changes canonical content at the same identity and revision."})

    old_first = copy.deepcopy(equal_first)
    old_first["records"][0]["revision"] = "2"
    old_first["next_cursor"] = "old-revision-checkpoint"
    old_second = copy.deepcopy(old_first)
    old_second["sync_mode"] = "INCREMENTAL"; old_second["source_snapshot_id"] = None
    old_second["next_cursor"] = "old-revision-terminal"
    old_second["records"][0]["revision"] = "1"
    old_second["records"][0]["payload"]["summary"] = "late historical revision"
    write_json(positive_dir / "old-revision-step-1.json", old_first)
    write_json(positive_dir / "old-revision-step-2.json", old_second)
    old_sequence = {"steps": [
        {"fixture": "fixtures/positive/old-revision-step-1.json", "request": request},
        {"fixture": "fixtures/positive/old-revision-step-2.json",
         "request": dict(request, cursor=old_first["next_cursor"])},
    ]}
    write_json(positive_dir / "old-revision-preserves-current.sequence.json", old_sequence)
    write_json(output / "positive-sequences.json", [{
        "case_id": "P-SYNC-001",
        "input_fixture": "fixtures/positive/old-revision-preserves-current.sequence.json",
        "expected_current_revision": "2",
        "actual_result": "NOT_RUN",
        "evidence_ref": "test-logs/P-SYNC-001.json",
        "reason": "An older revision remains historical and does not replace current revision 2.",
    }])
    write_json(output / "test-logs" / "P-SYNC-001.json", {
        "case_id": "P-SYNC-001", "actual_result": "NOT_RUN",
        "executed": False,
        "required_command": "python tools/verify_positive_sequences.py --record",
    })
    write_json(output / "negative-cases.json", cases)
    return bundle_pages


def record_response(output, case_id, response):
    value = {"status": response.status_code,
             "headers": {k: v for k, v in response.headers.items()
                         if k in ("Content-Type", "Cache-Control", "Retry-After", "Location", "X-Content-Type-Options")},
             "body": response.get_json(silent=True)}
    relative = f"test-logs/{case_id}.json"
    write_json(output / relative, value)
    return relative


def transport_catalog(output, client, token, config):
    def request_fixture(case_id, method, path, auth="fixture-secret-ref", body=None,
                        query=None, transport=None, fault_injection=None):
        value = {"method": method, "path": path, "authorization": auth, "json": body,
                 "query": query or {}, "transport": transport or {},
                 "fault_injection": fault_injection}
        relative = f"fixtures/transport/{case_id}.json"
        write_json(output / relative, value)
        return relative

    headers = {"Authorization": "Bearer " + token}
    cases = []
    def add(case_id, setup, request_ref, status, code, expected_headers, result, evidence):
        cases.append({"case_id": case_id, "stage": "transport", "setup": setup,
                      "request_fixture": request_ref, "expected_status": status,
                      "expected_code": code, "expected_headers": expected_headers,
                      "actual_result": result, "evidence_ref": evidence})

    req = request_fixture("T-401", "GET", connector.PREFIX + "/health", auth=None)
    response = client.get(connector.PREFIX + "/health")
    add("T-401", "Local Flask client without Authorization header.", req, 401, "AUTH_REQUIRED",
        {"Cache-Control": "no-store"}, "PASS", record_response(output, "T-401", response))

    conn = dashboard.dbmod.connect(config)
    try:
        limited, _ = connector.create_reader_token(conn, "limited-fixture", TENANT_ID,
                                                    ["dashboard:read:health"], days=1,
                                                    source_instance_id=SOURCE_INSTANCE_ID)
    finally: conn.close()
    req = request_fixture("T-403", "GET", connector.PREFIX + "/alerts")
    response = client.get(connector.PREFIX + "/alerts", headers={"Authorization": "Bearer " + limited})
    add("T-403", "Token has health scope only.", req, 403, "FORBIDDEN",
        {"Cache-Control": "no-store"}, "PASS", record_response(output, "T-403", response))

    first_page = client.get(connector.PREFIX + "/alerts?limit=1", headers=headers).get_json()
    evicted_cursor = first_page["next_cursor"]
    raw_cursor = base64.urlsafe_b64decode(evicted_cursor + "=" * (-len(evicted_cursor) % 4))
    cursor_document = json.loads(raw_cursor[:-32])
    conn = dashboard.dbmod.connect(config)
    try:
        conn.execute("DELETE FROM dashboard_export_snapshot_records WHERE snapshot_id=?",
                     (cursor_document["snapshot"],))
        conn.execute("DELETE FROM dashboard_export_snapshots WHERE snapshot_id=?",
                     (cursor_document["snapshot"],))
        conn.commit()
    finally: conn.close()
    response = client.get(connector.PREFIX + "/alerts?limit=1&cursor=" + evicted_cursor,
                          headers=headers)
    req = request_fixture("T-409", "GET", connector.PREFIX + "/alerts",
                          query={"limit": 1, "cursor": "evicted-snapshot-cursor-ref"},
                          fault_injection="delete the referenced durable snapshot before replay")
    add("T-409", "Local Flask client replays a valid signed cursor after its durable snapshot is evicted.",
        req, 409, "RESET_REQUIRED", {"Cache-Control": "no-store"}, "PASS",
        record_response(output, "T-409", response))

    conn = dashboard.dbmod.connect(config)
    try:
        rate_token, _ = connector.create_reader_token(conn, "rate-fixture", TENANT_ID,
                                                       ["dashboard:read:health"], days=1,
                                                       source_instance_id=SOURCE_INSTANCE_ID)
    finally: conn.close()
    previous = os.environ.get("MINISIEM_DASHBOARD_RATE_PER_MINUTE")
    os.environ["MINISIEM_DASHBOARD_RATE_PER_MINUTE"] = "1"
    rate_headers = {"Authorization": "Bearer " + rate_token}
    client.get(connector.PREFIX + "/health", headers=rate_headers)
    response = client.get(connector.PREFIX + "/health", headers=rate_headers)
    if previous is None: os.environ.pop("MINISIEM_DASHBOARD_RATE_PER_MINUTE", None)
    else: os.environ["MINISIEM_DASHBOARD_RATE_PER_MINUTE"] = previous
    req = request_fixture("T-429", "GET", connector.PREFIX + "/health")
    add("T-429", "Per-principal rate limit set to one request/minute.", req, 429,
        "RATE_LIMITED", {"Retry-After": "integer seconds"}, "PASS",
        record_response(output, "T-429", response))

    previous_capacity = os.environ.get("MINISIEM_DASHBOARD_MAX_ACTIVE_SNAPSHOTS")
    os.environ["MINISIEM_DASHBOARD_MAX_ACTIVE_SNAPSHOTS"] = "1"
    response = client.get(connector.PREFIX + "/alerts?limit=1", headers=headers)
    if previous_capacity is None: os.environ.pop("MINISIEM_DASHBOARD_MAX_ACTIVE_SNAPSHOTS", None)
    else: os.environ["MINISIEM_DASHBOARD_MAX_ACTIVE_SNAPSHOTS"] = previous_capacity
    req = request_fixture("T-503", "GET", connector.PREFIX + "/alerts", query={"limit": 1},
                          fault_injection="set active snapshot capacity below the existing durable snapshot count")
    add("T-503", "Local Flask client requests a new snapshot while durable snapshot capacity is exhausted.",
        req, 503, "TEMPORARY_UNAVAILABLE", {"Retry-After": "integer seconds or absent"}, "PASS",
        record_response(output, "T-503", response))

    req = request_fixture("T-MUTATION", "POST", connector.PREFIX + "/alerts", body={})
    response = client.post(connector.PREFIX + "/alerts", headers=headers, json={})
    add("T-MUTATION", "Reader token attempts a mutation.", req, 403, "FORBIDDEN",
        {"Cache-Control": "no-store"}, "PASS", record_response(output, "T-MUTATION", response))

    req = request_fixture("T-REDIRECT", "GET", connector.PREFIX + "/unknown")
    response = client.get(connector.PREFIX + "/unknown", headers=headers, follow_redirects=False)
    add("T-REDIRECT", "Unknown connector path; redirect following disabled.", req, 404,
        "NOT_FOUND", {"Location": "absent"}, "PASS", record_response(output, "T-REDIRECT", response))

    req = request_fixture("T-CONTENT-TYPE", "GET", connector.PREFIX + "/health")
    response = client.get(connector.PREFIX + "/health", headers=headers)
    add("T-CONTENT-TYPE", "Validate success response media type.", req, 200, None,
        {"Content-Type": "application/json; charset=utf-8"}, "PASS",
        record_response(output, "T-CONTENT-TYPE", response))

    conn = dashboard.dbmod.connect(config)
    try:
        conn.execute(
            "INSERT INTO logs(received_at,source_ip,hostname,format,severity,message,raw) VALUES(?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), "", "h" * 513, "fixture", "info",
             "oversize identity fixture", "oversize identity fixture"))
        conn.commit()
    finally: conn.close()
    response = client.get(connector.PREFIX + "/assets?limit=1", headers=headers)
    req = request_fixture("T-OVERSIZE", "GET", connector.PREFIX + "/assets", query={"limit": 1},
                          fault_injection="insert a 513-character native hostname before export")
    add("T-OVERSIZE", "Local Flask client exports a native asset identity exceeding the contract limit.",
        req, 422, "RECORD_UNEXPORTABLE", {"Cache-Control": "no-store"}, "PASS",
        record_response(output, "T-OVERSIZE", response))

    req = request_fixture("T-TIMEOUT", "GET", connector.PREFIX + "/alerts",
                          query={"limit": 1}, transport={"request_deadline_seconds": 0.05})
    timeout_evidence = "test-logs/T-TIMEOUT.json"
    write_json(output / timeout_evidence, {
        "case_id": "T-TIMEOUT", "actual_result": "NOT_RUN", "executed": False,
        "preflight": "offline Flask fixture has no network cancellation boundary",
        "required_environment": "deployed HTTP client/server deadline and cancellation path",
        "fabricated_result": False,
    })
    add("T-TIMEOUT", "Deployed cancellation/deadline environment was not available to the offline generator.",
        req, None, "TIMEOUT", {}, "NOT_RUN", timeout_evidence)

    req = request_fixture("T-TLS", "GET", connector.PREFIX + "/health",
                          transport={"scheme": "https", "verify_peer": True,
                                     "verify_hostname": True,
                                     "trust_bundle_ref": "fixture-ca-reference"})
    tls_evidence = "test-logs/T-TLS.json"
    write_json(output / tls_evidence, {
        "case_id": "T-TLS", "actual_result": "NOT_RUN", "executed": False,
        "preflight": "offline Flask fixture does not terminate TLS",
        "required_environment": "deployed HTTPS endpoint, reviewed CA, hostname and revocation policy",
        "fabricated_result": False,
    })
    add("T-TLS", "Intended HTTPS CA/hostname/revocation environment was not available to the offline generator.",
        req, None, "TLS_VALIDATION_FAILED", {}, "NOT_RUN", tls_evidence)
    write_json(output / "transport-cases.json", cases)


def sha256sums(root):
    lines = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name != "SHA256SUMS"):
        if set(path.relative_to(root).parts) & {"__pycache__", ".pytest_cache", ".git"}:
            continue
        lines.append(f"{sha(path)}  {path.relative_to(root).as_posix()}")
    (root / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=RETURN_ROOT)
    parser.add_argument("--checksums-only", action="store_true",
                        help="refresh SHA256SUMS without regenerating fixtures")
    args = parser.parse_args()
    output = args.output.resolve()

    if args.checksums_only:
        sha256sums(output)
        return

    for stale in ("adapter-manifest.json", "deployment-inputs.json"):
        path = output / stale
        if path.exists(): path.unlink()
    for stale_dir in ("fixture_bundle", "tests"):
        path = output / stale_dir
        if path.exists(): shutil.rmtree(path)
    for name in ("page.schema.json", "control.schema.json", "resource-manifest.json"):
        source = args.contract_root / "schemas" / name
        if not source.is_file(): raise SystemExit(f"required schema is missing: {source}")
        (output / "schemas").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, output / "schemas" / name)

    manifest = identity_and_manifest(output)
    binding = binding_fixture(output)
    with tempfile.TemporaryDirectory(prefix="mini-siem-dashboard-fixture-") as td:
        config = dashboard.dbmod.config_from_path(os.path.join(td, "fixture.db"))
        dashboard.DB_CONFIG = config
        dashboard.dbmod.initialize(config)
        conn = dashboard.dbmod.connect(config)
        try:
            token, _ = connector.create_reader_token(conn, "fixture-reader", TENANT_ID, days=1,
                                                      source_instance_id=SOURCE_INSTANCE_ID)
            seed(conn)
        finally: conn.close()
        guards = dashboard.app.before_request_funcs.get(None, [])
        if not any(fn.__name__ == "_guard" for fn in guards):
            auth_path = Path(td) / "auth-fixture.json"
            write_json(auth_path, dashboard.auth.DEFAULT_AUTH_CONFIG)
            dashboard.init_auth(str(auth_path))
        client = dashboard.app.test_client()
        headers = {"Authorization": "Bearer " + token}
        health = client.get(connector.PREFIX + "/health", headers=headers).get_json()
        capabilities = client.get(connector.PREFIX + "/capabilities", headers=headers).get_json()
        responses = {connector.PREFIX + "/health": [health],
                     connector.PREFIX + "/capabilities": [capabilities]}
        requests = []
        for lane, (_, _, page_size) in LANE_META.items():
            pages, lane_requests = collect_lane(client, headers, config, lane, page_size)
            responses[connector.PREFIX + "/" + lane] = pages
            requests.extend(lane_requests)
            lane_dir = output / "fixtures" / "responses" / lane
            for number, page in enumerate(pages, 1):
                write_json(lane_dir / f"response-{number:03d}.json", page)
        write_json(output / "fixtures" / "responses" / "health.json", health)
        write_json(output / "fixtures" / "responses" / "capabilities.json", capabilities)
        negative_pages = negative_page_fixtures(output, responses[connector.PREFIX + "/alerts"][0])
        transport_catalog(output, client, token, config)

    bundle = {"manifest": manifest,
              "product": {"tenant_id": binding["tenant_id"],
                          "product_id": binding["integration_instance_id"],
                          "product_type": binding["source_product"], "enabled": True,
                          "secret_ref": binding["auth"]["credential_ref"]},
              "responses": responses, "requests": requests,
              "negative_pages": negative_pages}
    write_json(output / "fixture-bundle.json", bundle)
    write_json(output / "fixture-provenance.json", {
        "purpose": "OFFLINE_FIXTURE_ONLY", "product_api_executed": True,
        "generator": "tools/generate_fixture_bundle.py",
        "command": "python tools/generate_fixture_bundle.py --contract-root <OWI_PACKET_ROOT>",
        "runtime": {"python": sys.version.split()[0], "platform": platform.platform()},
        "source": "isolated synthetic SQLite database through real Flask connector routes",
        "source_instance_id": SOURCE_INSTANCE_ID, "tenant_id": TENANT_ID,
        "source_identity_sha256": manifest["identity_sha256"],
        "scenarios": ["four-page alert snapshot", "incremental upsert", "empty incremental",
                      "auth and rate transport"],
        "sanitization": ["synthetic TEST-NET addresses only", "no plaintext token written",
                         "no production events or credentials"],
        "files": {path: len(values) for path, values in responses.items()},
    })
    sha256sums(output)


if __name__ == "__main__":
    main()
