"""Read-only operational diagnostics and support-bundle helpers.

This module deliberately contains no Flask, service-control, migration, archive
execution, or privilege-changing code.  It aggregates already-available health
signals and creates a bounded support bundle from an explicit allow-list.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import json
import os
import platform
import re
import subprocess
import tarfile
from typing import Any

STATUS_ORDER = {"HEALTHY": 0, "WARNING": 1, "DEGRADED": 2, "FAILED": 3, "UNKNOWN": 4}
_ALLOWED_STATUSES = set(STATUS_ORDER)
_SECRET_KEY_RE = re.compile(r"(password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)", re.I)
_SECRET_VALUE_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*([^\s,;]+)"
)
MAX_COMMAND_OUTPUT = 32 * 1024


def _status(value: Any, default: str = "UNKNOWN") -> str:
    text = str(value or default).upper()
    return text if text in _ALLOWED_STATUSES else default


def _component(name: str, status: str, reason: str = "", action: str = "", **extra) -> dict:
    out = {
        "name": name,
        "status": _status(status),
        "reason": str(reason or "")[:500],
        "recommended_action": str(action or "")[:500],
    }
    out.update(extra)
    return out


def _worst_status(statuses) -> str:
    values = [_status(x) for x in statuses]
    if not values:
        return "UNKNOWN"
    return max(values, key=lambda x: STATUS_ORDER.get(x, 99))


def build_diagnostics(health_snapshot: dict, postgres_status: dict | None = None,
                      archive_status: dict | None = None) -> dict:
    """Aggregate read-only health into an operator-oriented incident view."""
    health_snapshot = health_snapshot or {}
    runtime = health_snapshot.get("runtime") or {}
    siem = health_snapshot.get("siem") or {}
    pg = postgres_status or {}
    archive = archive_status or {}
    components = []

    db_state = str(runtime.get("database") or "UNKNOWN").upper()
    if db_state == "READY":
        components.append(_component("database", "HEALTHY", "Database runtime connection is ready."))
    elif db_state == "FAILED":
        components.append(_component("database", "FAILED", runtime.get("detail") or "Database runtime connection failed.",
                                     "Check database reachability and runtime credentials; do not grant DDL to runtime roles."))
    else:
        components.append(_component("database", "UNKNOWN", runtime.get("detail") or "Database readiness is not confirmed."))

    listener_state = str(runtime.get("listener") or "UNKNOWN").upper()
    if listener_state == "READY":
        components.append(_component("listener", "HEALTHY", "Listener heartbeat is current.",
                                     heartbeat_age_seconds=runtime.get("heartbeat_age_seconds")))
    elif listener_state == "STALE":
        components.append(_component("listener", "DEGRADED", runtime.get("detail") or "Listener heartbeat is stale.",
                                     "Check mini-siem-listener service state and its database connectivity.",
                                     heartbeat_age_seconds=runtime.get("heartbeat_age_seconds")))
    elif listener_state in {"FAILED", "DEGRADED"}:
        components.append(_component("listener", "FAILED" if listener_state == "FAILED" else "DEGRADED",
                                     runtime.get("detail") or f"Listener state is {listener_state}.",
                                     "Inspect mini-siem-listener service status and configured syslog ports."))
    elif listener_state == "STARTING":
        components.append(_component("listener", "WARNING", "Listener is still starting."))
    else:
        components.append(_component("listener", "UNKNOWN", runtime.get("detail") or "Listener heartbeat has not been recorded."))

    ingest_state = str(runtime.get("ingest") or "UNKNOWN").upper()
    failed = int(runtime.get("failed_events") or 0)
    dropped = int(runtime.get("dropped_events") or 0) + int(runtime.get("dropped_udp") or 0)
    if ingest_state == "RUNNING" and failed == 0 and dropped == 0:
        ingest_status = "HEALTHY"
        ingest_reason = "Ingest is running with no recorded failures or drops."
    elif ingest_state in {"RUNNING", "DEGRADED"}:
        ingest_status = "WARNING" if failed or dropped else "DEGRADED"
        ingest_reason = f"Ingest state={ingest_state}; failed={failed}; dropped={dropped}."
    elif ingest_state in {"FAILED", "STALE"}:
        ingest_status = "DEGRADED"
        ingest_reason = runtime.get("detail") or f"Ingest state is {ingest_state}."
    else:
        ingest_status = "UNKNOWN"
        ingest_reason = "Ingest state is not known."
    components.append(_component("ingest", ingest_status, ingest_reason,
                                 "Use Setup > Troubleshoot for a source-specific packet/storage check." if ingest_status != "HEALTHY" else "",
                                 processed_events=int(runtime.get("processed_events") or 0),
                                 failed_events=failed, dropped_events=dropped,
                                 last_event_at=runtime.get("last_event_at")))

    if pg.get("backend") == "postgres":
        if pg.get("status") == "ERROR":
            components.append(_component("postgres_security", "FAILED", pg.get("error") or "PostgreSQL security status failed.",
                                         "Check the dashboard database identity and privilege-boundary deployment."))
        elif pg.get("healthy") is True:
            components.append(_component("postgres_security", "HEALTHY", "Runtime PostgreSQL privilege boundary is enforced."))
        else:
            schema = pg.get("schema") or {}
            pending = schema.get("pending_versions") or []
            reason = "PostgreSQL runtime privilege or schema-readiness checks need attention."
            action = "Run the owner/migrator path and privilege checker outside the Web Console."
            if pending:
                reason = "Pending PostgreSQL migrations: " + ", ".join(str(x) for x in pending)
            components.append(_component("postgres_security", "WARNING", reason, action))
    else:
        components.append(_component("postgres_security", "HEALTHY", "PostgreSQL privilege checks are not applicable to the selected backend."))

    archive_state = str(archive.get("status") or "UNKNOWN").upper()
    if archive_state == "HEALTHY":
        components.append(_component("archive", "HEALTHY", "Archive/maintenance observability reports healthy."))
    elif archive_state == "WARNING":
        errors = archive.get("errors") or {}
        reason = errors.get("maintenance") or errors.get("archive") or "Archive verification or maintenance needs attention."
        components.append(_component("archive", "WARNING", reason,
                                     "Run archive maintenance/verification only with the dedicated maintenance identity."))
    elif archive_state == "ERROR":
        components.append(_component("archive", "DEGRADED", archive.get("error") or "Archive status could not be collected.",
                                     "Check archive catalog and maintenance tooling outside the Web Console."))
    else:
        components.append(_component("archive", "UNKNOWN", "Archive/maintenance state is not known."))

    udp = health_snapshot.get("udp") or {}
    syslog_status = "HEALTHY"
    syslog_reason = "No kernel UDP receive drops are currently reported."
    if udp.get("available") and int(udp.get("drops") or 0) > 0:
        syslog_status = "WARNING"
        syslog_reason = f"Kernel UDP receive drops={int(udp.get('drops') or 0)}."
    elif not udp.get("available"):
        syslog_status = "UNKNOWN"
        syslog_reason = "Kernel UDP receive counters are unavailable on this host."
    components.append(_component("syslog_socket", syslog_status, syslog_reason,
                                 "Check host receive buffers and sender/network path." if syslog_status == "WARNING" else ""))

    storage_count = int(siem.get("total_logs") or 0)
    components.append(_component("storage", "HEALTHY" if db_state == "READY" else "UNKNOWN",
                                 f"Stored events={storage_count}." if db_state == "READY" else "Storage health follows database readiness."))

    by_name = {c["name"]: c for c in components}
    dependencies = [
        {"name": "dashboard", "depends_on": ["database"], "status": by_name["database"]["status"]},
        {"name": "listener", "depends_on": ["database", "syslog_socket"],
         "status": _worst_status([by_name["listener"]["status"], by_name["database"]["status"], by_name["syslog_socket"]["status"]])},
        {"name": "ingest", "depends_on": ["listener", "storage"],
         "status": _worst_status([by_name["ingest"]["status"], by_name["listener"]["status"], by_name["storage"]["status"]])},
        {"name": "archive", "depends_on": ["database"],
         "status": _worst_status([by_name["archive"]["status"], by_name["database"]["status"]])},
    ]
    overall = _worst_status([c["status"] for c in components])
    # UNKNOWN must not hide a concrete failure/degradation/warning.
    concrete = [c["status"] for c in components if c["status"] != "UNKNOWN"]
    if concrete:
        overall = _worst_status(concrete)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall": overall,
        "components": components,
        "dependencies": dependencies,
        "read_only": True,
    }


def sanitize_mapping(value: Any) -> Any:
    """Recursively redact secret-looking keys/values for support artifacts."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if _SECRET_KEY_RE.search(str(key)):
                out[str(key)] = "<redacted>"
            else:
                out[str(key)] = sanitize_mapping(item)
        return out
    if isinstance(value, list):
        return [sanitize_mapping(x) for x in value]
    if isinstance(value, tuple):
        return [sanitize_mapping(x) for x in value]
    if isinstance(value, str):
        return _SECRET_VALUE_RE.sub(lambda m: f"{m.group(1)}=<redacted>", value)
    return value


def safe_config_summary(cfg: dict) -> dict:
    cfg = cfg or {}
    backend = str(cfg.get("backend") or "sqlite")
    out = {
        "backend": backend,
        "listen_ports": list(cfg.get("listen_ports") or [514]),
        "postgres_privilege_boundary": sanitize_mapping(cfg.get("postgres_privilege_boundary") or {}),
    }
    if backend == "sqlite":
        sqlite_cfg = cfg.get("sqlite") or {}
        out["sqlite"] = {"path_basename": os.path.basename(str(sqlite_cfg.get("path") or "siem.db"))}
    elif backend == "postgres":
        pg = cfg.get("postgres") or {}
        # Deliberately exclude username/password and exact host/database identifiers.
        out["postgres"] = {
            "port": int(pg.get("port") or 5432),
            "sslmode": str(pg.get("sslmode") or "prefer"),
            "host_configured": bool(pg.get("host")),
            "database_configured": bool(pg.get("dbname")),
        }
    return out


def _run_bounded(args: list[str], timeout: float = 3.0) -> str:
    """Run one fixed argv command without a shell and cap its output."""
    try:
        cp = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False,
                            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"})
        text = (cp.stdout or "") + (("\n" + cp.stderr) if cp.stderr else "")
        text = _SECRET_VALUE_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text)
        if len(text) > MAX_COMMAND_OUTPUT:
            text = text[:MAX_COMMAND_OUTPUT] + "\n[truncated]\n"
        return text.strip() or f"command exited rc={cp.returncode} with no output"
    except FileNotFoundError:
        return f"{args[0]} is not installed"
    except subprocess.TimeoutExpired:
        return f"{args[0]} timed out after {timeout}s"
    except Exception as exc:
        return f"{args[0]} failed: {type(exc).__name__}"


def service_status_text() -> str:
    """Collect non-secret systemd state only; never service command lines or env."""
    sections = []
    for unit in ("mini-siem-listener.service", "mini-siem-dashboard.service"):
        text = _run_bounded([
            "systemctl", "show", unit, "--no-pager",
            "--property=Id,LoadState,ActiveState,SubState,UnitFileState,Result,ExecMainStatus,NRestarts,ActiveEnterTimestamp"
        ])
        sections.append(f"[{unit}]\n{text}")
    return "\n\n".join(sections) + "\n"


def journal_tail_text() -> str:
    """Intentionally omit raw listener/dashboard journals from support bundles.

    Listener stdout can contain event-message excerpts.  Returning those would
    violate the support-bundle invariant that raw event payloads are excluded.
    """
    return (
        "Journal tail intentionally omitted. mini-SIEM service journals can contain "
        "raw event/message excerpts. Use host-local journalctl under the normal "
        "operator access policy when deeper log review is required.\n"
    )


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(sanitize_mapping(value), indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def build_support_bundle(health_snapshot: dict, diagnostics: dict, postgres_status: dict,
                         archive_status: dict, cfg: dict, version_info: dict | None = None,
                         extra_files: dict[str, str | bytes] | None = None) -> tuple[bytes, dict]:
    """Build an in-memory .tar.gz from a fixed allow-list of sanitized data."""
    entries: dict[str, bytes] = {
        "health.json": _json_bytes(health_snapshot),
        "diagnostics.json": _json_bytes(diagnostics),
        "postgres_status.json": _json_bytes(postgres_status),
        "archive_status.json": _json_bytes(archive_status),
        "config_summary.json": _json_bytes(safe_config_summary(cfg)),
        "version.json": _json_bytes(version_info or {}),
        "service_status.txt": service_status_text().encode("utf-8"),
        "journal_tail.txt": journal_tail_text().encode("utf-8"),
    }
    for name, content in (extra_files or {}).items():
        if name not in {"schema_status.json", "runtime_status.json", "security_boundary_status.json"}:
            continue
        data = content if isinstance(content, bytes) else str(content).encode("utf-8")
        entries[name] = data[:128 * 1024]

    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "hostname": platform.node(),
        "contains_raw_events": False,
        "contains_credentials": False,
        "files": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in sorted(entries.items())},
    }
    entries["manifest.json"] = _json_bytes(manifest)

    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz", format=tarfile.PAX_FORMAT) as tf:
        for name in sorted(entries):
            data = entries[name]
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o600
            info.mtime = int(datetime.now(timezone.utc).timestamp())
            tf.addfile(info, io.BytesIO(data))
    return out.getvalue(), manifest
