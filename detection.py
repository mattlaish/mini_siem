"""Validated, data-only detection configuration and process monitoring.

Configuration, bounded replay state and audit use existing application tables.
No runtime DDL, second evidence store, Python expressions or user regexes.
"""
import copy
import fnmatch
import hashlib
import json
import ntpath
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from windows_events import basename, timestamp

CONFIG_KEY = "detection_config_v1"
STATE_KEY = "detection_replay_v1"
EVIDENCE_MARKER = "\n\nDetection evidence: "
SHELLS = ["cmd.exe", "powershell.exe", "pwsh.exe"]
SEVERITIES = {"critical", "error", "warning", "notice", "informational"}
CONDITION_FIELDS = {
    "event.id", "event.kind", "event.provider", "event.channel", "host.name",
    "process.path", "process.name", "process.parent.path", "process.parent.name",
    "process.command_line", "user.name", "user.creator.sid", "user.target.sid", "script.text",
}
BUILTINS = {
    "ssh_bruteforce": {"threshold": 5, "window_seconds": 60, "severity": "critical"},
    "firewall_deny_burst": {"threshold": 20, "window_seconds": 60, "severity": "warning"},
    "repeated_login_failures": {"threshold": 8, "window_seconds": 120, "severity": "warning"},
    "nxlog_severity_event": {"severity": "warning"},
    "high_severity_event": {"severity": "critical"},
}


def defaults():
    rules = [{"id": k, "name": k.replace("_", " ").title(), "kind": "builtin", "enabled": True, **v}
             for k, v in BUILTINS.items()]
    rules += [
        {"id": "web_server_shell", "name": "Web server spawning shell", "kind": "web_shell", "enabled": True,
         "severity": "critical", "children": SHELLS[:], "parents": ["tomcat7.exe", "w3wp.exe"],
         "scoped_parents": ["java.exe", "httpd.exe"], "required_role": "web_server"},
        {"id": "out_of_hours_shell", "name": "Out-of-hours shell execution", "kind": "out_of_hours",
         "enabled": True, "severity": "error", "children": SHELLS[:]},
    ]
    return {"revision": 0, "rules": rules, "hosts": [], "schedules": [], "exceptions": []}


def _list(value, label, limit):
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(f"{label} must be a list of at most {limit} entries")
    return value


def _strings(value, label, limit=100):
    values = _list(value, label, limit)
    if any(not isinstance(v, str) or not v.strip() or len(v) > 1024 for v in values):
        raise ValueError(f"{label} must contain non-empty strings (max 1024 characters)")
    return values


def _int(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{label} must be an integer from {low} to {high}")


def _zone(name):
    if not isinstance(name, str) or len(name) > 100:
        raise ValueError("timezone must be an IANA timezone")
    try:
        ZoneInfo(name)
    except (KeyError, ValueError):
        raise ValueError(f"Unknown IANA timezone: {name}") from None


def _id(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 80 or not all(c.isascii() and (c.isalnum() or c in "_-") for c in value):
        raise ValueError("IDs must be 1-80 ASCII letters, digits, underscores or hyphens")


def _minute(value):
    if not isinstance(value, str) or len(value) != 5 or value[2] != ":":
        raise ValueError("Time must be HH:MM")
    try:
        h, m = map(int, value.split(":"))
    except ValueError:
        raise ValueError("Time must be HH:MM") from None
    if not 0 <= h < 24 or not 0 <= m < 60:
        raise ValueError("Invalid clock time")
    return h * 60 + m


def validate_config(config):
    if not isinstance(config, dict) or len(json.dumps(config)) > 256000:
        raise ValueError("Configuration must be an object under 256 KB")
    if set(config) - {"revision", "rules", "hosts", "schedules", "exceptions", "updated_at", "updated_by"}:
        raise ValueError("Unknown configuration section")
    _int(config.get("revision"), 0, 2**31 - 1, "revision")
    collections = {k: _list(config.get(k), k, n) for k, n in
                   (("rules", 100), ("hosts", 200), ("schedules", 200), ("exceptions", 300))}
    for name, entries in collections.items():
        ids = set()
        for row in entries:
            if not isinstance(row, dict):
                raise ValueError(f"{name} entries must be objects")
            key = row.get("hostname") if name == "hosts" else row.get("id")
            if name == "hosts":
                _strings([key], "hostname", 1)
                if any(c in key for c in "*?[]"):
                    raise ValueError("Host profiles use exact hostnames; use groups for collections")
            else:
                _id(key)
            if key.casefold() in ids:
                raise ValueError(f"Duplicate {name} identity: {key}")
            ids.add(key.casefold())
    rules = {r["id"]: r for r in config["rules"]}
    if not BUILTINS.keys() <= rules.keys() or not {"web_server_shell", "out_of_hours_shell"} <= rules.keys():
        raise ValueError("Keep built-in rule entries; disable instead of deleting them")
    for rule in config["rules"]:
        kind = rule.get("kind")
        if type(rule.get("enabled")) is not bool or rule.get("severity") not in SEVERITIES:
            raise ValueError("Rule enabled must be boolean and severity must be supported")
        _strings([rule.get("name")], "rule name", 1)
        if rule["id"] in BUILTINS:
            if kind != "builtin":
                raise ValueError("Built-in rule kind cannot change")
            if rule["id"] == "nxlog_severity_event" and rule["severity"] != "warning":
                raise ValueError("NXLog severity trigger preserves each source event severity")
            if "threshold" in BUILTINS[rule["id"]]:
                _int(rule.get("threshold"), 1, 10000, "threshold")
                _int(rule.get("window_seconds"), 1, 86400, "window_seconds")
        elif rule["id"] == "web_server_shell":
            if kind != "web_shell" or rule["severity"] != "critical":
                raise ValueError("Web server shell rule must remain critical/web_shell")
            for field in ("children", "parents", "scoped_parents"):
                _strings(rule.get(field), field)
            if any(basename(p) in {"java.exe", "httpd.exe"} for p in rule["parents"]):
                raise ValueError("java.exe/httpd.exe require a scoped host role")
            _strings([rule.get("required_role")], "required role", 1)
        elif rule["id"] == "out_of_hours_shell":
            if kind != "out_of_hours":
                raise ValueError("Out-of-hours rule kind cannot change")
            _strings(rule.get("children"), "children")
        elif kind == "match":
            conditions = _list(rule.get("conditions"), "conditions", 12)
            if not conditions:
                raise ValueError("Custom rules need at least one condition")
            for c in conditions:
                if not isinstance(c, dict) or set(c) != {"field", "op", "value"} or c["field"] not in CONDITION_FIELDS or c["op"] not in {"equals", "contains", "glob"}:
                    raise ValueError("Unsupported condition field/operator")
                _strings([c["value"]], "condition value", 1)
        else:
            raise ValueError("Only data-only match rules can be created")
    schedule_ids = {s["id"] for s in config["schedules"]}
    for host in config["hosts"]:
        _zone(host.get("timezone"))
        if type(host.get("telemetry_enabled", False)) is not bool:
            raise ValueError("telemetry_enabled must be boolean")
        _strings(host.get("groups", []), "host groups")
        _strings(host.get("roles", []), "host roles")
        if host.get("telemetry_enabled", False):
            if type(host["telemetry_enabled"]) is not bool:
                raise ValueError("telemetry_enabled must be boolean")
            _int(host.get("max_silence_seconds"), 60, 604800, "max_silence_seconds")
            sources = _strings(host.get("expected_sources", ["security_4688"]), "expected_sources", 3)
            if not sources or set(sources) - {"security_4688", "sysmon_1", "powershell_4104"}:
                raise ValueError("Unsupported expected telemetry source")
    for schedule in config["schedules"]:
        if type(schedule.get("exception_only", False)) is not bool:
            raise ValueError("exception_only must be boolean")
        _strings([schedule.get("name")], "schedule name", 1)
        _zone(schedule.get("timezone"))
        days = _list(schedule.get("weekdays"), "weekdays", 7)
        if (not days and not schedule.get("dates")) or any(type(d) is not int or not 0 <= d <= 6 for d in days):
            raise ValueError("weekdays must contain Monday=0 through Sunday=6")
        if _minute(schedule.get("start")) == _minute(schedule.get("end")):
            raise ValueError("Start and end must differ (end is exclusive)")
        _strings(schedule.get("hosts", []), "schedule hosts")
        _strings(schedule.get("groups", []), "schedule groups")
        if not schedule.get("hosts") and not schedule.get("groups"):
            raise ValueError("Schedules must target hosts or groups")
        for key in ("dates", "exclude_dates"):
            for date in _strings(schedule.get(key, []), key):
                try:
                    datetime.strptime(date, "%Y-%m-%d")
                except ValueError:
                    raise ValueError("Dates must be YYYY-MM-DD") from None
    for exc in config["exceptions"]:
        if exc.get("rule_id") not in rules or exc["rule_id"] == "web_server_shell":
            raise ValueError("Exceptions need a specific rule; web-server shell cannot be exempted")
        for key in ("hosts", "groups"):
            _strings(exc.get(key, []), key)
        if not exc.get("hosts") and not exc.get("groups"):
            raise ValueError("Exceptions must target a host or group")
        for key in ("process_path", "parent_path", "command_glob", "user", "approved_by", "ticket"):
            _strings([exc.get(key)], key, 1)
        if any(exc[k].strip() in {"*", "**", "?"} for k in ("process_path", "parent_path", "command_glob", "user")):
            raise ValueError("Blanket exception patterns are prohibited")
        if any(c in exc[k] for k in ("process_path", "parent_path", "user") for c in "*?[]"):
            raise ValueError("Executable, parent and account must be exact; glob is allowed only for the command line")
        if any(not ntpath.isabs(exc[k]) for k in ("process_path", "parent_path")):
            raise ValueError("Exception executable and parent must use full paths")
        if exc.get("schedule_id") not in schedule_ids:
            raise ValueError("Exception must reference an existing schedule")
        expiry = timestamp(exc.get("expires_at"))
        if not expiry:
            raise ValueError("Exception expiry requires an explicit UTC offset")
    return copy.deepcopy(config)


def load_config(conn):
    row = conn.execute("SELECT value FROM app_config WHERE key=?", (CONFIG_KEY,)).fetchone()
    return validate_config(json.loads(row["value"])) if row else defaults()


class ConfigConflict(ValueError):
    pass


def _locked_json(conn, key, initial):
    conn.execute("INSERT INTO app_config(key,value) VALUES(?,?) ON CONFLICT(key) DO NOTHING", (key, json.dumps(initial)))
    # The insert acquires SQLite's writer lock. PostgreSQL needs an explicit
    # row lock to serialize independent listener/dashboard processes.
    suffix = " FOR UPDATE" if getattr(conn, "backend", "sqlite") == "postgres" else ""
    row = conn.execute("SELECT value FROM app_config WHERE key=?" + suffix, (key,)).fetchone()
    return json.loads(row["value"])


def save_config(conn, incoming, actor, source_ip=""):
    clean = validate_config(incoming)
    try:
        previous = _locked_json(conn, CONFIG_KEY, defaults())
        if previous["revision"] != clean["revision"]:
            raise ConfigConflict("Configuration changed; reload before saving")
        clean["revision"] += 1
        clean["updated_at"] = datetime.now(timezone.utc).isoformat()
        clean["updated_by"] = actor
        old_exceptions = {e["id"]: e for e in previous["exceptions"]}
        for exc in clean["exceptions"]:
            if exc != old_exceptions.get(exc["id"]):
                exc["approved_by"] = actor
        conn.execute("UPDATE app_config SET value=? WHERE key=?", (json.dumps(clean), CONFIG_KEY))
        # Full before/after, committed with the change. Existing audit() is
        # best-effort and truncates detail at 500 characters, so use this path.
        conn.execute("INSERT INTO audit_log(at,username,source_ip,action,target,detail) VALUES(?,?,?,?,?,?)",
                     (clean["updated_at"], actor, source_ip, "detection_config_changed", CONFIG_KEY,
                      json.dumps({"before": previous, "after": clean})))
        conn.commit()
        return clean
    except Exception:
        conn.rollback()
        raise


def profile_for(config, fields):
    host = fields.get("host.name", "").casefold()
    return next((h for h in config["hosts"] if h["hostname"].casefold() == host), {})


def targeted(row, fields, host):
    name = fields.get("host.name", "").casefold()
    return name in {h.casefold() for h in row.get("hosts", [])} or bool(
        {g.casefold() for g in host.get("groups", [])} & {g.casefold() for g in row.get("groups", [])})


def in_window(schedule, dt):
    local = dt.astimezone(ZoneInfo(schedule["timezone"]))
    minute = local.hour * 60 + local.minute
    start, end = _minute(schedule["start"]), _minute(schedule["end"])
    anchor = local.date()
    if start < end:
        if not start <= minute < end:
            return False
    elif minute >= start:
        pass
    elif minute < end:
        anchor -= timedelta(days=1)
    else:
        return False
    if anchor.isoformat() in schedule.get("exclude_dates", []) or local.date().isoformat() in schedule.get("exclude_dates", []):
        return False
    return (anchor.weekday() in schedule["weekdays"] or anchor.isoformat() in schedule.get("dates", []))


def _matches(condition, fields):
    actual = str(fields.get(condition["field"], "")).casefold()
    wanted = condition["value"].casefold()
    return {"equals": lambda: actual == wanted, "contains": lambda: wanted in actual,
            "glob": lambda: fnmatch.fnmatchcase(actual[:65536], wanted)}[condition["op"]]()


def exception_for(config, rule_id, fields, host, dt, now):
    for exc in config["exceptions"]:
        expiry = timestamp(exc["expires_at"])
        if exc["rule_id"] != rule_id or now >= expiry or not dt or dt >= expiry or not targeted(exc, fields, host):
            continue
        schedule = next(s for s in config["schedules"] if s["id"] == exc["schedule_id"])
        checks = {"process.path": exc["process_path"], "process.parent.path": exc["parent_path"],
                  "process.command_line": exc["command_glob"], "user.name": exc["user"]}
        if targeted(schedule, fields, host) and in_window(schedule, dt) and all(
            fnmatch.fnmatchcase(fields.get(k, "").casefold(), v.casefold()) for k, v in checks.items()):
            return exc["id"]
    return None


def evaluate(config, fields, now=None):
    """Pure evaluator used by live ingest and the no-side-effect simulator."""
    now = now or datetime.now(timezone.utc)
    host = profile_for(config, fields)
    dt = timestamp(fields.get("event.time"), host.get("timezone"))
    findings, suppressed = [], []
    schedules = [s for s in config["schedules"] if not s.get("exception_only") and targeted(s, fields, host)]
    for rule in config["rules"]:
        if not rule["enabled"] or rule["kind"] == "builtin":
            continue
        name, parent = fields.get("process.name"), fields.get("process.parent.name")
        process = fields.get("event.kind") == "process_creation"
        match, reason = False, ""
        if rule["kind"] == "web_shell":
            parents = {basename(v) for v in rule["parents"]}
            scoped = {basename(v) for v in rule["scoped_parents"]}
            roles = {r.casefold() for r in host.get("roles", [])}
            match = process and name in {basename(v) for v in rule["children"]} and (
                parent in parents or (parent in scoped and rule["required_role"].casefold() in roles))
            reason = "Web server parent launched a command shell; applies at every hour"
        elif rule["kind"] == "out_of_hours":
            match = process and name in {basename(v) for v in rule["children"]} and bool(schedules) and dt is not None and not any(in_window(s, dt) for s in schedules)
            reason = "Shell execution is outside the host/group approved windows"
        elif rule["kind"] == "match":
            match = bool(fields) and all(_matches(c, fields) for c in rule["conditions"])
            reason = "All configured normalized-field conditions matched"
        if not match:
            continue
        exc = exception_for(config, rule["id"], fields, host, dt, now)
        if exc:
            suppressed.append({"rule_id": rule["id"], "exception_id": exc})
            continue
        findings.append({"rule_id": rule["id"], "severity": rule["severity"], "reason": reason,
                         "config_revision": config["revision"], "fields": dict(fields),
                         "event_time_utc": dt.isoformat() if dt else None})
    return {"findings": findings, "suppressed": suppressed,
            "time_status": "valid" if dt else "unknown: supply an offset or host timezone",
            "schedule_status": "configured" if schedules else "unconfigured: out-of-hours evaluation skipped"}


def _fingerprint(finding):
    f = finding["fields"]
    # Cross-source process identity needs host+PID+path+parent plus a close
    # event-time comparison. GUID is extra evidence, never a required field
    # because Security 4688 has no GUID. Missing identity fails to no-dedup.
    keys = [f.get(k, "").casefold() for k in ("host.name", "process.pid", "process.path", "process.parent.pid")]
    if f.get("event.kind") != "process_creation" or not all(keys) or not finding.get("event_time_utc"):
        return None
    keys += [finding["rule_id"], str(finding["config_revision"]), f.get("process.command_line", "").casefold()]
    return hashlib.sha256(json.dumps(keys).encode()).hexdigest()


def emit(conn, finding, log_id, source_ip):
    """Serialize duplicate suppression and evidence linking in one transaction.

    Caller owns the Storage lock. Bound references to 500 per alert and 512
    recent identities; all original events remain in logs/archive.
    """
    state = _locked_json(conn, STATE_KEY, {})
    now = datetime.now(timezone.utc)
    state = {k: v for k, v in state.items() if timestamp(v["seen_at"]) and (now - timestamp(v["seen_at"])).total_seconds() < 300}
    key = _fingerprint(finding)
    previous = state.get(key) if key else None
    old = None
    if previous and abs((timestamp(finding["event_time_utc"]) - timestamp(previous["event_time"])).total_seconds()) <= 2:
        old = conn.execute("SELECT id,description,log_ids,workflow_status FROM alerts WHERE id=?", (previous["alert_id"],)).fetchone()
        if old and old["workflow_status"] in {"resolved", "closed"}:
            old = None
    evidence = {**finding, "fields": {k: str(v)[:16384] for k, v in finding["fields"].items()},
                "field_preview_limit": 16384, "occurrences": 1, "first_seen": now.isoformat(), "last_seen": now.isoformat()}
    ids = [log_id]
    if old:
        evidence = json.loads(old["description"].split(EVIDENCE_MARKER, 1)[1])
        evidence["occurrences"] += 1
        evidence["last_seen"] = now.isoformat()
        evidence["sources"] = sorted(set(evidence.get("sources", [])) | {finding["fields"].get("event.provider", "")})
        ids = list(dict.fromkeys([int(i) for i in old["log_ids"].split(",") if i] + [log_id]))[-500:]
        alert_id = old["id"]
    else:
        evidence["sources"] = [finding["fields"].get("event.provider", "")]
        alert_id = conn.insert_returning_id("INSERT INTO alerts(created_at,rule_name,severity,source_ip,description,log_ids) VALUES(?,?,?,?,?,?)",
                                           (now.isoformat(), finding["rule_id"], finding["severity"], source_ip, "", str(log_id)))
    f = finding["fields"]
    summary = f"{finding['reason']}: {f.get('host.name', 'unknown')} | {f.get('process.parent.name', '')} -> {f.get('process.name', '')}"
    evidence["evidence_reference_limit"] = 500
    conn.execute("UPDATE alerts SET description=?,log_ids=? WHERE id=?",
                 (summary + EVIDENCE_MARKER + json.dumps(evidence), ",".join(map(str, ids)), alert_id))
    if key:
        state[key] = {"alert_id": alert_id, "event_time": finding["event_time_utc"], "seen_at": now.isoformat()}
    state = dict(sorted(state.items(), key=lambda kv: kv[1]["seen_at"])[-512:])
    conn.execute("UPDATE app_config SET value=? WHERE key=?", (json.dumps(state), STATE_KEY))
    conn.commit()
    return alert_id


def describe_alert(row):
    text = row.get("description") or ""
    if EVIDENCE_MARKER in text:
        summary, payload = text.split(EVIDENCE_MARKER, 1)
        try:
            row["detection_evidence"] = json.loads(payload)
            row["description"] = summary
        except ValueError:
            pass
    return row
