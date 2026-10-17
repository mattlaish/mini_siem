"""Validated, data-only detection configuration and process monitoring.

Configuration, bounded replay state and audit use existing application tables.
No runtime DDL, second evidence store, Python expressions or user regexes.
"""
import copy
import fnmatch
import hashlib
import json
import ntpath
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from windows_events import basename, find_host_profile, host_matches, timestamp

CONFIG_KEY = "detection_config_v1"
STATE_KEY = "detection_replay_v1"
EVIDENCE_MARKER = "\n\nDetection evidence: "
SHELLS = ["cmd.exe", "powershell.exe", "pwsh.exe"]
# Tomcat 8+ installs as a Windows service named tomcatN.exe (procrun hosts the
# JVM in-process), so tomcat7.exe alone misses every modern Tomcat service.
WEB_SHELL_PARENTS = ["tomcat7.exe", "tomcat8.exe", "tomcat9.exe", "tomcat10.exe", "tomcat11.exe",
                     "w3wp.exe", "php-cgi.exe"]
# Used only in "listed" child mode. The default "any" mode alerts on every
# process a web server launches, because an attacker can run any binary
# (renamed, dropped or living-off-the-land); a fixed tool list only catches
# the tools of the last incident.
WEB_SHELL_CHILDREN = SHELLS + ["whoami.exe", "net.exe", "net1.exe", "nltest.exe", "systeminfo.exe",
                               "certutil.exe", "bitsadmin.exe", "rundll32.exe", "regsvr32.exe",
                               "mshta.exe", "wscript.exe", "cscript.exe", "wmic.exe", "bash.exe"]
# Children IIS / ASP.NET / PHP-FastCGI / Apache start during normal operation.
# Children re-launching the parent's own binary (Apache and PHP-FastCGI
# workers) are excluded by path in the evaluator, not by name.
WEB_SHELL_EXCLUDED = ["conhost.exe", "csc.exe", "cvtres.exe", "vbc.exe", "werfault.exe", "wermgr.exe",
                      "php-cgi.exe", "rotatelogs.exe"]
CHILD_MATCH_MODES = {"any", "listed"}
WINDOWS_KINDS = {"process_creation", "script_execution"}
MATCH_SCOPES = {"windows", "all"}
# Fields every ingested event has, for all-events match rules.
GENERIC_FIELDS = {"message", "source.ip", "event.severity", "app.name", "log.format"}
# Extracted key/value fields (key=value, JSON keys, custom patterns) as field.<name>.
EXTRACTED_FIELD = re.compile(r"^field\.[A-Za-z0-9_.@-]{1,64}$")
# Exceptions match Windows process fields, so they can only apply to rules
# evaluated on Windows process events (web_server_shell is never exemptable).
EXCEPTION_RULES = {"out_of_hours_shell", "nxlog_severity_event", "high_severity_event"}
TRANSIENT_KEYS = {"load_warning"}
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
        {"id": "web_server_shell", "name": "Web server launched a process", "kind": "web_shell", "enabled": True,
         "severity": "critical", "child_match": "any", "excluded_children": WEB_SHELL_EXCLUDED[:],
         "children": WEB_SHELL_CHILDREN[:], "parents": WEB_SHELL_PARENTS[:],
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


def validate_config(config, strict=False):
    """Validate a configuration. ``strict`` adds checks introduced after
    configurations were first saved; it applies to new saves only, so a
    tightened rule never makes an already-stored configuration unloadable."""
    if not isinstance(config, dict) or len(json.dumps(config)) > 256000:
        raise ValueError("Configuration must be an object under 256 KB")
    config = {k: v for k, v in config.items() if k not in TRANSIENT_KEYS}
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
            _strings(rule.get("excluded_children", []), "excluded_children")
            if rule.get("child_match", "listed") not in CHILD_MATCH_MODES:
                raise ValueError("child_match must be 'any' or 'listed'")
            if rule.get("child_match", "listed") == "listed" and not rule["children"]:
                raise ValueError("Listed child mode needs at least one child process")
            if any(basename(p) in {"java.exe", "httpd.exe"} for p in rule["parents"]):
                raise ValueError("java.exe/httpd.exe require a scoped host role")
            _strings([rule.get("required_role")], "required role", 1)
        elif rule["id"] == "out_of_hours_shell":
            if kind != "out_of_hours":
                raise ValueError("Out-of-hours rule kind cannot change")
            _strings(rule.get("children"), "children")
        elif kind == "match":
            if rule.get("scope", "windows") not in MATCH_SCOPES:
                raise ValueError("Custom rule scope must be 'windows' or 'all'")
            conditions = _list(rule.get("conditions"), "conditions", 12)
            if not conditions:
                raise ValueError("Custom rules need at least one condition")
            for c in conditions:
                if (not isinstance(c, dict) or set(c) != {"field", "op", "value"}
                        or not isinstance(c["field"], str) or c["op"] not in {"equals", "contains", "glob"}
                        or not (c["field"] in CONDITION_FIELDS or c["field"] in GENERIC_FIELDS
                                or EXTRACTED_FIELD.match(c["field"]))):
                    raise ValueError("Unsupported condition field/operator (use a listed field or field.<name>)")
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
        if strict:
            target = rules[exc["rule_id"]]
            if not (exc["rule_id"] in EXCEPTION_RULES
                    or (target.get("kind") == "match" and target.get("scope", "windows") == "windows")):
                raise ValueError(f"Exception {exc.get('id')}: exceptions match Windows process fields and "
                                 f"cannot apply to rule {exc['rule_id']}")
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


def migrate_config(stored):
    """Bring a configuration saved by an older release up to the current
    schema without changing operator choices: missing sections become empty
    and built-in rules added by a later release arrive with their defaults."""
    if not isinstance(stored, dict):
        raise ValueError("Stored detection configuration is not an object")
    cfg = copy.deepcopy(stored)
    cfg.setdefault("revision", 0)
    for section in ("rules", "hosts", "schedules", "exceptions"):
        cfg.setdefault(section, [])
    if isinstance(cfg["rules"], list):
        existing = {r.get("id"): r for r in cfg["rules"] if isinstance(r, dict)}
        for rule in defaults()["rules"]:
            current = existing.get(rule["id"])
            if current is None:
                cfg["rules"].append(rule)
            else:
                if rule["id"] == "web_server_shell":
                    # Saved before child modes existed: it was an explicit child list.
                    current.setdefault("child_match", "listed")
                    current.setdefault("excluded_children", [])
                for key, value in rule.items():
                    current.setdefault(key, copy.deepcopy(value))
    return cfg


def load_config(conn):
    row = conn.execute("SELECT value FROM app_config WHERE key=?", (CONFIG_KEY,)).fetchone()
    return validate_config(migrate_config(json.loads(row["value"]))) if row else defaults()


def load_config_or_fallback(conn):
    """Return (config, warning) and never raise for bad stored content.

    A stored configuration that cannot be migrated is replaced in memory by
    the defaults carrying the stored revision, so an administrator can review
    and save over it. The rejected copy stays in app_config until then and
    every earlier revision is recorded in audit_log.
    """
    try:
        return load_config(conn), None
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        fallback = defaults()
        try:
            row = conn.execute("SELECT value FROM app_config WHERE key=?", (CONFIG_KEY,)).fetchone()
            revision = json.loads(row["value"]).get("revision") if row else 0
            if type(revision) is int and revision >= 0:
                fallback["revision"] = revision
        except (ValueError, TypeError, KeyError, AttributeError):
            pass
        return fallback, (f"Stored detection configuration was rejected ({exc}). Showing defaults; "
                          "saving replaces the stored copy. Earlier revisions are in the audit log.")


class ConfigConflict(ValueError):
    pass


def _locked_json(conn, key, initial):
    conn.execute("INSERT INTO app_config(key,value) VALUES(?,?) ON CONFLICT(key) DO NOTHING", (key, json.dumps(initial)))
    # The insert acquires SQLite's writer lock. PostgreSQL needs an explicit
    # row lock to serialize independent listener/dashboard processes.
    if getattr(conn, "backend", "sqlite") == "postgres":
        row = conn.execute("SELECT value FROM app_config WHERE key=? FOR UPDATE", (key,)).fetchone()
    else:
        row = conn.execute("SELECT value FROM app_config WHERE key=?", (key,)).fetchone()
    try:
        value = json.loads(row["value"])
    except (TypeError, ValueError):
        value = None
    # A corrupt state row must not wedge every later write; start it afresh.
    return value if isinstance(value, dict) else copy.deepcopy(initial)


def save_config(conn, incoming, actor, source_ip=""):
    clean = validate_config(incoming, strict=True)
    try:
        previous = _locked_json(conn, CONFIG_KEY, defaults())
        if previous.get("revision", 0) != clean["revision"]:
            raise ConfigConflict("Configuration changed; reload before saving")
        clean["revision"] += 1
        clean["updated_at"] = datetime.now(timezone.utc).isoformat()
        clean["updated_by"] = actor
        old_exceptions = {e.get("id"): e for e in previous.get("exceptions") or [] if isinstance(e, dict)}
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
    return find_host_profile(config["hosts"], fields.get("host.name", ""))


def targeted(row, fields, host):
    name = fields.get("host.name", "")
    return any(host_matches(h, name) for h in row.get("hosts", [])) or bool(
        {g.casefold() for g in host.get("groups", [])} & {g.casefold() for g in row.get("groups", [])})


def generic_fields(event, extracted=None):
    """Fields every ingested event has, plus extracted key/value fields as
    field.<name>, for all-events match rules. Windows canonical fields are
    layered on top by the caller."""
    out = {"host.name": event.get("hostname"), "message": event.get("message"),
           "source.ip": event.get("source_ip"), "event.severity": event.get("severity"),
           "app.name": event.get("app_name"), "log.format": event.get("format")}
    for key, value in (extracted or {}).items():
        name = "field." + str(key).casefold()
        if EXTRACTED_FIELD.match(name):
            out[name] = value
    return {k: str(v)[:65536] for k, v in out.items() if v not in (None, "")}


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
    key = condition["field"]
    if key.startswith("field."):
        key = key.casefold()
    actual = str(fields.get(key, "")).casefold()
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
    windows = fields.get("event.kind") in WINDOWS_KINDS
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
            any_child = rule.get("child_match", "listed") == "any"
            excluded = {basename(v) for v in rule.get("excluded_children", [])}
            path, parent_path = fields.get("process.path", ""), fields.get("process.parent.path", "")
            # A worker re-launching the parent's own binary (Apache, PHP-FastCGI)
            # is normal; compare full paths so a renamed lookalike still alerts.
            same_binary = bool(path) and path.strip('"').casefold() == parent_path.strip('"').casefold()
            child_ok = bool(name) if any_child else name in {basename(v) for v in rule["children"]}
            match = process and child_ok and name not in excluded and not same_binary and (
                parent in parents or (parent in scoped and rule["required_role"].casefold() in roles))
            reason = ("Web server process launched a child process that is not an approved web-server child; "
                      "applies at every hour") if any_child else \
                "Web server parent launched a listed shell or tool; applies at every hour"
        elif rule["kind"] == "out_of_hours":
            match = process and name in {basename(v) for v in rule["children"]} and bool(schedules) and dt is not None and not any(in_window(s, dt) for s in schedules)
            reason = "Shell execution is outside the host/group approved windows"
        elif rule["kind"] == "match":
            if rule.get("scope", "windows") == "windows" and not windows:
                continue
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
            "schedule_status": "configured" if schedules else "unconfigured: out-of-hours evaluation skipped",
            "host_profile": host.get("hostname") or "none: no exact or short-name host profile matched"}


def _fingerprint(finding):
    """Return (key, mode) for duplicate linking, or (None, None).

    process: cross-source identity needs host+PID+path+parent plus a close
    event-time comparison. GUID is extra evidence, never required, because
    Security 4688 has no GUID. Missing identity fails to no-dedup.
    stream: an all-events field match on a non-Windows event links into one
    alert per rule/host/source while it keeps firing (five-minute idle
    horizon), so a noisy match cannot flood the alert table.
    Script blocks stay individual alerts.
    """
    f = finding["fields"]
    kind = f.get("event.kind")
    if kind == "process_creation":
        keys = [f.get(k, "").casefold() for k in ("host.name", "process.pid", "process.path", "process.parent.pid")]
        if not all(keys) or not finding.get("event_time_utc"):
            return None, None
        keys += [finding["rule_id"], str(finding["config_revision"]), f.get("process.command_line", "").casefold()]
        return hashlib.sha256(json.dumps(keys).encode()).hexdigest(), "process"
    if kind in WINDOWS_KINDS:
        return None, None
    keys = ["stream", finding["rule_id"], str(finding["config_revision"]),
            f.get("host.name", "").casefold(), f.get("source.ip", "")]
    return hashlib.sha256(json.dumps(keys).encode()).hexdigest(), "stream"


def emit(conn, finding, log_id, source_ip):
    """Serialize duplicate suppression and evidence linking in one transaction.

    Caller owns the Storage lock. Bound references to 500 per alert and 512
    recent identities; all original events remain in logs/archive.
    """
    state = _locked_json(conn, STATE_KEY, {})
    now = datetime.now(timezone.utc)
    state = {k: v for k, v in state.items() if isinstance(v, dict) and timestamp(v.get("seen_at"))
             and (now - timestamp(v["seen_at"])).total_seconds() < 300}
    key, mode = _fingerprint(finding)
    previous = state.get(key) if key else None
    old = None
    if previous and mode == "process":
        a, b = timestamp(finding.get("event_time_utc")), timestamp(previous.get("event_time"))
        same = bool(a and b) and abs((a - b).total_seconds()) <= 2
    else:
        same = bool(previous) and mode == "stream"
    if same:
        old = conn.execute("SELECT id,description,log_ids,workflow_status FROM alerts WHERE id=?", (previous["alert_id"],)).fetchone()
        if old and (old["workflow_status"] in {"resolved", "closed"} or EVIDENCE_MARKER not in (old["description"] or "")):
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
    if f.get("process.name") or f.get("process.parent.name"):
        summary = f"{finding['reason']}: {f.get('host.name', 'unknown')} | {f.get('process.parent.name', '')} -> {f.get('process.name', '')}"
    else:
        summary = f"{finding['reason']}: {f.get('host.name') or f.get('source.ip') or 'unknown'} | {f.get('message', '')[:160]}"
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
