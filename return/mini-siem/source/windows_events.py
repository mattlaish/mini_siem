"""Source-qualified Windows event normalization; original JSON stays untouched."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import ipaddress
import ntpath


def timestamp(value, zone=None):
    """Never assume the collector timezone for a naive device timestamp."""
    try:
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        if dt.tzinfo is None:
            if not zone:
                return None
            tz = ZoneInfo(zone)
            a, b = dt.replace(tzinfo=tz, fold=0), dt.replace(tzinfo=tz, fold=1)
            # Ambiguous/nonexistent wall times need an explicit UTC offset.
            if a.utcoffset() != b.utcoffset():
                return None
            dt = a
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError, KeyError):
        return None


def _host_key(name):
    return str(name or "").strip().rstrip(".").casefold()


def _is_ip(name):
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


def host_matches(configured, observed):
    """Exact hostname match, or a short name against the same host's FQDN.

    Domain-joined Windows reports Computer as an FQDN while operators often
    type the short name. Two different FQDNs never match each other, and IP
    addresses only ever match exactly.
    """
    c, o = _host_key(configured), _host_key(observed)
    if not c or not o:
        return False
    if c == o:
        return True
    if _is_ip(c) or _is_ip(o) or ("." in c) == ("." in o):
        return False
    return c.split(".", 1)[0] == o.split(".", 1)[0]


def find_host_profile(hosts, observed):
    """Exact profile first; otherwise the single short/FQDN match. Ambiguous
    short-name matches (one short name, several domains) resolve to none
    rather than guessing a timezone or role."""
    key = _host_key(observed)
    exact = [h for h in hosts if _host_key(h.get("hostname")) == key]
    if exact:
        return exact[0]
    loose = [h for h in hosts if host_matches(h.get("hostname"), observed)]
    return loose[0] if len(loose) == 1 else {}


def basename(value):
    return ntpath.basename(str(value or "").strip().strip('"')).casefold()


def normalize_windows(event):
    obj = event.get("_json")
    if not isinstance(obj, dict):
        return {}
    root = obj.get("Event", obj)
    if not isinstance(root, dict):
        return {}
    system = root.get("System") if isinstance(root.get("System"), dict) else {}
    data = root.get("EventData") if isinstance(root.get("EventData"), dict) else {}
    flat = dict(data)
    if isinstance(data.get("Data"), list):
        for item in data["Data"]:
            if isinstance(item, dict):
                flat[item.get("Name", item.get("@Name", ""))] = item.get("#text", item.get("Value", ""))
    flat.update(root)

    def pick(*names):
        for name in names:
            v = flat.get(name, system.get(name))
            if isinstance(v, dict):
                v = v.get("SystemTime", v.get("#text", v.get("Name", v.get("@Name", ""))))
            if v not in (None, "", "-"):
                return str(v)
        return ""

    eid = pick("EventID", "EventId", "event_id")
    channel = pick("Channel").casefold()
    provider = pick("Provider", "ProviderName", "SourceName")
    p = provider.casefold()
    kind = None
    if eid == "4688" and channel == "security" and p == "microsoft-windows-security-auditing":
        kind = "process_creation"
    elif eid == "1" and channel == "microsoft-windows-sysmon/operational" and p == "microsoft-windows-sysmon":
        kind = "process_creation"
    elif eid == "4104" and channel in {"microsoft-windows-powershell/operational", "powershellcore/operational"} and p in {"microsoft-windows-powershell", "powershellcore"}:
        kind = "script_execution"
    if not kind:
        return {}

    fields = {
        "event.id": eid, "event.kind": kind, "event.provider": provider,
        "event.channel": pick("Channel"), "event.record_id": pick("EventRecordID", "RecordNumber"),
        "host.name": pick("Computer", "Hostname", "hostname") or event.get("hostname", ""),
        "event.time": pick("TimeCreated", "EventTime", "UtcTime", "timestamp"),
        "event.received_at": event.get("received_at", ""),
        "process.path": pick("NewProcessName") if eid == "4688" else pick("Image"),
        "process.parent.path": pick("ParentProcessName", "CreatorProcessName") if eid == "4688" else pick("ParentImage"),
        "process.command_line": pick("CommandLine"),
        "process.pid": pick("NewProcessId") if eid == "4688" else pick("ProcessId", "ProcessID"),
        "process.parent.pid": pick("ProcessId", "CreatorProcessId") if eid == "4688" else pick("ParentProcessId"),
        "process.guid": pick("ProcessGuid"), "process.parent.guid": pick("ParentProcessGuid"),
        "user.creator.sid": pick("SubjectUserSid"), "user.target.sid": pick("TargetUserSid"),
        "user.creator.name": pick("SubjectUserName"), "user.target.name": pick("TargetUserName"),
        "user.name": pick("User", "TargetUserName", "SubjectUserName"),
        "script.text": pick("ScriptBlockText"), "script.id": pick("ScriptBlockId"),
        "script.part": pick("MessageNumber"), "script.parts": pick("MessageTotal"),
    }
    for key in ("process.pid", "process.parent.pid"):
        try:
            value = fields[key]
            fields[key] = str(int(value, 16 if value.lower().startswith("0x") else 10))
        except ValueError:
            pass
    fields["process.name"] = basename(fields["process.path"])
    fields["process.parent.name"] = basename(fields["process.parent.path"])
    def account(domain, name):
        return domain + "\\" + name if domain and name and "\\" not in name else name
    fields["user.creator.name"] = account(pick("SubjectDomainName"), pick("SubjectUserName"))
    fields["user.target.name"] = account(pick("TargetDomainName"), pick("TargetUserName"))
    fields["user.name"] = pick("User") or fields["user.target.name"] or fields["user.creator.name"]
    if eid == "1" and pick("UtcTime"):
        utc = pick("UtcTime")
        parsed_utc = timestamp(utc, "UTC")
        if parsed_utc:
            fields["event.time"] = parsed_utc.isoformat()
    dt = timestamp(fields["event.time"])
    fields["event.time_status"] = "offset" if dt else "requires_host_timezone_or_valid_timestamp"
    if dt:
        fields["event.time"] = dt.isoformat()
        received = timestamp(event.get("received_at"))
        if received:
            fields["event.ingest_delay_seconds"] = str(round((received - dt).total_seconds(), 3))
    event["_normalized"] = {k: str(v) for k, v in fields.items() if v != ""}
    event["hostname"] = fields["host.name"]
    event["device_timestamp"] = fields["event.time"]
    return event["_normalized"]


def resolve_host_time(event, config):
    """Resolve naive source time only with an explicit matching host profile."""
    fields = event.get("_normalized", {})
    if not fields:
        return fields
    host = find_host_profile(config["hosts"], fields.get("host.name", ""))
    dt = timestamp(fields.get("event.time"), host.get("timezone"))
    if dt:
        fields["event.time"] = dt.isoformat()
        fields["event.time_status"] = "resolved"
        event["device_timestamp"] = dt.isoformat()
        received = timestamp(event.get("received_at"))
        if received:
            fields["event.ingest_delay_seconds"] = str(round((received - dt).total_seconds(), 3))
    return fields
