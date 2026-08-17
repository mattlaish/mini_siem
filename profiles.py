"""profiles — data-driven field mapping for JSON log sources.

Instead of hardcoding which JSON keys map to host/message/severity/etc. in
listener.py, a "source profile" describes that mapping as data (rows in the
source_profiles table). Adding a new log source becomes a config change in
the UI, not a code edit.

A profile has:
  * match_type / match_value: how to recognize events for this profile
      - source_ip:  the ingest source equals match_value (e.g. a connector name)
      - key_present: the JSON has this key (e.g. 'customer_id' => Sophos)
      - app_contains: app_name contains match_value (case-insensitive)
  * map_*: a comma-separated priority list of JSON keys for each target field.
      The first key present (non-empty) wins. e.g. map_host="location,Hostname"
  * ts_format: optional strptime format for map_timestamp (for normalization).
  * priority: lower number = checked first.

Zero external dependencies.
"""

import json
from datetime import datetime, timezone


def _first(obj, keylist, default=""):
    """First present, non-empty value among comma-separated keys in keylist.
    Supports dotted paths for one level of nesting (e.g. source_info.ip)."""
    if not keylist:
        return default
    for raw in keylist.split(","):
        key = raw.strip()
        if not key:
            continue
        if "." in key:
            top, sub = key.split(".", 1)
            v = obj.get(top)
            if isinstance(v, dict) and v.get(sub) not in (None, ""):
                return v.get(sub)
        elif key in obj and obj[key] not in (None, ""):
            return obj[key]
    return default


def match_profile(profiles, obj, source_ip, app_name=""):
    """Return the first matching profile (already priority-sorted) or None."""
    for p in profiles:
        if not p.get("enabled", 1):
            continue
        mt = p.get("match_type") or "source_ip"
        mv = (p.get("match_value") or "").strip()
        if mt == "source_ip" and source_ip == mv:
            return p
        if mt == "key_present" and mv and mv in obj:
            return p
        if mt == "app_contains" and mv and mv.lower() in (app_name or "").lower():
            return p
    return None


def normalize_timestamp(value, ts_format=""):
    """Parse a device timestamp string into a canonical UTC ISO-8601 string.
    Falls back to the raw value if parsing fails or no format is given."""
    if not value:
        return ""
    s = str(value)
    # try the configured format first
    if ts_format:
        try:
            dt = datetime.strptime(s, ts_format)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except (ValueError, TypeError):
            pass
    # try a few common formats automatically
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S"):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except (ValueError, TypeError):
            continue
    return s  # unparseable — keep the raw string


def apply_profile(profile, obj):
    """Apply a profile's key mappings to a JSON object. Returns a dict of the
    resolved target fields (host, message, app, msg_id, severity, device_ts)."""
    host = str(_first(obj, profile.get("map_host", "")))
    message = str(_first(obj, profile.get("map_message", "")))
    app = str(_first(obj, profile.get("map_app", ""), default="")) or ""
    msgid = str(_first(obj, profile.get("map_msgid", "")))
    severity = str(_first(obj, profile.get("map_severity", ""))).lower()
    ts_raw = _first(obj, profile.get("map_timestamp", ""))
    device_ts = normalize_timestamp(ts_raw, profile.get("ts_format", ""))
    return {
        "hostname": host,
        "message": message,
        "app_name": app,
        "msg_id": msgid,
        "severity": severity,
        "device_timestamp": device_ts,
    }


def load_profiles(conn):
    """Load enabled profiles, priority-sorted (lowest first)."""
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM source_profiles ORDER BY priority ASC, id ASC").fetchall()]
    return rows


# Default profiles seeded on first run — the previously-hardcoded mappings,
# now editable. Windows/NXLog and Sophos.
DEFAULT_PROFILES = [
    {
        "name": "Windows / NXLog",
        "match_type": "key_present", "match_value": "EventID",
        "map_host": "Hostname,hostname,host,Computer,MachineName",
        "map_message": "Message,message",
        "map_app": "SourceName,Channel,ProviderName",
        "map_msgid": "EventID,event_id,EventId",
        "map_severity": "",   # Windows severity comes from the EventID map in code
        "map_timestamp": "EventTime,TimeCreated,timestamp",
        "ts_format": "",
        "priority": 10, "enabled": 1,
    },
    {
        "name": "Sophos Central",
        "match_type": "key_present", "match_value": "customer_id",
        "map_host": "location,endpoint_name,device",
        "map_message": "name,description",
        "map_app": "type,product",
        "map_msgid": "type",
        "map_severity": "severity",
        "map_timestamp": "when,created_at",
        "ts_format": "%Y-%m-%dT%H:%M:%S.%fZ",
        "priority": 20, "enabled": 1,
    },
]


def seed_defaults(conn):
    """Insert default profiles if the table is empty."""
    n = conn.execute("SELECT COUNT(*) FROM source_profiles").fetchone()[0]
    if n:
        return
    for p in DEFAULT_PROFILES:
        conn.execute(
            """INSERT INTO source_profiles
               (name, match_type, match_value, map_host, map_message, map_app,
                map_msgid, map_severity, map_timestamp, ts_format, priority, enabled)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (p["name"], p["match_type"], p["match_value"], p["map_host"],
             p["map_message"], p["map_app"], p["map_msgid"], p["map_severity"],
             p["map_timestamp"], p["ts_format"], p["priority"], p["enabled"]))
    conn.commit()
