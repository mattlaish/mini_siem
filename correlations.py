"""
mini-SIEM on-demand correlation engine + playbook library
==========================================================
Unlike rules.py (which evaluates events live as they arrive), this
module runs retrospective correlations over the logs already stored in
SQLite, on demand from the dashboard's /correlate page.

Correlation types
-----------------
threshold   N+ events matching a pattern from the same key in the window
sequence    N+ "pattern A" events followed by a "pattern B" event from
            the same key within max_gap_seconds (e.g. brute force then
            successful login)
fanout      one key touching many distinct values of another field
            (e.g. one source IP hitting many hostnames = scan/lateral
            movement)
first_seen  keys appearing in the recent window that were never seen in
            the preceding baseline period (e.g. brand-new source IP)

Playbooks are just named, documented parameter sets for this engine,
plus suggested response steps. Add your own to PLAYBOOKS below.
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from sql_helpers import placeholders

import severity as severity_mod

# Rows are read in pages of PAGE_ROWS. A check run from the page reads at most
# INTERACTIVE_SCAN_LIMIT events (the newest ones in the window); scheduled
# reports read up to SCHEDULED_SCAN_LIMIT. Results carry "coverage" saying
# which part of the window was read, so a partial run is never shown as clean.
PAGE_ROWS = 5000
INTERACTIVE_SCAN_LIMIT = 500_000
SCHEDULED_SCAN_LIMIT = 10_000_000
MAX_GROUP_IDS = 1000      # evidence IDs kept per finding; counts stay exact

USER_PATTERNS = [
    re.compile(r"Account Name:\s*\|?\s*([^\s|]+)", re.IGNORECASE),
    re.compile(r"\bfor\s+(?:invalid user\s+)?([A-Za-z0-9._\-\\$]+)\s+from", re.IGNORECASE),
    re.compile(r"\buser[=:\s]+([A-Za-z0-9._\-\\$]+)", re.IGNORECASE),
]


def _extract_user(message: str):
    for pat in USER_PATTERNS:
        m = pat.search(message or "")
        if m:
            val = m.group(1)
            if val and val not in ("-", "N/A", "SYSTEM$"):
                return val
    return None


# Same defaults as dashboard.py's get_search_aliases(). Duplicated (not
# imported) to avoid a circular import — dashboard.py imports FROM this
# module. Both read the SAME app_config row, so editing aliases in Setup ->
# Search field aliases changes correlation grouping too, immediately.
_DEFAULT_ALIASES = {
    "source_ip": ["endpoint_ip", "src", "srcip", "src_ip"],
    "hostname": ["computer", "machinename", "endpoint_name", "device", "location"],
    "destination": ["dst", "dest", "target", "dhost", "destination_ip"],
}


def _get_aliases(conn):
    """Read the shared search-alias config, keyed by BASE COLUMN name
    (source_ip/hostname/destination) to match group_by values directly."""
    try:
        row = conn.execute(
            "SELECT value FROM app_config WHERE key='search_aliases'").fetchone()
        if not row or not row["value"]:
            return dict(_DEFAULT_ALIASES)
        import json as _json
        d = _json.loads(row["value"])
        return {
            "source_ip": d.get("source") or _DEFAULT_ALIASES["source_ip"],
            "hostname": d.get("host") or _DEFAULT_ALIASES["hostname"],
            "destination": d.get("destination") or _DEFAULT_ALIASES["destination"],
        }
    except Exception:
        return dict(_DEFAULT_ALIASES)


def _looks_like_ip(v):
    if not v:
        return False
    import ipaddress
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _resolve_identity(conn, rows, group_by, aliases):
    """For group_by values that mean an identity concept (source_ip,
    hostname, destination), fix up each row's value in-place: fall back to
    the first present alias field from log_fields when the base column
    doesn't hold a real identity for that concept.

    This is the SAME cross-source problem Log Search had: a playbook
    grouping by group_by="source_ip" only ever saw the raw `logs.source_ip`
    column — which, for events from an API-poller source, holds the
    CONNECTOR NAME (e.g. "sophos"), not a real per-endpoint identity. That
    value is NOT blank — it's just wrong — so a naive "fall back only when
    empty" check would never catch it. For source_ip/destination (which
    should always be IPs), the trigger is "doesn't parse as an IP address",
    which correctly flags "sophos" while leaving genuine IPs (Fortigate's
    src=) untouched. hostname isn't IP-shaped, so it only falls back when
    genuinely blank — it's already resolved correctly by source profiles in
    the common case.
    """
    fields = aliases.get(group_by)
    if not fields:
        return  # 'user' and other group_bys aren't column-based; untouched
    ip_shaped = group_by in ("source_ip", "destination")
    if ip_shaped:
        needs_fallback = [r for r in rows if not _looks_like_ip(r.get(group_by))]
    else:
        needs_fallback = [r for r in rows if not r.get(group_by)]
    if not needs_fallback:
        return
    ids = [r["id"] for r in needs_fallback]
    ph = placeholders(len(fields))
    id_ph = placeholders(len(ids))
    found = {}
    alias_sql = ("SELECT log_id, field, value FROM log_fields WHERE log_id IN ("
                 + id_ph + ") AND field IN (" + ph + ") ORDER BY log_id")
    for r in conn.execute(alias_sql, ids + fields).fetchall():
        # first matching field wins, but for ip_shaped concepts only accept
        # values that actually parse as an IP — an alias field with a
        # non-IP value (rare, but possible with a misconfigured alias list)
        # shouldn't silently become the group key either.
        if r["log_id"] in found:
            continue
        if ip_shaped and not _looks_like_ip(r["value"]):
            continue
        found[r["log_id"]] = r["value"]
    for r in needs_fallback:
        if r["id"] in found:
            r.setdefault("_resolved", {})[group_by] = found[r["id"]]


def _key_of(row: dict, group_by: str):
    resolved = row.get("_resolved")
    if resolved and group_by in resolved:
        return resolved[group_by]
    if group_by == "user":
        return _extract_user(row["message"])
    return row.get(group_by) or None


def _parse_ts(iso: str):
    try:
        return datetime.fromisoformat(iso)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Window scan
# ---------------------------------------------------------------------------
# Rows are read oldest-first in pages, so memory holds one page plus what each
# check keeps for its matches, not the whole window. If the window holds more
# events than the scan limit, the NEWEST events are scanned and the result
# says which part of the window it covers ("coverage"); nothing is dropped
# silently.

def _row_time(row):
    t = row.get("_t")
    if isinstance(t, datetime):
        return t
    return _parse_ts(str(t or row.get("received_at") or ""))


def _iso(value):
    return value.isoformat() if isinstance(value, datetime) else (str(value) if value is not None else None)


def _scan_start(conn, since_iso, until_iso, scan_limit):
    """Return (start, complete): where to begin so at most scan_limit events are read."""
    pg = getattr(conn, "backend", "sqlite") == "postgres"
    table, col = ("security_events", "event_time") if pg else ("logs", "received_at")
    cast = "::timestamptz" if pg else ""
    sql = "SELECT " + col + " AS t FROM " + table + " WHERE " + col + " >= ?" + cast
    params = [since_iso]
    if until_iso:
        sql += " AND " + col + " <= ?" + cast
        params.append(until_iso)
    sql += " ORDER BY " + col + " DESC LIMIT 2 OFFSET ?"
    params.append(max(0, int(scan_limit) - 1))
    rows = conn.execute(sql, params).fetchall()
    if len(rows) < 2:
        return since_iso, True
    return _iso(rows[0]["t"]), False


def _scan_window(conn, since_iso, until_iso, scan_limit, concepts, coverage):
    """Yield rows of [since, until] oldest-first; fill ``coverage``."""
    pg = getattr(conn, "backend", "sqlite") == "postgres"
    relation = "security_event_logs" if pg else "logs"
    col = "event_time" if pg else "received_at"
    cast = "::timestamptz" if pg else ""
    start, complete = _scan_start(conn, since_iso, until_iso, scan_limit)
    coverage.update(since=since_iso, until=until_iso, scanned_from=start,
                    complete=complete, scanned=0)
    aliases = _get_aliases(conn) if concepts else {}
    base = ("SELECT id, received_at, source_ip, hostname, destination, app_name, severity, message, "
            + col + " AS _t FROM " + relation + " WHERE " + col + " >= ?" + cast)
    bounds = [start]
    if until_iso:
        base += " AND " + col + " <= ?" + cast
        bounds.append(until_iso)
    last_t = last_id = None
    while True:
        sql, params = base, list(bounds)
        if last_t is not None:
            sql += " AND (" + col + " > ?" + cast + " OR (" + col + " = ?" + cast + " AND id > ?))"
            params += [last_t, last_t, last_id]
        sql += " ORDER BY " + col + ", id LIMIT ?"
        params.append(PAGE_ROWS)
        page = [dict(r) for r in conn.execute(sql, params).fetchall()]
        if not page:
            return
        last_t, last_id = page[-1]["_t"], page[-1]["id"]
        for concept in concepts:
            _resolve_identity(conn, page, concept, aliases)
        coverage["scanned"] += len(page)
        for row in page:
            row["_ts"] = _row_time(row)
            yield row
        if len(page) < PAGE_ROWS:
            return


def _matches(row: dict, regex):
    return bool(regex.search(row["message"] or ""))


def _hour_ok(row: dict, hours):
    """hours: optional (start_hour, end_hour) tuple in UTC; supports
    wrap-around ranges like (22, 6) for off-hours."""
    if not hours:
        return True
    ts = row.get("_ts") or _parse_ts(row["received_at"])
    if not ts:
        return False
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc)
    h = ts.hour
    start, end = hours
    if start <= end:
        return start <= h < end
    return h >= start or h < end


def _sample(rows, n=3):
    return [
        {"id": r["id"], "received_at": r["received_at"], "message": (r["message"] or "")[:300]}
        for r in rows[:n]
    ]


class _Group:
    """Exact count and time span; bounded evidence IDs and samples."""
    __slots__ = ("count", "first", "last", "ids", "samples")

    def __init__(self):
        self.count, self.first, self.last, self.ids, self.samples = 0, None, None, [], []

    def add(self, row):
        self.count += 1
        if self.first is None:
            self.first = row["received_at"]
        self.last = row["received_at"]
        if len(self.ids) < MAX_GROUP_IDS:
            self.ids.append(row["id"])
        if len(self.samples) < 3:
            self.samples.append(_sample([row], 1)[0])

    def result(self, key):
        out = {"key": key, "count": self.count, "first": self.first, "last": self.last,
               "log_ids": list(self.ids), "sample": list(self.samples)}
        if self.count > len(self.ids):
            out["log_ids_truncated"] = True
        return out


# ---------------------------------------------------------------------------
# Correlation implementations: each check consumes rows as they are scanned
# ---------------------------------------------------------------------------

class _Check:
    needs_baseline = False

    def __init__(self, p):
        self.p = p
        self.group_by = p["group_by"]
        self.regex = re.compile(p.get("pattern", "."), re.IGNORECASE)
        sev = p.get("severity_filter")
        self.severities = None
        if sev:
            self.severities = set(severity_mod.synonyms_of(sev) or [sev.lower()])

    def wanted(self, row):
        if self.severities is not None and str(row.get("severity") or "").lower() not in self.severities:
            return False
        return _matches(row, self.regex)


class _Threshold(_Check):
    def __init__(self, p):
        super().__init__(p)
        self.hours = p.get("hours")
        self.groups = defaultdict(_Group)

    def feed(self, row):
        if not self.wanted(row) or not _hour_ok(row, self.hours):
            return
        key = _key_of(row, self.group_by)
        if key:
            self.groups[key].add(row)

    def finish(self):
        results = [g.result(k) for k, g in self.groups.items() if g.count >= self.p["threshold"]]
        results.sort(key=lambda x: -x["count"])
        return results


class _Sequence(_Check):
    def __init__(self, p):
        super().__init__(p)
        self.re_b = re.compile(p["pattern_b"], re.IGNORECASE)
        self.min_a = p.get("min_a_count", 1)
        self.gap = timedelta(seconds=p.get("max_gap_seconds", 600))
        self.recent = defaultdict(list)       # key -> [(ts, id, sample)]
        self.results = []

    def feed(self, row):
        is_a, is_b = _matches(row, self.regex), _matches(row, self.re_b)
        if not (is_a or is_b):
            return
        key = _key_of(row, self.group_by)
        ts = row.get("_ts")
        if not key or ts is None:
            return
        recent = self.recent[key]
        if is_a:
            recent.append((ts, row["id"], _sample([row], 1)[0]))
            cutoff = ts - self.gap
            while recent and recent[0][0] < cutoff:
                recent.pop(0)
        if is_b and recent:
            cutoff = ts - self.gap
            window_a = [x for x in recent if x[0] >= cutoff]
            if len(window_a) >= self.min_a:
                ids = [x[1] for x in window_a][:MAX_GROUP_IDS - 1] + [row["id"]]
                result = {
                    "key": key,
                    "a_count": len(window_a),
                    "b_time": row["received_at"],
                    "gap_seconds": round((ts - window_a[0][0]).total_seconds(), 1),
                    "log_ids": ids,
                    "sample": [x[2] for x in window_a[:2]] + _sample([row], 1),
                }
                if len(window_a) + 1 > len(ids):
                    result["log_ids_truncated"] = True
                self.results.append(result)
                self.recent[key] = []          # one alert per burst

    def finish(self):
        self.results.sort(key=lambda x: -x["a_count"])
        return self.results


class _Fanout(_Check):
    def __init__(self, p):
        super().__init__(p)
        self.distinct_field = p["distinct_field"]
        self.groups = defaultdict(lambda: (set(), _Group()))

    def feed(self, row):
        if not self.wanted(row):
            return
        key = _key_of(row, self.group_by)
        field = self.distinct_field
        val = _key_of(row, field) if field == "user" else row.get(field)
        if key and val:
            values, group = self.groups[key]
            values.add(val)
            group.add(row)

    def finish(self):
        results = []
        for key, (values, group) in self.groups.items():
            if len(values) >= self.p["threshold"]:
                out = group.result(key)
                out.update(distinct_count=len(values), distinct_values=sorted(values)[:15])
                results.append(out)
        results.sort(key=lambda x: -x["distinct_count"])
        return results


class _FirstSeen(_Check):
    needs_baseline = True

    def __init__(self, p):
        super().__init__(p)
        since_dt = datetime.fromisoformat(p["since"])
        self.baseline_since = (since_dt - timedelta(minutes=p.get("baseline_minutes", 7 * 24 * 60))).isoformat()
        self.baseline = set()
        self.groups = defaultdict(_Group)

    def feed_baseline(self, row):
        key = _key_of(row, self.group_by)
        if key:
            self.baseline.add(key)

    def feed(self, row):
        if not self.wanted(row):
            return
        key = _key_of(row, self.group_by)
        if key and key not in self.baseline:
            self.groups[key].add(row)

    def finish(self):
        results = [g.result(k) for k, g in self.groups.items()]
        results.sort(key=lambda x: -x["count"])
        return results


CORRELATION_TYPES = {
    "threshold": _Threshold,
    "sequence": _Sequence,
    "fanout": _Fanout,
    "first_seen": _FirstSeen,
}


def _prepare(params, now=None):
    ctype = params.get("type")
    if ctype not in CORRELATION_TYPES:
        raise ValueError(f"Unknown correlation type: {ctype}")
    if "since" not in params:
        window = int(params.get("window_minutes", 60))
        now = now or datetime.now(timezone.utc)
        params["since"] = (now - timedelta(minutes=window)).isoformat()
    return CORRELATION_TYPES[ctype](params)


def _concepts(checks):
    return sorted({c.group_by for c in checks} & {"source_ip", "hostname", "destination"})


def run_checks(conn, checks, since, until, scan_limit):
    """Feed every check from ONE scan of [since, until] (plus baseline scans).

    Returns {id(check): {"coverage": {...}, "error": str|None}}. A check that
    fails is reported and dropped; the others continue.
    """
    status = {id(c): {"coverage": None, "error": None} for c in checks}
    live = list(checks)

    def feed(targets, rows, method):
        for row in rows:
            for check in list(targets):
                try:
                    getattr(check, method)(row)
                except Exception as exc:  # noqa: BLE001 - isolate one bad check
                    status[id(check)]["error"] = f"{type(exc).__name__}: {exc}"
                    targets.remove(check)
                    if check in live:
                        live.remove(check)

    baselines = defaultdict(list)
    for check in checks:
        if check.needs_baseline:
            baselines[check.baseline_since].append(check)
    for baseline_since, targets in baselines.items():
        cov = {}
        feed(list(targets), _scan_window(conn, baseline_since, since, scan_limit, _concepts(targets), cov),
             "feed_baseline")
        for check in targets:
            status[id(check)]["baseline_coverage"] = cov
    cov = {}
    if live:
        feed(live, _scan_window(conn, since, until, scan_limit, _concepts(live), cov), "feed")
    for check in checks:
        entry = status[id(check)]
        entry["coverage"] = dict(cov)
        base = entry.pop("baseline_coverage", None)
        if base is not None:
            entry["coverage"]["baseline_complete"] = base.get("complete", True)
            entry["coverage"]["complete"] = entry["coverage"].get("complete", True) and base.get("complete", True)
    return status


def run_correlation(conn, params: dict, scan_limit: int = None) -> dict:
    """Entry point. params must include: type, since (ISO), group_by,
    plus the type-specific fields documented at the top of this file."""
    check = _prepare(params)
    state = run_checks(conn, [check], params["since"], params.get("until"),
                       scan_limit or INTERACTIVE_SCAN_LIMIT)[id(check)]
    if state["error"]:
        raise RuntimeError(state["error"])
    results = check.finish()
    return {"type": params["type"], "params_used": {k: v for k, v in params.items() if k != "conn"},
            "group_count": len(results), "groups": results, "coverage": state["coverage"]}


def run_playbook_set(conn, playbooks, window_minutes, scan_limit):
    """Run several playbooks over the same window with one shared scan.

    Returns one entry per playbook: {"result": run_correlation-shaped dict}
    or {"error": "..."}.
    """
    now = datetime.now(timezone.utc)
    since = (now - timedelta(minutes=window_minutes)).isoformat()
    prepared, out = [], {}
    for pb in playbooks:
        params = dict(pb["params"])
        params["window_minutes"] = window_minutes
        params["since"] = since
        try:
            prepared.append((pb, params, _prepare(params, now)))
        except Exception as exc:  # noqa: BLE001
            out[pb["id"]] = {"error": f"{type(exc).__name__}: {exc}"}
    status = run_checks(conn, [c for _, _, c in prepared], since, None, scan_limit)
    for pb, params, check in prepared:
        state = status[id(check)]
        if state["error"]:
            out[pb["id"]] = {"error": state["error"], "coverage": state["coverage"]}
            continue
        results = check.finish()
        out[pb["id"]] = {"result": {"type": params["type"], "params_used": params,
                                    "group_count": len(results), "groups": results,
                                    "coverage": state["coverage"]}}
    return out


# ---------------------------------------------------------------------------
# Playbook library
# ---------------------------------------------------------------------------
# Each playbook = engine params + human documentation + response steps.
# window_minutes is a default; the UI lets the analyst override it.

PLAYBOOKS = [
    {
        "id": "bruteforce_then_success",
        "name": "Brute force followed by successful login",
        "category": "Credential attacks",
        "severity": "critical",
        "description": "Finds sources that generated repeated failed logins (Linux sshd "
                       "failures or Windows \b4625\b) and then produced a successful login "
                       "(sshd accepted / Windows \b4624\b) shortly after — the classic "
                       "signature of a password-guessing attack that worked.",
        "params": {
            "type": "sequence",
            "pattern": r"failed password|authentication failure|invalid user|(?:event[ _]?id\x22?[\s:=]+)4625|logon failure",
            "pattern_b": r"accepted password|session opened|(?:event[ _]?id\x22?[\s:=]+)4624|successfully logged",
            "group_by": "source_ip",
            "min_a_count": 5,
            "max_gap_seconds": 900,
            "window_minutes": 1440,
        },
        "response_steps": [
            "Confirm the successful login is not a legitimate user who mistyped their password repeatedly.",
            "Identify the account that succeeded and check what it did next (search its activity in the log view).",
            "If suspicious: disable/lock the account, terminate its sessions, and block the source IP at the firewall.",
            "Force a credential reset for the affected account and check for MFA gaps.",
            "Preserve the matched log IDs for the incident record.",
        ],
    },
    {
        "id": "windows_log_cleared",
        "name": "Windows event log cleared",
        "category": "Defense evasion",
        "severity": "critical",
        "description": "Windows Event ID \b1102\b (Security log cleared) or 104 (other logs "
                       "cleared) is rarely legitimate outside of planned maintenance — "
                       "attackers clear logs to cover their tracks. Any hit deserves a look.",
        "params": {
            "type": "threshold",
            "pattern": r"(?:event[ _]?id\x22?[\s:=]+)1102|(?:event[ _]?id\x22?[\s:=]+)104.*log file was cleared|audit log was cleared|event log.*cleared",
            "group_by": "hostname",
            "threshold": 1,
            "window_minutes": 1440,
        },
        "response_steps": [
            "Check change records: was maintenance scheduled on this host at this time?",
            "Identify which account cleared the log (the \b1102\b event itself names it).",
            "Review everything that host and account did in the hours before the clear — that's what someone wanted hidden.",
            "If unexplained, treat the host as potentially compromised: isolate and escalate.",
        ],
    },
    {
        "id": "new_admin_account",
        "name": "New account created / added to privileged group",
        "category": "Persistence",
        "severity": "warning",
        "description": "Windows 4720 (account created), 4728/4732/4756 (added to a "
                       "privileged group), or equivalent Linux useradd/usermod events. "
                       "Legitimate in onboarding; a persistence mechanism otherwise.",
        "params": {
            "type": "threshold",
            "pattern": r"(?:event[ _]?id\x22?[\s:=]+)4720|(?:event[ _]?id\x22?[\s:=]+)4728|(?:event[ _]?id\x22?[\s:=]+)4732|(?:event[ _]?id\x22?[\s:=]+)4756|account was created|added to.*(admin|sudo|domain admins)|useradd|usermod.*-aG",
            "group_by": "hostname",
            "threshold": 1,
            "window_minutes": 1440,
        },
        "response_steps": [
            "Cross-check against HR onboarding / approved change tickets.",
            "Verify who performed the creation and whether they were authorized.",
            "If unauthorized: disable the new account, then investigate the creating account as compromised.",
        ],
    },
    {
        "id": "scan_fanout",
        "name": "One source touching many hosts (scan / lateral movement)",
        "category": "Reconnaissance / lateral movement",
        "severity": "warning",
        "description": "A single source IP generating denied/blocked/failed events "
                       "against many distinct hostnames in a short window suggests "
                       "network scanning or an attacker moving laterally.",
        "params": {
            "type": "fanout",
            "pattern": r"deny|denied|drop|dropped|block|blocked|refused|failed",
            "group_by": "source_ip",
            "distinct_field": "hostname",
            "threshold": 5,
            "window_minutes": 60,
        },
        "response_steps": [
            "Determine whether the source is an internal host (compromised machine / misconfigured scanner) or external.",
            "Internal: isolate the machine and examine what it was probing for.",
            "External: block at the perimeter and check whether any of the touched hosts responded/accepted.",
            "Check whether a vulnerability scanner was legitimately scheduled (compare against change records).",
        ],
    },
    {
        "id": "account_multi_source",
        "name": "Same account logging in from many source IPs",
        "category": "Credential attacks",
        "severity": "warning",
        "description": "One account successfully authenticating from several different "
                       "source IPs in a short window can indicate shared/stolen "
                       "credentials or session hijacking. (Extracts the username from "
                       "sshd 'Accepted ... for user' and Windows 'Account Name:' fields.)",
        "params": {
            "type": "fanout",
            "pattern": r"accepted password|accepted publickey|session opened|(?:event[ _]?id\x22?[\s:=]+)4624|successfully logged",
            "group_by": "user",
            "distinct_field": "source_ip",
            "threshold": 3,
            "window_minutes": 120,
        },
        "response_steps": [
            "Check if the account is a service account expected to authenticate from many hosts (common false positive).",
            "For human accounts: verify with the user; look for geographic/VPN explanations.",
            "If unexplained: reset credentials, revoke sessions, review the account's recent activity.",
        ],
    },
    {
        "id": "off_hours_admin",
        "name": "Privileged activity outside business hours",
        "category": "Anomalous behavior",
        "severity": "warning",
        "description": "sudo usage, Windows \b4672\b (special privileges assigned), or "
                       "administrator logins occurring between 22:00 and 06:00 UTC. "
                       "Adjust the hour range in the params to match your timezone "
                       "and on-call reality.",
        "params": {
            "type": "threshold",
            "pattern": r"\bsudo\b|(?:event[ _]?id\x22?[\s:=]+)4672|administrator|root login|privileged",
            "group_by": "user",
            "threshold": 1,
            "window_minutes": 1440,
            "hours": [22, 6],
        },
        "response_steps": [
            "Check the on-call schedule and any open change windows for that time.",
            "Confirm with the account owner that the activity was theirs.",
            "If unconfirmed, review exactly what the privileged session did.",
        ],
    },
    {
        "id": "new_source_ips",
        "name": "Never-before-seen source IPs",
        "category": "Anomalous behavior",
        "severity": "informational",
        "description": "Source IPs sending logs (or appearing in auth events) in the "
                       "recent window that never appeared in the preceding 7-day "
                       "baseline. New devices are normal; new sources authenticating "
                       "to things are worth a glance.",
        "params": {
            "type": "first_seen",
            "pattern": r".",
            "group_by": "source_ip",
            "window_minutes": 1440,
            "baseline_minutes": 10080,
        },
        "response_steps": [
            "Match new IPs against recent change records / newly deployed devices.",
            "For unexplained internal IPs: identify the device (DHCP leases, switch tables).",
            "For unexplained external IPs in auth events: check reputation and block if hostile.",
        ],
    },
    {
        "id": "error_burst",
        "name": "Error/critical burst from a single host",
        "category": "Operational health",
        "severity": "warning",
        "description": "20+ error-or-worse events from one host in an hour. Usually an "
                       "operational problem (failing disk, crashing service) but "
                       "sometimes the side effect of an attack or a change gone wrong.",
        "params": {
            "type": "threshold",
            "pattern": r".",
            "group_by": "hostname",
            "threshold": 20,
            "window_minutes": 60,
            "severity_filter": "error",
        },
        "response_steps": [
            "Read the sample messages — most bursts self-identify (disk, service crash-loop, cert expiry).",
            "Correlate with recent change tickets against that host.",
            "If the errors are auth/security related, pivot to the credential-attack playbooks.",
        ],
    },
    {
        "id": "privilege_escalation",
        "name": "Privilege escalation attempts then success",
        "category": "Privilege abuse",
        "severity": "critical",
        "description": "Repeated failed sudo/su/runas attempts from a host followed by a "
                       "successful privileged session — someone working their way up to "
                       "root/admin. Failed-then-successful escalation is far more suspicious "
                       "than either alone.",
        "params": {
            "type": "sequence",
            "pattern": r"sudo.*(incorrect password|authentication failure)|su: FAILED|(?:event[ _]?id\x22?[\s:=]+)4673|(?:event[ _]?id\x22?[\s:=]+)4674.*denied",
            "pattern_b": r"sudo.*session opened|su: pam_unix.*session opened|session opened for user root|(?:event[ _]?id\x22?[\s:=]+)4672",
            "group_by": "hostname",
            "min_a_count": 3,
            "max_gap_seconds": 1800,
            "window_minutes": 1440,
        },
        "response_steps": [
            "Identify which account performed the escalation and whether that user should have admin rights at all.",
            "Review what the privileged session did immediately after (search the host's activity around the match).",
            "Check for persistence: new cron jobs, services, scheduled tasks, or accounts created during the session.",
            "If unauthorized: terminate the session, lock the account, and rotate credentials on that host.",
            "Check the same account's activity on other hosts for lateral movement.",
        ],
    },
    {
        "id": "account_lockout_storm",
        "name": "Account lockout storm",
        "category": "Credential attacks",
        "severity": "error",
        "description": "Multiple account lockouts in a short window (Windows \b4740\b or PAM "
                       "lockouts). A burst of lockouts usually means password spraying "
                       "against many accounts, a misconfigured service hammering old "
                       "credentials, or an attacker triggering lockouts as denial of service.",
        "params": {
            "type": "threshold",
            "pattern": r"account.*locked|locked out|(?:event[ _]?id\x22?[\s:=]+)4740|pam_tally|pam_faillock",
            "group_by": "source_ip",
            "threshold": 3,
            "window_minutes": 60,
        },
        "response_steps": [
            "List the locked accounts — many different accounts from one source suggests spraying; one account repeatedly suggests a stale credential in a script or service.",
            "Identify the source triggering lockouts and isolate/block it if it is not a known service host.",
            "Unlock affected accounts only after the source is contained.",
            "If spraying: check whether any account authenticated successfully during the same window (run the brute-force playbook).",
        ],
    },
    {
        "id": "malware_detected",
        "name": "Malware / AV detection events",
        "category": "Malware",
        "severity": "critical",
        "description": "Any antivirus/EDR detection, quarantine, or malware-name mention in "
                       "logs. One hit is already worth an analyst's eyes; several hits on "
                       "the same host suggests active infection rather than a caught-and-"
                       "cleaned file.",
        "params": {
            "type": "threshold",
            "pattern": r"virus|malware|trojan|ransomware|quarantin|infected|defender.*detected|(?:event[ _]?id\x22?[\s:=]+)1116|(?:event[ _]?id\x22?[\s:=]+)1117",
            "group_by": "hostname",
            "threshold": 1,
            "window_minutes": 1440,
        },
        "response_steps": [
            "Check whether the AV action succeeded (quarantined/cleaned) or only detected — a detect-without-clean means the file may still be live.",
            "Pull the file hash from the log and add it as a hash IOC on the Threat Intel page so any other host touching it alerts.",
            "Search the host's recent logins and network activity for how the file arrived (email, download, share).",
            "If multiple detections on one host: isolate the host from the network and rescan.",
            "Check other hosts for the same hash/filename.",
        ],
    },
    {
        "id": "service_failure_burst",
        "name": "Service crash / failure burst on a host",
        "category": "Availability & tampering",
        "severity": "error",
        "description": "A burst of service failures, crashes, or restarts on one host. "
                       "Can be plain instability — but attackers also crash services "
                       "(AV, logging, backup agents) to blind defenses before acting, so "
                       "a failure burst deserves a look at WHICH services died.",
        "params": {
            "type": "threshold",
            "pattern": r"failed to start|service.*(stopped|crashed|terminated unexpectedly)|core dump|segfault|(?:event[ _]?id\x22?[\s:=]+)7031|(?:event[ _]?id\x22?[\s:=]+)7034",
            "group_by": "hostname",
            "threshold": 5,
            "window_minutes": 120,
        },
        "response_steps": [
            "Identify which services failed — security tooling (AV/EDR/logging/backup) failing is a red flag; one flaky app crashing is likely operational.",
            "Check what happened on the host immediately before the first failure (logins, updates, new processes).",
            "If a security service was stopped: verify it is running again and review the gap window closely for other activity.",
            "For operational crashes: check disk space and memory on the Health page before assuming attack.",
        ],
    },
    {
        "id": "log_source_silence",
        "name": "Log tampering indicators (audit stopped / log cleared)",
        "category": "Availability & tampering",
        "severity": "critical",
        "description": "Events indicating logging itself was stopped, cleared, or "
                       "reconfigured: Windows \b1102\b/104 (log cleared), auditd stopping, "
                       "syslog daemon stopped. Attackers silence logging before doing "
                       "the thing they don't want recorded.",
        "params": {
            "type": "threshold",
            "pattern": r"(?:event[ _]?id\x22?[\s:=]+)1102|audit log.*cleared|the event log.*was cleared|auditd.*(stopp|terminat)|rsyslogd.*exiting|syslog.*stopped",
            "group_by": "hostname",
            "threshold": 1,
            "window_minutes": 1440,
        },
        "response_steps": [
            "Treat as high priority: identify WHO cleared/stopped logging (the clearing event usually names the account).",
            "Reconstruct the gap from other sources: this SIEM's copy of the host's earlier logs survives local clearing — search the host's history here.",
            "Check the host for what happened right before the clear and right after logging resumed.",
            "If not an authorized admin action, assume compromise of that host and escalate.",
        ],
    },
    {
        "id": "firewall_probe_pattern",
        "name": "Blocked traffic followed by an allowed connection",
        "category": "Network attacks",
        "severity": "error",
        "description": "A source that generated many firewall denies and then an allowed "
                       "connection — probing that eventually found an open door. More "
                       "actionable than deny-bursts alone, because something got through.",
        "params": {
            "type": "sequence",
            "pattern": r"denied|deny|blocked|drop",
            "pattern_b": r"allowed|accept|permitted|built.*connection",
            "group_by": "source_ip",
            "min_a_count": 10,
            "max_gap_seconds": 3600,
            "window_minutes": 1440,
        },
        "response_steps": [
            "Identify which port/service the allowed connection reached — that is the open door the probing found.",
            "Decide whether that service should be exposed to this source at all; tighten the firewall rule if not.",
            "Review the destination host's logs after the allowed connection for exploitation attempts.",
            "Add the source IP as an IOC (Threat Intel page) if it is not a known scanner/partner.",
        ],
    },
]


def get_playbook(playbook_id: str):
    for pb in PLAYBOOKS:
        if pb["id"] == playbook_id:
            return pb
    return None