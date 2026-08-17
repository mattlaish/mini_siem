"""
mini-SIEM automation workers
============================
Three background loops that live in the dashboard process, all following
the same pattern as the AI triage worker (poll the DB, act, record):

  ReportScheduler — runs all playbooks over a window and saves the
      results as a report. On demand from the Correlate page, or
      automatically weekly/monthly (schedule stored in app_config).

  TicketWorker — watches for new alerts at/above a severity threshold
      and POSTs each one to your ticketing system's REST API (Jira,
      ServiceNow, Zammad, osTicket, generic webhook...). The alert row
      records the ticket status/reference so nothing is sent twice.
      Uses a JSON body template with {{placeholders}} so it can match
      whatever shape your ticket API expects.

  FeedRefresher — re-downloads enabled IOC feeds (Threat Intel page)
      on their configured interval and imports new indicators.

All outbound calls (tickets, feeds) use stdlib urllib — no new deps.
NOTE: tickets and feeds are OUTBOUND connections from the SIEM. That is
the point of the feature, but be deliberate about what the SIEM is
allowed to reach.
"""

import base64
import json
import threading
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone

import severity as severity_mod


def _now():
    return datetime.now(timezone.utc).isoformat()


def _http(url, method="GET", headers=None, body=None, timeout=15, max_bytes=2000):
    """Minimal HTTP helper. Returns (status_code, response_text).
    max_bytes caps how much of the response we keep — the default (2000) is
    fine for webhook/API responses, but IOC feeds and other bulk downloads
    need it raised (or set to None for unlimited) or they'd be silently
    truncated mid-list."""
    req = urllib.request.Request(url, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    data = body.encode("utf-8") if isinstance(body, str) else body
    try:
        with urllib.request.urlopen(req, data=data, timeout=timeout) as resp:
            raw = resp.read()
            text = raw.decode("utf-8", "replace")
            return resp.status, (text if max_bytes is None else text[:max_bytes])
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", "replace")
        return e.code, (text if max_bytes is None else text[:max_bytes])


# ==========================================================================
# Playbook reports
# ==========================================================================

def run_playbook_report(conn, window_days: int = 7, trigger: str = "manual"):
    """Run every playbook over the window; save and return the report."""
    from correlations import PLAYBOOKS, run_correlation

    results = []
    findings = 0
    for pb in PLAYBOOKS:
        params = dict(pb["params"])
        params["window_minutes"] = window_days * 1440
        try:
            r = run_correlation(conn, params)
            hit = r.get("group_count", 0)
        except Exception as exc:
            r = {"error": f"{type(exc).__name__}: {exc}"}
            hit = 0
        findings += hit
        results.append({
            "id": pb["id"], "name": pb["name"], "category": pb.get("category", ""),
            "severity": pb.get("severity", ""), "group_count": hit,
            "groups": r.get("groups", [])[:20],
            "response_steps": pb.get("response_steps", []) if hit else [],
            "error": r.get("error"),
        })

    hits = [r for r in results if r["group_count"]]
    summary = (f"{findings} finding group(s) across {len(hits)} of {len(results)} playbooks"
               if findings else f"Clean: 0 findings across {len(results)} playbooks")
    report_id = conn.insert_returning_id(
        """INSERT INTO reports (created_at, kind, trigger, window_days, summary, findings, results_json)
           VALUES (?,?,?,?,?,?,?)""",
        (_now(), "playbooks", trigger, window_days, summary, findings,
         json.dumps(results)))
    conn.commit()
    return {"id": report_id, "created_at": _now(), "trigger": trigger,
            "window_days": window_days, "summary": summary,
            "findings": findings, "results": results}


class ReportScheduler:
    """Checks hourly whether a scheduled report is due.
    app_config: report_schedule = off|weekly|monthly."""

    def __init__(self, get_conn, get_schedule, on_report=None, check_interval=3600):
        self.get_conn = get_conn
        self.get_schedule = get_schedule       # () -> "off"|"weekly"|"monthly"
        self.on_report = on_report             # optional callback(report_dict)
        self.check_interval = check_interval
        self._stop = threading.Event()

    def start(self):
        threading.Thread(target=self._loop, daemon=True).start()
        print("[reports] scheduler started")

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.run_if_due()
            except Exception as exc:
                print(f"[reports] scheduler error: {exc}")
            self._stop.wait(self.check_interval)

    def run_if_due(self):
        schedule = (self.get_schedule() or "off").lower()
        if schedule not in ("weekly", "monthly"):
            return None
        period_days = 7 if schedule == "weekly" else 30
        conn = self.get_conn()
        try:
            row = conn.execute(
                "SELECT created_at FROM reports WHERE trigger=? ORDER BY id DESC LIMIT 1",
                (schedule,)).fetchone()
            if row:
                last = datetime.fromisoformat(row["created_at"])
                age_days = (datetime.now(timezone.utc) - last).total_seconds() / 86400
                if age_days < period_days:
                    return None
            report = run_playbook_report(conn, window_days=period_days, trigger=schedule)
            print(f"[reports] scheduled {schedule} report #{report['id']}: {report['summary']}")
            if self.on_report:
                try:
                    self.on_report(report)
                except Exception as exc:
                    print(f"[reports] on_report callback failed: {exc}")
            return report
        finally:
            conn.close()


# ==========================================================================
# Ticket dispatch
# ==========================================================================

DEFAULT_TICKET_TEMPLATE = json.dumps({
    "title": "[mini-SIEM] {{rule_name}} ({{severity}})",
    "description": "{{description}}\n\nSource: {{source_ip}}\nTime: {{created_at}}\nAlert ID: {{id}}\nRelated log IDs: {{log_ids}}\n\nAI analysis:\n{{ai_analysis}}",
    "severity": "{{severity}}",
}, indent=2)


def render_template(template: str, alert: dict) -> str:
    out = template
    for key in ("id", "created_at", "rule_name", "severity", "source_ip",
                "description", "log_ids", "ai_analysis"):
        val = str(alert.get(key) or "")
        # keep the JSON template valid: escape the value as a JSON string body
        escaped = json.dumps(val)[1:-1]
        out = out.replace("{{%s}}" % key, escaped)
    return out


class TicketWorker:
    """Sends qualifying alerts to a ticket API. get_settings() returns:
    {enabled, url, method, headers(dict), template(str), min_severity}."""

    def __init__(self, get_conn, get_settings, poll_interval=10, batch=5, max_attempts=3):
        self.get_conn = get_conn
        self.get_settings = get_settings
        self.poll_interval = poll_interval
        self.batch = batch
        self.max_attempts = max_attempts
        self._stop = threading.Event()

    def start(self):
        threading.Thread(target=self._loop, daemon=True).start()
        print("[tickets] dispatcher started")

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            self._stop.wait(self.poll_interval)
            if self._stop.is_set():
                break
            try:
                self.run_once()
            except Exception as exc:
                print(f"[tickets] cycle error: {exc}")

    def run_once(self) -> int:
        st = self.get_settings()
        if not st.get("enabled") or not st.get("url"):
            return 0
        min_idx = severity_mod.index_of(st.get("min_severity") or "warning")
        conn = self.get_conn()
        sent = 0
        try:
            rows = conn.execute(
                """SELECT * FROM alerts
                   WHERE (ticket_status IS NULL OR ticket_status = '')
                     AND (ticket_attempts IS NULL OR ticket_attempts < ?)
                   ORDER BY id ASC LIMIT ?""",
                (self.max_attempts, self.batch)).fetchall()
            for alert in rows:
                a = dict(alert)
                a_idx = severity_mod.index_of(a.get("severity") or "")
                if a_idx is None or a_idx > min_idx:
                    conn.execute("UPDATE alerts SET ticket_status='skipped' WHERE id=?", (a["id"],))
                    conn.commit()
                    continue
                body = render_template(st.get("template") or DEFAULT_TICKET_TEMPLATE, a)
                headers = dict(st.get("headers") or {})
                headers.setdefault("Content-Type", "application/json")
                try:
                    code, text = _http(st["url"], method=st.get("method") or "POST",
                                       headers=headers, body=body)
                    if 200 <= code < 300:
                        # try to pull a ticket id/key/number from the response
                        ref = ""
                        try:
                            j = json.loads(text)
                            for k in ("key", "id", "number", "ticket_id", "sys_id"):
                                if isinstance(j, dict) and j.get(k):
                                    ref = str(j[k]); break
                        except Exception:
                            pass
                        conn.execute(
                            "UPDATE alerts SET ticket_status='created', ticket_ref=? WHERE id=?",
                            (ref, a["id"]))
                        conn.commit()
                        sent += 1
                        print(f"[tickets] alert #{a['id']} -> ticket {ref or 'created'} (HTTP {code})")
                    else:
                        raise RuntimeError(f"HTTP {code}: {text[:200]}")
                except Exception as exc:
                    attempts = (a.get("ticket_attempts") or 0) + 1
                    status = "error" if attempts >= self.max_attempts else ""
                    conn.execute(
                        "UPDATE alerts SET ticket_attempts=?, ticket_status=? WHERE id=?",
                        (attempts, status, a["id"]))
                    conn.commit()
                    print(f"[tickets] alert #{a['id']} attempt {attempts} failed: {exc}")
                    break  # endpoint likely down; retry next cycle
        finally:
            conn.close()
        return sent

    def send_test(self):
        """Send a sample payload; returns (ok, detail)."""
        st = self.get_settings()
        if not st.get("url"):
            return False, "No ticket API URL configured."
        sample = {"id": 0, "created_at": _now(), "rule_name": "test_connection",
                  "severity": "informational", "source_ip": "203.0.113.1",
                  "description": "mini-SIEM ticket API test — safe to close.",
                  "log_ids": "", "ai_analysis": ""}
        body = render_template(st.get("template") or DEFAULT_TICKET_TEMPLATE, sample)
        headers = dict(st.get("headers") or {})
        headers.setdefault("Content-Type", "application/json")
        try:
            code, text = _http(st["url"], method=st.get("method") or "POST",
                               headers=headers, body=body)
            ok = 200 <= code < 300
            return ok, f"HTTP {code}: {text[:300]}"
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"


# ==========================================================================
# IOC feed refresh
# ==========================================================================

def _feed_auth(feed: dict, resolve_key_fn=None):
    """Build (url, headers) for a feed request per its auth_scheme. Covers
    the common IOC-feed auth patterns in the wild:
      none          - no auth (today's default; many CSV/plaintext feeds)
      header        - static header key, e.g. AlienVault OTX's
                      X-OTX-API-KEY, abuse.ch's Auth-Key, VirusTotal's
                      x-apikey, Recorded Future's X-RFToken
      authorization - the raw key IN the Authorization header with no
                      'Bearer' prefix (MISP's convention — NOT standard
                      OAuth, easy to get wrong by adding 'Bearer ')
      query_param   - key appended to the URL (Shodan-style, ?key=...)
      basic         - HTTP Basic auth, key as username (IBM X-Force style)
    A feed needing full OAuth2 client-credentials (e.g. CrowdStrike Falcon
    Intel) is better modeled as an API poller (Setup -> API poller
    connectors) since that flow already exists there — token endpoints and
    IOC endpoints are usually the same infrastructure per vendor.
    """
    scheme = (feed.get("auth_scheme") or "none").lower()
    url = feed["url"]
    headers = {"User-Agent": "mini-SIEM feed fetcher"}
    if scheme == "none":
        return url, headers
    key = resolve_key_fn(feed) if resolve_key_fn else ""
    if scheme == "header":
        name = feed.get("header_name") or "Authorization"
        prefix = feed.get("header_prefix") or ""
        headers[name] = f"{prefix}{key}" if prefix else key
    elif scheme == "authorization":
        headers["Authorization"] = key  # raw key, no Bearer prefix (MISP)
    elif scheme == "query_param":
        param = feed.get("query_param") or "key"
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{urllib.parse.quote(param)}={urllib.parse.quote(key)}"
    elif scheme == "basic":
        user = feed.get("basic_user") or ""
        token = base64.b64encode(f"{user}:{key}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {token}"
    return url, headers


def fetch_feed(conn, feed: dict, resolve_key_fn=None):
    """Download one feed URL, import new indicators. Returns dict result.
    resolve_key_fn(feed) -> plaintext API key/token, if the feed needs one
    (caller decrypts from key_encrypted — see dashboard._resolve_feed_key)."""
    import threatintel as ti
    try:
        url, headers = _feed_auth(feed, resolve_key_fn)
        # max_bytes=None: feeds can be thousands of lines; the 2000-char
        # default (meant for short webhook responses) would silently drop
        # most of the indicator list.
        code, text = _http(url, method="GET", headers=headers, max_bytes=None)
        if not (200 <= code < 300):
            raise RuntimeError(f"HTTP {code}")
    except Exception as exc:
        conn.execute("UPDATE ioc_feeds SET last_fetch_at=?, last_status=? WHERE id=?",
                     (_now(), f"error: {exc}", feed["id"]))
        conn.commit()
        return {"ok": False, "error": str(exc)}

    parsed = ti.parse_feed_text(
        text, default_type=feed.get("default_type") or "",
        default_threat=feed.get("threat") or "",
        source=feed["name"], severity=feed.get("severity") or "warning")
    added, skipped = 0, 0
    for item in parsed:
        dup = conn.execute("SELECT id FROM iocs WHERE ioc_type=? AND value_norm=?",
                           (item["ioc_type"], item["value_norm"])).fetchone()
        if dup:
            skipped += 1
            continue
        conn.execute(
            """INSERT INTO iocs (ioc_type, value, value_norm, threat, source, severity, enabled, created_at)
               VALUES (?,?,?,?,?,?,1,?)""",
            (item["ioc_type"], item["value"], item["value_norm"], item["threat"],
             item["source"], item["severity"], _now()))
        added += 1
    conn.execute(
        "UPDATE ioc_feeds SET last_fetch_at=?, last_status=?, last_added=? WHERE id=?",
        (_now(), f"ok: {added} added, {skipped} duplicates", added, feed["id"]))
    conn.commit()
    return {"ok": True, "added": added, "skipped_duplicates": skipped,
            "parsed": len(parsed)}


class FeedRefresher:
    """Re-fetches enabled feeds whose refresh interval has elapsed."""

    def __init__(self, get_conn, check_interval=600, resolve_key_fn=None):
        self.get_conn = get_conn
        self.check_interval = check_interval
        self.resolve_key_fn = resolve_key_fn
        self._stop = threading.Event()

    def start(self):
        threading.Thread(target=self._loop, daemon=True).start()
        print("[feeds] refresher started")

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            self._stop.wait(self.check_interval)
            if self._stop.is_set():
                break
            try:
                self.run_once()
            except Exception as exc:
                print(f"[feeds] cycle error: {exc}")

    def run_once(self):
        conn = self.get_conn()
        try:
            feeds = [dict(r) for r in conn.execute(
                "SELECT * FROM ioc_feeds WHERE enabled=1 AND refresh_hours > 0").fetchall()]
            for feed in feeds:
                due = True
                if feed.get("last_fetch_at"):
                    last = datetime.fromisoformat(feed["last_fetch_at"])
                    age_h = (datetime.now(timezone.utc) - last).total_seconds() / 3600
                    due = age_h >= feed["refresh_hours"]
                if due:
                    r = fetch_feed(conn, feed, resolve_key_fn=self.resolve_key_fn)
                    print(f"[feeds] refreshed '{feed['name']}': {r}")
        finally:
            conn.close()
