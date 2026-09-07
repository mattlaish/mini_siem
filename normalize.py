"""
mini-SIEM field normalization
=============================
Shared message-field extraction, plus the ingest-time indexer that
materializes extracted fields into the `log_fields` table so searching,
filtering, and sorting by extracted fields uses indexed lookups instead
of re-running regex over message text at query time.

log_fields rows: (log_id, field, value, value_norm). ``value`` preserves
display text while lowercase ``value_norm`` serves exact/prefix indexed filters.
One row per extracted field per log. Same database as
everything else (SQLite or PostgreSQL) — no second DB required.

Extraction sources (same as the on-demand normalizer):
  * automatic key=value / key: value pairs in the message
  * user-defined regex patterns with named groups, stored in
    app_config key 'norm_patterns' (JSON list) and hot-reloaded every
    few seconds, so newly saved patterns apply to new logs without a
    restart. Pattern changes do NOT rewrite already-indexed logs —
    use the re-index (backfill) action for that.
"""

import json
import re
import threading
import time

_KV_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9_.\-]{0,40})\s*[=:]\s*(\"[^\"]*\"|[^\s,;]+)")


def extract_fields(msg: str, patterns, json_obj=None) -> dict:
    """Extract fields from one message: auto kv pairs + named groups
    from the given regex pattern strings. If json_obj (a pre-parsed dict,
    e.g. from an NXLog to_json() event) is provided, its keys are used
    directly as fields instead of regex-splitting the serialized text —
    this avoids mangling JSON payloads into whitespace fragments.

    Note: cross-source identity resolution (treating Fortigate's src= and
    Sophos's endpoint_ip as "the same kind of thing" for search) is handled
    at QUERY TIME in dashboard.py's search-alias config (Setup -> Search
    field aliases), not here at ingest time — so it applies to historical
    data immediately and is admin-editable without a reindex."""
    fields = {}
    if isinstance(json_obj, dict):
        # flatten one level; stringify scalars, json-encode nested values
        for k, v in json_obj.items():
            if v is None:
                continue
            key = str(k).lower()
            if isinstance(v, (dict, list)):
                fields[key] = json.dumps(v, ensure_ascii=False)
            else:
                fields[key] = str(v)
        return fields
    msg = str(msg or "")
    for m in _KV_RE.finditer(msg):
        k, v = m.group(1), m.group(2).strip('"')
        if k.lower() not in fields:
            fields[k.lower()] = v
    for p in patterns or []:
        try:
            m = re.search(p, msg)
            if m:
                for k, v in (m.groupdict() or {}).items():
                    if v is not None:
                        fields[k] = v
        except re.error:
            continue
    return fields


def load_patterns_from_conn(conn) -> list:
    """Read the saved custom patterns from app_config via any db
    Connection (works under Storage.lock or a dashboard conn)."""
    try:
        row = conn.execute(
            "SELECT value FROM app_config WHERE key='norm_patterns'").fetchone()
        if row and row["value"]:
            pats = json.loads(row["value"])
            return pats if isinstance(pats, list) else []
    except Exception:
        pass
    return []


def field_rows(log_id: int, fields: dict):
    """Return display + normalized DB rows for one log's extracted fields."""
    rows = []
    for k, v in fields.items():
        value = str(v)[:300]
        rows.append((log_id, k[:60], value, value.lower()))
    return rows


def write_fields(conn, log_id: int, fields: dict):
    """Insert extracted fields for one log with one driver call.

    The caller owns transaction/locking semantics. Using ``executemany`` here
    avoids one Python/driver round-trip per extracted field.
    """
    rows = field_rows(log_id, fields)
    if rows:
        conn.executemany(
            "INSERT INTO log_fields (log_id, field, value, value_norm) VALUES (?,?,?,?)", rows)
    return len(rows)


class FieldIndexer:
    """Ingest-pipeline component: extracts fields from each event and
    materializes them into log_fields. Patterns hot-reload every
    reload_interval seconds (same pattern as the IOC matcher)."""

    def __init__(self, storage, reload_interval: int = 5):
        self.storage = storage
        self.reload_interval = reload_interval
        self._patterns = []
        self._stop = threading.Event()
        self._reload()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="field-index-reload")
        self._thread.start()

    def _loop(self):
        while not self._stop.wait(self.reload_interval):
            try:
                self._reload()
            except Exception as exc:
                print(f"[fields] pattern reload failed: {exc}")

    def stop(self):
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=2)

    def extract(self, event: dict) -> dict:
        """Extract fields without taking the storage lock.

        The listener uses this before persistence so the log row and its field
        rows can be written atomically under one storage-lock acquisition.
        """
        patterns = self._patterns
        return extract_fields(event.get("message"), patterns, json_obj=event.get("_json"))

    def _reload(self):
        with self.storage.lock:
            self._patterns = load_patterns_from_conn(self.storage.conn)
            # Refresh source profiles and hand them to the listener's parser
            # so JSON field mapping picks up UI edits without a restart.
            try:
                import profiles as _profiles_mod
                import listener as _listener_mod
                profs = _profiles_mod.load_profiles(self.storage.conn)
                _listener_mod.set_profiles(profs)
            except Exception as exc:
                print(f"[profiles] reload failed: {exc}")

    def process(self, log_id: int, event: dict) -> int:
        """Extract and store fields for one event. Returns field count.

        Kept for callers outside the main listener pipeline. Field writes use
        Storage's batched-commit path; this method never commits per event.
        """
        fields = self.extract(event)
        try:
            self.capture_unidentified(log_id, event, len(fields))
        except Exception:
            pass
        if not fields:
            return 0
        self.storage.write_log_fields(log_id, fields)
        return len(fields)

    def capture_unidentified(self, log_id: int, event: dict, field_count: int):
        """Public wrapper used when fields were persisted atomically with log."""
        return self._maybe_capture_unidentified(log_id, event, field_count)

    def _maybe_capture_unidentified(self, log_id, event, field_count):
        """Record the most recent poorly-mapped JSON event in app_config under
        'last_unidentified_log'. Only JSON events qualify (syslog parses fine
        via RFC rules). A JSON event is 'unidentified' when it matched no
        profile, or a key field came out blank, or nothing was extracted."""
        if event.get("format") != "json":
            return
        host = (event.get("hostname") or "").strip()
        msg = (event.get("message") or "").strip()
        matched = event.get("_profile")
        reasons = []
        if not matched:
            reasons.append("no source profile matched")
        if not host:
            reasons.append("host is blank")
        if not msg or msg.startswith("EventID=") and msg.strip() == "EventID=":
            reasons.append("message is blank")
        if field_count == 0:
            reasons.append("no fields extracted")
        if not reasons:
            return  # mapped fine — not unidentified
        import json as _json
        payload = {
            "log_id": log_id,
            "at": event.get("received_at", ""),
            "source": event.get("source_ip", ""),
            "raw": event.get("raw", ""),
            "reasons": reasons,
            "matched_profile": matched,
            "keys": sorted(list(event.get("_json", {}).keys()))
                    if isinstance(event.get("_json"), dict) else [],
        }
        sql = (
            "INSERT INTO app_config(key,value) VALUES('last_unidentified_log',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value"
        )
        params = (_json.dumps(payload, ensure_ascii=False),)
        self.storage.execute_batched(sql, params)


def reindex(conn, batch_size: int = 500, progress=None):
    """Backfill/refresh log_fields for ALL logs using the currently
    saved patterns. Replaces each log's rows. Returns (logs, fields)."""
    patterns = load_patterns_from_conn(conn)
    row = conn.execute("SELECT MAX(id) AS m FROM logs").fetchone()
    max_id = (row["m"] if row else None) or 0
    done_logs, done_fields = 0, 0
    last_id = 0
    while last_id < max_id:
        rows = conn.execute(
            "SELECT id, message FROM logs WHERE id > ? ORDER BY id ASC LIMIT ?",
            (last_id, batch_size)).fetchall()
        if not rows:
            break
        delete_rows = []
        insert_rows = []
        for r in rows:
            last_id = r["id"]
            delete_rows.append((r["id"],))
            fields = extract_fields(r["message"], patterns)
            if fields:
                new_rows = field_rows(r["id"], fields)
                insert_rows.extend(new_rows)
                done_fields += len(new_rows)
            done_logs += 1
        if delete_rows:
            conn.executemany("DELETE FROM log_fields WHERE log_id=?", delete_rows)
        if insert_rows:
            conn.executemany(
                "INSERT INTO log_fields (log_id, field, value, value_norm) VALUES (?,?,?,?)",
                insert_rows,
            )
        conn.commit()
        if progress:
            progress(done_logs, last_id, max_id)
    return done_logs, done_fields
