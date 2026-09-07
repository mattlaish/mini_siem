"""Evidence-preserving archive lifecycle for mini-SIEM.

The hot database is never age-deleted.  Eligible events are copied into sealed,
checksummed SQLite archive segments.  Archive segments use exact payload
content-addressing: every occurrence keeps its original log id and received_at,
while identical event payloads (including raw text and extracted fields) are
stored once.  ``mode=move`` may evict the *hot copy* only after a segment is
committed, compacted, checksummed, cataloged, reopened, and verified.  The
archived occurrence remains queryable through normal Log Search.

This is intentionally lossless deduplication.  It does not collapse merely
similar security events, because repetition can itself be detection evidence.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
import zlib

import db as dbmod
from sql_helpers import delete_in, select_in


class ArchiveError(RuntimeError):
    pass


class ArchiveSearchError(ArchiveError):
    pass


def _utc_now():
    return datetime.now(timezone.utc)


def _cfg(config):
    base = {
        "enabled": False,
        "directory": "archive",
        "hot_days": 30,
        "mode": "copy",
        "batch_rows": 500,
        "max_batches_per_cycle": 20,
        "run_interval_seconds": 3600,
        "verify_on_create": True,
    }
    base.update((config or {}).get("archive") or {})
    mode = str(base.get("mode") or "copy").strip().lower()
    base["mode"] = mode if mode in ("copy", "move") else "copy"
    return base


def _bounded_int(value, default, lo, hi):
    try:
        return max(lo, min(int(value), hi))
    except (TypeError, ValueError):
        return default


def _archive_dir(config):
    path = Path(str(_cfg(config).get("directory") or "archive")).expanduser()
    if not path.is_absolute():
        path = (Path(__file__).resolve().parent / path).resolve()
    return path


def _archive_unzip(blob):
    if blob is None:
        return ""
    try:
        data = bytes(blob)
        return zlib.decompress(data).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _segment_schema(conn):
    conn.create_function("archive_unzip", 1, _archive_unzip)
    conn.executescript(
        """
        PRAGMA journal_mode=DELETE;
        PRAGMA synchronous=FULL;
        PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS archive_payloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL UNIQUE,
            source_ip TEXT,
            peer_ip TEXT,
            format TEXT,
            priority INTEGER,
            facility TEXT,
            severity TEXT,
            device_timestamp TEXT,
            hostname TEXT,
            destination TEXT,
            app_name TEXT,
            proc_id TEXT,
            msg_id TEXT,
            message TEXT,
            raw_z BLOB NOT NULL,
            raw_len INTEGER NOT NULL DEFAULT 0,
            field_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_ap_source ON archive_payloads(source_ip COLLATE NOCASE);
        CREATE INDEX IF NOT EXISTS idx_ap_host ON archive_payloads(hostname COLLATE NOCASE);
        CREATE INDEX IF NOT EXISTS idx_ap_dest ON archive_payloads(destination COLLATE NOCASE);
        CREATE INDEX IF NOT EXISTS idx_ap_sev ON archive_payloads(severity);
        CREATE TABLE IF NOT EXISTS archive_occurrences (
            id INTEGER PRIMARY KEY,
            received_at TEXT NOT NULL,
            payload_id INTEGER NOT NULL REFERENCES archive_payloads(id)
        );
        CREATE INDEX IF NOT EXISTS idx_ao_received_id ON archive_occurrences(received_at,id);
        CREATE INDEX IF NOT EXISTS idx_ao_payload ON archive_occurrences(payload_id);
        CREATE TABLE IF NOT EXISTS archive_payload_fields (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload_id INTEGER NOT NULL REFERENCES archive_payloads(id),
            field TEXT NOT NULL,
            value TEXT,
            value_norm TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_apf_payload ON archive_payload_fields(payload_id);
        CREATE INDEX IF NOT EXISTS idx_apf_field_value_norm
          ON archive_payload_fields(field, value_norm COLLATE NOCASE, payload_id);
        DROP VIEW IF EXISTS logs;
        CREATE VIEW logs AS
          SELECT o.id AS id, o.received_at AS received_at,
                 p.source_ip, p.peer_ip, p.format, p.priority, p.facility,
                 p.severity, p.device_timestamp, p.hostname, p.destination,
                 p.app_name, p.proc_id, p.msg_id, p.message,
                 archive_unzip(p.raw_z) AS raw, p.id AS payload_id
          FROM archive_occurrences o JOIN archive_payloads p ON p.id=o.payload_id;
        DROP VIEW IF EXISTS log_fields;
        CREATE VIEW log_fields AS
          SELECT pf.id AS id, o.id AS log_id, pf.field, pf.value, pf.value_norm
          FROM archive_occurrences o
          JOIN archive_payload_fields pf ON pf.payload_id=o.payload_id;
        """
    )
    try:
        conn.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS archive_payloads_fts USING fts5("
            "message, content='archive_payloads', content_rowid='id', tokenize='unicode61')"
        )
        conn.executescript(
            """
            CREATE TRIGGER IF NOT EXISTS archive_payloads_ai AFTER INSERT ON archive_payloads BEGIN
              INSERT INTO archive_payloads_fts(rowid,message) VALUES(new.id,new.message);
            END;
            CREATE TRIGGER IF NOT EXISTS archive_payloads_ad AFTER DELETE ON archive_payloads BEGIN
              INSERT INTO archive_payloads_fts(archive_payloads_fts,rowid,message)
              VALUES('delete',old.id,old.message);
            END;
            CREATE TRIGGER IF NOT EXISTS archive_payloads_au AFTER UPDATE ON archive_payloads BEGIN
              INSERT INTO archive_payloads_fts(archive_payloads_fts,rowid,message)
              VALUES('delete',old.id,old.message);
              INSERT INTO archive_payloads_fts(rowid,message) VALUES(new.id,new.message);
            END;
            """
        )
    except sqlite3.Error:
        # Search remains correct through LIKE if FTS5 is unavailable.
        pass
    conn.commit()


def open_archive(path, readonly=True):
    path = str(path)
    if readonly:
        raw = sqlite3.connect(f"file:{Path(path).resolve()}?mode=ro", uri=True, check_same_thread=False)
    else:
        raw = sqlite3.connect(path, check_same_thread=False)
    raw.row_factory = sqlite3.Row
    raw.create_function("archive_unzip", 1, _archive_unzip)
    try:
        raw.execute("PRAGMA query_only=ON" if readonly else "PRAGMA foreign_keys=ON")
    except sqlite3.Error:
        pass
    return dbmod.Connection(raw, "sqlite")


def archive_fts5_available(conn):
    try:
        conn.execute(
            "SELECT rowid FROM archive_payloads_fts WHERE archive_payloads_fts MATCH ? LIMIT 1",
            ("__archive_probe__",),
        ).fetchone()
        return True
    except Exception:
        return False


def _canonical_payload(row, fields):
    keys = (
        "source_ip", "peer_ip", "format", "priority", "facility", "severity",
        "device_timestamp", "hostname", "destination", "app_name", "proc_id",
        "msg_id", "message", "raw",
    )
    payload = {k: row[k] for k in keys}
    payload["fields"] = sorted(
        [(str(f["field"]), "" if f["value"] is None else str(f["value"])) for f in fields],
        key=lambda item: (item[0], item[1]),
    )
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), payload


def _insert_event(conn, row, fields):
    fingerprint, payload = _canonical_payload(row, fields)
    raw_text = "" if payload.get("raw") is None else str(payload.get("raw"))
    raw_z = sqlite3.Binary(zlib.compress(raw_text.encode("utf-8"), 6))
    conn.execute(
        """INSERT OR IGNORE INTO archive_payloads
           (fingerprint,source_ip,peer_ip,format,priority,facility,severity,
            device_timestamp,hostname,destination,app_name,proc_id,msg_id,message,
            raw_z,raw_len,field_count)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            fingerprint, payload.get("source_ip"), payload.get("peer_ip"),
            payload.get("format"), payload.get("priority"), payload.get("facility"),
            payload.get("severity"), payload.get("device_timestamp"),
            payload.get("hostname"), payload.get("destination"), payload.get("app_name"),
            payload.get("proc_id"), payload.get("msg_id"), payload.get("message"),
            raw_z, len(raw_text.encode("utf-8")), len(payload["fields"]),
        ),
    )
    prow = conn.execute(
        "SELECT id FROM archive_payloads WHERE fingerprint=?", (fingerprint,)
    ).fetchone()
    if prow is None:
        raise ArchiveError("archive payload insert verification failed")
    payload_id = int(prow["id"])
    have_fields = conn.execute(
        "SELECT 1 FROM archive_payload_fields WHERE payload_id=? LIMIT 1", (payload_id,)
    ).fetchone()
    if have_fields is None and payload["fields"]:
        conn.executemany(
            "INSERT INTO archive_payload_fields(payload_id,field,value,value_norm) VALUES (?,?,?,?)",
            [(payload_id, name, value, value.lower()) for name, value in payload["fields"]],
        )
    conn.execute(
        "INSERT OR IGNORE INTO archive_occurrences(id,received_at,payload_id) VALUES (?,?,?)",
        (int(row["id"]), str(row["received_at"]), payload_id),
    )
    return payload_id


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _manifest_path(segment_path):
    return str(segment_path) + ".manifest.json"


def _write_manifest(segment_path, meta):
    path = _manifest_path(segment_path)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o640)
    except OSError:
        pass
    return path


def _catalog_segment(storage, meta, ids):
    storage.conn.execute(
        """INSERT INTO archive_segments
           (segment_id,path,manifest_path,state,mode,created_at,start_at,end_at,
            min_log_id,max_log_id,event_count,unique_payloads,duplicate_occurrences,
            sha256,bytes)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(segment_id) DO UPDATE SET
             path=excluded.path,manifest_path=excluded.manifest_path,state=excluded.state,
             mode=excluded.mode,created_at=excluded.created_at,start_at=excluded.start_at,
             end_at=excluded.end_at,min_log_id=excluded.min_log_id,max_log_id=excluded.max_log_id,
             event_count=excluded.event_count,unique_payloads=excluded.unique_payloads,
             duplicate_occurrences=excluded.duplicate_occurrences,sha256=excluded.sha256,
             bytes=excluded.bytes""",
        (
            meta["segment_id"], meta["path"], meta["manifest_path"], "SEALED",
            meta["mode"], meta["created_at"], meta["start_at"], meta["end_at"],
            meta["min_log_id"], meta["max_log_id"], meta["event_count"],
            meta["unique_payloads"], meta["duplicate_occurrences"], meta["sha256"],
            meta["bytes"],
        ),
    )
    archived_at = _utc_now().isoformat()
    storage.conn.executemany(
        """INSERT INTO archive_occurrence_catalog(log_id,segment_id,archived_at)
           VALUES (?,?,?) ON CONFLICT(log_id) DO NOTHING""",
        [(int(log_id), meta["segment_id"], archived_at) for log_id in ids],
    )


def _load_fields(conn, ids):
    if not ids:
        return {}
    sql, params = select_in(
        "log_fields", "log_id,field,value", "log_id", ids,
        suffix=" ORDER BY log_id,field",
    )
    rows = conn.execute(sql, params).fetchall()
    out = {}
    for row in rows:
        out.setdefault(int(row["log_id"]), []).append(row)
    return out


def _remove_hot_copies_locked(storage, ids):
    if not ids:
        return 0
    total = 0
    for pos in range(0, len(ids), 500):
        chunk = ids[pos:pos + 500]
        fields_sql, fields_params = delete_in("log_fields", "log_id", chunk)
        logs_sql, logs_params = delete_in("logs", "id", chunk)
        storage.conn.execute(fields_sql, fields_params)
        cur = storage.conn.execute(logs_sql, logs_params)
        total += max(0, int(getattr(cur, "rowcount", 0) or 0))
    # total_logs / hourly / source_last_seen intentionally remain unchanged:
    # evidence still exists and remains searchable in the archive.
    return total


def _verify_segment(path, expected_ids=None, expected_sha=None):
    if expected_sha is not None and _sha256(path) != expected_sha:
        raise ArchiveError("archive segment checksum mismatch")
    conn = open_archive(path, readonly=True)
    try:
        if expected_ids:
            sql, params = select_in(
                "archive_occurrences", "COUNT(*) c", "id", expected_ids,
            )
            count = conn.execute(sql, params).fetchone()["c"]
            if int(count) != len(expected_ids):
                raise ArchiveError("archive occurrence verification failed")
        row = conn.execute("SELECT COUNT(*) c FROM archive_occurrences").fetchone()
        return int(row["c"] or 0)
    finally:
        conn.close()



def _evict_verified_existing_copies(storage, cutoff_iso, limit):
    """Evict hot duplicates already present in sealed archive segments.

    This makes a later operator transition from archive mode=copy to mode=move
    useful without re-archiving the same ids. Every referenced segment is
    checksum-verified before any hot row is removed.
    """
    with storage.lock:
        rows = storage.conn.execute(
            """SELECT l.id,ac.segment_id,s.path,s.sha256
               FROM logs l
               JOIN archive_occurrence_catalog ac ON ac.log_id=l.id
               JOIN archive_segments s ON s.segment_id=ac.segment_id AND s.state='SEALED'
               WHERE l.received_at < ?
               ORDER BY l.received_at ASC,l.id ASC LIMIT ?""",
            (cutoff_iso, int(limit)),
        ).fetchall()
    if not rows:
        return 0
    by_segment = {}
    for row in rows:
        by_segment.setdefault(row["segment_id"], {
            "path": row["path"], "sha256": row["sha256"], "ids": []
        })["ids"].append(int(row["id"]))
    for seg in by_segment.values():
        _verify_segment(seg["path"], expected_ids=seg["ids"], expected_sha=seg["sha256"])
    ids = [int(r["id"]) for r in rows]
    with storage.lock:
        try:
            removed = _remove_hot_copies_locked(storage, ids)
            storage.conn.commit()
            storage._pending = 0
            storage._last_commit = time.time()
            return removed
        except Exception:
            storage.rollback_locked()
            raise

def run_archive_cycle(storage, config, now=None):
    """Create at most one immutable archive segment from eligible hot events."""
    now = now or _utc_now()
    cfg = _cfg(config)
    enabled = bool(cfg.get("enabled", False))
    hot_days = _bounded_int(cfg.get("hot_days"), 30, 1, 3650)
    batch_rows = _bounded_int(cfg.get("batch_rows"), 500, 10, 5000)
    max_batches = _bounded_int(cfg.get("max_batches_per_cycle"), 20, 1, 1000)
    max_rows = min(batch_rows * max_batches, 100000)
    mode = cfg.get("mode", "copy")
    cutoff = now - timedelta(days=hot_days)
    status = {
        "enabled": enabled,
        "mode": mode,
        "hot_days": hot_days,
        "cutoff": cutoff.isoformat(),
        "started_at": now.isoformat(),
        "archived_events": 0,
        "unique_payloads": 0,
        "duplicate_occurrences": 0,
        "hot_evicted": 0,
        "hot_evicted_existing": 0,
        "segment_id": None,
        "segment_path": None,
        "error": "",
    }
    if not enabled:
        status["finished_at"] = _utc_now().isoformat()
        return status

    segment_path = None
    try:
        if mode == "move":
            status["hot_evicted_existing"] = _evict_verified_existing_copies(
                storage, cutoff.isoformat(), max_rows)
        with storage.lock:
            if getattr(storage, "_pending", 0) > 0:
                storage.commit_locked()
            rows = storage.conn.execute(
                """SELECT id,received_at,source_ip,peer_ip,format,priority,facility,severity,
                          device_timestamp,hostname,destination,app_name,proc_id,msg_id,message,raw
                   FROM logs l WHERE received_at < ?
                     AND NOT EXISTS (SELECT 1 FROM archive_occurrence_catalog ac WHERE ac.log_id=l.id)
                   ORDER BY received_at ASC,id ASC LIMIT ?""",
                (cutoff.isoformat(), max_rows),
            ).fetchall()
            ids = [int(r["id"]) for r in rows]
            fields = _load_fields(storage.conn, ids)
        if not rows:
            status["finished_at"] = _utc_now().isoformat()
            return status

        archive_dir = _archive_dir(config)
        existed = archive_dir.exists()
        archive_dir.mkdir(parents=True, exist_ok=True)
        if not existed:
            try:
                os.chmod(archive_dir, 0o750)
            except OSError:
                pass
        created = _utc_now()
        segment_id = (
            created.strftime("%Y%m%dT%H%M%S.%fZ")
            + f"-{ids[0]}-{ids[-1]}"
        )
        segment_path = archive_dir / f"segment-{segment_id}.sqlite3"
        raw = sqlite3.connect(str(segment_path))
        raw.row_factory = sqlite3.Row
        try:
            _segment_schema(raw)
            raw.execute("BEGIN IMMEDIATE")
            for row in rows:
                _insert_event(raw, row, fields.get(int(row["id"]), []))
            raw.commit()
            counts = raw.execute(
                "SELECT (SELECT COUNT(*) FROM archive_occurrences) occurrences, "
                "(SELECT COUNT(*) FROM archive_payloads) payloads"
            ).fetchone()
            occurrences = int(counts["occurrences"] or 0)
            payloads = int(counts["payloads"] or 0)
            if occurrences != len(rows):
                raise ArchiveError("archive segment occurrence count mismatch")
            # VACUUM is safe here: this is a private offline segment being sealed,
            # never the live SIEM database.
            raw.execute("VACUUM")
            raw.commit()
        finally:
            raw.close()

        try:
            os.chmod(segment_path, 0o640)
        except OSError:
            pass
        digest = _sha256(segment_path)
        meta = {
            "format": "mini-siem-archive-v1",
            "segment_id": segment_id,
            "path": str(segment_path.resolve()),
            "mode": mode,
            "created_at": created.isoformat(),
            "start_at": str(rows[0]["received_at"]),
            "end_at": str(rows[-1]["received_at"]),
            "min_log_id": min(ids),
            "max_log_id": max(ids),
            "event_count": len(rows),
            "unique_payloads": payloads,
            "duplicate_occurrences": len(rows) - payloads,
            "sha256": digest,
            "bytes": os.path.getsize(segment_path),
        }
        meta["manifest_path"] = _write_manifest(segment_path, meta)
        if bool(cfg.get("verify_on_create", True)):
            _verify_segment(segment_path, expected_ids=ids, expected_sha=digest)

        with storage.lock:
            try:
                _catalog_segment(storage, meta, ids)
                if mode == "move":
                    # The segment is already sealed and verified. A crash before
                    # this commit leaves duplicate hot+archive copies, never lost
                    # evidence; the unique occurrence id makes a retry idempotent.
                    status["hot_evicted"] = _remove_hot_copies_locked(storage, ids)
                dbmod.runtime_stat_upsert(
                    storage.conn, "archive_status", value_text=json.dumps(meta, separators=(",", ":"), sort_keys=True),
                    updated_at=_utc_now().isoformat(),
                )
                storage.conn.commit()
                storage._pending = 0
                storage._last_commit = time.time()
            except Exception:
                storage.rollback_locked()
                raise

        status.update({
            "archived_events": len(rows),
            "unique_payloads": payloads,
            "duplicate_occurrences": len(rows) - payloads,
            "segment_id": segment_id,
            "segment_path": str(segment_path.resolve()),
            "sha256": digest,
            "bytes": meta["bytes"],
        })
    except Exception as exc:
        status["error"] = f"{type(exc).__name__}: {exc}"
        # An un-cataloged partial segment is not evidence authority. Keep it for
        # operator forensics rather than deleting it automatically.
        if segment_path is not None:
            status["partial_segment"] = str(segment_path)
    status["finished_at"] = _utc_now().isoformat()
    return status


def list_segments(conn, time_from=None, time_to=None, ids=None):
    clauses = ["state='SEALED'"]
    params = []
    if time_from:
        clauses.append("end_at >= ?")
        params.append(str(time_from))
    if time_to:
        clauses.append("start_at <= ?")
        params.append(str(time_to))
    if ids:
        vals = [int(v) for v in ids if int(v) > 0]
        if vals:
            ph = ",".join("?" for _ in vals)
            clauses.append("segment_id IN (SELECT segment_id FROM archive_occurrence_catalog WHERE log_id IN (" + ph + "))")
            params.extend(vals)
    sql = (
        "SELECT segment_id,path,manifest_path,start_at,end_at,min_log_id,max_log_id,"
        "event_count,unique_payloads,duplicate_occurrences,sha256,bytes,mode "
        "FROM archive_segments WHERE " + " AND ".join(clauses) + " ORDER BY end_at DESC"
    )
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def archive_summary(conn):
    row = conn.execute(
        """SELECT COUNT(*) segments, COALESCE(SUM(event_count),0) archived_events,
                  COALESCE(SUM(unique_payloads),0) unique_payloads,
                  COALESCE(SUM(duplicate_occurrences),0) duplicate_occurrences,
                  COALESCE(SUM(bytes),0) bytes,
                  MIN(start_at) oldest, MAX(end_at) newest
           FROM archive_segments WHERE state='SEALED'"""
    ).fetchone()
    return dict(row) if row else {
        "segments": 0, "archived_events": 0, "unique_payloads": 0,
        "duplicate_occurrences": 0, "bytes": 0, "oldest": None, "newest": None,
    }


def verify_catalog(conn):
    """Verify every cataloged segment checksum. Intended for operator jobs."""
    results = []
    for seg in list_segments(conn):
        ok = False
        error = ""
        try:
            _verify_segment(seg["path"], expected_sha=seg["sha256"])
            ok = True
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        results.append({"segment_id": seg["segment_id"], "ok": ok, "error": error})
    return results
