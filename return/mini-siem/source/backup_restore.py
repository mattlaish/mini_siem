"""Backup/restore integrity primitives used by SQLite and PostgreSQL workflows."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import os
import sqlite3
import tempfile
import uuid


@dataclass
class BackupManifest:
    backup_id: str
    schema_version: str
    contains_secrets: bool = False
    backend: str = ""
    created_at_utc: str = ""
    sha256: str = ""
    source_database: str = ""
    source_owner: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_backup(path: str | Path, expected_sha256: str) -> bool:
    return bool(expected_sha256) and sha256_file(path) == expected_sha256.lower()


def write_manifest(path: str | Path, payload: dict, mode: int = 0o600) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, target)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def read_manifest(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise RuntimeError("backup manifest must be a JSON object")
    return data


def sqlite_integrity_check(path: str | Path) -> tuple[bool, str]:
    """Run a full integrity check against a SQLite backup copy."""
    target = Path(path)
    if not target.is_file():
        return False, f"backup file not found: {target}"
    conn = sqlite3.connect(str(target))
    try:
        rows = conn.execute("PRAGMA integrity_check").fetchall()
    finally:
        conn.close()
    detail = "; ".join(str(row[0]) for row in rows) if rows else "no integrity result"
    return rows == [("ok",)], detail


def create_sqlite_backup(source: str | Path, backup_dir: str | Path, *, keep: int = 14,
                         prefix: str = "siem") -> dict:
    """Create and verify a WAL-safe SQLite online backup.

    The destination is created with an exclusive random suffix so concurrent
    operator/API requests cannot overwrite a prior backup.  Rotation occurs
    only after the new copy passes a full integrity check.
    """
    src_path = Path(source).resolve()
    out_dir = Path(backup_dir).resolve()
    if not src_path.is_file():
        raise RuntimeError(f"SQLite source database not found: {src_path}")
    if isinstance(keep, bool) or not isinstance(keep, int) or keep < 1:
        raise RuntimeError("SQLite backup retention must be a positive integer")

    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    fd, raw_dest = tempfile.mkstemp(
        prefix=f"{prefix}-{stamp}-{uuid.uuid4().hex[:8]}-",
        suffix=".db",
        dir=str(out_dir),
    )
    os.close(fd)
    dest = Path(raw_dest)
    os.chmod(dest, 0o600)

    src_conn = None
    dst_conn = None
    try:
        src_conn = sqlite3.connect(str(src_path))
        dst_conn = sqlite3.connect(str(dest))
        with dst_conn:
            src_conn.backup(dst_conn)
    except Exception:
        dest.unlink(missing_ok=True)
        raise
    finally:
        if dst_conn is not None:
            dst_conn.close()
        if src_conn is not None:
            src_conn.close()

    ok, detail = sqlite_integrity_check(dest)
    if not ok:
        dest.unlink(missing_ok=True)
        raise RuntimeError(f"SQLite backup integrity check failed: {detail}")

    backups = sorted(
        (p for p in out_dir.glob(f"{prefix}-*.db") if p.is_file()),
        key=lambda p: (p.stat().st_mtime_ns, p.name),
    )
    removed = 0
    for old in backups[:-keep]:
        old.unlink()
        removed += 1

    return {
        "path": str(dest),
        "size_bytes": dest.stat().st_size,
        "sha256": sha256_file(dest),
        "verified": True,
        "verify_detail": detail,
        "rotated_out": removed,
        "dir": str(out_dir),
    }
