"""Phase 12.3 backup/restore readiness helpers.

The module intentionally provides validation-oriented workflow primitives.
Database owner operations remain outside runtime identities.
"""
from dataclasses import dataclass
from pathlib import Path
import hashlib

@dataclass
class BackupManifest:
    backup_id: str
    schema_version: str
    contains_secrets: bool = False

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def validate_backup(path: str, expected_sha256: str) -> bool:
    return sha256_file(path) == expected_sha256
