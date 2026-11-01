#!/usr/bin/env python3
"""Artifact provenance records for mini-SIEM release engineering."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_head(root: Path) -> str:
    try:
        cp = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        return cp.stdout.strip()
    except Exception:
        return ""


def _artifact_manifest(artifact: Path) -> dict:
    with zipfile.ZipFile(artifact) as zf:
        try:
            return json.loads(zf.read("ARTIFACT_MANIFEST.json"))
        except KeyError as exc:
            raise RuntimeError("artifact is missing ARTIFACT_MANIFEST.json") from exc


def create_record(source, artifact, checksum):
    """Backward-compatible minimal record constructor."""
    return {"source": source, "artifact": artifact, "checksum": checksum}


def build_provenance(root: str | Path, artifact: str | Path, evidence_paths=()) -> dict:
    root = Path(root).resolve()
    artifact = Path(artifact).resolve()
    if not artifact.is_file():
        raise RuntimeError(f"artifact does not exist: {artifact}")
    manifest = _artifact_manifest(artifact)
    evidence = []
    for item in evidence_paths:
        path = Path(item).resolve()
        if not path.is_file():
            raise RuntimeError(f"release evidence does not exist: {path}")
        evidence.append({
            "path": str(path),
            "name": path.name,
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        })
    return {
        "format": "mini-siem-artifact-provenance-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_root": str(root),
        "git_head": _git_head(root),
        "artifact": {
            "path": str(artifact),
            "name": artifact.name,
            "bytes": artifact.stat().st_size,
            "sha256": sha256_file(artifact),
        },
        "embedded_manifest": {
            "artifact": manifest.get("artifact"),
            "parent": manifest.get("parent"),
            "status": manifest.get("status"),
            "generated_at_utc": manifest.get("generated_at_utc"),
            "file_count_excluding_manifest": manifest.get("file_count_excluding_manifest"),
        },
        "evidence": evidence,
    }
