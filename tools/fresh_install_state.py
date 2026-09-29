#!/usr/bin/env python3
"""Fresh-install checkpoint state for mini-SIEM.

The state file is root-owned installer metadata, not runtime configuration.  It
exists only to distinguish an interrupted *fresh* install from an operational
installation and to make ``fresh-install.sh --resume`` fail closed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from datetime import datetime, timezone

KIND = "mini-siem-fresh-install"
VERSION = 1
PHASES = [
    "STAGED",
    "OWNER_READY",
    "DATABASE_READY",
    "SCHEMA_MIGRATED",
    "SCHEMA_VERIFIED",
    "RUNTIME_CREDENTIALS_READY",
    "SERVICES_INSTALLED",
    "OPERATIONAL",
]
FINGERPRINT_FILES = (
    "fresh-install.sh",
    "install-services.sh",
    "db.py",
    "requirements.txt",
    "tools/postgres_bootstrap.py",
    "tools/postgres_privilege_boundary.py",
    "tools/fresh_install_state.py",
)
ARTIFACT_MANIFEST = "ARTIFACT_MANIFEST.json"


def _artifact_manifest_identity(root: Path) -> str | None:
    """Return a verified full packaged-source identity when a release manifest exists.

    Runtime files such as ``db-config.json``, databases, credentials and venvs are
    intentionally absent from the package manifest.  Every immutable packaged
    file listed by the artifact builder is re-hashed here, so ``--resume`` is
    bound to the complete delivered source rather than a small hand-picked
    subset of installer files.  The manifest bytes are included in the final
    identity so a modified manifest cannot silently redefine the package.
    """
    manifest_path = root / ARTIFACT_MANIFEST
    if not manifest_path.is_file():
        return None
    try:
        raw = manifest_path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError(f"invalid artifact manifest {manifest_path}: {exc}") from exc
    files = payload.get("files")
    if not isinstance(files, list) or not files:
        raise RuntimeError(f"artifact manifest has no packaged file list: {manifest_path}")

    h = hashlib.sha256()
    h.update(b"mini-siem-artifact-source-identity-v1\0")
    h.update(hashlib.sha256(raw).digest())
    seen: set[str] = set()
    root_resolved = root.resolve()
    for entry in sorted(files, key=lambda item: str(item.get("path", ""))):
        rel = entry.get("path")
        expected = entry.get("sha256")
        if not isinstance(rel, str) or not rel or not isinstance(expected, str) or len(expected) != 64:
            raise RuntimeError("artifact manifest contains an invalid file entry")
        if rel in seen:
            raise RuntimeError(f"artifact manifest contains duplicate path: {rel}")
        seen.add(rel)
        candidate = (root / rel)
        resolved = candidate.resolve()
        try:
            resolved.relative_to(root_resolved)
        except ValueError as exc:
            raise RuntimeError(f"artifact manifest path escapes source root: {rel}") from exc
        if candidate.is_symlink() or not candidate.is_file():
            raise RuntimeError(f"packaged source file missing or not a regular file: {rel}")
        actual = _sha_file(candidate)
        if actual != expected:
            raise RuntimeError(
                f"packaged source file changed since artifact creation: {rel} "
                f"(expected {expected}, got {actual})"
            )
        h.update(rel.encode("utf-8") + b"\0")
        h.update(bytes.fromhex(actual))
    return h.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def source_fingerprint(root: Path) -> str:
    root = root.resolve()
    manifest_identity = _artifact_manifest_identity(root)
    if manifest_identity is not None:
        return manifest_identity

    # Development/test trees may not carry a release artifact manifest.  Keep
    # the historical minimum identity there, but packaged production installs
    # always take the verified full-manifest path above.
    h = hashlib.sha256()
    h.update(b"mini-siem-development-source-identity-v1\0")
    for rel in FINGERPRINT_FILES:
        p = root / rel
        if not p.is_file():
            raise RuntimeError(f"fresh-install fingerprint file missing: {p}")
        h.update(rel.encode("utf-8") + b"\0")
        h.update(bytes.fromhex(_sha_file(p)))
    return h.hexdigest()


def config_fingerprint(path: Path) -> str:
    if not path.is_file():
        raise RuntimeError(f"database configuration missing: {path}")
    return _sha_file(path)


def load(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("kind") != KIND or int(data.get("version", 0)) != VERSION:
        raise RuntimeError("not a recognized mini-SIEM fresh-install checkpoint")
    if data.get("phase") not in PHASES:
        raise RuntimeError(f"invalid fresh-install checkpoint phase: {data.get('phase')!r}")
    return data


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def init(path: Path, *, target: Path, source: Path, backend: str, config: Path) -> dict:
    if path.exists():
        raise RuntimeError(f"fresh-install checkpoint already exists: {path}; use --resume")
    target = target.resolve()
    source = source.resolve()
    data = {
        "kind": KIND,
        "version": VERSION,
        "target": str(target),
        "backend": backend,
        # The deployed target tree is canonical after staging.  Source must
        # match it too, unless the operator resumes directly from TARGET.
        "source_fingerprint": source_fingerprint(target),
        "config_sha256": config_fingerprint(config),
        "phase": "STAGED",
        "status": "in_progress",
        "created_at": _now(),
        "updated_at": _now(),
    }
    if source_fingerprint(source) != data["source_fingerprint"]:
        raise RuntimeError("staged target source does not match the invoking source tree")
    _write(path, data)
    return data


def validate_resume(path: Path, *, target: Path, source: Path, backend: str, config: Path) -> dict:
    if not path.is_file():
        raise RuntimeError("no interrupted fresh-install checkpoint exists; normal fresh install or upgrade is required")
    data = load(path)
    target = target.resolve()
    source = source.resolve()
    if data.get("phase") == "OPERATIONAL" or data.get("status") == "operational":
        raise RuntimeError("checkpoint is already operational; use upgrade-existing.sh, not --resume")
    if Path(data.get("target", "")).resolve() != target:
        raise RuntimeError("fresh-install checkpoint target does not match this --target")
    if data.get("backend") != backend:
        raise RuntimeError("database backend differs from the interrupted fresh install")
    if data.get("config_sha256") != config_fingerprint(config):
        raise RuntimeError("db-config.json changed since the interrupted fresh install")
    expected = data.get("source_fingerprint")
    if source_fingerprint(target) != expected:
        raise RuntimeError("deployed source changed since the interrupted fresh install; use the supported upgrade path")
    if source_fingerprint(source) != expected:
        raise RuntimeError("resume source does not match the interrupted fresh-install source")
    data["status"] = "in_progress"
    data["updated_at"] = _now()
    _write(path, data)
    return data


def set_phase(path: Path, phase: str, *, status: str | None = None) -> dict:
    if phase not in PHASES:
        raise RuntimeError(f"unsupported fresh-install phase: {phase}")
    data = load(path)
    old = PHASES.index(data["phase"])
    new = PHASES.index(phase)
    if new < old:
        raise RuntimeError(f"refusing checkpoint phase regression {data['phase']} -> {phase}")
    data["phase"] = phase
    if status is not None:
        data["status"] = status
    elif phase == "OPERATIONAL":
        data["status"] = "operational"
    data["updated_at"] = _now()
    _write(path, data)
    return data


def mark_interrupted(path: Path) -> None:
    if not path.is_file():
        return
    data = load(path)
    if data.get("phase") == "OPERATIONAL":
        return
    data["status"] = "interrupted"
    data["updated_at"] = _now()
    _write(path, data)


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init")
    p.add_argument("--state", required=True); p.add_argument("--target", required=True)
    p.add_argument("--source", required=True); p.add_argument("--backend", required=True)
    p.add_argument("--config", required=True)
    p = sub.add_parser("validate-resume")
    p.add_argument("--state", required=True); p.add_argument("--target", required=True)
    p.add_argument("--source", required=True); p.add_argument("--backend", required=True)
    p.add_argument("--config", required=True)
    p = sub.add_parser("phase")
    p.add_argument("--state", required=True); p.add_argument("--phase", required=True)
    p.add_argument("--status", default=None)
    p = sub.add_parser("interrupt")
    p.add_argument("--state", required=True)
    p = sub.add_parser("show")
    p.add_argument("--state", required=True)
    args = ap.parse_args()
    state = Path(args.state)
    if args.cmd == "init":
        out = init(state, target=Path(args.target), source=Path(args.source), backend=args.backend, config=Path(args.config))
    elif args.cmd == "validate-resume":
        out = validate_resume(state, target=Path(args.target), source=Path(args.source), backend=args.backend, config=Path(args.config))
    elif args.cmd == "phase":
        out = set_phase(state, args.phase, status=args.status)
    elif args.cmd == "interrupt":
        mark_interrupted(state); out = load(state)
    else:
        out = load(state)
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
