#!/usr/bin/env python3
"""Durable existing-upgrade journal for crash/reboot recovery.

This journal is deliberately separate from fresh-install ``--resume`` state.
It never turns the fresh-install resume switch into an upgrade mechanism.  The
existing-installation entry point owns this state and uses an explicit
``--recover-interrupted`` path after a process kill or host reboot.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path

from tools.fresh_install_state import source_fingerprint

KIND = "mini-siem-existing-upgrade"
VERSION = 1
PHASES = [
    "STAGED",
    "SERVICES_STOPPED",
    "STATE_COPIED",
    "DATABASE_MUTATION_STARTED",
    "DATABASE_MIGRATED",
    "READY_FOR_CUTOVER",
    "CUTOVER_STARTED",
    "CUTOVER_COMPLETE",
    "SERVICES_INSTALLED",
    "OPERATIONAL",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def load(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("kind") != KIND or int(data.get("version", 0)) != VERSION:
        raise RuntimeError("not a recognized mini-SIEM existing-upgrade journal")
    if data.get("phase") not in PHASES:
        raise RuntimeError(f"invalid existing-upgrade phase: {data.get('phase')!r}")
    return data


def init(path: Path, *, target: Path, source: Path, backend: str, stage: Path,
         previous: Path, failed: Path, evidence: Path, services: list[str]) -> dict:
    if path.exists():
        raise RuntimeError(f"existing-upgrade journal already exists: {path}")
    if backend not in {"sqlite", "postgres"}:
        raise RuntimeError(f"unsupported upgrade backend: {backend!r}")
    source_id = source_fingerprint(source)
    stage_id = source_fingerprint(stage)
    if source_id != stage_id:
        raise RuntimeError("staged upgrade source does not match invoking source artifact")
    data = {
        "kind": KIND,
        "version": VERSION,
        "status": "in_progress",
        "phase": "STAGED",
        "target": str(target.resolve()),
        "source_fingerprint": source_id,
        "backend": backend,
        "stage": str(stage.resolve()),
        "previous": str(previous.resolve()),
        "failed": str(failed.resolve()),
        "evidence": str(evidence.resolve()),
        "services_were_active": sorted(set(services)),
        "created_at": _now(),
        "updated_at": _now(),
    }
    _write(path, data)
    return data


def validate(path: Path, *, target: Path | None = None, source: Path | None = None) -> dict:
    data = load(path)
    if target is not None and Path(data["target"]).resolve() != target.resolve():
        raise RuntimeError("existing-upgrade journal target does not match --target")
    if source is not None and source_fingerprint(source) != data.get("source_fingerprint"):
        raise RuntimeError("recovery source does not match the interrupted upgrade source artifact")
    return data


def set_phase(path: Path, phase: str, *, status: str | None = None) -> dict:
    if phase not in PHASES:
        raise RuntimeError(f"unsupported existing-upgrade phase: {phase}")
    data = load(path)
    old_i = PHASES.index(data["phase"])
    new_i = PHASES.index(phase)
    if new_i < old_i:
        raise RuntimeError(f"refusing existing-upgrade phase regression {data['phase']} -> {phase}")
    data["phase"] = phase
    if status is not None:
        data["status"] = status
    elif phase == "OPERATIONAL":
        data["status"] = "operational"
    data["updated_at"] = _now()
    _write(path, data)
    return data


def mark_interrupted(path: Path, *, reason: str = "process_or_host_interruption") -> dict:
    data = load(path)
    if data.get("phase") != "OPERATIONAL":
        data["status"] = "interrupted"
        data["interruption_reason"] = reason
        data["updated_at"] = _now()
        _write(path, data)
    return data


def recovery_plan(data: dict) -> str:
    phase = data.get("phase")
    if phase not in PHASES:
        raise RuntimeError(f"invalid existing-upgrade phase: {phase!r}")
    idx = PHASES.index(phase)
    if phase == "OPERATIONAL":
        return "NONE"
    if idx < PHASES.index("DATABASE_MUTATION_STARTED"):
        return "RESTORE_PRE_UPGRADE"
    if phase == "DATABASE_MUTATION_STARTED":
        # Schema/role mutation may have partially committed.  Do not restart the
        # old runtime or guess whether rollback is safe.  The operator must
        # rerun the controlled upgrade so ledger/idempotent migration logic can
        # converge the database before cutover.
        return "RERUN_REQUIRED"
    return "COMPLETE_FORWARD"


def archive_and_remove(path: Path, *, status: str, suffix: str) -> Path:
    data = load(path)
    data["status"] = status
    data["updated_at"] = _now()
    evidence = Path(data["evidence"])
    evidence.mkdir(parents=True, exist_ok=True)
    out = evidence / f"existing-upgrade-journal-{suffix}.json"
    _write(out, data)
    path.unlink(missing_ok=True)
    return out


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="mini-SIEM durable existing-upgrade journal")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init")
    for name in ("state", "target", "source", "backend", "stage", "previous", "failed", "evidence"):
        p.add_argument(f"--{name}", required=True)
    p.add_argument("--service", action="append", default=[])
    p = sub.add_parser("phase")
    p.add_argument("--state", required=True); p.add_argument("--phase", required=True)
    p = sub.add_parser("interrupt")
    p.add_argument("--state", required=True); p.add_argument("--reason", default="process_or_host_interruption")
    p = sub.add_parser("validate")
    p.add_argument("--state", required=True); p.add_argument("--target", required=True); p.add_argument("--source", default="")
    p = sub.add_parser("plan")
    p.add_argument("--state", required=True)
    p = sub.add_parser("archive")
    p.add_argument("--state", required=True); p.add_argument("--status", required=True); p.add_argument("--suffix", required=True)
    p = sub.add_parser("show")
    p.add_argument("--state", required=True)
    return ap


def main() -> int:
    args = _parser().parse_args()
    state = Path(args.state).resolve()
    if args.cmd == "init":
        out = init(
            state, target=Path(args.target), source=Path(args.source), backend=args.backend,
            stage=Path(args.stage), previous=Path(args.previous), failed=Path(args.failed),
            evidence=Path(args.evidence), services=args.service,
        )
    elif args.cmd == "phase":
        out = set_phase(state, args.phase)
    elif args.cmd == "interrupt":
        out = mark_interrupted(state, reason=args.reason)
    elif args.cmd == "validate":
        out = validate(state, target=Path(args.target), source=Path(args.source) if args.source else None)
    elif args.cmd == "plan":
        out = {"plan": recovery_plan(load(state)), "journal": load(state)}
    elif args.cmd == "archive":
        out = {"archived": str(archive_and_remove(state, status=args.status, suffix=args.suffix))}
    else:
        out = load(state)
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
