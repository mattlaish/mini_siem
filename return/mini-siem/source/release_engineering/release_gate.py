#!/usr/bin/env python3
"""Fail-closed mini-SIEM final release gate.

The gate independently validates source truth, the delivered ZIP, its embedded
per-file manifest, canonical documentation status, qualification evidence,
artifact provenance, and an explicit human approval record.  Local integrity
success alone can never promote an IMPLEMENTED_TESTING_DEFERRED build to a
release: unresolved qualification blockers keep the final decision BLOCKED.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import zipfile

# The release gate must not mutate the source tree merely by importing its own
# helper modules: packaging hygiene deliberately rejects __pycache__/pyc output.
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from release_engineering import artifact_provenance
from tools import build_source_artifact as builder

CANONICAL_DOCS = ("ROADMAP.md", "DEVELOPMENT.md", "TESTING.md", "AI_HANDOVER.md")
REQUIRED_QUALIFICATION_DOMAINS = (
    "postgresql",
    "systemd_selinux",
    "install_upgrade_resume",
    "backup_restore",
    "performance",
    "alert_lifecycle_browser",
    "ai_provider",
    "ingest_detection",
    "operations_security",
    "full_regression",
)
VALID_GATE_STATUSES = {"PASS", "FAIL", "BLOCKED_ENVIRONMENT", "NOT_RUN"}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_embedded_manifest(artifact: Path) -> dict:
    with zipfile.ZipFile(artifact) as zf:
        try:
            manifest = json.loads(zf.read(builder.MANIFEST))
        except KeyError as exc:
            raise RuntimeError(f"artifact missing {builder.MANIFEST}") from exc
        expected = {r["path"]: (int(r["size"]), str(r["sha256"])) for r in manifest.get("files", [])}
        actual_names = {
            i.filename for i in zf.infolist()
            if not i.is_dir() and i.filename != builder.MANIFEST
        }
        if actual_names != set(expected):
            missing = sorted(set(expected) - actual_names)
            extra = sorted(actual_names - set(expected))
            raise RuntimeError(f"embedded manifest file set mismatch: missing={missing[:10]} extra={extra[:10]}")
        for name, (size, digest) in expected.items():
            data = zf.read(name)
            if len(data) != size or _sha(data) != digest:
                raise RuntimeError(f"embedded manifest mismatch for {name}")
        return {
            "status": "PASS",
            "files_verified": len(expected),
            "manifest_status": manifest.get("status"),
            "manifest_parent": manifest.get("parent"),
        }


def verify_canonical_docs(root: Path, expected_status: str) -> dict:
    results = {}
    for rel in CANONICAL_DOCS:
        path = root / rel
        if not path.is_file():
            raise RuntimeError(f"canonical documentation missing: {rel}")
        text = path.read_text(encoding="utf-8")
        if expected_status not in text:
            raise RuntimeError(f"canonical documentation {rel} does not contain expected status {expected_status}")
        results[rel] = {"bytes": path.stat().st_size, "sha256": builder.sha256(path)}
    return {"status": "PASS", "documents": results}


def evaluate_qualification(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    domains = data.get("domains") or {}
    if not isinstance(domains, dict):
        raise RuntimeError("qualification evidence must contain a domains object")
    missing = [name for name in REQUIRED_QUALIFICATION_DOMAINS if name not in domains]
    if missing:
        raise RuntimeError("qualification evidence missing required domains: " + ", ".join(missing))
    normalized = {}
    blockers = []
    for name in REQUIRED_QUALIFICATION_DOMAINS:
        entry = domains[name]
        status = str(entry.get("status") if isinstance(entry, dict) else entry).upper()
        if status not in VALID_GATE_STATUSES:
            raise RuntimeError(f"invalid qualification status for {name}: {status!r}")
        detail = entry.get("detail", "") if isinstance(entry, dict) else ""
        normalized[name] = {"status": status, "detail": str(detail)}
        if status != "PASS":
            blockers.append({"domain": name, "status": status, "detail": str(detail)})
    return {
        "status": "PASS" if not blockers else "BLOCKED",
        "domains": normalized,
        "blockers": blockers,
    }


def evaluate_approval(path: Path | None, *, qualification_clear: bool) -> dict:
    if not qualification_clear:
        return {"status": "NOT_APPLICABLE_WHILE_BLOCKED", "approved": False}
    if path is None or not path.is_file():
        return {"status": "BLOCKED", "approved": False, "reason": "explicit release approval record is required"}
    data = json.loads(path.read_text(encoding="utf-8"))
    approved = data.get("approved") is True
    approver = str(data.get("approver") or "").strip()
    approved_at = str(data.get("approved_at_utc") or "").strip()
    if not approved or not approver or not approved_at:
        return {"status": "BLOCKED", "approved": False, "reason": "approval must include approved=true, approver and approved_at_utc"}
    return {"status": "PASS", "approved": True, "approver": approver, "approved_at_utc": approved_at}


def run(root: Path, artifact: Path, qualification_evidence: Path, *, expected_status: str,
        approval: Path | None = None, provenance_output: Path | None = None,
        evidence_paths=()) -> dict:
    root = root.resolve(); artifact = artifact.resolve()
    if not artifact.is_file():
        raise RuntimeError(f"release artifact missing: {artifact}")

    builder.validate_required(root)
    source_checks = {
        "required_files": "PASS",
        "python_syntax_files": builder.validate_python_syntax(root),
        "shell_syntax_files": builder.validate_shell_syntax(root),
        "javascript_syntax_files": builder.validate_js_syntax(root),
    }
    builder.validate_placeholder_truth(root)
    source_checks["placeholder_truth"] = "PASS"

    artifact_integrity = builder.safe_extract_and_verify(artifact, root)
    embedded_manifest = verify_embedded_manifest(artifact)
    docs = verify_canonical_docs(root, expected_status)
    qualification = evaluate_qualification(qualification_evidence)
    approval_result = evaluate_approval(approval, qualification_clear=(qualification["status"] == "PASS"))

    provenance = artifact_provenance.build_provenance(
        root, artifact, [qualification_evidence, *evidence_paths]
    )
    if provenance_output is not None:
        provenance_output.parent.mkdir(parents=True, exist_ok=True)
        provenance_output.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    local_checks_pass = True
    release_eligible = local_checks_pass and qualification["status"] == "PASS" and approval_result.get("approved") is True
    decision = "RELEASE_ELIGIBLE" if release_eligible else "BLOCKED"
    blockers = list(qualification.get("blockers") or [])
    if qualification["status"] == "PASS" and not approval_result.get("approved"):
        blockers.append({"domain": "explicit_release_approval", "status": "BLOCKED", "detail": approval_result.get("reason", "approval required")})

    return {
        "format": "mini-siem-final-release-gate-v1",
        "evaluated_at_utc": datetime.now(timezone.utc).isoformat(),
        "expected_status": expected_status,
        "decision": decision,
        "release_eligible": release_eligible,
        "source_checks": source_checks,
        "artifact_integrity": artifact_integrity,
        "embedded_manifest": embedded_manifest,
        "documentation": docs,
        "qualification": qualification,
        "approval": approval_result,
        "provenance": provenance,
        "blockers": blockers,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="mini-SIEM fail-closed final release gate")
    ap.add_argument("--root", default=str(ROOT))
    ap.add_argument("--artifact", required=True)
    ap.add_argument("--qualification-evidence", required=True)
    ap.add_argument("--expected-status", default="IMPLEMENTED_TESTING_DEFERRED")
    ap.add_argument("--approval", default="")
    ap.add_argument("--provenance-output", default="")
    ap.add_argument("--output", default="")
    ap.add_argument("--evidence", action="append", default=[])
    args = ap.parse_args()
    try:
        report = run(
            Path(args.root), Path(args.artifact), Path(args.qualification_evidence),
            expected_status=args.expected_status,
            approval=Path(args.approval) if args.approval else None,
            provenance_output=Path(args.provenance_output) if args.provenance_output else None,
            evidence_paths=[Path(x) for x in args.evidence],
        )
        text = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            out = Path(args.output); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(text, encoding="utf-8")
        print(text, end="")
        return 0 if report["release_eligible"] else 3
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
