import hashlib
import json
from pathlib import Path
import zipfile

import pytest

from release_engineering import artifact_provenance as prov
from release_engineering import release_gate as gate


def _qualification(path: Path, status="PASS"):
    path.write_text(json.dumps({
        "domains": {name: {"status": status, "detail": "evidence"} for name in gate.REQUIRED_QUALIFICATION_DOMAINS}
    }))


def test_qualification_gate_requires_every_domain_and_blocks_nonpass(tmp_path):
    q = tmp_path / "q.json"
    _qualification(q)
    result = gate.evaluate_qualification(q)
    assert result["status"] == "PASS"
    assert result["blockers"] == []

    data = json.loads(q.read_text())
    data["domains"]["performance"]["status"] = "NOT_RUN"
    q.write_text(json.dumps(data))
    result = gate.evaluate_qualification(q)
    assert result["status"] == "BLOCKED"
    assert result["blockers"][0]["domain"] == "performance"

    del data["domains"]["ai_provider"]
    q.write_text(json.dumps(data))
    with pytest.raises(RuntimeError, match="missing required domains"):
        gate.evaluate_qualification(q)


def test_explicit_human_approval_is_required_only_after_qualification_is_clear(tmp_path):
    assert gate.evaluate_approval(None, qualification_clear=False)["status"] == "NOT_APPLICABLE_WHILE_BLOCKED"
    assert gate.evaluate_approval(None, qualification_clear=True)["status"] == "BLOCKED"
    approval = tmp_path / "approval.json"
    approval.write_text(json.dumps({"approved": True, "approver": "release-manager", "approved_at_utc": "2026-09-23T00:00:00Z"}))
    out = gate.evaluate_approval(approval, qualification_clear=True)
    assert out["status"] == "PASS"
    assert out["approved"] is True


def test_embedded_manifest_verification_checks_exact_file_set_and_hash(tmp_path):
    artifact = tmp_path / "artifact.zip"
    content = b"hello"
    manifest = {
        "artifact": artifact.name,
        "status": "IMPLEMENTED_TESTING_DEFERRED",
        "files": [{"path": "README.md", "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}],
    }
    with zipfile.ZipFile(artifact, "w") as zf:
        zf.writestr("README.md", content)
        zf.writestr("ARTIFACT_MANIFEST.json", json.dumps(manifest))
    out = gate.verify_embedded_manifest(artifact)
    assert out["status"] == "PASS"
    assert out["files_verified"] == 1

    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr("README.md", b"tampered")
        zf.writestr("ARTIFACT_MANIFEST.json", json.dumps(manifest))
    with pytest.raises(RuntimeError, match="manifest mismatch"):
        gate.verify_embedded_manifest(bad)


def test_provenance_hashes_artifact_and_evidence(tmp_path):
    artifact = tmp_path / "artifact.zip"
    manifest = {"artifact": artifact.name, "parent": "parent.zip", "status": "IMPLEMENTED_TESTING_DEFERRED", "file_count_excluding_manifest": 0}
    with zipfile.ZipFile(artifact, "w") as zf:
        zf.writestr("ARTIFACT_MANIFEST.json", json.dumps(manifest))
    evidence = tmp_path / "evidence.json"; evidence.write_text('{"ok":true}')
    out = prov.build_provenance(tmp_path, artifact, [evidence])
    assert out["format"] == "mini-siem-artifact-provenance-v1"
    assert out["artifact"]["sha256"] == prov.sha256_file(artifact)
    assert out["embedded_manifest"]["parent"] == "parent.zip"
    assert out["evidence"][0]["sha256"] == prov.sha256_file(evidence)
