import hashlib
import json
from pathlib import Path
import shutil

import pytest

from tools import fresh_install_state as fis
from tools import upgrade_cutover_state as ucs

ROOT = Path(__file__).resolve().parents[1]


def _copy_dev_fingerprint_tree(src: Path) -> None:
    for rel in fis.FINGERPRINT_FILES:
        origin = ROOT / rel
        dest = src / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(origin, dest)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_packaged_source_identity_covers_files_beyond_historical_subset(tmp_path):
    root = tmp_path / "artifact"
    root.mkdir()
    _copy_dev_fingerprint_tree(root)
    extra = root / "listener.py"
    extra.write_text("print('immutable packaged source')\n", encoding="utf-8")
    files = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        files.append({"path": rel, "size": path.stat().st_size, "sha256": _sha(path)})
    manifest = root / "ARTIFACT_MANIFEST.json"
    manifest.write_text(json.dumps({"files": files}, sort_keys=True), encoding="utf-8")

    before = fis.source_fingerprint(root)
    assert before
    extra.write_text("print('drifted source')\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="listener.py"):
        fis.source_fingerprint(root)


def test_development_tree_fallback_fingerprint_still_supports_tests(tmp_path):
    root = tmp_path / "dev"
    root.mkdir()
    _copy_dev_fingerprint_tree(root)
    assert len(fis.source_fingerprint(root)) == 64


def test_upgrade_journal_recovery_plans_are_phase_safe(tmp_path):
    source = tmp_path / "source"
    stage = tmp_path / "stage"
    target = tmp_path / "target"
    previous = tmp_path / "previous"
    failed = tmp_path / "failed"
    evidence = tmp_path / "evidence"
    for root in (source, stage):
        root.mkdir()
        _copy_dev_fingerprint_tree(root)
    target.mkdir()
    state = tmp_path / "upgrade-state.json"

    ucs.init(
        state,
        target=target,
        source=source,
        backend="postgres",
        stage=stage,
        previous=previous,
        failed=failed,
        evidence=evidence,
        services=["mini-siem-listener", "mini-siem-dashboard"],
    )
    assert ucs.recovery_plan(ucs.load(state)) == "RESTORE_PRE_UPGRADE"

    ucs.set_phase(state, "DATABASE_MUTATION_STARTED")
    assert ucs.recovery_plan(ucs.load(state)) == "RERUN_REQUIRED"

    ucs.set_phase(state, "DATABASE_MIGRATED")
    assert ucs.recovery_plan(ucs.load(state)) == "COMPLETE_FORWARD"
    ucs.set_phase(state, "CUTOVER_STARTED")
    assert ucs.recovery_plan(ucs.load(state)) == "COMPLETE_FORWARD"
    ucs.set_phase(state, "OPERATIONAL")
    assert ucs.recovery_plan(ucs.load(state)) == "NONE"


def test_upgrade_journal_refuses_phase_regression_and_source_change(tmp_path):
    source = tmp_path / "source"
    stage = tmp_path / "stage"
    target = tmp_path / "target"
    for root in (source, stage):
        root.mkdir()
        _copy_dev_fingerprint_tree(root)
    target.mkdir()
    state = tmp_path / "upgrade-state.json"
    ucs.init(
        state,
        target=target,
        source=source,
        backend="sqlite",
        stage=stage,
        previous=tmp_path / "previous",
        failed=tmp_path / "failed",
        evidence=tmp_path / "evidence",
        services=[],
    )
    ucs.set_phase(state, "READY_FOR_CUTOVER")
    with pytest.raises(RuntimeError, match="phase regression"):
        ucs.set_phase(state, "STATE_COPIED")
    (source / "fresh-install.sh").write_text("changed\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="recovery source"):
        ucs.validate(state, target=target, source=source)


def test_upgrade_entrypoint_has_durable_recovery_not_fresh_resume():
    upgrade = (ROOT / "upgrade-existing.sh").read_text(encoding="utf-8")
    fresh = (ROOT / "fresh-install.sh").read_text(encoding="utf-8")

    assert "--recover-interrupted" in upgrade
    assert ".existing-upgrade-state.json" in upgrade
    assert "DATABASE_MUTATION_STARTED" in upgrade
    assert "READY_FOR_CUTOVER" in upgrade
    assert "CUTOVER_STARTED" in upgrade
    assert "COMPLETE_FORWARD" in upgrade
    assert "old-code rollback is unsafe" in upgrade
    assert "verified P5 backup/restore path" in upgrade

    # Fresh-install resume remains a separate semantic boundary.
    assert "--resume resumes only the same checkpointed interrupted fresh installation" in fresh
    assert "--recover-interrupted" not in fresh
