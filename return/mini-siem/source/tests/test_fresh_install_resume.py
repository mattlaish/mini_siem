from pathlib import Path
import json
import shutil

import pytest

from tools import fresh_install_state as fis

ROOT = Path(__file__).resolve().parents[1]


def _stage(tmp_path):
    src = tmp_path / "src"
    target = tmp_path / "target"
    src.mkdir(); target.mkdir()
    for rel in fis.FINGERPRINT_FILES:
        sp = ROOT / rel
        for base in (src, target):
            dp = base / rel
            dp.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(sp, dp)
    config = target / "db-config.json"
    config.write_text(json.dumps({"backend":"postgres", "postgres":{"host":"db","port":5432,"dbname":"minisiem","user":"","password":""}}))
    shutil.copy2(config, src / "db-config.json")
    return src, target, config


def test_checkpoint_resume_requires_same_source_and_config(tmp_path):
    src, target, config = _stage(tmp_path)
    state = target / ".fresh-install-state.json"
    data = fis.init(state, target=target, source=src, backend="postgres", config=config)
    assert data["phase"] == "STAGED"
    fis.set_phase(state, "OWNER_READY")
    resumed = fis.validate_resume(state, target=target, source=src, backend="postgres", config=config)
    assert resumed["phase"] == "OWNER_READY"
    assert resumed["status"] == "in_progress"

    (src / "fresh-install.sh").write_text("changed")
    with pytest.raises(RuntimeError, match="source"):
        fis.validate_resume(state, target=target, source=src, backend="postgres", config=config)


def test_checkpoint_refuses_config_drift_and_phase_regression(tmp_path):
    src, target, config = _stage(tmp_path)
    state = target / ".fresh-install-state.json"
    fis.init(state, target=target, source=src, backend="postgres", config=config)
    fis.set_phase(state, "SCHEMA_MIGRATED")
    with pytest.raises(RuntimeError, match="phase regression"):
        fis.set_phase(state, "DATABASE_READY")
    config.write_text(json.dumps({"backend":"postgres", "postgres":{"host":"other","port":5432,"dbname":"minisiem"}}))
    with pytest.raises(RuntimeError, match="db-config.json changed"):
        fis.validate_resume(state, target=target, source=src, backend="postgres", config=config)


def test_fresh_install_resume_is_not_force_install_contract():
    text = (ROOT / "fresh-install.sh").read_text()
    assert "--resume" in text
    assert ".fresh-install-state.json" in text
    assert "appears operational" in text
    assert "upgrade-existing.sh" in text
    assert "validate-resume" in text
    assert "db-config.json changed" in (ROOT / "tools" / "fresh_install_state.py").read_text()
