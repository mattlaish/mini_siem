from pathlib import Path

import pytest

import importlib.util

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mini_siem_build_source_artifact", ROOT / "tools" / "build_source_artifact.py")
b = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(b)


def test_runtime_secret_patterns_rejected():
    assert b._matches_runtime_secret("db-listener-credentials.json")
    assert b._matches_runtime_secret("state/siem.db")
    assert not b._matches_runtime_secret("db-config.json")


def test_collect_files_rejects_symlink(tmp_path):
    (tmp_path / "real.txt").write_text("x")
    try:
        (tmp_path / "link.txt").symlink_to(tmp_path / "real.txt")
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(RuntimeError, match="symlink"):
        b.collect_files(tmp_path)


def test_python_syntax_validation_detects_prose_py(tmp_path):
    (tmp_path / "bad.py").write_text("this is not python prose here\n")
    with pytest.raises(SyntaxError):
        b.validate_python_syntax(tmp_path)
