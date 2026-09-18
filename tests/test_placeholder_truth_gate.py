import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "tools" / "check_placeholder_truth.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("placeholder_truth_gate", GATE)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_reclassified_paths_are_absent():
    gate = _load_gate()
    import json
    inventory = json.loads((ROOT / "PLACEHOLDER_TRUTH_INVENTORY.json").read_text(encoding="utf-8"))
    paths = (
        inventory["runtime_placeholders_reclassified"]
        + inventory["trivial_tests_reclassified"]
        + inventory["tool_scaffolds_reclassified"]
    )
    assert paths
    assert all(not (ROOT / rel).exists() for rel in paths)


def test_truth_gate_passes_current_repository():
    gate = _load_gate()
    assert gate.main() == 0
