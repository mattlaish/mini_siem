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


def _mirror_gate(tmp_path, monkeypatch, relative, source):
    import json
    gate = _load_gate()
    inventory = tmp_path / "PLACEHOLDER_TRUTH_INVENTORY.json"
    inventory.write_text(json.dumps({}), encoding="utf-8")
    target = tmp_path / "return/mini-siem/source" / relative
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8")
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    monkeypatch.setattr(gate, "INVENTORY", inventory)
    return gate


def test_mirrored_intentional_example_keeps_the_existing_policy(tmp_path, monkeypatch):
    gate = _mirror_gate(tmp_path, monkeypatch,
        "integrations/sophos_poller_bundle/integration_example.py",
        '"""Integration skeleton."""\nEXAMPLE_ONLY = True\n')
    assert gate.main() == 0


def test_mirrored_example_without_explicit_marker_is_rejected(tmp_path, monkeypatch):
    gate = _mirror_gate(tmp_path, monkeypatch,
        "integrations/sophos_poller_bundle/integration_example.py",
        '"""Integration skeleton."""\n')
    assert gate.main() == 1


def test_other_mirrored_placeholder_is_still_rejected(tmp_path, monkeypatch):
    gate = _mirror_gate(tmp_path, monkeypatch, "unexpected.py",
        '"""Runtime scaffold only."""\nEXAMPLE_ONLY = True\n')
    assert gate.main() == 1
