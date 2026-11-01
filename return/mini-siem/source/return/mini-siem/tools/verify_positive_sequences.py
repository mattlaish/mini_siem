#!/usr/bin/env python3
"""Verify positive OWI replay sequences with Dashboard's reviewed runtime.

Run with Dashboard's ``src`` and ``tools`` directories on ``PYTHONPATH``.
This tool performs no network I/O. --record writes only this return's generated
positive-sequence evidence, never Dashboard source or production state.
"""

import argparse
import json
from pathlib import Path

from qualify_owi_connector_fixture import build_qualification
from utm_backend.operator_workspace_connector_runtime import OWIRuntimeBinding
from utm_backend.owi_fixture_validation import ReplayState
from utm_backend.product_connector import ConnectorReadRequest


ROOT = Path(__file__).resolve().parents[1]


def load(relative):
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", action="store_true", help="record actual replay evidence in this return bundle")
    args = parser.parse_args()
    binding_bytes = (ROOT / "binding.fixture.json").read_bytes()
    import hashlib
    binding = OWIRuntimeBinding.from_document(
        json.loads(binding_bytes),
        binding_sha256=hashlib.sha256(binding_bytes).hexdigest(),
        purpose="OFFLINE_FIXTURE_ONLY",
    )
    connector, _, _, _ = build_qualification(load("fixture-bundle.json"), binding)
    case = load("positive-sequences.json")[0]
    sequence = load(case["input_fixture"])
    state = ReplayState()
    accepted = []
    identity = None
    for step in sequence["steps"]:
        wire = load(step["fixture"])
        request = ConnectorReadRequest(**step["request"])
        page = connector.decoder.decode(
            "alerts", wire,
            integration_instance_id=connector.binding.integration_instance_id,
        )
        records = page.validate(request, source_product=connector.describe().product_type)
        state.accept(request, page, records)
        record = records[0]
        identity = (request.tenant_id, request.product_id, record.source_instance_id,
                    record.resource_kind, record.external_id)
        accepted.append(record.revision)
    current = state.current[identity].revision
    if current != case["expected_current_revision"]:
        raise SystemExit(f"current revision mismatch: {current}")
    result = {"case_id": case["case_id"], "actual_result": "PASS",
                      "accepted_revisions": accepted,
                      "current_revision_after_sequence": current,
                      "network_io": False, "production_registration": False}
    if args.record:
        (ROOT / case["evidence_ref"]).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        case["actual_result"] = "PASS"
        (ROOT / "positive-sequences.json").write_text(json.dumps([case], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
