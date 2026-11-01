#!/usr/bin/env python3
"""Validate the exact Dashboard return shape, schemas, chains and hashes."""

import hashlib
import json
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parents[1]
if not (PROJECT_ROOT / "dashboard_connector.py").is_file():
    PROJECT_ROOT = ROOT / "source"
PREFIX = "/api/integrations/dashboard/v1"


def read(name):
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exact_keys(value, keys, label):
    if set(value) != set(keys):
        raise AssertionError(f"{label} keys differ: {sorted(value)}")


def inside(relative):
    target = (ROOT / relative).resolve()
    if ROOT.resolve() not in target.parents:
        raise AssertionError(f"fixture path escapes return root: {relative}")
    if not target.is_file():
        raise AssertionError(f"fixture path does not exist: {relative}")
    return target


def main():
    required = [
        "HANDOFF.md", "binding.fixture.json", "binding.deployment.template.json",
        "deployment-inputs.md", "adapter-manifest.fixture.json", "identity-inputs.json",
        "fixture-bundle.json", "fixture-provenance.json", "negative-cases.json",
        "positive-sequences.json", "transport-cases.json", "mapping.md", "schemas/page.schema.json",
        "schemas/control.schema.json", "schemas/resource-manifest.json", "fixtures",
        "tools/generate_fixture_bundle.py", "test-results.md", "test-logs",
        "tools/verify_positive_sequences.py",
        "deployment.md", "open-gaps.md", "SHA256SUMS",
    ]
    missing = [name for name in required if not (ROOT / name).exists()]
    if missing: raise AssertionError("missing required return paths: " + ", ".join(missing))
    obsolete = [name for name in ("adapter-manifest.json", "deployment-inputs.json") if (ROOT / name).exists()]
    if obsolete: raise AssertionError("obsolete incompatible metadata remains: " + ", ".join(obsolete))

    page_validator = jsonschema.Draft202012Validator(read("schemas/page.schema.json"))
    control_validator = jsonschema.Draft202012Validator(read("schemas/control.schema.json"))
    binding = read("binding.fixture.json")
    manifest = read("adapter-manifest.fixture.json")
    identity = read("identity-inputs.json")
    bundle = read("fixture-bundle.json")

    exact_keys(manifest, ["adapter_id", "product_type", "vendor", "protocol_version",
                          "identity_sha256", "capabilities", "capability_generation",
                          "qualification_status", "qualification_evidence_sha256"], "manifest")
    if manifest["identity_sha256"] != sha(ROOT / "identity-inputs.json"):
        raise AssertionError("manifest identity_sha256 does not hash final identity-inputs bytes")
    for item in identity["files"]:
        packaged_source = ROOT / "source" / item["path"]
        repository_source = PROJECT_ROOT / item["path"]
        if not packaged_source.is_file() or not repository_source.is_file():
            raise AssertionError(f"identity source is missing: {item['path']}")
        if sha(packaged_source) != item["sha256"] or sha(repository_source) != item["sha256"]:
            raise AssertionError(f"identity source hash mismatch: {item['path']}")
    if identity["purpose"] != "OFFLINE_FIXTURE_ONLY":
        raise AssertionError("identity purpose must be OFFLINE_FIXTURE_ONLY")

    exact_keys(bundle, ["manifest", "product", "responses", "requests", "negative_pages"], "bundle")
    if bundle["manifest"] != manifest:
        raise AssertionError("embedded manifest differs from adapter-manifest.fixture.json")
    exact_keys(bundle["product"], ["tenant_id", "product_id", "product_type", "enabled", "secret_ref"], "product")
    product = bundle["product"]
    if (product["tenant_id"], product["product_id"], product["product_type"], product["secret_ref"]) != (
            binding["tenant_id"], binding["integration_instance_id"], binding["source_product"],
            binding["auth"]["credential_ref"]):
        raise AssertionError("bundle product does not match binding")
    if binding["enabled"] is not False or product["enabled"] is not True:
        raise AssertionError("binding must be disabled while offline fixture product is enabled")

    expected_paths = {PREFIX + suffix for suffix in (
        "/health", "/capabilities", "/alerts", "/incidents", "/assets", "/health-observations")}
    if set(bundle["responses"]) != expected_paths:
        raise AssertionError("responses paths differ from enabled/control path set")
    control_count = 0
    page_count = 0
    for path, responses in bundle["responses"].items():
        if not isinstance(responses, list) or not responses:
            raise AssertionError(f"response list is empty: {path}")
        validator = control_validator if path.endswith(("/health", "/capabilities")) else page_validator
        for response in responses:
            validator.validate(response)
            if validator is control_validator: control_count += 1
            else: page_count += 1

    request_fields = ["tenant_id", "product_id", "capability", "resource_kind", "cursor", "page_size"]
    capability_by_path = {
        PREFIX + "/alerts": "LIST_ALERTS", PREFIX + "/incidents": "LIST_INCIDENTS",
        PREFIX + "/assets": "LIST_ASSETS", PREFIX + "/health-observations": "HEALTH",
    }
    for request in bundle["requests"]:
        exact_keys(request, request_fields, "request")
        if request["tenant_id"] != product["tenant_id"] or request["product_id"] != product["product_id"]:
            raise AssertionError("request tenant/product differs from fixture product")
    for path, capability in capability_by_path.items():
        pages = bundle["responses"][path]
        requests = [r for r in bundle["requests"] if r["capability"] == capability]
        if len(requests) != len(pages):
            raise AssertionError(f"request/response count mismatch: {path}")
        page_size = requests[0]["page_size"]
        if requests[0]["cursor"] is not None:
            raise AssertionError(f"first cursor must be null: {path}")
        for index, request in enumerate(requests):
            if request["page_size"] != page_size:
                raise AssertionError(f"page_size changed within cursor chain: {path}")
            if index and request["cursor"] != pages[index - 1]["next_cursor"]:
                raise AssertionError(f"cursor chain is not replayable: {path} page {index + 1}")
        if len(pages) < 3 or pages[-1]["records"] or pages[-1]["has_more"]:
            raise AssertionError(f"lane lacks snapshot/delta/empty sequence: {path}")
    if len(bundle["responses"][PREFIX + "/alerts"]) < 5:
        raise AssertionError("alerts must include at least three snapshot pages plus delta and empty")

    negative_fields = ["case_id", "stage", "input_fixture", "request", "expected_error", "reason"]
    negative = read("negative-cases.json")
    if not isinstance(negative, list) or not negative: raise AssertionError("negative catalog is empty")
    expected_negative_contract = {
        "N-DEC-001": ("decoder", "ProductConnectorError"),
        "N-DEC-002": ("decoder", "ProductConnectorError"),
        "N-DEC-003": ("decoder", "ProductConnectorError"),
        "N-DEC-004": ("decoder", "ProductConnectorError"),
        "N-DEC-005": ("decoder", "ProductConnectorError"),
        "N-DEC-006": ("decoder", "ProductConnectorError"),
        "N-PAGE-001": ("decoder", "ProductConnectorConflictError"),
        "N-PAGE-002": ("decoder", "ProductConnectorConflictError"),
        "N-PAGE-003": ("decoder", "ProductConnectorError"),
        "N-PAGE-004": ("page_validate", "ProductConnectorError"),
        "N-SYNC-001": ("page_validate", "ProductConnectorCursorError"),
        "N-SYNC-002": ("page_validate", "ProductConnectorCursorError"),
        "N-SYNC-003": ("sync", "ProductConnectorConflictError"),
        "N-SYNC-005": ("sync", "ProductConnectorConflictError"),
    }
    if {case.get("case_id") for case in negative} != set(expected_negative_contract):
        raise AssertionError("negative catalog case set differs from the reviewed stage contract")
    for case in negative:
        exact_keys(case, negative_fields, "negative case")
        if (case["stage"], case["expected_error"]) != expected_negative_contract[case["case_id"]]:
            raise AssertionError(f"negative stage/error mismatch: {case['case_id']}")
        fixture = json.loads(inside(case["input_fixture"]).read_text(encoding="utf-8"))
        if case["stage"] == "sync":
            if set(fixture) != {"steps"} or len(fixture["steps"]) < 2:
                raise AssertionError(f"sync case lacks explicit sequence: {case['case_id']}")
            for step in fixture["steps"]:
                exact_keys(step, ["fixture", "request"], "sync step")
                inside(step["fixture"])
    for item in bundle["negative_pages"]:
        exact_keys(item, ["route_name", "page"], "negative page")
        if not list(page_validator.iter_errors(item["page"])):
            raise AssertionError("bundle negative page unexpectedly passes page schema")

    positive = read("positive-sequences.json")
    if len(positive) != 1 or positive[0]["case_id"] != "P-SYNC-001":
        raise AssertionError("old-revision positive sequence is missing")
    positive_case = positive[0]
    exact_keys(positive_case, ["case_id", "input_fixture", "expected_current_revision",
                               "actual_result", "evidence_ref", "reason"], "positive sequence")
    sequence = json.loads(inside(positive_case["input_fixture"]).read_text(encoding="utf-8"))
    if set(sequence) != {"steps"} or len(sequence["steps"]) != 2:
        raise AssertionError("old-revision positive sequence must contain exactly two steps")
    positive_pages = []
    for step in sequence["steps"]:
        page = json.loads(inside(step["fixture"]).read_text(encoding="utf-8"))
        page_validator.validate(page)
        positive_pages.append(page)
    records = [page["records"][0] for page in positive_pages]
    identities = [(page["source_instance_id"], page["resource_kind"], record["external_id"])
                  for page, record in zip(positive_pages, records)]
    if identities[0] != identities[1] or [record["revision"] for record in records] != ["2", "1"]:
        raise AssertionError("old-revision positive sequence does not test one identity at revisions 2 then 1")
    current_revision = max((record["revision"] for record in records), key=int)
    if current_revision != positive_case["expected_current_revision"] or positive_case["actual_result"] != "PASS":
        raise AssertionError("old revision overwrote the expected current revision")
    inside(positive_case["evidence_ref"])

    transport_fields = ["case_id", "stage", "setup", "request_fixture", "expected_status",
                        "expected_code", "expected_headers", "actual_result", "evidence_ref"]
    transport = read("transport-cases.json")
    if not isinstance(transport, list) or not transport: raise AssertionError("transport catalog is empty")
    for case in transport:
        exact_keys(case, transport_fields, "transport case")
        if case["stage"] != "transport": raise AssertionError("transport stage must be transport")
        if case["actual_result"] not in ("PASS", "FAIL", "NOT_RUN", "NOT_IMPLEMENTED"):
            raise AssertionError("invalid transport actual_result")
        inside(case["request_fixture"])
        if case["evidence_ref"] is None:
            raise AssertionError(f"transport evidence is missing: {case['case_id']}")
        evidence = json.loads(inside(case["evidence_ref"]).read_text(encoding="utf-8"))
        if case["actual_result"] == "PASS":
            if evidence.get("status") != case["expected_status"]:
                raise AssertionError(f"transport status evidence mismatch: {case['case_id']}")
            if case["expected_code"] is not None and evidence.get("body", {}).get("error", {}).get("code") != case["expected_code"]:
                raise AssertionError(f"transport code evidence mismatch: {case['case_id']}")
        elif evidence.get("actual_result") != case["actual_result"]:
            raise AssertionError(f"transport non-pass evidence mismatch: {case['case_id']}")

    if (ROOT / "fixture-bundle.json").stat().st_size > 8 * 1024 * 1024:
        raise AssertionError("fixture bundle exceeds 8 MiB")
    if (ROOT / "binding.fixture.json").stat().st_size > 256 * 1024:
        raise AssertionError("binding exceeds 256 KiB")

    expected = {}
    for line in (ROOT / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1); expected[name] = digest
    for name, digest in expected.items():
        if sha(ROOT / name) != digest: raise AssertionError(f"checksum mismatch: {name}")

    print(json.dumps({"status": "PASS", "schema_validated_pages": page_count,
                      "schema_validated_controls": control_count,
                      "requests": len(bundle["requests"]),
                      "negative_cases": len(negative), "transport_cases": len(transport),
                      "checksum_validated_files": len(expected)}, sort_keys=True))


if __name__ == "__main__":
    main()
