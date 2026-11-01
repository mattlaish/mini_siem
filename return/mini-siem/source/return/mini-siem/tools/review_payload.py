#!/usr/bin/env python3
"""Review safe source parity, syntax and high-confidence accidental secrets.

This is not a guarantee that every possible credential format can be recognized.
It never reads excluded runtime configuration or changes source files.
"""
import argparse
import ast
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from build_return_package import RETURN_ROOT, PROJECT_ROOT, package_files


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summary(path):
    suites = ET.parse(path).getroot().findall("testsuite")
    counts = {k: sum(int(s.get(k, 0)) for s in suites) for k in ("tests", "failures", "errors", "skipped")}
    counts["passed"] = counts["tests"] - counts["failures"] - counts["errors"] - counts["skipped"]
    failed = sorted((c.get("classname"), c.get("name")) for s in suites for c in s.findall("testcase")
                    if c.find("failure") is not None or c.find("error") is not None)
    return counts, failed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-xml", type=Path)
    args = parser.parse_args()
    source = RETURN_ROOT / "source"
    manifest = json.loads((RETURN_ROOT / "SOURCE_MANIFEST.json").read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        path = entry["path"]
        for root in (source, PROJECT_ROOT):
            target = (root / path).resolve()
            if root.resolve() not in target.parents or sha(target) != entry["sha256"]:
                raise SystemExit("source parity mismatch: " + path)
    actual = {p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()}
    if actual != {entry["path"] for entry in manifest["files"]}:
        raise SystemExit("source inventory is incomplete")
    python_count = 0
    for path in sorted(source.rglob("*.py")):
        ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        python_count += 1
    patterns = {
        "private_key_material": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/=]{40,}"),
        "opaque_reader_token": re.compile(rb"msdr_[A-Za-z0-9_-]{64,}"),
        "openai_key_shape": re.compile(rb"sk-(?:proj-)?[A-Za-z0-9_-]{40,}"),
    }
    hits = []
    files = package_files()
    for path in files:
        for label, pattern in patterns.items():
            if pattern.search(path.read_bytes()):
                hits.append({"path": path.relative_to(RETURN_ROOT).as_posix(), "kind": label})
    if hits:
        raise SystemExit("potential accidental credentials require review: " + json.dumps(hits))
    result = {"status": "PASS", "source_files_matched": len(manifest["files"]),
              "python_syntax_checked": python_count, "high_confidence_secret_hits": [],
              "secret_scan_scope": list(patterns), "runtime_config_included": False,
              "reviewed_members": len(files), "reviewed_expanded_bytes": sum(p.stat().st_size for p in files),
              "not_a_production_qualification": True}
    if args.baseline_xml:
        old_counts, old_failed = summary(args.baseline_xml)
        new_counts, new_failed = summary(RETURN_ROOT / "test-logs/full-regression.xml")
        result["full_regression_comparison"] = {
            "baseline_report_sha256": sha(args.baseline_xml), "baseline_counts": old_counts,
            "current_counts": new_counts, "baseline_failed_tests": old_failed,
            "new_failed_tests": sorted(set(new_failed) - set(old_failed)),
            "resolved_failed_tests": sorted(set(old_failed) - set(new_failed)),
        }
        if result["full_regression_comparison"]["new_failed_tests"]:
            raise SystemExit("new full-suite failures require review")
    (RETURN_ROOT / "test-logs/artifact-review.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
