#!/usr/bin/env python3
"""Run isolated product regressions and the existing Dashboard offline consumer.

No network calls, registry edits, production credentials or Git operations.
Only this return's generated test-logs and positive replay evidence are written.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parents[1]
if not (PROJECT / "dashboard_connector.py").is_file():
    PROJECT = ROOT / "source"

TESTS = [
    "test_dashboard_connector.py", "test_dashboard_return_package.py",
    "test_detection_management.py", "test_detection_hardening.py",
    "test_ux_improvements.py", "test_product_language.py", "test_db.py",
    "test_admin_bootstrap.py", "test_postgres_privilege_boundary.py",
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dashboard-root", type=Path, required=True)
    parser.add_argument("--tests", action="store_true")
    args = parser.parse_args()
    consumer = args.dashboard_root.resolve(strict=True)
    tool = consumer / "tools/qualify_owi_connector_fixture.py"
    if not tool.is_file():
        raise SystemExit("Dashboard offline CLI is unavailable; record NOT_RUN, do not substitute a mock")
    logs = ROOT / "test-logs"
    logs.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    env["PYTHONPATH"] = os.pathsep.join([str(consumer / "src"), str(consumer / "tools"), env.get("PYTHONPATH", "")])
    env["OWI_PAGE_SCHEMA"] = str(PROJECT / "schemas/operator_workspace/page.schema.json")
    env["OWI_CONTROL_SCHEMA"] = str(PROJECT / "schemas/operator_workspace/control.schema.json")
    runs = []

    def run(name, arguments, *, parse_json=False):
        command = [sys.executable, "-B", *map(str, arguments)]
        started = datetime.now(timezone.utc).isoformat()
        completed = subprocess.run(command, cwd=PROJECT, env=env, capture_output=True, text=True, encoding="utf-8")
        (logs / (name + ".stdout.txt")).write_text(completed.stdout, encoding="utf-8")
        (logs / (name + ".stderr.txt")).write_text(completed.stderr, encoding="utf-8")
        runs.append({"name": name, "command": command, "cwd": str(PROJECT), "started_at_utc": started,
                     "exit_code": completed.returncode,
                     "stdout_ref": name + ".stdout.txt", "stderr_ref": name + ".stderr.txt"})
        if completed.returncode:
            raise RuntimeError(f"{name} failed; inspect test-logs/{name}.stdout.txt and .stderr.txt")
        return json.loads(completed.stdout) if parse_json else None

    with tempfile.TemporaryDirectory(prefix="mini-siem-return-checks-") as temporary:
        env["TEMP"] = env["TMP"] = temporary
        if args.tests:
            run("focused-regression", ["-m", "pytest", "-q", "--tb=short", "-p", "no:cacheprovider",
                *["tests/" + name for name in TESTS], "--basetemp", str(Path(temporary) / "pytest"),
                "--junitxml", str(logs / "focused-regression.xml")])
        base = [tool, "--binding", ROOT / "binding.fixture.json", "--binding-sha256", digest(ROOT / "binding.fixture.json"),
                "--bundle", ROOT / "fixture-bundle.json"]
        plan = run("dashboard-plan", base, parse_json=True)
        replay = run("dashboard-execute", [*base, "--execute", "--confirm", plan["execute_confirmation"]], parse_json=True)
        positive = run("positive-sequence", [ROOT / "tools/verify_positive_sequences.py", "--record"], parse_json=True)
        catalog_code = '''import hashlib,json,sys
from pathlib import Path
from qualify_owi_connector_fixture import build_qualification
from utm_backend.operator_workspace_connector_runtime import OWIRuntimeBinding
from utm_backend.owi_return_acceptance import audit_catalogs
root=Path(sys.argv[1])
files={p.relative_to(root).as_posix():p.read_bytes() for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
binding=OWIRuntimeBinding.from_document(json.loads(files['binding.fixture.json']),binding_sha256=hashlib.sha256(files['binding.fixture.json']).hexdigest(),purpose='OFFLINE_FIXTURE_ONLY')
connector,_,_,_=build_qualification(json.loads(files['fixture-bundle.json']),binding)
print(json.dumps(audit_catalogs(files,connector),sort_keys=True))
'''
        catalogs = run("dashboard-catalog-audit", ["-c", catalog_code, ROOT], parse_json=True)
    pin_names = ["tools/qualify_owi_connector_fixture.py", "tools/audit_owi_return.py",
                 "src/utm_backend/owi_fixture_validation.py", "src/utm_backend/owi_return_acceptance.py",
                 "src/utm_backend/operator_workspace_connector_runtime.py", "src/utm_backend/product_connector.py"]
    report = {"scope": "OFFLINE_FIXTURE_ONLY", "network_io": False, "production_registration": False,
              "binding_sha256": digest(ROOT / "binding.fixture.json"), "bundle_sha256": digest(ROOT / "fixture-bundle.json"),
              "identity_sha256": digest(ROOT / "identity-inputs.json"),
              "consumer_root": str(consumer), "consumer_files": [{"path": name, "sha256": digest(consumer / name)} for name in pin_names],
              "runs": runs, "replay": replay, "positive_sequence": positive, "catalog_audit": catalogs}
    (logs / "offline-checks.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"scope": "OFFLINE_FIXTURE_ONLY", "replay": replay, "positive_sequence": positive, "catalog_audit": catalogs}, sort_keys=True))


if __name__ == "__main__":
    main()
