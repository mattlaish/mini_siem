#!/usr/bin/env python3
"""Record the entire Windows-compatible test suite without hiding failures."""
import json
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

RETURN = Path(__file__).resolve().parents[1]
PROJECT = RETURN.parents[1]
if not (PROJECT / "dashboard_connector.py").is_file():
    PROJECT = RETURN / "source"


def main():
    logs = RETURN / "test-logs"
    logs.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    env["OWI_PAGE_SCHEMA"] = str(PROJECT / "schemas/operator_workspace/page.schema.json")
    env["OWI_CONTROL_SCHEMA"] = str(PROJECT / "schemas/operator_workspace/control.schema.json")
    with tempfile.TemporaryDirectory(prefix="mini-siem-full-regression-") as temporary:
        env["TEMP"] = env["TMP"] = temporary
        command = [sys.executable, "-B", "-m", "pytest", "tests", "-q", "--tb=line", "-p", "no:cacheprovider",
                   "--ignore=tests/test_systemd_host_qualification.py", "--basetemp", str(Path(temporary) / "pytest"),
                   "--junitxml", str(logs / "full-regression.xml")]
        result = subprocess.run(command, cwd=PROJECT, env=env, capture_output=True, encoding="utf-8")
    (logs / "full-regression.stdout.txt").write_text(result.stdout, encoding="utf-8")
    (logs / "full-regression.stderr.txt").write_text(result.stderr, encoding="utf-8")
    suites = ET.parse(logs / "full-regression.xml").getroot().findall("testsuite")
    counts = {key: sum(int(suite.get(key, "0")) for suite in suites) for key in ("tests", "failures", "errors", "skipped")}
    counts["passed"] = counts["tests"] - counts["failures"] - counts["errors"] - counts["skipped"]
    failures = [{"class": case.get("classname"), "name": case.get("name")}
                for suite in suites for case in suite.findall("testcase")
                if case.find("failure") is not None or case.find("error") is not None]
    report = {"command": command, "cwd": str(PROJECT), "exit_code": result.returncode,
              "counts": counts, "failed_tests": failures,
              "excluded": "test_systemd_host_qualification requires POSIX pwd/systemd, unavailable on Windows"}
    (logs / "full-regression.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
