#!/usr/bin/env python3
"""Fail when executable/test source masquerades as implemented placeholder code.

This gate is intentionally narrow. It does not reject legitimate SQL parameter
"placeholders" or abstract base methods. It rejects module-level design-only markers in Python source, trivial ``assert True`` tests, and reclassified placeholder paths reappearing as executable Python.
"""
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "PLACEHOLDER_TRUTH_INVENTORY.json"
SUSPICIOUS_DOCSTRING = re.compile(
    r"\b(contract placeholder|placeholder source|scaffold(?: only)?|skeleton|planning only|plan only|foundation)\b",
    re.IGNORECASE,
)
DOCSTRING_WORD_EXCEPTIONS = {
    "sql_helpers.py",
    "security_static_scan.py",
}
ALLOWED_INCOMPLETE_EXAMPLES = {
    "integrations/sophos_poller_bundle/integration_example.py",
}


def _strip_docstring(body):
    body = list(body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        return body[1:]
    return body


def _trivial_true_test(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    body = _strip_docstring(node.body)
    if len(body) != 1 or not isinstance(body[0], ast.Assert):
        return False
    test = body[0].test
    return isinstance(test, ast.Constant) and test.value is True


def _has_true_assignment(tree: ast.AST, name: str) -> bool:
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return isinstance(node.value, ast.Constant) and node.value.value is True
    return False


def main() -> int:
    if not INVENTORY.is_file():
        print("FAIL: PLACEHOLDER_TRUTH_INVENTORY.json is missing")
        return 1
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    removed = set(inventory.get("runtime_placeholders_reclassified", []))
    removed |= set(inventory.get("trivial_tests_reclassified", []))
    removed |= set(inventory.get("tool_scaffolds_reclassified", []))

    failures: list[str] = []
    for rel in sorted(removed):
        if (ROOT / rel).exists():
            failures.append(f"reclassified placeholder path reappeared: {rel}")

    for path in sorted(ROOT.rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        if any(part in {".git", "__pycache__", ".pytest_cache"} for part in path.parts):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            failures.append(f"python syntax error: {rel}: {exc}")
            continue

        doc = ast.get_docstring(tree) or ""
        if rel not in DOCSTRING_WORD_EXCEPTIONS and SUSPICIOUS_DOCSTRING.search(doc):
            if rel in ALLOWED_INCOMPLETE_EXAMPLES:
                if not _has_true_assignment(tree, "EXAMPLE_ONLY"):
                    failures.append(f"intentional incomplete example lacks EXAMPLE_ONLY=True: {rel}")
            else:
                failures.append(f"executable Python has design/scaffold module docstring: {rel}")

        if rel.startswith("tests/") and path.name.startswith("test_"):
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                    if _trivial_true_test(node):
                        failures.append(f"trivial assert-True test provides no evidence: {rel}:{node.lineno}")

    if failures:
        print("PLACEHOLDER TRUTH GATE: FAIL")
        for item in failures:
            print(f"- {item}")
        return 1

    print("PLACEHOLDER TRUTH GATE: PASS")
    print(f"reclassified executable/test paths: {len(removed)}")
    print(f"allowed incomplete examples: {len(ALLOWED_INCOMPLETE_EXAMPLES)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
