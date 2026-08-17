#!/usr/bin/env python3
"""
mini-SIEM static security scanner
=================================
Analyzes the Python source WITHOUT running it, flagging common web-app
vulnerability classes for a Flask + SQLite stack: SQL injection, command
injection, arbitrary code execution, unsafe deserialization, hardcoded
secrets, weak crypto, disabled TLS, Flask misconfig, path traversal, SSRF.

Zero dependencies — standard library only (ast, re), matching the project's
own constraint. This is deliberately tuned to this codebase, which means
fewer false positives than a generic tool, but it is NOT a substitute for a
full audit: it finds patterns, not logic bugs.

IMPORTANT — read the findings, don't just count them. Many SQL "findings"
are false positives: an f-string in execute() is only dangerous if it
interpolates USER INPUT. Interpolating internally-generated placeholder
strings ("?,?,?") for an IN (...) clause is the correct, safe pattern.
Always trace each flagged line to its data source before acting.

Usage:
    python3 security_static_scan.py               # scan *.py in this folder
    python3 security_static_scan.py path/to/dir   # scan a specific folder
    python3 security_static_scan.py --json        # machine-readable output

Exit code is 0 always (this is an advisory tool); parse output or --json.
"""
import ast
import re
import sys
import json
from pathlib import Path

SEV_ORDER = {"HIGH": 0, "MED": 1, "LOW": 2, "INFO": 3}


# ---- line-oriented pattern checks ------------------------------------------
# (severity, compiled_regex, rule_id, human_detail)
_RAW_CHECKS = [
    ("HIGH", r'execute\s*\(\s*f["\']', "SQL-fstring",
     "execute() with an f-string — SAFE only if it interpolates placeholders/"
     "column names, NOT user input. Trace the source."),
    ("HIGH", r'execute\s*\([^,)]*\+', "SQL-concat",
     "execute() with string concatenation — check what is concatenated."),
    ("HIGH", r'os\.system\s*\(', "cmd-os-system",
     "os.system() — command injection risk if any part is user-controlled."),
    ("HIGH", r'subprocess\.(call|run|Popen|check_output)\([^)]*shell\s*=\s*True',
     "cmd-shell-true", "subprocess with shell=True — command injection risk."),
    ("MED",  r'os\.popen\s*\(', "cmd-popen", "os.popen() — command injection risk."),
    ("HIGH", r'(?<![A-Za-z_])eval\s*\(', "eval", "eval() — arbitrary code execution."),
    ("HIGH", r'(?<![A-Za-z_])exec\s*\(', "exec", "exec() — arbitrary code execution."),
    ("HIGH", r'pickle\.loads?\s*\(', "pickle", "pickle load — unsafe deserialization."),
    ("MED",  r'yaml\.load\s*\((?!.*Loader)', "yaml-load", "yaml.load without SafeLoader."),
    ("MED",  r'hashlib\.md5\s*\(', "weak-md5",
     "MD5 — weak hash; fine for non-security checksums only."),
    ("MED",  r'hashlib\.sha1\s*\(', "weak-sha1", "SHA1 — weak hash for security use."),
    ("HIGH", r'(password|passwd|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{6,}["\']',
     "hardcoded-secret",
     "Possible hardcoded secret — verify it is a placeholder/default, not a real credential."),
    ("MED",  r'verify\s*=\s*False', "tls-verify-off", "TLS verification disabled."),
    ("MED",  r'ssl\._create_unverified_context', "tls-unverified", "Unverified SSL context."),
    ("HIGH", r'debug\s*=\s*True', "flask-debug",
     "Flask debug=True — exposes an interactive debugger (RCE) if reachable."),
    ("MED",  r'render_template_string\s*\(', "ssti",
     "render_template_string — server-side template injection risk with user input."),
    ("MED",  r'(open|send_file|send_from_directory)\s*\([^)]*request\.', "path-traversal",
     "File operation using request data — path traversal risk."),
    ("MED",  r'(urlopen|urllib\.request)\s*\([^)]*request\.', "ssrf",
     "Outbound request built from user data — SSRF risk."),
]
CHECKS = [(sev, re.compile(pat), rid, det) for sev, pat, rid, det in _RAW_CHECKS]


def scan_lines(fname, text, out):
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if s.startswith("#"):
            continue
        for sev, rx, rid, det in CHECKS:
            if rx.search(line):
                out.append((sev, fname, i, rid, det))


# ---- AST-based checks (smarter: cut regex false positives) -----------------
class _ExecuteVisitor(ast.NodeVisitor):
    """Flag execute()/executemany() whose FIRST arg is dynamically built
    (f-string, + concat, or .format()). A plain string literal is safe."""
    def __init__(self, fname, out):
        self.f = fname
        self.out = out

    def visit_Call(self, node):
        fn = node.func
        name = getattr(fn, "attr", getattr(fn, "id", ""))
        if name in ("execute", "executemany") and node.args:
            a0 = node.args[0]
            if isinstance(a0, ast.JoinedStr):
                self.out.append(("HIGH", self.f, a0.lineno, "AST-SQL-fstring",
                                 "execute() first arg is an f-string — verify no user "
                                 "input is interpolated (placeholders are fine)."))
            elif isinstance(a0, ast.BinOp) and isinstance(a0.op, ast.Add):
                self.out.append(("HIGH", self.f, a0.lineno, "AST-SQL-concat",
                                 "execute() first arg uses + concatenation — verify the "
                                 "concatenated part is a literal, not user input."))
            elif isinstance(a0, ast.Call) and getattr(a0.func, "attr", "") == "format":
                self.out.append(("HIGH", self.f, a0.lineno, "AST-SQL-format",
                                 "execute() first arg uses .format() — verify no user input."))
        self.generic_visit(node)


def scan_ast(fname, text, out):
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        out.append(("INFO", fname, e.lineno or 0, "parse-error", str(e)))
        return
    _ExecuteVisitor(fname, out).visit(tree)


# ---- driver ----------------------------------------------------------------
def scan(target="."):
    root = Path(target)
    files = sorted(root.glob("*.py")) if root.is_dir() else [root]
    # don't scan the scanners themselves
    files = [f for f in files if f.name not in
             ("security_static_scan.py", "security_dynamic_scan.py")]
    findings = []
    for f in files:
        try:
            text = f.read_text(errors="replace")
        except Exception:
            continue
        scan_lines(f.name, text, findings)
        scan_ast(f.name, text, findings)
    findings.sort(key=lambda x: (SEV_ORDER.get(x[0], 9), x[1], x[2]))
    return files, findings


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv
    target = args[0] if args else "."
    files, findings = scan(target)

    if as_json:
        print(json.dumps({
            "files_scanned": [f.name for f in files],
            "findings": [
                {"severity": s, "file": f, "line": ln, "rule": r, "detail": d}
                for (s, f, ln, r, d) in findings],
        }, indent=2))
        return

    counts = {}
    for s, *_ in findings:
        counts[s] = counts.get(s, 0) + 1
    print("=" * 72)
    print("STATIC SECURITY SCAN — mini-SIEM")
    print("=" * 72)
    print(f"Files scanned: {len(files)}   Findings: {len(findings)}")
    print(f"  HIGH={counts.get('HIGH',0)}  MED={counts.get('MED',0)}  "
          f"LOW={counts.get('LOW',0)}  INFO={counts.get('INFO',0)}")
    print("=" * 72)
    if not findings:
        print("No findings.")
    for sev, f, ln, rid, det in findings:
        print(f"[{sev:4}] {f}:{ln}  ({rid})")
        print(f"        {det}")
    print()
    print("Reminder: findings are PATTERNS, not confirmed bugs. An f-string in")
    print("execute() that interpolates '?,?,?' placeholders is SAFE. Trace each")
    print("flagged line to its data source before acting.")


if __name__ == "__main__":
    main()
