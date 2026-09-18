#!/usr/bin/env python3
"""Build and independently verify a complete mini-SIEM source ZIP.

The package is part of the production surface.  This builder rejects delivery
junk and runtime secrets, writes a per-file SHA-256 manifest, builds the ZIP,
extracts it into a clean temporary directory, and verifies archive safety,
syntax, required files, critical file sizes/shebangs, and source-to-extracted
byte parity.
"""

from __future__ import annotations

import argparse
import ast
import datetime as dt
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]

PROHIBITED_DIRS = {".git", "__pycache__", ".pytest_cache"}
PROHIBITED_SUFFIXES = {".pyc", ".pyo"}
RUNTIME_SECRET_PATTERNS = (
    "ai-secret-master.key",
    "db-listener-credentials.json",
    "db-dashboard-credentials.json",
    "db-maintenance-credentials.json",
    ".env",
    ".env.*",
    "*.db",
    "*.db-wal",
    "*.db-shm",
)
REQUIRED_FILES = {
    "README.md": 100,
    "DEVELOPMENT.md": 100,
    "AI_HANDOVER.md": 100,
    "ROADMAP.md": 100,
    "TESTING.md": 100,
    "SECURITY.md": 100,
    "DEPLOYMENT.md": 100,
    "db.py": 1000,
    "listener.py": 100,
    "dashboard.py": 100,
    "configure-db.py": 500,
    "install-services.sh": 1000,
    "tools/postgres_bootstrap.py": 1000,
    "tools/postgres_privilege_boundary.py": 1000,
}
SHEBANG_FILES = (
    "configure-db.py",
    "install-services.sh",
    "tools/postgres_bootstrap.py",
    "tools/postgres_privilege_boundary.py",
)
MANIFEST = "ARTIFACT_MANIFEST.json"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _matches_runtime_secret(rel: str) -> bool:
    name = Path(rel).name
    return any(fnmatch.fnmatch(name, pat) for pat in RUNTIME_SECRET_PATTERNS)


def collect_files(root: Path, *, output: Path | None = None) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        parts = set(rel.parts)
        if parts & PROHIBITED_DIRS:
            raise RuntimeError(f"prohibited delivery directory present: {rel}")
        if path.is_symlink():
            raise RuntimeError(f"symlink not allowed in source delivery: {rel}")
        if not path.is_file():
            continue
        if output and path.resolve() == output.resolve():
            continue
        if path.suffix.lower() in PROHIBITED_SUFFIXES:
            raise RuntimeError(f"prohibited compiled Python file present: {rel}")
        rel_s = rel.as_posix()
        if _matches_runtime_secret(rel_s):
            raise RuntimeError(f"runtime secret/state file must not be packaged: {rel_s}")
        files.append(path)
    return files


def file_map(root: Path, files: list[Path], *, skip_manifest: bool = False) -> list[dict]:
    records = []
    for path in files:
        rel = path.relative_to(root).as_posix()
        if skip_manifest and rel == MANIFEST:
            continue
        records.append({"path": rel, "size": path.stat().st_size, "sha256": sha256(path)})
    return records


def validate_required(root: Path) -> None:
    for rel, min_size in REQUIRED_FILES.items():
        path = root / rel
        if not path.is_file():
            raise RuntimeError(f"required file missing: {rel}")
        if path.stat().st_size < min_size:
            raise RuntimeError(f"critical file unexpectedly small: {rel} ({path.stat().st_size} bytes)")
    for rel in SHEBANG_FILES:
        first = (root / rel).read_bytes().splitlines()[0] if (root / rel).stat().st_size else b""
        if not first.startswith(b"#!"):
            raise RuntimeError(f"script missing shebang: {rel}")


def validate_python_syntax(root: Path) -> int:
    count = 0
    for path in sorted(root.rglob("*.py")):
        if set(path.relative_to(root).parts) & PROHIBITED_DIRS:
            continue
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        count += 1
    return count


def validate_shell_syntax(root: Path) -> int:
    bash = shutil.which("bash")
    if not bash:
        return 0
    count = 0
    for path in sorted(root.rglob("*.sh")):
        subprocess.run([bash, "-n", str(path)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        count += 1
    return count


def validate_js_syntax(root: Path) -> int:
    node = shutil.which("node")
    if not node:
        return 0
    count = 0
    for path in sorted(root.rglob("*.js")):
        subprocess.run([node, "--check", str(path)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        count += 1
    return count


def validate_placeholder_truth(root: Path) -> None:
    gate = root / "tools" / "check_placeholder_truth.py"
    if not gate.is_file():
        raise RuntimeError("placeholder truth gate missing: tools/check_placeholder_truth.py")
    subprocess.run(
        [sys.executable, str(gate)], cwd=str(root), check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )


def write_manifest(root: Path, *, artifact_name: str, parent: str, status: str,
                   scope: list[str], validation: dict) -> dict:
    existing = root / MANIFEST
    if existing.exists():
        existing.unlink()
    files = collect_files(root)
    records = file_map(root, files)
    manifest = {
        "artifact": artifact_name,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "parent": parent,
        "status": status,
        "scope": scope,
        "validation": validation,
        "manifest_hash_scope": f"all packaged files except {MANIFEST} itself",
        "file_count_excluding_manifest": len(records),
        "files": records,
    }
    existing.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return manifest


def safe_extract_and_verify(zip_path: Path, source_root: Path) -> dict:
    with zipfile.ZipFile(zip_path) as zf:
        bad_crc = zf.testzip()
        if bad_crc:
            raise RuntimeError(f"ZIP CRC failure: {bad_crc}")
        for info in zf.infolist():
            name = info.filename
            norm = os.path.normpath(name)
            if name.startswith(("/", "\\")) or norm == ".." or norm.startswith("../"):
                raise RuntimeError(f"ZIP path traversal entry: {name}")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise RuntimeError(f"ZIP symlink entry is not allowed: {name}")

        with tempfile.TemporaryDirectory(prefix="mini-siem-artifact-") as td:
            dest = Path(td) / "extract"
            dest.mkdir()
            zf.extractall(dest)
            validate_required(dest)
            py_count = validate_python_syntax(dest)
            sh_count = validate_shell_syntax(dest)
            js_count = validate_js_syntax(dest)
            validate_placeholder_truth(dest)
            extracted = collect_files(dest)
            source = collect_files(source_root, output=zip_path)
            src_map = {r["path"]: (r["size"], r["sha256"]) for r in file_map(source_root, source)}
            out_map = {r["path"]: (r["size"], r["sha256"]) for r in file_map(dest, extracted)}
            if src_map != out_map:
                missing = sorted(set(src_map) - set(out_map))
                extra = sorted(set(out_map) - set(src_map))
                changed = sorted(k for k in set(src_map) & set(out_map) if src_map[k] != out_map[k])
                raise RuntimeError(
                    f"source/extracted parity mismatch: missing={missing[:10]} extra={extra[:10]} changed={changed[:10]}"
                )
            return {
                "zip_crc": "PASS",
                "path_traversal": "PASS",
                "symlink_check": "PASS",
                "required_files": "PASS",
                "source_extracted_sha256_parity": "PASS",
                "python_syntax_files": py_count,
                "shell_syntax_files": sh_count,
                "javascript_syntax_files": js_count,
                "placeholder_truth_gate": "PASS",
                "extracted_file_count": len(out_map),
            }


def build(root: Path, output: Path, *, parent: str, status: str,
          scope: list[str], validation: dict) -> dict:
    root = root.resolve()
    output = output.resolve()
    # Cleanup is explicit and narrow: only generated test/bytecode caches.
    for dirname in ("__pycache__", ".pytest_cache"):
        for p in list(root.rglob(dirname)):
            if p.is_dir():
                shutil.rmtree(p)
    for suffix in ("*.pyc", "*.pyo"):
        for p in root.rglob(suffix):
            p.unlink()

    validate_required(root)
    validate_python_syntax(root)
    validate_shell_syntax(root)
    validate_js_syntax(root)
    validate_placeholder_truth(root)
    write_manifest(
        root,
        artifact_name=output.name,
        parent=parent,
        status=status,
        scope=scope,
        validation=validation,
    )
    files = collect_files(root, output=output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in files:
            rel = path.relative_to(root).as_posix()
            zf.write(path, rel)
    integrity = safe_extract_and_verify(output, root)
    return {
        "artifact": str(output),
        "sha256": sha256(output),
        "size": output.stat().st_size,
        "integrity": integrity,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Build verified mini-SIEM complete-source artifact")
    ap.add_argument("--root", default=str(ROOT))
    ap.add_argument("--output", required=True)
    ap.add_argument("--parent", required=True)
    ap.add_argument("--status", default="IMPLEMENTED_TESTING_DEFERRED")
    ap.add_argument("--scope", action="append", default=[])
    ap.add_argument("--validation-json", default="")
    args = ap.parse_args()
    validation = {}
    if args.validation_json:
        validation = json.loads(Path(args.validation_json).read_text(encoding="utf-8"))
    result = build(
        Path(args.root), Path(args.output), parent=args.parent, status=args.status,
        scope=args.scope, validation=validation,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
