#!/usr/bin/env python3
"""Build a self-contained mini-SIEM dashboard connector return ZIP.

The return bundle includes the integration source files in their repository
paths as well as the contract handoff, schemas, generated fixtures and tests.
It never includes runtime databases, credentials, caches or Git metadata.
"""

import argparse
import hashlib
import json
import shutil
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import Path


RETURN_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = RETURN_ROOT.parents[1]

EXCLUDED_DIRS = {".git", "return", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules"}
SOURCE_SUFFIXES = {".py", ".md", ".json", ".txt", ".html", ".css", ".js", ".sh", ".sql", ".yaml", ".yml", ".ps1", ".xml", ".conf"}
RUNTIME_NAMES = {"auth-config.json", "db-config.json", "db-listener-credentials.json", "db-dashboard-credentials.json", "db-maintenance-credentials.json"}

SOURCE_FILES = (
    "dashboard_connector.py",
    "dashboard.py",
    "auth.py",
    "db.py",
    "runtime_health.py",
    "requirements-dev.txt",
    "schemas/operator_workspace/control.schema.json",
    "schemas/operator_workspace/page.schema.json",
    "schemas/operator_workspace/resource-manifest.json",
    "tools/manage_dashboard_reader_token.py",
    "tools/postgres_privilege_boundary.py",
    "tests/test_dashboard_connector.py",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare_source_payload(refresh_local_manifest=False):
    source_root = RETURN_ROOT / "source"
    if source_root.resolve() != (PROJECT_ROOT / "return" / "mini-siem" / "source").resolve():
        raise SystemExit("source refresh must run in the authoritative repository layout")
    # The current dashboard imports the complete detection/UI stack. Shipping
    # only the former twelve-file overlay would mix incompatible versions.
    selected = []
    for source in sorted(PROJECT_ROOT.rglob("*")):
        relative = source.relative_to(PROJECT_ROOT)
        if set(relative.parts) & EXCLUDED_DIRS or not source.is_file():
            continue
        if source.name in RUNTIME_NAMES or source.name.startswith(".env") or source.name == "ARTIFACT_MANIFEST.json":
            continue
        if source.suffix.lower() not in SOURCE_SUFFIXES and source.name != ".gitignore":
            continue
        if source.is_symlink():
            raise SystemExit(f"source symlink is not allowed: {relative}")
        selected.append(relative.as_posix())
    # Keep the source snapshot independently testable/rebuildable without copying
    # generated fixture trees or recursively embedding an earlier return payload.
    selected.extend(path.relative_to(PROJECT_ROOT).as_posix()
                    for path in sorted((RETURN_ROOT / "tools").glob("*.py")))
    missing = set(SOURCE_FILES) - set(selected)
    if missing:
        raise SystemExit(f"required integration source is missing: {sorted(missing)}")
    if source_root.exists():
        shutil.rmtree(source_root)
    entries = []
    for relative in selected:
        source = PROJECT_ROOT / relative
        if not source.is_file():
            raise SystemExit(f"required integration source is missing: {source}")
        destination = source_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        entries.append({"path": relative, "sha256": digest(destination)})
    if refresh_local_manifest:
        local = PROJECT_ROOT / "ARTIFACT_MANIFEST.json"
        parent = digest(local) if local.is_file() else None
        metadata = {
            "artifact": "mini-siem-dashboard-return-rebuild-2026-10-22",
            "artifact_kind": "Local safe source snapshot; connector archive and external checksum under return/",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "parent_manifest_sha256": parent,
            "status": "IMPLEMENTED_TESTING_DEFERRED",
            "scope": ["Dashboard connector return recovery and current-source integration; October 17-18 detection and UI retained"],
            "validation": {"offline_evidence": "return/mini-siem/test-logs/offline-checks.json",
                           "full_R3_G1": "PARTIAL", "live_deployment": "NOT_RUN"},
            "manifest_hash_scope": "safe application source and return tools; excludes self, runtime state, credentials and generated return payload",
            "file_count_excluding_manifest": len(entries),
            "files": [{"path": item["path"], "size": (PROJECT_ROOT / item["path"]).stat().st_size,
                       "sha256": item["sha256"]} for item in entries],
        }
        local.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        shutil.copyfile(local, source_root / "ARTIFACT_MANIFEST.json")
        entries.append({"path": "ARTIFACT_MANIFEST.json", "sha256": digest(local)})
        entries.sort(key=lambda item: item["path"])
    manifest = {
        "package": "mini-siem-dashboard-connector",
        "source_layout": "repository-relative",
        "installation": "Complete safe source snapshot. Preserve local runtime configuration; run owner initialization and role grants before restart.",
        "files": entries,
    }
    (RETURN_ROOT / "SOURCE_MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def verify_checksums():
    sums = RETURN_ROOT / "SHA256SUMS"
    if not sums.is_file():
        raise SystemExit("SHA256SUMS is missing; regenerate and validate the return first")
    covered = set()
    for line in sums.read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        path = (RETURN_ROOT / relative).resolve()
        if RETURN_ROOT.resolve() not in path.parents or relative in covered:
            raise SystemExit(f"unsafe or duplicate checksum path: {relative}")
        covered.add(relative)
        if not path.is_file() or digest(path) != expected:
            raise SystemExit(f"return checksum verification failed: {relative}")
    actual = {p.relative_to(RETURN_ROOT).as_posix() for p in package_files() if p.name != "SHA256SUMS"}
    if covered != actual:
        raise SystemExit(f"checksum inventory mismatch: missing={sorted(actual-covered)} extra={sorted(covered-actual)}")


def package_files():
    files = []
    for path in sorted(RETURN_ROOT.rglob("*")):
        relative = path.relative_to(RETURN_ROOT)
        if set(relative.parts) & {"__pycache__", ".pytest_cache", ".git"}:
            continue
        if path.is_symlink():
            raise SystemExit(f"return symlink is not allowed: {relative}")
        if not path.is_file():
            continue
        if path.suffix.lower() in {".pyc", ".pyo", ".db", ".sqlite", ".sqlite3", ".db-wal", ".db-shm", ".key", ".pem"} or path.name in RUNTIME_NAMES or path.name.startswith(".env"):
            raise SystemExit(f"unsafe return member: {relative}")
        files.append(path)
    return files


def build_zip(output):
    output = output.resolve()
    if RETURN_ROOT.resolve() in output.parents:
        raise SystemExit("archive output must stay outside its own return payload")
    verify_checksums()
    files = package_files()
    if len(files) > 512 or sum(path.stat().st_size for path in files) > 32 * 1024 * 1024:
        raise SystemExit("return exceeds the reviewed Dashboard archive entry/expanded-byte budget")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9) as archive:
        for path in files:
            name = (Path("mini-siem") / path.relative_to(RETURN_ROOT)).as_posix()
            info = zipfile.ZipInfo.from_file(path, arcname=name)
            info.create_system = 3
            mode = 0o755 if path.suffix == ".sh" or path.read_bytes().startswith(b"#!") else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    with zipfile.ZipFile(output, "r") as archive:
        bad = archive.testzip()
        if bad:
            raise SystemExit(f"ZIP integrity check failed: {bad}")
    archive_digest = digest(output)
    Path(str(output) + ".sha256").write_text(archive_digest + "  " + output.name + "\n", encoding="utf-8")
    print(json.dumps({"status": "PASS", "zip": str(output),
                      "bytes": output.stat().st_size,
                      "sha256": archive_digest}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare", action="store_true",
                        help="refresh source/ and SOURCE_MANIFEST.json only")
    parser.add_argument("--refresh-local-manifest", action="store_true",
                        help="with --prepare, refresh and include the authoritative local source inventory")
    parser.add_argument("--output", type=Path,
                        default=RETURN_ROOT.parent / "mini-siem-return-package.zip")
    args = parser.parse_args()
    if args.prepare:
        prepare_source_payload(args.refresh_local_manifest)
        return
    build_zip(args.output.resolve())


if __name__ == "__main__":
    main()
