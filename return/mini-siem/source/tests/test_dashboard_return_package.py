"""Safety checks for the connector handoff archive, using disposable files."""
import hashlib
import importlib.util
import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def builder(tmp_path, monkeypatch):
    path = Path(__file__).parents[1] / "return/mini-siem/tools/build_return_package.py"
    spec = importlib.util.spec_from_file_location("return_builder_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    project = tmp_path / "project"
    returned = project / "return" / "mini-siem"
    returned.mkdir(parents=True)
    monkeypatch.setattr(module, "PROJECT_ROOT", project)
    monkeypatch.setattr(module, "RETURN_ROOT", returned)
    monkeypatch.setattr(module, "SOURCE_FILES", ("dashboard.py",))
    return module


def write(path, text="synthetic"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def checksums(builder):
    text = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(builder.RETURN_ROOT).as_posix()}\n"
                   for p in builder.package_files() if p.name != "SHA256SUMS")
    write(builder.RETURN_ROOT / "SHA256SUMS", text)


def test_prepare_keeps_complete_safe_source_and_excludes_runtime(builder):
    for name in ("dashboard.py", "detection.py", "templates/detection.html", "static/app.js", "requirements.txt"):
        write(builder.PROJECT_ROOT / name)
    for name in ("auth-config.json", "db-config.json", "siem.db", "private.pem", ".env", "archive.zip", "__pycache__/code.pyc"):
        write(builder.PROJECT_ROOT / name)
    builder.prepare_source_payload()
    names = {p.relative_to(builder.RETURN_ROOT / "source").as_posix()
             for p in (builder.RETURN_ROOT / "source").rglob("*") if p.is_file()}
    assert names == {"dashboard.py", "detection.py", "templates/detection.html", "static/app.js", "requirements.txt"}


def test_missing_required_source_does_not_delete_previous_payload(builder):
    write(builder.RETURN_ROOT / "source/previous.py")
    with pytest.raises(SystemExit, match="required integration source"):
        builder.prepare_source_payload()
    assert (builder.RETURN_ROOT / "source/previous.py").exists()


def test_archive_omits_old_python_cache(builder, tmp_path):
    write(builder.RETURN_ROOT / "HANDOFF.md")
    write(builder.RETURN_ROOT / "source/install.sh", "#!/bin/sh\nexit 0\n")
    write(builder.RETURN_ROOT / "tools/__pycache__/old.pyc")
    checksums(builder)
    archive = tmp_path / "returned.zip"
    builder.build_zip(archive)
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        assert set(z.namelist()) == {"mini-siem/HANDOFF.md", "mini-siem/SHA256SUMS", "mini-siem/source/install.sh"}
        assert (z.getinfo("mini-siem/source/install.sh").external_attr >> 16) & 0o777 == 0o755
        assert (z.getinfo("mini-siem/HANDOFF.md").external_attr >> 16) & 0o777 == 0o644


def test_unlisted_file_cannot_enter_archive(builder, tmp_path):
    write(builder.RETURN_ROOT / "HANDOFF.md")
    checksums(builder)
    write(builder.RETURN_ROOT / "unreviewed.txt")
    with pytest.raises(SystemExit, match="inventory mismatch"):
        builder.build_zip(tmp_path / "returned.zip")


def test_changed_member_fails_before_archive_creation(builder, tmp_path):
    write(builder.RETURN_ROOT / "HANDOFF.md")
    checksums(builder)
    write(builder.RETURN_ROOT / "HANDOFF.md", "changed")
    with pytest.raises(SystemExit, match="checksum verification failed"):
        builder.build_zip(tmp_path / "returned.zip")
    assert not (tmp_path / "returned.zip").exists()


def test_checksum_path_cannot_escape_return_root(builder):
    write(builder.RETURN_ROOT / "SHA256SUMS", "0" * 64 + "  ../../outside.txt\n")
    with pytest.raises(SystemExit, match="unsafe or duplicate"):
        builder.verify_checksums()


def test_runtime_file_in_return_is_rejected(builder):
    write(builder.RETURN_ROOT / "fixture.db")
    with pytest.raises(SystemExit, match="unsafe return member"):
        builder.package_files()


def test_duplicate_checksum_entry_is_rejected(builder):
    write(builder.RETURN_ROOT / "HANDOFF.md")
    checksums(builder)
    path = builder.RETURN_ROOT / "SHA256SUMS"
    write(path, path.read_text(encoding="utf-8") * 2)
    with pytest.raises(SystemExit, match="unsafe or duplicate"):
        builder.verify_checksums()
