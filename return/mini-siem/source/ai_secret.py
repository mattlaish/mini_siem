"""Secure storage helper for the external AI provider API key.

The encrypted API key is stored in ``app_config``; the encryption master is
kept outside the database so a database-only disclosure does not expose both
ciphertext and key material.

Installed service deployments use ``MINISIEM_AI_SECRET_MASTER_FILE`` (set by
``install-services.sh``) and keep the master under ``/var/lib/mini-siem``.
Development/manual runs fall back to ``~/.mini-siem/ai-secret-master.key``.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

import secretbox

_ENV_PATH = "MINISIEM_AI_SECRET_MASTER_FILE"
_DEFAULT_NAME = "ai-secret-master.key"


def _validate_master(value: str) -> str:
    text = (value or "").strip()
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception as exc:
        raise RuntimeError("AI secret master is not valid base64") from exc
    if len(raw) != 32:
        raise RuntimeError("AI secret master must decode to exactly 32 bytes")
    return text


def master_path() -> Path:
    configured = (os.environ.get(_ENV_PATH) or "").strip()
    if configured:
        return Path(configured).expanduser()
    home = Path(os.environ.get("HOME") or str(Path.home())).expanduser()
    return home / ".mini-siem" / _DEFAULT_NAME


def load_master(path: str | os.PathLike | None = None) -> str:
    """Load an existing master without creating replacement key material.

    Decrypt paths use this fail-closed helper so a restore that forgot the
    external master cannot silently generate a different key and mask the
    recovery error.
    """
    target = Path(path).expanduser() if path is not None else master_path()
    if not target.exists():
        raise RuntimeError(
            f"AI secret master file is missing: {target}; restore the original master "
            "before decrypting the stored API key"
        )
    try:
        mode = target.stat().st_mode & 0o777
    except OSError as exc:
        raise RuntimeError(f"cannot stat AI secret master file: {target}") from exc
    if mode & 0o077:
        raise RuntimeError(
            f"AI secret master file permissions are too broad ({oct(mode)}): {target}; "
            "require owner-only access (0600)"
        )
    try:
        return _validate_master(target.read_text(encoding="ascii"))
    except OSError as exc:
        raise RuntimeError(f"cannot read AI secret master file: {target}") from exc


def load_or_create_master(path: str | os.PathLike | None = None) -> str:
    target = Path(path).expanduser() if path is not None else master_path()
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)

    if target.exists():
        return load_master(target)

    value = secretbox.generate_master()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(target, flags, 0o600)
    except FileExistsError:
        return load_or_create_master(target)
    except OSError as exc:
        raise RuntimeError(f"cannot create AI secret master file: {target}") from exc
    try:
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(value + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    finally:
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
    return _validate_master(value)


def encrypt_api_key(api_key: str) -> str:
    return secretbox.encrypt(api_key or "", load_or_create_master())


def decrypt_api_key(token: str) -> str:
    if not token:
        return ""
    return secretbox.decrypt(token, load_master())
