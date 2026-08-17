"""secretbox — stdlib-only authenticated encryption for secrets at rest.

Zero external dependencies (project constraint): uses hashlib/hmac/secrets
from the standard library. This protects stored credentials (like a Sophos
CLIENT_SECRET) against someone who reads the database file — NOT against a
full compromise of the host, since the master key lives on the same box.

Scheme (encrypt-then-MAC, authenticated):
  * A master key is persisted once in app_config ('secretbox_master'), 32
    random bytes, base64. Treat the DB and that row as sensitive.
  * Per-secret: random 16-byte salt + 16-byte nonce.
  * enc_key, mac_key = HKDF-ish split of PBKDF2-HMAC-SHA256(master, salt).
  * Keystream = SHA256(enc_key || nonce || counter) blocks, XORed with the
    plaintext (a stdlib stream cipher construction).
  * Tag = HMAC-SHA256(mac_key, salt || nonce || ciphertext); verified on
    decrypt before returning (authenticated — tampering is detected).

This is deliberately conservative and simple. If the `cryptography` package
ever becomes acceptable, swap this for Fernet/AES-GCM; the call sites use
encrypt()/decrypt() and won't change.
"""

import base64
import hashlib
import hmac
import secrets
import struct

_PBKDF2_ROUNDS = 200_000
_MAGIC = b"SB1"  # format version marker


def generate_master() -> str:
    """A fresh base64 master key (store once in app_config)."""
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def _derive(master: bytes, salt: bytes):
    dk = hashlib.pbkdf2_hmac("sha256", master, salt, _PBKDF2_ROUNDS, dklen=64)
    return dk[:32], dk[32:]  # enc_key, mac_key


def _keystream(enc_key: bytes, nonce: bytes, n: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        block = hashlib.sha256(enc_key + nonce + struct.pack(">I", counter)).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:n])


def encrypt(plaintext: str, master_b64: str) -> str:
    """Return a base64 token embedding salt, nonce, ciphertext, and tag."""
    if plaintext is None:
        plaintext = ""
    master = base64.b64decode(master_b64)
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    enc_key, mac_key = _derive(master, salt)
    pt = plaintext.encode("utf-8")
    ct = bytes(a ^ b for a, b in zip(pt, _keystream(enc_key, nonce, len(pt))))
    tag = hmac.new(mac_key, salt + nonce + ct, hashlib.sha256).digest()
    blob = _MAGIC + salt + nonce + tag + ct
    return base64.b64encode(blob).decode("ascii")


def decrypt(token: str, master_b64: str) -> str:
    """Reverse encrypt(). Raises ValueError if the tag doesn't verify."""
    master = base64.b64decode(master_b64)
    blob = base64.b64decode(token)
    if blob[:3] != _MAGIC:
        raise ValueError("unrecognized secret format")
    off = 3
    salt = blob[off:off + 16]; off += 16
    nonce = blob[off:off + 16]; off += 16
    tag = blob[off:off + 32]; off += 32
    ct = blob[off:]
    enc_key, mac_key = _derive(master, salt)
    expected = hmac.new(mac_key, salt + nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("authentication failed — secret was tampered or wrong key")
    pt = bytes(a ^ b for a, b in zip(ct, _keystream(enc_key, nonce, len(ct))))
    return pt.decode("utf-8")
