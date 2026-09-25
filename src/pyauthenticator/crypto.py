"""Local encryption for stored secrets.

Strategy:
  1. Try to store/retrieve a symmetric encryption key in the OS
     credential manager via `keyring` (Windows Credential Locker,
     macOS Keychain, Linux Secret Service/KWallet).
  2. If `keyring` is unavailable or fails (e.g. headless Linux with
     no secret service running), fall back to a locally-stored key
     file with restrictive permissions (0600) under the user's
     config directory.

Either way, secrets are encrypted at rest with Fernet (AES-128-CBC +
HMAC) before touching disk, and are only ever decrypted in memory.

A *separate* password-based scheme (`encrypt_with_password` /
`decrypt_with_password`) is provided for portable, shareable backup
files, since those must be decryptable on another machine without
access to this machine's keyring/key file.
"""

from __future__ import annotations

import base64
import os
import stat
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    import keyring
    from keyring.errors import KeyringError
except Exception:  # pragma: no cover - keyring always installed, defensive
    keyring = None  # type: ignore[assignment]

    class KeyringError(Exception):  # type: ignore[no-redef]
        pass


SERVICE_NAME = "PyAuthenticator"
KEY_ACCOUNT_NAME = "local-encryption-key"

APP_DIR_NAME = "pyauthenticator"


class DecryptionError(Exception):
    """Raised when data cannot be decrypted (wrong key/password/corrupt)."""


def app_config_dir() -> Path:
    """Return (and create) the per-user application config directory."""
    base = os.environ.get("XDG_CONFIG_HOME")
    if base:
        root = Path(base)
    elif os.name == "nt":
        root = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        root = Path.home() / ".config"
    path = root / APP_DIR_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def app_data_dir() -> Path:
    """Return (and create) the per-user application data directory."""
    base = os.environ.get("XDG_DATA_HOME")
    if base:
        root = Path(base)
    elif os.name == "nt":
        root = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        root = Path.home() / ".local" / "share"
    path = root / APP_DIR_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def _local_key_file() -> Path:
    return app_config_dir() / "local.key"


def _read_local_key_file() -> bytes | None:
    path = _local_key_file()
    if not path.exists():
        return None
    return path.read_bytes()


def _write_local_key_file(key: bytes) -> None:
    path = _local_key_file()
    path.write_bytes(key)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass  # best effort on platforms without POSIX permissions


def get_or_create_key() -> bytes:
    """Return this machine's local Fernet key, creating it if needed.

    Prefers the OS credential manager; falls back to a restricted
    local file if that isn't available.
    """
    if keyring is not None:
        try:
            existing = keyring.get_password(SERVICE_NAME, KEY_ACCOUNT_NAME)
            if existing:
                return existing.encode("utf-8")
            new_key = Fernet.generate_key()
            keyring.set_password(SERVICE_NAME, KEY_ACCOUNT_NAME, new_key.decode("utf-8"))
            return new_key
        except KeyringError:
            pass  # fall through to file-based fallback

    existing_file_key = _read_local_key_file()
    if existing_file_key:
        return existing_file_key
    new_key = Fernet.generate_key()
    _write_local_key_file(new_key)
    return new_key


def encrypt_bytes(data: bytes, key: bytes | None = None) -> bytes:
    fernet = Fernet(key or get_or_create_key())
    return fernet.encrypt(data)


def decrypt_bytes(token: bytes, key: bytes | None = None) -> bytes:
    fernet = Fernet(key or get_or_create_key())
    try:
        return fernet.decrypt(token)
    except InvalidToken as exc:
        raise DecryptionError("Failed to decrypt data: invalid key or corrupt file") from exc


def encrypt_str(text: str, key: bytes | None = None) -> str:
    return encrypt_bytes(text.encode("utf-8"), key).decode("utf-8")


def decrypt_str(token: str, key: bytes | None = None) -> str:
    return decrypt_bytes(token.encode("utf-8"), key).decode("utf-8")


# --- Password-based encryption for portable backup files ---------------

_PBKDF2_ITERATIONS = 390_000
_SALT_SIZE = 16


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_with_password(data: bytes, password: str) -> bytes:
    """Encrypt `data` with a password, returning a self-contained blob.

    Layout: [16-byte salt][fernet token]. The salt is not secret.
    """
    salt = os.urandom(_SALT_SIZE)
    key = _derive_key(password, salt)
    token = Fernet(key).encrypt(data)
    return salt + token


def decrypt_with_password(blob: bytes, password: str) -> bytes:
    if len(blob) <= _SALT_SIZE:
        raise DecryptionError("Backup file is corrupt or truncated")
    salt, token = blob[:_SALT_SIZE], blob[_SALT_SIZE:]
    key = _derive_key(password, salt)
    try:
        return Fernet(key).decrypt(token)
    except InvalidToken as exc:
        raise DecryptionError("Wrong password or corrupt backup file") from exc
