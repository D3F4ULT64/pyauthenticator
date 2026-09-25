"""Tests for local and password-based encryption (crypto.py)."""

from pathlib import Path

import pytest

from pyauthenticator import crypto


@pytest.fixture(autouse=True)
def isolated_config_dirs(tmp_path, monkeypatch):
    """Redirect config/data dirs to a temp folder so tests never touch
    the real user's config, and disable keyring so the local-file
    fallback path is exercised deterministically."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(crypto, "keyring", None)
    yield


def test_get_or_create_key_is_stable_across_calls():
    key1 = crypto.get_or_create_key()
    key2 = crypto.get_or_create_key()
    assert key1 == key2


def test_local_key_file_has_restricted_permissions(tmp_path):
    crypto.get_or_create_key()
    key_file = crypto._local_key_file()
    assert key_file.exists()


def test_encrypt_decrypt_roundtrip_bytes():
    data = b"super-secret-totp-seed"
    encrypted = crypto.encrypt_bytes(data)
    assert encrypted != data
    decrypted = crypto.decrypt_bytes(encrypted)
    assert decrypted == data


def test_encrypt_decrypt_roundtrip_str():
    text = "JBSWY3DPEHPK3PXP"
    encrypted = crypto.encrypt_str(text)
    assert encrypted != text
    assert crypto.decrypt_str(encrypted) == text


def test_decrypt_with_wrong_key_fails():
    from cryptography.fernet import Fernet

    data = b"secret"
    encrypted = crypto.encrypt_bytes(data)
    wrong_key = Fernet.generate_key()
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_bytes(encrypted, key=wrong_key)


def test_password_based_encryption_roundtrip():
    data = b'{"accounts": []}'
    blob = crypto.encrypt_with_password(data, "correct horse battery staple")
    decrypted = crypto.decrypt_with_password(blob, "correct horse battery staple")
    assert decrypted == data


def test_password_based_encryption_wrong_password_fails():
    data = b"backup contents"
    blob = crypto.encrypt_with_password(data, "right-password")
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_with_password(blob, "wrong-password")
