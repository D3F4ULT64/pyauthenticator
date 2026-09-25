"""Tests for account persistence (storage.py)."""

import pytest

from pyauthenticator import crypto
from pyauthenticator.storage import Account, DuplicateAccountError, StorageManager


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(crypto, "keyring", None)
    yield


@pytest.fixture
def data_file(tmp_path):
    return tmp_path / "accounts.enc"


def make_account(issuer="GitHub", account="me@example.com", secret="JBSWY3DPEHPK3PXP"):
    return Account(issuer=issuer, account=account, secret=secret)


def test_new_storage_starts_empty(data_file):
    storage = StorageManager(data_path=data_file)
    assert storage.accounts == []


def test_add_and_persist_account(data_file):
    storage = StorageManager(data_path=data_file)
    storage.add_account(make_account())
    assert len(storage.accounts) == 1
    assert data_file.exists()

    # Reload from disk into a fresh manager instance
    reloaded = StorageManager(data_path=data_file)
    assert len(reloaded.accounts) == 1
    assert reloaded.accounts[0].issuer == "GitHub"
    assert reloaded.accounts[0].secret == "JBSWY3DPEHPK3PXP"


def test_duplicate_account_raises(data_file):
    storage = StorageManager(data_path=data_file)
    storage.add_account(make_account())
    with pytest.raises(DuplicateAccountError):
        storage.add_account(make_account())


def test_duplicate_account_can_be_replaced(data_file):
    storage = StorageManager(data_path=data_file)
    storage.add_account(make_account(secret="OLDSECRET234567"))
    storage.add_account(make_account(secret="NEWSECRET234567"), replace=True)
    assert len(storage.accounts) == 1
    assert storage.accounts[0].secret == "NEWSECRET234567"


def test_delete_account(data_file):
    storage = StorageManager(data_path=data_file)
    storage.add_account(make_account())
    uid = storage.accounts[0].uid
    storage.delete_account(uid)
    assert storage.accounts == []


def test_update_account(data_file):
    storage = StorageManager(data_path=data_file)
    storage.add_account(make_account())
    account = storage.accounts[0]
    account.issuer = "Renamed"
    storage.update_account(account)
    assert storage.accounts[0].issuer == "Renamed"


def test_export_and_import_backup_roundtrip(tmp_path, data_file):
    storage = StorageManager(data_path=data_file)
    storage.add_account(make_account(issuer="GitHub"))
    storage.add_account(make_account(issuer="Google", account="me@gmail.com"))

    backup_path = tmp_path / "backup.pyauth"
    storage.export_backup(backup_path, password="hunter2")

    fresh_storage = StorageManager(data_path=tmp_path / "other_accounts.enc")
    imported_count = fresh_storage.import_backup(backup_path, password="hunter2")
    assert imported_count == 2
    assert len(fresh_storage.accounts) == 2


def test_import_backup_wrong_password_raises(tmp_path, data_file):
    storage = StorageManager(data_path=data_file)
    storage.add_account(make_account())
    backup_path = tmp_path / "backup.pyauth"
    storage.export_backup(backup_path, password="correct")

    fresh_storage = StorageManager(data_path=tmp_path / "other_accounts.enc")
    with pytest.raises(crypto.DecryptionError):
        fresh_storage.import_backup(backup_path, password="wrong")


def test_stored_file_is_encrypted_on_disk(data_file):
    storage = StorageManager(data_path=data_file)
    storage.add_account(make_account())
    raw_bytes = data_file.read_bytes()
    assert b"JBSWY3DPEHPK3PXP" not in raw_bytes
    assert b"GitHub" not in raw_bytes
