"""Local, encrypted persistence for authenticator accounts.

Accounts are stored as a single JSON document, encrypted at rest with
the machine-local key from :mod:`pyauthenticator.crypto`. Generated
TOTP codes are never persisted — only the parameters needed to
compute them (secret, algorithm, digits, period).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import crypto

DEFAULT_DATA_FILENAME = "accounts.enc"


@dataclass
class Account:
    """A single TOTP account (issuer + user), never storing live codes."""

    issuer: str
    account: str
    secret: str
    algorithm: str = "SHA1"
    digits: int = 6
    period: int = 30
    uid: str = field(default_factory=lambda: uuid.uuid4().hex)

    def identity_key(self) -> tuple[str, str]:
        """Key used to detect duplicate accounts (issuer + account name)."""
        return (self.issuer.strip().lower(), self.account.strip().lower())

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Account":
        return cls(
            issuer=data["issuer"],
            account=data["account"],
            secret=data["secret"],
            algorithm=data.get("algorithm", "SHA1"),
            digits=int(data.get("digits", 6)),
            period=int(data.get("period", 30)),
            uid=data.get("uid", uuid.uuid4().hex),
        )


class DuplicateAccountError(Exception):
    """Raised when adding an account that already exists (same identity)."""

    def __init__(self, existing: Account):
        self.existing = existing
        super().__init__(f"Account already exists: {existing.issuer} ({existing.account})")


class StorageManager:
    """Loads/saves the encrypted account list from/to disk."""

    def __init__(self, data_path: Path | None = None) -> None:
        self.data_path = data_path or (crypto.app_data_dir() / DEFAULT_DATA_FILENAME)
        self._accounts: list[Account] = []
        self.load()

    # -- persistence -------------------------------------------------

    def load(self) -> None:
        if not self.data_path.exists():
            self._accounts = []
            return
        encrypted = self.data_path.read_bytes()
        if not encrypted:
            self._accounts = []
            return
        raw = crypto.decrypt_bytes(encrypted)
        payload = json.loads(raw.decode("utf-8"))
        self._accounts = [Account.from_dict(d) for d in payload.get("accounts", [])]

    def save(self) -> None:
        payload = {"version": 1, "accounts": [a.to_dict() for a in self._accounts]}
        raw = json.dumps(payload).encode("utf-8")
        encrypted = crypto.encrypt_bytes(raw)
        self.data_path.write_bytes(encrypted)

    # -- queries -------------------------------------------------------

    @property
    def accounts(self) -> list[Account]:
        return list(self._accounts)

    def find_duplicate(self, account: Account) -> Account | None:
        key = account.identity_key()
        for existing in self._accounts:
            if existing.identity_key() == key:
                return existing
        return None

    def get(self, uid: str) -> Account | None:
        for a in self._accounts:
            if a.uid == uid:
                return a
        return None

    # -- mutations -----------------------------------------------------

    def add_account(self, account: Account, *, replace: bool = False) -> None:
        duplicate = self.find_duplicate(account)
        if duplicate is not None:
            if not replace:
                raise DuplicateAccountError(duplicate)
            self._accounts.remove(duplicate)
        self._accounts.append(account)
        self.save()

    def update_account(self, account: Account) -> None:
        for i, existing in enumerate(self._accounts):
            if existing.uid == account.uid:
                self._accounts[i] = account
                self.save()
                return
        raise KeyError(f"No account with uid {account.uid}")

    def delete_account(self, uid: str) -> None:
        self._accounts = [a for a in self._accounts if a.uid != uid]
        self.save()

    # -- import / export -------------------------------------------------

    def export_backup(self, path: Path, password: str) -> None:
        """Write all accounts to an encrypted, password-protected backup file."""
        payload = {"version": 1, "accounts": [a.to_dict() for a in self._accounts]}
        raw = json.dumps(payload).encode("utf-8")
        blob = crypto.encrypt_with_password(raw, password)
        Path(path).write_bytes(blob)

    def import_backup(self, path: Path, password: str, *, replace_existing: bool = False) -> int:
        """Import accounts from a backup file. Returns count of accounts imported."""
        blob = Path(path).read_bytes()
        raw = crypto.decrypt_with_password(blob, password)
        payload = json.loads(raw.decode("utf-8"))
        imported = 0
        for d in payload.get("accounts", []):
            account = Account.from_dict(d)
            account.uid = uuid.uuid4().hex  # avoid uid collisions across machines
            try:
                self.add_account(account, replace=replace_existing)
                imported += 1
            except DuplicateAccountError:
                continue
        return imported

    def export_single_account(self, account: Account, path: Path, password: str) -> None:
        payload = {"version": 1, "accounts": [account.to_dict()]}
        raw = json.dumps(payload).encode("utf-8")
        blob = crypto.encrypt_with_password(raw, password)
        Path(path).write_bytes(blob)
