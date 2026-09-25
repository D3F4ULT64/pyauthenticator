"""RFC 6238 TOTP code generation utilities.

This module contains no GUI code — it is pure logic so it can be
unit-tested and reused independently of PySide6.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import pyotp

SUPPORTED_ALGORITHMS = ("SHA1", "SHA256", "SHA512")


class InvalidSecretError(ValueError):
    """Raised when a base32 TOTP secret cannot be parsed."""


@dataclass(frozen=True)
class TotpParams:
    """Parameters required to generate a TOTP code (RFC 6238)."""

    secret: str
    algorithm: str = "SHA1"
    digits: int = 6
    period: int = 30

    def __post_init__(self) -> None:
        if self.algorithm.upper() not in SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
        if not (6 <= self.digits <= 10):
            raise ValueError("digits must be between 6 and 10")
        if self.period <= 0:
            raise ValueError("period must be positive")


def _totp_for(params: TotpParams) -> pyotp.TOTP:
    try:
        return pyotp.TOTP(
            s=params.secret,
            digits=params.digits,
            digest=_digest_for(params.algorithm),
            interval=params.period,
        )
    except Exception as exc:  # pyotp raises binascii.Error on bad base32
        raise InvalidSecretError(f"Invalid base32 secret: {exc}") from exc


def _digest_for(algorithm: str):
    import hashlib

    return {
        "SHA1": hashlib.sha1,
        "SHA256": hashlib.sha256,
        "SHA512": hashlib.sha512,
    }[algorithm.upper()]


def generate_code(params: TotpParams, *, at_time: float | None = None) -> str:
    """Generate the current (or given-time) TOTP code as a string."""
    totp = _totp_for(params)
    return totp.at(at_time) if at_time is not None else totp.now()


def seconds_remaining(period: int, *, at_time: float | None = None) -> int:
    """Seconds remaining until the current TOTP window rolls over."""
    now = at_time if at_time is not None else time.time()
    return period - int(now) % period


def fraction_elapsed(period: int, *, at_time: float | None = None) -> float:
    """Fraction (0.0-1.0) of the current period that has elapsed."""
    now = at_time if at_time is not None else time.time()
    return (int(now) % period) / period


def validate_secret(secret: str) -> bool:
    """Return True if `secret` is a plausible base32 TOTP secret."""
    try:
        generate_code(TotpParams(secret=secret))
        return True
    except InvalidSecretError:
        return False
