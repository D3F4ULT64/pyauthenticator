"""Tests for RFC 6238 TOTP generation logic."""

import pytest

from pyauthenticator.totp import (
    InvalidSecretError,
    TotpParams,
    fraction_elapsed,
    generate_code,
    seconds_remaining,
    validate_secret,
)

# RFC 6238 test vector secret ("12345678901234567890" ASCII, base32 encoded)
RFC_SECRET_SHA1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def test_generate_code_returns_correct_digit_count():
    params = TotpParams(secret=RFC_SECRET_SHA1, digits=6, period=30)
    code = generate_code(params)
    assert len(code) == 6
    assert code.isdigit()


def test_generate_code_is_deterministic_for_a_given_time():
    params = TotpParams(secret=RFC_SECRET_SHA1, digits=8, period=30)
    code_a = generate_code(params, at_time=59)
    code_b = generate_code(params, at_time=59)
    assert code_a == code_b
    assert len(code_a) == 8


def test_generate_code_changes_across_periods():
    params = TotpParams(secret=RFC_SECRET_SHA1, period=30)
    code_window_1 = generate_code(params, at_time=1)
    code_window_2 = generate_code(params, at_time=31)
    assert code_window_1 != code_window_2


def test_seconds_remaining_boundaries():
    assert seconds_remaining(30, at_time=0) == 30
    assert seconds_remaining(30, at_time=1) == 29
    assert seconds_remaining(30, at_time=29) == 1
    assert seconds_remaining(30, at_time=30) == 30


def test_fraction_elapsed_boundaries():
    assert fraction_elapsed(30, at_time=0) == 0.0
    assert fraction_elapsed(30, at_time=15) == 0.5
    assert fraction_elapsed(30, at_time=29) == pytest.approx(29 / 30)


def test_invalid_algorithm_raises():
    with pytest.raises(ValueError):
        TotpParams(secret=RFC_SECRET_SHA1, algorithm="MD5")


def test_invalid_digits_raises():
    with pytest.raises(ValueError):
        TotpParams(secret=RFC_SECRET_SHA1, digits=3)


def test_invalid_secret_raises_invalid_secret_error():
    params = TotpParams(secret="not-valid-base32!!!")
    with pytest.raises(InvalidSecretError):
        generate_code(params)


def test_validate_secret():
    assert validate_secret(RFC_SECRET_SHA1) is True
    assert validate_secret("###invalid###") is False


def test_sha256_and_sha512_supported():
    for algo in ("SHA256", "SHA512"):
        params = TotpParams(secret=RFC_SECRET_SHA1, algorithm=algo)
        code = generate_code(params, at_time=100)
        assert len(code) == 6
