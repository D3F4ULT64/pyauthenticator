"""Tests for otpauth:// URI parsing (qr.py)."""

import pytest

from pyauthenticator.qr import InvalidOtpUriError, parse_otpauth_uri
from pyauthenticator.storage import Account


def test_parse_basic_otpauth_uri():
    uri = (
        "otpauth://totp/GitHub:default@example.com"
        "?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
    )
    account = parse_otpauth_uri(uri)
    assert isinstance(account, Account)
    assert account.issuer == "GitHub"
    assert account.account == "default@example.com"
    assert account.secret == "JBSWY3DPEHPK3PXP"
    assert account.algorithm == "SHA1"
    assert account.digits == 6
    assert account.period == 30


def test_parse_uri_with_all_optional_params():
    uri = (
        "otpauth://totp/Google:me@gmail.com"
        "?secret=ABCDEFGH234567&issuer=Google&algorithm=SHA256&digits=8&period=60"
    )
    account = parse_otpauth_uri(uri)
    assert account.issuer == "Google"
    assert account.account == "me@gmail.com"
    assert account.algorithm == "SHA256"
    assert account.digits == 8
    assert account.period == 60


def test_parse_uri_without_issuer_param_falls_back_to_label():
    uri = "otpauth://totp/MyService:user1?secret=JBSWY3DPEHPK3PXP"
    account = parse_otpauth_uri(uri)
    assert account.issuer == "MyService"
    assert account.account == "user1"


def test_parse_uri_missing_secret_raises():
    uri = "otpauth://totp/GitHub:default@example.com?issuer=GitHub"
    with pytest.raises(InvalidOtpUriError):
        parse_otpauth_uri(uri)


def test_parse_uri_wrong_scheme_raises():
    with pytest.raises(InvalidOtpUriError):
        parse_otpauth_uri("https://example.com/not-otp-auth")


def test_parse_uri_invalid_algorithm_falls_back_to_sha1():
    uri = "otpauth://totp/Foo:bar?secret=JBSWY3DPEHPK3PXP&algorithm=MD5"
    account = parse_otpauth_uri(uri)
    assert account.algorithm == "SHA1"
