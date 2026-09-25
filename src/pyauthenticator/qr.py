"""QR code decoding and otpauth:// URI parsing.

Decoding prefers `pyzbar` (libzbar) since it handles multiple QR
codes per image and rotated/skewed codes well. If pyzbar or its
native `libzbar` dependency is unavailable, we fall back to OpenCV's
`QRCodeDetector`, which ships as a pure pip wheel with no system
dependency.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .storage import Account
from .totp import SUPPORTED_ALGORITHMS

SUPPORTED_IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".bmp", ".webp"}


class QrDecodeError(Exception):
    """Raised when no QR code could be found/decoded in an image."""


class InvalidOtpUriError(ValueError):
    """Raised when a decoded string is not a valid otpauth:// URI."""


@dataclass
class DecodedImage:
    path: Path
    uris: list[str]


def is_supported_image(path: Path) -> bool:
    return path.suffix.lower() in SUPPORTED_IMAGE_SUFFIXES


def decode_qr_strings(path: Path) -> list[str]:
    """Return all QR payload strings found in the image at `path`."""
    results = _decode_with_pyzbar(path)
    if not results:
        results = _decode_with_opencv(path)
    if not results:
        raise QrDecodeError(f"No QR code found in {path.name}")
    return results


def _decode_with_pyzbar(path: Path) -> list[str]:
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode as zbar_decode
    except Exception:
        return []
    try:
        with Image.open(path) as img:
            img = img.convert("RGB")
            decoded = zbar_decode(img)
        return [d.data.decode("utf-8", errors="ignore") for d in decoded]
    except Exception:
        return []


def _decode_with_opencv(path: Path) -> list[str]:
    try:
        import cv2
    except Exception:
        return []
    try:
        image = cv2.imread(str(path))
        if image is None:
            return []
        detector = cv2.QRCodeDetector()
        # detectAndDecodeMulti handles more than one QR code per image
        ok, decoded_info, _points, _straight_qrcode = detector.detectAndDecodeMulti(image)
        if ok and decoded_info:
            return [s for s in decoded_info if s]
        text, _points, _ = detector.detectAndDecode(image)
        return [text] if text else []
    except Exception:
        return []


def parse_otpauth_uri(uri: str) -> Account:
    """Parse an ``otpauth://totp/...`` URI into an :class:`Account`."""
    parsed = urlparse(uri)
    if parsed.scheme != "otpauth" or parsed.netloc != "totp":
        raise InvalidOtpUriError(f"Not a supported otpauth TOTP URI: {uri!r}")

    label = unquote(parsed.path.lstrip("/"))
    query = parse_qs(parsed.query)

    secret_list = query.get("secret")
    if not secret_list or not secret_list[0]:
        raise InvalidOtpUriError("otpauth URI is missing the 'secret' parameter")
    secret = secret_list[0]

    issuer_param = query.get("issuer", [None])[0]

    # Label format is either "Issuer:account" or just "account"
    if ":" in label:
        label_issuer, _, label_account = label.partition(":")
    else:
        label_issuer, label_account = "", label

    issuer = (issuer_param or label_issuer or "Unknown").strip()
    account = (label_account or "unknown").strip()

    algorithm = query.get("algorithm", ["SHA1"])[0].upper()
    if algorithm not in SUPPORTED_ALGORITHMS:
        algorithm = "SHA1"

    try:
        digits = int(query.get("digits", ["6"])[0])
    except ValueError:
        digits = 6

    try:
        period = int(query.get("period", ["30"])[0])
    except ValueError:
        period = 30

    return Account(
        issuer=issuer,
        account=account,
        secret=secret,
        algorithm=algorithm,
        digits=digits,
        period=period,
    )


def accounts_from_image(path: Path) -> list[Account]:
    """Decode all otpauth URIs in an image into Account objects.

    Non-otpauth QR payloads in the same image are silently skipped.
    """
    uris = decode_qr_strings(path)
    accounts: list[Account] = []
    for uri in uris:
        try:
            accounts.append(parse_otpauth_uri(uri))
        except InvalidOtpUriError:
            continue
    if not accounts:
        raise InvalidOtpUriError(f"No valid otpauth:// QR code found in {path.name}")
    return accounts
