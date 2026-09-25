"""Generate a sample otpauth:// QR code image for testing PyAuthenticator.

Usage:
    python examples/generate_sample_qr.py

Requires the extra dependency `qrcode` (not part of the app's own
requirements — this is just a convenience script for developers):

    pip install qrcode[pil]
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import qrcode
except ImportError:
    print("This script needs the 'qrcode' package: pip install qrcode[pil]")
    sys.exit(1)

SAMPLE_URI = (
    "otpauth://totp/GitHub:default@example.com"
    "?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30"
)


def main() -> None:
    out_path = Path(__file__).parent / "sample_github_qr.png"
    img = qrcode.make(SAMPLE_URI)
    img.save(out_path)
    print(f"Wrote sample QR code to {out_path}")
    print(f"Encoded URI: {SAMPLE_URI}")
    print("Drag this image onto PyAuthenticator, or use File -> Import QR Image.")


if __name__ == "__main__":
    main()
