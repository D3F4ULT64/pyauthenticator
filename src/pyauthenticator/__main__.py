"""Allows running the app with `python -m pyauthenticator`."""

import sys

from .app import main

if __name__ == "__main__":
    sys.exit(main())
