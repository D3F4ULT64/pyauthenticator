"""Application bootstrap: wires storage, main window, and system tray."""

from __future__ import annotations

import sys

from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import QApplication

from .gui import MainWindow
from .storage import StorageManager
from .tray import TrayIcon


def _build_fallback_icon() -> QIcon:
    """Generate a simple in-memory app icon (no external asset needed)."""
    pixmap = QPixmap(64, 64)
    pixmap.fill(QColor(0, 0, 0, 0))
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QColor("#4f6df5"))
    painter.setPen(QColor("#4f6df5"))
    painter.drawRoundedRect(4, 4, 56, 56, 16, 16)
    painter.setPen(QColor("white"))
    font = painter.font()
    font.setBold(True)
    font.setPointSize(28)
    painter.setFont(font)
    painter.drawText(pixmap.rect(), 0x0084, "PA")  # Qt.AlignCenter
    painter.end()
    return QIcon(pixmap)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("PyAuthenticator")
    app.setQuitOnLastWindowClosed(False)

    icon = _build_fallback_icon()
    app.setWindowIcon(icon)

    storage = StorageManager()
    window = MainWindow(storage)
    window.setWindowIcon(icon)

    tray = TrayIcon(icon, window, on_quit=app.quit)
    window.set_tray(tray)
    if tray.isSystemTrayAvailable():
        tray.show()

    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
