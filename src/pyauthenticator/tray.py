"""System tray integration: minimize-to-tray and quick actions."""

from __future__ import annotations

from typing import Callable

from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QApplication, QMenu, QSystemTrayIcon, QWidget


class TrayIcon(QSystemTrayIcon):
    """System tray icon with Show/Hide and Quit actions."""

    def __init__(
        self,
        icon: QIcon,
        parent_window: QWidget,
        on_quit: Callable[[], None],
    ) -> None:
        super().__init__(icon, parent_window)
        self._window = parent_window
        self.setToolTip("PyAuthenticator")

        menu = QMenu()
        self.show_action = QAction("Show PyAuthenticator")
        self.show_action.triggered.connect(self._show_window)
        menu.addAction(self.show_action)

        quit_action = QAction("Quit")
        quit_action.triggered.connect(on_quit)
        menu.addAction(quit_action)

        self.setContextMenu(menu)
        self.activated.connect(self._on_activated)

    def _show_window(self) -> None:
        self._window.showNormal()
        self._window.raise_()
        self._window.activateWindow()

    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            if self._window.isVisible():
                self._window.hide()
            else:
                self._show_window()

    def notify_hidden_to_tray(self) -> None:
        if QApplication.instance() is not None:
            self.showMessage(
                "PyAuthenticator",
                "Still running in the system tray.",
                QSystemTrayIcon.MessageIcon.Information,
                2000,
            )
