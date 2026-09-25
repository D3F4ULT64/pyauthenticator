"""PySide6 GUI for PyAuthenticator.

This module only concerns itself with presentation and user
interaction; all TOTP math, QR decoding, and persistence live in
`totp.py`, `qr.py`, and `storage.py` respectively.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QMimeData, Qt, QTimer, Signal
from PySide6.QtGui import (
    QAction,
    QClipboard,
    QCloseEvent,
    QDragEnterEvent,
    QDropEvent,
    QFont,
)
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from . import qr
from .storage import Account, DuplicateAccountError, StorageManager
from .totp import TotpParams, fraction_elapsed, generate_code, seconds_remaining
from .tray import TrayIcon

LIGHT_QSS = """
QMainWindow, QWidget#central { background-color: #f2f3f7; }
QLabel#appTitle { font-size: 20px; font-weight: 700; color: #1a1a2e; }
QLabel#sectionLabel { font-size: 13px; font-weight: 600; color: #6b6f80; }
QLineEdit#searchBox {
    background: #ffffff; border: 1px solid #dcdfe6; border-radius: 8px;
    padding: 6px 10px; color: #1a1a2e;
}
QPushButton#actionButton {
    background-color: #4f6df5; color: white; border: none;
    border-radius: 8px; padding: 8px 14px; font-weight: 600;
}
QPushButton#actionButton:hover { background-color: #3d5ae0; }
QFrame#card {
    background-color: #ffffff; border-radius: 14px; border: 1px solid #e6e8ee;
}
QFrame#card:hover { border: 1px solid #4f6df5; }
QLabel#issuer { font-size: 15px; font-weight: 700; color: #1a1a2e; }
QLabel#accountName { font-size: 12px; color: #8a8fa3; }
QLabel#code { font-size: 26px; font-weight: 700; color: #1a1a2e; letter-spacing: 3px; }
QLabel#countdown { font-size: 11px; color: #8a8fa3; }
QProgressBar#ring {
    border: none; border-radius: 5px; background-color: #ecedf3; max-height: 8px;
}
QProgressBar#ring::chunk { background-color: #4f6df5; border-radius: 5px; }
QScrollArea { border: none; background: transparent; }
"""

DARK_QSS = """
QMainWindow, QWidget#central { background-color: #17181f; }
QLabel#appTitle { font-size: 20px; font-weight: 700; color: #f2f3f7; }
QLabel#sectionLabel { font-size: 13px; font-weight: 600; color: #9295a8; }
QLineEdit#searchBox {
    background: #23242e; border: 1px solid #33354a; border-radius: 8px;
    padding: 6px 10px; color: #f2f3f7;
}
QPushButton#actionButton {
    background-color: #6d87ff; color: #101018; border: none;
    border-radius: 8px; padding: 8px 14px; font-weight: 600;
}
QPushButton#actionButton:hover { background-color: #849bff; }
QFrame#card {
    background-color: #1f2029; border-radius: 14px; border: 1px solid #2c2d3a;
}
QFrame#card:hover { border: 1px solid #6d87ff; }
QLabel#issuer { font-size: 15px; font-weight: 700; color: #f2f3f7; }
QLabel#accountName { font-size: 12px; color: #9295a8; }
QLabel#code { font-size: 26px; font-weight: 700; color: #f2f3f7; letter-spacing: 3px; }
QLabel#countdown { font-size: 11px; color: #9295a8; }
QProgressBar#ring {
    border: none; border-radius: 5px; background-color: #2c2d3a; max-height: 8px;
}
QProgressBar#ring::chunk { background-color: #6d87ff; border-radius: 5px; }
QScrollArea { border: none; background: transparent; }
"""


class AccountCard(QFrame):
    """A rounded card showing one account's live TOTP code."""

    rename_requested = Signal(str)
    delete_requested = Signal(str)
    show_secret_requested = Signal(str)
    export_requested = Signal(str)

    def __init__(self, account: Account, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.account = account
        self.setObjectName("card")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._open_context_menu)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 12, 16, 12)
        outer.setSpacing(6)

        self.issuer_label = QLabel(account.issuer)
        self.issuer_label.setObjectName("issuer")
        self.account_label = QLabel(account.account)
        self.account_label.setObjectName("accountName")

        self.code_label = QLabel("------")
        self.code_label.setObjectName("code")
        code_font = QFont("Menlo, Consolas, Monospace")
        code_font.setStyleHint(QFont.StyleHint.Monospace)
        self.code_label.setFont(code_font)

        self.progress = QProgressBar()
        self.progress.setObjectName("ring")
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 1000)

        self.countdown_label = QLabel("")
        self.countdown_label.setObjectName("countdown")

        outer.addWidget(self.issuer_label)
        outer.addWidget(self.account_label)
        outer.addWidget(self.code_label)
        outer.addWidget(self.progress)
        outer.addWidget(self.countdown_label)

        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def refresh_code(self) -> None:
        params = TotpParams(
            secret=self.account.secret,
            algorithm=self.account.algorithm,
            digits=self.account.digits,
            period=self.account.period,
        )
        code = generate_code(params)
        spaced = " ".join(
            code[i : i + 3] for i in range(0, len(code), 3)
        )  # groups of 3 for readability
        self.code_label.setText(spaced)

        remaining = seconds_remaining(self.account.period)
        elapsed_fraction = fraction_elapsed(self.account.period)
        self.progress.setValue(int((1.0 - elapsed_fraction) * 1000))
        unit = "second" if remaining == 1 else "seconds"
        self.countdown_label.setText(f"{remaining} {unit}")

    def current_code(self) -> str:
        return self.code_label.text().replace(" ", "")

    def mousePressEvent(self, event) -> None:  # noqa: N802 (Qt override)
        if event.button() == Qt.MouseButton.LeftButton:
            QApplication.clipboard().setText(self.current_code(), QClipboard.Mode.Clipboard)
            self._flash_copied()
        super().mousePressEvent(event)

    def _flash_copied(self) -> None:
        original = self.countdown_label.text()
        self.countdown_label.setText("Copied!")
        QTimer.singleShot(900, lambda: self.countdown_label.setText(original))

    def _open_context_menu(self, pos) -> None:
        menu = QMenu(self)
        copy_action = menu.addAction("Copy code")
        rename_action = menu.addAction("Rename")
        show_secret_action = menu.addAction("Show secret")
        export_action = menu.addAction("Export")
        menu.addSeparator()
        delete_action = menu.addAction("Delete")

        chosen = menu.exec(self.mapToGlobal(pos))
        if chosen == copy_action:
            QApplication.clipboard().setText(self.current_code(), QClipboard.Mode.Clipboard)
            self._flash_copied()
        elif chosen == rename_action:
            self.rename_requested.emit(self.account.uid)
        elif chosen == show_secret_action:
            self.show_secret_requested.emit(self.account.uid)
        elif chosen == export_action:
            self.export_requested.emit(self.account.uid)
        elif chosen == delete_action:
            self.delete_requested.emit(self.account.uid)


class MainWindow(QMainWindow):
    """The application's main window: list of accounts + toolbar + search."""

    def __init__(self, storage: StorageManager) -> None:
        super().__init__()
        self.storage = storage
        self.cards: dict[str, AccountCard] = {}
        self.dark_mode = False

        self.setWindowTitle("PyAuthenticator")
        self.resize(420, 620)
        self.setAcceptDrops(True)
        self.setMinimumWidth(360)

        self._build_ui()
        self._apply_theme()
        self._rebuild_cards()

        self.refresh_timer = QTimer(self)
        self.refresh_timer.setInterval(1000)
        self.refresh_timer.timeout.connect(self._tick)
        self.refresh_timer.start()

        self.tray: TrayIcon | None = None

    # -- UI construction -------------------------------------------------

    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("central")
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(12)

        title_row = QHBoxLayout()
        title = QLabel("PyAuthenticator")
        title.setObjectName("appTitle")
        title_row.addWidget(title)
        title_row.addStretch(1)

        self.theme_button = QPushButton("🌙")
        self.theme_button.setFixedWidth(36)
        self.theme_button.setToolTip("Toggle dark / light mode")
        self.theme_button.clicked.connect(self._toggle_theme)
        title_row.addWidget(self.theme_button)
        root.addLayout(title_row)

        button_row = QHBoxLayout()
        add_qr_btn = QPushButton("+ Add QR")
        add_qr_btn.setObjectName("actionButton")
        add_qr_btn.clicked.connect(self._import_qr_dialog)
        import_btn = QPushButton("+ Import Image")
        import_btn.setObjectName("actionButton")
        import_btn.clicked.connect(self._import_qr_dialog)
        button_row.addWidget(add_qr_btn)
        button_row.addWidget(import_btn)
        button_row.addStretch(1)
        root.addLayout(button_row)

        self.search_box = QLineEdit()
        self.search_box.setObjectName("searchBox")
        self.search_box.setPlaceholderText("Search accounts...")
        self.search_box.textChanged.connect(self._apply_filter)
        root.addWidget(self.search_box)

        section_label = QLabel("Accounts")
        section_label.setObjectName("sectionLabel")
        root.addWidget(section_label)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.cards_container = QWidget()
        self.cards_layout = QVBoxLayout(self.cards_container)
        self.cards_layout.setSpacing(10)
        self.cards_layout.addStretch(1)
        self.scroll_area.setWidget(self.cards_container)
        root.addWidget(self.scroll_area, 1)

        self.empty_label = QLabel(
            "No accounts yet.\nDrag & drop a QR code image here, or use + Add QR."
        )
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.setWordWrap(True)

        self._build_menu()

    def _build_menu(self) -> None:
        menu_bar = self.menuBar()

        file_menu = menu_bar.addMenu("&File")
        import_action = QAction("Import QR Image...", self)
        import_action.triggered.connect(self._import_qr_dialog)
        file_menu.addAction(import_action)

        export_backup_action = QAction("Export Backup...", self)
        export_backup_action.triggered.connect(self._export_backup_dialog)
        file_menu.addAction(export_backup_action)

        import_backup_action = QAction("Import Backup...", self)
        import_backup_action.triggered.connect(self._import_backup_dialog)
        file_menu.addAction(import_backup_action)

        file_menu.addSeparator()
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(QApplication.quit)
        file_menu.addAction(exit_action)

        view_menu = menu_bar.addMenu("&View")
        toggle_theme_action = QAction("Toggle Dark / Light Mode", self)
        toggle_theme_action.triggered.connect(self._toggle_theme)
        view_menu.addAction(toggle_theme_action)

    # -- theme -------------------------------------------------------------

    def _apply_theme(self) -> None:
        app = QApplication.instance()
        app.setStyleSheet(DARK_QSS if self.dark_mode else LIGHT_QSS)
        self.theme_button.setText("☀️" if self.dark_mode else "🌙")

    def _toggle_theme(self) -> None:
        self.dark_mode = not self.dark_mode
        self._apply_theme()

    # -- account list rendering -------------------------------------------

    def _rebuild_cards(self) -> None:
        while self.cards_layout.count() > 1:
            item = self.cards_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        self.cards.clear()

        accounts = sorted(
            self.storage.accounts, key=lambda a: (a.issuer.lower(), a.account.lower())
        )
        if not accounts:
            self.cards_layout.insertWidget(0, self.empty_label)
            return

        for account in accounts:
            card = AccountCard(account)
            card.rename_requested.connect(self._rename_account)
            card.delete_requested.connect(self._delete_account)
            card.show_secret_requested.connect(self._show_secret)
            card.export_requested.connect(self._export_account)
            card.refresh_code()
            self.cards[account.uid] = card
            self.cards_layout.insertWidget(self.cards_layout.count() - 1, card)

        self._apply_filter(self.search_box.text())

    def _apply_filter(self, text: str) -> None:
        needle = text.strip().lower()
        for uid, card in self.cards.items():
            visible = (
                not needle
                or needle in card.account.issuer.lower()
                or needle in card.account.account.lower()
            )
            card.setVisible(visible)

    def _tick(self) -> None:
        for card in self.cards.values():
            card.refresh_code()

    # -- drag & drop -----------------------------------------------------

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        mime: QMimeData = event.mimeData()
        paths = [Path(url.toLocalFile()) for url in mime.urls() if url.isLocalFile()]
        image_paths = [p for p in paths if qr.is_supported_image(p)]
        if not image_paths:
            QMessageBox.warning(
                self, "Unsupported file", "Please drop PNG, JPG, JPEG, BMP, or WebP images."
            )
            return
        for path in image_paths:
            self._import_qr_file(path)
        event.acceptProposedAction()

    # -- import actions ----------------------------------------------------

    def _import_qr_dialog(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Import QR code image(s)",
            "",
            "QR Images (*.png *.jpg *.jpeg *.bmp *.webp)",
        )
        for path_str in paths:
            self._import_qr_file(Path(path_str))

    def _import_qr_file(self, path: Path) -> None:
        try:
            accounts = qr.accounts_from_image(path)
        except (qr.QrDecodeError, qr.InvalidOtpUriError) as exc:
            QMessageBox.warning(self, "Import failed", str(exc))
            return

        for account in accounts:
            self._add_account_with_duplicate_check(account)
        self._rebuild_cards()

    def _add_account_with_duplicate_check(self, account: Account) -> None:
        try:
            self.storage.add_account(account, replace=False)
        except DuplicateAccountError as exc:
            choice = QMessageBox.question(
                self,
                "Account already exists",
                f"An account for '{exc.existing.issuer} ({exc.existing.account})' "
                "already exists.\n\nReplace it with the new one?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if choice == QMessageBox.StandardButton.Yes:
                account.uid = exc.existing.uid
                self.storage.update_account(account)

    # -- context menu actions ------------------------------------------

    def _rename_account(self, uid: str) -> None:
        account = self.storage.get(uid)
        if account is None:
            return
        new_issuer, ok = QInputDialog.getText(self, "Rename", "Issuer name:", text=account.issuer)
        if not ok or not new_issuer.strip():
            return
        new_account_name, ok = QInputDialog.getText(
            self, "Rename", "Account name:", text=account.account
        )
        if not ok or not new_account_name.strip():
            return
        account.issuer = new_issuer.strip()
        account.account = new_account_name.strip()
        self.storage.update_account(account)
        self._rebuild_cards()

    def _delete_account(self, uid: str) -> None:
        account = self.storage.get(uid)
        if account is None:
            return
        choice = QMessageBox.question(
            self,
            "Delete account",
            f"Delete '{account.issuer} ({account.account})'? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if choice == QMessageBox.StandardButton.Yes:
            self.storage.delete_account(uid)
            self._rebuild_cards()

    def _show_secret(self, uid: str) -> None:
        account = self.storage.get(uid)
        if account is None:
            return
        QMessageBox.information(
            self,
            f"Secret for {account.issuer}",
            f"Account: {account.account}\nSecret: {account.secret}\n\n"
            "Keep this secret safe — anyone with it can generate your codes.",
        )

    def _export_account(self, uid: str) -> None:
        account = self.storage.get(uid)
        if account is None:
            return
        path_str, _ = QFileDialog.getSaveFileName(
            self, "Export account", f"{account.issuer}.pyauth", "PyAuthenticator Backup (*.pyauth)"
        )
        if not path_str:
            return
        password, ok = QInputDialog.getText(
            self, "Backup password", "Set a password to encrypt this export:", QLineEdit.EchoMode.Password
        )
        if not ok or not password:
            return
        self.storage.export_single_account(account, Path(path_str), password)
        QMessageBox.information(self, "Exported", "Account exported successfully.")

    def _export_backup_dialog(self) -> None:
        if not self.storage.accounts:
            QMessageBox.information(self, "Nothing to export", "You have no accounts yet.")
            return
        path_str, _ = QFileDialog.getSaveFileName(
            self, "Export backup", "pyauthenticator-backup.pyauth", "PyAuthenticator Backup (*.pyauth)"
        )
        if not path_str:
            return
        password, ok = QInputDialog.getText(
            self, "Backup password", "Set a password to encrypt this backup:", QLineEdit.EchoMode.Password
        )
        if not ok or not password:
            return
        self.storage.export_backup(Path(path_str), password)
        QMessageBox.information(self, "Exported", "Backup exported successfully.")

    def _import_backup_dialog(self) -> None:
        path_str, _ = QFileDialog.getOpenFileName(
            self, "Import backup", "", "PyAuthenticator Backup (*.pyauth);;All files (*)"
        )
        if not path_str:
            return
        password, ok = QInputDialog.getText(
            self, "Backup password", "Enter the backup password:", QLineEdit.EchoMode.Password
        )
        if not ok or not password:
            return
        try:
            count = self.storage.import_backup(Path(path_str), password)
        except Exception as exc:
            QMessageBox.warning(self, "Import failed", str(exc))
            return
        self._rebuild_cards()
        QMessageBox.information(self, "Imported", f"Imported {count} account(s).")

    # -- tray / close behavior ----------------------------------------

    def set_tray(self, tray: TrayIcon) -> None:
        self.tray = tray

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 (Qt override)
        if self.tray is not None and self.tray.isSystemTrayAvailable():
            event.ignore()
            self.hide()
            self.tray.notify_hidden_to_tray()
        else:
            event.accept()
