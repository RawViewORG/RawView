"""Hex memory view: paging, size/columns, syntax highlight, copy helpers."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from rawview.qt_ui.controller import RawViewQtController
from rawview.qt_ui.themes import pseudocode_palette


class _HexHighlighter(QSyntaxHighlighter):
    """Highlight tab-separated dump rows; lines starting with # are metadata."""

    def __init__(self, doc, palette: dict[str, str]) -> None:
        super().__init__(doc)
        self._rebuild_formats(palette)

    def _rebuild_formats(self, palette: dict[str, str]) -> None:
        def c(key: str, fallback: str) -> QColor:
            return QColor(palette.get(key, fallback))

        self._meta = QTextCharFormat()
        self._meta.setForeground(c("comment", "#565f89"))
        self._addr = QTextCharFormat()
        self._addr.setForeground(c("keyword", "#7aa2f7"))
        self._hex = QTextCharFormat()
        self._hex.setForeground(c("number", "#bb9af7"))
        self._ascii = QTextCharFormat()
        self._ascii.setForeground(c("string", "#9ece6a"))

    def set_palette(self, palette: dict[str, str]) -> None:
        self._rebuild_formats(palette)
        self.rehighlight()

    def highlightBlock(self, text: str) -> None:
        if text.startswith("#"):
            self.setFormat(0, len(text), self._meta)
            return
        if "\t" not in text:
            return
        parts = text.split("\t", 2)
        if len(parts) < 3:
            return
        addr, hx, asc = parts[0], parts[1], parts[2]
        i = 0
        self.setFormat(i, len(addr), self._addr)
        i += len(addr) + 1
        self.setFormat(i, len(hx), self._hex)
        i += len(hx) + 1
        self.setFormat(i, len(asc), self._ascii)


class HexViewPanel(QWidget):
    """Toolbar + read-only hex dump; syncs with navigation and supports local refresh / paging."""

    def __init__(self, controller: RawViewQtController, mono_font: QFont, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._ctrl = controller
        self._highlighter: _HexHighlighter | None = None
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(220)
        self._debounce.timeout.connect(self._apply_options_and_refresh)

        row = QHBoxLayout()
        row.addWidget(QLabel("Address"))
        self._addr = QLineEdit()
        self._addr.setPlaceholderText("Same as listing / Annotations Addr")
        self._addr.setClearButtonEnabled(True)
        self._addr.returnPressed.connect(self._go_address)
        row.addWidget(self._addr, stretch=2)

        self._btn_go = QPushButton("Go")
        self._btn_go.setAutoDefault(False)
        self._btn_go.setToolTip("Jump listing, decompiler, and hex to this address.")
        self._btn_go.clicked.connect(self._go_address)
        row.addWidget(self._btn_go)

        self._btn_prev = QPushButton("◀ Page")
        self._btn_prev.setAutoDefault(False)
        self._btn_prev.setToolTip("Move back one window (Size bytes) in memory.")
        self._btn_prev.clicked.connect(lambda: self._page(-1))
        row.addWidget(self._btn_prev)

        self._btn_next = QPushButton("Page ▶")
        self._btn_next.setAutoDefault(False)
        self._btn_next.setToolTip("Move forward one window (Size bytes) in memory.")
        self._btn_next.clicked.connect(lambda: self._page(1))
        row.addWidget(self._btn_next)

        self._btn_refresh = QPushButton("Refresh")
        self._btn_refresh.setAutoDefault(False)
        self._btn_refresh.clicked.connect(self._ctrl.refresh_hex_view)
        row.addWidget(self._btn_refresh)

        row.addWidget(QLabel("Size"))
        self._size = QComboBox()
        for v in (256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
            self._size.addItem(f"{v} B", v)
        self._size.setCurrentIndex(4)  # 4096
        self._size.currentIndexChanged.connect(lambda _i: self._debounce.start())
        row.addWidget(self._size)

        row.addWidget(QLabel("Cols"))
        self._cols = QComboBox()
        for v in (8, 16, 32, 64):
            self._cols.addItem(str(v), v)
        self._cols.setCurrentIndex(1)  # 16
        self._cols.currentIndexChanged.connect(lambda _i: self._debounce.start())
        row.addWidget(self._cols)

        self._follow = QCheckBox("Follow listing")
        self._follow.setChecked(True)
        self._follow.setToolTip("When on, hex address tracks the current listing selection.")
        self._follow.toggled.connect(self._on_follow_toggled)
        row.addWidget(self._follow)

        self._btn_copy = QPushButton("Copy")
        self._btn_copy.setAutoDefault(False)
        self._btn_copy.setToolTip("Copy selection, or entire dump if nothing selected.")
        self._btn_copy.clicked.connect(self._copy_selection_or_all)
        row.addWidget(self._btn_copy)

        self._btn_copy_hex = QPushButton("Copy hex")
        self._btn_copy_hex.setAutoDefault(False)
        self._btn_copy_hex.setToolTip("Copy only hex bytes (no addresses) from selection or full view.")
        self._btn_copy_hex.clicked.connect(self._copy_hex_only)
        row.addWidget(self._btn_copy_hex)

        self._btn_patch = QPushButton("Patch...")
        self._btn_patch.setAutoDefault(False)
        self._btn_patch.setToolTip(
            "Write bytes, or assemble an instruction, at the address of the line the cursor is on."
        )
        self._btn_patch.clicked.connect(self._open_patch)
        row.addWidget(self._btn_patch)

        self._edit = QPlainTextEdit()
        self._edit.setReadOnly(True)
        self._edit.setFont(mono_font)
        self._edit.setPlaceholderText("Load a binary and navigate to an address.")
        self._edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._edit.setCursorWidth(2)

        vl = QVBoxLayout(self)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.addLayout(row)
        vl.addWidget(self._edit, stretch=1)

        self.apply_theme(controller.settings.rawview_theme)
        self._ctrl.hex_dump_text.connect(self._on_dump_text)
        self._ctrl.current_address_changed.connect(self._on_listing_address)
        self._ctrl.set_hex_view_options(self._size_bytes(), self._cols_value())

    def address_at_cursor(self) -> str:
        """Address of the dump row the cursor sits on, falling back to the toolbar address."""
        cursor = self._edit.textCursor()
        line = cursor.block().text()
        if line and not line.startswith("#") and "\t" in line:
            head = line.split("\t", 1)[0].strip()
            if head:
                return head
        return self._addr.text().strip() or self._ctrl.current_address

    def _open_patch(self) -> None:
        from rawview.qt_ui.patch_dialog import open_patch_dialog

        open_patch_dialog(self, self._ctrl, self.address_at_cursor(), self._edit.font())

    def _on_follow_toggled(self, on: bool) -> None:
        if on:
            self._addr.setText(self._ctrl.current_address)
            self._debounce.start()

    def apply_theme(self, theme_id: str) -> None:
        pal = pseudocode_palette(theme_id)
        if self._highlighter is None:
            self._highlighter = _HexHighlighter(self._edit.document(), pal)
        else:
            self._highlighter.set_palette(pal)

    def _on_dump_text(self, text: str) -> None:
        self._edit.setPlainText(text)
        if self._highlighter is not None:
            self._highlighter.rehighlight()

    def _on_listing_address(self, addr: str) -> None:
        a = addr.strip()
        if not a:
            return
        if self._follow.isChecked():
            self._addr.setText(a)

    def _size_bytes(self) -> int:
        v = self._size.currentData()
        return int(v) if v is not None else 4096

    def _cols_value(self) -> int:
        v = self._cols.currentData()
        return int(v) if v is not None else 16

    def set_options_from_hints(self, size: int, cols: int) -> None:
        """Align Size/Cols combos with a restored RE session, then refresh."""
        for i in range(self._size.count()):
            if int(self._size.itemData(i)) == size:
                self._size.setCurrentIndex(i)
                break
        for i in range(self._cols.count()):
            if int(self._cols.itemData(i)) == cols:
                self._cols.setCurrentIndex(i)
                break
        self._debounce.start()

    def _apply_options_and_refresh(self) -> None:
        self._ctrl.set_hex_view_options(self._size_bytes(), self._cols_value())
        self._ctrl.refresh_hex_view()

    def _go_address(self) -> None:
        a = self._addr.text().strip()
        if a:
            self._ctrl.set_hex_view_options(self._size_bytes(), self._cols_value())
            self._ctrl.navigate_to_address(a)

    def _page(self, direction: int) -> None:
        base = self._addr.text().strip() or self._ctrl.current_address
        if not base:
            return
        self._ctrl.set_hex_view_options(self._size_bytes(), self._cols_value())
        naddr = self._ctrl.advance_program_address(base, direction * self._size_bytes())
        if not naddr.strip():
            return
        self._ctrl.navigate_to_address(naddr)

    def _copy_selection_or_all(self) -> None:
        c = self._edit.textCursor()
        if c.hasSelection():
            self._edit.copy()
        else:
            self._edit.selectAll()
            self._edit.copy()
            c2 = QTextCursor(self._edit.document())
            self._edit.setTextCursor(c2)

    def _copy_hex_only(self) -> None:
        text = self._edit.textCursor().selectedText() if self._edit.textCursor().hasSelection() else self._edit.toPlainText()
        if not text:
            return
        # Join hex pairs from tab rows (skip # lines)
        pairs: list[str] = []
        for line in text.replace("\u2029", "\n").split("\n"):
            ls = line.strip()
            if not ls or ls.startswith("#"):
                continue
            if "\t" not in line:
                continue
            parts = line.split("\t", 2)
            if len(parts) < 2:
                continue
            hx = parts[1].replace("  ", " ").strip()
            for tok in hx.split():
                t = tok.strip().upper()
                if len(t) == 2 and all(c in "0123456789ABCDEF" for c in t):
                    pairs.append(t)
        QApplication.clipboard().setText(" ".join(pairs))

    def refresh_if_visible(self) -> None:
        """Call when the Hex tab becomes active (e.g. after switching tabs)."""
        self._ctrl.set_hex_view_options(self._size_bytes(), self._cols_value())
        self._ctrl.refresh_hex_view()
