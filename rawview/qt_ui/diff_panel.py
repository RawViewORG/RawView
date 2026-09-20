"""Diff pane: compare the loaded program against a second binary, function by function.

The comparison is by function, not by bytes. Two builds of the same source differ in almost every
byte and in almost no functions, and the question worth answering about a second sample is which
functions are new, gone, or changed.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

_COLUMNS = ("Change", "Function", "Address", "Instructions", "Delta")

# Result key -> (row label, whether the address is in the loaded program and so navigable).
_SECTIONS = (
    ("changed", "changed", True),
    ("only_in_a", "only here", True),
    ("only_in_b", "only there", False),
)


class DiffPanel(QWidget):
    """Pick a second binary, compare, and list what differs."""

    navigate_requested = Signal(str)
    compare_requested = Signal()
    close_comparison_requested = Signal()

    def __init__(self, mono_font: QFont | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._summary = QLabel("Compare the loaded program against another binary.")
        self._summary.setWordWrap(True)

        self._btn_compare = QPushButton("Compare with binary...")
        self._btn_compare.setAutoDefault(False)
        self._btn_compare.setToolTip(
            "Pick a second binary. It is imported and analyzed, then compared with the loaded one."
        )
        self._btn_compare.clicked.connect(self.compare_requested)

        self._btn_close = QPushButton("Close comparison")
        self._btn_close.setAutoDefault(False)
        self._btn_close.setEnabled(False)
        self._btn_close.clicked.connect(self.close_comparison_requested)

        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(list(_COLUMNS))
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.setSortingEnabled(True)
        self._table.cellDoubleClicked.connect(self._on_double_click)
        if mono_font is not None:
            self._table.setFont(mono_font)

        row = QHBoxLayout()
        row.addWidget(self._btn_compare)
        row.addWidget(self._btn_close)
        row.addStretch(1)

        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.addLayout(row)
        root.addWidget(self._summary)
        root.addWidget(self._table, 1)

    def set_busy(self, message: str) -> None:
        self._summary.setText(message)
        self._btn_compare.setEnabled(False)

    def clear(self) -> None:
        self._table.setRowCount(0)
        self._summary.setText("Compare the loaded program against another binary.")
        self._btn_compare.setEnabled(True)
        self._btn_close.setEnabled(False)

    def load(self, payload: dict[str, Any]) -> None:
        self._btn_compare.setEnabled(True)
        if payload.get("error"):
            self._table.setRowCount(0)
            hint = payload.get("hint") or ""
            self._summary.setText(f"{payload['error']}{': ' + hint if hint else ''}")
            return

        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        for key, label, navigable in _SECTIONS:
            for hit in payload.get(key) or []:
                r = self._table.rowCount()
                self._table.insertRow(r)
                delta = hit.get("instruction_delta")
                values = (
                    label,
                    str(hit.get("name", "")),
                    str(hit.get("address", "")),
                    str(hit.get("instructions", "")),
                    "" if delta is None else f"{int(delta):+d}",
                )
                for c, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    if c == 2 and not navigable:
                        # The address is in the other binary, which this window is not showing.
                        item.setToolTip("Address in the compared binary, not the loaded one.")
                    if c == 0:
                        item.setData(Qt.ItemDataRole.UserRole, navigable)
                    self._table.setItem(r, c, item)
        self._table.setSortingEnabled(True)
        self._table.resizeColumnsToContents()
        self._btn_close.setEnabled(True)

        a = payload.get("a") or {}
        b = payload.get("b") or {}
        changed = len(payload.get("changed") or [])
        only_a = len(payload.get("only_in_a") or [])
        only_b = len(payload.get("only_in_b") or [])
        text = (
            f"{a.get('name', 'A')} ({a.get('functions', 0)} functions) vs "
            f"{b.get('name', 'B')} ({b.get('functions', 0)} functions): "
            f"{payload.get('identical', 0)} identical, {changed} changed, "
            f"{only_a} only here, {only_b} only there."
        )
        if payload.get("truncated"):
            text += " Listing capped; there are more."
        self._summary.setText(text)

    def _on_double_click(self, row: int, _column: int) -> None:
        kind_item = self._table.item(row, 0)
        addr_item = self._table.item(row, 2)
        if kind_item is None or addr_item is None:
            return
        if not kind_item.data(Qt.ItemDataRole.UserRole):
            return
        if addr_item.text():
            self.navigate_requested.emit(addr_item.text())
