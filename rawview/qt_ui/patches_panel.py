"""Patches pane: every byte that differs from the imported file, with revert and export.

The list is not a record RawView keeps of what it did. It is read back out of the program each
time, so it also shows edits made in a previous session or from the agent, and it cannot claim a
patch that is no longer there.
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

_COLUMNS = ("Address", "File offset", "Length", "Original", "Patched")


def _spaced(hex_text: str, limit: int = 48) -> str:
    """``9090`` -> ``90 90``, truncated so a long run does not stretch the column off screen."""
    pairs = [hex_text[i : i + 2] for i in range(0, len(hex_text), 2)]
    if len(pairs) * 3 > limit:
        shown = pairs[: limit // 3]
        return " ".join(shown) + f" ... (+{len(pairs) - len(shown)})"
    return " ".join(pairs)


class PatchesPanel(QWidget):
    """Table of changed byte runs, with revert and export actions."""

    navigate_requested = Signal(str)
    revert_requested = Signal(str, int)
    export_requested = Signal()
    refresh_requested = Signal()

    def __init__(self, mono_font: QFont | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._summary = QLabel("No patches.")
        self._summary.setWordWrap(True)

        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(list(_COLUMNS))
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._table.itemSelectionChanged.connect(self._sync_buttons)
        self._table.cellDoubleClicked.connect(self._on_double_click)
        if mono_font is not None:
            self._table.setFont(mono_font)

        self._btn_refresh = QPushButton("Refresh")
        self._btn_refresh.setAutoDefault(False)
        self._btn_refresh.setToolTip("Re-read which bytes differ from the imported file.")
        self._btn_refresh.clicked.connect(self.refresh_requested)

        self._btn_revert = QPushButton("Revert selected")
        self._btn_revert.setAutoDefault(False)
        self._btn_revert.setToolTip("Put the original file bytes back at this address.")
        self._btn_revert.clicked.connect(self._on_revert)

        self._btn_export = QPushButton("Export patched binary...")
        self._btn_export.setAutoDefault(False)
        self._btn_export.setToolTip(
            "Write the imported file back out with every patch applied. Headers and unmapped "
            "regions are preserved, so the result still runs."
        )
        self._btn_export.clicked.connect(self.export_requested)

        row = QHBoxLayout()
        row.addWidget(self._btn_refresh)
        row.addWidget(self._btn_revert)
        row.addStretch(1)
        row.addWidget(self._btn_export)

        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.addWidget(self._summary)
        root.addWidget(self._table, 1)
        root.addLayout(row)
        self._sync_buttons()

    def load(self, payload: dict[str, Any]) -> None:
        runs = payload.get("runs") or []
        self._table.setRowCount(0)
        for run in runs:
            r = self._table.rowCount()
            self._table.insertRow(r)
            values = (
                str(run.get("address", "")),
                str(run.get("file_offset", "")),
                str(run.get("length", "")),
                _spaced(str(run.get("original", ""))),
                _spaced(str(run.get("patched", ""))),
            )
            for c, value in enumerate(values):
                item = QTableWidgetItem(value)
                if c == 0:
                    item.setData(Qt.ItemDataRole.UserRole, run)
                self._table.setItem(r, c, item)
        self._table.resizeColumnsToContents()

        if payload.get("error"):
            self._summary.setText(f"Could not read patches: {payload['error']}")
        elif not runs:
            self._summary.setText("No patches. Bytes match the file this program was imported from.")
        else:
            count = int(payload.get("count", len(runs)) or len(runs))
            total = sum(int(r.get("length", 0) or 0) for r in runs)
            text = f"{count} changed run{'s' if count != 1 else ''}, {total} byte{'s' if total != 1 else ''}."
            if payload.get("truncated"):
                text += " Listing stopped at the cap; there are more."
            self._summary.setText(text)
        self._sync_buttons()

    def _selected_run(self) -> dict[str, Any] | None:
        rows = self._table.selectionModel().selectedRows() if self._table.selectionModel() else []
        if not rows:
            return None
        item = self._table.item(rows[0].row(), 0)
        if item is None:
            return None
        data = item.data(Qt.ItemDataRole.UserRole)
        return data if isinstance(data, dict) else None

    def _sync_buttons(self) -> None:
        self._btn_revert.setEnabled(self._selected_run() is not None)
        self._btn_export.setEnabled(self._table.rowCount() >= 0)

    def _on_revert(self) -> None:
        run = self._selected_run()
        if not run:
            return
        address = str(run.get("address", ""))
        if not address:
            return
        self.revert_requested.emit(address, int(run.get("length", 0) or 0))

    def _on_double_click(self, row: int, _column: int) -> None:
        item = self._table.item(row, 0)
        if item and item.text():
            self.navigate_requested.emit(item.text())
