"""Search everywhere: one box over functions, symbols, strings, imports, exports and data.

Ghidra has this and RawView did not, so finding a name meant guessing which of six tabs it lived
in and scrolling. The query runs in the JVM across all of them at once rather than pulling each
listing over the bridge and filtering here.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

_COLUMNS = ("Kind", "Address", "Name", "Detail")

# Checkbox label -> the kind token the bridge understands.
_KINDS = (
    ("Functions", "functions"),
    ("Symbols", "symbols"),
    ("Strings", "strings"),
    ("Imports", "imports"),
    ("Exports", "exports"),
    ("Data", "data"),
)


class SearchPanel(QWidget):
    """A query box, kind filters, and a results table that navigates on double-click."""

    navigate_requested = Signal(str)
    search_requested = Signal(str, str)  # query, comma-separated kinds ("" means all)

    def __init__(self, mono_font: QFont | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._pending_query = ""

        self._query = QLineEdit()
        self._query.setPlaceholderText("Search functions, symbols, strings, imports, exports, data...")
        self._query.setClearButtonEnabled(True)
        self._query.returnPressed.connect(self._run_search)
        self._query.textChanged.connect(self._on_text_changed)

        # Typing is not a search request until it pauses; otherwise every keystroke walks the
        # whole program in the JVM.
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(350)
        self._debounce.timeout.connect(self._run_search)

        self._boxes: list[tuple[QCheckBox, str]] = []
        kinds_row = QHBoxLayout()
        kinds_row.addWidget(QLabel("In:"))
        for label, token in _KINDS:
            box = QCheckBox(label)
            box.setChecked(True)
            box.toggled.connect(self._on_kinds_changed)
            kinds_row.addWidget(box)
            self._boxes.append((box, token))
        kinds_row.addStretch(1)

        self._summary = QLabel("Type to search the loaded program.")
        self._summary.setWordWrap(True)

        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(list(_COLUMNS))
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.setSortingEnabled(True)
        self._table.cellDoubleClicked.connect(self._on_double_click)
        if mono_font is not None:
            self._table.setFont(mono_font)

        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.addWidget(self._query)
        root.addLayout(kinds_row)
        root.addWidget(self._summary)
        root.addWidget(self._table, 1)

    def focus_query(self) -> None:
        """Put the cursor in the box, for the shortcut that opens this pane."""
        self._query.setFocus()
        self._query.selectAll()

    def _selected_kinds(self) -> str:
        chosen = [token for box, token in self._boxes if box.isChecked()]
        # All of them selected means "everything", which the bridge expresses as an empty filter.
        return "" if len(chosen) == len(self._boxes) else ",".join(chosen)

    def _on_text_changed(self, _text: str) -> None:
        self._debounce.start()

    def _on_kinds_changed(self, _checked: bool) -> None:
        if self._query.text().strip():
            self._debounce.start()

    def _run_search(self) -> None:
        self._debounce.stop()
        query = self._query.text().strip()
        if not query:
            self._table.setRowCount(0)
            self._summary.setText("Type to search the loaded program.")
            return
        if not [box for box, _ in self._boxes if box.isChecked()]:
            self._table.setRowCount(0)
            self._summary.setText("Select at least one kind to search in.")
            return
        self._pending_query = query
        self._summary.setText(f"Searching for {query}...")
        self.search_requested.emit(query, self._selected_kinds())

    def load(self, payload: dict[str, Any]) -> None:
        """Show one result set. Stale answers for an earlier query are dropped."""
        query = str(payload.get("query", ""))
        if self._pending_query and query and query != self._pending_query:
            return
        results = payload.get("results") or []
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        for hit in results:
            r = self._table.rowCount()
            self._table.insertRow(r)
            values = (
                str(hit.get("kind", "")),
                str(hit.get("address", "")),
                str(hit.get("name", "")),
                str(hit.get("detail", "")),
            )
            for c, value in enumerate(values):
                item = QTableWidgetItem(value)
                if c == 1:
                    item.setData(Qt.ItemDataRole.UserRole, hit)
                self._table.setItem(r, c, item)
        self._table.setSortingEnabled(True)
        self._table.resizeColumnsToContents()

        if payload.get("error"):
            self._summary.setText(
                "Load a binary first." if payload["error"] == "no_program" else str(payload["error"])
            )
            return
        count = int(payload.get("count", len(results)) or 0)
        truncated = payload.get("truncated") or {}
        text = f"{count} result{'s' if count != 1 else ''} for {query}."
        if isinstance(truncated, dict) and truncated:
            text += " Capped in: " + ", ".join(sorted(truncated)) + "."
        self._summary.setText(text)

    def _on_double_click(self, row: int, _column: int) -> None:
        item = self._table.item(row, 1)
        if item and item.text():
            self.navigate_requested.emit(item.text())
