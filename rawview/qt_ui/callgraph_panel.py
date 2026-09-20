"""Call graph panel: who calls the current function, and what it calls.

Two lazily expanded trees rather than one node graph. A call graph is not a CFG: even a
modest binary reaches hundreds of functions two levels out from ``main``, and a drawn graph
of that is unreadable, while a tree the user opens one branch at a time is not. Each expand
asks the bridge for a single level around that node, so nothing is fetched until it is
actually looked at.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

# Roles on a tree item: the function address it stands for, and whether its children are loaded.
_ROLE_ADDR = Qt.ItemDataRole.UserRole
_ROLE_LOADED = Qt.ItemDataRole.UserRole + 1
_ROLE_RECURSIVE = Qt.ItemDataRole.UserRole + 2

CALLERS = "callers"
CALLEES = "callees"


def _fmt_size(node: dict[str, Any]) -> str:
    try:
        n = int(node.get("size", 0) or 0)
    except (TypeError, ValueError):
        return ""
    return f"{n:,}" if n else ""


def _label(node: dict[str, Any]) -> str:
    name = str(node.get("name", "") or "?")
    tags = []
    if node.get("external"):
        tags.append("external")
    if node.get("thunk"):
        tags.append("thunk")
    return f"{name} [{', '.join(tags)}]" if tags else name


class CallGraphPanel(QWidget):
    """Callers/callees trees for the current function.

    The panel owns no Ghidra access of its own: it emits :attr:`expand_requested` and waits for
    :meth:`apply_level`, so every bridge call still happens on the controller's worker thread.
    """

    navigate_requested = Signal(str)
    # address, direction ("callers"/"callees"), token to echo back in apply_level()
    expand_requested = Signal(str, str, str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._root_addr = ""
        # token -> the item whose children that response fills
        self._pending: dict[str, QTreeWidgetItem] = {}
        # Tokens of the two first-level requests, so their answers can name the root function.
        self._root_tokens: set[str] = set()
        self._token_seq = 0

        self._heading = QLabel("Select a function to see its call graph.")
        self._heading.setWordWrap(True)

        self._callers = self._make_tree("Callers")
        self._callees = self._make_tree("Calls")

        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._wrap(self._callers, "Called by"))
        split.addWidget(self._wrap(self._callees, "Calls out to"))
        split.setSizes([1, 1])

        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        head = QHBoxLayout()
        head.addWidget(self._heading, 1)
        root.addLayout(head)
        root.addWidget(split, 1)

    def _make_tree(self, first_column: str) -> QTreeWidget:
        t = QTreeWidget()
        t.setColumnCount(3)
        t.setHeaderLabels([first_column, "Address", "Size"])
        t.setUniformRowHeights(True)
        t.setAlternatingRowColors(True)
        t.setExpandsOnDoubleClick(False)
        t.itemExpanded.connect(self._on_item_expanded)
        t.itemDoubleClicked.connect(self._on_item_activated)
        t.setColumnWidth(0, 260)
        t.setColumnWidth(1, 110)
        return t

    @staticmethod
    def _wrap(tree: QTreeWidget, title: str) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(3)
        lbl = QLabel(title)
        lbl.setProperty("class", "section-title")
        lay.addWidget(lbl)
        lay.addWidget(tree, 1)
        return w

    # -- population -------------------------------------------------------------------

    def set_root(self, address: str) -> None:
        """Point both trees at ``address`` and request the first level of each."""
        addr = (address or "").strip()
        self._pending.clear()
        self._root_tokens.clear()
        self._callers.clear()
        self._callees.clear()
        self._root_addr = addr
        if not addr:
            self._heading.setText("Select a function to see its call graph.")
            return
        self._heading.setText(f"Call graph around {addr}")
        for tree, direction in ((self._callers, CALLERS), (self._callees, CALLEES)):
            placeholder = QTreeWidgetItem(tree, ["Loading...", "", ""])
            placeholder.setDisabled(True)
            # The invisible root stands for the function itself, so a function that calls
            # itself is marked as recursion at the first level like any other cycle.
            tree.invisibleRootItem().setData(0, _ROLE_ADDR, addr)
            self._root_tokens.add(self._request(tree.invisibleRootItem(), addr, direction))

    def clear(self) -> None:
        self.set_root("")

    def apply_level(self, payload: dict[str, Any]) -> None:
        """Fill in the children for one expansion. ``payload`` is a call-graph dict plus ``token``."""
        token = str(payload.get("token", ""))
        item = self._pending.pop(token, None)
        if item is None:
            return
        direction = str(payload.get("direction", CALLEES))
        parent = item
        self._clear_children(parent)
        parent.setData(0, _ROLE_LOADED, True)
        # The bridge resolves the address to its containing function, so the heading can name it
        # even when the user navigated to an address in the middle of a body.
        if token in self._root_tokens and payload.get("root_name"):
            self._heading.setText(
                f"Call graph around {payload['root_name']} @ {payload.get('root', self._root_addr)}"
            )

        if payload.get("error"):
            note = QTreeWidgetItem(parent, [f"({payload['error']})", "", ""])
            note.setDisabled(True)
            return

        anchor = str(payload.get("root", "")) or str(parent.data(0, _ROLE_ADDR) or self._root_addr)
        by_addr = {str(n.get("address", "")): n for n in payload.get("nodes", []) or []}
        children: list[str] = []
        for edge in payload.get("edges", []) or []:
            frm, to = str(edge.get("from", "")), str(edge.get("to", ""))
            if direction == CALLERS and to == anchor and frm != anchor:
                children.append(frm)
            elif direction == CALLEES and frm == anchor and to != anchor:
                children.append(to)
        # Ghidra can report the same pair through several call sites.
        seen: set[str] = set()
        children = [a for a in children if not (a in seen or seen.add(a))]

        if not children:
            note = QTreeWidgetItem(
                parent, ["(no callers)" if direction == CALLERS else "(calls nothing)", "", ""]
            )
            note.setDisabled(True)
            return

        ancestry = self._ancestry(parent)
        for addr in sorted(children, key=lambda a: str(by_addr.get(a, {}).get("name", a)).lower()):
            node = by_addr.get(addr, {"address": addr, "name": addr})
            recursive = addr in ancestry
            text = _label(node) + (" (recursion)" if recursive else "")
            child = QTreeWidgetItem(parent, [text, addr, _fmt_size(node)])
            child.setData(0, _ROLE_ADDR, addr)
            child.setData(0, _ROLE_LOADED, False)
            child.setData(0, _ROLE_RECURSIVE, recursive)
            child.setToolTip(0, f"{node.get('name', addr)} @ {addr}\nDouble-click to navigate")
            # A cycle would expand forever; an external function has nothing behind it.
            if not recursive and not node.get("external"):
                stub = QTreeWidgetItem(child, ["...", "", ""])
                stub.setDisabled(True)

        if payload.get("truncated"):
            note = QTreeWidgetItem(parent, ["(truncated: too many edges here)", "", ""])
            note.setDisabled(True)

    # -- interaction ------------------------------------------------------------------

    def _on_item_expanded(self, item: QTreeWidgetItem) -> None:
        if item.data(0, _ROLE_LOADED):
            return
        addr = str(item.data(0, _ROLE_ADDR) or "")
        if not addr or item.data(0, _ROLE_RECURSIVE):
            return
        tree = item.treeWidget()
        direction = CALLERS if tree is self._callers else CALLEES
        self._request(item, addr, direction)

    def _on_item_activated(self, item: QTreeWidgetItem, _column: int) -> None:
        addr = str(item.data(0, _ROLE_ADDR) or "")
        if addr:
            self.navigate_requested.emit(addr)

    def _request(self, item: QTreeWidgetItem, address: str, direction: str) -> str:
        self._token_seq += 1
        token = f"{direction}:{address}:{self._token_seq}"
        self._pending[token] = item
        self.expand_requested.emit(address, direction, token)
        return token

    @staticmethod
    def _clear_children(item: QTreeWidgetItem) -> None:
        while item.childCount():
            item.removeChild(item.child(0))

    def _ancestry(self, item: QTreeWidgetItem) -> set[str]:
        """
        Addresses on the path back to the root, so a call cycle can be marked and stopped.

        The root function is always in the set: a top-level item's ``parent()`` is ``None`` rather
        than the invisible root, so walking up alone never reaches it.
        """
        out: set[str] = {self._root_addr} if self._root_addr else set()
        cur: QTreeWidgetItem | None = item
        while cur is not None:
            addr = cur.data(0, _ROLE_ADDR)
            if addr:
                out.add(str(addr))
            cur = cur.parent()
        return out
