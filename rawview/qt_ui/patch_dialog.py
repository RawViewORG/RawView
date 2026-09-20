"""Patch an address: raw bytes, or one assembled instruction.

The hex pane stays read-only. Editing a rendered dump in place means mapping every keystroke back
through the address/hex/ascii columns, and a mis-mapped keystroke writes the wrong byte to the
wrong address with nothing to show for it. A dialog that says what is there now, what it will
write, and how the two lengths compare is both safer and easier to read.
"""

from __future__ import annotations

import re
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from rawview.qt_ui.controller import RawViewQtController

_HEX_OK = re.compile(r"^[0-9a-fA-F\s,]*$")


def _hex_byte_count(text: str) -> int | None:
    """Number of bytes ``text`` describes, or None when it is not a whole number of bytes."""
    cleaned = re.sub(r"[\s,]+", "", text.replace("0x", "").replace("0X", ""))
    if not cleaned or len(cleaned) % 2:
        return None
    return len(cleaned) // 2


class PatchDialog(QDialog):
    """Write bytes or an assembled instruction at one address."""

    def __init__(
        self,
        parent: QWidget | None,
        controller: RawViewQtController,
        address: str,
        mono_font: QFont | None = None,
    ) -> None:
        super().__init__(parent)
        self._ctrl = controller
        self.setWindowTitle("Patch")
        self.setMinimumWidth(560)
        self._result: dict[str, Any] = {}

        self._address = QLineEdit(address.strip())
        self._address.setToolTip("Address to write at. Accepts 0x-prefixed, block-qualified, or a symbol name.")
        self._address.textChanged.connect(self._refresh_current)

        self._current = QLabel("")
        self._current.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        if mono_font is not None:
            self._current.setFont(mono_font)

        self._bytes = QLineEdit()
        self._bytes.setPlaceholderText("90 90 90 90")
        if mono_font is not None:
            self._bytes.setFont(mono_font)
        self._bytes.textChanged.connect(self._refresh_status)

        self._instruction = QLineEdit()
        self._instruction.setPlaceholderText("MOV EAX,0x1")
        if mono_font is not None:
            self._instruction.setFont(mono_font)
        self._instruction.textChanged.connect(self._refresh_status)

        bytes_page = QWidget()
        bl = QFormLayout(bytes_page)
        bl.addRow("Bytes (hex)", self._bytes)

        asm_page = QWidget()
        al = QFormLayout(asm_page)
        al.addRow("Instruction", self._instruction)

        self._tabs = QTabWidget()
        self._tabs.addTab(bytes_page, "Bytes")
        self._tabs.addTab(asm_page, "Assemble")
        self._tabs.currentChanged.connect(lambda _i: self._refresh_status())

        self._status = QLabel("")
        self._status.setWordWrap(True)
        self._status.setTextFormat(Qt.TextFormat.RichText)

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Apply | QDialogButtonBox.StandardButton.Cancel
        )
        self._apply_btn = self._buttons.button(QDialogButtonBox.StandardButton.Apply)
        self._apply_btn.setDefault(True)
        self._apply_btn.clicked.connect(self._apply)
        self._buttons.rejected.connect(self.reject)

        form = QFormLayout()
        form.addRow("Address", self._address)
        form.addRow("Currently", self._current)

        root = QVBoxLayout(self)
        root.addLayout(form)
        root.addWidget(self._tabs)
        root.addWidget(self._status)
        root.addWidget(self._buttons)

        self._refresh_current()

    @property
    def result_payload(self) -> dict[str, Any]:
        """What the bridge returned for the applied patch, or {} if nothing was applied."""
        return self._result

    # -- live feedback ----------------------------------------------------------------

    def _refresh_current(self) -> None:
        addr = self._address.text().strip()
        if not addr:
            self._current.setText("")
            self._refresh_status()
            return
        # hex_dump_at answers "" for a bad address or a dead bridge rather than raising.
        dump = self._ctrl.hex_dump_at(addr, 16)
        self._current.setText(dump or "(nothing readable at this address)")
        self._refresh_status()

    def _refresh_status(self) -> None:
        addr = self._address.text().strip()
        if not addr:
            self._set_status("Enter an address.", ok=False)
            return
        if self._tabs.currentIndex() == 0:
            text = self._bytes.text().strip()
            if not text:
                self._set_status("Enter the bytes to write.", ok=False)
                return
            if not _HEX_OK.match(text.replace("0x", "").replace("0X", "")):
                self._set_status("Bytes must be hex digits, optionally spaced or comma separated.", ok=False)
                return
            count = _hex_byte_count(text)
            if count is None:
                self._set_status("Hex needs an even number of digits.", ok=False)
                return
            self._set_status(f"Writes {count} byte{'s' if count != 1 else ''}.", ok=True)
            return

        instruction = self._instruction.text().strip()
        if not instruction:
            self._set_status("Enter an instruction to assemble.", ok=False)
            return
        preview = self._ctrl.assemble_preview(addr, instruction)
        if preview.get("error"):
            hint = preview.get("hint") or ""
            self._set_status(f"{preview['error']}{': ' + hint if hint else ''}", ok=False)
            return
        encoded = str(preview.get("bytes", ""))
        length = int(preview.get("length", 0) or 0)
        replaced = int(preview.get("replaced_length", 0) or 0)
        spaced = " ".join(encoded[i : i + 2] for i in range(0, len(encoded), 2))
        msg = f"Assembles to <b>{spaced}</b> ({length} bytes)"
        if replaced:
            msg += f", replacing an instruction of {replaced}"
        if preview.get("overruns"):
            msg += (
                f".<br><b>This is {length - replaced} byte(s) longer than the instruction it "
                "replaces and will overwrite the one after it.</b>"
            )
        else:
            msg += "."
        self._set_status(msg, ok=True, warn=bool(preview.get("overruns")))

    def _set_status(self, text: str, *, ok: bool, warn: bool = False) -> None:
        colour = "#e0af68" if warn else ("#9ece6a" if ok else "#f7768e")
        self._status.setText(f'<span style="color:{colour}">{text}</span>')
        self._apply_btn.setEnabled(ok)

    # -- apply ------------------------------------------------------------------------

    def _apply(self) -> None:
        addr = self._address.text().strip()
        if self._tabs.currentIndex() == 0:
            res = self._ctrl.apply_patch_bytes(addr, self._bytes.text())
        else:
            res = self._ctrl.apply_assembled_instruction(addr, self._instruction.text())
        if not res.get("ok"):
            hint = res.get("hint") or ""
            self._set_status(
                f"{res.get('error', 'failed')}{': ' + hint if hint else ''}", ok=False
            )
            self._apply_btn.setEnabled(True)
            return
        self._result = res
        self.accept()


def open_patch_dialog(
    parent: QWidget | None,
    controller: RawViewQtController,
    address: str,
    mono_font: QFont | None = None,
) -> dict[str, Any]:
    """Show the dialog. Returns the applied patch's result, or {} if the user cancelled."""
    dlg = PatchDialog(parent, controller, address, mono_font)
    if dlg.exec() == QDialog.DialogCode.Accepted:
        return dlg.result_payload
    return {}
