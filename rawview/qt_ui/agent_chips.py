"""
Clickable pill widgets for the Agent dock: the empty-state welcome and the quick-action row.

A blank chat box tells a new user nothing about what the agent can do. These give it a face and a
starting point - example prompts to click when the feed is empty, and a always-present row of
one-tap actions ("Explain this function", "Strings here", ...) that fill the prompt so common
requests are one click, not a sentence typed from scratch. Pills are real QPushButtons, so hover
and press states are free and consistent with the theme accent.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

# (label, prompt) for the empty-state suggestions. The prompt is what gets sent.
_WELCOME_PROMPTS = (
    ("Summarize this program", "Give me a high-level summary of what this program does."),
    ("Explain the current function", "Explain what the function at the current address does."),
    ("Find suspicious strings", "List the most interesting or suspicious strings and where they are used."),
    ("Where does execution start", "Walk me through the program from its entry point."),
)

# (label, prompt) for the always-on quick-action row. Kept short so they fit.
_QUICK_ACTIONS = (
    ("Explain this", "Explain the function at the current address."),
    ("Strings here", "What strings does the current function reference?"),
    ("Rename by behavior", "Suggest and apply a better name for the current function based on what it does."),
    ("Callers", "What calls the current function, and what does it call?"),
    ("Summarize", "Give a high-level summary of this program."),
)


def _pill(text: str, tooltip: str, on_click: Callable[[], None], *, object_name: str) -> QPushButton:
    b = QPushButton(text)
    b.setObjectName(object_name)
    b.setToolTip(tooltip)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    b.setAutoDefault(False)
    b.setFlat(True)
    b.clicked.connect(on_click)
    b.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
    return b


class AgentWelcome(QWidget):
    """Shown in place of the feed when the conversation is empty."""

    def __init__(self, run_prompt: Callable[[str], None], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._run = run_prompt
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 28, 20, 20)
        outer.setSpacing(10)
        outer.addStretch(1)

        title = QLabel("RawView agent")
        title.setObjectName("agent_welcome_title")
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        outer.addWidget(title)

        sub = QLabel("Ask about the binary you have open, or start with one of these:")
        sub.setObjectName("agent_welcome_sub")
        sub.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        sub.setWordWrap(True)
        outer.addWidget(sub)

        outer.addSpacing(6)
        for label, prompt in _WELCOME_PROMPTS:
            row = QHBoxLayout()
            row.addStretch(1)
            btn = _pill(label, prompt, lambda p=prompt: self._run(p), object_name="agent_welcome_pill")
            row.addWidget(btn)
            row.addStretch(1)
            outer.addLayout(row)
        outer.addStretch(2)


class AgentQuickActions(QFrame):
    """A single wrapping row of one-tap starters above the input."""

    def __init__(self, fill_prompt: Callable[[str], None], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("agent_quick_actions")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        for label, prompt in _QUICK_ACTIONS:
            lay.addWidget(
                _pill(label, prompt, lambda p=prompt: fill_prompt(p), object_name="agent_quick_pill")
            )
        lay.addStretch(1)
