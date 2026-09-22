"""
The Agent dock's "working" indicator: a small animated bar that says what the agent is doing.

Qt's rich-text feed cannot animate, so the sense of a live agent has to come from real widgets.
This is a spinner (a braille cycle, the same trick modern CLIs use, so it needs no icon assets or
qtawesome animation support) next to a status line that the dock updates as events arrive -
"Thinking", "Running decompile_function", "Writing" - with a drifting ellipsis. It fades in when a
turn starts and fades out when it ends, so the panel feels responsive rather than frozen.
"""

from __future__ import annotations

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt, QTimer
from PySide6.QtWidgets import QFrame, QGraphicsOpacityEffect, QHBoxLayout, QLabel

# One full braille spin. Ten frames at ~80ms reads as smooth without being frantic.
_SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class AgentActivityBar(QFrame):
    """A spinner + status line shown while the agent is working."""

    def __init__(self, accent: str = "#7aa2f7", parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("agent_activity_bar")
        self._accent = accent
        self._frame = 0
        self._dots = 0
        self._base_status = "Thinking"

        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 6, 10, 6)
        lay.setSpacing(8)

        self._spinner = QLabel(_SPINNER_FRAMES[0])
        self._spinner.setObjectName("agent_activity_spinner")
        self._spinner.setFixedWidth(16)
        self._spinner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self._spinner)

        self._status = QLabel("Thinking")
        self._status.setObjectName("agent_activity_status")
        self._status.setSizePolicy(self._status.sizePolicy().horizontalPolicy(), self._status.sizePolicy().verticalPolicy())
        lay.addWidget(self._status, stretch=1)

        self._timer = QTimer(self)
        self._timer.setInterval(80)
        self._timer.timeout.connect(self._tick)

        # Opacity is animated on show/hide so the bar slides in rather than snapping.
        self._opacity = QGraphicsOpacityEffect(self)
        self._opacity.setOpacity(0.0)
        self.setGraphicsEffect(self._opacity)
        self._fade = QPropertyAnimation(self._opacity, b"opacity", self)
        self._fade.setDuration(180)
        self._fade.setEasingCurve(QEasingCurve.Type.InOutQuad)

        self.setVisible(False)
        self._apply_style()

    def set_accent(self, accent: str) -> None:
        self._accent = accent
        self._apply_style()

    def _apply_style(self) -> None:
        self.setStyleSheet(
            "QFrame#agent_activity_bar {"
            "  background: rgba(122,162,247,0.10);"
            f"  border: 1px solid {self._accent};"
            "  border-radius: 8px;"
            "}"
            f"QLabel#agent_activity_spinner {{ color: {self._accent}; font-size: 12pt; font-weight: bold; }}"
            "QLabel#agent_activity_status { color: palette(window-text); font-size: 9.5pt; }"
        )

    # -- control ----------------------------------------------------------------------

    def start(self, status: str = "Thinking") -> None:
        self._base_status = status
        self._dots = 0
        self._render_status()
        if not self._timer.isActive():
            self._timer.start()
        self.setVisible(True)
        self._fade.stop()
        self._fade.setStartValue(self._opacity.opacity())
        self._fade.setEndValue(1.0)
        self._fade.start()

    def set_status(self, status: str) -> None:
        """Change the label without restarting the animation (called on each event)."""
        if status and status != self._base_status:
            self._base_status = status
            self._dots = 0
            self._render_status()

    def stop(self) -> None:
        if not self.isVisible() and not self._timer.isActive():
            return
        self._timer.stop()
        try:
            self._fade.stop()
            self._fade.setStartValue(self._opacity.opacity())
            self._fade.setEndValue(0.0)
            self._fade.start()
            self._fade.finished.connect(self._hide_after_fade)
        except (RuntimeError, TypeError):
            self.setVisible(False)

    def _hide_after_fade(self) -> None:
        try:
            self._fade.finished.disconnect(self._hide_after_fade)
        except (RuntimeError, TypeError):
            pass
        if self._opacity.opacity() <= 0.01:
            self.setVisible(False)

    # -- animation --------------------------------------------------------------------

    def _tick(self) -> None:
        self._frame = (self._frame + 1) % len(_SPINNER_FRAMES)
        self._spinner.setText(_SPINNER_FRAMES[self._frame])
        # The ellipsis drifts a step every few spinner frames, slower than the spinner.
        if self._frame % 4 == 0:
            self._dots = (self._dots + 1) % 4
            self._render_status()

    def _render_status(self) -> None:
        self._status.setText(self._base_status + "." * self._dots)
