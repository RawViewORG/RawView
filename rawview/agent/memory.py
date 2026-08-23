from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ConversationMemory:
    """Rolling Anthropic message list with optional pinned system context."""

    max_messages: int = 24
    _messages: deque[dict[str, Any]] = field(default_factory=deque)

    def add_user(self, content: str | list) -> None:
        self._trim()
        if isinstance(content, str):
            if self._messages:
                last = self._messages[-1]
                if last.get("role") == "user":
                    prev = last.get("content")
                    if isinstance(prev, str):
                        last["content"] = prev.rstrip() + "\n\n" + content.lstrip()
                        return
            self._messages.append({"role": "user", "content": content})
        else:
            # List content (e.g. image + text blocks) is never merged with a prior turn.
            self._messages.append({"role": "user", "content": content})

    def add_assistant_blocks(self, blocks: list[dict[str, Any]]) -> None:
        self._trim()
        self._messages.append({"role": "assistant", "content": blocks})

    def add_host_note(self, text: str) -> None:
        """Append an out-of-band note from the host, as user-role text the model reads.

        Never starts a second user message in a row: Anthropic expects alternating
        roles, and a note that follows tool results belongs *in* that same user turn,
        after the ``tool_result`` blocks.
        """
        if self._messages:
            last = self._messages[-1]
            if last.get("role") == "user":
                content = last.get("content")
                if isinstance(content, str):
                    last["content"] = content.rstrip() + "\n\n" + text.lstrip()
                    return
                if isinstance(content, list):
                    content.append({"type": "text", "text": text})
                    return
        self.add_user(text)

    def add_tool_results(self, blocks: list[dict[str, Any]]) -> None:
        self._trim()
        self._messages.append({"role": "user", "content": blocks})

    def for_api(self) -> list[dict[str, Any]]:
        self._trim()
        return list(self._messages)

    def is_nonempty(self) -> bool:
        return len(self._messages) > 0

    def clear(self) -> None:
        self._messages.clear()

    def export_messages(self) -> list[dict[str, Any]]:
        """Serializable copy of API messages (shallow copy of dicts)."""
        return [dict(m) for m in self._messages]

    def load_messages(self, messages: list[dict[str, Any]]) -> None:
        self._messages.clear()
        for m in messages:
            if not isinstance(m, dict):
                continue
            role = m.get("role")
            if role not in ("user", "assistant"):
                continue
            content = m.get("content")
            if content is None:
                continue
            self._messages.append({"role": role, "content": content})
        self._trim()

    def _trim(self) -> None:
        while len(self._messages) > self.max_messages:
            self._messages.popleft()
