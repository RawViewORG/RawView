"""Provider-neutral contract for the RawView agent loop.

RawView's canonical in-memory transcript format is Anthropic-shaped content blocks
(``{"type": "text"|"thinking"|"tool_use"|"tool_result", ...}``). That is deliberate:
``ConversationMemory``, the tool registry in ``rawview.agent.tools`` and the on-disk
RE session archives all speak it, so keeping it as the internal canon means adding a
provider costs one adapter instead of a rewrite - and old ``.rvre`` sessions keep
loading.

A provider therefore has exactly two jobs:

1. Translate the canonical transcript + tool schemas into its own wire format.
2. Run one assistant turn and translate the reply back into a :class:`TurnResult`.

Tool execution, history bookkeeping and UI events stay in ``AgentBrain``, which never
learns which vendor answered.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable

EmitFn = Callable[[str, dict[str, Any]], None]
AbortFn = Callable[[], bool]


class ProviderError(RuntimeError):
    """Provider failed in a way the user should see verbatim."""


class ProviderInterrupted(Exception):
    """The user stopped the agent mid-request; not an error."""


@dataclass(frozen=True)
class ToolCall:
    """One tool invocation, normalized across vendors.

    ``input`` is always a parsed dict. Anthropic sends it that way; OpenAI-style APIs
    send a JSON *string* under ``function.arguments``, which the adapter parses before
    it ever reaches the agent loop.
    """

    id: str
    name: str
    input: dict[str, Any]


@dataclass
class TurnResult:
    """One assistant turn, normalized.

    ``assistant_blocks`` is what gets appended to the transcript, in canonical block
    form. ``thinking_blocks`` is kept separate because Anthropic requires signed
    thinking blocks to precede ``tool_use`` when a turn is continued with tool
    results; other providers simply leave it empty.
    """

    assistant_blocks: list[dict[str, Any]] = field(default_factory=list)
    thinking_blocks: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = "end_turn"
    streamed: bool = False

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


@dataclass(frozen=True)
class ProviderCapabilities:
    """What a backend can do, so the UI can gray out controls that would be lies.

    Local runners in particular vary wildly: many have no reasoning channel, and some
    have no tool-calling at all. Reporting this honestly is better than sending
    parameters that get ignored or rejected.
    """

    supports_tools: bool = True
    supports_thinking: bool = False
    supports_effort: bool = False
    supports_temperature: bool = True
    supports_streaming: bool = True


class LLMProvider(ABC):
    """One chat backend."""

    #: Stable id used in settings and telemetry, e.g. ``"anthropic"``.
    id: str = "unknown"

    @property
    @abstractmethod
    def model(self) -> str:
        """Model id being addressed, for display."""

    @property
    @abstractmethod
    def capabilities(self) -> ProviderCapabilities:
        ...

    @abstractmethod
    def run_turn(
        self,
        *,
        system: Any,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        emit: EmitFn,
        should_abort: AbortFn,
    ) -> TurnResult | None:
        """Run one assistant turn.

        Returns ``None`` when the user interrupted before a reply was assembled.
        Raises :class:`ProviderError` for anything the user needs to read.
        """

    @property
    def tool_protocol_prompt(self) -> str:
        """System-prompt section describing how *this* API wants tool calls emitted.

        The mechanics differ enough between vendors that one shared description would
        be wrong for somebody: Anthropic wants ``tool_use`` blocks with a parsed
        ``input`` object, OpenAI-style APIs want ``tool_calls`` with a JSON-*string*
        ``function.arguments``. Telling a model the other vendor's rules measurably
        degrades tool use, so each provider supplies its own.
        """
        return ""

    def generate_title(self, first_message: str) -> str:
        """Short chat title for the sidebar. Best effort: "" means "no title".

        Never raise - a failed title must not disturb the conversation.
        """
        return ""

    def close(self) -> None:  # pragma: no cover - most providers hold no resources
        """Release any long-lived transport."""
