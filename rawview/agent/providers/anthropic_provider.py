"""Anthropic Messages API backend.

This is the reference provider: RawView's canonical transcript format is already
Anthropic-shaped, so translation here is close to the identity function. The
model-specific parameter handling (adaptive vs budgeted thinking, effort clamping,
which models reject sampling params) lives in :mod:`rawview.agent.claude_model_limits`.
"""

from __future__ import annotations

import logging
from typing import Any

import anthropic

from rawview.agent.anthropic_backoff import (
    AnthropicBackoffInterrupted,
    messages_create_with_backoff,
    messages_stream_with_backoff,
)
from rawview.agent.claude_model_limits import (
    effort_for_model,
    max_output_tokens_for_claude_model,
    model_accepts_sampling_params,
    model_rejects_disabled_thinking,
    model_thinks_by_default,
    model_uses_adaptive_thinking,
)
from rawview.agent.providers.base import (
    AbortFn,
    EmitFn,
    LLMProvider,
    ProviderCapabilities,
    ProviderInterrupted,
    ToolCall,
    TurnResult,
)

logger = logging.getLogger(__name__)

_TOOL_PROTOCOL = """### Put yourself in the right mode
1. You see a **tools** list in the request (each entry: tool `name`, human-readable `description`, machine `input_schema`). That list is the **only** callable function names - no hidden APIs.
2. Whenever you need **fresh data** from the binary (functions, strings, decompilation, xrefs, …), your next assistant turn should include a **`tool_use`** payload for that data. Guessing addresses or pasting fake JSON "results" in chat is a failure mode.
3. Each call is one object with **exactly two** fields you control: **`name`** (string, must match a tool `name` character-for-character) and **`input`** (a JSON **object** of arguments). This is **Anthropic's shape**, not OpenAI's: there is **no** `function` wrapper, **no** `arguments` string field - only `name` + `input` as a parsed object. If your habits say "arguments", translate them into **`input`** here.

### What you emit (concretely)
- Your assistant message may contain normal **`text`** blocks (optional) plus one or more **`tool_use`** blocks. Only **`tool_use`** triggers execution.
- For every `tool_use`: set **`name`** to the tool identifier (e.g. `list_functions`, never `ListFunctions` or `list-functions`). Set **`input`** to a flat JSON object whose keys are **exactly** the property names from `input_schema` (`address`, not `addr` or `Address`). Include every **required** key; optional keys may be omitted.
- For tools with no parameters, **`input` must still be `{}`** (empty object). **`null`**, omitting `input`, or `[]` is wrong.
- After the host runs tools, you receive a **`user`** message whose content includes **`tool_result`** blocks. Each `content` is a **string** (often JSON). Parse that string; that is the ground truth."""

_TITLE_PROMPT = (
    "Give a 3-5 word title for a conversation starting with this message. "
    "Reply with ONLY the title, no quotes or punctuation:\n\n"
)


def _text_from_message(msg: object) -> str:
    parts: list[str] = []
    for block in getattr(msg, "content", None) or []:
        if getattr(block, "type", None) == "text":
            parts.append(getattr(block, "text", "") or "")
    return "".join(parts).strip()


def _block_to_api_dict(block: object) -> dict[str, Any] | None:
    """Map SDK content block objects to Anthropic API-style dicts for message history."""
    btype = getattr(block, "type", None)
    if btype == "text":
        return {"type": "text", "text": getattr(block, "text", "")}
    if btype == "thinking":
        d: dict[str, Any] = {"type": "thinking", "thinking": getattr(block, "thinking", "")}
        sig = getattr(block, "signature", None)
        if sig:
            d["signature"] = sig
        return d
    if btype == "redacted_thinking":
        return {"type": "redacted_thinking", "data": getattr(block, "data", "")}
    if btype == "tool_use":
        tid = getattr(block, "id", "")
        name = getattr(block, "name", "")
        raw_inp = getattr(block, "input", None) or {}
        inp = dict(raw_inp) if isinstance(raw_inp, dict) else {}
        return {"type": "tool_use", "id": tid, "name": name, "input": inp}
    return None


class AnthropicProvider(LLMProvider):
    id = "anthropic"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        extended_thinking: bool = False,
        thinking_budget_tokens: int = 4096,
        temperature: float = 0.3,
        effort: str = "medium",
    ) -> None:
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model
        self._extended_thinking = extended_thinking
        self._thinking_budget_tokens = thinking_budget_tokens
        self._temperature = float(temperature)
        self._effort = effort

    @property
    def model(self) -> str:
        return self._model

    @property
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            supports_tools=True,
            supports_thinking=True,
            supports_effort=True,
            supports_temperature=model_accepts_sampling_params(self._model),
            supports_streaming=True,
        )

    # ---------------------------------------------------------------- params

    def _build_params(
        self,
        *,
        system: Any,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "model": self._model,
            "system": system,
            "messages": messages,
            "tools": tools,
        }
        # Opus 4.7+/4.8/5, Sonnet 5, and Fable/Mythos 5 reject temperature (HTTP 400).
        if model_accepts_sampling_params(self._model):
            params["temperature"] = self._temperature
        # Haiku rejects effort; xhigh only exists on some models (helper clamps/omits).
        # Opus 5 also caps effort at "high" when thinking is off.
        eff = effort_for_model(
            self._model, self._effort, thinking_disabled=not self._extended_thinking
        )
        if eff is not None:
            params["output_config"] = {"effort": eff}

        if self._extended_thinking:
            if model_uses_adaptive_thinking(self._model):
                params["thinking"] = {"type": "adaptive"}
                params["max_tokens"] = 16000
                # Extended thinking wants temperature=1.0, but only send it on
                # models that accept sampling params at all (else it 400s).
                if "temperature" in params:
                    params["temperature"] = 1.0
            else:
                budget = int(self._thinking_budget_tokens)
                api_max = max_output_tokens_for_claude_model(self._model)
                max_out = min(max(8192, budget + 2048), api_max)
                budget = min(budget, max(1024, max_out - 2048))
                params["thinking"] = {"type": "enabled", "budget_tokens": budget}
                params["max_tokens"] = max_out
                if "temperature" in params:
                    params["temperature"] = 1.0
        elif not model_thinks_by_default(self._model):
            params["max_tokens"] = 8192
        elif model_rejects_disabled_thinking(self._model):
            # Fable/Mythos 5 think unconditionally and 400 on an explicit disable, so
            # leave the parameter out and give max_tokens room for thinking plus reply.
            params["max_tokens"] = min(16000, max_output_tokens_for_claude_model(self._model))
        else:
            # Opus 5 / Sonnet 5 think when "thinking" is omitted, so turning it off
            # has to be explicit.
            params["thinking"] = {"type": "disabled"}
            params["max_tokens"] = 8192
        return params

    # ----------------------------------------------------------------- turn

    def run_turn(
        self,
        *,
        system: Any,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        emit: EmitFn,
        should_abort: AbortFn,
    ) -> TurnResult | None:
        params = self._build_params(system=system, messages=messages, tools=tools)
        try:
            pair = self._messages_turn(params, emit, should_abort)
        except AnthropicBackoffInterrupted:
            raise ProviderInterrupted() from None
        except TypeError:
            logger.warning("messages API rejected thinking kwargs; retrying without thinking")
            pair = self._retry_without_thinking(params, emit, should_abort)
        except Exception as e:
            if self._extended_thinking and "thinking" in params:
                logger.warning("Extended thinking failed (%s); retrying without it", e)
                pair = self._retry_without_thinking(params, emit, should_abort)
            else:
                raise
        if pair is None:
            return None
        msg, streamed = pair
        if msg is None:
            return None
        return self._to_turn_result(msg, streamed, emit)

    def _retry_without_thinking(
        self, params: dict[str, Any], emit: EmitFn, should_abort: AbortFn
    ) -> tuple[Any, bool] | None:
        retry = {k: v for k, v in params.items() if k != "thinking"}
        retry["max_tokens"] = 8192
        if "temperature" in retry:
            retry["temperature"] = self._temperature
        try:
            return self._messages_turn(retry, emit, should_abort)
        except AnthropicBackoffInterrupted:
            raise ProviderInterrupted() from None

    def _to_turn_result(self, msg: Any, streamed: bool, emit: EmitFn) -> TurnResult:
        result = TurnResult(stop_reason=getattr(msg, "stop_reason", "end_turn") or "end_turn",
                            streamed=streamed)
        for block in msg.content:
            btype = getattr(block, "type", None)
            if btype == "text":
                if not streamed:
                    emit("assistant_text", {"text": getattr(block, "text", "")})
                bd = _block_to_api_dict(block)
                if bd:
                    result.assistant_blocks.append(bd)
            elif btype in ("thinking", "redacted_thinking"):
                if not streamed:
                    if btype == "thinking":
                        t = getattr(block, "thinking", "") or ""
                        if t:
                            emit("assistant_thinking", {"text": t})
                    else:
                        emit("assistant_thinking", {"text": "[redacted thinking block]"})
                bd = _block_to_api_dict(block)
                if bd:
                    result.thinking_blocks.append(bd)
            elif btype == "tool_use":
                tid = getattr(block, "id", "")
                name = getattr(block, "name", "")
                raw_inp = getattr(block, "input", None) or {}
                inp = dict(raw_inp) if isinstance(raw_inp, dict) else {}
                result.tool_calls.append(ToolCall(id=tid, name=name, input=inp))
                result.assistant_blocks.append(
                    {"type": "tool_use", "id": tid, "name": name, "input": inp}
                )
        return result

    @property
    def tool_protocol_prompt(self) -> str:
        return """### Put yourself in the right mode
1. You see a **tools** list in the request (each entry: tool `name`, human-readable `description`, machine `input_schema`). That list is the **only** callable function names - no hidden APIs.
2. Whenever you need **fresh data** from the binary (functions, strings, decompilation, xrefs, …), your next assistant turn should include a **`tool_use`** payload for that data. Guessing addresses or pasting fake JSON "results" in chat is a failure mode.
3. Each call is one object with **exactly two** fields you control: **`name`** (string, must match a tool `name` character-for-character) and **`input`** (a JSON **object** of arguments). This is **Anthropic's shape**, not OpenAI's: there is **no** `function` wrapper, **no** `arguments` string field - only `name` + `input` as a parsed object. If your habits say "arguments", translate them into **`input`** here.

### What you emit (concretely)
- Your assistant message may contain normal **`text`** blocks (optional) plus one or more **`tool_use`** blocks. Only **`tool_use`** triggers execution.
- For every `tool_use`: set **`name`** to the tool identifier (e.g. `list_functions`, never `ListFunctions` or `list-functions`). Set **`input`** to a flat JSON object whose keys are **exactly** the property names from `input_schema` (`address`, not `addr` or `Address`). Include every **required** key; optional keys may be omitted.
- For tools with no parameters, **`input` must still be `{}`** (empty object). **`null`**, omitting `input`, or `[]` is wrong.
- After the host runs tools, you receive a **`user`** message whose content includes **`tool_result`** blocks. Each `content` is a **string** (often JSON). Parse that string; that is the ground truth."""

    @property
    def tool_protocol_prompt(self) -> str:
        return _TOOL_PROTOCOL

    def complete_text(
        self,
        *,
        system: str,
        user_text: str,
        max_tokens: int = 8192,
        emit: EmitFn | None = None,
        should_abort: AbortFn | None = None,
        source: str = "",
    ) -> str:
        params: dict[str, Any] = {
            "model": self._model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user_text}],
        }
        if model_accepts_sampling_params(self._model):
            params["temperature"] = self._temperature

        if hasattr(self._client.messages, "stream"):
            try:
                stream_began = False
                with messages_stream_with_backoff(
                    self._client, emit, params, should_abort=should_abort
                ) as stream:
                    if emit is not None:
                        emit("assistant_stream_begin", {"source": source})
                    stream_began = True
                    try:
                        text_stream = getattr(stream, "text_stream", None)
                        if text_stream is None:
                            raise AttributeError("no text_stream")
                        for piece in text_stream:
                            if should_abort is not None and should_abort():
                                raise AnthropicBackoffInterrupted()
                            if emit is not None:
                                emit("assistant_text_delta", {"text": piece, "source": source})
                        msg = stream.get_final_message()
                    finally:
                        if emit is not None and stream_began:
                            emit("assistant_stream_end", {"source": source})
                text = _text_from_message(msg)
                if not text:
                    raise RuntimeError("summarizer_returned_no_text")
                if emit is not None:
                    emit("assistant_stream_commit", {"text": text, "source": source})
                return text
            except AnthropicBackoffInterrupted:
                raise
            except Exception as e:
                logger.warning("streaming completion failed (%s); falling back", e)

        msg = messages_create_with_backoff(self._client, emit, params, should_abort=should_abort)
        text = _text_from_message(msg)
        if not text:
            raise RuntimeError("summarizer_returned_no_text")
        if emit is not None:
            emit("assistant_stream_commit", {"text": text, "source": source})
        return text

    def generate_title(self, first_message: str) -> str:
        """Titles use Haiku regardless of the chat model: it is cheap and fast."""
        try:
            resp = self._client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=30,
                messages=[{"role": "user", "content": _TITLE_PROMPT + first_message[:400]}],
            )
            if resp.content:
                return resp.content[0].text.strip()[:60]
        except Exception:
            pass
        return ""

    # ------------------------------------------------------------ transport

    def _messages_turn(
        self, params: dict[str, Any], emit: EmitFn, should_abort: AbortFn
    ) -> tuple[Any, bool] | None:
        """Return (message, streamed_text). Falls back to non-streaming on recoverable stream errors.

        Anthropic requires the streaming API when extended thinking is enabled (non-streaming
        ``messages.create`` rejects those requests). Do not fall back to create while
        ``thinking`` is present.
        """
        thinking_on = params.get("thinking") is not None and params["thinking"].get(
            "type"
        ) != "disabled"
        if hasattr(self._client.messages, "stream"):
            try:
                return self._messages_turn_stream(params, emit, should_abort), True
            except TypeError:
                raise
            except AnthropicBackoffInterrupted:
                raise
            except Exception as e:
                if thinking_on:
                    logger.warning(
                        "Streaming failed while extended thinking was enabled (%s); "
                        "will not fall back to non-streaming create (API forbids it with thinking).",
                        e,
                    )
                    raise
                logger.warning("Streaming request failed (%s); using non-streaming fallback", e)
        elif thinking_on:
            raise RuntimeError(
                "Extended thinking requires client.messages.stream(); "
                "this Anthropic SDK has no streaming Messages API."
            )
        msg = messages_create_with_backoff(self._client, emit, params, should_abort=should_abort)
        return msg, False

    def _messages_turn_stream(
        self, params: dict[str, Any], emit: EmitFn, should_abort: AbortFn
    ) -> Any:
        stream_cm = messages_stream_with_backoff(
            self._client, emit, params, should_abort=should_abort
        )
        acc: list[str] = []
        stream_began = False
        msg: Any = None
        try:
            with stream_cm as stream:
                emit("assistant_stream_begin", {})
                stream_began = True
                # Unified event loop handles both text and thinking deltas.
                for event in stream:
                    if should_abort():
                        # Return inside `with` - __exit__ closes the HTTP connection immediately.
                        return None
                    etype = getattr(event, "type", None)
                    if etype != "content_block_delta":
                        continue
                    delta = getattr(event, "delta", None)
                    if delta is None:
                        continue
                    dtype = getattr(delta, "type", None)
                    if dtype == "text_delta":
                        piece = getattr(delta, "text", "") or ""
                        if piece:
                            acc.append(piece)
                            emit("assistant_text_delta", {"text": piece})
                    elif dtype == "thinking_delta":
                        piece = getattr(delta, "thinking", "") or ""
                        if piece:
                            emit("assistant_thinking_live", {"text": piece})
                # True stop: do not call get_final_message (drains stream) if interrupted.
                if should_abort():
                    return None
                try:
                    msg = stream.get_final_message()
                except Exception as ge:
                    logger.warning("get_final_message after stream: %s", ge)
                    if should_abort():
                        return None
                    raise
        finally:
            if stream_began:
                emit("assistant_stream_end", {})
        if should_abort():
            return None
        all_txt_parts: list[str] = []
        if msg is not None:
            for block in msg.content:
                if getattr(block, "type", None) == "text":
                    all_txt_parts.append(getattr(block, "text", "") or "")
        merged = "".join(acc) if acc else "".join(all_txt_parts)
        if not merged.strip():
            merged = "".join(all_txt_parts)
        # Emit committed thinking blocks before the assistant reply.
        if msg is not None and params.get("thinking"):
            for block in msg.content:
                bt = getattr(block, "type", None)
                if bt == "thinking":
                    t = getattr(block, "thinking", "") or ""
                    if t.strip():
                        emit("assistant_thinking", {"text": t})
                elif bt == "redacted_thinking":
                    emit("assistant_thinking", {"text": "[redacted thinking block]"})
        if merged.strip():
            emit("assistant_stream_commit", {"text": merged})
        return msg
