"""OpenAI-compatible Chat Completions backend.

One adapter covers most of the non-Anthropic world, because `/v1/chat/completions`
became the de-facto interface. Pointing ``base_url`` at a different host is the only
difference between:

* OpenAI itself
* Google Gemini (via its OpenAI-compatibility endpoint)
* local runners: Ollama, LM Studio, llama.cpp ``server``, vLLM, text-generation-webui
* aggregators and other clouds: OpenRouter, Groq, Together, DeepSeek, Mistral

It talks HTTP directly rather than through the ``openai`` SDK. That is deliberate:
RawView ships as a PyInstaller bundle onto RawOS, the SDK pulls a vendored
httpx/aiohttp stack that has conflicted with distro packages, and the surface actually
needed here is one POST plus SSE. ``httpx`` already ships as an ``anthropic``
dependency, so this costs no new wheel.

Local endpoints are not uniform in practice, so the request is kept minimal and the
few well-known incompatibilities are auto-healed once (see ``_STRIPPABLE``).
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Iterable

import httpx

from rawview.agent.providers.base import (
    AbortFn,
    EmitFn,
    LLMProvider,
    ProviderCapabilities,
    ProviderError,
    ToolCall,
    TurnResult,
)

logger = logging.getLogger(__name__)

_TOOL_PROTOCOL = """### Put yourself in the right mode
1. You see a **tools** list in the request (each entry is a function with a `name`, a human-readable `description`, and a JSON Schema under `parameters`). Those are the **only** callable function names - no hidden APIs.
2. Whenever you need **fresh data** from the binary (functions, strings, decompilation, xrefs, …), your next assistant turn must contain a **tool call** for that data. Guessing addresses, or writing fake JSON "results" as chat text, is a failure mode: text is never executed.
3. Emit tool calls through the API's **`tool_calls`** field - not as prose, not in a code fence. Each entry has `function.name` (matching a tool `name` character-for-character) and `function.arguments`, a **JSON string** that parses to a flat object.

### What you emit (concretely)
- Set `function.name` to the tool identifier exactly (e.g. `list_functions`, never `ListFunctions` or `list-functions`).
- `function.arguments` keys must be **exactly** the property names from that tool's `parameters` schema (`address`, not `addr` or `Address`). Include every **required** key; optional keys may be omitted.
- For tools with no parameters, `function.arguments` must still be **`"{}"`** - an empty JSON object, never `null` or an empty string.
- Emit one entry per call; to run several tools, put several entries in the same `tool_calls` array.
- After the host runs them you receive one **`tool`** role message per call, matched by `tool_call_id`. Its content is a **string** (often JSON). Parse it; that is the ground truth."""

# finish_reason -> canonical stop reason.
_FINISH_MAP = {
    "tool_calls": "tool_use",
    "function_call": "tool_use",
    "stop": "end_turn",
    "length": "max_tokens",
    "content_filter": "refusal",
}

# Fields some servers reject, and what to do about it. Each is tried at most once so a
# genuinely broken request still fails fast instead of looping.
#   - GPT-5 / o-series renamed max_tokens to max_completion_tokens.
#   - Reasoning models and several local runners reject temperature outright.
_STRIPPABLE = ("max_tokens", "temperature", "tools")


def _flatten_system(system: Any) -> str:
    """RawView passes system as Anthropic text blocks (with cache_control); flatten it."""
    if system is None:
        return ""
    if isinstance(system, str):
        return system
    parts: list[str] = []
    for block in system:
        if isinstance(block, dict):
            if block.get("type") == "text":
                parts.append(str(block.get("text", "")))
        elif isinstance(block, str):
            parts.append(block)
    return "\n\n".join(p for p in parts if p)


def _content_to_text(content: Any) -> str:
    """Best-effort text for a tool_result payload, which may be str or block list."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(str(block.get("text", "")))
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts)
    return str(content)


class OpenAICompatibleProvider(LLMProvider):
    id = "openai"

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        temperature: float = 0.3,
        max_tokens: int = 4096,
        supports_tools: bool = True,
        stream: bool = True,
        timeout: float = 600.0,
        provider_label: str = "OpenAI-compatible",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        # Local servers usually ignore the key but still want the header present.
        self._api_key = api_key or "not-needed"
        self._model = model
        self._temperature = float(temperature)
        self._max_tokens = int(max_tokens)
        self._supports_tools = supports_tools
        self._stream = stream
        self._label = provider_label
        self._client = httpx.Client(timeout=httpx.Timeout(timeout, connect=15.0))

    @property
    def model(self) -> str:
        return self._model

    @property
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            supports_tools=self._supports_tools,
            # Reasoning text is surfaced when a server sends it, but it is not a
            # parameter the user can dial the way Anthropic thinking is.
            supports_thinking=False,
            supports_effort=False,
            supports_temperature=True,
            supports_streaming=True,
        )

    def close(self) -> None:
        self._client.close()

    # ---------------------------------------------------------- translation

    def _translate_tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for t in tools or []:
            name = t.get("name")
            if not name:
                continue
            out.append(
                {
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": t.get("description", ""),
                        # Anthropic calls it input_schema; OpenAI calls it parameters.
                        # cache_control rides on the Anthropic copy and is dropped here.
                        "parameters": t.get("input_schema") or {"type": "object", "properties": {}},
                    },
                }
            )
        return out

    def _translate_messages(
        self, system: Any, messages: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Canonical Anthropic-block transcript -> OpenAI message list.

        Ordering matters: an OpenAI ``role: "tool"`` message must follow the assistant
        message carrying the matching ``tool_calls``. The canonical form already
        alternates assistant(tool_use) -> user(tool_result), so a straight walk
        preserves that.
        """
        out: list[dict[str, Any]] = []
        sys_text = _flatten_system(system)
        if sys_text:
            out.append({"role": "system", "content": sys_text})

        for msg in messages:
            role = msg.get("role")
            content = msg.get("content")

            if isinstance(content, str):
                out.append({"role": role, "content": content})
                continue
            if not isinstance(content, list):
                continue

            if role == "assistant":
                text_parts: list[str] = []
                tool_calls: list[dict[str, Any]] = []
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    btype = block.get("type")
                    if btype == "text":
                        text_parts.append(str(block.get("text", "")))
                    elif btype == "tool_use":
                        tool_calls.append(
                            {
                                "id": block.get("id") or f"call_{uuid.uuid4().hex[:12]}",
                                "type": "function",
                                "function": {
                                    "name": block.get("name", ""),
                                    "arguments": json.dumps(block.get("input") or {}),
                                },
                            }
                        )
                    # thinking / redacted_thinking are Anthropic-signed and not portable.
                entry: dict[str, Any] = {"role": "assistant"}
                entry["content"] = "\n".join(p for p in text_parts if p) or None
                if tool_calls:
                    entry["tool_calls"] = tool_calls
                out.append(entry)
                continue

            # role == "user": may hold tool results, plain text, and/or images.
            pending_text: list[dict[str, Any]] = []
            for block in content:
                if not isinstance(block, dict):
                    continue
                btype = block.get("type")
                if btype == "tool_result":
                    out.append(
                        {
                            "role": "tool",
                            "tool_call_id": block.get("tool_use_id", ""),
                            "content": _content_to_text(block.get("content")),
                        }
                    )
                elif btype == "text":
                    pending_text.append({"type": "text", "text": str(block.get("text", ""))})
                elif btype == "image":
                    src = block.get("source") or {}
                    if src.get("type") == "base64":
                        media = src.get("media_type", "image/png")
                        pending_text.append(
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:{media};base64,{src.get('data', '')}"
                                },
                            }
                        )
                    elif src.get("type") == "url":
                        pending_text.append(
                            {"type": "image_url", "image_url": {"url": src.get("url", "")}}
                        )
            if pending_text:
                if all(p.get("type") == "text" for p in pending_text):
                    out.append(
                        {
                            "role": "user",
                            "content": "\n".join(p["text"] for p in pending_text),
                        }
                    )
                else:
                    out.append({"role": "user", "content": pending_text})
        return out

    # ------------------------------------------------------------- request

    def _payload(
        self, system: Any, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": self._translate_messages(system, messages),
            "temperature": self._temperature,
            "max_tokens": self._max_tokens,
        }
        if self._supports_tools and tools:
            payload["tools"] = self._translate_tools(tools)
        return payload

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    def _adapt_payload(self, payload: dict[str, Any], detail: str) -> dict[str, Any] | None:
        """Heal one known incompatibility, or return None if nothing applies.

        Endpoints disagree about a handful of fields; rather than maintaining a matrix
        of every local runner, react to what the server actually complained about.
        """
        low = detail.lower()
        if "max_completion_tokens" in low and "max_tokens" in payload:
            # GPT-5 / o-series rename.
            payload = dict(payload)
            payload["max_completion_tokens"] = payload.pop("max_tokens")
            return payload
        for field in _STRIPPABLE:
            if field in payload and field in low:
                payload = dict(payload)
                payload.pop(field)
                logger.warning("Endpoint rejected %r; retrying without it", field)
                return payload
        return None

    def _post(self, payload: dict[str, Any], *, stream: bool) -> Any:
        url = f"{self._base_url}/chat/completions"
        body = dict(payload)
        body["stream"] = stream
        try:
            if stream:
                return self._client.stream("POST", url, json=body, headers=self._headers())
            return self._client.post(url, json=body, headers=self._headers())
        except httpx.ConnectError as e:
            raise ProviderError(
                f"Could not reach {self._label} at {self._base_url}. "
                f"Is the server running? ({e})"
            ) from e
        except httpx.HTTPError as e:
            raise ProviderError(f"{self._label} request failed: {e}") from e

    @staticmethod
    def _raise_for_status(status: int, text: str, label: str) -> None:
        if status < 400:
            return
        detail = text.strip()
        try:
            parsed = json.loads(detail)
            detail = (
                parsed.get("error", {}).get("message")
                if isinstance(parsed.get("error"), dict)
                else parsed.get("error") or parsed.get("message") or detail
            )
        except Exception:
            pass
        raise ProviderError(f"{label} returned HTTP {status}: {detail}")

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
        payload = {
            "model": self._model,
            "max_tokens": max_tokens,
            "temperature": self._temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user_text},
            ],
        }
        for attempt in range(len(_STRIPPABLE) + 1):
            try:
                resp = self._post(payload, stream=False)
                self._raise_for_status(resp.status_code, resp.text, self._label)
                choice = (resp.json().get("choices") or [{}])[0]
                text = (choice.get("message") or {}).get("content") or ""
                if not text.strip():
                    raise ProviderError("summarizer_returned_no_text")
                if emit is not None:
                    emit("assistant_stream_commit", {"text": text, "source": source})
                return text
            except ProviderError as e:
                healed = self._adapt_payload(payload, str(e))
                if healed is None or attempt == len(_STRIPPABLE):
                    raise
                payload = healed
        raise ProviderError("summarizer_failed")

    def generate_title(self, first_message: str) -> str:
        try:
            resp = self._client.post(
                f"{self._base_url}/chat/completions",
                json={
                    "model": self._model,
                    "max_tokens": 30,
                    "messages": [
                        {
                            "role": "user",
                            "content": (
                                "Give a 3-5 word title for a conversation starting with this "
                                "message. Reply with ONLY the title, no quotes or punctuation:"
                                f"\n\n{first_message[:400]}"
                            ),
                        }
                    ],
                },
                headers=self._headers(),
            )
            if resp.status_code >= 400:
                return ""
            choice = (resp.json().get("choices") or [{}])[0]
            return (choice.get("message") or {}).get("content", "").strip()[:60]
        except Exception:
            return ""

    # ---------------------------------------------------------------- turn

    def run_turn(
        self,
        *,
        system: Any,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        emit: EmitFn,
        should_abort: AbortFn,
    ) -> TurnResult | None:
        payload = self._payload(system, messages, tools)
        for attempt in range(len(_STRIPPABLE) + 1):
            try:
                if self._stream:
                    return self._run_streaming(payload, emit, should_abort)
                return self._run_blocking(payload, emit, should_abort)
            except ProviderError as e:
                healed = self._adapt_payload(payload, str(e))
                if healed is None or attempt == len(_STRIPPABLE):
                    raise
                payload = healed
        return None

    def _run_blocking(
        self, payload: dict[str, Any], emit: EmitFn, should_abort: AbortFn
    ) -> TurnResult | None:
        resp = self._post(payload, stream=False)
        self._raise_for_status(resp.status_code, resp.text, self._label)
        if should_abort():
            return None
        data = resp.json()
        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        text = message.get("content") or ""
        reasoning = message.get("reasoning_content") or message.get("reasoning") or ""
        if reasoning:
            emit("assistant_thinking", {"text": reasoning})
        if text:
            emit("assistant_text", {"text": text})
        return self._assemble(
            text=text,
            raw_tool_calls=message.get("tool_calls") or [],
            finish_reason=choice.get("finish_reason"),
            streamed=False,
        )

    def _run_streaming(
        self, payload: dict[str, Any], emit: EmitFn, should_abort: AbortFn
    ) -> TurnResult | None:
        text_parts: list[str] = []
        # Tool call fragments arrive split across deltas, keyed by index.
        acc: dict[int, dict[str, Any]] = {}
        finish_reason: str | None = None
        stream_began = False

        stream_cm = self._post(payload, stream=True)
        try:
            with stream_cm as resp:
                if resp.status_code >= 400:
                    resp.read()
                    self._raise_for_status(resp.status_code, resp.text, self._label)
                emit("assistant_stream_begin", {})
                stream_began = True
                for line in resp.iter_lines():
                    if should_abort():
                        return None
                    if not line:
                        continue
                    if line.startswith("data:"):
                        line = line[5:].strip()
                    if not line or line == "[DONE]":
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    choices = event.get("choices") or []
                    if not choices:
                        continue
                    choice = choices[0]
                    if choice.get("finish_reason"):
                        finish_reason = choice["finish_reason"]
                    delta = choice.get("delta") or {}

                    piece = delta.get("content")
                    if piece:
                        text_parts.append(piece)
                        emit("assistant_text_delta", {"text": piece})

                    # DeepSeek/Qwen/Ollama expose reasoning on a side channel.
                    think = delta.get("reasoning_content") or delta.get("reasoning")
                    if think:
                        emit("assistant_thinking_live", {"text": think})

                    for frag in delta.get("tool_calls") or []:
                        idx = frag.get("index", 0)
                        slot = acc.setdefault(idx, {"id": "", "name": "", "arguments": ""})
                        if frag.get("id"):
                            slot["id"] = frag["id"]
                        fn = frag.get("function") or {}
                        if fn.get("name"):
                            slot["name"] = fn["name"]
                        if fn.get("arguments"):
                            slot["arguments"] += fn["arguments"]
        finally:
            if stream_began:
                emit("assistant_stream_end", {})

        if should_abort():
            return None
        merged = "".join(text_parts)
        if merged.strip():
            emit("assistant_stream_commit", {"text": merged})

        raw_tool_calls = [
            {
                "id": slot["id"],
                "function": {"name": slot["name"], "arguments": slot["arguments"]},
            }
            for _, slot in sorted(acc.items())
            if slot.get("name")
        ]
        return self._assemble(
            text=merged,
            raw_tool_calls=raw_tool_calls,
            finish_reason=finish_reason,
            streamed=True,
        )

    # ------------------------------------------------------------ assembly

    def _assemble(
        self,
        *,
        text: str,
        raw_tool_calls: Iterable[dict[str, Any]],
        finish_reason: str | None,
        streamed: bool,
    ) -> TurnResult:
        result = TurnResult(streamed=streamed)
        if text:
            result.assistant_blocks.append({"type": "text", "text": text})

        for raw in raw_tool_calls:
            fn = raw.get("function") or {}
            name = fn.get("name") or ""
            if not name:
                continue
            args = fn.get("arguments")
            parsed: dict[str, Any]
            if isinstance(args, dict):
                parsed = args
            else:
                try:
                    parsed = json.loads(args or "{}")
                except json.JSONDecodeError:
                    # Smaller local models emit malformed argument JSON often enough
                    # that failing the whole turn would be the wrong call; hand the
                    # error to the model as a tool result instead.
                    logger.warning("Unparsable tool arguments for %s: %r", name, args)
                    parsed = {"__raw_arguments__": args}
            if not isinstance(parsed, dict):
                parsed = {"__raw_arguments__": args}
            # Some local servers omit ids entirely; the loop needs one to correlate.
            call_id = raw.get("id") or f"call_{uuid.uuid4().hex[:12]}"
            result.tool_calls.append(ToolCall(id=call_id, name=name, input=parsed))
            result.assistant_blocks.append(
                {"type": "tool_use", "id": call_id, "name": name, "input": parsed}
            )

        # Some servers report "stop" even while returning tool calls; trust the calls.
        if result.tool_calls:
            result.stop_reason = "tool_use"
        else:
            result.stop_reason = _FINISH_MAP.get(finish_reason or "stop", "end_turn")
        return result
