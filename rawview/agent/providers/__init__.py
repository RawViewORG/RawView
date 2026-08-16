"""Provider registry: presets, construction from settings, and model discovery.

Adding a backend means adding a :class:`ProviderPreset` row. Anything that speaks
OpenAI-style ``/chat/completions`` needs no new code at all - only a base URL.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

import httpx

from rawview.agent.providers.base import (
    LLMProvider,
    ProviderCapabilities,
    ProviderError,
    ProviderInterrupted,
    ToolCall,
    TurnResult,
)

logger = logging.getLogger(__name__)

__all__ = [
    "LLMProvider",
    "ProviderCapabilities",
    "ProviderError",
    "ProviderInterrupted",
    "ProviderPreset",
    "ToolCall",
    "TurnResult",
    "PRESETS",
    "preset_by_id",
    "build_provider",
    "discover_models",
]


@dataclass(frozen=True)
class ProviderPreset:
    id: str
    label: str
    kind: str  # "anthropic" or "openai"
    base_url: str
    requires_key: bool
    suggested_model: str
    hint: str


# Suggested models are starting points only - the model field stays free text, and
# Settings can fetch the real list from the endpoint (see `discover_models`). That
# matters most for local runners, where the catalogue is whatever the user pulled.
PRESETS: tuple[ProviderPreset, ...] = (
    ProviderPreset(
        id="anthropic",
        label="Anthropic (Claude)",
        kind="anthropic",
        base_url="",
        requires_key=True,
        suggested_model="claude-opus-5",
        hint="Native Messages API: extended thinking, effort, and signed reasoning blocks.",
    ),
    ProviderPreset(
        id="openai",
        label="OpenAI",
        kind="openai",
        base_url="https://api.openai.com/v1",
        requires_key=True,
        suggested_model="gpt-5",
        hint="Uses your OpenAI API key.",
    ),
    ProviderPreset(
        id="gemini",
        label="Google Gemini",
        kind="openai",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
        requires_key=True,
        suggested_model="gemini-2.5-flash",
        hint="Google's OpenAI-compatibility endpoint. Use a Google AI Studio key.",
    ),
    ProviderPreset(
        id="ollama",
        label="Ollama (local)",
        kind="openai",
        base_url="http://localhost:11434/v1",
        requires_key=False,
        suggested_model="",
        hint="Runs fully offline. Start it with `ollama serve`, then Refresh to list pulled models.",
    ),
    ProviderPreset(
        id="lmstudio",
        label="LM Studio (local)",
        kind="openai",
        base_url="http://localhost:1234/v1",
        requires_key=False,
        suggested_model="",
        hint="Enable the local server in LM Studio, then Refresh.",
    ),
    ProviderPreset(
        id="llamacpp",
        label="llama.cpp server (local)",
        kind="openai",
        base_url="http://localhost:8080/v1",
        requires_key=False,
        suggested_model="",
        hint="`llama-server -m model.gguf`. Tool calling depends on the model's chat template.",
    ),
    ProviderPreset(
        id="vllm",
        label="vLLM (local)",
        kind="openai",
        base_url="http://localhost:8000/v1",
        requires_key=False,
        suggested_model="",
        hint="`vllm serve <model>`. Start it with a tool-call parser for agent use.",
    ),
    ProviderPreset(
        id="openrouter",
        label="OpenRouter",
        kind="openai",
        base_url="https://openrouter.ai/api/v1",
        requires_key=True,
        suggested_model="",
        hint="Routes to many vendors behind one key.",
    ),
    ProviderPreset(
        id="custom",
        label="Custom (OpenAI-compatible)",
        kind="openai",
        base_url="",
        requires_key=False,
        suggested_model="",
        hint="Any server exposing /v1/chat/completions. Enter its base URL.",
    ),
)

_BY_ID = {p.id: p for p in PRESETS}


def preset_by_id(pid: str) -> ProviderPreset:
    return _BY_ID.get(pid or "anthropic", _BY_ID["anthropic"])


def build_provider(settings: Any) -> LLMProvider:
    """Construct the configured provider from a ``Settings`` object.

    Anthropic keeps its own key/model fields so existing installs and saved
    ``rawview.env`` files keep working untouched.
    """
    preset = preset_by_id(getattr(settings, "llm_provider", "anthropic"))

    if preset.kind == "anthropic":
        from rawview.agent.providers.anthropic_provider import AnthropicProvider

        return AnthropicProvider(
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model,
            extended_thinking=getattr(settings, "agent_extended_thinking", False),
            thinking_budget_tokens=getattr(settings, "agent_thinking_budget_tokens", 4096),
            temperature=getattr(settings, "agent_temperature", 0.3),
            effort=getattr(settings, "agent_effort", "medium"),
        )

    from rawview.agent.providers.openai_provider import OpenAICompatibleProvider

    base_url = (getattr(settings, "llm_base_url", "") or preset.base_url).strip()
    if not base_url:
        raise ProviderError(
            f"{preset.label} needs a base URL. Set it under File -> Settings."
        )
    model = (getattr(settings, "llm_model", "") or preset.suggested_model).strip()
    if not model:
        raise ProviderError(
            f"{preset.label} needs a model id. Set it under File -> Settings "
            "(use Refresh to list what the endpoint offers)."
        )
    return OpenAICompatibleProvider(
        base_url=base_url,
        api_key=getattr(settings, "llm_api_key", ""),
        model=model,
        temperature=getattr(settings, "agent_temperature", 0.3),
        max_tokens=getattr(settings, "llm_max_tokens", 4096),
        supports_tools=getattr(settings, "llm_supports_tools", True),
        provider_label=preset.label,
    )


def discover_models(base_url: str, api_key: str, timeout: float = 15.0) -> list[str]:
    """List model ids from an OpenAI-compatible ``/models`` endpoint.

    Ollama, LM Studio, vLLM, llama.cpp, OpenAI and Gemini's compat endpoint all
    implement this, so Settings can offer real ids instead of guesses.
    """
    url = f"{base_url.rstrip('/')}/models"
    headers = {"Authorization": f"Bearer {api_key or 'not-needed'}"}
    try:
        resp = httpx.get(url, headers=headers, timeout=timeout)
    except httpx.HTTPError as e:
        raise ProviderError(f"Could not reach {url}: {e}") from e
    if resp.status_code >= 400:
        raise ProviderError(f"{url} returned HTTP {resp.status_code}: {resp.text[:200]}")
    try:
        payload = resp.json()
    except json.JSONDecodeError as e:
        raise ProviderError(f"{url} did not return JSON") from e
    entries = payload.get("data") if isinstance(payload, dict) else payload
    out: list[str] = []
    for item in entries or []:
        if isinstance(item, dict):
            mid = item.get("id") or item.get("name")
            if mid:
                out.append(str(mid))
        elif isinstance(item, str):
            out.append(item)
    return sorted(set(out))
