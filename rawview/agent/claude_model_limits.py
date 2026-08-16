"""Per-model max output tokens for Anthropic Claude (Messages API).

Caps follow https://platform.claude.com/docs/en/about-claude/models/overview
(synchronous Messages API). Update when Anthropic publishes new snapshot IDs.

Bedrock / Vertex style IDs are normalized (last path segment, ``anthropic.`` stripped)
before matching.
"""

from __future__ import annotations

# (prefix, max_output_tokens): first matching prefix wins; list is most-specific first.
_CLAUDE_MODEL_PREFIX_MAX_OUTPUT: tuple[tuple[str, int], ...] = (
    # Claude 5 / 4.8 / 4.7 / 4.6 (latest)
    ("claude-fable-5", 128_000),
    ("claude-mythos-5", 128_000),
    ("claude-opus-5", 128_000),
    ("claude-sonnet-5", 128_000),
    ("claude-opus-4-8", 128_000),
    ("claude-opus-4-7", 128_000),
    ("claude-opus-4-6", 128_000),
    ("claude-sonnet-4-6", 64_000),
    # Claude 4.5 / Haiku 4.5
    ("claude-haiku-4-5", 64_000),
    ("claude-opus-4-5", 64_000),
    ("claude-sonnet-4-5", 64_000),
    # Claude 4.1 / 4.0
    ("claude-opus-4-1", 32_000),
    ("claude-sonnet-4-20250514", 64_000),
    ("claude-opus-4-20250514", 32_000),
    ("claude-opus-4-", 32_000),
    ("claude-sonnet-4-", 64_000),
    ("claude-haiku-4-", 64_000),
    # Claude 3.x
    ("claude-3-5-haiku", 8192),
    ("claude-3-5-sonnet", 8192),
    ("claude-sonnet-3-5", 8192),
    ("claude-3-opus", 4096),
    ("claude-3-sonnet", 4096),
    ("claude-3-haiku", 4096),
    # Any other claude-* id
    ("claude-", 8192),
)


def _normalize_claude_model_id(model: str) -> str:
    m = (model or "").strip().lower()
    if not m:
        return ""
    if "/" in m:
        m = m.rsplit("/", maxsplit=1)[-1]
    if m.startswith("anthropic."):
        m = m[len("anthropic.") :]
    if "@" in m:
        m = m.split("@", maxsplit=1)[0]
    return m


def max_output_tokens_for_claude_model(model: str) -> int:
    """Return Anthropic's max ``max_tokens`` for this Claude model id (Messages API)."""
    m = _normalize_claude_model_id(model)
    if not m:
        return 8192
    for prefix, cap in _CLAUDE_MODEL_PREFIX_MAX_OUTPUT:
        if m.startswith(prefix):
            return cap
    return 8192


# Models that reject temperature/top_p/top_k with HTTP 400 (sampling params removed).
_NO_SAMPLING_PREFIXES: tuple[str, ...] = (
    "claude-opus-4-7",
    "claude-opus-4-8",
    "claude-opus-5",
    "claude-sonnet-5",
    "claude-fable",
    "claude-mythos",
)

# Models where output_config effort "xhigh" is valid (added with Opus 4.7).
_XHIGH_EFFORT_PREFIXES: tuple[str, ...] = (
    "claude-opus-4-7",
    "claude-opus-4-8",
    "claude-opus-5",
    "claude-sonnet-5",
    "claude-fable",
    "claude-mythos",
)

# Models that reject an explicit thinking={"type": "disabled"} outright (thinking is
# always on) - the parameter must be omitted entirely instead.
_NO_DISABLED_THINKING_PREFIXES: tuple[str, ...] = (
    "claude-fable",
    "claude-mythos",
)

# Models that accept thinking={"type": "disabled"} only at effort "high" or lower;
# pairing it with "xhigh"/"max" is an HTTP 400.
_DISABLED_THINKING_EFFORT_CAPPED_PREFIXES: tuple[str, ...] = ("claude-opus-5",)

# Models where thinking runs even when the "thinking" parameter is omitted. On these,
# leaving it out is not the same as turning thinking off.
_THINKING_ON_BY_DEFAULT_PREFIXES: tuple[str, ...] = (
    "claude-opus-5",
    "claude-sonnet-5",
    "claude-fable",
    "claude-mythos",
)


def model_accepts_sampling_params(model: str) -> bool:
    """False for models that reject temperature/top_p/top_k (Opus 4.7+/4.8, Sonnet 5, Fable/Mythos 5)."""
    m = _normalize_claude_model_id(model)
    return not any(m.startswith(p) for p in _NO_SAMPLING_PREFIXES)


def model_uses_adaptive_thinking(model: str) -> bool:
    """True for models that use adaptive thinking (and reject ``budget_tokens``): Sonnet 4.6+/5,
    Opus 4.6+/4.7/4.8/5, Fable/Mythos 5. Haiku and older models still use ``budget_tokens``."""
    m = _normalize_claude_model_id(model)
    if "haiku" in m:
        return False
    return (
        m.startswith("claude-sonnet-4")
        or m.startswith("claude-sonnet-5")
        or m.startswith("claude-opus-4")
        or m.startswith("claude-opus-5")
        or m.startswith("claude-fable")
        or m.startswith("claude-mythos")
    )


def model_rejects_disabled_thinking(model: str) -> bool:
    """True when ``thinking={"type": "disabled"}`` is an HTTP 400 at any effort (Fable/Mythos 5).

    On these models thinking is always on; the parameter has to be omitted entirely.
    """
    m = _normalize_claude_model_id(model)
    return any(m.startswith(p) for p in _NO_DISABLED_THINKING_PREFIXES)


def model_caps_effort_when_thinking_disabled(model: str) -> bool:
    """True when disabling thinking is only valid at effort ``high`` or lower (Opus 5)."""
    m = _normalize_claude_model_id(model)
    return any(m.startswith(p) for p in _DISABLED_THINKING_EFFORT_CAPPED_PREFIXES)


def model_thinks_by_default(model: str) -> bool:
    """True when omitting ``thinking`` still runs thinking (Opus 5, Sonnet 5, Fable/Mythos 5).

    On these models the parameter must be sent explicitly to turn thinking off, and
    ``max_tokens`` caps thinking plus response text together.
    """
    m = _normalize_claude_model_id(model)
    return any(m.startswith(p) for p in _THINKING_ON_BY_DEFAULT_PREFIXES)


def model_supports_xhigh_effort(model: str) -> bool:
    m = _normalize_claude_model_id(model)
    return any(m.startswith(p) for p in _XHIGH_EFFORT_PREFIXES)


def effort_for_model(model: str, effort: str, *, thinking_disabled: bool = False) -> str | None:
    """Return the effort value to place in ``output_config``, or ``None`` to omit it.

    Haiku 4.5 rejects ``output_config.effort`` -> ``None``. ``xhigh`` is only valid on
    Opus 4.7/4.8/5, Sonnet 5, and Fable/Mythos 5 -> downgraded to ``high`` elsewhere.
    With ``thinking_disabled``, models that cap disabled thinking at ``high`` (Opus 5)
    also get ``xhigh``/``max`` clamped down, since that pairing is an HTTP 400.
    """
    m = _normalize_claude_model_id(model)
    if "haiku" in m:
        return None
    if effort == "xhigh" and not model_supports_xhigh_effort(model):
        return "high"
    if (
        thinking_disabled
        and effort in ("xhigh", "max")
        and model_caps_effort_when_thinking_disabled(model)
    ):
        return "high"
    return effort
