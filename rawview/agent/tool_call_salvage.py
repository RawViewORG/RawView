"""Recover tool calls that a model emitted as plain text, and spot identity lapses.

Two related failure modes show up constantly on local runners (Ollama, LM Studio,
llama.cpp, vLLM without a tool-call parser) and on smaller hosted models:

1. **The call is there, but not in ``tool_calls``.** The model writes
   ``<tool_call>{"name": "list_functions", "arguments": {"limit": 200}}</tool_call>``
   (or a Mistral ``[TOOL_CALLS] [...]``, a Llama ``<function=…>`` tag, a pythonic
   ``[list_functions(limit=200)]``, or a fenced JSON block) into the assistant text.
   Whether that reaches the API's structured field depends entirely on the server's
   chat template and parser, so the same GGUF works on one runner and not another.
   The host sees no call, the loop ends, and the user gets JSON in the chat feed.

2. **The model forgets it is the agent.** It hands the work back to the human -
   "run this and paste the tool output so I can keep working" - and then waits
   forever for a transcript that the host was always going to deliver on its own.

:func:`extract_tool_calls` handles the first; :func:`looks_like_tool_handoff` detects
the second so the loop can correct the model instead of stalling. Both are pure text
functions with no provider dependency, and both are gated on the *real* tool-name set
so ordinary prose that merely mentions a tool cannot trigger them.
"""

from __future__ import annotations

import ast
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Iterable

logger = logging.getLogger(__name__)

__all__ = ["SalvagedCall", "extract_tool_calls", "looks_like_tool_handoff", "repair_call"]

# Keys different templates use for the argument object.
_ARG_KEYS = ("arguments", "input", "parameters", "params", "args", "tool_input")
_NAME_KEYS = ("name", "tool", "tool_name", "function", "recipient_name")

# Wrappers to strip from the leftover prose once calls have been lifted out.
_WRAPPER_RE = re.compile(
    r"""(?xi)
    <\|?/?\s*(?:tool_call|tool_calls|tool_use|function_call|function_calls|
                 python_tag|tool_code|invoke)s?\s*\|?>
    | \[/?TOOL_CALLS?\]
    | </?function(?:\s*=\s*[A-Za-z0-9_.\-]+)?\s*>
    | ```[A-Za-z0-9_+-]*
    """
)

# `<function=get_strings>{"limit": 5}</function>` (Llama 3.1 tool syntax).
_FUNCTION_TAG_RE = re.compile(r"<function\s*=\s*([A-Za-z0-9_.\-]+)\s*>", re.IGNORECASE)

_MAX_CALLS = 8
# Scanning is bounded on both axes so a wall of prose full of braces cannot turn
# salvage into a hot loop: assistant turns that large are never a missed tool call.
_MAX_SCAN_CHARS = 100_000
_MAX_SCAN_STARTS = 200
_MAX_REPAIRS = 3
# No real tool call runs longer than this, so a span that has not closed by here is
# prose with a stray brace in it - stop walking and move on.
_MAX_VALUE_CHARS = 20_000

# Wrapper keys worth descending into. Deliberately not "tools"/"functions": those hold
# a *catalogue* of tools, and a model quoting the tool list back is not calling one.
_WRAPPER_KEYS = ("tool_calls", "tool_call", "calls", "function_call", "invoke")

# Names from the *protocol's* own vocabulary. A model that emits one of these as the
# tool name has wrapped the real call one level too deep - it named the envelope
# ("emit a tool_use block") instead of the tool inside it.
_ENVELOPE_NAMES = frozenset(
    {"tool_use", "tool_call", "tool_calls", "tool", "function", "function_call", "call", "invoke"}
)


def _canonical_name(name: str, valid: frozenset[str]) -> str:
    """Map a model's spelling of a tool name onto the registered one, or ``""``.

    Exact match first; then the spellings models reach for when they paraphrase the
    identifier instead of copying it - a recipient prefix (``functions.get_strings``),
    dashes or spaces for underscores, and camel case (``getStrings``).
    """
    name = name.strip()
    if name in valid:
        return name
    if "." in name:
        tail = name.rsplit(".", 1)[-1]
        if tail in valid:
            return tail
        name = tail
    squashed = re.sub(r"[^a-z0-9]", "", name.lower())
    if not squashed:
        return ""
    for candidate in valid:
        if re.sub(r"[^a-z0-9]", "", candidate.lower()) == squashed:
            return candidate
    return ""


@dataclass(frozen=True)
class SalvagedCall:
    name: str
    input: dict[str, Any]


def _loads_relaxed(fragment: str) -> Any:
    """JSON first, then Python literal syntax (single quotes, True/None)."""
    try:
        return json.loads(fragment)
    except json.JSONDecodeError:
        pass
    try:
        return ast.literal_eval(fragment)
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return None


def _scan_value(text: str, start: int, *, allow_repair: bool = True) -> tuple[Any, int]:
    """Parse the balanced ``{...}``/``[...]`` beginning at ``start``.

    Returns ``(value, end)``; ``value`` is ``None`` when the span does not parse.
    ``end`` always advances past the span so the caller cannot loop forever.
    ``allow_repair`` covers the truncated-call case, which the caller rations because
    every unbalanced brace otherwise re-parses the whole tail.
    """
    opener = text[start]
    closer = "}" if opener == "{" else "]"
    limit = min(len(text), start + _MAX_VALUE_CHARS)
    depth = 0
    in_str = False
    quote = ""
    esc = False
    for i in range(start, limit):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                in_str = False
            continue
        if ch in ('"', "'"):
            in_str = True
            quote = ch
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return _loads_relaxed(text[start : i + 1]), i + 1
    if limit < len(text):
        return None, start + 1
    # Unbalanced to the end of the message: the model (or the token budget) cut the
    # call short. One repair attempt, because a truncated final call is worth running.
    if not allow_repair:
        return None, len(text)
    tail = text[start:]
    repaired = _loads_relaxed(tail + closer * depth)
    return repaired, len(text)


def _coerce_args(raw: Any) -> dict[str, Any] | None:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return {}
        parsed = _loads_relaxed(stripped)
        return parsed if isinstance(parsed, dict) else None
    return None


def _calls_from_value(value: Any, valid: frozenset[str], out: list[SalvagedCall]) -> None:
    """Walk a parsed value, appending every recognizable call to ``out``."""
    if len(out) >= _MAX_CALLS:
        return
    if isinstance(value, list):
        for item in value:
            _calls_from_value(item, valid, out)
        return
    if not isinstance(value, dict):
        return

    # OpenAI shape: {"type": "function", "function": {"name": ..., "arguments": ...}}
    inner = value.get("function")
    if isinstance(inner, dict):
        _calls_from_value(inner, valid, out)
        return
    for key in _WRAPPER_KEYS:
        if key in value:
            _calls_from_value(value[key], valid, out)
            return

    name = ""
    for key in _NAME_KEYS:
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate.strip():
            name = candidate.strip()
            break
    if not name:
        return
    canonical = _canonical_name(name, valid)
    if not canonical:
        # Not a tool - but the real call may be nested one level down, under a name
        # borrowed from the protocol ({"name": "tool_use", "arguments": {"name":
        # "list_functions", "input": {...}}}). Descend only when something real is
        # actually in there, so prose that merely mentions a call stays inert.
        if name.lower() in _ENVELOPE_NAMES:
            for key in _ARG_KEYS:
                nested = _coerce_args(value.get(key))
                if not nested:
                    continue
                found: list[SalvagedCall] = []
                _calls_from_value(nested, valid, found)
                if found:
                    out.extend(found[: _MAX_CALLS - len(out)])
                    return
        return
    name = canonical

    args: dict[str, Any] | None = None
    for key in _ARG_KEYS:
        if key in value:
            args = _coerce_args(value.get(key))
            break
    if args is None:
        # No argument key at all: treat the rest of the object as the arguments,
        # which is what "flat" templates emit ({"name": ..., "address": ...}).
        args = {
            k: v for k, v in value.items() if k not in _NAME_KEYS and k not in ("type", "id")
        }
    out.append(SalvagedCall(name=name, input=args))


def _pythonic_calls(span: str, valid: frozenset[str]) -> list[SalvagedCall]:
    """Parse Llama-3.2 style ``[get_disassembly(address="004010a0", length=40)]``."""
    try:
        tree = ast.parse(span.strip(), mode="eval")
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return []
    node = tree.body
    candidates = node.elts if isinstance(node, ast.List) else [node]
    out: list[SalvagedCall] = []
    for item in candidates:
        if not isinstance(item, ast.Call) or item.args:
            continue
        func = item.func
        name = func.id if isinstance(func, ast.Name) else (
            func.attr if isinstance(func, ast.Attribute) else ""
        )
        if name not in valid:
            continue
        kwargs: dict[str, Any] = {}
        ok = True
        for kw in item.keywords:
            if kw.arg is None:
                ok = False
                break
            try:
                kwargs[kw.arg] = ast.literal_eval(kw.value)
            except (ValueError, SyntaxError):
                ok = False
                break
        if ok:
            out.append(SalvagedCall(name=name, input=kwargs))
    return out


def _clean(text: str, spans: list[tuple[int, int]]) -> str:
    """Remove salvaged spans and their wrapper syntax from the prose."""
    if spans:
        kept: list[str] = []
        cursor = 0
        for start, end in sorted(spans):
            if start > cursor:
                kept.append(text[cursor:start])
            cursor = max(cursor, end)
        kept.append(text[cursor:])
        text = "".join(kept)
    text = _WRAPPER_RE.sub("", text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def repair_call(name: str, args: Any, valid_names: Iterable[str]) -> SalvagedCall | None:
    """Map a *structured* call whose name is not a registered tool onto the one it meant.

    The wire path needs this as much as the text path: a model that has been told to
    "emit a tool_use block" will sometimes put ``tool_use`` in ``function.name`` and
    the real call in the arguments, which the host would otherwise execute as a tool
    that does not exist. Returns ``None`` when nothing recognizable is in there, so
    the caller can still hand the model an ``unknown_tool`` result to react to.
    """
    valid = frozenset(n for n in valid_names if n)
    if not name or not valid:
        return None
    found: list[SalvagedCall] = []
    _calls_from_value({"name": name, "arguments": _coerce_args(args) or {}}, valid, found)
    return found[0] if found else None


def extract_tool_calls(
    text: str, valid_names: Iterable[str]
) -> tuple[list[SalvagedCall], str]:
    """Lift plain-text tool calls out of ``text``.

    Returns the recovered calls and the prose with those fragments removed, so the
    transcript never teaches the model that writing JSON in chat is how calling works.
    Only names in ``valid_names`` are recovered - an unknown name means the model was
    talking *about* a call, not making one.
    """
    valid = frozenset(n for n in valid_names if n)
    if not text or not valid or len(text) > _MAX_SCAN_CHARS:
        return [], text or ""

    calls: list[SalvagedCall] = []
    spans: list[tuple[int, int]] = []

    # `<function=NAME>` names the tool in the tag, so the payload is bare arguments.
    consumed_until = 0
    for match in _FUNCTION_TAG_RE.finditer(text):
        if len(calls) >= _MAX_CALLS or match.start() < consumed_until:
            continue
        name = match.group(1)
        if name not in valid:
            continue
        rest = text[match.end() :]
        offset = len(rest) - len(rest.lstrip())
        pos = match.end() + offset
        args: dict[str, Any] = {}
        end = match.end()
        if pos < len(text) and text[pos] == "{":
            value, end = _scan_value(text, pos)
            coerced = _coerce_args(value)
            if coerced is None:
                continue
            args = coerced
        calls.append(SalvagedCall(name=name, input=args))
        spans.append((match.start(), end))
        consumed_until = end

    i = 0
    starts = 0
    repairs = 0
    while i < len(text) and len(calls) < _MAX_CALLS and starts < _MAX_SCAN_STARTS:
        ch = text[i]
        if ch not in "{[":
            i += 1
            continue
        if any(start <= i < end for start, end in spans):
            i += 1
            continue
        starts += 1
        allow_repair = repairs < _MAX_REPAIRS and len(text) - i <= _MAX_VALUE_CHARS
        value, end = _scan_value(text, i, allow_repair=allow_repair)
        if allow_repair and end == len(text):
            repairs += 1
        before = len(calls)
        if value is not None:
            _calls_from_value(value, valid, calls)
        elif ch == "[":
            calls.extend(_pythonic_calls(text[i:end], valid))
        if len(calls) > before:
            spans.append((i, end))
            i = end
        elif value is not None:
            # Parsed cleanly and held no call: nothing nested is worth re-scanning.
            i = end
        else:
            i += 1

    if not calls:
        return [], text
    del calls[_MAX_CALLS:]
    return calls, _clean(text, spans)


# Phrasings that mean "you, the human, go run the tool and report back". Kept
# specific: a model saying "the tool returned an error" must not trip this.
_HANDOFF_PATTERNS = (
    r"\bpaste\b[^.\n]{0,60}\b(?:output|result|results|response|json|transcript|here)\b",
    r"\b(?:send|share|provide|post|give)\s+(?:me\s+)?(?:the\s+)?[^.\n]{0,40}"
    r"\b(?:tool|command|function)\s+(?:output|result|results|response)\b",
    r"\b(?:once|when|after)\s+you\s+(?:paste|send|share|provide|give|post|run|reply)\b",
    r"\bi(?:'m| am)\s+(?:waiting|standing by|on hold)\b[^.\n]{0,40}"
    r"\b(?:output|result|results|response|you)\b",
    r"\b(?:i'?ll|i will)\s+wait\b[^.\n]{0,40}\b(?:output|result|results|response|you)\b",
    r"\bi\s+(?:don'?t|do not|can'?t|cannot)\s+have\s+(?:access\s+to\s+)?"
    r"(?:the\s+)?(?:tool\s+)?(?:output|results?|access to run)\b",
    r"\b(?:run|execute|call|issue|invoke)\b[^.\n]{0,60}?"
    r"\b(?:yourself|manually|on your (?:own|end|side|machine))\b",
    r"\b(?:run|execute|call|issue|invoke)\b[^.\n]{0,60}?"
    r"\band\s+(?:let me know|tell me|report back|paste|share|send)\b",
    r"\bso\s+i\s+can\s+(?:keep|continue|resume)\s+(?:working|going|the analysis)\b",
    r"\bcopy\s*(?:[/-]|\s+and\s+)?\s*paste\b",
    r"\breply\s+with\s+the\s+(?:tool\s+)?(?:output|results?)\b",
)

_HANDOFF_RE = re.compile("|".join(_HANDOFF_PATTERNS), re.IGNORECASE)


def looks_like_tool_handoff(text: str) -> bool:
    """True when the assistant is asking the human to run tools and report back.

    That request is always a mistake in RawView: the host executes every tool call
    itself and feeds the result straight back into the same loop, so a model waiting
    on the user is waiting on something that will never arrive.
    """
    if not text or not text.strip():
        return False
    return bool(_HANDOFF_RE.search(text))
