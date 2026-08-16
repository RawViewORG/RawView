"""One-shot summarization of agent chat history for /summarize (no tools)."""

from __future__ import annotations

import json
import logging
from typing import Any, Callable


from rawview.agent.providers import LLMProvider

logger = logging.getLogger(__name__)

NoticeEmit = Callable[[str, dict[str, Any]], None] | None
ShouldAbort = Callable[[], bool] | None

_SUMMARY_SYSTEM = """You compress reverse-engineering chat transcripts for the RawView Ghidra agent.

The transcript uses sections === USER === and === ASSISTANT ===. Tool calls and JSON results appear inline.

Write a single Markdown document that will REPLACE the old transcript in the model context. Include:
1. **User goals**: what they asked, in order, briefly.
2. **Key findings**: verified addresses, function names, imports/strings called out, hypotheses that were confirmed or refuted.
3. **Actions taken**: notable renames, comments, files opened (names only).
4. **Open threads**: unanswered questions or next steps.

Rules:
- Drop verbatim long hex, full disassembly, and huge JSON; keep only what matters for continuing RE.
- Preserve exact addresses/symbols when they are load-bearing for follow-up.
- Be as short as clarity allows (typical target: under 2-3k words unless the source is tiny).
- Do not invent facts not present in the transcript."""


def flatten_messages_for_summary(
    messages: list[dict[str, Any]],
    *,
    max_transcript_chars: int = 280_000,
) -> str:
    """Turn API-style message list into plain text for the summarizer model."""
    parts: list[str] = []
    for m in messages:
        role = m.get("role")
        if role not in ("user", "assistant"):
            continue
        content = m.get("content")
        parts.append(f"=== {str(role).upper()} ===")
        parts.append(_flatten_content(content))
        parts.append("")
    text = "\n".join(parts).strip()
    if len(text) <= max_transcript_chars:
        return text
    head = max_transcript_chars // 2
    tail = max_transcript_chars - head - 120
    return (
        text[:head]
        + "\n\n... [middle of transcript truncated for summarizer input] ...\n\n"
        + text[-tail:]
    )


def _flatten_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        lines: list[str] = []
        for block in content:
            if not isinstance(block, dict):
                continue
            btype = block.get("type")
            if btype == "text":
                lines.append(str(block.get("text", "")))
            elif btype in ("thinking", "redacted_thinking"):
                lines.append("[thinking block omitted]")
            elif btype == "tool_use":
                name = block.get("name", "")
                inp = block.get("input", {})
                try:
                    inp_s = json.dumps(inp, ensure_ascii=False)[:4000]
                except (TypeError, ValueError):
                    inp_s = str(inp)[:4000]
                lines.append(f"Tool use: {name} {inp_s}")
            elif btype == "tool_result":
                body = str(block.get("content", ""))
                cap = 2500
                if len(body) > cap:
                    body = body[:cap] + "…(truncated)"
                lines.append(f"Tool result: {body}")
            else:
                lines.append(str(block)[:2000])
        return "\n".join(lines)
    return str(content)[:50_000]


def _text_from_message(msg: Any) -> str:
    out: list[str] = []
    for block in msg.content:
        if getattr(block, "type", None) == "text":
            out.append(getattr(block, "text", "") or "")
    return "\n".join(out).strip()


def summarize_conversation_transcript(
    *,
    provider: LLMProvider,
    transcript: str,
    emit: NoticeEmit = None,
    should_abort: ShouldAbort = None,
) -> str:
    """Condense a chat transcript. Works on whatever backend is configured."""
    if not transcript.strip():
        raise ValueError("empty_transcript")
    return provider.complete_text(
        system=_SUMMARY_SYSTEM,
        user_text=transcript,
        max_tokens=8192,
        emit=emit,
        should_abort=should_abort,
        source="summarize",
    )
