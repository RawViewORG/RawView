from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable
from typing import Any

from rawview.agent.memory import ConversationMemory
from rawview.agent.providers import LLMProvider, ProviderInterrupted
from rawview.agent.tools import AgentBatchToolPort, anthropic_tool_list, run_tool
from rawview.ghidra.api import GhidraAPI

logger = logging.getLogger(__name__)

EmitFn = Callable[[str, dict[str, Any]], None]


def _tool_result_preview_cap(tool_name: str) -> int:
    """UI preview truncation only; full tool JSON still enters conversation memory."""
    if tool_name == "web_search":
        return 14_000
    if tool_name == "batch_run_tools":
        return 16_000
    if tool_name in ("list_functions", "get_strings", "get_imports"):
        return 10_000
    return 4000

# Short user phrases that should always map to Ghidra auto-analysis (model often replies in prose otherwise).
_ANALYZE_ALIASES = frozenset(
    {
        "analyze",
        "analyse",
        "analysis",
        "auto analyze",
        "auto-analyze",
        "autoanalysis",
        "run analysis",
        "run auto-analysis",
        "run auto analysis",
        "ghidra analyze",
        "auto analysis",
    }
)


def _expand_short_analyze_intent(text: str) -> str:
    t = text.strip().lower().rstrip(".!?")
    if not t:
        return text
    if t.startswith("please "):
        t = t.removeprefix("please ").strip()
    if t in _ANALYZE_ALIASES:
        return (
            "Run Ghidra auto-analysis on the currently loaded program now using the "
            "run_auto_analysis tool (it takes no arguments). After the tool returns, "
            "give a one-sentence confirmation."
        )
    return text


class AgentBrain:
    """Provider-agnostic tool loop with cooperative interrupt between turns.

    The loop owns tool execution, transcript bookkeeping and UI events. Everything
    vendor-specific - wire format, streaming, retries, sampling knobs - lives behind
    :class:`~rawview.agent.providers.base.LLMProvider`.
    """

    def __init__(
        self,
        *,
        provider: LLMProvider,
        ghidra_api: GhidraAPI,
        memory: ConversationMemory,
        max_turns: int,
        on_navigate: Callable[[str], None],
        emit: EmitFn,
        batch_port: AgentBatchToolPort | None = None,
    ) -> None:
        self._provider = provider
        self._ghidra = ghidra_api
        self._memory = memory
        self._max_turns = max_turns
        self._on_navigate = on_navigate
        self._emit = emit
        self._batch_port = batch_port
        self._interrupt = threading.Event()

    @property
    def provider(self) -> LLMProvider:
        return self._provider

    def interrupt(self) -> None:
        self._interrupt.set()

    def clear_interrupt(self) -> None:
        self._interrupt.clear()

    def close(self) -> None:
        self._provider.close()

    def generate_chat_title(self, first_message: str) -> str:
        """Short chat title; empty string on any failure."""
        return self._provider.generate_title(first_message)

    def run_user_prompt(
        self,
        text: str,
        *,
        goal: str | None = None,
        images: list[dict[str, Any]] | None = None,
    ) -> None:
        text = _expand_short_analyze_intent(text)
        if images:
            content: list[dict[str, Any]] = list(images)
            if text.strip():
                content.append({"type": "text", "text": text})
            self._memory.add_user(content)
        else:
            self._memory.add_user(text)
        system = """
You are RawView, the in-app reverse-engineering agent. You act on a live Ghidra session through tools - not from memory of binaries you have not inspected.

## Safety and scope
- Stay focused on reverse engineering, Ghidra, and the loaded program. Help with malware analysis **only** as technical RE in a defensive or research context inside this tool.
- **Refuse** requests for instructions that enable serious real-world harm unrelated to legitimate RE - for example: weapons or explosives, terrorism, targeted harassment, non-consensual surveillance, or detailed guidance for committing crimes. Decline briefly and offer safe alternatives (e.g. general security concepts, or analysis confined to the binary at hand) when appropriate.
- Do not provide step-by-step instructions for self-harm; encourage seeking professional help instead.
- Normal RE tasks (unpacking, unpacking malware samples in Ghidra, exploit mitigation understanding, crypto in binaries) remain in scope when tied to analysis here.

## How you work
- Default to tools over speculation. If you lack facts (addresses, names, xrefs), fetch them; do not invent addresses or behavior.
- Work in tight loops: gather evidence → interpret → decide the next smallest tool step. Prefer incremental exploration over one giant assumption.
- After tool results, answer the user in clear prose: what you checked, what you found, and what it implies. Quote symbols or addresses from tool output when it helps.
- If the user's target is ambiguous (multiple matches, unclear image base, vague "the crypto function"), ask one short clarifying question instead of guessing.
- **Batch analysis (File dock):** The user may queue several binaries in the UI. You only see that queue through **`analysis_batch_status`**, which returns **`items`**: each row has `index`, `basename`, and full `path`, plus `next_index` / `next_path`. Ghidra holds **one** program at a time.
- When work spans multiple queued files, or the user mentions "next", "batch", "the queue", or a filename from the list, call **`analysis_batch_status`** first, then **`analysis_batch_open_next`** (follow `next_index`) or **`analysis_batch_open_index`** with the chosen `index`. Prefer those over **`open_file`** alone so the batch cursor stays aligned with the UI (double-click / Open next).

## Ghidra workflow (suggested order, adapt as needed)
- Orientation: list_functions (with limit when the image is large), get_entry_points, get_imports/exports, get_strings as appropriate to map the surface.
- Drill-down: get_xrefs_to/from, get_disassembly, decompile_function, get_data_at, search_bytes, get_control_flow_graph.
- When you change the database (rename_function, rename_variable, set_comment, set_function_signature, create_struct), be deliberate and explain the rationale briefly to the user.

## Memory (two stores)
- **Conversation memory**: the `messages` you receive are the live chat transcript - prior **user** turns and **assistant** turns (assistant text plus tool calls; tool results arrive as following **user** messages per the API). Use them for continuity across sends. The UI may also show thinking that is **not** re-injected here to save context. When the user runs `/summarize`, older turns are replaced by a single bracketed Markdown summary - treat that block as authoritative shorthand for what was dropped.
- **Long-term agent memory** (`read_agent_memory` / `append_agent_memory`): a Markdown file on disk that persists across sessions. Use it for stable, reusable facts (binary identity, key function addresses you verified, architecture, analysis plan). Read it when the user refers to "last time," prior goals, or anything that might already be recorded. Before appending, read if the file may be large or you might duplicate content. Never store secrets, credentials, API keys, or private personal data - summaries only.
- **Work dock** (`list_work_notes`, `read_work_markdown`, `append_work_markdown`): user-facing notes in the Work UI - prefer these for write-ups the human will edit alongside the session.

## Tools: how you must call them
You do **not** run Python, shell, or HTTP from here. Ghidra and the Work UI change only when **the host executes a tool** after you issue a proper tool call. Explaining what you "would" do in chat **does nothing** unless a matching tool actually runs.

__TOOL_PROTOCOL__

### Before you call - 5-second checklist
- Is this tool name spelled **exactly** as in the tools list?
- Does `input` include **every required** key for that schema?
- Are addresses **JSON strings** (quoted)? Are counts like `length` **JSON numbers** (unquoted)?
- For `search_bytes`, is `pattern` several **two-digit hex tokens separated by spaces**?
- If the next step needs a value from a prior tool, did you **wait** for that `tool_result` first?

### Examples (same logical `name` + `input` you must supply)
- List functions (first window): `name` = `list_functions`, `input` = `{\"limit\": 200, \"offset\": 0}` (still valid: `input` = `{}` for full list when small).
- Decompile: `name` = `decompile_function`, `input` = {\"address\": \"004012a0\"}.
- Disassembly with limit: `name` = `get_disassembly`, `input` = {\"address\": \"004012a0\", \"length\": 48}.
- You may combine independent calls in **one** assistant message (e.g. `get_imports` + `get_entry_points`, each its own `tool_use` block).
- When you want **one** `tool_use` block that still runs several tools, use **`batch_run_tools`**: `input` = `{\"calls\": [{\"name\": \"…\", \"input\": {…}}, …]}` (max 24 calls, no nested `batch_run_tools`). The host returns one JSON object with per-call results.

### Frequent mistakes (avoid these)
- Answering the user with a long analysis **without** having issued the `tool_use` that would have produced the underlying facts.
- Putting the JSON arguments only inside a Markdown **code fence** in `text` - the runtime does **not** scrape code fences as tools.
- Using keys your intuition likes (`addr`, `fn`, `file`) instead of the schema's keys (`address`, `path`, …).
- Passing `length` or `max_chars` as quoted strings - use numbers.
- Calling `run_auto_analysis` with invented keys - its `input` is always `{}`.

### After tools run
- Read **`tool_result`** content from the latest user message. You may add brief `text` in the same turn as tools, but **do not** pretend you already have tool output before it appears.

### Tools with no parameters (always pass `input`: `{}`)
- **`run_auto_analysis`**: Re-run auto-analysis on the program already open in Ghidra.
- **`analysis_batch_status`**: Read the File-dock batch queue (`items` has per-row `index`, `basename`, `path`; also `next_index`, `next_path`, `count`).
- **`analysis_batch_open_next`**: Import and analyze the file at `next_index`, then advance the queue cursor (same as UI Open next).
- **`get_exports`**: Export-like symbols for this image (may be simplified).
- **`get_entry_points`**: Program entry symbols.
- **`list_work_notes`**: List Markdown files in the Work dock folder.

### Tools with parameters (name, purpose, `input` keys)
- **`list_functions`**: Function names and entry addresses. `input`: optional `limit`, `offset`, `name_contains` (see schema). Prefer a limit on large programs.
- **`get_strings`**: String literals. `input`: optional `limit`, `offset` (see schema).
- **`get_imports`**: Import table. `input`: optional `limit`, `offset`.
- **`open_file`**: Import from disk; optional `run_auto_analysis` (boolean, default true). `input`: `path` (string). If false, call `run_auto_analysis` separately when ready.
- **`analysis_batch_open_index`**: Open batch queue item by index. `input`: `index` (integer).
- **`decompile_function`**: Decompiler output for one function. `input`: `address` (string, function entry).
- **`get_disassembly`**: Linear instructions from an address. `input`: `address` (string); optional `length` (integer, max instructions, default if omitted).
- **`navigate_to`**: Move the UI cursor/listing to an address. `input`: `address` (string).
- **`get_xrefs_to`**: References pointing **to** an address. `input`: `address` (string).
- **`get_xrefs_from`**: References going **out from** an address. `input`: `address` (string).
- **`rename_function`**: Persist a new function name. `input`: `address` (string), `new_name` (string).
- **`rename_variable`**: Rename a decompiler local. `input`: `function_address`, `old_name`, `new_name` (strings).
- **`set_comment`**: EOL comment in the database. `input`: `address` (string), `text` (string).
- **`search_bytes`**: First match of a fixed byte pattern from image min address. `input`: `pattern` (string): exact **space-separated** hex pairs only, e.g. `48 89 E5` - **no** wildcards.
- **`get_data_at`**: What Ghidra has at an address (data vs code). `input`: `address` (string).
- **`create_struct`**: Apply/create struct layout text at an address. `input`: `address`, `struct_definition` (strings); may be unsupported in some builds - check result JSON.
- **`set_function_signature`**: Set C-like prototype. `input`: `address`, `signature` (strings); may be unsupported - check result JSON.
- **`get_control_flow_graph`**: CFG metadata for a function. `input`: `address` (string).
- **`read_work_markdown`**: Read one Work-dock note. `input`: `filename` and/or `note` (string); optional `max_chars` (integer).
- **`append_work_markdown`**: Append to a Work-dock note. `input`: `markdown` (string, required); optional `tab_title` (string).
- **`read_agent_memory`**: Read persistent agent memory file. `input`: optional `max_chars` (integer) only; `{}` is valid.
- **`append_agent_memory`**: Append durable session facts to persistent memory. `input`: `markdown` (string, required).
- **`web_search`**: Read-only web lookup (DuckDuckGo instant-answer style). `input`: `query` (string, required); optional `max_results` (integer 1–12); optional `fetch_primary_excerpt` (boolean, slower). Use for docs/CVEs/vendor context; verify against primary sources.
- **`batch_run_tools`**: Run multiple tools in one host step. `input`: `calls` (array of `{name, input}`). Max 24; do not nest another `batch_run_tools`.
- **`user_tip`**: Short UI tip for the user. `input`: `message` (string, required); use sparingly.

### Policy reminders
- **`open_file`**: new path on disk; defaults to full auto-analysis unless `run_auto_analysis` is false. Not for "refresh the listing" of an already loaded program.
- **`run_auto_analysis`**: only the loaded program; if the user asks to analyze/re-analyze you **must** call this or `open_file`, never only describe doing so.
- **`navigate_to`**: UI only; does not change analysis.
- **`user_tip`**: rare UX hints - not where normal analysis belongs.

## Communication
- Keep tool arguments minimal and valid per each tool's schema; when unsure, read the tool's `description` and `input_schema` in the tool list.
- State uncertainty and alternatives when decompilation or types are wrong or incomplete - that is normal in RE.
- If a tool returns an error JSON, acknowledge it and recover (fix args, try another path, or ask the user).
""".strip()

        # Build tools list with cache_control on the last entry (caches tools + system together).
        tools_raw = anthropic_tool_list(self._on_navigate, self._batch_port)
        if tools_raw:
            tools_cached = list(tools_raw)
            last_tool = dict(tools_cached[-1])
            last_tool["cache_control"] = {"type": "ephemeral"}
            tools_cached[-1] = last_tool
        else:
            tools_cached = tools_raw

        # Build system as list with cache_control; inject goal as prefix to keep the base cacheable.
        # Tool-call mechanics differ per API, so the provider supplies that section.
        # Plain replace, not str.format: the prompt is full of literal JSON braces.
        system = system.replace("__TOOL_PROTOCOL__", self._provider.tool_protocol_prompt)
        system_text = system
        if goal:
            system_text = system + f"\n\nPinned goal: {goal}"
        system_for_api: list[dict[str, Any]] = [
            {"type": "text", "text": system_text, "cache_control": {"type": "ephemeral"}}
        ]

        for _ in range(self._max_turns):
            if self._interrupt.is_set():
                self._emit("agent_stopped", {"reason": "interrupt"})
                return

            try:
                result = self._provider.run_turn(
                    system=system_for_api,
                    messages=self._memory.for_api(),
                    tools=tools_cached,
                    emit=self._emit,
                    should_abort=lambda: self._interrupt.is_set(),
                )
            except ProviderInterrupted:
                self._emit("agent_stopped", {"reason": "interrupt"})
                return
            except Exception as e:
                logger.exception("%s request failed", self._provider.id)
                self._emit("agent_error", {"message": str(e)})
                return

            if result is None:
                if self._interrupt.is_set():
                    self._emit("agent_stopped", {"reason": "interrupt"})
                else:
                    self._emit(
                        "agent_error",
                        {"message": "Incomplete response (stream ended without a message)."},
                    )
                return

            blocks_out = list(result.assistant_blocks)
            tool_result_blocks: list[dict[str, Any]] = []

            for call in result.tool_calls:
                self._emit("tool_call", {"id": call.id, "name": call.name, "input": call.input})
                if self._interrupt.is_set():
                    output = json.dumps({"error": "interrupted_before_tool"})
                else:
                    try:
                        output = run_tool(
                            call.name,
                            call.input,
                            self._ghidra,
                            self._on_navigate,
                            self._emit,
                            self._batch_port,
                        )
                    except Exception as e:
                        logger.exception("Tool %s failed", call.name)
                        output = json.dumps({"error": str(e)})
                cap = _tool_result_preview_cap(call.name)
                preview = output if len(output) < cap else output[:cap] + "..."
                self._emit("tool_result", {"id": call.id, "name": call.name, "preview": preview})
                tool_result_blocks.append(
                    {"type": "tool_result", "tool_use_id": call.id, "content": output}
                )

            # Thinking blocks must precede tool_use in history when continuing with tool
            # results (Anthropic requires signed thinking blocks for multi-turn continuity).
            if tool_result_blocks and result.thinking_blocks:
                blocks_out = result.thinking_blocks + blocks_out

            if blocks_out:
                self._memory.add_assistant_blocks(blocks_out)

            if tool_result_blocks:
                self._memory.add_tool_results(tool_result_blocks)
                continue

            self._emit("agent_done", {"stop_reason": result.stop_reason})
            return

        self._emit("agent_stopped", {"reason": "max_turns"})
