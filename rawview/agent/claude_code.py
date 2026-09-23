"""
Run the Agent dock on a local Claude Code (or Claude Desktop) subscription, no API key.

RawView's own agent loop (``AgentBrain`` + a provider) needs an Anthropic API key or a local
model. This is the third way: shell out to the ``claude`` CLI, which is already signed in to the
user's subscription, and let *it* run the loop. RawView's Ghidra tools are handed to it through the
``rawview`` MCP server we already ship, so Claude Code drives the same 48 tools the in-app agent
has, against the binary the user has open.

It does not implement :class:`LLMProvider`. A provider runs one turn and hands tool calls back to
the brain to execute; Claude Code runs the whole agent loop itself, so it sits beside the brain
rather than inside it. The controller branches to this when the provider is ``claude_code``.

Multi-turn works by resume, not by a long-lived pipe: each turn is one ``claude -p`` invocation,
and every turn after the first passes ``--resume <session_id>`` so Claude Code restores the full
conversation. That keeps process management trivial - Stop just kills the current process, and the
next message resumes where it left off - and avoids the stream-json input and interrupt-control
bookkeeping a persistent pipe would need.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

EmitFn = Callable[[str, dict[str, Any]], None]

# The MCP server name Claude Code registers our tools under, so tool events read "mcp__rawview__x".
_MCP_SERVER_NAME = "rawview"
_TOOL_PREFIX = f"mcp__{_MCP_SERVER_NAME}__"

# What the CLI is told about the job. Kept short: Claude Code already has a capable system prompt,
# and this only needs to set the stage and the house rules the in-app agent also follows.
_APPEND_SYSTEM_PROMPT = (
    "You are the RawView agent, embedded in a running RawView window (a Qt front end for the "
    "Ghidra reverse-engineering tool). The `rawview` MCP tools act on the binary the user has open "
    "right now, and navigation moves their actual view. When they say 'this function', 'here' or "
    "'the current address', call get_current_address or get_current_function rather than guessing. "
    "Prefer these tools over your own filesystem or shell tools; you are here to analyze the loaded "
    "program, not the user's machine. Tools that modify the program (rename_*, set_*, patch_bytes, "
    "assemble_instruction with apply, revert_patch) change the user's analysis database, and "
    "export_patched_file writes a file to disk - say what you are about to change before doing it. "
    "Keep answers focused and cite addresses and function names."
)


class ClaudeCodeUnavailable(RuntimeError):
    """The ``claude`` CLI is not installed, or RawView's MCP endpoint is off."""


def find_claude_cli(explicit: str = "") -> str:
    """Locate the ``claude`` executable, or "" if it cannot be found."""
    if explicit.strip():
        p = Path(explicit.strip())
        if p.is_file():
            return str(p)
    found = shutil.which("claude")
    if found:
        return found
    # npm global and the official installer both drop it in these spots before PATH is set up.
    for cand in (
        Path.home() / ".local/bin/claude",
        Path.home() / ".claude/local/claude",
        Path("/usr/local/bin/claude"),
        Path("/opt/homebrew/bin/claude"),
    ):
        if cand.is_file():
            return str(cand)
    return ""


def claude_code_available(explicit_path: str = "") -> bool:
    return bool(find_claude_cli(explicit_path))


class ClaudeCodeSession:
    """One Agent-dock conversation backed by the ``claude`` CLI.

    Reused across turns so ``--resume`` can carry the session. Not thread-safe: the controller runs
    exactly one turn at a time on its agent thread, the same as it does for the brain.
    """

    def __init__(
        self,
        *,
        claude_path: str,
        model: str = "",
        mcp_command: list[str] | None = None,
    ) -> None:
        self._claude = claude_path
        self._model = (model or "").strip()
        self._mcp_command = mcp_command or []
        self._session_id: str | None = None
        self._proc: subprocess.Popen[str] | None = None
        self._interrupt = threading.Event()
        self._mcp_config_path: Path | None = None
        # tool_use id -> friendly name, so a tool_result (which carries only the id) can be labelled.
        self._tool_names: dict[str, str] = {}

    # -- lifecycle --------------------------------------------------------------------

    @property
    def model(self) -> str:
        return self._model or "claude (subscription default)"

    def reset(self) -> None:
        """Forget the conversation so the next turn starts a fresh Claude Code session."""
        self._session_id = None
        self._tool_names.clear()

    def interrupt(self) -> None:
        self._interrupt.set()
        proc = self._proc
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                logger.debug("claude terminate", exc_info=True)

    def close(self) -> None:
        self.interrupt()
        if self._mcp_config_path is not None:
            try:
                self._mcp_config_path.unlink(missing_ok=True)
            except OSError:
                logger.debug("remove mcp config", exc_info=True)
            self._mcp_config_path = None

    # -- one turn ---------------------------------------------------------------------

    def run_turn(self, prompt: str, *, emit: EmitFn) -> None:
        """Run one user turn to completion, translating Claude Code's events to dock events."""
        self._interrupt.clear()
        self._thinking_accum = ""
        self._streaming_text = False
        argv = self._build_argv(prompt)
        logger.info("claude-code: %s", " ".join(argv[:6]) + " ...")
        try:
            self._proc = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except FileNotFoundError as e:
            raise ClaudeCodeUnavailable(
                f"Could not launch the claude CLI at {self._claude!r}: {e}"
            ) from e

        proc = self._proc
        assert proc.stdout is not None
        saw_result = False
        try:
            for line in proc.stdout:
                if self._interrupt.is_set():
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    # Non-JSON on stdout is unexpected in stream-json mode; surface it quietly.
                    logger.debug("claude-code non-json line: %s", line[:200])
                    continue
                if self._dispatch(event, emit):
                    saw_result = True
        finally:
            self._finish(proc, saw_result, emit)

    def _finish(self, proc: subprocess.Popen[str], saw_result: bool, emit: EmitFn) -> None:
        if self._interrupt.is_set():
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                logger.debug("claude terminate on interrupt", exc_info=True)
            # The controller emits the terminal event (agent_stopped) so it is not sent twice.
            self._proc = None
            return
        try:
            code = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.terminate()
            code = -1
        stderr = ""
        if proc.stderr is not None:
            stderr = proc.stderr.read() or ""
        self._proc = None
        if code != 0 and not saw_result:
            hint = stderr.strip().splitlines()[-1] if stderr.strip() else f"exit code {code}"
            emit(
                "agent_error",
                {"message": f"Claude Code exited without answering: {hint}"},
            )

    # -- argv -------------------------------------------------------------------------

    def _build_argv(self, prompt: str) -> list[str]:
        argv = [
            self._claude,
            "-p",
            prompt,
            "--output-format",
            "stream-json",
            "--include-partial-messages",  # token-by-token deltas, for a live feed
            "--verbose",  # stream-json needs this to emit per-message events
            "--append-system-prompt",
            _APPEND_SYSTEM_PROMPT,
            # Only our Ghidra tools are pre-approved; anything else prompts, and with no one to
            # answer in headless mode it is denied, so the agent stays scoped to the binary.
            "--allowedTools",
            f"{_TOOL_PREFIX}*",
            "--permission-prompts",
            "none",
        ]
        if self._model:
            argv += ["--model", self._model]
        if self._mcp_command:
            argv += ["--mcp-config", self._mcp_config_file(), "--strict-mcp-config"]
        if self._session_id:
            argv += ["--resume", self._session_id]
        return argv

    def _mcp_config_file(self) -> str:
        """Write (once) a Claude Code MCP config pointing at RawView's stdio server."""
        if self._mcp_config_path is not None and self._mcp_config_path.is_file():
            return str(self._mcp_config_path)
        command = self._mcp_command[0]
        args = self._mcp_command[1:]
        config = {"mcpServers": {_MCP_SERVER_NAME: {"command": command, "args": args, "env": {}}}}
        with tempfile.NamedTemporaryFile(
            "w", suffix=".mcp.json", prefix="rawview-cc-", delete=False, encoding="utf-8"
        ) as fd:
            json.dump(config, fd)
            path = Path(fd.name)
        self._mcp_config_path = path
        return str(path)

    # -- event translation ------------------------------------------------------------

    def _dispatch(self, event: dict[str, Any], emit: EmitFn) -> bool:
        """Map one Claude Code stream-json event to dock events. Returns True for the final result."""
        etype = str(event.get("type", ""))

        if etype == "system" and event.get("subtype") == "init":
            self._session_id = event.get("session_id") or self._session_id
            servers = event.get("mcp_servers") or []
            connected = any(
                str(s.get("name")) == _MCP_SERVER_NAME and str(s.get("status")) == "connected"
                for s in servers
                if isinstance(s, dict)
            )
            if not connected:
                emit(
                    "agent_notice",
                    {
                        "message": (
                            "Claude Code started but could not connect to RawView's tools. "
                            "Check that 'Allow MCP clients' is on in Settings."
                        )
                    },
                )
            return False

        if etype == "stream_event":
            self._handle_partial(event.get("event") or {}, emit)
            return False

        if etype == "assistant":
            self._handle_assistant(event.get("message") or {}, emit)
            return False

        if etype == "user":
            self._handle_tool_results(event.get("message") or {}, emit)
            return False

        if etype == "result":
            self._session_id = event.get("session_id") or self._session_id
            if event.get("is_error"):
                subtype = str(event.get("subtype", "error"))
                msg = str(event.get("result") or subtype)
                if subtype == "error_max_turns":
                    msg = "Claude Code hit its turn limit before finishing."
                emit("agent_error", {"message": msg})
            return True

        return False

    def _handle_partial(self, sse: dict[str, Any], emit: EmitFn) -> None:
        """A single SSE delta from --include-partial-messages: drives the live typing feed."""
        kind = str(sse.get("type", ""))
        if kind == "message_start":
            self._streaming_text = False
            return
        if kind == "content_block_start":
            block = sse.get("content_block") or {}
            if block.get("type") == "text":
                emit("assistant_stream_begin", {})
                self._streaming_text = True
            elif block.get("type") == "thinking":
                self._thinking_accum = ""
            return
        if kind == "content_block_delta":
            delta = sse.get("delta") or {}
            dtype = str(delta.get("type", ""))
            if dtype == "text_delta":
                emit("assistant_text_delta", {"text": str(delta.get("text", ""))})
            elif dtype == "thinking_delta":
                # Accumulate: the indicator should show the growing thought, not one lone chunk.
                self._thinking_accum += str(delta.get("thinking", ""))
                if self._thinking_accum.strip():
                    emit("assistant_thinking_live", {"text": self._thinking_accum})
            return
        if kind == "content_block_stop" and getattr(self, "_streaming_text", False):
            # The committed, markdown-rendered version arrives with the whole assistant message.
            self._streaming_text = False
            return

    def _handle_assistant(self, message: dict[str, Any], emit: EmitFn) -> None:
        for block in message.get("content") or []:
            if not isinstance(block, dict):
                continue
            btype = str(block.get("type", ""))
            if btype == "text":
                text = str(block.get("text", "")).strip()
                if text:
                    # Commit replaces the streamed plain text with formatted markdown.
                    emit("assistant_stream_commit", {"text": text, "source": "agent"})
            elif btype == "thinking":
                text = str(block.get("thinking", "")).strip()
                if text:
                    emit("assistant_thinking", {"text": text})
            elif btype == "tool_use":
                name = self._friendly_tool(str(block.get("name", "")))
                tid = str(block.get("id", ""))
                self._tool_names[tid] = name
                emit("tool_call", {"id": tid, "name": name, "input": block.get("input") or {}})

    def _handle_tool_results(self, message: dict[str, Any], emit: EmitFn) -> None:
        for block in message.get("content") or []:
            if not isinstance(block, dict) or block.get("type") != "tool_result":
                continue
            tid = str(block.get("tool_use_id", ""))
            name = self._tool_names.get(tid, "tool")
            emit("tool_result", {"name": name, "preview": _flatten_tool_result(block.get("content"))})

    @staticmethod
    def _friendly_tool(name: str) -> str:
        """``mcp__rawview__decompile_function`` -> ``decompile_function`` for the dock."""
        return name.removeprefix(_TOOL_PREFIX)


def _flatten_tool_result(content: Any) -> str:
    """Claude Code wraps tool output as a list of content blocks; the dock wants one string."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(str(block.get("text", "")))
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts)
    return json.dumps(content) if content is not None else ""
