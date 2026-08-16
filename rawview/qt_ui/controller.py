"""Qt-facing controller: Ghidra bridge, GhidraAPI, optional agent; UI talks only here."""

from __future__ import annotations

import json
import logging
import tempfile
import threading
import time
from datetime import datetime
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, Signal

from rawview.agent.anthropic_backoff import AnthropicBackoffInterrupted
from rawview.agent.brain import AgentBrain
from rawview.agent.tools import AgentBatchToolPort
from rawview.agent.conversation_summarize import (
    flatten_messages_for_summary,
    summarize_conversation_transcript,
)
from rawview.agent.memory import ConversationMemory
from rawview.agent.providers import ProviderError, build_provider, preset_by_id
from rawview.config import Settings, load_settings, user_data_dir
from rawview.ghidra_bootstrap import is_valid_ghidra_root
from rawview.ghidra.api import GhidraAPI
from rawview.ghidra.bridge import (
    BridgeState,
    GhidraBridgeController,
    MissingJavaError,
    default_java_executable,
)

logger = logging.getLogger(__name__)


def _bridge_restart_fingerprint(s: Settings) -> tuple[object, ...]:
    """Settings that require restarting the Ghidra JVM when changed."""
    gid = s.ghidra_install_dir
    jcd = s.rawview_java_classes_dir
    return (
        str(gid.resolve()) if gid is not None else "",
        str(s.java_executable).strip().lower(),
        str(s.ghidra_jvm_max_heap).strip().lower(),
        int(s.py4j_port),
        str(s.rawview_project_dir.resolve()),
        str(jcd.resolve()) if jcd is not None else "",
        (s.rawview_java_classpath or "").strip(),
    )


class RawViewQtController(QObject):
    """Signals are emitted from worker threads where noted; Qt queues them to the GUI thread."""

    status_message = Signal(str)
    ghidra_analysis_begin = Signal()
    ghidra_analysis_end = Signal()
    bridge_state_changed = Signal(str)
    program_changed = Signal(str)  # program name or ""
    functions_updated = Signal(list)  # list[dict]
    decompiler_text = Signal(str)
    disassembly_text = Signal(str)
    hex_dump_text = Signal(str)
    strings_updated = Signal(list)
    imports_updated = Signal(list)
    exports_updated = Signal(list)
    symbols_updated = Signal(list)
    xrefs_updated = Signal(list)
    log_line = Signal(str)
    current_address_changed = Signal(str)
    agent_event = Signal(str, object)  # kind, dict (includes tool-driven "ghidra_shell_refresh")
    ghidra_task_failed = Signal(str)
    cfg_graph_updated = Signal(object)  # dict from get_control_flow_graph
    bridge_prewarm_finished = Signal(bool, str)  # ok, message (NO_GHIDRA / BAD_GHIDRA / ...)
    session_restore_hints = Signal(object)  # dict: hex_dump_size, hex_dump_bpl (optional current_address)
    analysis_batch_changed = Signal(object)  # dict: paths, next_index, count, loaded_program

    def __init__(self, *, no_agent: bool = False) -> None:
        super().__init__()
        self._no_agent = bool(no_agent)
        self.settings: Settings = load_settings()
        self._bridge: GhidraBridgeController | None = None
        self._api: GhidraAPI | None = None
        self._functions_cache: list[dict[str, str]] = []
        self._current_address: str = ""
        self._hex_dump_size: int = 4096
        self._hex_dump_bpl: int = 16
        self.agent_memory = ConversationMemory(max_messages=self.settings.agent_history_messages)
        self._brain: AgentBrain | None = None
        self._agent_thread: threading.Thread | None = None
        self._agent_start_lock = threading.Lock()
        self._agent_stop_event = threading.Event()
        self._active_program: str = ""
        self._re_autosave_lock = threading.Lock()
        self._batch_lock = threading.Lock()
        self._analysis_batch_paths: list[str] = []
        self._analysis_batch_next_index: int = 0

    @property
    def agent_enabled(self) -> bool:
        return not self._no_agent

    def reload_settings(self) -> None:
        """Reload .env / user settings after the Settings dialog saves."""
        old_fp = _bridge_restart_fingerprint(self.settings)
        self.settings = load_settings()
        if _bridge_restart_fingerprint(self.settings) != old_fp:
            self.shutdown_bridge()
        if self.agent_enabled:
            self.agent_memory = ConversationMemory(max_messages=self.settings.agent_history_messages)

    def prewarm_bridge_if_enabled(self) -> None:
        """Start Ghidra JVM on startup when configured (runs in a background thread)."""

        def work() -> None:
            try:
                if not self.settings.rawview_auto_start_bridge:
                    self.bridge_prewarm_finished.emit(True, "AUTO_START_OFF")
                    return
                gd = self.settings.ghidra_install_dir
                if gd is None:
                    self.bridge_prewarm_finished.emit(False, "NO_GHIDRA")
                    return
                if not is_valid_ghidra_root(Path(gd)):
                    self.bridge_prewarm_finished.emit(False, "BAD_GHIDRA")
                    return
                self._ensure_bridge()
                self.bridge_prewarm_finished.emit(True, "READY")
            except MissingJavaError:
                self.bridge_prewarm_finished.emit(False, "NO_JAVA")
            except Exception as e:
                logger.exception("prewarm")
                self.bridge_prewarm_finished.emit(False, str(e))

        threading.Thread(target=work, name="rawview-prewarm", daemon=True).start()

    @property
    def api(self) -> GhidraAPI | None:
        return self._api

    @property
    def current_address(self) -> str:
        return self._current_address

    def has_anthropic_key(self) -> bool:
        return bool(self.settings.anthropic_api_key.strip())

    def agent_credentials_error(self) -> str:
        """Empty string when the configured provider is usable, else the reason.

        Local backends legitimately need no key at all, so this must not assume an
        Anthropic key is required.
        """
        preset = preset_by_id(self.settings.llm_provider)
        if preset.kind == "anthropic":
            if not self.settings.anthropic_api_key.strip():
                return "Set ANTHROPIC_API_KEY in File → Settings."
            return ""
        if preset.requires_key and not self.settings.llm_api_key.strip():
            return f"{preset.label} needs an API key. Set it in File → Settings."
        if not (self.settings.llm_base_url.strip() or preset.base_url):
            return f"{preset.label} needs a base URL. Set it in File → Settings."
        if not (self.settings.llm_model.strip() or preset.suggested_model):
            return f"{preset.label} needs a model id. Set it in File → Settings."
        return ""

    def analysis_progress_file(self) -> Path:
        """JSON snapshot written by Ghidra during auto-analysis (see AnalysisProgressMonitor.java)."""
        return self.settings.rawview_project_dir / ".rawview_analysis_progress.json"

    def bridge_state(self) -> BridgeState:
        if self._bridge is None:
            return BridgeState.STOPPED
        return self._bridge.state

    def _ensure_bridge(self) -> None:
        if self._bridge is not None and self._bridge.state == BridgeState.READY:
            return
        gdir = self.settings.ghidra_install_dir
        if gdir is None:
            raise RuntimeError(
                "Ghidra install directory is not set. Use File → Settings or set GHIDRA_INSTALL_DIR."
            )
        self.settings.rawview_project_dir.mkdir(parents=True, exist_ok=True)
        self._bridge = GhidraBridgeController(
            ghidra_install_dir=gdir,
            java_executable=default_java_executable(
                self.settings.java_executable,
                ghidra_install_dir=gdir,
            ),
            jvm_max_heap=self.settings.ghidra_jvm_max_heap,
            py4j_port=self.settings.py4j_port,
            project_dir=self.settings.rawview_project_dir,
            java_classes_dir=self.settings.rawview_java_classes_dir,
            raw_classpath=self.settings.rawview_java_classpath,
        )
        self.status_message.emit("Starting Ghidra JVM...")
        self.bridge_state_changed.emit(BridgeState.STARTING.value)
        self._bridge.start()
        self._api = GhidraAPI(bridge=self._bridge)
        self.bridge_state_changed.emit(BridgeState.READY.value)
        self.status_message.emit("Ghidra bridge ready.")

    def shutdown_bridge(self) -> None:
        if self._bridge is not None:
            try:
                self._bridge.stop()
            except Exception:
                logger.debug("bridge stop", exc_info=True)
            self._bridge = None
            self._api = None
        self._active_program = ""
        self.bridge_state_changed.emit(BridgeState.STOPPED.value)

    def navigate_to_address(self, address: str) -> None:
        self._current_address = address.strip()
        self.current_address_changed.emit(self._current_address)
        self._refresh_views_for_address(self._current_address)

    def _pick_initial_navigation_address(self, rows: list[dict[str, str]]) -> str:
        """Best address to show listing + decompiler after load/analyze (often user saw no output before)."""
        if self._api is None:
            return ""
        for r in rows:
            a = (r.get("address") or "").strip()
            if a:
                return a
        try:
            for e in self._api.get_entry_points():
                a = (e.get("address") or "").strip()
                if a:
                    return a
        except Exception:
            logger.debug("get_entry_points for initial navigation", exc_info=True)
        try:
            for x in self._api.get_exports():
                a = (x.get("address") or "").strip()
                if a:
                    return a
        except Exception:
            logger.debug("get_exports for initial navigation", exc_info=True)
        try:
            return self._api.get_image_base_address()
        except Exception:
            logger.debug("get_image_base_address", exc_info=True)
        return ""

    def _refresh_views_for_address(self, address: str) -> None:
        if not address or self._api is None:
            return

        def work() -> None:
            try:
                listing = self._api.get_disassembly(address, 80)
                self.disassembly_text.emit(listing)
                try:
                    hx = self._api.get_hex_dump(address, self._hex_dump_size, self._hex_dump_bpl)
                except Exception:
                    logger.debug("hex dump", exc_info=True)
                    hx = (
                        "# Hex dump failed (rebuild Java bridge if this persists):\n"
                        "#   python -m rawview.scripts.compile_java\n"
                    )
                self.hex_dump_text.emit(hx)
                text = self._api.decompile_function(address)
                self.decompiler_text.emit(text)
                xr = self._api.get_xrefs_to(address)
                self.xrefs_updated.emit(xr)
            except Exception as e:
                logger.exception("refresh views")
                self.ghidra_task_failed.emit(str(e))

        threading.Thread(target=work, name="rawview-ghidra-ui", daemon=True).start()

    def set_hex_view_options(self, max_bytes: int, bytes_per_line: int) -> None:
        self._hex_dump_size = max(64, min(int(max_bytes), 65536))
        self._hex_dump_bpl = max(1, min(int(bytes_per_line), 64))

    def refresh_hex_view(self) -> None:
        """Reload hex only (respects :attr:`_hex_dump_size` / :attr:`_hex_dump_bpl`)."""
        addr = self._current_address.strip()
        if not addr or self._api is None:
            self.hex_dump_text.emit("")
            return

        def work() -> None:
            try:
                assert self._api is not None
                hx = self._api.get_hex_dump(addr, self._hex_dump_size, self._hex_dump_bpl)
                self.hex_dump_text.emit(hx)
            except Exception as e:
                logger.exception("hex refresh")
                self.ghidra_task_failed.emit(str(e))

        threading.Thread(target=work, name="rawview-hex-refresh", daemon=True).start()

    def advance_program_address(self, address: str, delta_bytes: int) -> str:
        if self._api is None:
            return ""
        try:
            return self._api.advance_program_address(address, int(delta_bytes))
        except Exception as e:
            logger.warning("advance_program_address: %s", e)
            return ""

    def open_binary(self, path: str, *, after_success: Callable[[], None] | None = None) -> None:
        if not (path or "").strip():
            self.status_message.emit("The file path cannot be empty.")
            return

        def work() -> None:
            try:
                self._ensure_bridge()
                assert self._api is not None
                self.status_message.emit(f"Opening {path}...")
                name = self._api.open_file(path)
                rows = self._api.list_functions()
                self._functions_cache = rows
                self._active_program = str(name or "").strip()
                self.program_changed.emit(name)
                self.functions_updated.emit(rows)
                self._refresh_tables()
                start = self._pick_initial_navigation_address(rows)
                if start:
                    self.navigate_to_address(start)
                    self.status_message.emit(
                        f"Imported: {name}. Run auto-analysis when you want Ghidra to finish full analysis."
                    )
                else:
                    self.status_message.emit(
                        f"Imported: {name} -  no address to show yet; run auto-analysis or enter an address."
                    )
                if after_success is not None:
                    after_success()
            except Exception as e:
                logger.exception("open_binary")
                self._active_program = ""
                self.ghidra_task_failed.emit(str(e))
                self.status_message.emit("Open failed.")

        threading.Thread(target=work, name="rawview-open", daemon=True).start()

    def _analysis_batch_emit_changed(self) -> None:
        self.analysis_batch_changed.emit(self.analysis_batch_snapshot())

    def analysis_batch_snapshot(self) -> dict[str, Any]:
        with self._batch_lock:
            return {
                "paths": list(self._analysis_batch_paths),
                "next_index": int(self._analysis_batch_next_index),
                "count": len(self._analysis_batch_paths),
                "loaded_program": str(self._active_program or ""),
            }

    def set_analysis_batch(self, paths: list[str]) -> None:
        cleaned: list[str] = []
        for p in paths:
            if not (p or "").strip():
                continue
            try:
                cleaned.append(str(Path(p).resolve()))
            except OSError:
                cleaned.append(str(Path(p).absolute()))
        with self._batch_lock:
            self._analysis_batch_paths = cleaned
            self._analysis_batch_next_index = 0
        self.status_message.emit(f"Batch analysis queue: {len(cleaned)} file(s).")
        self._analysis_batch_emit_changed()

    def clear_analysis_batch(self) -> None:
        with self._batch_lock:
            self._analysis_batch_paths = []
            self._analysis_batch_next_index = 0
        self.status_message.emit("Batch analysis queue cleared.")
        self._analysis_batch_emit_changed()

    def open_analysis_batch_next(self) -> None:
        with self._batch_lock:
            if self._analysis_batch_next_index >= len(self._analysis_batch_paths):
                self.status_message.emit("Batch queue: no more files (or queue is empty).")
                return
            path = self._analysis_batch_paths[self._analysis_batch_next_index]
            idx = self._analysis_batch_next_index

        def bump() -> None:
            with self._batch_lock:
                self._analysis_batch_next_index = idx + 1
            self._analysis_batch_emit_changed()

        self.open_binary(path, after_success=bump)

    def open_analysis_batch_at(self, index: int) -> None:
        """Open the queued binary at ``index`` and set the next cursor to ``index + 1`` (same as Open next, but explicit)."""
        with self._batch_lock:
            if index < 0 or index >= len(self._analysis_batch_paths):
                self.status_message.emit("Batch queue: nothing at that index (or queue is empty).")
                return
            path = self._analysis_batch_paths[index]
            idx = index

        def bump() -> None:
            with self._batch_lock:
                self._analysis_batch_next_index = idx + 1
            self._analysis_batch_emit_changed()

        self.open_binary(path, after_success=bump)

    def pinned_goal_for_analysis_batch(self) -> str | None:
        with self._batch_lock:
            if not self._analysis_batch_paths:
                return None
            n = len(self._analysis_batch_paths)
            i = int(self._analysis_batch_next_index)
            samples = [Path(p).name for p in self._analysis_batch_paths[:3]]
            tail = f" (+{n - 3} more)" if n > 3 else ""
            return (
                f"Batch analysis: {n} queued binary path(s); next queue index is {i}. "
                f"First names: {', '.join(samples)}{tail}. "
                "Only one Ghidra program is loaded at a time; use analysis_batch_status (see `items` for index/path) "
                "then analysis_batch_open_next or analysis_batch_open_index to load; use list_functions with limit when mapping."
            )

    def agent_batch_status_json(self) -> str:
        snap = self.analysis_batch_snapshot()
        paths = snap["paths"]
        basenames = [Path(p).name for p in paths]
        next_i = snap["next_index"]
        next_path: str | None = None
        if 0 <= next_i < len(paths):
            next_path = paths[next_i]
        items = [{"index": i, "basename": Path(p).name, "path": p} for i, p in enumerate(paths)]
        return json.dumps(
            {
                "basenames": basenames,
                "items": items,
                "next_index": next_i,
                "count": snap["count"],
                "loaded_program": snap["loaded_program"],
                "next_path": next_path,
            }
        )

    def agent_batch_open_index(self, index: int, api: GhidraAPI, emit_fn: Callable[[str, dict[str, Any]], None]) -> str:
        with self._batch_lock:
            if index < 0 or index >= len(self._analysis_batch_paths):
                return json.dumps({"error": "index_out_of_range", "index": index, "count": len(self._analysis_batch_paths)})
            path = self._analysis_batch_paths[index]
        try:
            name = api.open_file(path)
            api.run_auto_analysis()
            if emit_fn is not None:
                emit_fn("ghidra_shell_refresh", {"program": name})
            with self._batch_lock:
                self._analysis_batch_next_index = index + 1
            self._analysis_batch_emit_changed()
            return json.dumps({"ok": True, "program": name, "path": path, "index": index, "next_index": index + 1})
        except Exception as e:
            logger.exception("agent_batch_open_index")
            return json.dumps({"error": str(e), "path": path, "index": index})

    def agent_batch_open_next(self, api: GhidraAPI, emit_fn: Callable[[str, dict[str, Any]], None]) -> str:
        with self._batch_lock:
            if self._analysis_batch_next_index >= len(self._analysis_batch_paths):
                return json.dumps(
                    {"error": "batch_queue_empty_or_finished", "next_index": self._analysis_batch_next_index, "count": len(self._analysis_batch_paths)}
                )
            idx = self._analysis_batch_next_index
        return self.agent_batch_open_index(idx, api, emit_fn)

    def run_auto_analysis(self) -> None:
        def work() -> None:
            try:
                self._ensure_bridge()
                assert self._api is not None
                self.status_message.emit("Auto-analysis running...")
                self.ghidra_analysis_begin.emit()
                try:
                    self._api.run_auto_analysis()
                finally:
                    self.ghidra_analysis_end.emit()
                rows = self._api.list_functions()
                self._functions_cache = rows
                self.functions_updated.emit(rows)
                self._refresh_tables()
                if self._current_address.strip():
                    self._refresh_views_for_address(self._current_address)
                else:
                    start = self._pick_initial_navigation_address(rows)
                    if start:
                        self.navigate_to_address(start)
                self.status_message.emit("Auto-analysis complete.")
            except Exception as e:
                logger.exception("auto_analysis")
                self.ghidra_task_failed.emit(str(e))

        threading.Thread(target=work, name="rawview-analyze", daemon=True).start()

    def _refresh_tables(self) -> None:
        if self._api is None:
            return

        def work() -> None:
            try:
                assert self._api is not None
                self.strings_updated.emit(self._api.get_strings())
                self.imports_updated.emit(self._api.get_imports())
                self.exports_updated.emit(self._api.get_exports())
                self.symbols_updated.emit(self._api.get_symbols()[:500])
            except Exception as e:
                logger.exception("refresh tables")
                self.ghidra_task_failed.emit(str(e))

        threading.Thread(target=work, name="rawview-tables", daemon=True).start()

    def filter_functions(self, query: str) -> None:
        q = query.strip().lower()
        if not q:
            self.functions_updated.emit(list(self._functions_cache))
            return
        rows = [r for r in self._functions_cache if q in r.get("name", "").lower()]
        self.functions_updated.emit(rows)

    def interrupt_agent(self) -> None:
        if not self.agent_enabled:
            return
        self._agent_stop_event.set()
        if self._brain is not None:
            self._brain.interrupt()

    def schedule_ghidra_shell_refresh(self, program_name: str | None) -> None:
        """Refresh function list, tables, and listing/decompiler after agent tools change the program."""

        def work() -> None:
            try:
                if self._api is None:
                    return
                rows = self._api.list_functions()
                self._functions_cache = rows
                pn = (program_name or "").strip()
                if pn:
                    self._active_program = pn
                    self.program_changed.emit(pn)
                self.functions_updated.emit(rows)
                self.strings_updated.emit(self._api.get_strings())
                self.imports_updated.emit(self._api.get_imports())
                self.exports_updated.emit(self._api.get_exports())
                self.symbols_updated.emit(self._api.get_symbols()[:500])
                addr = self._current_address.strip()
                if addr:
                    self._refresh_views_for_address(addr)
                else:
                    start = self._pick_initial_navigation_address(rows)
                    if start:
                        self.navigate_to_address(start)
            except Exception as e:
                logger.exception("ghidra shell refresh")
                self.ghidra_task_failed.emit(str(e))

        threading.Thread(target=work, name="rawview-agent-shell-refresh", daemon=True).start()

    def send_agent_prompt(self, text: str, images: list[dict] | None = None) -> None:
        if not self.agent_enabled:
            return
        text = text.strip()
        if not text and not images:
            return
        low = text.lower()
        if low == "/summarize" or low.startswith("/summarize "):
            cred_err = self.agent_credentials_error()
            if cred_err:
                self.agent_event.emit("agent_error", {"message": cred_err})
                return
            self._start_summarize_bootstrap()
            return
        cred_err = self.agent_credentials_error()
        if cred_err:
            self.agent_event.emit("agent_error", {"message": cred_err})
            return

        is_new_chat = not self.agent_memory.is_nonempty()

        def start() -> None:
            def emit(kind: str, data: dict[str, Any]) -> None:
                self.agent_event.emit(kind, data)

            with self._agent_start_lock:
                t = self._agent_thread
                if t is not None and t.is_alive():
                    self.agent_event.emit(
                        "agent_error",
                        {
                            "message": "The agent is still running. Wait for it to finish or press Stop before sending another prompt.",
                        },
                    )
                    return
                try:
                    self._ensure_bridge()
                    assert self._api is not None
                except Exception as e:
                    self.agent_event.emit("agent_error", {"message": str(e)})
                    return
                batch_port = AgentBatchToolPort(
                    status_json=self.agent_batch_status_json,
                    open_index_json=self.agent_batch_open_index,
                    open_next_json=self.agent_batch_open_next,
                )
                goal = self.pinned_goal_for_analysis_batch()
                try:
                    provider = build_provider(self.settings)
                except ProviderError as e:
                    emit("agent_error", {"message": str(e)})
                    return
                self._brain = AgentBrain(
                    provider=provider,
                    ghidra_api=self._api,
                    memory=self.agent_memory,
                    max_turns=self.settings.agent_max_turns,
                    on_navigate=self.navigate_to_address,
                    emit=emit,
                    batch_port=batch_port,
                )
                if self._agent_stop_event.is_set():
                    self._brain.interrupt()

                brain_ref = self._brain

                def run() -> None:
                    emit("agent_generating", {"active": True})
                    try:
                        try:
                            assert brain_ref is not None
                            brain_ref.run_user_prompt(text, goal=goal, images=images or None)
                        except Exception as e:
                            logger.exception("agent")
                            self.agent_event.emit(
                                "agent_error",
                                {"message": str(e), "trace": traceback.format_exc()},
                            )
                    finally:
                        self._agent_stop_event.clear()
                        emit("agent_generating", {"active": False})

                self._agent_thread = threading.Thread(target=run, name="rawview-agent", daemon=True)
                self._agent_thread.start()

                # Generate chat title via Haiku after first message (non-blocking).
                if is_new_chat and text.strip():
                    title_text = text
                    b = brain_ref

                    def _gen_title() -> None:
                        title = b.generate_chat_title(title_text)
                        if title:
                            self.agent_event.emit("chat_title", {"title": title})

                    threading.Thread(target=_gen_title, name="rawview-title-gen", daemon=True).start()

        threading.Thread(target=start, name="rawview-agent-bootstrap", daemon=True).start()

    def _start_summarize_bootstrap(self) -> None:
        """Compress agent_memory with a side API call (/summarize). Uses _agent_thread slot so agent cannot overlap."""
        if not self.agent_enabled:
            return

        def start() -> None:
            def emit(kind: str, data: dict[str, Any]) -> None:
                self.agent_event.emit(kind, data)

            with self._agent_start_lock:
                t = self._agent_thread
                if t is not None and t.is_alive():
                    self.agent_event.emit(
                        "agent_error",
                        {
                            "message": "Wait for the agent (or a running /summarize) to finish before sending again.",
                        },
                    )
                    return

                def run() -> None:
                    emit("agent_generating", {"active": True})
                    try:
                        try:
                            snap = list(self.agent_memory.for_api())
                            if not snap:
                                emit("agent_error", {"message": "Nothing to summarize yet - chat history is empty."})
                                return
                            transcript = flatten_messages_for_summary(snap)
                            if not transcript.strip():
                                emit("agent_error", {"message": "Nothing to summarize yet - chat history is empty."})
                                return
                            summary = summarize_conversation_transcript(
                                provider=build_provider(self.settings),
                                transcript=transcript,
                                emit=emit,
                                should_abort=lambda: self._agent_stop_event.is_set(),
                            )
                            before = len(snap)
                            before_chars = len(transcript)
                            self.agent_memory.clear()
                            self.agent_memory.add_user(
                                "[Session summary -  prior messages were compressed with /summarize to save context.]\n\n"
                                + summary
                            )
                            emit(
                                "conversation_summarized",
                                {
                                    "api_messages_before": before,
                                    "transcript_chars": before_chars,
                                    "summary_chars": len(summary),
                                },
                            )
                        except AnthropicBackoffInterrupted:
                            emit("agent_stopped", {"reason": "interrupt"})
                        except Exception as e:
                            logger.exception("summarize")
                            emit("agent_error", {"message": f"/summarize failed: {e}"})
                    finally:
                        self._agent_stop_event.clear()
                        emit("agent_generating", {"active": False})

                self._agent_thread = threading.Thread(target=run, name="rawview-summarize", daemon=True)
                self._agent_thread.start()

        threading.Thread(target=start, name="rawview-summarize-bootstrap", daemon=True).start()

    def agent_chats_dir(self) -> Path:
        d = user_data_dir() / "agent_chats"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def clear_agent_memory(self) -> None:
        self.agent_memory.clear()

    def save_agent_chat_archive(
        self,
        messages: list[dict[str, Any]],
        feed_html_chunks: list[str],
    ) -> Path | None:
        if not messages and not feed_html_chunks:
            return None
        ts = int(time.time())
        path = self.agent_chats_dir() / f"chat-{ts}.json"
        title = self._agent_chat_title(messages)
        payload: dict[str, Any] = {
            "version": 1,
            "saved_at": ts,
            "title": title,
            "messages": messages,
            "feed_html": feed_html_chunks,
        }
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
        return path

    @staticmethod
    def _agent_chat_title(messages: list[dict[str, Any]]) -> str:
        for m in messages:
            if m.get("role") == "user" and isinstance(m.get("content"), str):
                line = m["content"].strip().split("\n", 1)[0].strip()[:72]
                if line:
                    return line
        return "Chat"

    def list_agent_chat_archives(self) -> list[tuple[Path, str]]:
        out: list[tuple[Path, str]] = []
        d = self.agent_chats_dir()
        for p in sorted(d.glob("chat-*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                title = str(data.get("title", p.stem))
                st = int(data.get("saved_at", p.stat().st_mtime))
                label = f"{title}  ({datetime.fromtimestamp(st).strftime('%Y-%m-%d %H:%M')})"
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                label = p.stem
            out.append((p, label))
        return out

    def load_agent_chat_archive(self, path: Path) -> tuple[list[dict[str, Any]], list[str]]:
        raw = json.loads(path.read_text(encoding="utf-8"))
        messages = raw.get("messages") if isinstance(raw.get("messages"), list) else []
        feed = raw.get("feed_html") if isinstance(raw.get("feed_html"), list) else []
        messages = [m for m in messages if isinstance(m, dict)]
        feed_html = [str(h) for h in feed]
        return messages, feed_html

    def manual_rename_function(self, address: str, new_name: str) -> None:
        if self._api is None:
            self.status_message.emit("Load a binary first (Browse / Open), then run auto-analysis if needed.")
            return

        def work() -> None:
            try:
                res = self._api.rename_function(address, new_name)
                self.log_line.emit(json.dumps(res))
                rows = self._api.list_functions()
                self._functions_cache = rows
                self.functions_updated.emit(rows)
            except Exception as e:
                self.ghidra_task_failed.emit(str(e))

        threading.Thread(target=work, name="rawview-rename", daemon=True).start()

    def refresh_control_flow_graph(self) -> None:
        addr = self._current_address
        if not addr or self._api is None:
            self.cfg_graph_updated.emit({"note": "Select a function address first.", "nodes": [], "edges": []})
            return

        def work() -> None:
            try:
                assert self._api is not None
                self.cfg_graph_updated.emit(self._api.get_control_flow_graph(addr))
            except Exception as e:
                logger.exception("cfg")
                self.ghidra_task_failed.emit(str(e))

        threading.Thread(target=work, name="rawview-cfg", daemon=True).start()

    def apply_comment(self, address: str, text: str) -> None:
        if self._api is None:
            self.status_message.emit("Load a binary first (Browse / Open), then run auto-analysis if needed.")
            return

        def work() -> None:
            try:
                res = self._api.set_comment(address, text)
                self.log_line.emit(json.dumps(res))
            except Exception as e:
                self.ghidra_task_failed.emit(str(e))

        threading.Thread(target=work, name="rawview-comment", daemon=True).start()

    def collect_re_session_ui_hints(self) -> dict[str, Any]:
        """Caller (main thread) supplies UI fields not stored in Ghidra."""
        return {
            "current_address": self._current_address.strip(),
            "hex_dump_size": int(self._hex_dump_size),
            "hex_dump_bpl": int(self._hex_dump_bpl),
        }

    def save_re_session_archive(self, dest: Path) -> None:
        """Pack current Ghidra project + UI hints into a .rvre.zip (Work-dock notes are not included)."""

        def work() -> None:
            try:
                from rawview.re_session import (
                    build_session_manifest,
                    project_folder_from_re_meta,
                    zip_ghidra_project_folder,
                )

                self._ensure_bridge()
                assert self._api is not None
                self._api.flush_program_to_disk()
                meta = self._api.get_re_session_meta()
                if not meta.get("projectName"):
                    self.status_message.emit("Nothing to save: open a binary first.")
                    return
                folder = project_folder_from_re_meta(meta)
                ui = self.collect_re_session_ui_hints()
                manifest = build_session_manifest(java_meta=meta, ui=ui)
                zip_ghidra_project_folder(project_folder=folder, manifest=manifest, dest_zip=dest)
                self.status_message.emit(f"RE session saved ({dest.name}).")
            except Exception as e:
                logger.exception("save_re_session")
                msg = str(e).strip() or e.__class__.__name__
                self.ghidra_task_failed.emit(msg)
                self.status_message.emit(f"Save RE session failed: {msg[:240]}")

        threading.Thread(target=work, name="rawview-save-re", daemon=True).start()

    def load_re_session_archive(self, zip_path: Path) -> None:
        """Restore Ghidra project from a .rvre.zip created by RawView."""

        def work() -> None:
            extract_root: Path | None = None
            try:
                from rawview.re_session import (
                    extract_session_zip,
                    import_project_tree_into_parent,
                    remove_extract_root,
                )

                self._ensure_bridge()
                assert self._api is not None
                project_parent = self.settings.rawview_project_dir
                project_parent.mkdir(parents=True, exist_ok=True)
                extract_root, manifest = extract_session_zip(zip_path, Path(tempfile.gettempdir()))
                pname_dir = str(manifest.get("projectName", "")).strip()
                src_proj = extract_root / pname_dir
                new_name, _dest = import_project_tree_into_parent(
                    source_project_dir=src_proj,
                    project_parent=project_parent,
                    preferred_name=pname_dir or None,
                )
                pdom = str(manifest.get("programDomainName", "")).strip()
                if not pdom:
                    raise ValueError("Session manifest missing programDomainName")
                pfolder = str(manifest.get("programFolder", "/")).strip() or "/"
                name = self._api.open_saved_project(
                    str(project_parent.resolve()),
                    new_name,
                    pfolder,
                    pdom,
                )
                rows = self._api.list_functions()
                self._functions_cache = rows
                self._active_program = str(name or "").strip()
                self.program_changed.emit(name)
                self.functions_updated.emit(rows)
                self._refresh_tables()
                ui = manifest.get("ui") if isinstance(manifest.get("ui"), dict) else {}
                hints = {
                    "hex_dump_size": ui.get("hex_dump_size"),
                    "hex_dump_bpl": ui.get("hex_dump_bpl"),
                }
                self.session_restore_hints.emit(hints)
                addr = str(ui.get("current_address", "")).strip()
                if addr:
                    self.navigate_to_address(addr)
                else:
                    start = self._pick_initial_navigation_address(rows)
                    if start:
                        self.navigate_to_address(start)
                self.status_message.emit(f"RE session loaded ({new_name}).")
                from rawview.re_session import mark_re_recovery_clean

                mark_re_recovery_clean()
            except Exception as e:
                logger.exception("load_re_session")
                self.ghidra_task_failed.emit(str(e))
                self.status_message.emit("Load RE session failed.")
            finally:
                if extract_root is not None:
                    remove_extract_root(extract_root)

        threading.Thread(target=work, name="rawview-load-re", daemon=True).start()

    def tick_re_autosave(self) -> None:
        """Periodic crash snapshot (Ghidra DB + UI hints). Skips if idle or another save is running."""

        def work() -> None:
            if not self._active_program.strip():
                return
            if not self._re_autosave_lock.acquire(blocking=False):
                return
            try:
                from rawview.re_session import (
                    build_session_manifest,
                    mark_re_recovery_dirty,
                    project_folder_from_re_meta,
                    re_autosave_zip_path,
                    zip_ghidra_project_folder,
                )

                self._ensure_bridge()
                assert self._api is not None
                self._api.flush_program_to_disk()
                meta = self._api.get_re_session_meta()
                if not meta.get("projectName"):
                    return
                folder = project_folder_from_re_meta(meta)
                ui = self.collect_re_session_ui_hints()
                manifest = build_session_manifest(java_meta=meta, ui=ui)
                zip_ghidra_project_folder(
                    project_folder=folder,
                    manifest=manifest,
                    dest_zip=re_autosave_zip_path(),
                )
                mark_re_recovery_dirty()
            except Exception:
                logger.debug("re autosave", exc_info=True)
            finally:
                self._re_autosave_lock.release()

        threading.Thread(target=work, name="rawview-re-autosave", daemon=True).start()

    def mark_re_recovery_clean_shutdown(self) -> None:
        from rawview.re_session import mark_re_recovery_clean

        mark_re_recovery_clean()
