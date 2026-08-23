from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rawview.agent.long_term_memory import append_agent_memory_text, agent_memory_path, read_agent_memory_text
from rawview.agent.web_search import perform_web_search
from rawview.ghidra.api import GhidraAPI

ToolHandler = Callable[[dict[str, Any], GhidraAPI, Callable[[str], None]], str]


def _work_notes_dir() -> Path:
    """Deferred import so `rawview.agent.tools` can load before Qt bootstrap (avoids circular imports)."""
    from rawview.qt_ui.work_dock import work_notes_dir

    return work_notes_dir()


@dataclass(frozen=True)
class AgentBatchToolPort:
    """Host callbacks so batch-analysis tools can read the UI queue without global state."""

    status_json: Callable[[], str]
    open_index_json: Callable[[int, GhidraAPI, Callable[[str, dict[str, Any]], None] | None], str]
    open_next_json: Callable[[GhidraAPI, Callable[[str, dict[str, Any]], None] | None], str]


@dataclass(frozen=True)
class RegisteredTool:
    name: str
    description: str
    parameters_schema: dict[str, Any]
    handler: ToolHandler

    def anthropic_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters_schema,
        }


def _build_registry(
    on_navigate: Callable[[str], None],
    emit_fn: Callable[[str, dict[str, Any]], None] | None = None,
    batch_port: AgentBatchToolPort | None = None,
) -> dict[str, RegisteredTool]:
    def append_work_markdown(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        md = str(inp.get("markdown", ""))
        title = str(inp.get("tab_title", "")).strip()
        wd = _work_notes_dir()
        if title:
            safe = re.sub(r"[^a-zA-Z0-9_-]+", "-", title)[:60].strip("-") or "note"
            fname = f"{safe}.md"
        else:
            fname = "agent-notes.md"
        path = Path(wd) / fname
        wd.mkdir(parents=True, exist_ok=True)
        existing = path.read_text(encoding="utf-8") if path.is_file() else ""
        sep = "\n\n" if existing.strip() else ""
        path.write_text(existing + sep + md, encoding="utf-8")
        if emit_fn is not None:
            emit_fn("work_note_updated", {"path": str(path.resolve())})
        return json.dumps({"ok": True, "path": str(path.resolve())})

    def user_tip(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        msg = str(inp.get("message", ""))[:2000]
        if emit_fn is not None and msg.strip():
            emit_fn("user_tip", {"message": msg.strip()})
        return json.dumps({"ok": True})

    def list_work_notes(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        wd = _work_notes_dir()
        wd.mkdir(parents=True, exist_ok=True)
        rows: list[dict[str, Any]] = []
        for f in sorted(wd.glob("*.md"), key=lambda x: x.stat().st_mtime, reverse=True):
            st = f.stat()
            rows.append({"filename": f.name, "bytes": st.st_size, "mtime": int(st.st_mtime)})
        return json.dumps({"notes": rows, "count": len(rows)})

    def read_work_markdown(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        wd = _work_notes_dir()
        wd.mkdir(parents=True, exist_ok=True)
        key = str(inp.get("filename", "") or inp.get("note", "") or "").strip()
        if not key:
            return json.dumps({"error": "missing_filename"})
        base = Path(key.replace("\\", "/")).name
        if not base.endswith(".md"):
            base = f"{base}.md"
        path = (wd / base).resolve()
        try:
            path.relative_to(wd.resolve())
        except ValueError:
            return json.dumps({"error": "invalid_path"})
        if not path.is_file():
            slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", Path(key).stem.lower())[:60].strip("-") or "note"
            alt = (wd / f"{slug}.md").resolve()
            if alt.is_file():
                path = alt
            else:
                return json.dumps({"error": "not_found", "tried": base})
        max_c = int(inp.get("max_chars", 60000) or 60000)
        max_c = max(1024, min(max_c, 200_000))
        text = path.read_text(encoding="utf-8", errors="replace")
        truncated = len(text) > max_c
        body = text[:max_c] if truncated else text
        return json.dumps(
            {
                "filename": path.name,
                "truncated": truncated,
                "markdown": body,
            }
        )

    def open_file(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        path = str(inp["path"])
        run_aa = inp.get("run_auto_analysis", True)
        if isinstance(run_aa, str):
            run_aa = run_aa.strip().lower() in ("1", "true", "yes", "on")
        else:
            run_aa = bool(run_aa)
        name = api.open_file(path)
        analysis: dict[str, Any] = {}
        if run_aa:
            analysis = api.run_auto_analysis()
        if emit_fn is not None:
            emit_fn("ghidra_shell_refresh", {"program": name})
        out: dict[str, Any] = {"program": name, "path": path, "run_auto_analysis": run_aa}
        if run_aa:
            out["functions"] = analysis.get("functions")
            out["analysis_cancelled"] = bool(analysis.get("cancelled"))
        return json.dumps(out)

    def run_auto(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        res = api.run_auto_analysis()
        if emit_fn is not None:
            emit_fn("ghidra_shell_refresh", {})
        cancelled = bool(res.get("cancelled"))
        return json.dumps(
            {
                "status": "analysis_cancelled" if cancelled else "analysis_complete",
                "seconds": res.get("seconds"),
                "functions": res.get("functions"),
            }
        )

    def list_functions(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        needle = str(inp.get("name_contains", "") or "").strip()
        off = max(0, int(inp.get("offset", 0) or 0))
        lim_raw = inp.get("limit", None)
        lim = max(1, min(int(lim_raw), 50_000)) if lim_raw is not None else 50_000
        # Filtering and windowing happen in the JVM, so a 100k-function image is not marshalled whole.
        page = api.list_functions_page(offset=off, limit=lim, name_filter=needle)
        out: dict[str, Any] = {
            "functions": page.get("rows", []),
            "count": page.get("count", 0),
            "matched_after_name_filter": page.get("total", 0),
            "offset": page.get("offset", off),
            "truncated": bool(page.get("truncated", False)),
        }
        if not needle:
            # Unfiltered, the match count is the whole function count; keep the old key for that case.
            out["total_defined"] = page.get("total", 0)
        return json.dumps(out)

    def decompile_function(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        addr = str(inp["address"])
        timeout_raw = inp.get("timeout_seconds", None)
        timeout_s = int(timeout_raw) if timeout_raw is not None else None
        text = api.decompile_function(addr, timeout_s=timeout_s)
        return json.dumps({"address": addr, "pseudocode": text})

    def get_disassembly(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        addr = str(inp["address"])
        length = int(inp.get("length", 64))
        text = api.get_disassembly(addr, length)
        return json.dumps({"address": addr, "listing": text})

    def navigate_to(inp: dict[str, Any], _api: GhidraAPI, nav: Callable[[str], None]) -> str:
        addr = str(inp["address"])
        nav(addr)
        return json.dumps({"navigated": addr})

    def get_strings(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        off = max(0, int(inp.get("offset", 0) or 0))
        lim_raw = inp.get("limit", None)
        lim = max(1, min(int(lim_raw), 50_000)) if lim_raw is not None else 50_000
        min_len = max(0, int(inp.get("min_length", 0) or 0))
        page = api.get_strings_page(offset=off, limit=lim, min_length=min_len)
        return json.dumps(
            {
                "strings": page.get("rows", []),
                "count": page.get("count", 0),
                "total_defined": page.get("total", 0),
                "offset": page.get("offset", off),
                "truncated": bool(page.get("truncated", False)),
            }
        )

    def get_imports(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        rows = api.get_imports()
        total = len(rows)
        off = int(inp.get("offset", 0) or 0)
        off = max(0, off)
        if off:
            rows = rows[off:]
        lim_raw = inp.get("limit", None)
        truncated_by_limit = False
        if lim_raw is not None:
            lim = int(lim_raw)
            lim = max(1, min(lim, 50_000))
            if len(rows) > lim:
                truncated_by_limit = True
                rows = rows[:lim]
        return json.dumps(
            {"imports": rows, "count": len(rows), "total_defined": total, "offset": off, "truncated": truncated_by_limit}
        )

    def get_exports(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        rows = api.get_exports()
        return json.dumps({"exports": rows, "count": len(rows)})

    def get_entry_points(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        rows = api.get_entry_points()
        return json.dumps({"entry_points": rows})

    def get_xrefs_to(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        addr = str(inp["address"])
        rows = api.get_xrefs_to(addr)
        return json.dumps({"address": addr, "xrefs": rows})

    def get_xrefs_from(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        addr = str(inp["address"])
        rows = api.get_xrefs_from(addr)
        return json.dumps({"address": addr, "xrefs": rows})

    def rename_function(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        res = api.rename_function(str(inp["address"]), str(inp["new_name"]))
        if emit_fn is not None:
            emit_fn("ghidra_shell_refresh", {})
        return json.dumps(res)

    def rename_variable(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        res = api.rename_variable(
            str(inp["function_address"]), str(inp["old_name"]), str(inp["new_name"])
        )
        if emit_fn is not None and res.get("ok"):
            emit_fn("ghidra_shell_refresh", {})
        return json.dumps(res)

    def set_comment(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        res = api.set_comment(
            str(inp["address"]), str(inp["text"]), str(inp.get("comment_type", "EOL") or "EOL")
        )
        if emit_fn is not None:
            emit_fn("ghidra_shell_refresh", {})
        return json.dumps(res)

    def search_bytes(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        max_matches = int(inp.get("max_matches", 64) or 64)
        return json.dumps(api.search_bytes(str(inp["pattern"]), max_matches=max_matches))

    def get_data_at(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        return json.dumps(api.get_data_at(str(inp["address"])))

    def create_struct(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        res = api.create_struct(str(inp.get("address", "") or ""), str(inp["struct_definition"]))
        if emit_fn is not None and res.get("ok"):
            emit_fn("ghidra_shell_refresh", {})
        return json.dumps(res)

    def set_function_signature(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        res = api.set_function_signature(str(inp["address"]), str(inp["signature"]))
        if emit_fn is not None and res.get("ok"):
            emit_fn("ghidra_shell_refresh", {})
        return json.dumps(res)

    def get_control_flow_graph(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        return json.dumps(api.get_control_flow_graph(str(inp["address"])))

    def read_agent_memory(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        max_c = int(inp.get("max_chars", 32000) or 32000)
        max_c = max(256, min(max_c, 200_000))
        body, truncated, approx_b = read_agent_memory_text(max_chars=max_c)
        return json.dumps(
            {
                "path": str(agent_memory_path().resolve()),
                "markdown": body,
                "truncated": truncated,
                "approx_total_bytes": approx_b,
            }
        )

    def append_agent_memory(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        md = str(inp.get("markdown", ""))
        if not md.strip():
            return json.dumps({"error": "empty_markdown"})
        path = append_agent_memory_text(md)
        return json.dumps({"ok": True, "path": str(path.resolve())})

    def web_search(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        q = str(inp.get("query", ""))
        max_r = int(inp.get("max_results", 6) or 6)
        fetch_ex = bool(inp.get("fetch_primary_excerpt", False))
        out = perform_web_search(q, max_results=max_r, fetch_primary_excerpt=fetch_ex)
        return json.dumps(out, ensure_ascii=False)

    def batch_run_tools(inp: dict[str, Any], api: GhidraAPI, nav: Callable[[str], None]) -> str:
        calls = inp.get("calls")
        if not isinstance(calls, list) or not calls:
            return json.dumps({"error": "calls_must_be_non_empty_array"})
        if len(calls) > 24:
            return json.dumps({"error": "max_24_calls_per_batch", "got": len(calls)})
        results: list[dict[str, Any]] = []
        for i, c in enumerate(calls):
            if not isinstance(c, dict):
                results.append({"index": i, "error": "each_call_must_be_object"})
                continue
            n = str(c.get("name", "")).strip()
            sub = c.get("input")
            if not isinstance(sub, dict):
                sub = {}
            if n == "batch_run_tools":
                results.append({"index": i, "error": "nested_batch_run_tools_not_allowed"})
                continue
            if not n:
                results.append({"index": i, "error": "missing_tool_name"})
                continue
            try:
                out = run_tool(n, sub, api, nav, emit_fn, batch_port)
                results.append({"index": i, "name": n, "result": out})
            except Exception as e:
                results.append({"index": i, "name": n, "error": str(e)})
        return json.dumps({"ok": True, "count": len(calls), "results": results}, ensure_ascii=False)

    def analysis_batch_status(_inp: dict[str, Any], _api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        if batch_port is None:
            return json.dumps({"error": "batch_port_unconfigured"})
        return batch_port.status_json()

    def analysis_batch_open_index(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        if batch_port is None:
            return json.dumps({"error": "batch_port_unconfigured"})
        idx = int(inp.get("index", -1))
        return batch_port.open_index_json(idx, api, emit_fn)

    def analysis_batch_open_next(_inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        if batch_port is None:
            return json.dumps({"error": "batch_port_unconfigured"})
        return batch_port.open_next_json(api, emit_fn)

    tools: list[RegisteredTool] = [
        RegisteredTool(
            name="open_file",
            description=(
                "Import a new executable/library into Ghidra from disk and make it the active program. "
                "By default runs full automatic analysis immediately (set run_auto_analysis false to import only, "
                "then call run_auto_analysis yourself). Use when the user supplies a path or wants to switch binaries. "
                "If they are using the **batch analysis queue** in the File dock, prefer **`analysis_batch_open_next`** "
                "or **`analysis_batch_open_index`** (after `analysis_batch_status`) so queue indices stay aligned. "
                "Do not use for re-analyzing an already loaded image without a new path (use run_auto_analysis)."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute file path to the binary (Windows: drive letter, escaped backslashes ok).",
                    },
                    "run_auto_analysis": {
                        "type": "boolean",
                        "description": "If true (default), run Ghidra auto-analysis after import. If false, import only.",
                    },
                },
                "required": ["path"],
            },
            handler=open_file,
        ),
        RegisteredTool(
            name="analysis_batch_status",
            description=(
                "Read the File-dock **batch analysis** queue shared with the user: `count`, `next_index`, "
                "`loaded_program`, `next_path`, `basenames`, and **`items`** (each entry has `index`, `basename`, "
                "`path`). Call this whenever the user refers to multiple binaries, the queue, or “the next file”. "
                "To load one, use `analysis_batch_open_index` with that `index`, or `analysis_batch_open_next` "
                "to follow `next_index` order. Ghidra only holds one program at a time."
            ),
            parameters_schema={"type": "object", "properties": {}},
            handler=analysis_batch_status,
        ),
        RegisteredTool(
            name="analysis_batch_open_index",
            description=(
                "Batch analysis: open queue row `index` (0-based, from `analysis_batch_status.items`). "
                "Imports that file into Ghidra, runs full auto-analysis, refreshes the UI, and sets the batch "
                "cursor to `index+1` on success (matches the user double-clicking that row)."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "index": {"type": "integer", "description": "Zero-based index into the batch queue."},
                },
                "required": ["index"],
            },
            handler=analysis_batch_open_index,
        ),
        RegisteredTool(
            name="analysis_batch_open_next",
            description=(
                "Batch analysis: open the file at `next_index` from `analysis_batch_status` (same as the "
                "File dock **Open next** button). Runs import + full auto-analysis and advances the cursor on success."
            ),
            parameters_schema={"type": "object", "properties": {}},
            handler=analysis_batch_open_next,
        ),
        RegisteredTool(
            name="run_auto_analysis",
            description=(
                "Re-run Ghidra’s automatic analysis pipeline on the **currently loaded** program only. "
                "Takes no arguments. Use after renaming segments, changing loader options, or when the user "
                "explicitly asks to (re)analyze or refresh analysis. open_file runs this by default unless "
                "run_auto_analysis was set false on that call."
            ),
            parameters_schema={
                "type": "object",
                "properties": {},
                "description": "No parameters.",
            },
            handler=run_auto,
        ),
        RegisteredTool(
            name="list_functions",
            description=(
                "Defined functions with names and entry addresses. Prefer optional limit/offset/name_contains on "
                "large binaries to save tokens; omit limit only when you need the full list."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Max functions to return after filtering (1–50000). Omit to return all (can be huge).",
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Skip this many functions after name_contains filter (default 0).",
                    },
                    "name_contains": {
                        "type": "string",
                        "description": "If set, only functions whose name contains this substring (case-insensitive).",
                    },
                },
            },
            handler=list_functions,
        ),
        RegisteredTool(
            name="decompile_function",
            description=(
                "High-level pseudocode for the function whose entry is at `address` (Decompiler view). "
                "Prefer after narrowing with xrefs or list_functions. Output can be wrong or incomplete - verify "
                "critical paths with get_disassembly."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Function entry symbol or hex address (e.g. FUN_00401000 or 00401000).",
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Decompiler budget for this function, 1-600. Defaults to 120.",
                    },
                },
                "required": ["address"],
            },
            handler=decompile_function,
        ),
        RegisteredTool(
            name="get_disassembly",
            description=(
                "Linear listing of instructions starting at `address` for up to `length` instructions. "
                "Use for exact opcodes, branches, and when decompiler output is misleading."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Instruction or label address to start listing from.",
                    },
                    "length": {
                        "type": "integer",
                        "description": "Maximum number of instructions (default 64; cap 5000 - keep small when possible).",
                    },
                },
                "required": ["address"],
            },
            handler=get_disassembly,
        ),
        RegisteredTool(
            name="navigate_to",
            description=(
                "Scrolls RawView/Ghidra UI focus to `address` so the user sees the same location you are discussing. "
                "Does not change analysis data - purely for coordination."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Address or symbol to jump the UI to."},
                },
                "required": ["address"],
            },
            handler=navigate_to,
        ),
        RegisteredTool(
            name="get_strings",
            description=(
                "Defined string literals (value + address). Optional limit/offset window large tables and save tokens."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Max rows after offset (1–50000). Omit for full list."},
                    "offset": {"type": "integer", "description": "Skip this many strings (default 0)."},
                    "min_length": {
                        "type": "integer",
                        "description": "Drop strings shorter than this many characters. Defaults to 0.",
                    },
                },
            },
            handler=get_strings,
        ),
        RegisteredTool(
            name="get_imports",
            description=(
                "Import table (DLLs/APIs). Optional limit/offset on very large tables to reduce tool-result size."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Max rows after offset (1–50000). Omit for full list."},
                    "offset": {"type": "integer", "description": "Skip this many imports (default 0)."},
                },
            },
            handler=get_imports,
        ),
        RegisteredTool(
            name="get_exports",
            description=(
                "Export-like symbols exposed by this image (implementation may be simplified/MVP). "
                "Useful for libraries and drivers; cross-check with list_functions."
            ),
            parameters_schema={"type": "object", "properties": {}},
            handler=get_exports,
        ),
        RegisteredTool(
            name="get_entry_points",
            description=(
                "Declared entry points (e.g. main image entry). Start here for execution flow when you need "
                "the first code that runs after the loader."
            ),
            parameters_schema={"type": "object", "properties": {}},
            handler=get_entry_points,
        ),
        RegisteredTool(
            name="get_xrefs_to",
            description=(
                "Every code/data reference **to** `address` (who calls or reads this). Essential for finding "
                "callers of a string, thunk, or API stub."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Target address or symbol that others refer to.",
                    },
                },
                "required": ["address"],
            },
            handler=get_xrefs_to,
        ),
        RegisteredTool(
            name="get_xrefs_from",
            description=(
                "References **from** `address` outward (calls, loads, jumps). Use inside a function to map "
                "its callees and data dependencies."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Instruction or data address to enumerate outgoing refs from.",
                    },
                },
                "required": ["address"],
            },
            handler=get_xrefs_from,
        ),
        RegisteredTool(
            name="rename_function",
            description=(
                "Persistently rename the function at `address` in the Ghidra database (affects listings and "
                "decompiler). Use descriptive reverse-engineered names; avoid renaming unless confident."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Entry address of the function to rename."},
                    "new_name": {
                        "type": "string",
                        "description": "Valid identifier-style name (letters, digits, underscore).",
                    },
                },
                "required": ["address", "new_name"],
            },
            handler=rename_function,
        ),
        RegisteredTool(
            name="rename_variable",
            description=(
                "Rename a local or parameter inside a function. `old_name` must match the name as it "
                "appears in the decompiler output (e.g. `iVar1`, `param_1`, `local_18`). If the name is "
                "not found the result lists the variables the function does have."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "function_address": {"type": "string", "description": "Entry address of the containing function."},
                    "old_name": {"type": "string", "description": "Current variable name in decompiler output."},
                    "new_name": {"type": "string", "description": "New variable name."},
                },
                "required": ["function_address", "old_name", "new_name"],
            },
            handler=rename_variable,
        ),
        RegisteredTool(
            name="set_comment",
            description=(
                "Attach a comment at `address` in the database. Good for marking invariants, protocol "
                "fields, or TODOs visible in both listing and decompiler. Defaults to an end-of-line "
                "comment; use PLATE for a block comment above a function."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Instruction or data address."},
                    "text": {"type": "string", "description": "Short comment text (avoid secrets)."},
                    "comment_type": {
                        "type": "string",
                        "enum": ["EOL", "PRE", "POST", "PLATE", "REPEATABLE"],
                        "description": "Comment slot to write. Defaults to EOL.",
                    },
                },
                "required": ["address", "text"],
            },
            handler=set_comment,
        ),
        RegisteredTool(
            name="search_bytes",
            description=(
                "Search all program memory for a byte pattern and return every match, each with the "
                'containing function and memory block. Hex bytes with or without separators ("48 89 E5" '
                'or "4889e5"), and "??" matches any byte, so signatures with wildcards work directly.'
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": 'Hex bytes, "??" for a wildcard byte, e.g. "48 8B ?? ?? E8".',
                    },
                    "max_matches": {
                        "type": "integer",
                        "description": "Match cap, 1-1000. Defaults to 64.",
                    },
                },
                "required": ["pattern"],
            },
            handler=search_bytes,
        ),
        RegisteredTool(
            name="get_data_at",
            description=(
                "Inspect how Ghidra has typed the item at `address` (data, undefined, instruction). "
                "Use to verify structs, pointers, strings, or alignment before applying types."
            ),
            parameters_schema={
                "type": "object",
                "properties": {"address": {"type": "string", "description": "Any program address."}},
                "required": ["address"],
            },
            handler=get_data_at,
        ),
        RegisteredTool(
            name="create_struct",
            description=(
                "Define a C data type in the program and optionally lay it down at `address`. Takes real C "
                "text - a struct, typedef or enum - and resolves field types against the program's own type "
                "manager. Leave `address` empty to define the type without applying it anywhere."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Where to apply the type; empty string to only define it.",
                    },
                    "struct_definition": {
                        "type": "string",
                        "description": 'C text, e.g. "struct Hdr { int magic; char name[8]; void *next; };".',
                    },
                },
                "required": ["struct_definition"],
            },
            handler=create_struct,
        ),
        RegisteredTool(
            name="set_function_signature",
            description=(
                "Set the function prototype - return type, name, parameter names and types, calling "
                "convention - which usually improves the decompiled output of this function and its "
                "callers immediately. Returns the prototype Ghidra actually applied."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Function entry address."},
                    "signature": {
                        "type": "string",
                        "description": "C-like signature, e.g. int foo(char *a, size_t n);",
                    },
                },
                "required": ["address", "signature"],
            },
            handler=set_function_signature,
        ),
        RegisteredTool(
            name="get_control_flow_graph",
            description=(
                "Retrieve control-flow graph information for the function at `address` (shape, blocks, edges - "
                "exact schema depends on bridge; may be summary/placeholder JSON)."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Function entry address for CFG scope."},
                },
                "required": ["address"],
            },
            handler=get_control_flow_graph,
        ),
        RegisteredTool(
            name="list_work_notes",
            description=(
                "Enumerate Markdown files in the Work dock folder (mtime, size). Call before read_work_markdown "
                "or append_work_markdown when you need the correct filename or want to avoid duplicate notes."
            ),
            parameters_schema={"type": "object", "properties": {}},
            handler=list_work_notes,
        ),
        RegisteredTool(
            name="read_work_markdown",
            description=(
                "Load the contents of one Work-dock Markdown note by `filename` or `note` stem. Scoped to the "
                "work folder only (no arbitrary paths). Use max_chars to cap huge notes."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Basename like findings.md or a stem resolved to *.md in the work folder.",
                    },
                    "note": {"type": "string", "description": "Alias for filename if the latter is empty."},
                    "max_chars": {
                        "type": "integer",
                        "description": "Max characters returned (default 60000, hard max 200000).",
                    },
                },
            },
            handler=read_work_markdown,
        ),
        RegisteredTool(
            name="append_work_markdown",
            description=(
                "Append Markdown to a user-visible Work dock note (good for session write-ups the human edits). "
                "Creates the file if missing. `tab_title` slugifies into the filename; otherwise defaults to "
                "agent-notes.md. Prefer short structured sections over dumping full listings."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "markdown": {"type": "string", "description": "Markdown chunk to append (headings, bullets, links)."},
                    "tab_title": {
                        "type": "string",
                        "description": "Optional human-readable title used to derive the .md filename.",
                    },
                },
                "required": ["markdown"],
            },
            handler=append_work_markdown,
        ),
        RegisteredTool(
            name="read_agent_memory",
            description=(
                "Read RawView’s persistent **agent long-term memory** file (Markdown under the user data directory). "
                "Survives app restarts. Use when the user refers to past sessions, goals, or facts you may have "
                "stored earlier; read before large append_agent_memory updates so you do not duplicate or contradict prior notes."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "max_chars": {
                        "type": "integer",
                        "description": "Max characters of the file to return (default 32000, max 200000).",
                    },
                },
            },
            handler=read_agent_memory,
        ),
        RegisteredTool(
            name="append_agent_memory",
            description=(
                "Append Markdown to the persistent agent memory file (same store as read_agent_memory). "
                "Use for durable, cross-session facts: binary goals, resolved identities of FUN_ labels, "
                "architecture, safe analysis checkpoints. **Do not** store passwords, API keys, tokens, or "
                "private personal data. Keep entries concise."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "markdown": {
                        "type": "string",
                        "description": "Markdown to append (e.g. bullet list of verified facts with dates).",
                    },
                },
                "required": ["markdown"],
            },
            handler=append_agent_memory,
        ),
        RegisteredTool(
            name="web_search",
            description=(
                "Search the public web for documentation, CVEs, vendor advisories, or general facts. "
                "Uses DuckDuckGo instant answers and related links (no API key). "
                "Verify critical claims against primary sources."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query."},
                    "max_results": {
                        "type": "integer",
                        "description": "Max result rows to return (1–12). Default 6.",
                    },
                    "fetch_primary_excerpt": {
                        "type": "boolean",
                        "description": "If true, fetch the primary result page and include a short text excerpt (slower).",
                    },
                },
                "required": ["query"],
            },
            handler=web_search,
        ),
        RegisteredTool(
            name="batch_run_tools",
            description=(
                "Run multiple tools in one assistant turn to save tokens. Provide an array of {name, input} calls. "
                "Each call is independent (same rules as single tools). Max 24 calls; do not nest batch_run_tools."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "calls": {
                        "type": "array",
                        "description": "Ordered list of tool invocations.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "input": {"type": "object"},
                            },
                            "required": ["name", "input"],
                        },
                    }
                },
                "required": ["calls"],
            },
            handler=batch_run_tools,
        ),
        RegisteredTool(
            name="user_tip",
            description=(
                "Push a short, user-visible toast-style tip in the RawView UI. Reserve for rare UX guidance "
                "(where to click, what a panel means). Do not use for ordinary analysis text - put that in chat."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "One or two sentences; plain language; no markdown required.",
                    },
                },
                "required": ["message"],
            },
            handler=user_tip,
        ),
    ]
    return {t.name: t for t in tools}


def anthropic_tool_list(
    on_navigate: Callable[[str], None],
    batch_port: AgentBatchToolPort | None = None,
) -> list[dict[str, Any]]:
    return [t.anthropic_schema() for t in _build_registry(on_navigate, None, batch_port).values()]


def run_tool(
    name: str,
    arguments_json: str | Mapping[str, Any],
    api: GhidraAPI,
    on_navigate: Callable[[str], None],
    emit: Callable[[str, dict[str, Any]], None] | None = None,
    batch_port: AgentBatchToolPort | None = None,
) -> str:
    reg = _build_registry(on_navigate, emit, batch_port)
    if name not in reg:
        return json.dumps({"error": f"unknown_tool:{name}"})
    if isinstance(arguments_json, str):
        inp = json.loads(arguments_json or "{}")
    else:
        inp = dict(arguments_json)
    return reg[name].handler(inp, api, on_navigate)
