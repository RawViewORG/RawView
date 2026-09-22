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
    current_address_fn: Callable[[], str] | None = None,
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

    def get_program_info(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        return json.dumps(api.get_program_info())

    def read_bytes(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        return json.dumps(api.read_bytes(str(inp["address"]), int(inp.get("length", 16) or 16)))

    def get_hex_dump(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        dump = api.get_hex_dump(
            str(inp["address"]),
            int(inp.get("max_bytes", 256) or 256),
            int(inp.get("bytes_per_line", 16) or 16),
        )
        return json.dumps({"address": str(inp["address"]), "dump": dump})

    def get_function_variables(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        return json.dumps(api.get_function_variables(str(inp["address"])))

    def define_data(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        res = api.define_data(str(inp["address"]), str(inp["type"]))
        if emit_fn is not None and res.get("ok"):
            emit_fn("ghidra_shell_refresh", {})
        return json.dumps(res)

    def get_comments(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        return json.dumps(api.get_comments(str(inp["address"])))

    def search_immediate(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        return json.dumps(
            api.search_immediate(str(inp["value"]), max_matches=int(inp.get("max_matches", 64) or 64))
        )

    def strings_in_function(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        return json.dumps(api.strings_in_function(str(inp["address"])))

    def get_function_at(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        return json.dumps(api.get_function_at(str(inp["address"])))

    def get_call_graph(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        return json.dumps(
            api.get_call_graph(
                str(inp["address"]),
                depth=int(inp.get("depth", 2) or 2),
                direction=str(inp.get("direction", "both") or "both"),
            )
        )

    def search_program(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        return json.dumps(
            api.search_program(
                str(inp["query"]),
                limit_per_kind=int(inp.get("limit_per_kind", 25) or 25),
                kinds=str(inp.get("kinds", "") or ""),
            )
        )

    def list_segments(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        rows = api.list_segments()
        return json.dumps({"segments": rows, "count": len(rows)})

    def list_namespaces(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        rows = api.list_namespaces()
        return json.dumps({"namespaces": rows, "count": len(rows)})

    def list_data_items(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        return json.dumps(
            api.list_data_items(int(inp.get("offset", 0) or 0), int(inp.get("limit", 200) or 200))
        )

    def rename_data(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        res = api.rename_data(str(inp["address"]), str(inp["new_name"]))
        if emit_fn is not None and res.get("ok"):
            emit_fn("ghidra_shell_refresh", {})
        return json.dumps(res)

    def set_local_variable_type(
        inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]
    ) -> str:
        return json.dumps(
            api.set_local_variable_type(
                str(inp["function_address"]), str(inp["variable_name"]), str(inp["type"])
            )
        )

    def patch_bytes(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        res = api.patch_bytes(str(inp["address"]), str(inp["bytes"]))
        if emit_fn is not None and res.get("ok"):
            emit_fn("ghidra_shell_refresh", {})
        return json.dumps(res)

    def assemble_instruction(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        apply_it = inp.get("apply", False)
        if isinstance(apply_it, str):
            apply_it = apply_it.strip().lower() in ("1", "true", "yes", "on")
        res = api.assemble_instruction(
            str(inp["address"]), str(inp["instruction"]), apply=bool(apply_it)
        )
        if emit_fn is not None and res.get("applied"):
            emit_fn("ghidra_shell_refresh", {})
        return json.dumps(res)

    def list_patches(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        return json.dumps(api.list_patches())

    def revert_patch(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        res = api.revert_patch(str(inp["address"]), int(inp.get("length", 0) or 0))
        if emit_fn is not None and res.get("ok"):
            emit_fn("ghidra_shell_refresh", {})
        return json.dumps(res)

    def export_patched_file(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        return json.dumps(api.export_patched_file(str(inp["path"])))

    def compare_binary(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        """Import, analyze and diff in one call: three round trips the model should not have to make."""
        opened = api.open_comparison_file(str(inp["path"]))
        if not opened.get("ok"):
            return json.dumps(opened)
        analyze = inp.get("analyze", True)
        if isinstance(analyze, str):
            analyze = analyze.strip().lower() in ("1", "true", "yes", "on")
        if analyze:
            analyzed = api.analyze_comparison_program()
            if not analyzed.get("ok"):
                return json.dumps(analyzed)
        out = api.diff_programs(int(inp.get("limit", 100) or 100))
        out["compared_with"] = opened.get("name", "")
        return json.dumps(out)

    def close_comparison(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        return json.dumps(api.close_comparison_program())

    def get_current_address(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        """Where the user is looking. RawView runs inside the window, so this is the real selection."""
        address = current_address_fn() if current_address_fn is not None else ""
        return json.dumps({"address": address})

    def get_current_function(inp: dict[str, Any], api: GhidraAPI, _nav: Callable[[str], None]) -> str:
        address = current_address_fn() if current_address_fn is not None else ""
        if not address:
            return json.dumps({"error": "no_current_address"})
        out = api.get_function_at(address)
        out["current_address"] = address
        return json.dumps(out)

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
                out = run_tool(n, sub, api, nav, emit_fn, batch_port, current_address_fn)
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
                        "description": "Max functions to return after filtering (1-50000). Omit to return all (can be huge).",
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
                    "limit": {"type": "integer", "description": "Max rows after offset (1-50000). Omit for full list."},
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
                    "limit": {"type": "integer", "description": "Max rows after offset (1-50000). Omit for full list."},
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
                "Search the web for documentation, CVEs, vendor advisories, or general facts. "
                "Goes to whichever provider is configured (WormT, Brave, SearXNG, or DuckDuckGo); "
                "the answer names the one that served it under `source`. "
                "Verify critical claims against primary sources."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query."},
                    "max_results": {
                        "type": "integer",
                        "description": "Max result rows to return (1-12). Default 6.",
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
            name="get_program_info",
            description=(
                "One-call orientation for the loaded program: file format, CPU/architecture, "
                "endianness, pointer size, image base, address range, compiler, MD5/SHA-256, and "
                "function/symbol counts. Call this first when you open something unfamiliar."
            ),
            parameters_schema={"type": "object", "properties": {}},
            handler=get_program_info,
        ),
        RegisteredTool(
            name="read_bytes",
            description=(
                "Raw bytes at an address as a hex string (up to 4096). Use for headers, tables, or "
                "data the decompiler shows as bytes; get_hex_dump is the formatted view."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Address to read from."},
                    "length": {"type": "integer", "description": "Bytes to read (default 16, max 4096)."},
                },
                "required": ["address"],
            },
            handler=read_bytes,
        ),
        RegisteredTool(
            name="get_hex_dump",
            description="Formatted hex+ASCII dump at an address. `input`: address; optional max_bytes, bytes_per_line.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Address to dump from."},
                    "max_bytes": {"type": "integer", "description": "Bytes to show (default 256)."},
                    "bytes_per_line": {"type": "integer", "description": "Columns (default 16)."},
                },
                "required": ["address"],
            },
            handler=get_hex_dump,
        ),
        RegisteredTool(
            name="get_function_variables",
            description=(
                "Parameters and locals of a function, each with its type and storage. Call before "
                "rename_variable or set_local_variable_type so you use the exact names Ghidra has."
            ),
            parameters_schema={
                "type": "object",
                "properties": {"address": {"type": "string", "description": "Function entry or any address in it."}},
                "required": ["address"],
            },
            handler=get_function_variables,
        ),
        RegisteredTool(
            name="define_data",
            description=(
                "Define data of a named C type at an address - mark a dword, a pointer, a string, or "
                "a struct laid down in memory. `type` is C text like 'int', 'char *', 'dword', or a "
                "struct name already created with create_struct. Modifies the program."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Where to define the data."},
                    "type": {"type": "string", "description": "C type, e.g. 'int', 'char[16]', 'void *'."},
                },
                "required": ["address", "type"],
            },
            handler=define_data,
        ),
        RegisteredTool(
            name="get_comments",
            description="Read back every comment at an address (EOL, PRE, POST, PLATE, REPEATABLE).",
            parameters_schema={
                "type": "object",
                "properties": {"address": {"type": "string", "description": "Address to read comments at."}},
                "required": ["address"],
            },
            handler=get_comments,
        ),
        RegisteredTool(
            name="search_immediate",
            description=(
                "Find every instruction whose operand is a given constant - a magic number, XOR key, "
                "port, or size. `value` is decimal or 0x-prefixed hex; matches both signed and "
                "unsigned readings. The direct way to answer 'where is this constant used'."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "value": {"type": "string", "description": "Constant to find, e.g. '0xdeadbeef' or '4919'."},
                    "max_matches": {"type": "integer", "description": "Cap (default 64, max 300)."},
                },
                "required": ["value"],
            },
            handler=search_immediate,
        ),
        RegisteredTool(
            name="strings_in_function",
            description=(
                "The strings referenced from within one function's body - fast triage of what a "
                "function touches (URLs, file paths, registry keys, error text) without reading it all."
            ),
            parameters_schema={
                "type": "object",
                "properties": {"address": {"type": "string", "description": "Function entry or any address in it."}},
                "required": ["address"],
            },
            handler=strings_in_function,
        ),
        RegisteredTool(
            name="get_function_at",
            description=(
                "Resolve `address` to the function containing it: name, entry point, signature, size, "
                "calling convention. Use when you hold an address from a string xref, a call target or "
                "the user and need to know what function it is in."
            ),
            parameters_schema={
                "type": "object",
                "properties": {"address": {"type": "string", "description": "Any address inside a function."}},
                "required": ["address"],
            },
            handler=get_function_at,
        ),
        RegisteredTool(
            name="get_call_graph",
            description=(
                "Callers and/or callees of the function at `address`, walked `depth` levels. "
                "`direction` is callers, callees or both (default both). Edges always point caller -> "
                "callee. Prefer this over reading xrefs by hand to answer 'what reaches this code'. "
                "Large graphs are capped and report truncated."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Function entry or any address inside it."},
                    "depth": {"type": "integer", "description": "Levels to walk, 1-5 (default 2)."},
                    "direction": {
                        "type": "string",
                        "description": "callers, callees, or both (default).",
                    },
                },
                "required": ["address"],
            },
            handler=get_call_graph,
        ),
        RegisteredTool(
            name="search_program",
            description=(
                "One case-insensitive substring search across functions, symbols, strings, imports, "
                "exports and data labels. `kinds` narrows it (comma-separated subset of "
                "functions,symbols,strings,imports,exports,data); empty searches everything. A query "
                "that parses as an address also returns an address hit. Use this instead of listing a "
                "whole category and filtering yourself."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Substring to look for."},
                    "kinds": {"type": "string", "description": "Comma-separated kinds, or empty for all."},
                    "limit_per_kind": {
                        "type": "integer",
                        "description": "Max hits per kind (default 25, hard max 200).",
                    },
                },
                "required": ["query"],
            },
            handler=search_program,
        ),
        RegisteredTool(
            name="list_segments",
            description=(
                "Memory map: every block with start, end, size, permissions and whether it holds bytes. "
                "Use to tell code from data, spot RWX blocks, or check whether an address is mapped."
            ),
            parameters_schema={"type": "object", "properties": {}},
            handler=list_segments,
        ),
        RegisteredTool(
            name="list_namespaces",
            description="Namespaces and classes defined in the program (C++ classes, external libraries).",
            parameters_schema={"type": "object", "properties": {}},
            handler=list_namespaces,
        ),
        RegisteredTool(
            name="list_data_items",
            description=(
                "Defined, labelled data: globals, tables and structures with their type and value. "
                "Paged through `offset`/`limit`."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "offset": {"type": "integer", "description": "Rows to skip (default 0)."},
                    "limit": {"type": "integer", "description": "Rows to return (default 200, max 5000)."},
                },
            },
            handler=list_data_items,
        ),
        RegisteredTool(
            name="rename_data",
            description=(
                "Rename (or create) the label at `address`. For data and globals; use rename_function "
                "for a function entry point."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Address of the data item."},
                    "new_name": {"type": "string", "description": "New label."},
                },
                "required": ["address", "new_name"],
            },
            handler=rename_data,
        ),
        RegisteredTool(
            name="set_local_variable_type",
            description=(
                "Retype one local or parameter of a function, as retyping it in the decompiler would. "
                "Ghidra refuses a type whose size does not fit the variable's storage; that comes back "
                "as error type_rejected with the reason, not as a failure to act on."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "function_address": {"type": "string", "description": "Function entry address."},
                    "variable_name": {"type": "string", "description": "Variable as the decompiler names it."},
                    "type": {"type": "string", "description": "C type, e.g. 'char *' or 'unsigned int'."},
                },
                "required": ["function_address", "variable_name", "type"],
            },
            handler=set_local_variable_type,
        ),
        RegisteredTool(
            name="assemble_instruction",
            description=(
                "Assemble one instruction for `address`. Defaults to a dry run that writes nothing and "
                "reports the encoding, its length, the length of the instruction it would replace, and "
                "`overruns` when the new one is longer and would overwrite the next instruction. Pass "
                "apply=true to write it. Always dry-run first and check overruns before applying."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Where the instruction goes."},
                    "instruction": {"type": "string", "description": "Assembly, e.g. 'MOV EAX,0x1' or 'NOP'."},
                    "apply": {
                        "type": "boolean",
                        "description": "Write it (default false, which only reports what would be written).",
                    },
                },
                "required": ["address", "instruction"],
            },
            handler=assemble_instruction,
        ),
        RegisteredTool(
            name="patch_bytes",
            description=(
                "Overwrite the bytes at `address` with hex `bytes`. Modifies the program: say what you "
                "are patching and why before calling it, and prefer assemble_instruction when you mean "
                "an instruction rather than raw bytes. Returns the original bytes, which revert_patch "
                "can restore."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Address to write at."},
                    "bytes": {"type": "string", "description": "Hex, e.g. '90 90' or '9090'."},
                },
                "required": ["address", "bytes"],
            },
            handler=patch_bytes,
        ),
        RegisteredTool(
            name="list_patches",
            description=(
                "Every byte run that differs from the file the program was imported from, with the "
                "original and current bytes. Read back from the program, so it includes patches made "
                "by the user. Relocations Ghidra applied at import are excluded."
            ),
            parameters_schema={"type": "object", "properties": {}},
            handler=list_patches,
        ),
        RegisteredTool(
            name="revert_patch",
            description=(
                "Restore the original file bytes at `address`. `length` 0 (the default) reverts the "
                "whole changed run starting there, which is what list_patches reports."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Start of the patched run."},
                    "length": {"type": "integer", "description": "Bytes to revert, or 0 for the whole run."},
                },
                "required": ["address"],
            },
            handler=revert_patch,
        ),
        RegisteredTool(
            name="export_patched_file",
            description=(
                "Write the imported file back out to `path` with every patch applied, preserving "
                "headers and unmapped regions so the result still runs. Writes a file to disk: only "
                "call it when the user asked for a patched binary, and tell them where it went."
            ),
            parameters_schema={
                "type": "object",
                "properties": {"path": {"type": "string", "description": "Destination file path."}},
                "required": ["path"],
            },
            handler=export_patched_file,
        ),
        RegisteredTool(
            name="compare_binary",
            description=(
                "Import the binary at `path` beside the loaded program, analyze it, and report which "
                "functions are identical, changed, only here, or only there, with instruction-count "
                "deltas. Matching survives rebasing, and changed constants do count as a change. Use "
                "for variant analysis: what is new or different in this sample versus the known one."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Second binary to compare against."},
                    "analyze": {
                        "type": "boolean",
                        "description": "Auto-analyze the second binary first (default true; needed for a useful diff).",
                    },
                    "limit": {"type": "integer", "description": "Max rows per category (default 100)."},
                },
                "required": ["path"],
            },
            handler=compare_binary,
        ),
        RegisteredTool(
            name="close_comparison",
            description="Drop the comparison binary opened by compare_binary and free its memory.",
            parameters_schema={"type": "object", "properties": {}},
            handler=close_comparison,
        ),
        RegisteredTool(
            name="get_current_address",
            description=(
                "The address the user is currently looking at in RawView. Use it when they say 'this "
                "function', 'here' or 'the current address' instead of guessing or asking."
            ),
            parameters_schema={"type": "object", "properties": {}},
            handler=get_current_address,
        ),
        RegisteredTool(
            name="get_current_function",
            description=(
                "The function containing the address the user is looking at, with its name and "
                "signature. The direct answer to 'what is this function doing'."
            ),
            parameters_schema={"type": "object", "properties": {}},
            handler=get_current_function,
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
    current_address_fn: Callable[[], str] | None = None,
) -> list[dict[str, Any]]:
    registry = _build_registry(on_navigate, None, batch_port, current_address_fn)
    return [t.anthropic_schema() for t in registry.values()]


def run_tool(
    name: str,
    arguments_json: str | Mapping[str, Any],
    api: GhidraAPI,
    on_navigate: Callable[[str], None],
    emit: Callable[[str, dict[str, Any]], None] | None = None,
    batch_port: AgentBatchToolPort | None = None,
    current_address_fn: Callable[[], str] | None = None,
) -> str:
    reg = _build_registry(on_navigate, emit, batch_port, current_address_fn)
    if name not in reg:
        return json.dumps({"error": f"unknown_tool:{name}"})
    if isinstance(arguments_json, str):
        inp = json.loads(arguments_json or "{}")
    else:
        inp = dict(arguments_json)
    return reg[name].handler(inp, api, on_navigate)
