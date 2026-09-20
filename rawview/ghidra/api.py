from __future__ import annotations

import json
import logging
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from rawview.ghidra.bridge import GhidraBridgeController

logger = logging.getLogger(__name__)


def _java_rpc_method_missing(exc: BaseException) -> bool:
    """True when Py4J reports the JVM GhidraBridge has no such method (stale rawview/java/out)."""
    s = str(exc)
    return "does not exist" in s and "Method" in s


@dataclass
class GhidraAPI:
    """Typed facade for Ghidra operations; UI and agent use this class only."""

    bridge: GhidraBridgeController

    def _invoke_json_object_rows(
        self,
        call: Callable[[Any], Any],
        *,
        empty: list[dict[str, str]],
    ) -> list[dict[str, str]]:
        try:
            raw = self.bridge.invoke_java(call)
            data = json.loads(str(raw))
            if not isinstance(data, list):
                return empty
            return [{str(k): str(v) for k, v in row.items()} for row in data]
        except Exception as e:
            if _java_rpc_method_missing(e):
                head = str(e).split("\n", 1)[0].strip()
                logger.warning(
                    "Ghidra JVM bridge is out of date (%s). Run: python -m rawview.scripts.compile_java",
                    head[:220],
                )
                return empty
            raise

    def _invoke_page(
        self,
        call: Callable[[Any], Any],
        *,
        fallback: Callable[[], list[dict[str, str]]],
        offset: int,
        limit: int,
    ) -> dict[str, Any]:
        """
        Call a JVM-side paged listing, falling back to fetching everything and slicing in Python.

        The fallback keeps RawView working against a bridge JAR built before the paged methods existed
        (``rawview/java/out`` is compiled by the user, not shipped), at the cost of the transfer the
        paged call is meant to avoid.
        """
        try:
            raw = self.bridge.invoke_java(call)
            data = json.loads(str(raw))
            if isinstance(data, dict) and isinstance(data.get("rows"), list):
                data["rows"] = [{str(k): v for k, v in row.items()} for row in data["rows"]]
                return data
        except Exception as e:
            if not _java_rpc_method_missing(e):
                raise
            logger.warning(
                "Ghidra JVM bridge predates paged listings; falling back to a full transfer. "
                "Run: python -m rawview.scripts.compile_java"
            )
        rows = fallback()
        total = len(rows)
        window = rows[offset : offset + limit] if limit > 0 else rows[offset:]
        return {
            "total": total,
            "offset": offset,
            "count": len(window),
            "truncated": total > offset + len(window),
            "rows": window,
        }

    def ping(self) -> str:
        return str(self.bridge.invoke_java(lambda ep: ep.ping()))

    def open_file(self, path: str) -> str:
        # Under the bubblewrap sandbox the JVM cannot see most of the filesystem; this copies the
        # binary somewhere it can when that applies, and is a no-op otherwise.
        usable = self.bridge.stage_path_for_jvm(path)
        name = self.bridge.invoke_java(lambda ep: ep.openFile(usable))
        return str(name)

    def run_auto_analysis(self) -> dict[str, Any]:
        """Run Ghidra auto-analysis to completion. Returns ``{ok, cancelled, seconds, functions}``."""
        raw = self.bridge.invoke_java(lambda ep: ep.runAutoAnalysis())
        if raw is None:
            # Bridge built before runAutoAnalysis reported a result.
            return {"ok": True}
        try:
            data = json.loads(str(raw))
        except json.JSONDecodeError:
            return {"ok": True}
        return data if isinstance(data, dict) else {"ok": True}

    def cancel_analysis(self) -> dict[str, Any]:
        """
        Ask an in-flight auto-analysis to stop.

        Goes out of band around the Py4J mutex: the analysis RPC holds that mutex for its whole run, so a
        cancel queued behind it could only be delivered once there was nothing left to cancel.
        """
        try:
            raw = self.bridge.invoke_java_out_of_band(lambda ep: ep.cancelAnalysis())
        except Exception as e:
            if _java_rpc_method_missing(e):
                return {"ok": False, "reason": "bridge_out_of_date"}
            raise
        try:
            data = json.loads(str(raw))
        except json.JSONDecodeError:
            return {"ok": False, "reason": "bad_response"}
        return data if isinstance(data, dict) else {"ok": False}

    def is_analysis_running(self) -> bool:
        try:
            return bool(self.bridge.invoke_java_out_of_band(lambda ep: ep.isAnalysisRunning()))
        except Exception as e:
            if _java_rpc_method_missing(e):
                return False
            raise

    def list_functions(self) -> list[dict[str, str]]:
        return self._invoke_json_object_rows(lambda ep: ep.listFunctionsJson(), empty=[])

    def list_functions_page(
        self, *, offset: int = 0, limit: int = 1000, name_filter: str = ""
    ) -> dict[str, Any]:
        """
        One window of the function list, filtered and windowed inside the JVM.

        Rows carry ``name``, ``address``, ``size``, ``is_thunk``, ``is_external`` and ``signature``.
        """
        off = max(0, int(offset))
        lim = max(1, min(int(limit), 50_000))
        needle = name_filter or ""

        def _fallback() -> list[dict[str, str]]:
            rows = self.list_functions()
            if needle:
                low = needle.lower()
                rows = [r for r in rows if low in str(r.get("name", "")).lower()]
            return rows

        return self._invoke_page(
            lambda ep: ep.listFunctionsPageJson(off, lim, needle),
            fallback=_fallback,
            offset=off,
            limit=lim,
        )

    def decompile_function(self, address: str, *, timeout_s: int | None = None) -> str:
        if timeout_s is None:
            return str(self.bridge.invoke_java(lambda ep: ep.decompileFunction(address)))
        budget = max(1, min(int(timeout_s), 600))
        try:
            return str(
                self.bridge.invoke_java(lambda ep: ep.decompileFunctionWithTimeout(address, budget))
            )
        except Exception as e:
            if _java_rpc_method_missing(e):
                return str(self.bridge.invoke_java(lambda ep: ep.decompileFunction(address)))
            raise

    def get_disassembly(self, address: str, length: int) -> str:
        return str(self.bridge.invoke_java(lambda ep: ep.getDisassembly(address, int(length))))

    def get_hex_dump(self, address: str, max_bytes: int = 4096, bytes_per_line: int = 16) -> str:
        msg = (
            "# Rebuild the Java bridge for the hex view:\n"
            "#   python -m rawview.scripts.compile_java\n"
        )
        try:
            return str(
                self.bridge.invoke_java(
                    lambda ep: ep.getHexDumpText(address, int(max_bytes), int(bytes_per_line))
                )
            )
        except Exception as e1:
            if _java_rpc_method_missing(e1):
                return msg
            try:
                return str(self.bridge.invoke_java(lambda ep: ep.getHexDumpText(address, int(max_bytes))))
            except Exception as e2:
                if _java_rpc_method_missing(e2):
                    return msg
                raise e2 from e1

    def advance_program_address(self, address: str, delta_bytes: int) -> str:
        try:
            return str(
                self.bridge.invoke_java(lambda ep: ep.advanceProgramAddress(address, int(delta_bytes)))
            ).strip()
        except Exception as e:
            if _java_rpc_method_missing(e):
                return ""
            raise

    def get_strings(self) -> list[dict[str, str]]:
        return self._invoke_json_object_rows(lambda ep: ep.getStringsJson(), empty=[])

    def get_strings_page(
        self, *, offset: int = 0, limit: int = 1000, min_length: int = 0
    ) -> dict[str, Any]:
        """One window of the defined strings; ``min_length`` drops short noise inside the JVM."""
        off = max(0, int(offset))
        lim = max(1, min(int(limit), 50_000))
        min_len = max(0, int(min_length))

        def _fallback() -> list[dict[str, str]]:
            rows = self.get_strings()
            if min_len:
                rows = [r for r in rows if len(str(r.get("value", ""))) >= min_len]
            return rows

        return self._invoke_page(
            lambda ep: ep.getStringsPageJson(off, lim, min_len),
            fallback=_fallback,
            offset=off,
            limit=lim,
        )

    def get_imports(self) -> list[dict[str, str]]:
        return self._invoke_json_object_rows(lambda ep: ep.getImportsJson(), empty=[])

    def get_exports(self) -> list[dict[str, str]]:
        return self._invoke_json_object_rows(lambda ep: ep.getExportsJson(), empty=[])

    def get_symbols(self) -> list[dict[str, str]]:
        return self._invoke_json_object_rows(lambda ep: ep.getSymbolsJson(), empty=[])

    def get_symbols_page(
        self, *, offset: int = 0, limit: int = 500, name_filter: str = ""
    ) -> dict[str, Any]:
        """One window of the non-external symbols, filtered and windowed inside the JVM."""
        off = max(0, int(offset))
        lim = max(1, min(int(limit), 50_000))
        needle = name_filter or ""

        def _fallback() -> list[dict[str, str]]:
            rows = self.get_symbols()
            if needle:
                low = needle.lower()
                rows = [r for r in rows if low in str(r.get("name", "")).lower()]
            return rows

        return self._invoke_page(
            lambda ep: ep.getSymbolsPageJson(off, lim, needle),
            fallback=_fallback,
            offset=off,
            limit=lim,
        )

    def get_entry_points(self) -> list[dict[str, str]]:
        return self._invoke_json_object_rows(lambda ep: ep.getEntryPointsJson(), empty=[])

    def get_image_base_address(self) -> str:
        return str(self.bridge.invoke_java(lambda ep: ep.getImageBaseAddress())).strip()

    def get_xrefs_to(self, address: str) -> list[dict[str, str]]:
        return self._invoke_json_object_rows(lambda ep: ep.getXrefsToJson(address), empty=[])

    def get_xrefs_from(self, address: str) -> list[dict[str, str]]:
        return self._invoke_json_object_rows(lambda ep: ep.getXrefsFromJson(address), empty=[])

    def rename_function(self, address: str, new_name: str) -> dict[str, Any]:
        raw = str(self.bridge.invoke_java(lambda ep: ep.renameFunction(address, new_name)))
        return json.loads(raw)

    def set_comment(self, address: str, text: str, comment_type: str = "EOL") -> dict[str, Any]:
        """Set a comment. ``comment_type`` is EOL, PRE, POST, PLATE or REPEATABLE."""
        kind = (comment_type or "EOL").strip().upper()
        if kind == "EOL":
            raw = str(self.bridge.invoke_java(lambda ep: ep.setComment(address, text)))
            return json.loads(raw)
        try:
            raw = str(self.bridge.invoke_java(lambda ep: ep.setCommentOfType(address, text, kind)))
        except Exception as e:
            if _java_rpc_method_missing(e):
                raw = str(self.bridge.invoke_java(lambda ep: ep.setComment(address, text)))
            else:
                raise
        return json.loads(raw)

    def search_bytes(self, pattern: str, *, max_matches: int = 64) -> dict[str, Any]:
        """
        Find every occurrence of a byte pattern.

        ``pattern`` is hex bytes with or without separators, and ``??`` marks a wildcard byte.
        """
        limit = max(1, min(int(max_matches), 1000))
        try:
            raw = str(self.bridge.invoke_java(lambda ep: ep.searchBytesLimitJson(pattern, limit)))
        except Exception as e:
            if _java_rpc_method_missing(e):
                raw = str(self.bridge.invoke_java(lambda ep: ep.searchBytesJson(pattern)))
            else:
                raise
        return json.loads(raw)

    def get_data_at(self, address: str) -> dict[str, Any]:
        raw = str(self.bridge.invoke_java(lambda ep: ep.getDataAtJson(address)))
        return json.loads(raw)

    def get_control_flow_graph(self, address: str) -> dict[str, Any]:
        raw = str(self.bridge.invoke_java(lambda ep: ep.getControlFlowGraphJson(address)))
        return json.loads(raw)

    def get_call_graph(
        self, address: str, *, depth: int = 2, direction: str = "both"
    ) -> dict[str, Any]:
        """
        Call graph around ``address``: ``{root, nodes, edges, truncated}``.

        ``direction`` is ``callers``, ``callees`` or ``both``. Edges always point caller -> callee.
        """
        depth_i = max(1, min(int(depth), 5))
        raw = str(
            self.bridge.invoke_java(lambda ep: ep.getCallGraphJson(address, depth_i, direction))
        )
        data = json.loads(raw)
        return data if isinstance(data, dict) else {"nodes": [], "edges": []}

    def get_function_at(self, address: str) -> dict[str, Any]:
        """The function at or containing ``address``, or ``{"error": "no_function"}``."""
        raw = str(self.bridge.invoke_java(lambda ep: ep.getFunctionAtJson(address)))
        data = json.loads(raw)
        return data if isinstance(data, dict) else {"error": "no_function"}

    def rename_variable(self, function_address: str, old_name: str, new_name: str) -> dict[str, Any]:
        raw = str(
            self.bridge.invoke_java(
                lambda ep: ep.renameVariable(function_address, old_name, new_name)
            )
        )
        return json.loads(raw)

    def create_struct(self, address: str, struct_definition: str) -> dict[str, Any]:
        raw = str(self.bridge.invoke_java(lambda ep: ep.createStruct(address, struct_definition)))
        return json.loads(raw)

    def set_function_signature(self, address: str, signature: str) -> dict[str, Any]:
        raw = str(self.bridge.invoke_java(lambda ep: ep.setFunctionSignature(address, signature)))
        return json.loads(raw)

    def search_program(
        self, query: str, *, limit_per_kind: int = 50, kinds: str = ""
    ) -> dict[str, Any]:
        """
        One substring search over functions, symbols, strings, imports, exports and data labels.

        ``kinds`` narrows it to a comma-separated subset; empty means everything. The result is
        ``{query, results, count, truncated}`` where each result carries ``kind``, ``address``,
        ``name`` and ``detail``.
        """
        raw = str(
            self.bridge.invoke_java(
                lambda ep: ep.searchProgramJson(query, int(limit_per_kind), kinds)
            )
        )
        data = json.loads(raw)
        return data if isinstance(data, dict) else {"results": [], "count": 0}

    def list_segments(self) -> list[dict[str, Any]]:
        """Memory map: one row per block, with permissions."""
        raw = str(self.bridge.invoke_java(lambda ep: ep.listSegmentsJson()))
        data = json.loads(raw)
        return data if isinstance(data, list) else []

    def list_namespaces(self) -> list[dict[str, str]]:
        """Namespaces and classes defined in the program."""
        return self._invoke_json_object_rows(lambda ep: ep.listNamespacesJson(), empty=[])

    def list_data_items(self, offset: int = 0, limit: int = 500) -> dict[str, Any]:
        """Defined, labelled data: globals, tables, structures."""
        raw = str(
            self.bridge.invoke_java(lambda ep: ep.listDataItemsJson(int(offset), int(limit)))
        )
        data = json.loads(raw)
        return data if isinstance(data, dict) else {"rows": [], "count": 0}

    def rename_data(self, address: str, new_name: str) -> dict[str, Any]:
        """Rename (or create) the label at ``address``."""
        raw = str(self.bridge.invoke_java(lambda ep: ep.renameDataJson(address, new_name)))
        return json.loads(raw)

    def set_local_variable_type(
        self, function_address: str, variable_name: str, type_name: str
    ) -> dict[str, Any]:
        """Retype one local or parameter, as retyping it in the decompiler would."""
        raw = str(
            self.bridge.invoke_java(
                lambda ep: ep.setLocalVariableTypeJson(function_address, variable_name, type_name)
            )
        )
        return json.loads(raw)

    def patch_bytes(self, address: str, hex_bytes: str) -> dict[str, Any]:
        """Overwrite the bytes at ``address``. Returns the original and patched bytes as hex."""
        raw = str(self.bridge.invoke_java(lambda ep: ep.patchBytesJson(address, hex_bytes)))
        return json.loads(raw)

    def assemble_instruction(
        self, address: str, instruction: str, *, apply: bool = False
    ) -> dict[str, Any]:
        """
        Assemble one instruction for ``address``.

        With ``apply`` false nothing is written: the result carries the encoding, its length and
        the length of the instruction it would replace, which is what tells you whether it fits.
        """
        raw = str(
            self.bridge.invoke_java(
                lambda ep: ep.assembleInstructionJson(address, instruction, bool(apply))
            )
        )
        return json.loads(raw)

    def list_patches(self) -> dict[str, Any]:
        """Every byte run that differs from the imported file: ``{runs, count, truncated}``."""
        raw = str(self.bridge.invoke_java(lambda ep: ep.listPatchesJson()))
        return json.loads(raw)

    def revert_patch(self, address: str, length: int = 0) -> dict[str, Any]:
        """Restore the original file bytes at ``address``; ``length`` 0 reverts the whole run."""
        raw = str(self.bridge.invoke_java(lambda ep: ep.revertPatchJson(address, int(length))))
        return json.loads(raw)

    def export_patched_file(self, out_path: str) -> dict[str, Any]:
        """
        Write the imported file back out with every patch applied.

        The JVM may not be able to write where the user asked (the sandbox hides their
        directories), in which case it writes into the project dir and the file is moved into
        place here, where there is no sandbox to get in the way.
        """
        jvm_path, staged = self.bridge.jvm_output_path(out_path)
        raw = str(self.bridge.invoke_java(lambda ep: ep.exportPatchedFileJson(jvm_path)))
        result = json.loads(raw)
        if staged is None:
            return result
        if not result.get("ok"):
            staged.unlink(missing_ok=True)
            return result
        try:
            destination = Path(out_path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(staged), str(destination))
            result["path"] = str(destination.resolve())
        except OSError as e:
            staged.unlink(missing_ok=True)
            return {"error": "write_failed", "hint": str(e)[:300], "path": out_path}
        return result

    def close_all(self) -> None:
        self.bridge.invoke_java(lambda ep: ep.closeAll())

    def flush_program_to_disk(self) -> None:
        self.bridge.invoke_java(lambda ep: ep.flushProgramToDisk())

    def get_re_session_meta(self) -> dict[str, str]:
        raw = str(self.bridge.invoke_java(lambda ep: ep.getReSessionMetaJson()))
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if not isinstance(data, dict):
            return {}
        return {str(k): str(v) for k, v in data.items()}

    def open_saved_project(
        self,
        projects_parent: str,
        project_folder: str,
        program_folder: str,
        program_domain: str,
    ) -> str:
        return str(
            self.bridge.invoke_java(
                lambda ep: ep.openSavedProject(
                    projects_parent,
                    project_folder,
                    program_folder,
                    program_domain,
                )
            )
        )
