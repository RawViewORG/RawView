"""Bridge smoke test: start JVM, open a PE, run auto-analysis, list functions. Run from repo root."""
from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root))
    _default_ghidra_versions = ("ghidra_12.1.3_PUBLIC", "ghidra_12.0.4_PUBLIC", "ghidra_11.4.3_PUBLIC")
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share")))
    rpa = base / "RawView" / "ghidra_bundle" / "ghidra_extract"
    cand = next((rpa / v for v in _default_ghidra_versions if (rpa / v).is_dir()), None)
    if cand is not None:
        os.environ.setdefault("GHIDRA_INSTALL_DIR", str(cand))

    from rawview.config import load_settings
    from rawview.ghidra.api import GhidraAPI
    from rawview.ghidra.bridge import GhidraBridgeController, default_java_executable

    s = load_settings()
    gdir = s.ghidra_install_dir or Path(os.environ["GHIDRA_INSTALL_DIR"])
    jcd = s.rawview_java_classes_dir
    if jcd is None:
        cand = root / "rawview" / "java" / "out"
        if (cand / "io" / "rawview" / "ghidra" / "GhidraServer.class").is_file():
            jcd = cand

    bridge = GhidraBridgeController(
        ghidra_install_dir=gdir,
        java_executable=default_java_executable(s.java_executable, ghidra_install_dir=gdir),
        jvm_max_heap=s.ghidra_jvm_max_heap,
        py4j_port=s.py4j_port,
        project_dir=s.rawview_project_dir,
        java_classes_dir=jcd,
        raw_classpath=s.rawview_java_classpath,
        sandbox=s.rawview_sandbox,
    )
    api = GhidraAPI(bridge=bridge)
    print("starting JVM…", flush=True)
    bridge.start()
    print("ping:", api.ping(), flush=True)
    _default_bin = r"C:\Windows\System32\hostname.exe" if sys.platform == "win32" else "/bin/ls"
    test_bin = os.environ.get("RAWVIEW_TEST_BINARY", _default_bin)
    print("open:", test_bin, flush=True)
    name = api.open_file(test_bin)
    print("program:", name, flush=True)
    print("run_auto_analysis…", flush=True)
    print("analysis:", api.run_auto_analysis(), flush=True)
    fns = api.list_functions()
    print("function_count:", len(fns), flush=True)
    for f in fns[:12]:
        print(" ", f, flush=True)
    failures = _check_engine(api, test_bin)
    bridge.stop()
    if failures:
        for f in failures:
            print("FAIL:", f, flush=True)
        print("TEST_FAIL", flush=True)
        return 1
    print("TEST_PASS", flush=True)
    return 0


def _check_engine(api: "GhidraAPI", test_bin: str = "") -> list[str]:  # noqa: F821
    """Exercise the parts of the bridge that need a real program, returning human-readable failures."""
    failures: list[str] = []

    def check(label: str, ok: bool, detail: object = "") -> None:
        print(f"  {'ok  ' if ok else 'FAIL'} {label}: {detail}", flush=True)
        if not ok:
            failures.append(f"{label} -> {detail!r}")

    print("engine checks…", flush=True)

    entries = api.get_entry_points()
    check("entry_points", len(entries) > 0, entries[:3])

    exports = api.get_exports()
    check("exports", isinstance(exports, list), f"{len(exports)} rows")

    page = api.list_functions_page(offset=0, limit=5)
    check(
        "list_functions_page",
        page.get("count", 0) > 0 and "size" in (page.get("rows") or [{}])[0],
        {k: page.get(k) for k in ("total", "count", "truncated")},
    )

    strings = api.get_strings_page(offset=0, limit=5, min_length=4)
    check("get_strings_page", strings.get("count", 0) >= 0, strings.get("total"))

    symbols = api.get_symbols_page(offset=0, limit=5)
    check("get_symbols_page", symbols.get("count", 0) >= 0, symbols.get("total"))

    rows = page.get("rows") or []
    target = next((r for r in rows if not r.get("is_thunk")), rows[0] if rows else None)
    if target is None:
        failures.append("no function to exercise")
        return failures
    addr = str(target["address"])

    # A hex window that runs past the end of a memory block must return the readable prefix.
    dump = api.get_hex_dump(addr, 65536, 16)
    check("hex_dump_partial", "bytes=" in dump.splitlines()[0], dump.splitlines()[0][:60])

    # Addresses as the agent tends to write them.
    check("address_0x_prefix", "invalid_address" not in api.get_data_at("0x" + addr), "0x" + addr)

    search = api.search_bytes("48 89 ??", max_matches=8)
    check("search_wildcards", "matches" in search, {k: search.get(k) for k in ("count", "wildcards")})

    # Call graph: depth 1 in one direction must only produce edges that touch the root.
    graph = api.get_call_graph(addr, depth=1, direction="callers")
    root = str(graph.get("root", ""))
    edges = graph.get("edges") or []
    check(
        "call_graph_callers",
        "error" not in graph and all(str(e.get("to")) == root for e in edges),
        {"nodes": len(graph.get("nodes") or []), "edges": len(edges)},
    )
    graph_out = api.get_call_graph(addr, depth=2, direction="both")
    check(
        "call_graph_both",
        len(graph_out.get("nodes") or []) >= len(graph.get("nodes") or []),
        {"nodes": len(graph_out.get("nodes") or []), "truncated": graph_out.get("truncated")},
    )
    check(
        "call_graph_bad_direction",
        api.get_call_graph(addr, depth=1, direction="sideways").get("error") == "bad_direction",
        "rejected",
    )

    # An address inside a body resolves to the function that contains it, not to nothing.
    fn_at = api.get_function_at(addr)
    inside = api.get_function_at(hex(int(addr, 16) + 1))
    check("function_at_entry", fn_at.get("address", "").lower() == addr.lower(), fn_at.get("name"))
    check(
        "function_at_inside_body",
        int(fn_at.get("size", 0)) < 2 or inside.get("address") == fn_at.get("address"),
        inside.get("name"),
    )

    sig = api.set_function_signature(addr, "int rawview_smoke(char *buf, unsigned long len)")
    check("set_function_signature", bool(sig.get("ok")), sig)

    # The prototype must reach the decompiler; the function keeps its own name unless it was a default one.
    decompiled = api.decompile_function(addr)
    check(
        "signature_visible_in_decompile",
        "buf" in decompiled and "len" in decompiled,
        next((ln for ln in decompiled.splitlines() if "buf" in ln), decompiled[:60]),
    )

    struct = api.create_struct("", "struct RawViewSmoke { int magic; char name[8]; void *next; };")
    check("create_struct", bool(struct.get("ok")) and struct.get("size", 0) > 0, struct)

    comment = api.set_comment(addr, "rawview smoke test", "PLATE")
    check("set_comment_plate", bool(comment.get("ok")), comment)

    renamed = api.rename_function(addr, "rawview_smoke_renamed")
    check("rename_function", bool(renamed.get("ok")), renamed)

    # One query across every listing, and the kind filter that narrows it.
    found = api.search_program(target["name"][:6], limit_per_kind=5)
    check(
        "search_program",
        found.get("count", 0) > 0 and all("kind" in h for h in found.get("results", [])),
        {"count": found.get("count"), "kinds": sorted({h["kind"] for h in found.get("results", [])})},
    )
    only_strings = api.search_program("a", limit_per_kind=3, kinds="strings")
    check(
        "search_kind_filter",
        all(h["kind"] == "string" for h in only_strings.get("results", [])),
        f"{len(only_strings.get('results', []))} rows, all strings",
    )
    check(
        "search_by_address",
        any(h["kind"] == "address" for h in api.search_program(addr).get("results", [])),
        addr,
    )
    check("search_empty_query", api.search_program("").get("error") == "empty_query", "rejected")

    segments = api.list_segments()
    check(
        "list_segments",
        bool(segments) and all({"start", "end", "execute"} <= set(s_) for s_ in segments),
        f"{len(segments)} blocks",
    )
    data_items = api.list_data_items(0, 5)
    check("list_data_items", data_items.get("count", 0) >= 0, data_items.get("count"))
    check("list_namespaces", isinstance(api.list_namespaces(), list), len(api.list_namespaces()))

    # Patching: write bytes, see them in the patch list, put them back.
    before_dump = api.get_hex_dump(addr, 16, 16)
    patched = api.patch_bytes(addr, "90 90 90 90")
    check("patch_bytes", bool(patched.get("ok")) and patched.get("length") == 4, patched.get("patched"))
    runs = api.list_patches()
    mine = [r for r in runs.get("runs", []) if str(r.get("address", "")).lower() == addr.lower()]
    check("list_patches_sees_it", bool(mine), {"count": runs.get("count"), "mine": len(mine)})
    reverted = api.revert_patch(addr)
    check("revert_patch", bool(reverted.get("ok")), reverted.get("reverted"))
    check("revert_restores_bytes", api.get_hex_dump(addr, 16, 16) == before_dump, "byte-identical")

    # Relocations are Ghidra's own edits and must not be reported as user patches.
    check(
        "patch_list_excludes_relocations",
        api.list_patches().get("count", 0) == 0,
        "clean after revert",
    )

    # Assembling: a dry run writes nothing and still reports whether the encoding fits.
    dry = api.assemble_instruction(addr, "NOP", apply=False)
    check(
        "assemble_dry_run",
        bool(dry.get("ok")) and dry.get("applied") is False and dry.get("length", 0) > 0,
        {k: dry.get(k) for k in ("bytes", "length", "replaced_length", "overruns")},
    )
    check(
        "assemble_rejects_nonsense",
        api.assemble_instruction(addr, "DEFINITELY NOT AN INSTRUCTION").get("error")
        == "assembly_failed",
        "rejected",
    )

    # Export writes the imported file back out, patches and all.
    import tempfile

    out_path = str(Path(tempfile.gettempdir()) / "rawview_smoke_export.bin")
    exported = api.export_patched_file(out_path)
    check(
        "export_patched_file",
        bool(exported.get("ok")) and int(exported.get("bytes", 0)) > 0,
        {"bytes": exported.get("bytes"), "source": exported.get("source")},
    )
    try:
        Path(out_path).unlink(missing_ok=True)
    except OSError:
        pass

    # Comparing a program with itself is the one diff whose answer is known in advance.
    check("diff_without_comparison", api.diff_programs().get("error") == "no_comparison_program", "rejected")
    opened = api.open_comparison_file(test_bin)
    check("open_comparison_file", bool(opened.get("ok")), opened.get("name"))
    if opened.get("ok"):
        api.analyze_comparison_program()
        self_diff = api.diff_programs()
        check(
            "diff_self_is_clean",
            not self_diff.get("changed") and not self_diff.get("only_in_a")
            and not self_diff.get("only_in_b"),
            {k: len(self_diff.get(k, [])) for k in ("changed", "only_in_a", "only_in_b")},
        )
        check("diff_self_matches_all", self_diff.get("identical", 0) > 0, self_diff.get("identical"))
        api.close_comparison_program()
    check(
        "open_comparison_rejects_missing_file",
        api.open_comparison_file(test_bin + ".nope").get("error") == "not_a_file",
        "rejected",
    )

    check("cancel_analysis_when_idle", api.cancel_analysis().get("ok") is False, "no analysis running")
    check("is_analysis_running", api.is_analysis_running() is False, False)

    return failures


if __name__ == "__main__":
    raise SystemExit(main())
