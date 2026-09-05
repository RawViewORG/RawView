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
    failures = _check_engine(api)
    bridge.stop()
    if failures:
        for f in failures:
            print("FAIL:", f, flush=True)
        print("TEST_FAIL", flush=True)
        return 1
    print("TEST_PASS", flush=True)
    return 0


def _check_engine(api: "GhidraAPI") -> list[str]:  # noqa: F821
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

    check("cancel_analysis_when_idle", api.cancel_analysis().get("ok") is False, "no analysis running")
    check("is_analysis_running", api.is_analysis_running() is False, False)

    return failures


if __name__ == "__main__":
    raise SystemExit(main())
