"""MCP support: let any MCP client drive the running RawView window."""

from __future__ import annotations

import shutil
import sys


def rawview_mcp_command() -> list[str]:
    """
    The argv that starts the RawView MCP stdio server for this installation.

    A pip install puts ``rawview-mcp`` on PATH. A packaged (frozen) build has no console
    scripts and no system Python, so it re-enters its own executable with ``--mcp``, which
    runs the server instead of opening a window. A source checkout with neither falls back
    to ``python -m rawview.mcp.server``.

    Returned as a list so it can go straight into a Claude Code ``--mcp-config`` file or a
    ``subprocess`` call without shell quoting.
    """
    if getattr(sys, "frozen", False):
        return [sys.executable, "--mcp"]
    script = shutil.which("rawview-mcp")
    if script:
        return [script]
    return [sys.executable, "-m", "rawview.mcp.server"]
