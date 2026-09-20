"""
``rawview-mcp``: an MCP server that hands RawView's tools to any MCP client.

This is what lets someone use the agent without an Anthropic API key: Claude Code (or Claude
Desktop, or any other MCP client) spawns this process, and their existing subscription drives
RawView's 48 Ghidra tools. The model comes from the client; RawView supplies the reverse
engineering.

It is a thin pipe on purpose. All it does is forward to the RawView window that is already open,
so the tools act on the program the user is looking at rather than on a second, invisible copy of
Ghidra. Start RawView and turn on "Allow MCP clients" in File -> Settings; this process finds the
port and token in ``mcp.json`` under the user data directory.

Speaks JSON-RPC 2.0 over stdin/stdout, one message per line, implemented directly rather than
through an SDK so the packaged app gains no dependency for it.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from typing import Any

# Versions of the MCP spec this server knows how to talk. A client asking for one of these gets
# it back; anything else is answered with the newest, which is what the spec says to do.
_SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
_DEFAULT_PROTOCOL = _SUPPORTED_PROTOCOLS[0]
_HTTP_TIMEOUT_S = 600.0  # analyzing a large binary is a legitimate tool call

_NOT_RUNNING = (
    "RawView is not accepting MCP connections. Start RawView, then turn on "
    "File -> Settings -> Allow MCP clients to drive RawView."
)


def _config() -> dict[str, Any]:
    from rawview.mcp.endpoint import mcp_config_path

    path = mcp_config_path()
    if not path.is_file():
        raise RuntimeError(_NOT_RUNNING)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise RuntimeError(f"Could not read {path}: {e}") from e
    if not data.get("port") or not data.get("token"):
        raise RuntimeError(_NOT_RUNNING)
    return data


def _request(method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = _config()
    url = f"http://{cfg.get('host', '127.0.0.1')}:{cfg['port']}{path}"
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {cfg['token']}",
            "Content-Type": "application/json",
        },
    )
    try:
        # Loopback, to the address this app itself wrote into mcp.json.
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.URLError as e:
        # The config file outlives a crash, so "connection refused" means the window is gone.
        raise RuntimeError(f"{_NOT_RUNNING} ({e.reason})") from e


def _tools() -> list[dict[str, Any]]:
    """RawView's tool list, in MCP's shape."""
    listed = _request("GET", "/mcp/tools").get("tools") or []
    out = []
    for tool in listed:
        out.append(
            {
                "name": tool["name"],
                "description": tool.get("description", ""),
                # The agent registry calls it input_schema; MCP calls it inputSchema.
                "inputSchema": tool.get("input_schema") or {"type": "object", "properties": {}},
            }
        )
    return out


def _call(name: str, arguments: dict[str, Any]) -> tuple[str, bool]:
    answer = _request("POST", "/mcp/call", {"name": name, "arguments": arguments})
    return str(answer.get("result", "")), bool(answer.get("is_error"))


def _handle(message: dict[str, Any]) -> dict[str, Any] | None:
    """Answer one JSON-RPC message, or None when it is a notification that needs no reply."""
    method = str(message.get("method", ""))
    msg_id = message.get("id")

    if msg_id is None:
        # Notifications (initialized, cancelled, ...) are acknowledged by saying nothing.
        return None

    def ok(result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def fail(code: int, text: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": text}}

    if method == "initialize":
        asked = str((message.get("params") or {}).get("protocolVersion", ""))
        version = asked if asked in _SUPPORTED_PROTOCOLS else _DEFAULT_PROTOCOL
        return ok(
            {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "rawview", "version": _version()},
                "instructions": (
                    "These tools drive a running RawView window: a Qt front end for Ghidra. They act "
                    "on the binary the user currently has open, and navigation moves their actual "
                    "view. Call get_current_address or get_current_function when the user says "
                    "'this function' or 'here'. Tools that modify the program (rename_*, set_*, "
                    "patch_bytes, assemble_instruction with apply) change the user's analysis "
                    "database, so say what you are about to change before changing it."
                ),
            }
        )

    if method == "ping":
        return ok({})

    if method == "tools/list":
        try:
            return ok({"tools": _tools()})
        except RuntimeError as e:
            return fail(-32000, str(e))

    if method == "tools/call":
        params = message.get("params") or {}
        name = str(params.get("name", ""))
        arguments = params.get("arguments") or {}
        if not name:
            return fail(-32602, "tools/call needs a name")
        if not isinstance(arguments, dict):
            return fail(-32602, "arguments must be an object")
        try:
            text, is_error = _call(name, arguments)
        except RuntimeError as e:
            # Reported as tool output, not a protocol error: the model can then tell the user to
            # start RawView instead of the client dropping the connection.
            return ok({"content": [{"type": "text", "text": str(e)}], "isError": True})
        return ok({"content": [{"type": "text", "text": text}], "isError": is_error})

    return fail(-32601, f"method not found: {method}")


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("rawview")
    except Exception:  # noqa: BLE001 - a missing dist is not worth failing a handshake over
        return "0"


def main() -> int:
    """Read JSON-RPC from stdin, write answers to stdout, until stdin closes."""
    out = sys.stdout
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            out.write(
                json.dumps(
                    {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
                )
                + "\n"
            )
            out.flush()
            continue
        if isinstance(message, list):
            # Batches were dropped from the spec in 2025-06-18; answer each anyway for older clients.
            replies = [r for r in (_handle(m) for m in message if isinstance(m, dict)) if r]
            if replies:
                out.write(json.dumps(replies) + "\n")
                out.flush()
            continue
        if not isinstance(message, dict):
            continue
        reply = _handle(message)
        if reply is not None:
            out.write(json.dumps(reply) + "\n")
            out.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
