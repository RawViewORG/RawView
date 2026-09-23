"""
Loopback HTTP endpoint that lets an MCP client drive the running RawView.

The point of driving the *running* app rather than starting a second headless Ghidra is that the
tools then act on the program the user is looking at: ``get_current_address`` means something,
``navigate_to`` moves their window, and a rename they asked for shows up in front of them. A
detached server would have its own JVM, its own program and no idea what the user is doing.

Access control, in order of what actually stops what:

* The socket binds to loopback only, so nothing off this machine can reach it.
* Every request must carry the bearer token from ``mcp.json``, which is written 0600 in the user
  data directory. That is what separates RawView's own client from another local user.
* Requests carrying an ``Origin`` header are refused outright. A web page cannot read a
  cross-origin response, but it can send the request, and a DNS-rebinding page could otherwise
  reach a loopback service with the victim's own browser. MCP clients never send ``Origin``.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Bigger than any sane tool call; stops a stray client from making us buffer a program image.
_MAX_BODY_BYTES = 4 * 1024 * 1024


def mcp_config_path() -> Path:
    """Where the port and token live, for the stdio server to read."""
    from rawview.config import user_data_dir

    return user_data_dir() / "mcp.json"


class RawViewMcpEndpoint:
    """Serves the agent's tool registry over loopback HTTP for MCP clients."""

    def __init__(
        self,
        *,
        list_tools: Callable[[], list[dict[str, Any]]],
        call_tool: Callable[[str, dict[str, Any]], str],
        status: Callable[[], dict[str, Any]],
        port: int = 0,
    ) -> None:
        self._list_tools = list_tools
        self._call_tool = call_tool
        self._status = status
        self._requested_port = int(port)
        self._token = secrets.token_urlsafe(32)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def port(self) -> int:
        return self._server.server_address[1] if self._server else 0

    @property
    def token(self) -> str:
        return self._token

    def start(self) -> int:
        """Bind, serve in a background thread, and publish the config file. Returns the port."""
        if self._server is not None:
            return self.port
        handler = _make_handler(self)
        self._server = ThreadingHTTPServer(("127.0.0.1", self._requested_port), handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="rawview-mcp-endpoint", daemon=True
        )
        self._thread.start()
        self._write_config()
        logger.info("MCP endpoint listening on 127.0.0.1:%s", self.port)
        return self.port

    def stop(self) -> None:
        if self._server is None:
            return
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            logger.debug("MCP endpoint shutdown", exc_info=True)
        self._server = None
        self._thread = None
        # Leaving a config file behind would point clients at a port nobody is listening on.
        try:
            mcp_config_path().unlink(missing_ok=True)
        except OSError:
            logger.debug("could not remove mcp config", exc_info=True)

    def _write_config(self) -> None:
        path = mcp_config_path()
        payload = {"host": "127.0.0.1", "port": self.port, "token": self._token, "pid": os.getpid()}
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            # Windows does not honour these bits; the token is still only in the user's profile.
            logger.debug("could not chmod mcp config", exc_info=True)


def _make_handler(endpoint: RawViewMcpEndpoint) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "RawView-MCP/1"

        def log_message(self, fmt: str, *args: Any) -> None:
            logger.debug("mcp endpoint: " + fmt, *args)

        def _write(self, code: int, body: bytes) -> None:
            # A client that hangs up mid-request (cancelled tool call, closed session) leaves a
            # broken/reset socket; that is normal, not a server fault, so swallow it quietly
            # instead of letting socketserver dump a traceback.
            try:
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                logger.debug("mcp endpoint: client disconnected before the response was sent")

        def _reject(self, code: int, message: str) -> None:
            self._write(code, json.dumps({"error": message}).encode("utf-8"))

        def _send(self, payload: dict[str, Any]) -> None:
            self._write(200, json.dumps(payload).encode("utf-8"))

        def _authorized(self) -> bool:
            if self.headers.get("Origin"):
                self._reject(403, "requests from a browser origin are refused")
                return False
            header = self.headers.get("Authorization", "")
            token = header[7:].strip() if header.lower().startswith("bearer ") else ""
            if not token or not secrets.compare_digest(token, endpoint.token):
                self._reject(401, "missing or bad bearer token")
                return False
            return True

        # Named by BaseHTTPRequestHandler's dispatch, not by choice.
        def do_GET(self) -> None:
            if not self._authorized():
                return
            if self.path == "/mcp/tools":
                self._send({"tools": endpoint._list_tools()})
            elif self.path == "/mcp/status":
                self._send(endpoint._status())
            else:
                self._reject(404, "no such path")

        def do_POST(self) -> None:
            if not self._authorized():
                return
            if self.path != "/mcp/call":
                self._reject(404, "no such path")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._reject(400, "bad Content-Length")
                return
            if length <= 0 or length > _MAX_BODY_BYTES:
                self._reject(413, "body missing or too large")
                return
            try:
                request = json.loads(self.rfile.read(length).decode("utf-8", errors="replace"))
            except json.JSONDecodeError as e:
                self._reject(400, f"bad JSON: {e}")
                return
            name = str(request.get("name", ""))
            arguments = request.get("arguments") or {}
            if not name or not isinstance(arguments, dict):
                self._reject(400, "expected {name, arguments}")
                return
            try:
                result = endpoint._call_tool(name, arguments)
            except Exception as e:
                # A failing tool is an answer for the model to read, not a transport error.
                logger.exception("MCP tool %s failed", name)
                self._send({"result": json.dumps({"error": str(e)[:600]}), "is_error": True})
                return
            self._send({"result": result, "is_error": False})

    return Handler
