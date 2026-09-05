from __future__ import annotations

import logging
import os
import shutil
import site
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import py4j

if TYPE_CHECKING:
    from py4j.java_gateway import JavaGateway

logger = logging.getLogger(__name__)


class MissingJavaError(RuntimeError):
    """No usable JVM: not on PATH, no Ghidra-bundled JDK, and user did not set a valid JAVA_EXECUTABLE."""


def _find_py4j_jar() -> Path:
    """
    Return the py4j client JAR for the JVM classpath.

    Py4J wheels vary: some ship ``py4j*.jar`` next to ``py4j/__init__.py``; newer
    installs place it under ``<sys.prefix>/share/py4j/`` (no jar under site-packages).
    """
    seen: set[Path] = set()
    jars: list[Path] = []

    def collect(base: Path, pattern: str = "py4j*.jar") -> None:
        if not base.is_dir():
            return
        for j in sorted(base.glob(pattern)):
            r = j.resolve()
            if r not in seen:
                seen.add(r)
                jars.append(r)

    py4j_pkg = Path(py4j.__file__).resolve().parent
    collect(py4j_pkg)

    # PyInstaller onedir: JAR is bundled under _MEIPASS/share/py4j (sys.prefix may match _MEIPASS).
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        collect(Path(meipass) / "share" / "py4j")

    for root in {Path(sys.prefix), Path(getattr(sys, "base_prefix", sys.prefix))}:
        collect(root / "share" / "py4j")

    for sp in site.getsitepackages():
        sp_path = Path(sp).resolve()
        for up in (sp_path.parent.parent, sp_path.parent.parent.parent):
            collect(up / "share" / "py4j")

    user_site = getattr(site, "getusersitepackages", lambda: "")()
    if user_site:
        us = Path(user_site).resolve()
        for up in (us.parent.parent, us.parent.parent.parent):
            collect(up / "share" / "py4j")

    if not jars:
        raise FileNotFoundError(
            "Could not find py4j*.jar. Re-install py4j (`pip install -U py4j`) or set "
            "RAWVIEW_JAVA_CLASSPATH to include the py4j JAR (often under "
            f"{Path(sys.prefix) / 'share' / 'py4j'} on recent wheels)."
        )
    return sorted(jars)[-1]


def _write_java_argfile(path: Path, java_args: list[str]) -> None:
    """Write a UTF-8 JDK @argfile (Java 9+). One JVM argument per line; quote args that contain whitespace."""
    lines: list[str] = []
    for arg in java_args:
        if any(c in arg for c in (" ", "\t", "\n", "\r", '"')):
            esc = arg.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'"{esc}"')
        else:
            lines.append(arg)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _packaged_bridge_classes_dir() -> Path | None:
    """
    Compiled bridge classes live under ``rawview/java/out`` (repo, editable install, or PyInstaller onedir).

    PyInstaller sets ``__file__`` under ``sys._MEIPASS/rawview/ghidra/`` even when the ``.py`` is not on disk;
    bundling ``rawview/java/out`` as data next to that tree keeps resolution consistent.
    """
    rel = Path("io") / "rawview" / "ghidra" / "GhidraServer.class"

    def _try(rawview_root: Path) -> Path | None:
        out = rawview_root / "java" / "out"
        if (out / rel).is_file():
            return out
        return None

    rawview_pkg = Path(__file__).resolve().parent.parent
    hit = _try(rawview_pkg)
    if hit is not None:
        return hit
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        hit = _try(Path(meipass) / "rawview")
        if hit is not None:
            return hit
    return None


def _windows_java_cmdline_limit() -> int:
    # CreateProcess command line is ~32K UTF-16 units; stay well under with room for quoting.
    return 24_000


def _classpath_items(java_args: list[str]) -> list[str]:
    """Extract the classpath entries from a ``-cp`` java argument list."""
    try:
        i = java_args.index("-cp")
    except ValueError:
        return []
    cp = java_args[i + 1]
    sep = ";" if sys.platform == "win32" else ":"
    return [c for c in cp.split(sep) if c]


def _build_bwrap_mounts_and_rewrite(
    *,
    java_exe: Path,
    ghidra_install: Path,
    classes_root: Path,
    py4j_jar: Path,
    project_dir: Path,
    java_args: list[str],
) -> tuple[list[str], list[str]]:
    """
    Build bwrap arguments that sandbox the Ghidra JVM using a read-only root + overlay layout.

    Layout:
      --ro-bind / /   read-only whole root (so the JVM's arbitrary absolute toolchain paths resolve)
      --tmpfs over user/sensitive trees to strip real data:
          /home, /root, /media, /mnt, /srv, /var
      --ro-bind back the exact toolchain dirs that must exist under /home (Ghidra install,
          JDK, bridge classes, py4j jar) at their real absolute guest paths.
      --bind  <project_dir> <same>   the ONLY writable host tree (analyzed programs / RE sessions).
      --tmpfs /tmp + HOME=/tmp        sandbox-local temp space.

    The project dir keeps its real host absolute path so Ghidra-returned paths round-trip to RawView.
    Py4J is loopback-only, so the network namespace is shared (:func:`_classpath` uses loopback).
    With /home + /root stripped to tmpfs and only the toolchain re-bound, a compromise of the Ghidra
    process cannot read the user's wallets, .ssh, browsers, or other data.
    """
    jdk_root = java_exe.resolve().parent.parent

    bwrap_args = [
        "bwrap",
        "--unshare-pid",
        "--unshare-uts",
        "--unshare-ipc",
        "--unshare-user",
        "--die-with-parent",
        "--share-net",
        "--ro-bind",
        "/",
        "/",
        "--tmpfs",
        "/home",
        "--tmpfs",
        "/root",
        "--tmpfs",
        "/media",
        "--tmpfs",
        "/mnt",
        "--tmpfs",
        "/srv",
        "--tmpfs",
        "/var",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--ro-bind",
        "/sys",
        "/sys",
        "--tmpfs",
        "/tmp",
    ]

    toolchain_roots: list[Path] = [
        ghidra_install.resolve(),
        jdk_root,
        classes_root.resolve(),
        py4j_jar.resolve().parent,
    ]
    for root in sorted(toolchain_roots, key=lambda p: -len(p.parts)):
        bwrap_args += ["--ro-bind", str(root), str(root)]
    proj = project_dir.resolve()
    bwrap_args += ["--bind", str(proj), str(proj)]
    bwrap_args += ["--setenv", "HOME", "/tmp"]
    bwrap_args += ["--chdir", str(proj)]

    # The toolchain stays at its real host paths, so java_args need no path rewriting.
    bwrap_args.append(str(java_exe.resolve()))
    return bwrap_args, java_args


def _pick_free_loopback_tcp_port(preferred: int, *, span: int = 256) -> int:
    """
    Return a port on 127.0.0.1 that is free at probe time, scanning upward from ``preferred``.

    Used so a new JVM does not collide with a lingering RawView JVM or another process
    still bound to the configured PY4J_PORT.
    """
    lo = max(1024, int(preferred))
    hi = min(65535, lo + span)
    for port in range(lo, hi):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError(
        f"No free TCP port on 127.0.0.1 in range {lo}..{hi - 1} "
        f"(change PY4J_PORT in Settings or close the process using port {preferred})."
    )


def _jvm_output_suggests_py4j_bind_failure(text: str) -> bool:
    t = text.lower()
    return (
        "address already in use" in t
        or "failed to bind" in t
        or "bindexception" in t
        or "py4jnetworkexception" in t
    )


class BridgeState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    READY = "ready"
    FAILED = "failed"


@dataclass
class GhidraBridgeController:
    """Owns the Ghidra JVM subprocess and Py4J client.

    Py4J is not thread-safe; every remote call must go through :meth:`invoke_java`
    so RPCs do not interleave from Qt/agent worker threads (which otherwise breaks
    analysis and surfaces as errors when the JVM is shut down).
    """

    ghidra_install_dir: Path
    java_executable: str
    jvm_max_heap: str
    py4j_port: int
    project_dir: Path
    java_classes_dir: Path | None
    raw_classpath: str | None
    sandbox: str = "none"
    startup_timeout_s: float = 120.0
    # Wait for in-flight RPC before tearing down Py4J (auto-analysis can run a long time).
    # Still bounded so Quit does not hang forever on a stuck JVM.
    java_shutdown_acquire_timeout_s: float = 90.0

    _state: BridgeState = field(default=BridgeState.STOPPED, init=False)
    _proc: subprocess.Popen[str] | None = field(default=None, init=False)
    _gateway: JavaGateway | None = field(default=None, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _java_call_lock: threading.RLock = field(default_factory=threading.RLock, init=False)
    _last_error: str | None = field(default=None, init=False)
    _active_py4j_port: int = field(default=0, init=False)

    @property
    def state(self) -> BridgeState:
        return self._state

    @property
    def last_error(self) -> str | None:
        return self._last_error

    def start(self) -> None:
        with self._lock:
            if self._state == BridgeState.READY and self._proc and self._proc.poll() is None:
                return
        # Do not hold _lock across shutdown/spawn: the GUI thread calls stop() and must not deadlock
        # behind a worker that is still holding _lock during a long JVM boot.
        self._shutdown_unlocked()
        with self._lock:
            if self._state == BridgeState.READY and self._proc and self._proc.poll() is None:
                return
            self._state = BridgeState.STARTING
            self._last_error = None
        try:
            self._spawn_and_connect()
        except Exception as e:
            logger.exception("Ghidra bridge failed to start")
            with self._lock:
                self._last_error = str(e)
                self._state = BridgeState.FAILED
            self._shutdown_unlocked()
            raise
        with self._lock:
            self._state = BridgeState.READY

    def stop(self) -> None:
        # Never wait on Ghidra while holding _lock; Qt closeEvent runs on the GUI thread.
        self._shutdown_unlocked()
        with self._lock:
            self._state = BridgeState.STOPPED

    def invoke_java(self, fn: Callable[[Any], Any]) -> Any:
        """Run ``fn(entry_point)`` with exclusive access to the Py4J gateway."""
        with self._java_call_lock:
            if self._gateway is None:
                raise RuntimeError("Bridge not started")
            return fn(self._gateway.entry_point)

    def invoke_java_out_of_band(self, fn: Callable[[Any], Any]) -> Any:
        """
        Run ``fn(entry_point)`` *without* taking the RPC mutex.

        Only for calls that must reach the JVM while another RPC is in flight — cancelling an
        auto-analysis run that will otherwise hold the mutex for minutes — and only for JVM methods that
        are cheap, non-blocking and safe to enter concurrently (``cancelAnalysis``, ``isAnalysisRunning``:
        neither is ``synchronized`` on the Java side, and both only touch a volatile flag). Py4J opens a
        separate socket per calling thread, so this does not disturb the in-flight call. Anything that
        reads or mutates program state must go through :meth:`invoke_java` instead.
        """
        gw = self._gateway
        if gw is None:
            raise RuntimeError("Bridge not started")
        return fn(gw.entry_point)

    def _terminate_subprocess(self) -> None:
        if self._proc is None:
            return
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    def _shutdown_unlocked(self) -> None:
        # Prefer a short wait for in-flight Py4J (e.g. auto-analysis) so the UI thread never
        # blocks long enough for Windows to kill the process; then tear down the JVM.
        t = float(self.java_shutdown_acquire_timeout_s)
        if not self._java_call_lock.acquire(timeout=t):
            logger.warning(
                "Ghidra RPC did not finish within %ss during shutdown; terminating JVM.",
                t,
            )
            self._terminate_subprocess()
            if not self._java_call_lock.acquire(timeout=20.0):
                logger.error(
                    "Py4J mutex not released after JVM terminate; skipping gateway shutdown "
                    "(try restarting RawView if the bridge misbehaves)."
                )
                self._terminate_subprocess()
                return
        try:
            if self._gateway is not None:
                try:
                    self._gateway.shutdown()
                except Exception:
                    logger.debug("gateway.shutdown failed", exc_info=True)
                self._gateway = None
        finally:
            self._java_call_lock.release()

        self._terminate_subprocess()

    def _java_command(self, java_args: list[str]) -> tuple[list[str], Path | None]:
        """Build ``[java, …]``, using a ``@argfile`` on Windows when the command line would be too long."""
        exe = self.java_executable
        if sys.platform == "win32":
            approx = len(exe) + sum(len(a) for a in java_args) + len(java_args) + 64
            if approx > _windows_java_cmdline_limit():
                tmp = Path(os.environ.get("TEMP", os.environ.get("TMP", ".")))
                argf = tmp / f"rawview_jvm_{os.getpid()}_{time.time_ns()}.args.txt"
                _write_java_argfile(argf, java_args)
                logger.info("Using Java @argfile (command line length ~%s): %s", approx, argf)
                return [exe, f"@{argf.resolve()}"], argf
        plain = [exe] + java_args
        if self.sandbox == "bwrap" and not sys.platform.startswith("win"):
            try:
                classes_root = self.java_classes_dir
                if classes_root is None:
                    classes_root = _packaged_bridge_classes_dir()
                if classes_root is None:
                    raise FileNotFoundError("cannot resolve Java bridge classes dir for sandbox mount")
                bwrap_args, rewritten = _build_bwrap_mounts_and_rewrite(
                    java_exe=Path(exe),
                    ghidra_install=self.ghidra_install_dir,
                    classes_root=classes_root,
                    py4j_jar=_find_py4j_jar(),
                    project_dir=self.project_dir,
                    java_args=java_args,
                )
                cmd = bwrap_args + rewritten
                logger.info(
                    "Running Ghidra JVM inside bubblewrap sandbox (%d ro-binds, project rw): %s",
                    bwrap_args.count("--ro-bind"),
                    " ".join(cmd) [:240],
                )
                return cmd, None
            except Exception:
                logger.exception("bwrap sandbox build failed; falling back to unsandboxed JVM")
        return plain, None

    def _spawn_and_connect(self) -> None:
        """Start JVM + Py4J, retrying if the listen port is still occupied (stale process / race)."""
        last_err: RuntimeError | None = None
        cursor = self.py4j_port
        for attempt in range(24):
            port = _pick_free_loopback_tcp_port(cursor)
            if port != cursor and attempt > 0:
                logger.info("Retrying Ghidra JVM on Py4J port %s (attempt %s).", port, attempt + 1)
            try:
                self._spawn_and_connect_on_port(port)
                self._active_py4j_port = port
                if port != self.py4j_port:
                    logger.info(
                        "Py4J listening on %s because PY4J_PORT=%s is already in use on 127.0.0.1 "
                        "(often a leftover RawView/Java process). This is OK; close the other "
                        "process or pick a free port in Settings to use your configured port.",
                        port,
                        self.py4j_port,
                    )
                return
            except RuntimeError as e:
                last_err = e
                if not _jvm_output_suggests_py4j_bind_failure(str(e)):
                    raise
                logger.warning("Py4J bind failed on port %s: %s", port, e)
                self._terminate_subprocess()
                cursor = port + 1
                time.sleep(0.2)
        raise RuntimeError(
            f"Ghidra JVM could not bind a Py4J port after several tries (last error: {last_err})"
        ) from last_err

    def _spawn_and_connect_on_port(self, py4j_listen_port: int) -> None:
        cp = self._classpath()
        ghidra = str(self.ghidra_install_dir.resolve())
        proj = str(self.project_dir.resolve())
        heap = (self.jvm_max_heap or "8g").strip()
        java_args = [
            f"-Xmx{heap}",
            # Must be set before AWT/Ghidra classes load (main() is too late for some loaders).
            "-Djava.awt.headless=true",
            "-DSystemUtilities.isHeadless=true",
            f"-Dghidra.install.dir={ghidra}",
            "-cp",
            cp,
            "io.rawview.ghidra.GhidraServer",
            ghidra,
            proj,
            str(py4j_listen_port),
        ]
        cmd, argfile_path = self._java_command(java_args)
        logger.info("Starting Ghidra JVM: %s", " ".join(cmd[:3]) + " ...")
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        assert self._proc.stdout is not None
        deadline = time.monotonic() + self.startup_timeout_s
        ready = False
        captured: list[str] = []
        while time.monotonic() < deadline:
            line = self._proc.stdout.readline()
            if not line:
                if self._proc.poll() is not None:
                    break
                time.sleep(0.05)
                continue
            captured.append(line)
            logger.debug("ghidra-jvm: %s", line.rstrip())
            if "PY4J_RAWVIEW_READY" in line:
                ready = True
                break
        if not ready:
            extra = ""
            try:
                out_rest, _ = self._proc.communicate(timeout=5.0)
                if out_rest:
                    extra = out_rest
            except (subprocess.TimeoutExpired, ValueError):
                try:
                    extra = self._proc.stdout.read() or ""
                except ValueError:
                    extra = ""
            rest = ("".join(captured) + extra).strip()
            code = self._proc.poll()
            if argfile_path is not None:
                try:
                    argfile_path.unlink(missing_ok=True)
                except OSError:
                    logger.debug("Could not remove argfile", exc_info=True)
            if not rest:
                rest = (
                    "(no output captured - often means the Windows command line was too long, "
                    "JAVA_EXECUTABLE failed immediately, or the bridge classes are not on the classpath.)"
                )
            raise RuntimeError(f"Ghidra JVM did not become ready (exit={code}). Output:\n{rest[-8000:]}")
        if argfile_path is not None:
            try:
                argfile_path.unlink(missing_ok=True)
            except OSError:
                logger.debug("Could not remove argfile", exc_info=True)

        from py4j.java_gateway import GatewayParameters, JavaGateway

        self._gateway = JavaGateway(
            gateway_parameters=GatewayParameters(port=py4j_listen_port, auto_convert=True),
        )
        pong = self._gateway.entry_point.ping()
        if pong != "pong":
            raise RuntimeError(f"Unexpected ping response: {pong!r}")
        self._start_jvm_stdout_drain()

    def _start_jvm_stdout_drain(self) -> None:
        """Read the JVM's stdout forever; Ghidra logs to stdout and an unread PIPE deadlocks the process."""
        proc = self._proc
        if proc is None or proc.stdout is None:
            return

        def drain() -> None:
            try:
                while True:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    logger.debug("ghidra-jvm: %s", line.rstrip())
            except Exception:
                logger.debug("JVM stdout drain stopped", exc_info=True)

        threading.Thread(target=drain, name="rawview-jvm-stdout", daemon=True).start()

    def _classpath(self) -> str:
        if self.raw_classpath:
            return self.raw_classpath
        sep = ";" if sys.platform == "win32" else ":"
        jars: list[str] = []
        root = self.ghidra_install_dir
        for sub in ("Ghidra", "GPL", "support"):
            p = root / sub
            if p.is_dir():
                for jar in p.rglob("*.jar"):
                    jars.append(str(jar.resolve()))
        jars = sorted(set(jars))
        py4j_jar = _find_py4j_jar()
        logger.info("Using Py4J jar: %s", py4j_jar)
        parts = jars + [str(py4j_jar)]
        classes_root: Path | None = None
        if self.java_classes_dir is not None:
            classes_root = self.java_classes_dir.resolve()
        else:
            packaged = _packaged_bridge_classes_dir()
            if packaged is not None:
                classes_root = packaged
                logger.info("Using Java bridge classes from checkout: %s", classes_root)
        if classes_root is None:
            raise FileNotFoundError(
                "Java bridge is not built: RAWVIEW_JAVA_CLASSES_DIR is unset and "
                "rawview/java/out does not contain io/rawview/ghidra/GhidraServer.class. "
                "Run `python -m rawview.scripts.compile_java` with GHIDRA_INSTALL_DIR set to your Ghidra root, "
                "then restart RawView (or set RAWVIEW_JAVA_CLASSES_DIR / RAWVIEW_JAVA_CLASSPATH in Settings)."
            )
        if not classes_root.is_dir():
            raise FileNotFoundError(f"RAWVIEW_JAVA_CLASSES_DIR is not a directory: {classes_root}")
        marker = classes_root / "io" / "rawview" / "ghidra" / "GhidraServer.class"
        if not marker.is_file():
            raise FileNotFoundError(
                f"Java bridge class missing (expected {marker}). Re-run "
                "`python -m rawview.scripts.compile_java` or fix RAWVIEW_JAVA_CLASSES_DIR."
            )
        parts.insert(0, str(classes_root))
        return sep.join(parts)


def _bundled_java_from_ghidra(ghidra_install: Path) -> str | None:
    """Ghidra full builds ship a JDK under ``jdk/`` or ``jbr/`` at the install root."""
    exe = "java.exe" if sys.platform == "win32" else "java"
    root = ghidra_install.resolve()
    for sub in ("jdk", "jbr", "JDK", "JBR"):
        candidate = root / sub / "bin" / exe
        if candidate.is_file():
            return str(candidate)
    return None


def default_java_executable(
    settings_java: str,
    *,
    ghidra_install_dir: Path | None = None,
) -> str:
    """
    Resolve the JVM used to launch ``GhidraServer``.

    Order: explicit ``JAVA_EXECUTABLE`` (if not the placeholder ``java``), ``PATH``,
    then Ghidra's bundled JDK when ``ghidra_install_dir`` is set.
    """
    j = (settings_java or "").strip()
    if j and j.lower() != "java":
        p = Path(j)
        if p.is_file():
            return str(p.resolve())
        raise FileNotFoundError(
            f"JAVA_EXECUTABLE is set but is not a file: {j!r}. Fix it in Settings or clear it to auto-detect."
        )
    which = shutil.which("java")
    if which:
        return which
    if ghidra_install_dir is not None:
        bundled = _bundled_java_from_ghidra(ghidra_install_dir)
        if bundled:
            logger.info("Using Ghidra-bundled Java: %s", bundled)
            return bundled
    raise MissingJavaError(
        "No java on PATH and no bundled JDK next to Ghidra (expected jdk/bin/java under the "
        f"Ghidra install root{f' ({ghidra_install_dir})' if ghidra_install_dir is not None else ''}). "
        "Use Download JDK in the boot screen or Settings, install a JDK, add it to PATH, "
        "or set JAVA_EXECUTABLE in Settings."
    )
