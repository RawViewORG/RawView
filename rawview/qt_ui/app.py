"""Qt application entry with boot splash and optional Ghidra JVM prewarm."""

from __future__ import annotations

import logging
import sys
import threading

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtWidgets import QApplication, QMessageBox

from rawview.config import load_settings, save_user_settings_file, user_data_dir
from rawview.ghidra_bootstrap import DEFAULT_GHIDRA_ZIP_URL, download_and_extract_ghidra
from rawview.java_bootstrap import download_temurin_jdk
from rawview.qt_ui.boot_screen import BootSplash
from rawview.qt_ui.branding import apply_window_icon_to_app
from rawview.qt_ui.main_window import MainWindow


class _BootDownloadSignals(QObject):
    progress = Signal(int, int, str)
    finished = Signal(bool, str)


def _center_on_screen(app: QApplication, widget) -> None:
    screen = app.primaryScreen()
    if screen is None:
        return
    geo = screen.availableGeometry()
    w, h = widget.width(), widget.height()
    widget.move(geo.x() + (geo.width() - w) // 2, geo.y() + (geo.height() - h) // 2)


def _install_qt_excepthook() -> None:
    """
    Keep one unhandled exception in a Qt slot from killing the whole app.

    PySide6 routes an exception raised inside a signal/slot or event handler through
    ``sys.excepthook``; with the default hook the process aborts, so a single bad callback took
    RawView's whole window down (that was the pill-click crash). This logs the traceback and lets
    the event loop keep running, so the app survives a faulty handler instead of vanishing.
    KeyboardInterrupt still exits, so Ctrl-C in a terminal works.
    """
    log = logging.getLogger("rawview")
    prev = sys.excepthook

    def hook(exc_type, exc, tb):
        if issubclass(exc_type, KeyboardInterrupt):
            prev(exc_type, exc, tb)
            return
        log.error("Unhandled exception (kept alive)", exc_info=(exc_type, exc, tb))

    sys.excepthook = hook


def run_qt_app(*, no_agent: bool = False) -> int:
    _install_qt_excepthook()
    app = QApplication(sys.argv)
    app.setApplicationName("RawView")
    app.setOrganizationName("RawView")
    apply_window_icon_to_app(app)

    settings_init = load_settings()
    splash = BootSplash(no_agent=no_agent, theme_id=settings_init.rawview_theme)
    splash.show()
    _center_on_screen(app, splash)
    app.processEvents()

    win = MainWindow(no_agent=no_agent)
    win.hide()
    # Off unless the user turned it on; publishes mcp.json for `rawview-mcp` when they have.
    win.controller.start_mcp_endpoint()

    splash._boot_mode = "initial"  # type: ignore[attr-defined]

    boot_finished = False
    boot_aborted = False
    expect_prewarm_callback = False
    boot_download_active = False
    prewarm_watchdog = QTimer()
    prewarm_watchdog.setSingleShot(True)

    def disarm_prewarm_watchdog() -> None:
        prewarm_watchdog.stop()

    def arm_prewarm_watchdog() -> None:
        nonlocal expect_prewarm_callback
        expect_prewarm_callback = True
        prewarm_watchdog.stop()
        prewarm_watchdog.start(25_000)

    def on_prewarm_watchdog_timeout() -> None:
        nonlocal boot_aborted, expect_prewarm_callback
        if boot_finished or boot_aborted or not expect_prewarm_callback or boot_download_active:
            return
        if not splash.isVisible():
            return
        boot_aborted = True
        expect_prewarm_callback = False
        disarm_prewarm_watchdog()
        QMessageBox.critical(
            splash,
            "RawView",
            "RawView did not finish starting within 25 seconds while waiting for the Ghidra JVM.\n\n"
            "Check Ghidra install path and JAVA_EXECUTABLE in Settings, then try again.",
        )
        splash.close()
        app.exit(1)

    prewarm_watchdog.timeout.connect(on_prewarm_watchdog_timeout)

    def reveal_main() -> None:
        nonlocal boot_finished, expect_prewarm_callback
        if boot_finished:
            return
        expect_prewarm_callback = False
        disarm_prewarm_watchdog()
        boot_finished = True
        splash.close()
        win.present()

        def maybe_first_run_tutorial() -> None:
            from rawview.qt_ui.first_run import is_tutorial_complete
            from rawview.qt_ui.spotlight_tutorial import attach_spotlight_tutorial

            if not is_tutorial_complete():
                o = attach_spotlight_tutorial(win, mark_complete=True, no_agent=getattr(win, "_no_agent", False))
                win._spotlight_overlay = o
                o.finished.connect(win._clear_spotlight_overlay)

        QTimer.singleShot(0, maybe_first_run_tutorial)

    def on_prewarm(ok: bool, msg: str) -> None:
        nonlocal expect_prewarm_callback
        if boot_aborted:
            return
        expect_prewarm_callback = False
        disarm_prewarm_watchdog()
        mode = getattr(splash, "_boot_mode", "initial")
        if mode == "after_dl":
            if ok and msg == "READY":
                splash.set_status("Ghidra JVM is running.\n\nClick Open RawView when you are ready.")
            elif ok:
                splash.set_status(f"{msg}\n\nClick Open RawView when you are ready.")
            elif msg == "NO_JAVA":
                splash.set_status(
                    "Ghidra is installed, but no Java runtime was found.\n"
                    "Click Download JDK to install Eclipse Temurin 21 into user data folder, or set JAVA_EXECUTABLE in Settings."
                )
                splash.show_boot_actions(show_java_download=True, show_ghidra_download=False)
                splash._boot_mode = "initial"  # type: ignore[attr-defined]
                return
            else:
                splash.set_status(
                    f"Could not start Ghidra: {msg}\n\n"
                    "You can fix settings and try again, or open the app anyway."
                )
            splash._boot_mode = "initial"  # type: ignore[attr-defined]
            splash.show_boot_actions(show_ghidra_download=False, show_java_download=False)
            return

        if msg in ("NO_GHIDRA", "BAD_GHIDRA"):
            splash.set_status(
                "Ghidra is not configured or the path is invalid.\n"
                "Use Download to fetch an official build, open Settings, or open RawView to set up later."
            )
            splash.show_boot_actions(show_ghidra_download=True, show_java_download=False)
            return
        if msg == "NO_JAVA":
            splash.set_status(
                "No Java runtime was found (not on PATH and not bundled with Ghidra).\n"
                "Click Download JDK to install Eclipse Temurin 21 into user data folder, or set JAVA_EXECUTABLE in Settings."
            )
            splash.show_boot_actions(show_java_download=True, show_ghidra_download=False)
            return
        if msg == "AUTO_START_OFF":
            splash.set_status(
                "Ghidra JVM auto-start is disabled (see Settings).\n\nClick Open RawView when you are ready."
            )
            splash.show_boot_actions(show_ghidra_download=False, show_java_download=False)
            return
        if ok:
            splash.set_status("Ghidra JVM is running.\n\nClick Open RawView to continue.")
        else:
            splash.set_status(
                f"Could not start Ghidra:\n{msg}\n\n"
                "Use Settings to fix the install path, or open RawView anyway."
            )
        splash.show_boot_actions(show_ghidra_download=False, show_java_download=False)

    def quit_from_splash() -> None:
        """Splash exit must tear down the Ghidra bridge if prewarm already started it; otherwise the JVM
        and Py4J threads keep the process alive after QApplication.quit()."""
        nonlocal boot_aborted, expect_prewarm_callback
        if boot_finished or boot_aborted:
            return
        boot_aborted = True
        expect_prewarm_callback = False
        disarm_prewarm_watchdog()
        try:
            win._ctrl.bridge_prewarm_finished.disconnect(on_prewarm)
        except (TypeError, RuntimeError):
            pass
        try:
            win._ctrl.shutdown_bridge()
        except Exception:
            pass
        win.close()
        splash.close()
        app.quit()

    splash._btn_close.clicked.connect(quit_from_splash)

    win._ctrl.bridge_prewarm_finished.connect(on_prewarm)
    splash._btn_continue.clicked.connect(reveal_main)

    def on_open_settings_boot() -> None:
        from rawview.qt_ui.settings_dialog import open_settings_dialog

        open_settings_dialog(splash, win._ctrl)
        win._ctrl.reload_settings()
        splash.set_status(
            "Settings saved.\n\n"
            "Use Download JDK or Download Ghidra if needed, then Open RawView when you are ready."
        )

    splash._btn_settings.clicked.connect(on_open_settings_boot)

    dl_signals = _BootDownloadSignals()
    dl_signals.progress.connect(lambda a, b, c: (splash.set_progress(a, b), splash.set_status(c)))

    def on_download_boot() -> None:
        nonlocal boot_download_active, expect_prewarm_callback
        expect_prewarm_callback = False
        disarm_prewarm_watchdog()
        boot_download_active = True
        settings = load_settings()
        url = (settings.ghidra_bundle_url or "").strip() or DEFAULT_GHIDRA_ZIP_URL
        splash._btn_download.setEnabled(False)
        splash._btn_download_java.setEnabled(False)
        splash.set_busy(False)
        splash.set_status("Downloading Ghidra (large)...")

        def work() -> None:
            try:

                def prog(a: int, b: int, c: str) -> None:
                    dl_signals.progress.emit(a, b, c)

                root = download_and_extract_ghidra(
                    zip_url=url,
                    dest_parent=user_data_dir() / "ghidra_bundle",
                    progress=prog,
                )
                dl_signals.finished.emit(True, str(root))
            except Exception as e:
                dl_signals.finished.emit(False, str(e))

        threading.Thread(target=work, name="rawview-boot-dl", daemon=True).start()

    def on_dl_finished(ok: bool, msg: str) -> None:
        nonlocal boot_download_active
        boot_download_active = False
        splash._btn_download.setEnabled(True)
        splash._btn_download_java.setEnabled(True)
        if not ok:
            splash.set_status(f"Download failed: {msg}\n\nUse Open RawView or Settings when ready.")
            splash.show_boot_actions(show_ghidra_download=True, show_java_download=False)
            return
        save_user_settings_file({"GHIDRA_INSTALL_DIR": msg})
        win._ctrl.reload_settings()
        splash.set_status("Starting Ghidra JVM...")
        splash._boot_mode = "after_dl"  # type: ignore[attr-defined]
        win._ctrl.prewarm_bridge_if_enabled()
        arm_prewarm_watchdog()

    dl_signals.finished.connect(on_dl_finished)
    splash._btn_download.clicked.connect(on_download_boot)

    java_dl_signals = _BootDownloadSignals()
    java_dl_signals.progress.connect(lambda a, b, c: (splash.set_progress(a, b), splash.set_status(c)))

    def on_download_java_boot() -> None:
        nonlocal boot_download_active, expect_prewarm_callback
        expect_prewarm_callback = False
        disarm_prewarm_watchdog()
        boot_download_active = True
        splash._btn_download_java.setEnabled(False)
        splash._btn_download.setEnabled(False)
        splash.set_busy(False)
        splash.set_status("Preparing JDK download...")

        def work() -> None:
            try:

                def prog(a: int, b: int, c: str) -> None:
                    java_dl_signals.progress.emit(a, b, c)

                java_exe = download_temurin_jdk(
                    dest_parent=user_data_dir() / "temurin_bundle",
                    progress=prog,
                )
                java_dl_signals.finished.emit(True, str(java_exe))
            except Exception as e:
                java_dl_signals.finished.emit(False, str(e))

        threading.Thread(target=work, name="rawview-boot-java-dl", daemon=True).start()

    def on_java_dl_finished(ok: bool, msg: str) -> None:
        nonlocal boot_download_active
        boot_download_active = False
        splash._btn_download_java.setEnabled(True)
        splash._btn_download.setEnabled(True)
        if not ok:
            splash.set_status(f"JDK download failed: {msg}\n\nUse Open RawView or Settings when ready.")
            splash.show_boot_actions(show_java_download=True, show_ghidra_download=False)
            return
        save_user_settings_file({"JAVA_EXECUTABLE": msg})
        win._ctrl.reload_settings()
        splash.set_status("Starting Ghidra JVM...")
        splash._boot_mode = "after_dl"  # type: ignore[attr-defined]
        win._ctrl.prewarm_bridge_if_enabled()
        arm_prewarm_watchdog()

    java_dl_signals.finished.connect(on_java_dl_finished)
    splash._btn_download_java.clicked.connect(on_download_java_boot)

    win._ctrl.prewarm_bridge_if_enabled()
    arm_prewarm_watchdog()

    def boot_stuck_help() -> None:
        if boot_aborted or boot_finished or not splash.isVisible():
            return
        splash.set_status(
            splash._status.text()
            + "\n\nStill waiting on Ghidra? Check Settings or your network.\n"
            "Use Open RawView to enter the app."
        )
        splash.show_boot_actions(show_ghidra_download=True, show_java_download=True)

    QTimer.singleShot(120_000, boot_stuck_help)

    return app.exec()
