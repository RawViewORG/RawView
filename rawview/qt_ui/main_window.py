"""Main Qt window: docks + central analysis tabs + optional agent."""

from __future__ import annotations

import base64
import html
import json
import math
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import (
    QByteArray,
    QEvent,
    QEventLoop,
    QObject,
    QEasingCurve,
    QPropertyAnimation,
    QSettings,
    QSize,
    QTimer,
    Qt,
    QUrl,
    QUrlQuery,
)
from PySide6.QtGui import (
    QAction,
    QFont,
    QGuiApplication,
    QKeySequence,
    QShortcut,
    QTextCursor,
    QTextDocumentFragment,
    QTextOption,
)
from PySide6.QtWidgets import (
    QStackedWidget,
    QAbstractItemView,
    QApplication,
    QComboBox,
    QDockWidget,
    QFileDialog,
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QStatusBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

import qtawesome as qta

from rawview.config import user_data_dir
from rawview.qt_ui.cfg_panel import CfgPanel
from rawview.qt_ui.agent_activity import AgentActivityBar
from rawview.qt_ui.agent_chips import AgentQuickActions, AgentWelcome
from rawview.qt_ui.callgraph_panel import CallGraphPanel
from rawview.qt_ui.patches_panel import PatchesPanel
from rawview.qt_ui.search_panel import SearchPanel
from rawview.qt_ui.diff_panel import DiffPanel
from rawview.qt_ui.controller import RawViewQtController
from rawview.qt_ui.hex_view import HexViewPanel
from rawview.qt_ui.highlighter import PseudocodeHighlighter
from rawview.qt_ui.shortcuts import ShortcutController, effective_sequence, load_shortcut_map
from rawview.qt_ui.themes import (
    agent_dock_stylesheet,
    agent_feed_document_default_stylesheet,
    apply_application_style,
    main_window_stylesheet,
    pseudocode_palette,
)
from rawview.qt_ui.branding import load_app_icon
from rawview.qt_ui.work_dock import WorkDockPanel

# Bump when dock/splitter serialization is incompatible - v1 layouts from wide monitors could force a
# minimum width > 1920px and trigger Windows setGeometry warnings on smaller displays.
_UI_STATE_VERSION = 2


def _highlight_code(code: str, lang: str, *, style: str) -> str:
    """
    Syntax-highlight a code block into inline HTML (no <pre>, so it survives in a feed card).

    Pygments with noclasses+nowrap emits colored <span> runs and nothing structural; newlines
    become <br/> and the whole thing sits in a monospace block span. Falls back to plain escaped
    monospace if Pygments or the language is unavailable - a code block must never crash the feed.
    """
    try:
        from pygments import highlight
        from pygments.formatters import HtmlFormatter
        from pygments.lexers import get_lexer_by_name, guess_lexer
        from pygments.util import ClassNotFound
    except Exception:  # noqa: BLE001 - pygments optional; degrade gracefully
        body = html.escape(code).replace("\n", "<br/>")
        return f'<span style="font-family:Consolas,monospace;">{body}</span>'
    try:
        lexer = get_lexer_by_name(lang) if lang else guess_lexer(code)
    except (ClassNotFound, ValueError):
        try:
            lexer = get_lexer_by_name("text")
        except ClassNotFound:
            body = html.escape(code).replace("\n", "<br/>")
            return f'<span style="font-family:Consolas,monospace;">{body}</span>'
    try:
        out = highlight(code, lexer, HtmlFormatter(noclasses=True, nowrap=True, style=style))
    except Exception:  # noqa: BLE001
        body = html.escape(code).replace("\n", "<br/>")
        return f'<span style="font-family:Consolas,monospace;">{body}</span>'
    out = out.replace("\n", "<br/>")
    return (
        '<span style="font-family:Consolas,monospace; font-size:9.5pt;">' + out + "</span>"
    )


def _inline_html(inner: str) -> str:
    """
    Flatten Qt's block-level markdown HTML into inline HTML that renders inside a message card.

    QTextBrowser drops every card after one that nests a block element (``<p>``, ``<ul>``, ``<pre>``)
    inside its ``<div>``, so the whole feed collapses to the first message. Converting blocks to
    inline runs with ``<br/>`` breaks keeps the card intact while preserving bold/italic/links/code.
    """
    t = inner
    t = re.sub(r"(?is)<style.*?</style>", "", t)
    t = t.replace("<!--StartFragment-->", "").replace("<!--EndFragment-->", "")
    # headings -> bold line
    t = re.sub(r"(?is)<h[1-6][^>]*>", "<b>", t)
    t = re.sub(r"(?is)</h[1-6]>", "</b><br/>", t)
    # list items -> bulleted lines; drop the list containers
    t = re.sub(r"(?is)<li[^>]*>", "• ", t)
    t = re.sub(r"(?is)</li>", "<br/>", t)
    t = re.sub(r"(?is)</?(ul|ol)[^>]*>", "", t)
    # code blocks -> inline monospace, newlines kept as breaks
    def _pre(mm):
        body = re.sub(r"(?is)<[^>]+>", "", mm.group(1))
        return '<br/><span style="font-family:Consolas,monospace;">' + body.replace("\n", "<br/>") + "</span><br/>"
    t = re.sub(r"(?is)<pre[^>]*>(.*?)</pre>", _pre, t)
    # paragraphs -> break-separated inline
    t = re.sub(r"(?is)<p[^>]*>", "", t)
    t = re.sub(r"(?is)</p>", "<br/>", t)
    # blockquotes / divs -> nothing structural
    t = re.sub(r"(?is)</?(blockquote|div)[^>]*>", "", t)
    # collapse trailing breaks
    t = re.sub(r"(?:<br/>\s*){3,}", "<br/><br/>", t)
    return t.strip().removesuffix("<br/>").strip()


class MainWindow(QMainWindow):
    def __init__(self, *, no_agent: bool = False) -> None:
        super().__init__()
        self._no_agent = bool(no_agent)
        self.setWindowTitle("RawView RE" if self._no_agent else "RawView")
        _ic = load_app_icon()
        if not _ic.isNull():
            self.setWindowIcon(_ic)
        self.resize(1400, 900)
        self._did_show_reconcile = False
        # Whether a usable saved geometry was restored; drives maximize-by-default in present().
        self._had_saved_geometry = False

        self._ctrl = RawViewQtController(no_agent=self._no_agent)
        self._ui_settings = QSettings(str(user_data_dir() / "ui_state.ini"), QSettings.Format.IniFormat)
        self._save_ui_timer = QTimer(self)
        self._save_ui_timer.setSingleShot(True)
        self._save_ui_timer.setInterval(450)
        self._save_ui_timer.timeout.connect(self._persist_ui_layout)
        self._ph: PseudocodeHighlighter | None = None
        self._agent_dock_root: QWidget | None = None
        self._shortcut_controller = ShortcutController(self, self._ui_settings)
        self._spotlight_overlay: QWidget | None = None
        self._agent_feed_html_chunks: list[str] = []
        self._agent_tool_expand_html: dict[str, str] = {}
        # Streaming-into-feed state (setHtml rebuild model)
        self._stream_active: bool = False
        self._stream_text: str = ""
        # Image attachment
        self._pending_images: list[dict] = []
        # Generation state
        self._agent_generating: bool = False
        self._chat_title: str = ""
        self._program_loaded: bool = False
        self._psutil_mod: Any = None  # lazy: False = unavailable, else the psutil module
        self._nav_history: list[str] = []
        self._nav_pos: int = -1
        self._nav_jumping: bool = False
        self._editor_font_size: int = 10

        self._build_central()
        self._build_docks()
        self._install_layout_save_event_filters()
        self._wire_layout_autosave()
        self._build_menu()

        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage(
            "Ready: Ghidra manual RE - use Cursor chat beside this app for AI help (no in-app agent in this build)."
            if self._no_agent
            else "Ready: manual RE; agent optional (configure ANTHROPIC_API_KEY)."
        )
        self._tip_label = QLabel("")
        self._tip_label.setStyleSheet("color: #e0af68; padding-left: 12px; max-width: 520px;")
        self._analysis_ui_active = False
        self._build_status_metrics_strip()
        self.statusBar().addPermanentWidget(self._status_metrics_container)
        self.statusBar().addPermanentWidget(self._tip_label)
        self._tip_timer = QTimer(self)
        self._tip_timer.setSingleShot(True)
        self._tip_timer.timeout.connect(self._clear_user_tip)
        self._status_resource_timer = QTimer(self)
        self._status_resource_timer.setInterval(750)
        self._status_resource_timer.timeout.connect(self._refresh_status_metrics)
        self._status_resource_timer.start()

        self._re_recovery_checked = False
        self._re_autosave_timer = QTimer(self)
        self._re_autosave_timer.setInterval(300_000)  # 5 minutes - Ghidra DB + UI hints (not Work tabs)
        self._re_autosave_timer.timeout.connect(self._ctrl.tick_re_autosave)
        self._re_autosave_timer.start()

        from rawview.qt_ui.discord_rpc import DiscordRichPresence
        self._discord = DiscordRichPresence(self._ctrl.settings.discord_client_id)
        self._discord.connect()

        self._connect_controller()
        self._register_shortcuts()
        self._shortcut_controller.apply()
        self._restore_ui_layout()
        self._apply_theme()
        self._apply_default_visible_tabs()
        QTimer.singleShot(0, self._apply_default_visible_tabs)
        if not self._no_agent:
            self._populate_saved_chats_combo()

    def _main_docks(self) -> tuple[QDockWidget, ...]:
        if self._no_agent:
            return (self._dock_file, self._dock_functions, self._dock_work, self._dock_tools)
        return (self._dock_file, self._dock_functions, self._dock_agent, self._dock_work, self._dock_tools)

    def _setup_agent_feed_html(self) -> None:
        if self._no_agent:
            return
        doc = self._agent_feed.document()
        doc.setDefaultStyleSheet(agent_feed_document_default_stylesheet(self._ctrl.settings.rawview_theme))

    def _clear_agent_feed(self) -> None:
        if self._no_agent:
            return
        self._stream_active = False
        self._stream_text = ""
        if hasattr(self, "_stream_render_timer"):
            self._stream_render_timer.stop()
        self._agent_generating = False
        self._btn_send_stop.setIcon(qta.icon("fa6s.paper-plane", color="#7aa2f7"))
        self._btn_send_stop.setText("Send")
        self._thinking_indicator.clear()
        self._thinking_indicator.setVisible(False)
        self._chat_title = ""
        self._chat_title_label.setText("")
        self._agent_feed_html_chunks.clear()
        self._agent_tool_expand_html.clear()
        self._render_agent_feed()
        self._show_feed_stack(welcome=True)

    def _render_agent_feed(self, *, preserve_scroll: bool = False) -> None:
        """
        Rebuild the whole feed with setHtml.

        QTextBrowser drops class-based styling and merges blocks when fragments are added with
        insertHtml + setDefaultStyleSheet - the message cards and role chips never actually
        applied. Rendering the entire feed as one document with an inline <style> is the only way
        Qt resolves the classes, so the feed is rebuilt from the stored chunks (plus the live
        streaming card, if any) on each change.
        """
        if self._no_agent:
            return
        bar = self._agent_feed.verticalScrollBar()
        at_bottom = bar.value() >= bar.maximum() - 4
        prev = bar.value()
        parts = list(self._agent_feed_html_chunks)
        if getattr(self, "_stream_active", False):
            body = html.escape(self._stream_text).replace("\n", "<br/>")
            parts.append(
                '<div class="rva"><span class="rvavatar">◆</span>'
                ' <span class="rvrole">Assistant</span><br/>' + body + "</div>"
            )
        css = agent_feed_document_default_stylesheet(self._ctrl.settings.rawview_theme)
        self._agent_feed.setHtml(f"<html><head><style>{css}</style></head><body>{''.join(parts)}</body></html>")
        if preserve_scroll and not at_bottom:
            bar.setValue(min(prev, bar.maximum()))
        else:
            bar.setValue(bar.maximum())

    def _append_feed_html(self, fragment: str) -> None:
        if self._no_agent:
            return
        self._agent_feed_html_chunks.append(fragment)
        self._render_agent_feed()

    def _replay_feed_html_chunks(self, chunks: list[str], *, preserve_scroll: bool = False) -> None:
        if self._no_agent:
            return
        self._agent_feed_html_chunks = list(chunks)
        if chunks:
            self._show_feed_stack(welcome=False)
        self._render_agent_feed(preserve_scroll=preserve_scroll)

    def _materialize_collapsed_tool_chunks(self, chunks: list[str]) -> list[str]:
        """Replace fold links with full tool HTML so saved archives stay readable offline."""
        out: list[str] = []
        pat = re.compile(r"rvexpand:\?uid=([0-9a-f]{8,64})")
        for ch in chunks:
            m = pat.search(ch)
            if m:
                uid = m.group(1)
                full = self._agent_tool_expand_html.get(uid)
                if full is not None:
                    out.append(full)
                    continue
            out.append(ch)
        return out

    def _assistant_body_from_markdown(self, text: str) -> str:
        """
        Markdown -> inline HTML that nests inside a message card.

        ``QTextDocumentFragment.toHtml`` returns a whole HTML *document* (its own <head>, <style>
        and <body>); dropped inside our ``<div class="rva">`` card that resets the card's styling
        and the role chip, so the feed collapses into one undifferentiated blob. Strip the wrapper
        and the document <style> so only the body's inner markup remains and the card CSS applies.
        """
        # Pull fenced code blocks out first: Qt's markdown drops the language and its <pre> breaks
        # the card, so each block is highlighted separately and spliced back in as inline HTML.
        style = "friendly" if self._ctrl.settings.rawview_theme == "light" else "monokai"
        blocks: list[str] = []

        def _stash(mm: re.Match[str]) -> str:
            lang = (mm.group(1) or "").strip()
            code = mm.group(2)
            blocks.append(_highlight_code(code, lang, style=style))
            return f"\n\nRVCODEBLK{len(blocks) - 1}ENDRVCB\n\n"

        staged = re.sub(r"```([\w+-]*)\n(.*?)```", _stash, text, flags=re.DOTALL)
        try:
            frag = QTextDocumentFragment.fromMarkdown(staged)
            full = frag.toHtml()
        except (AttributeError, TypeError):
            return html.escape(staged).replace("\n", "<br/>")
        m = re.search(r"<body[^>]*>(.*)</body>", full, re.DOTALL | re.IGNORECASE)
        inner = _inline_html(m.group(1) if m else full)
        for i, block in enumerate(blocks):
            inner = inner.replace(f"RVCODEBLK{i}ENDRVCB", block)
        return inner

    def _on_agent_feed_anchor(self, url: QUrl) -> None:
        if url.scheme() != "rvexpand":
            return
        uid = QUrlQuery(url.query()).queryItemValue("uid")
        if not uid:
            return
        expanded = self._agent_tool_expand_html.get(uid)
        if expanded is None:
            return
        needle = f"rvexpand:?uid={uid}"
        replaced = False
        new_chunks: list[str] = []
        for ch in self._agent_feed_html_chunks:
            if not replaced and needle in ch:
                new_chunks.append(expanded)
                replaced = True
            else:
                new_chunks.append(ch)
        if replaced:
            self._agent_tool_expand_html.pop(uid, None)
            self._replay_feed_html_chunks(new_chunks, preserve_scroll=True)

    def _adjust_prompt_height(self) -> None:
        d = self._agent_prompt.document()
        vw = self._agent_prompt.viewport().width()
        if vw > 0:
            d.setTextWidth(vw)
        h = int(d.size().height()) + 12
        self._agent_prompt.setFixedHeight(max(34, min(h, 150)))

    def _set_agent_generating(self, active: bool) -> None:
        self._agent_generating = active
        if active:
            self._btn_send_stop.setIcon(qta.icon("fa6s.stop", color="#f7768e"))
            self._btn_send_stop.setText("Stop")
            self._activity_bar.start("Thinking")
        else:
            self._btn_send_stop.setIcon(qta.icon("fa6s.paper-plane", color="#7aa2f7"))
            self._btn_send_stop.setText("Send")
            self._thinking_indicator.clear()
            self._thinking_indicator.setVisible(False)
            self._activity_bar.stop()

    def _agent_accent_color(self) -> str:
        """Theme accent for the activity bar and chip, taken from the pseudocode keyword color."""
        try:
            return pseudocode_palette(self._ctrl.settings.rawview_theme).get("keyword", "#7aa2f7")
        except Exception:  # noqa: BLE001 - a bad theme id must not break the dock chrome
            return "#7aa2f7"

    def _refresh_provider_chip(self) -> None:
        """Show which backend the Agent dock is talking to, e.g. 'Claude Code · opus'."""
        if self._no_agent or not hasattr(self, "_agent_provider_chip"):
            return
        from rawview.agent.providers import preset_by_id

        s = self._ctrl.settings
        preset = preset_by_id(s.llm_provider)
        if preset.kind == "claude_code":
            model = (s.claude_code_model or "").strip()
            label = "Claude Code" + (f" · {model}" if model else "")
        elif preset.kind == "anthropic":
            label = (s.anthropic_model or "claude").strip()
        else:
            label = (s.llm_model or preset.label).strip()
        self._agent_provider_chip.setText(label)

    def _show_user_tip(self, message: str) -> None:
        self._tip_label.setText(message[:400])
        self._tip_timer.stop()
        self._tip_timer.start(8000)

    def _clear_user_tip(self) -> None:
        self._tip_label.clear()

    def _sync_menu_action_shortcuts(self) -> None:
        ov = load_shortcut_map(self._ui_settings)
        self._act_open.setShortcut(effective_sequence("open_binary", ov))
        self._act_settings.setShortcut(effective_sequence("open_settings", ov))
        self._act_quit.setShortcut(effective_sequence("quit", ov))

    def _register_shortcuts(self) -> None:
        sc = self._shortcut_controller
        sc.register("next_central_tab", self._shortcut_next_tab)
        sc.register("prev_central_tab", self._shortcut_prev_tab)
        sc.register("decompiler_tab", lambda: self._tabs.setCurrentWidget(self._decompiler))
        sc.register("disasm_tab", lambda: self._tabs.setCurrentWidget(self._disasm))
        sc.register("hex_tab", lambda: self._tabs.setCurrentWidget(self._hex_panel))
        if not self._no_agent:
            sc.register(
                "focus_agent_prompt",
                lambda: (
                    self._dock_agent.show(),  # type: ignore[union-attr]
                    self._dock_agent.raise_(),  # type: ignore[union-attr]
                    self._agent_prompt.setFocus(),
                ),
            )
            sc.register("run_agent", self._send_agent)
            sc.register("stop_agent", self._ctrl.interrupt_agent)
            sc.register("toggle_agent_dock", lambda: self._toggle_dock(self._dock_agent))  # type: ignore[arg-type]
        sc.register("run_auto_analysis", self._on_run_auto_analysis)
        sc.register("toggle_file_dock", lambda: self._toggle_dock(self._dock_file))
        sc.register("toggle_work_dock", lambda: self._toggle_dock(self._dock_work))
        sc.register("jump_to_address", self._jump_to_address)
        sc.register("nav_back", self._nav_back)
        sc.register("nav_forward", self._nav_forward)
        sc.register("font_size_up", lambda: self._change_editor_font_size(1))
        sc.register("font_size_down", lambda: self._change_editor_font_size(-1))
        self._sync_menu_action_shortcuts()
        sc.apply()

    def _toggle_dock(self, dock: QDockWidget) -> None:
        dock.setVisible(not dock.isVisible())
        if dock.isVisible():
            dock.raise_()

    def _shortcut_next_tab(self) -> None:
        n = self._tabs.count()
        if n:
            self._tabs.setCurrentIndex((self._tabs.currentIndex() + 1) % n)

    def _shortcut_prev_tab(self) -> None:
        n = self._tabs.count()
        if n:
            self._tabs.setCurrentIndex((self._tabs.currentIndex() - 1 + n) % n)

    def _mono(self) -> QFont:
        f = QFont("Consolas", 10)
        f.setStyleHint(QFont.StyleHint.Monospace)
        return f

    def _build_central(self) -> None:
        mono = self._mono()
        self._decompiler = QPlainTextEdit()
        self._decompiler.setReadOnly(True)
        self._decompiler.setFont(mono)
        self._decompiler.setPlaceholderText("Decompiled pseudocode appears here.")
        self._disasm = QPlainTextEdit()
        self._disasm.setReadOnly(True)
        self._disasm.setFont(mono)
        self._disasm.setPlaceholderText("Disassembly listing.")

        self._hex_panel = HexViewPanel(self._ctrl, mono)

        self._strings_table = QTableWidget(0, 2)
        self._strings_table.setHorizontalHeaderLabels(["Address", "String"])
        self._strings_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._setup_table(self._strings_table)
        self._strings_table.cellDoubleClicked.connect(
            lambda r, _c: self._navigate_to_table_addr(self._strings_table, r, 0)
        )
        self._strings_table.customContextMenuRequested.connect(
            lambda pos: self._show_table_context_menu(self._strings_table, pos, addr_col=0)
        )

        self._imports_table = QTableWidget(0, 3)
        self._imports_table.setHorizontalHeaderLabels(["Library", "Name", "Address"])
        self._imports_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._setup_table(self._imports_table)
        self._imports_table.cellDoubleClicked.connect(
            lambda r, _c: self._navigate_to_table_addr(self._imports_table, r, 2)
        )
        self._imports_table.customContextMenuRequested.connect(
            lambda pos: self._show_table_context_menu(self._imports_table, pos, addr_col=2)
        )

        self._exports_table = QTableWidget(0, 2)
        self._exports_table.setHorizontalHeaderLabels(["Name", "Address"])

        self._exports_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._setup_table(self._exports_table)
        self._exports_table.cellDoubleClicked.connect(
            lambda r, _c: self._navigate_to_table_addr(self._exports_table, r, 1)
        )
        self._exports_table.customContextMenuRequested.connect(
            lambda pos: self._show_table_context_menu(self._exports_table, pos, addr_col=1)
        )

        self._symbols_table = QTableWidget(0, 2)
        self._symbols_table.setHorizontalHeaderLabels(["Name", "Address"])
        self._setup_table(self._symbols_table)
        self._symbols_table.cellDoubleClicked.connect(
            lambda r, _c: self._navigate_to_table_addr(self._symbols_table, r, 1)
        )
        self._symbols_table.customContextMenuRequested.connect(
            lambda pos: self._show_table_context_menu(self._symbols_table, pos, addr_col=1)
        )

        self._xrefs_table = QTableWidget(0, 3)
        self._xrefs_table.setHorizontalHeaderLabels(["From", "To", "Type"])
        self._xrefs_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._setup_table(self._xrefs_table)
        self._xrefs_table.cellDoubleClicked.connect(
            lambda r, _c: self._navigate_to_table_addr(self._xrefs_table, r, 0)
        )
        self._xrefs_table.customContextMenuRequested.connect(
            lambda pos: self._show_table_context_menu(self._xrefs_table, pos, addr_col=0)
        )

        self._cfg = CfgPanel()
        self._callgraph = CallGraphPanel()
        self._patches = PatchesPanel(mono)
        self._search = SearchPanel(mono)
        self._diff = DiffPanel(mono)

        tabs = QTabWidget()
        tabs.addTab(self._decompiler, "Decompiler")
        tabs.addTab(self._disasm, "Disassembly")
        tabs.addTab(self._hex_panel, "Hex")
        tabs.addTab(self._strings_table, "Strings")
        tabs.addTab(self._imports_table, "Imports")
        tabs.addTab(self._exports_table, "Exports")
        tabs.addTab(self._symbols_table, "Symbols")
        tabs.addTab(self._xrefs_table, "Xrefs (to addr)")
        tabs.addTab(self._cfg, "CFG")
        tabs.addTab(self._callgraph, "Call graph")
        tabs.addTab(self._patches, "Patches")
        tabs.addTab(self._search, "Search")
        tabs.addTab(self._diff, "Diff")
        tabs.setTabsClosable(False)
        tabs.setDocumentMode(True)
        tabs.setMovable(True)
        tabs.currentChanged.connect(self._on_central_tab_changed)
        self.setCentralWidget(tabs)
        self._tabs = tabs

    def _build_docks(self) -> None:
        # File dock
        file_w = QWidget()
        fl = QVBoxLayout(file_w)
        self._path_edit = QLineEdit()
        self._path_edit.setPlaceholderText("Path to binary...")
        row = QHBoxLayout()
        btn_open = QPushButton("Browse...")
        btn_open.setIcon(qta.icon("fa6s.folder-open", color="#7aa2f7"))
        btn_open.clicked.connect(self._browse_open)
        btn_load = QPushButton("Open")
        btn_load.setIcon(qta.icon("fa6s.file-import", color="#7aa2f7"))
        btn_load.clicked.connect(self._open_path)
        btn_analyze = QPushButton("Analyze")
        btn_analyze.setIcon(qta.icon("fa6s.magnifying-glass", color="#9ece6a"))
        btn_analyze.setToolTip("Run auto-analysis on the loaded binary")
        btn_analyze.clicked.connect(self._on_run_auto_analysis)
        row.addWidget(btn_open)
        row.addWidget(btn_load)
        row.addWidget(btn_analyze)
        fl.addWidget(QLabel("Project / binary"))
        fl.addWidget(self._path_edit)
        fl.addLayout(row)
        fl.addWidget(QLabel("Batch analysis"))
        self._batch_list = QListWidget()
        self._batch_list.setMaximumHeight(100)
        self._batch_list.setToolTip(
            "Queued binaries. Bold row: next for Open next. Double-click a row to open that file in Ghidra."
        )
        self._batch_list.itemDoubleClicked.connect(self._on_batch_item_double_clicked)
        batch_row = QHBoxLayout()
        btn_batch = QPushButton("Batch…")
        btn_batch.setIcon(qta.icon("fa6s.layer-group", color="#bb9af7"))
        btn_batch.setToolTip("Select multiple binaries to queue (Ghidra loads one at a time).")
        btn_batch.clicked.connect(self._browse_batch_analysis)
        btn_batch_next = QPushButton("Open next")
        btn_batch_next.setIcon(qta.icon("fa6s.forward-step", color="#7aa2f7"))
        btn_batch_next.setToolTip("Import the next queued file (advances the queue on success).")
        btn_batch_next.clicked.connect(self._ctrl.open_analysis_batch_next)
        btn_batch_clear = QPushButton("Clear batch")
        btn_batch_clear.setIcon(qta.icon("fa6s.trash", color="#f7768e"))
        btn_batch_clear.clicked.connect(self._clear_analysis_batch)
        batch_row.addWidget(btn_batch)
        batch_row.addWidget(btn_batch_next)
        batch_row.addWidget(btn_batch_clear)
        fl.addLayout(batch_row)
        fl.addWidget(self._batch_list)
        self._dock_file = QDockWidget("File", self)
        self._dock_file.setObjectName("dock_file")
        self._dock_file.setWidget(file_w)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self._dock_file)

        # Functions dock
        fw = QWidget()
        fvl = QVBoxLayout(fw)
        self._fn_search = QLineEdit()
        self._fn_search.setPlaceholderText("Search functions...")
        self._fn_search.textChanged.connect(self._ctrl.filter_functions)
        self._fn_list = QListWidget()
        self._fn_list.itemDoubleClicked.connect(self._on_fn_activated)
        self._fn_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._fn_list.customContextMenuRequested.connect(self._show_fn_list_context_menu)
        fvl.addWidget(self._fn_search)
        fvl.addWidget(self._fn_list)
        self._dock_functions = QDockWidget("Functions", self)
        self._dock_functions.setObjectName("dock_functions")
        self._dock_functions.setWidget(fw)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self._dock_functions)

        self.tabifyDockWidget(self._dock_file, self._dock_functions)
        self._dock_file.raise_()

        self._dock_agent: QDockWidget | None = None
        if not self._no_agent:
            self._build_agent_dock_inner()

        self._work_panel = WorkDockPanel()
        self._dock_work = QDockWidget("Work", self)
        self._dock_work.setObjectName("dock_work")
        self._dock_work.setWidget(self._work_panel)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self._dock_work)
        if self._dock_agent is not None:
            self.tabifyDockWidget(self._dock_agent, self._dock_work)
            self._dock_agent.raise_()
        else:
            self._dock_work.raise_()

        # Bottom: nav history + rename + comment quick actions
        tools = QWidget()
        tl = QHBoxLayout(tools)
        self._btn_back = QPushButton()
        self._btn_back.setIcon(qta.icon("fa6s.arrow-left", color="#565f89"))
        self._btn_back.setIconSize(QSize(14, 14))
        self._btn_back.setToolTip("Navigate back (Alt+Left)")
        self._btn_back.setFixedWidth(28)
        self._btn_back.setEnabled(False)
        self._btn_back.clicked.connect(self._nav_back)
        self._btn_fwd = QPushButton()
        self._btn_fwd.setIcon(qta.icon("fa6s.arrow-right", color="#565f89"))
        self._btn_fwd.setIconSize(QSize(14, 14))
        self._btn_fwd.setToolTip("Navigate forward (Alt+Right)")
        self._btn_fwd.setFixedWidth(28)
        self._btn_fwd.setEnabled(False)
        self._btn_fwd.clicked.connect(self._nav_forward)
        self._addr_edit = QLineEdit()
        self._addr_edit.setPlaceholderText("Address")
        self._addr_edit.setMinimumWidth(0)
        self._rename_edit = QLineEdit()
        self._rename_edit.setPlaceholderText("New function name")
        self._rename_edit.setMinimumWidth(0)
        btn_re = QPushButton("Rename function")
        btn_re.setIcon(qta.icon("fa6s.pen", color="#e0af68"))
        btn_re.clicked.connect(self._do_rename)
        self._comment_edit = QLineEdit()
        self._comment_edit.setPlaceholderText("EOL comment text")
        self._comment_edit.setMinimumWidth(0)
        btn_co = QPushButton("Set comment")
        btn_co.setIcon(qta.icon("fa6s.comment", color="#73daca"))
        btn_co.clicked.connect(self._do_comment)
        tl.addWidget(self._btn_back)
        tl.addWidget(self._btn_fwd)
        tl.addWidget(QLabel("Addr"))
        tl.addWidget(self._addr_edit)
        tl.addWidget(self._rename_edit)
        tl.addWidget(btn_re)
        tl.addWidget(self._comment_edit)
        tl.addWidget(btn_co)
        self._dock_tools = QDockWidget("Annotations", self)
        self._dock_tools.setObjectName("dock_annotations")
        self._dock_tools.setWidget(tools)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self._dock_tools)

    def _build_agent_dock_inner(self) -> None:
        """Anthropic agent dock (omitted in RawView RE / --no-agent builds)."""
        agent = QWidget()
        agent.setObjectName("agent_dock_root")
        self._agent_dock_root = agent
        al = QVBoxLayout(agent)
        al.setContentsMargins(6, 6, 6, 6)
        al.setSpacing(4)

        # ── Header row ─────────────────────────────────────────────────────────
        row_head = QHBoxLayout()
        row_head.setSpacing(6)
        head_lbl = QLabel("Agent")
        head_lbl.setObjectName("agent_head_label")
        row_head.addWidget(head_lbl)
        self._agent_provider_chip = QLabel("")
        self._agent_provider_chip.setObjectName("agent_provider_chip")
        self._agent_provider_chip.setToolTip("Active agent backend. Change it in File -> Settings.")
        row_head.addWidget(self._agent_provider_chip)
        self._chat_title_label = QLabel("")
        self._chat_title_label.setObjectName("agent_chat_title")
        self._chat_title_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        row_head.addWidget(self._chat_title_label, stretch=1)
        self._btn_new_chat = QPushButton("New chat")
        self._btn_new_chat.setIcon(qta.icon("fa6s.plus", color="#bb9af7"))
        self._btn_new_chat.setToolTip("Save this session to disk and start a fresh conversation.")
        self._btn_new_chat.setAutoDefault(False)
        self._btn_new_chat.clicked.connect(self._new_agent_chat)
        row_head.addWidget(self._btn_new_chat)
        row_head.addWidget(QLabel("Saved:"))
        self._chat_combo = QComboBox()
        self._chat_combo.setMinimumWidth(160)
        self._chat_combo.setToolTip("Open a previously saved agent conversation.")
        self._chat_combo.currentIndexChanged.connect(self._on_saved_chat_selected)
        row_head.addWidget(self._chat_combo, stretch=1)
        al.addLayout(row_head)

        # ── Chat feed ──────────────────────────────────────────────────────────
        self._agent_feed = QTextBrowser()
        self._agent_feed.setObjectName("agent_feed")
        self._agent_feed.setReadOnly(True)
        self._agent_feed.setOpenLinks(False)
        self._agent_feed.setOpenExternalLinks(False)
        self._agent_feed.anchorClicked.connect(self._on_agent_feed_anchor)
        self._agent_feed.setPlaceholderText("Agent activity (tools, results) streams here when enabled.")
        # Wrap everything, including long unbroken tokens (hex, JSON, addresses) and <pre> blocks,
        # so the feed never scrolls off to the right - "lines go into infinity" was Qt not wrapping
        # pre-formatted content or wordless strings.
        self._agent_feed.setLineWrapMode(QTextBrowser.LineWrapMode.WidgetWidth)
        self._agent_feed.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        self._agent_feed.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        # Throttles the setHtml rebuild while streaming so token bursts do not thrash the renderer.
        self._stream_render_timer = QTimer(self)
        self._stream_render_timer.setSingleShot(True)
        self._stream_render_timer.setInterval(60)
        self._stream_render_timer.timeout.connect(lambda: self._render_agent_feed(preserve_scroll=False))
        # A welcome card sits in front of the empty feed and steps aside on the first message.
        self._agent_welcome = AgentWelcome(self._run_prompt_from_chip)
        self._agent_feed_stack = QStackedWidget()
        self._agent_feed_stack.addWidget(self._agent_welcome)
        self._agent_feed_stack.addWidget(self._agent_feed)
        al.addWidget(self._agent_feed_stack, stretch=1)

        # ── Animated activity bar (spinner + live status while the agent works) ─
        self._activity_bar = AgentActivityBar(accent="#7aa2f7")
        al.addWidget(self._activity_bar)
        # Kept for the long "live thinking" preview text; folded under the activity bar.
        self._thinking_indicator = QLabel("")
        self._thinking_indicator.setObjectName("agent_thinking_indicator")
        self._thinking_indicator.setVisible(False)
        self._thinking_indicator.setWordWrap(True)
        self._thinking_indicator.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self._thinking_indicator.setMaximumHeight(48)
        al.addWidget(self._thinking_indicator)

        # ── Attachment preview ──────────────────────────────────────────────────
        self._attach_preview = QLabel("")
        self._attach_preview.setObjectName("agent_attach_preview")
        self._attach_preview.setVisible(False)
        al.addWidget(self._attach_preview)

        # ── Quick actions: one-tap starters that fill the prompt ───────────────
        self._agent_quick_actions = AgentQuickActions(self._fill_prompt_from_chip)
        al.addWidget(self._agent_quick_actions)

        # ── Input bar: [ [⊕  prompt text area  ] ] [Send/Stop] ────────────────
        input_row = QHBoxLayout()
        input_row.setSpacing(6)

        # Unified input box: the circle-plus lives INSIDE the styled frame
        input_frame = QFrame()
        input_frame.setObjectName("agent_input_frame")
        self._agent_input_frame = input_frame
        input_frame.setFrameShape(QFrame.Shape.StyledPanel)
        input_frame_layout = QHBoxLayout(input_frame)
        input_frame_layout.setContentsMargins(6, 4, 6, 4)
        input_frame_layout.setSpacing(6)

        self._btn_attach = QPushButton()
        self._btn_attach.setObjectName("btn_attach")
        self._btn_attach.setToolTip("Attach image or document")
        self._btn_attach.setIcon(qta.icon("fa6s.circle-plus", color="#565f89"))
        self._btn_attach.setIconSize(QSize(20, 20))
        self._btn_attach.setFixedSize(28, 28)
        self._btn_attach.setFlat(True)
        self._btn_attach.setAutoDefault(False)
        self._btn_attach.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_attach.clicked.connect(self._show_attach_menu)
        input_frame_layout.addWidget(self._btn_attach, alignment=Qt.AlignmentFlag.AlignVCenter)

        self._agent_prompt = QTextEdit()
        self._agent_prompt.setObjectName("agent_prompt")
        self._agent_prompt.setPlaceholderText("Ask the agent… /summarize to compress history.")
        self._agent_prompt.setFixedHeight(34)
        self._agent_prompt.setFrameShape(QFrame.Shape.NoFrame)
        self._agent_prompt.document().contentsChanged.connect(self._adjust_prompt_height)
        self._agent_prompt.installEventFilter(self)
        input_frame_layout.addWidget(self._agent_prompt, stretch=1)

        input_row.addWidget(input_frame, stretch=1)

        self._btn_send_stop = QPushButton("Send")
        self._btn_send_stop.setIcon(qta.icon("fa6s.paper-plane", color="#7aa2f7"))
        self._btn_send_stop.setObjectName("btn_send_stop")
        self._btn_send_stop.setAutoDefault(False)
        self._btn_send_stop.clicked.connect(self._on_send_stop_clicked)
        input_row.addWidget(self._btn_send_stop)
        al.addLayout(input_row)

        self._dock_agent = QDockWidget("Agent", self)
        self._dock_agent.setObjectName("dock_agent")
        self._dock_agent.setWidget(agent)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self._dock_agent)
        self._apply_agent_availability()
        self._setup_agent_feed_html()

    def _apply_agent_dock_styles(self) -> None:
        if self._no_agent or self._agent_dock_root is None:
            return
        self._agent_dock_root.setStyleSheet(agent_dock_stylesheet(self._ctrl.settings.rawview_theme))

    def _install_layout_save_event_filters(self) -> None:
        """Dock splitter drags resize children without resizing the top-level window; watch those too."""
        self._layout_watch: tuple[QObject, ...] = (self._tabs, *self._main_docks())
        for w in self._layout_watch:
            w.installEventFilter(self)

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:  # type: ignore[override]
        if watched in getattr(self, "_layout_watch", ()) and event.type() in (
            QEvent.Type.Resize,
            QEvent.Type.Move,
        ):
            self._save_ui_timer.start()
        if watched is getattr(self, "_agent_prompt", None) and event.type() in (
            QEvent.Type.FocusIn,
            QEvent.Type.FocusOut,
        ):
            self._set_input_focus_glow(event.type() == QEvent.Type.FocusIn)
        return super().eventFilter(watched, event)

    def _set_input_focus_glow(self, on: bool) -> None:
        """Brighten the prompt frame's border while it holds focus."""
        frame = getattr(self, "_agent_input_frame", None)
        if frame is None:
            return
        accent = self._agent_accent_color()
        border = accent if on else "palette(mid)"
        frame.setStyleSheet(f"QFrame#agent_input_frame {{ border: 1px solid {border}; border-radius: 6px; }}")

    def _wire_layout_autosave(self) -> None:
        for dock in self._main_docks():
            dock.visibilityChanged.connect(lambda _v: self._save_ui_timer.start())

    def _restore_ui_layout(self) -> None:
        """Restore dock toolbars first, drop layouts that cannot fit the primary display, then geometry."""
        app = QApplication.instance()
        state = self._ui_settings.value("windowstate")
        if isinstance(state, QByteArray) and not state.isEmpty():
            if not self.restoreState(state, _UI_STATE_VERSION):
                self._ui_settings.remove("windowstate")
                self._ui_settings.sync()
        if isinstance(app, QApplication):
            app.processEvents(QEventLoop.ProcessEventsFlag.ExcludeUserInputEvents)
        self.updateGeometry()
        self._coerce_docks_if_minimum_exceeds_primary_screen()
        geom = self._ui_settings.value("geometry")
        if isinstance(geom, QByteArray) and not geom.isEmpty():
            self.restoreGeometry(geom)
            self._had_saved_geometry = True
            self._shrink_window_client_to_primary_screen()
        if isinstance(app, QApplication):
            app.processEvents(QEventLoop.ProcessEventsFlag.ExcludeUserInputEvents)
        self._reconcile_window_with_screen()
        QTimer.singleShot(0, self._reconcile_window_with_screen)
        QTimer.singleShot(80, self._reconcile_window_with_screen)

    def _coerce_docks_if_minimum_exceeds_primary_screen(self) -> None:
        """If restored (or default) docks imply a minimum window larger than the primary work area, reset docks
        and clear saved layout before restoreGeometry runs (avoids Qt/Windows setGeometry warnings)."""
        screen = QGuiApplication.primaryScreen()
        if screen is None:
            return
        avail = screen.availableGeometry()
        margin = 12
        chrome_x = 16
        chrome_y = 31
        max_inner_w = max(320, avail.width() - 2 * margin - chrome_x)
        max_inner_h = max(240, avail.height() - 2 * margin - chrome_y)
        mw = self.minimumSize().width()
        mh = self.minimumSize().height()
        if mw > max_inner_w or mh > max_inner_h:
            self._ui_settings.remove("windowstate")
            self._ui_settings.remove("geometry")
            self._ui_settings.sync()
            self._reapply_default_dock_layout()
            app = QApplication.instance()
            if isinstance(app, QApplication):
                app.processEvents(QEventLoop.ProcessEventsFlag.ExcludeUserInputEvents)

    def _shrink_window_client_to_primary_screen(self) -> None:
        """Immediately after restoreGeometry: saved size may exceed the monitor even when dock minimum is fine."""
        if self.isMaximized() or self.isFullScreen():
            return
        screen = QGuiApplication.primaryScreen()
        if screen is None:
            return
        avail = screen.availableGeometry()
        margin = 12
        chrome_x = max(16, self.frameGeometry().width() - self.width())
        chrome_y = max(31, self.frameGeometry().height() - self.height())
        max_inner_w = max(320, avail.width() - 2 * margin - chrome_x)
        max_inner_h = max(240, avail.height() - 2 * margin - chrome_y)
        mw, mh = self.minimumSize().width(), self.minimumSize().height()
        cw = max(mw, min(self.width(), max_inner_w))
        ch = max(mh, min(self.height(), max_inner_h))
        if cw != self.width() or ch != self.height():
            self.resize(cw, ch)

    def _reapply_default_dock_layout(self) -> None:
        """Rebuild dock placement like startup when saved splitter/dock sizes are unusable on this display."""
        docks = self._main_docks()
        for d in docks:
            self.removeDockWidget(d)
            d.setFloating(False)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self._dock_file)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self._dock_functions)
        self.tabifyDockWidget(self._dock_file, self._dock_functions)
        self._dock_file.raise_()
        if self._dock_agent is not None:
            self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self._dock_agent)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self._dock_work)
        if self._dock_agent is not None:
            self.tabifyDockWidget(self._dock_agent, self._dock_work)
            self._dock_agent.raise_()
        else:
            self._dock_work.raise_()
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self._dock_tools)
        self._apply_default_visible_tabs()

    def _apply_default_visible_tabs(self) -> None:
        """Saved windowstate can hide every dock or leave them floating off-screen - then only the center strip
        looks like 'no tabs'. Show core docks again, dock them to the main window, Decompiler on top, then File/Agent."""
        for dock in self._main_docks():
            dock.setFloating(False)
            dock.setVisible(True)
        self._tabs.setCurrentWidget(self._decompiler)
        self._dock_file.raise_()
        if self._dock_agent is not None:
            self._dock_agent.raise_()
        else:
            self._dock_work.raise_()

    def _reconcile_window_with_screen(self) -> None:
        """Clamp window to the work area; only erase saved dock layout when minimum size cannot fit the screen.

        Previously we also cleared ``geometry``/``windowstate`` whenever the *current* client size exceeded
        the screen (e.g. moving from a large monitor). That nuked valid splitter/dock data and made layout
        feel like it never persisted. Client overflow is handled by shrinking/moving only.
        """
        screen = QGuiApplication.screenAt(self.frameGeometry().center())
        if screen is None:
            screen = QGuiApplication.primaryScreen()
        if screen is None:
            return
        avail = screen.availableGeometry()
        margin = 12
        min_sz = self.minimumSize()
        fg0 = self.frameGeometry()
        # Before the window is shown, frame−client delta can be 0; reserve typical Windows decoration size.
        chrome_x = max(16, fg0.width() - self.width())
        chrome_y = max(31, fg0.height() - self.height())
        max_inner_w = max(320, avail.width() - 2 * margin - chrome_x)
        max_inner_h = max(240, avail.height() - 2 * margin - chrome_y)

        min_too_wide = min_sz.width() > max_inner_w
        min_too_tall = min_sz.height() > max_inner_h
        if min_too_wide or min_too_tall:
            self._ui_settings.remove("windowstate")
            self._ui_settings.remove("geometry")
            self._ui_settings.sync()
            self._reapply_default_dock_layout()
            min_sz = self.minimumSize()
            fg0 = self.frameGeometry()
            chrome_x = max(16, fg0.width() - self.width())
            chrome_y = max(31, fg0.height() - self.height())
            max_inner_w = max(320, avail.width() - 2 * margin - chrome_x)
            max_inner_h = max(240, avail.height() - 2 * margin - chrome_y)
            if self.width() > max_inner_w or self.height() > max_inner_h:
                self.resize(1400, 900)

        if self.isMaximized() or self.isFullScreen():
            return

        min_sz = self.minimumSize()
        cw = max(min_sz.width(), min(self.width(), max_inner_w))
        ch = max(min_sz.height(), min(self.height(), max_inner_h))
        self.resize(cw, ch)

        fg = self.frameGeometry()
        x = min(max(fg.x(), avail.left() + margin), max(avail.left() + margin, avail.right() - fg.width() - margin))
        y = min(max(fg.y(), avail.top() + margin), max(avail.top() + margin, avail.bottom() - fg.height() - margin))
        self.move(x, y)

    def present(self) -> None:
        """
        Show the window, maximized by default.

        RawView is an IDE-class window with several docks; opening it windowed and relying on the
        desktop's maximize action fails on window managers that will not do it, so it opens
        maximized. The last session's maximized state is remembered (``was_maximized``), and when
        that key is absent - every install predating this - it defaults to maximized, so the window
        fills the screen without any help from the desktop. A user who deliberately runs it
        windowed has that remembered and honored on the next launch.
        """
        val = self._ui_settings.value("was_maximized", True)
        was_max = val if isinstance(val, bool) else str(val).lower() in ("true", "1")
        if was_max or not self._had_saved_geometry:
            self.showMaximized()
        else:
            self.show()
        self.raise_()
        self.activateWindow()

    def _persist_ui_layout(self) -> None:
        self._ui_settings.setValue("geometry", self.saveGeometry())
        self._ui_settings.setValue("windowstate", self.saveState(_UI_STATE_VERSION))
        self._ui_settings.setValue("was_maximized", self.isMaximized() or self.isFullScreen())
        self._ui_settings.sync()

    def _apply_theme(self) -> None:
        app = QApplication.instance()
        if isinstance(app, QApplication):
            apply_application_style(app, self._ctrl.settings.rawview_theme)
        self.setStyleSheet(main_window_stylesheet(self._ctrl.settings.rawview_theme))
        self._apply_agent_dock_styles()
        if self._ph is not None:
            self._ph.setDocument(None)
            self._ph.deleteLater()
            self._ph = None
        self._ph = PseudocodeHighlighter(
            self._decompiler.document(),
            palette=pseudocode_palette(self._ctrl.settings.rawview_theme),
        )
        self._cfg.set_theme(self._ctrl.settings.rawview_theme)
        self._hex_panel.apply_theme(self._ctrl.settings.rawview_theme)
        self._setup_agent_feed_html()
        if not self._no_agent:
            self._refresh_provider_chip()
            self._activity_bar.set_accent(self._agent_accent_color())
            self._render_agent_feed(preserve_scroll=True)

    def showEvent(self, event) -> None:  # type: ignore[override]
        super().showEvent(event)
        if not self._did_show_reconcile:
            self._did_show_reconcile = True
            QTimer.singleShot(0, self._reconcile_window_with_screen)
        if not self._re_recovery_checked:
            self._re_recovery_checked = True
            QTimer.singleShot(1200, self._try_re_crash_recovery)

    def resizeEvent(self, event) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        self._save_ui_timer.start()
        if self._spotlight_overlay is not None:
            self._spotlight_overlay.setGeometry(self.rect())

    def moveEvent(self, event) -> None:  # type: ignore[override]
        super().moveEvent(event)
        self._save_ui_timer.start()

    def _apply_agent_availability(self) -> None:
        if self._no_agent or self._dock_agent is None:
            return
        self._refresh_provider_chip()
        cred_err = self._ctrl.agent_credentials_error()
        ready = not cred_err
        self._dock_agent.setEnabled(True)
        self._agent_prompt.setEnabled(ready)
        self._btn_send_stop.setEnabled(ready)
        self._btn_attach.setEnabled(ready)
        if not ready:
            self._agent_feed.setPlaceholderText(
                f"Agent not ready: {cred_err} All other panels work without it."
            )
        else:
            self._agent_feed.setPlaceholderText("Ask the agent about the binary you have open.")

    def _build_menu(self) -> None:
        m_file = self.menuBar().addMenu("&File")
        self._act_open = QAction("Open binary...", self)
        self._act_open.triggered.connect(self._browse_open)
        m_file.addAction(self._act_open)
        self._act_batch = QAction("Batch analysis…", self)
        self._act_batch.setToolTip("Select multiple binaries to queue for sequential analysis in Ghidra.")
        self._act_batch.triggered.connect(self._browse_batch_analysis)
        m_file.addAction(self._act_batch)
        self._act_save_re = QAction("Save RE session…", self)
        self._act_save_re.setToolTip(
            "Export the current Ghidra project (names, comments, analysis) to a .rvre.zip file. "
            "Work-dock Markdown notes are not included."
        )
        self._act_save_re.setEnabled(False)
        self._act_save_re.triggered.connect(self._save_re_session)
        m_file.addAction(self._act_save_re)
        self._act_load_re = QAction("Load RE session…", self)
        self._act_load_re.setToolTip("Import a .rvre.zip saved earlier on this machine or another.")
        self._act_load_re.triggered.connect(self._load_re_session)
        m_file.addAction(self._act_load_re)
        m_file.addSeparator()
        self._act_patch = QAction("Patch bytes at address...", self)
        self._act_patch.setToolTip("Write raw bytes, or assemble one instruction, at an address.")
        self._act_patch.triggered.connect(self._open_patch_dialog)
        m_file.addAction(self._act_patch)
        self._act_export_patched = QAction("Export patched binary...", self)
        self._act_export_patched.setToolTip(
            "Write the imported file back out with every patch applied."
        )
        self._act_export_patched.triggered.connect(self._export_patched_binary)
        m_file.addAction(self._act_export_patched)
        m_file.addSeparator()
        self._act_settings = QAction("Settings...", self)
        self._act_settings.triggered.connect(self._open_settings)
        m_file.addAction(self._act_settings)
        self._act_quit = QAction("Quit", self)
        self._act_quit.triggered.connect(self.close)
        m_file.addAction(self._act_quit)

        m_view = self.menuBar().addMenu("&View")

        m_panels = m_view.addMenu("Side panels")
        for dock in self._main_docks():
            m_panels.addAction(dock.toggleViewAction())

        act_restore = QAction("Restore all panels", self)
        act_restore.setToolTip("Show every dock window again (after closing the dock close button).")
        act_restore.triggered.connect(self._restore_all_panels)
        m_view.addAction(act_restore)
        self._act_show_tutorial = QAction("Show tutorial…", self)
        self._act_show_tutorial.setToolTip("Replay the interactive RE overview tour.")
        self._act_show_tutorial.triggered.connect(self._on_show_tutorial)
        m_view.addAction(self._act_show_tutorial)

        act_find = QAction("Search everywhere", self)
        act_find.setShortcut("Ctrl+Shift+F")
        act_find.setToolTip("Open the Search tab and put the cursor in the query box.")
        act_find.triggered.connect(self._focus_search)
        m_view.addAction(act_find)

        m_tabs = m_view.addMenu("Analysis tabs")
        tab_targets: list[tuple[str, QWidget]] = [
            ("Decompiler", self._decompiler),
            ("Disassembly", self._disasm),
            ("Hex", self._hex_panel),
            ("Strings", self._strings_table),
            ("Imports", self._imports_table),
            ("Exports", self._exports_table),
            ("Symbols", self._symbols_table),
            ("Xrefs (to addr)", self._xrefs_table),
            ("CFG", self._cfg),
            ("Call graph", self._callgraph),
            ("Patches", self._patches),
            ("Search", self._search),
            ("Diff", self._diff),
        ]
        for title, w in tab_targets:
            act = QAction(title, self)
            act.triggered.connect(lambda _c=False, wid=w: self._tabs.setCurrentWidget(wid))
            m_tabs.addAction(act)

        m_help = self.menuBar().addMenu("&Help")
        act_tutorial = QAction("Interactive tutorial (RE overview)", self)
        act_tutorial.triggered.connect(self._on_show_tutorial)
        m_help.addAction(act_tutorial)
        about = QAction("About RawView", self)
        about.triggered.connect(self._about)
        m_help.addAction(about)

    def _build_status_metrics_strip(self) -> None:
        host = QWidget()
        row = QHBoxLayout(host)
        row.setContentsMargins(0, 0, 8, 0)
        row.setSpacing(10)
        self._analysis_label = QLabel("")
        self._analysis_label.setVisible(False)
        self._analysis_bar = QProgressBar()
        self._analysis_bar.setFixedWidth(160)
        self._analysis_bar.setFixedHeight(16)
        self._analysis_bar.setVisible(False)
        self._cpu_ram_label = QLabel("CPU: [-]  RAM: [-]")
        row.addWidget(self._analysis_label)
        row.addWidget(self._analysis_bar)
        row.addWidget(self._cpu_ram_label)
        self._status_metrics_container = host
        try:
            import psutil

            self._psutil_mod = psutil
            # Non-blocking CPU% needs a prior sample; prime so the first timer tick is meaningful.
            psutil.cpu_percent(interval=None, percpu=False)
        except ImportError:
            self._psutil_mod = False
        except Exception:
            self._psutil_mod = None

    def _host_cpu_ram_text(self) -> tuple[str, str]:
        mod = self._psutil_mod
        if mod is False:
            return "-", "-"
        if mod is None:
            try:
                import psutil
            except ImportError:
                self._psutil_mod = False
                return "-", "-"
            except Exception:
                return "-", "-"
            self._psutil_mod = psutil
            try:
                psutil.cpu_percent(interval=None, percpu=False)
            except Exception:
                self._psutil_mod = False
                return "-", "-"
            try:
                ram = float(psutil.virtual_memory().percent)
            except Exception:
                return "-", "-"
            if not math.isfinite(ram):
                return "-", "-"
            ram = max(0.0, min(100.0, ram))
            return "-", f"{ram:.0f}%"
        try:
            cpu = float(mod.cpu_percent(interval=None, percpu=False))
            ram = float(mod.virtual_memory().percent)
        except Exception:
            return "-", "-"
        if not math.isfinite(cpu):
            cpu = 0.0
        if not math.isfinite(ram):
            return f"{max(0.0, min(100.0, cpu)):.0f}%", "-"
        cpu = max(0.0, min(100.0, cpu))
        ram = max(0.0, min(100.0, ram))
        return f"{cpu:.0f}%", f"{ram:.0f}%"

    def _refresh_status_metrics(self) -> None:
        cpu_t, ram_t = self._host_cpu_ram_text()
        self._cpu_ram_label.setText(f"CPU: [{cpu_t}]  RAM: [{ram_t}]")
        if not self._analysis_ui_active:
            return
        path = self._ctrl.analysis_progress_file()
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError, TypeError):
            self._analysis_label.setText("Analyzing…")
            self._analysis_bar.setRange(0, 0)
            self._analysis_bar.setFormat("")
            return
        # Show the current analyzer name; fall back to message for context
        analyzer = str(data.get("analyzer", "") or "").strip()
        if not analyzer:
            analyzer = str(data.get("message", "") or "").strip()
        analyzer = (analyzer[:52] + "…") if len(analyzer) > 52 else (analyzer or "…")
        self._analysis_label.setText(analyzer)
        indet = bool(data.get("indeterminate"))
        pct_raw = data.get("percent")
        try:
            pct = int(pct_raw) if pct_raw is not None else -1
        except (TypeError, ValueError):
            pct = -1
        if indet or pct < 0:
            self._analysis_bar.setRange(0, 0)
            self._analysis_bar.setFormat("")
        else:
            self._analysis_bar.setRange(0, 100)
            self._analysis_bar.setValue(max(0, min(100, pct)))
            self._analysis_bar.setFormat("%p%")

    def _on_ghidra_analysis_begin(self) -> None:
        self._analysis_ui_active = True
        self._analysis_label.setVisible(True)
        self._analysis_bar.setVisible(True)
        self._analysis_label.setText("Starting…")
        self._analysis_bar.setRange(0, 0)  # bouncing indeterminate until first progress update
        self._analysis_bar.setFormat("")
        self._status_resource_timer.setInterval(200)
        try:
            self._ctrl.analysis_progress_file().unlink(missing_ok=True)
        except OSError:
            pass

    def _on_ghidra_analysis_end(self) -> None:
        self._analysis_ui_active = False
        self._status_resource_timer.setInterval(750)
        self._analysis_label.setVisible(False)
        self._analysis_bar.setVisible(False)
        self._analysis_bar.setRange(0, 0)
        self._analysis_bar.setFormat("")

    def _connect_controller(self) -> None:
        c = self._ctrl
        c.status_message.connect(self.statusBar().showMessage)
        c.ghidra_analysis_begin.connect(self._on_ghidra_analysis_begin)
        c.ghidra_analysis_end.connect(self._on_ghidra_analysis_end)
        c.functions_updated.connect(self._populate_functions)
        c.decompiler_text.connect(self._decompiler.setPlainText)
        c.disassembly_text.connect(self._disasm.setPlainText)
        c.strings_updated.connect(lambda rows: self._fill_table(self._strings_table, rows, ["address", "value"]))
        c.imports_updated.connect(
            lambda rows: self._fill_table(self._imports_table, rows, ["library", "name", "address"])
        )
        c.exports_updated.connect(lambda rows: self._fill_table(self._exports_table, rows, ["name", "address"]))
        c.symbols_updated.connect(lambda rows: self._fill_table(self._symbols_table, rows, ["name", "address"]))
        c.xrefs_updated.connect(
            lambda rows: self._fill_table(self._xrefs_table, rows, ["fromAddress", "toAddress", "type"])
        )
        c.current_address_changed.connect(self._on_address_changed)
        if not self._no_agent:
            c.agent_event.connect(self._on_agent_event)
        c.log_line.connect(self._append_log)
        c.ghidra_task_failed.connect(self._toast_error)
        c.program_changed.connect(self._on_program)
        c.analysis_batch_changed.connect(self._refresh_analysis_batch_list)
        c.session_restore_hints.connect(self._apply_re_session_ui_hints)
        c.cfg_graph_updated.connect(self._cfg.load_cfg_json)
        self._cfg.navigate_requested.connect(self._ctrl.navigate_to_address)
        c.call_graph_level.connect(self._callgraph.apply_level)
        self._callgraph.navigate_requested.connect(self._ctrl.navigate_to_address)
        self._callgraph.expand_requested.connect(self._ctrl.fetch_call_graph_level)
        c.patches_updated.connect(self._patches.load)
        c.patch_applied.connect(self._on_patch_applied)
        c.patch_export_finished.connect(self._on_patch_export_finished)
        self._patches.navigate_requested.connect(self._ctrl.navigate_to_address)
        self._patches.refresh_requested.connect(self._ctrl.refresh_patches)
        self._patches.revert_requested.connect(self._on_revert_patch)
        self._patches.export_requested.connect(self._export_patched_binary)
        c.search_results_updated.connect(self._search.load)
        self._search.search_requested.connect(self._ctrl.search_program)
        self._search.navigate_requested.connect(self._ctrl.navigate_to_address)
        c.diff_updated.connect(self._diff.load)
        c.diff_progress.connect(self._diff.set_busy)
        self._diff.navigate_requested.connect(self._ctrl.navigate_to_address)
        self._diff.compare_requested.connect(self._choose_comparison_binary)
        self._diff.close_comparison_requested.connect(self._close_comparison)

    @property
    def controller(self) -> RawViewQtController:
        """The controller, for app-level wiring such as the MCP endpoint."""
        return self._ctrl

    def _restore_all_panels(self) -> None:
        """Re-show dock widgets after the user closes them from the title bar."""
        for dock in self._main_docks():
            dock.setVisible(True)
        self._dock_file.raise_()
        self.statusBar().showMessage("All side panels restored.", 4000)

    def _on_central_tab_changed(self, index: int) -> None:
        w = self._tabs.widget(index)
        if w is self._cfg:
            self._ctrl.refresh_control_flow_graph()
        if w is self._callgraph:
            self._refresh_call_graph_root()
        if w is self._patches:
            self._ctrl.refresh_patches()
        if w is self._hex_panel:
            self._hex_panel.refresh_if_visible()

    def _on_program(self, name: str) -> None:
        self._program_loaded = bool(name)
        self._act_save_re.setEnabled(bool(name))
        base = "RawView RE" if self._no_agent else "RawView"
        if name:
            self.setWindowTitle(f"{base} - {name}")
        else:
            self.setWindowTitle(base)
        self._discord.set_program(name or None)

    def _append_log(self, line: str) -> None:
        self.statusBar().showMessage(line, 8000)

    def _toast_error(self, msg: str) -> None:
        QMessageBox.warning(self, "RawView", msg)

    def _open_settings(self) -> None:
        from rawview.qt_ui.settings_dialog import open_settings_dialog

        if open_settings_dialog(self, self._ctrl):
            self._apply_theme()
        self._apply_agent_availability()
        self._sync_menu_action_shortcuts()
        self._shortcut_controller.apply()
        if not self._no_agent:
            self._populate_saved_chats_combo()

    def _on_show_tutorial(self) -> None:
        """Replay tour without toggling first-run completion (users can refresh anytime)."""
        self._run_interactive_tutorial(mark_complete=False)

    def _run_interactive_tutorial(self, *, mark_complete: bool) -> None:
        if self._spotlight_overlay is not None:
            return
        from rawview.qt_ui.spotlight_tutorial import attach_spotlight_tutorial

        self._spotlight_overlay = attach_spotlight_tutorial(
            self, mark_complete=mark_complete, no_agent=self._no_agent
        )
        self._spotlight_overlay.finished.connect(self._clear_spotlight_overlay)

    def _clear_spotlight_overlay(self) -> None:
        self._spotlight_overlay = None

    def _about(self) -> None:
        mb = QMessageBox(self)
        mb.setWindowTitle("About RawView")
        mb.setIcon(QMessageBox.Icon.Information)
        mb.setTextFormat(Qt.TextFormat.RichText)
        agent_para = (
            "<p><b>Optional agent:</b> with an Anthropic API key in <b>File → Settings</b>, an <b>Agent</b> dock can "
            "call the same Ghidra bridge (decompile, rename, navigate, and more). Nothing else requires the network "
            "or cloud services.</p>"
            if not self._no_agent
            else "<p><b>AI help:</b> this build omits the in-app agent. Use <b>Cursor</b> (or another assistant) "
            "beside RawView for conversational help while you work in Ghidra panes.</p>"
        )
        mb.setText(
            "<p style='margin-top:0'><b>RawView</b> is a desktop UI for manual reverse engineering. "
            "It connects to <b>Ghidra</b> running headlessly in the background so you can open binaries, run analysis, "
            "and work in familiar panes: decompiler, disassembly, strings, imports/exports, xrefs, and a basic CFG "
            "view - all from one window with docked tools and saved layout.</p>"
            + agent_para
            + "<p><b>Notes &amp; data:</b> Markdown work notes, UI state, downloads, and <code>rawview.env</code> live "
            "under your user data folder (see Settings for paths). "
            "<b>RE sessions</b> (<code>.rvre.zip</code>) save Ghidra’s database only - not Work tabs; crash recovery "
            "autosaves every few minutes under <code>re_recovery</code>.</p>"
        )
        mb.setInformativeText(
            "Licensed under the GNU General Public License v3.0 - see the LICENSE file next to the program."
        )
        mb.exec()

    def _browse_open(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open binary", "", "All files (*)")
        if path:
            self._path_edit.setText(path)
            self._ctrl.open_binary(path)

    def _browse_batch_analysis(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "Batch analysis - select binaries", "", "All files (*)")
        if not paths:
            return
        self._ctrl.set_analysis_batch(list(paths))
        self._path_edit.setText(paths[0])

    def _clear_analysis_batch(self) -> None:
        self._ctrl.clear_analysis_batch()

    def _refresh_analysis_batch_list(self, _payload: object = None) -> None:
        snap = self._ctrl.analysis_batch_snapshot()
        self._batch_list.clear()
        for i, p in enumerate(snap["paths"]):
            it = QListWidgetItem(Path(p).name)
            it.setToolTip(p)
            if i == snap["next_index"]:
                f = it.font()
                f.setBold(True)
                it.setFont(f)
            self._batch_list.addItem(it)

    def _on_batch_item_double_clicked(self, item: QListWidgetItem) -> None:
        row = self._batch_list.row(item)
        if row < 0:
            return
        snap = self._ctrl.analysis_batch_snapshot()
        paths = snap["paths"]
        if row >= len(paths):
            return
        self._path_edit.setText(paths[row])
        self._ctrl.open_analysis_batch_at(row)

    def _open_path(self) -> None:
        p = self._path_edit.text().strip()
        if not p:
            QMessageBox.warning(
                self,
                "Cannot open",
                "The file path cannot be empty.\n\n"
                "Use Browse… to choose a binary, or paste the full path, then click Open again.",
            )
            return
        self._ctrl.open_binary(p)

    def _on_run_auto_analysis(self) -> None:
        if not self._path_edit.text().strip():
            QMessageBox.warning(
                self,
                "Cannot run auto-analysis",
                "The file path cannot be empty.\n\n"
                "Set the path to your binary and click Open to load it, then run auto-analysis.",
            )
            return
        if not self._program_loaded:
            QMessageBox.warning(
                self,
                "Cannot run auto-analysis",
                "No program is loaded yet.\n\n"
                "Set the path to your binary and click Open first, then run auto-analysis.",
            )
            return
        self._ctrl.run_auto_analysis()

    def _populate_functions(self, rows: list[dict[str, str]]) -> None:
        self._fn_list.clear()
        for r in rows:
            addr = r.get("address", "")
            name = r.get("name", "")
            item = QListWidgetItem(f"{addr}  {name}")
            item.setData(Qt.ItemDataRole.UserRole, r)
            self._fn_list.addItem(item)
        count = len(rows)
        self._dock_functions.setWindowTitle(f"Functions ({count})" if count else "Functions")

    def _on_fn_activated(self, item: QListWidgetItem) -> None:
        data = item.data(Qt.ItemDataRole.UserRole)
        if isinstance(data, dict):
            addr = data.get("address", "")
            if addr:
                self._ctrl.navigate_to_address(addr)

    def _fill_table(self, table: QTableWidget, rows: list[dict[str, str]], keys: list[str]) -> None:
        was_sorting = table.isSortingEnabled()
        table.setSortingEnabled(False)
        table.setRowCount(0)
        table.setRowCount(len(rows))
        _ro = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        for i, row in enumerate(rows):
            for j, k in enumerate(keys):
                it = QTableWidgetItem(str(row.get(k, "")))
                it.setFlags(_ro)
                table.setItem(i, j, it)
        table.setSortingEnabled(was_sorting)

    # ------------------------------------------------------------------
    # Table and list helpers

    def _setup_table(self, table: QTableWidget) -> None:
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(True)
        table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        table.verticalHeader().setVisible(False)

    def _navigate_to_table_addr(self, table: QTableWidget, row: int, addr_col: int) -> None:
        it = table.item(row, addr_col)
        if it:
            addr = it.text().strip()
            if addr:
                self._ctrl.navigate_to_address(addr)

    def _show_table_context_menu(self, table: QTableWidget, pos, addr_col: int = -1) -> None:
        row = table.rowAt(pos.y())
        if row < 0:
            return
        menu = QMenu(self)
        clicked_item = table.itemAt(pos)
        if clicked_item:
            preview = clicked_item.text()[:60]
            act = menu.addAction(f"Copy: {preview}")
            act.triggered.connect(lambda _=False, t=clicked_item.text(): QGuiApplication.clipboard().setText(t))
        if addr_col >= 0:
            addr_item = table.item(row, addr_col)
            if addr_item:
                addr = addr_item.text().strip()
                if addr:
                    menu.addSeparator()
                    act_nav = menu.addAction(f"Navigate to  {addr}")
                    act_nav.triggered.connect(lambda _=False, a=addr: self._ctrl.navigate_to_address(a))
                    act_cp = menu.addAction(f"Copy address  {addr}")
                    act_cp.triggered.connect(lambda _=False, a=addr: QGuiApplication.clipboard().setText(a))
        row_parts = []
        for col in range(table.columnCount()):
            it = table.item(row, col)
            if it:
                row_parts.append(it.text())
        if row_parts:
            menu.addSeparator()
            row_text = "\t".join(row_parts)
            act_row = menu.addAction("Copy row")
            act_row.triggered.connect(lambda _=False, rt=row_text: QGuiApplication.clipboard().setText(rt))
        if not menu.isEmpty():
            menu.exec(table.viewport().mapToGlobal(pos))

    def _show_fn_list_context_menu(self, pos) -> None:
        item = self._fn_list.itemAt(pos)
        if not item:
            return
        data = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(data, dict):
            return
        addr = data.get("address", "")
        name = data.get("name", "")
        menu = QMenu(self)
        if addr:
            act_nav = menu.addAction(f"Navigate to  {addr}")
            act_nav.triggered.connect(lambda _=False, a=addr: self._ctrl.navigate_to_address(a))
            menu.addSeparator()
            act_ca = menu.addAction(f"Copy address  {addr}")
            act_ca.triggered.connect(lambda _=False, a=addr: QGuiApplication.clipboard().setText(a))
        if name:
            act_cn = menu.addAction(f"Copy name  {name}")
            act_cn.triggered.connect(lambda _=False, n=name: QGuiApplication.clipboard().setText(n))
        if not menu.isEmpty():
            menu.exec(self._fn_list.viewport().mapToGlobal(pos))

    # ------------------------------------------------------------------
    # Address navigation history

    def _on_address_changed(self, addr: str) -> None:
        self._addr_edit.setText(addr)
        if not self._nav_jumping and addr:
            if self._nav_pos < len(self._nav_history) - 1:
                self._nav_history = self._nav_history[: self._nav_pos + 1]
            if not self._nav_history or self._nav_history[-1] != addr:
                self._nav_history.append(addr)
                self._nav_pos = len(self._nav_history) - 1
        self._update_nav_buttons()
        self._ctrl.refresh_control_flow_graph()
        if self._tabs.currentWidget() is self._callgraph:
            self._refresh_call_graph_root()

    def _open_patch_dialog(self, _checked: bool = False, address: str = "") -> None:
        if not self._program_loaded:
            self.statusBar().showMessage("Load a binary before patching.", 5000)
            return
        from rawview.qt_ui.patch_dialog import open_patch_dialog

        target = (address or self._addr_edit.text()).strip()
        open_patch_dialog(self, self._ctrl, target, self._mono())

    def _on_patch_applied(self, result: dict) -> None:
        if result.get("ok"):
            what = result.get("instruction") or result.get("patched") or ""
            if result.get("reverted"):
                msg = f"Reverted {result['reverted']} byte(s) at {result.get('address', '')}."
            else:
                msg = f"Patched {result.get('address', '')}: {what}"
            self.statusBar().showMessage(msg, 6000)
        elif result.get("error"):
            hint = result.get("hint") or ""
            self.statusBar().showMessage(
                f"Patch failed: {result['error']}{' - ' + hint if hint else ''}", 8000
            )

    def _on_revert_patch(self, address: str, length: int) -> None:
        reply = QMessageBox.question(
            self,
            "Revert patch?",
            f"Put the original file bytes back at {address}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._ctrl.revert_patch(address, length)

    def _export_patched_binary(self) -> None:
        if not self._program_loaded:
            self.statusBar().showMessage("Load a binary first.", 5000)
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export patched binary", "", "All files (*)")
        if path:
            self._ctrl.export_patched_file(path)

    def _on_patch_export_finished(self, result: dict) -> None:
        if result.get("ok"):
            self.statusBar().showMessage(
                f"Wrote {result.get('bytes', 0)} bytes to {result.get('path', '')}", 10000
            )
        else:
            hint = result.get("hint") or ""
            self._toast_error(
                f"Could not export the patched binary: {result.get('error', 'failed')}"
                f"{chr(10) + hint if hint else ''}"
            )

    def _choose_comparison_binary(self) -> None:
        if not self._program_loaded:
            self.statusBar().showMessage("Load a binary before comparing.", 5000)
            return
        path, _ = QFileDialog.getOpenFileName(self, "Compare with binary", "", "All files (*)")
        if path:
            self._ctrl.compare_with_binary(path)

    def _close_comparison(self) -> None:
        self._ctrl.close_comparison()
        self._diff.clear()

    def _focus_search(self) -> None:
        self._tabs.setCurrentWidget(self._search)
        self._search.focus_query()

    def _refresh_call_graph_root(self) -> None:
        """Re-root the call graph pane on the current address; it names the function itself."""
        self._callgraph.set_root(self._addr_edit.text().strip())

    def _nav_back(self) -> None:
        if self._nav_pos > 0:
            self._nav_pos -= 1
            self._nav_jumping = True
            self._ctrl.navigate_to_address(self._nav_history[self._nav_pos])
            self._nav_jumping = False
            self._update_nav_buttons()

    def _nav_forward(self) -> None:
        if self._nav_pos < len(self._nav_history) - 1:
            self._nav_pos += 1
            self._nav_jumping = True
            self._ctrl.navigate_to_address(self._nav_history[self._nav_pos])
            self._nav_jumping = False
            self._update_nav_buttons()

    def _update_nav_buttons(self) -> None:
        self._btn_back.setEnabled(self._nav_pos > 0)
        self._btn_fwd.setEnabled(self._nav_pos < len(self._nav_history) - 1)

    def _jump_to_address(self) -> None:
        addr, ok = QInputDialog.getText(
            self,
            "Jump to Address",
            "Enter address (hex):",
            text=self._addr_edit.text().strip(),
        )
        if ok and addr.strip():
            self._ctrl.navigate_to_address(addr.strip())

    def _change_editor_font_size(self, delta: int) -> None:
        self._editor_font_size = max(6, min(24, self._editor_font_size + delta))
        f = QFont("Consolas", self._editor_font_size)
        f.setStyleHint(QFont.StyleHint.Monospace)
        self._decompiler.setFont(f)
        self._disasm.setFont(f)

    def _on_send_stop_clicked(self) -> None:
        if self._agent_generating:
            self._ctrl.interrupt_agent()
        else:
            self._send_agent()

    def _show_attach_menu(self) -> None:
        if self._no_agent:
            return
        menu = QMenu(self)
        img_act = menu.addAction(qta.icon("fa6s.image", color="#7aa2f7"), "Image  (PNG, JPG, GIF, WEBP)")
        pdf_act = menu.addAction(qta.icon("fa6s.file-pdf", color="#f7768e"), "PDF Document")
        txt_act = menu.addAction(qta.icon("fa6s.file-lines", color="#e0af68"), "Text File  (TXT, MD, CSV…)")
        pos = self._btn_attach.mapToGlobal(self._btn_attach.rect().topLeft())
        act = menu.exec(pos)
        if act == img_act:
            self._attach_image()
        elif act == pdf_act:
            self._attach_document("pdf")
        elif act == txt_act:
            self._attach_document("text")

    def _attach_document(self, kind: str) -> None:
        if self._no_agent:
            return
        if kind == "pdf":
            fpath, _ = QFileDialog.getOpenFileName(
                self, "Attach PDF", "", "PDF Documents (*.pdf);;All files (*)"
            )
        else:
            fpath, _ = QFileDialog.getOpenFileName(
                self, "Attach Text File", "",
                "Text files (*.txt *.md *.csv *.py *.js *.ts *.json *.yaml *.toml *.xml *.html *.c *.cpp *.h *.rs);;All files (*)",
            )
        if not fpath:
            return
        path = Path(fpath)
        try:
            if kind == "pdf":
                data = base64.standard_b64encode(path.read_bytes()).decode()
                self._pending_images.append({
                    "type": "document",
                    "source": {"type": "base64", "media_type": "application/pdf", "data": data},
                    "title": path.name,
                })
            else:
                text_data = path.read_text(encoding="utf-8", errors="replace")
                self._pending_images.append({
                    "type": "document",
                    "source": {"type": "text", "media_type": "text/plain", "data": text_data},
                    "title": path.name,
                })
        except OSError as e:
            self.statusBar().showMessage(f"Could not read file: {e}", 5000)
            return
        self._update_attach_preview()

    def _attach_image(self) -> None:
        if self._no_agent:
            return
        fpath, _ = QFileDialog.getOpenFileName(
            self,
            "Attach image",
            "",
            "Images (*.png *.jpg *.jpeg *.gif *.webp);;All files (*)",
        )
        if not fpath:
            return
        path = Path(fpath)
        suffix = path.suffix.lower()
        media_types = {
            ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
            ".gif": "image/gif", ".webp": "image/webp",
        }
        media_type = media_types.get(suffix, "image/png")
        try:
            data = base64.standard_b64encode(path.read_bytes()).decode()
        except OSError as e:
            self.statusBar().showMessage(f"Could not read image: {e}", 5000)
            return
        self._pending_images.append({
            "type": "image",
            "source": {"type": "base64", "media_type": media_type, "data": data},
        })
        self._update_attach_preview()

    def _update_attach_preview(self) -> None:
        n = len(self._pending_images)
        if n == 0:
            self._attach_preview.setVisible(False)
            self._attach_preview.clear()
        else:
            imgs = sum(1 for a in self._pending_images if a.get("type") == "image")
            docs = sum(1 for a in self._pending_images if a.get("type") == "document")
            parts: list[str] = []
            if imgs:
                parts.append(f"{imgs} image{'s' if imgs != 1 else ''}")
            if docs:
                parts.append(f"{docs} document{'s' if docs != 1 else ''}")
            self._attach_preview.setText(f"📎 {', '.join(parts)} attached - will send with next message")
            self._attach_preview.setVisible(True)

    def _fill_prompt_from_chip(self, text: str) -> None:
        """Quick-action pill: drop a starter into the prompt and focus it (does not send)."""
        if self._no_agent:
            return
        self._agent_prompt.setPlainText(text)
        self._agent_prompt.setFocus()
        cursor = self._agent_prompt.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self._agent_prompt.setTextCursor(cursor)

    def _run_prompt_from_chip(self, text: str) -> None:
        """Welcome-card pill: send the prompt straight away."""
        if self._no_agent or not self._agent_prompt.isEnabled():
            return
        self._agent_prompt.setPlainText(text)
        self._send_agent()

    def _show_feed_stack(self, *, welcome: bool) -> None:
        """Flip between the welcome card and the live feed."""
        stack = getattr(self, "_agent_feed_stack", None)
        if stack is None:
            return
        stack.setCurrentWidget(self._agent_welcome if welcome else self._agent_feed)

    def _send_agent(self) -> None:
        if self._no_agent:
            return
        self._show_feed_stack(welcome=False)
        raw = self._agent_prompt.toPlainText()
        if not raw.strip() and not self._pending_images:
            return
        ts = datetime.now().strftime("%H:%M:%S")
        esc = html.escape
        # Show user message in feed immediately
        text_display = esc(raw).replace('\n', '<br/>')
        img_note = ""
        if self._pending_images:
            n = len(self._pending_images)
            noun = "attachment" if n == 1 else "attachments"
            img_note = f' <span class="rvmeta">[+{n} {noun}]</span>'
        if raw.strip() or self._pending_images:
            self._append_feed_html(
                f'<div class="rvu"><span class="rvavatar">👤</span>'
                f' <span class="rvmeta">[{esc(ts)}] you{img_note}</span><br/>{text_display}</div>'
            )
        images = list(self._pending_images) if self._pending_images else None
        self._ctrl.send_agent_prompt(raw, images=images)
        self._agent_prompt.clear()
        self._pending_images.clear()
        self._update_attach_preview()

    def _new_agent_chat(self) -> None:
        if self._no_agent:
            return
        msgs = self._ctrl.agent_memory.export_messages()
        if self._ctrl.agent_memory.is_nonempty() or self._agent_feed_html_chunks:
            feed_save = self._materialize_collapsed_tool_chunks(self._agent_feed_html_chunks)
            self._ctrl.save_agent_chat_archive(msgs, feed_save)
        self._ctrl.clear_agent_memory()
        self._clear_agent_feed()
        self._populate_saved_chats_combo()
        self.statusBar().showMessage("New agent chat started. Previous session saved under agent_chats.", 5000)

    def _populate_saved_chats_combo(self) -> None:
        if self._no_agent:
            return
        self._chat_combo.blockSignals(True)
        self._chat_combo.clear()
        self._chat_combo.addItem("Current session", "")
        for path, label in self._ctrl.list_agent_chat_archives():
            self._chat_combo.addItem(label, str(path))
        self._chat_combo.setCurrentIndex(0)
        self._chat_combo.blockSignals(False)

    def _on_saved_chat_selected(self, index: int) -> None:
        if self._no_agent:
            return
        if index <= 0:
            return
        raw = self._chat_combo.itemData(index)
        if not raw:
            return
        path = Path(str(raw))
        if not path.is_file():
            return
        try:
            messages, feed_html = self._ctrl.load_agent_chat_archive(path)
        except (OSError, json.JSONDecodeError, TypeError) as e:
            QMessageBox.warning(self, "RawView", f"Could not load saved chat:\n{e}")
            return
        self._ctrl.clear_agent_memory()
        self._ctrl.agent_memory.load_messages(messages)
        self._replay_feed_html_chunks(feed_html)
        self.statusBar().showMessage(f"Loaded: {path.name}", 4000)

    def _on_agent_event(self, kind: str, data: object) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        esc = html.escape
        if not isinstance(data, dict):
            data = {"value": data}

        if kind == "user_tip":
            self._show_user_tip(str(data.get("message", "")))
            return
        if kind == "agent_generating":
            self._set_agent_generating(bool(data.get("active")))
            return
        if kind == "chat_title":
            title = str(data.get("title", ""))
            if title:
                self._chat_title = title
                self._chat_title_label.setText(f"- {esc(title)}")
            return
        if kind == "assistant_stream_begin":
            self._stream_active = True
            self._stream_text = ""
            self._render_agent_feed()
            return
        if kind == "assistant_text_delta":
            chunk = str(data.get("text", ""))
            if not chunk:
                return
            self._activity_bar.set_status("Writing")
            self._stream_active = True
            self._stream_text += chunk
            # Throttle the setHtml rebuild so token bursts do not thrash the renderer.
            self._stream_render_timer.start()
            return
        if kind == "assistant_thinking_live":
            raw = str(data.get("text", ""))
            if not raw.strip():
                return
            display = raw[-240:] if len(raw) > 240 else raw
            self._activity_bar.set_status("Thinking")
            self._thinking_indicator.setText(f"💭 {display}")
            self._thinking_indicator.setVisible(True)
            return
        if kind == "assistant_stream_end":
            return
        if kind == "assistant_stream_commit":
            text = str(data.get("text", ""))
            src = str(data.get("source", "agent"))
            self._stream_render_timer.stop()
            self._stream_active = False
            self._stream_text = ""
            self._thinking_indicator.clear()
            self._thinking_indicator.setVisible(False)
            role = "/summarize" if src == "summarize" else "Assistant"
            body = self._assistant_body_from_markdown(text)
            self._append_feed_html(
                f'<div class="rva"><span class="rvavatar">◆</span>'
                f' <span class="rvrole">{esc(role)}</span><br/>{body}</div>'
            )
            return
        if kind == "agent_notice":
            note = esc(str(data.get("message", "")))
            self._append_feed_html(
                f'<div class="rvnotice"><span class="rvmeta">[{esc(ts)}] notice</span><br/>{note}</div>'
            )
            self.statusBar().showMessage(str(data.get("message", ""))[:500], 12_000)
            return
        if kind == "conversation_summarized":
            n = int(data.get("api_messages_before", 0) or 0)
            tin = int(data.get("transcript_chars", 0) or 0)
            tout = int(data.get("summary_chars", 0) or 0)
            self._append_feed_html(
                f'<div class="rvmeta">[{esc(ts)}] /summarize complete - replaced {esc(str(n))} API message(s); '
                f"transcript ~{tin} chars → summary ~{tout} chars.</div>"
            )
            self.statusBar().showMessage("Chat history summarized for a smaller context window.", 6000)
            return
        if kind == "work_note_updated":
            p = str(data.get("path", "")).strip()
            if p:
                self._work_panel.ensure_tab_for_path(Path(p))
            return

        if kind == "ghidra_shell_refresh":
            prog = data.get("program")
            pname = str(prog).strip() if isinstance(prog, str) and str(prog).strip() else None
            self._ctrl.schedule_ghidra_shell_refresh(pname)
            return

        if kind == "assistant_thinking":
            body = self._assistant_body_from_markdown(str(data.get("text", "")))
            self._append_feed_html(
                f'<div class="rvt"><span class="rvrole">💭 Thinking</span><br/>{body}</div>'
            )
            return
        if kind == "assistant_text":
            body = self._assistant_body_from_markdown(str(data.get("text", "")))
            self._append_feed_html(
                f'<div class="rva"><span class="rvavatar">◆</span>'
                f' <span class="rvrole">Assistant</span><br/>{body}</div>'
            )
            return
        if kind == "tool_call":
            name = esc(str(data.get("name", "")))
            self._activity_bar.set_status(f"Running {data.get('name', 'tool')!s}")
            inp = data.get("input", {})
            try:
                inp_s = json.dumps(inp, indent=2, ensure_ascii=False)
            except (TypeError, ValueError):
                inp_s = str(inp)
            inp_h = esc(inp_s)
            uid = uuid.uuid4().hex
            # One-line arg summary so the common case reads at a glance without expanding.
            summary = ", ".join(f"{k}={v}" for k, v in inp.items()) if isinstance(inp, dict) else ""
            summary = esc(summary[:80] + ("…" if len(summary) > 80 else ""))
            summary_html = f' <span class="rvmeta">{summary}</span>' if summary else ""
            expanded = (
                f'<div class="rvtool"><span class="rvtoolglyph">&#9881;</span> <b>{name}</b>'
                f'<pre class="rvpre">{inp_h}</pre></div>'
            )
            collapsed = (
                f'<div class="rvtool rvtool-fold"><span class="rvtoolglyph">&#9881;</span> '
                f'<b>{name}</b>{summary_html} '
                f'<a class="rvlink" href="rvexpand:?uid={uid}">details</a></div>'
            )
            self._agent_tool_expand_html[uid] = expanded
            self._append_feed_html(collapsed)
            return
        if kind == "tool_result":
            raw_name = str(data.get("name", ""))
            raw_prev = str(data.get("preview", ""))
            name = esc(raw_name)
            prev_esc = esc(raw_prev)
            if raw_name == "web_search":
                parsed: dict[str, Any] | None
                try:
                    j = json.loads(raw_prev)
                    parsed = j if isinstance(j, dict) else None
                except json.JSONDecodeError:
                    parsed = None
                if parsed is not None:
                    uid = uuid.uuid4().hex
                    pu = str(parsed.get("primary_url") or "").strip()
                    pt = str(parsed.get("primary_title") or "").strip()
                    psnip = str(parsed.get("primary_snippet") or "").strip()
                    if not pu:
                        res = parsed.get("results")
                        if isinstance(res, list) and res and isinstance(res[0], dict):
                            pu = str(res[0].get("url") or "").strip()
                            pt = str(res[0].get("title") or pt).strip()
                            psnip = str(res[0].get("snippet") or psnip).strip()
                    if pu:
                        p_esc = esc(pu)
                        t_show = esc((pt or pu)[:200])
                        primary_line = (
                            f'<div class="rvweb-primary"><span class="rvmeta">Top result</span> '
                            f'<a class="rvlink" href="{p_esc}">{p_esc}</a> '
                            f'<span class="rvmeta">{t_show}</span></div>'
                        )
                    else:
                        primary_line = '<div class="rvmeta">No linkable results.</div>'
                    snip_show = ""
                    if psnip:
                        s_esc = esc(psnip[:240])
                        snip_show = (
                            f'<div class="rvmeta" style="margin:4px 0;">{s_esc}'
                            f'{"…" if len(psnip) > 240 else ""}</div>'
                        )
                    collapsed = (
                        f'<div class="rvtool rvtool-fold rvweb"><span class="rvmeta">[{esc(ts)}] tool result</span> '
                        f'<b>web_search</b>{primary_line}{snip_show}'
                        f'<a class="rvlink" href="rvexpand:?uid={uid}">Uncollapse full JSON</a></div>'
                    )
                    expanded = (
                        f'<div class="rvtool rvweb"><span class="rvmeta">[{esc(ts)}] tool result</span> <b>web_search</b>'
                        f'<pre class="rvpre">{prev_esc}</pre></div>'
                    )
                    self._agent_tool_expand_html[uid] = expanded
                    self._append_feed_html(collapsed)
                    return
            short = prev_esc[:220] + ("…" if len(prev_esc) > 220 else "")
            uid = uuid.uuid4().hex
            expanded = (
                f'<div class="rvtool"><span class="rvtoolglyph">&#8592;</span> <b>{name}</b>'
                f'<pre class="rvpre">{prev_esc}</pre></div>'
            )
            collapsed = (
                f'<div class="rvtool rvtool-fold"><span class="rvtoolglyph">&#8592;</span> <b>{name}</b>'
                f'<div class="rvmeta" style="margin:4px 0;">{short}</div>'
                f'<a class="rvlink" href="rvexpand:?uid={uid}">details</a></div>'
            )
            self._agent_tool_expand_html[uid] = expanded
            self._append_feed_html(collapsed)
            self._activity_bar.set_status("Thinking")
            return
        if kind in ("agent_done", "agent_stopped", "agent_error"):
            # Drop any half-streamed text that never got a commit (e.g. interrupted).
            if getattr(self, "_stream_active", False):
                self._stream_render_timer.stop()
                self._stream_active = False
                self._stream_text = ""
                self._render_agent_feed()
            if kind == "agent_error":
                msg = esc(str(data.get("message", "The agent hit an error.")))
                self._append_feed_html(
                    f'<div class="rverror"><span class="rverrglyph">&#9888;</span> {msg}</div>'
                )
            elif kind == "agent_stopped":
                self._append_feed_html('<div class="rvstopped">Stopped.</div>')
            # agent_done is silent: the answer already stands on its own.
            return

        blob = esc(json.dumps(data, ensure_ascii=False)[:4000])
        self._append_feed_html(f'<div class="rvmeta">[{esc(ts)}] {esc(kind)} {blob}</div>')

    def _do_rename(self) -> None:
        addr = self._addr_edit.text().strip()
        name = self._rename_edit.text().strip()
        if addr and name:
            self._ctrl.manual_rename_function(addr, name)
        elif not addr:
            self.statusBar().showMessage("Enter an address in the Addr field to rename.", 6000)
        elif not name:
            self.statusBar().showMessage("Enter a new function name.", 6000)

    def _do_comment(self) -> None:
        addr = self._addr_edit.text().strip()
        text = self._comment_edit.text()
        if addr:
            self._ctrl.apply_comment(addr, text)
        else:
            self.statusBar().showMessage("Enter an address in the Addr field to set a comment.", 6000)

    def _try_re_crash_recovery(self) -> None:
        from rawview.re_session import mark_re_recovery_clean, re_autosave_zip_path, read_recovery_state

        z = re_autosave_zip_path()
        if not z.is_file():
            return
        st = read_recovery_state()
        if st and st.get("clean_shutdown"):
            try:
                z.unlink(missing_ok=True)
            except OSError:
                pass
            return
        r = QMessageBox.question(
            self,
            "Recover RE session?",
            "A crash-recovery snapshot of your Ghidra database was found from a previous run.\n\n"
            "Restore it now?\n\n"
            "Work-dock notes use a separate recovery file and are not changed here.\n\n"
            "Choose No to discard this snapshot.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if r == QMessageBox.StandardButton.Yes:
            self._ctrl.load_re_session_archive(z)
        else:
            mark_re_recovery_clean()

    def _save_re_session(self) -> None:
        if not self._program_loaded:
            self.statusBar().showMessage("Open a binary first, then save your RE session.", 5000)
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save RE session",
            "",
            "RawView RE session (*.rvre.zip)",
        )
        if path:
            if not str(path).lower().endswith(".rvre.zip"):
                path = str(path) + ".rvre.zip"
            self._ctrl.save_re_session_archive(Path(path))

    def _load_re_session(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Load RE session",
            "",
            "RawView RE session (*.rvre.zip);;Zip archives (*.zip)",
        )
        if path:
            self._ctrl.load_re_session_archive(Path(path))

    def _apply_re_session_ui_hints(self, d: object) -> None:
        if not isinstance(d, dict):
            return
        try:
            sz = int(d.get("hex_dump_size") or 0)
            bpl = int(d.get("hex_dump_bpl") or 0)
            if sz > 0 and bpl > 0:
                self._ctrl.set_hex_view_options(sz, bpl)
                self._hex_panel.set_options_from_hints(sz, bpl)
        except (TypeError, ValueError):
            pass

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self._save_ui_timer.stop()
        self._re_autosave_timer.stop()
        self._ctrl.mark_re_recovery_clean_shutdown()
        self._work_panel.mark_clean_shutdown()
        self._persist_ui_layout()
        # Before the bridge: an MCP client mid-call would otherwise reach a dead JVM, and the
        # config file must not outlive the port it points at.
        self._ctrl.stop_mcp_endpoint()
        self._ctrl.shutdown_bridge()
        self._discord.close()
        super().closeEvent(event)
