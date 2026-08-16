"""Edit RawView settings persisted to the user data folder (rawview.env)."""

from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import QObject, QSettings, Qt, Signal
from PySide6.QtGui import QKeySequence
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from rawview.agent.claude_model_limits import model_uses_adaptive_thinking
from rawview.agent.providers import PRESETS, ProviderError, discover_models, preset_by_id
from rawview.config import (
    Settings,
    parse_ghidra_jvm_max_heap,
    save_user_settings_file,
    user_data_dir,
)
from rawview.ghidra_bootstrap import DEFAULT_GHIDRA_ZIP_URL, download_and_extract_ghidra, is_valid_ghidra_root
from rawview.java_bootstrap import download_temurin_jdk
from rawview.qt_ui.controller import RawViewQtController
from rawview.qt_ui.shortcuts import (
    AGENT_RELATED_SHORTCUT_IDS,
    SHORTCUT_DEFAULTS,
    load_shortcut_map,
    save_shortcut_map,
)
from rawview.qt_ui.themes import (
    THEME_IDS,
    main_window_stylesheet,
    normalize_theme_id,
    theme_display_name,
)


class _DownloadSignals(QObject):
    progress = Signal(int, int, str)
    finished = Signal(bool, str)


class SettingsDialog(QDialog):
    def __init__(self, parent, controller: RawViewQtController) -> None:
        super().__init__(parent)
        self._ctrl = controller
        self.setWindowTitle("RawView Settings")
        self.setMinimumSize(620, 520)
        self.resize(720, 580)
        self.setStyleSheet(main_window_stylesheet(controller.settings.rawview_theme))

        self._ghidra_dir = QLineEdit()
        self._ghidra_url = QLineEdit()
        self._java = QLineEdit()
        self._heap = QLineEdit()
        self._heap.setPlaceholderText("8g")
        self._heap.setToolTip("JVM -Xmx for the headless Ghidra process (suffix g, m, or k required).")
        self._port = QSpinBox()
        self._port.setRange(1024, 65535)
        self._project = QLineEdit()
        self._classes = QLineEdit()
        self._classpath = QTextEdit()
        self._classpath.setPlaceholderText("Optional full Java classpath (overrides auto-discovery)")
        self._classpath.setMaximumHeight(80)
        _KNOWN_MODELS = [
            "claude-opus-5",
            "claude-opus-4-8",
            "claude-opus-4-7",
            "claude-opus-4-6",
            "claude-sonnet-5",
            "claude-sonnet-4-6",
            "claude-haiku-4-5",
            "claude-haiku-4-5-20251001",
            "claude-fable-5",
        ]
        self._provider = QComboBox()
        for _p in PRESETS:
            self._provider.addItem(_p.label, _p.id)
        self._provider.setToolTip("Which backend the agent talks to.")
        self._provider_hint = QLabel("")
        self._provider_hint.setWordWrap(True)
        self._llm_base_url = QLineEdit()
        self._llm_base_url.setPlaceholderText("http://localhost:11434/v1")
        self._llm_key = QLineEdit()
        self._llm_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._llm_model = QComboBox()
        self._llm_model.setEditable(True)
        self._llm_model.setToolTip(
            "Model id as the endpoint names it. Use Refresh to list what it offers."
        )
        self._llm_refresh = QPushButton("Refresh")
        self._llm_refresh.setToolTip("Ask the endpoint which models it serves.")
        self._llm_refresh.clicked.connect(self._refresh_llm_models)
        self._llm_tools = QCheckBox("Model can call tools")
        self._llm_tools.setToolTip(
            "Turn off for local models whose chat template cannot emit tool calls. "
            "RawView's agent needs tools to read the binary, so it will be chat-only."
        )
        self._llm_max_tokens = QSpinBox()
        self._llm_max_tokens.setRange(256, 200000)
        self._llm_max_tokens.setSingleStep(256)
        self._api_key = QLineEdit()
        self._api_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._model = QComboBox()
        self._model.setEditable(True)
        self._model.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        for mid in _KNOWN_MODELS:
            self._model.addItem(mid)
        self._model.setToolTip("Anthropic model ID. Select from the list or type a custom model ID.")
        self._model.currentTextChanged.connect(self._on_model_changed)
        self._max_turns = QSpinBox()
        self._max_turns.setRange(1, 256)
        self._hist = QSpinBox()
        self._hist.setRange(1, 200)
        self._agent_temp = QDoubleSpinBox()
        self._agent_temp.setRange(0.0, 1.0)
        self._agent_temp.setSingleStep(0.05)
        self._agent_temp.setDecimals(2)
        self._agent_temp.setToolTip(
            "Anthropic Messages API: optional sampling temperature (default in API docs: 1.0). "
            "Lower ≈ more analytical / steadier tool arguments; higher ≈ more varied prose. "
            "When extended thinking is enabled, the API requires temperature 1.0; RawView sends 1.0 for those "
            "requests and uses this value only when thinking is off. "
            "Do not set top_p elsewhere - use temperature only."
        )
        self._think = QCheckBox("Agent extended thinking (adaptive on Sonnet 4.6+, Opus 4.8+)")
        self._think.setToolTip(
            "Sonnet 4.6+ and Opus 4.8+ use adaptive thinking (model self-selects budget). "
            "Older models (Haiku 4.5, etc.) use the thinking budget token count below. "
            "RawView always retries without thinking if the model rejects it."
        )
        self._think_budget = QSpinBox()
        self._think_budget.setRange(1024, 100_000)
        self._think_budget.setSingleStep(1024)
        self._effort_combo = QComboBox()
        for val, label in [
            ("low", "Low: faster, shorter replies"),
            ("medium", "Medium (default)"),
            ("high", "High: deeper reasoning"),
            ("xhigh", "xhigh: Opus 4.7+, Sonnet 5, Fable 5"),
            ("max", "Max: maximum reasoning"),
        ]:
            self._effort_combo.addItem(label, val)
        self._effort_combo.setToolTip(
            "Controls how much reasoning effort the model applies (output_config.effort). "
            "Low/medium/high/max: Opus, Sonnet, and Fable models. "
            "xhigh: Opus 4.7/4.8, Sonnet 5, Fable 5 (auto-downgraded to high on models without it). "
            "Haiku 4.5 ignores this setting."
        )
        self._auto_bridge = QCheckBox("Start Ghidra JVM automatically when RawView launches")
        self._auto_bridge.setToolTip("When enabled, the boot screen waits for the Ghidra bridge to come up.")

        self._theme = QComboBox()
        for tid in THEME_IDS:
            self._theme.addItem(theme_display_name(tid), tid)

        browse_g = QPushButton("Browse...")
        browse_g.clicked.connect(self._browse_ghidra)
        browse_p = QPushButton("Browse...")
        browse_p.clicked.connect(self._browse_project)
        browse_c = QPushButton("Browse...")
        browse_c.clicked.connect(self._browse_classes)

        row_g = QHBoxLayout()
        row_g.addWidget(self._ghidra_dir, stretch=1)
        row_g.addWidget(browse_g)

        row_p = QHBoxLayout()
        row_p.addWidget(self._project, stretch=1)
        row_p.addWidget(browse_p)

        row_c = QHBoxLayout()
        row_c.addWidget(self._classes, stretch=1)
        row_c.addWidget(browse_c)

        form = QFormLayout()
        form.setSpacing(10)
        form.setHorizontalSpacing(14)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        form.addRow("Theme", self._theme)
        form.addRow("Ghidra install directory", row_g)
        hint = QLabel(
            "Official builds can be downloaded from the boot screen or with the button below.\n"
            f"Default bundle URL:\n{DEFAULT_GHIDRA_ZIP_URL}"
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: palette(mid); font-size: 11px;")
        form.addRow(hint)
        form.addRow("Ghidra zip URL (optional override)", self._ghidra_url)
        dl = QPushButton("Download & install Ghidra...")
        dl.clicked.connect(self._download_ghidra)
        form.addRow("", dl)
        java_wrap = QWidget()
        java_row = QHBoxLayout(java_wrap)
        java_row.setContentsMargins(0, 0, 0, 0)
        java_row.addWidget(self._java, stretch=1)
        java_dl_btn = QPushButton("Download JDK...")
        java_dl_btn.setToolTip("Download Eclipse Temurin OpenJDK 21 into user data folder and set JAVA_EXECUTABLE.")
        java_dl_btn.clicked.connect(self._download_java)
        java_row.addWidget(java_dl_btn)
        form.addRow("Java executable", java_wrap)
        form.addRow("Ghidra JVM max heap (-Xmx)", self._heap)
        form.addRow("Py4J port", self._port)
        form.addRow("Ghidra project directory", row_p)
        form.addRow("Compiled bridge classes dir", row_c)
        form.addRow("RAWVIEW_JAVA_CLASSPATH", self._classpath)
        form.addRow("", self._auto_bridge)

        self._agent_form_block = QWidget()
        af = QFormLayout(self._agent_form_block)
        af.setSpacing(10)
        af.setHorizontalSpacing(14)
        af.addRow("Provider", self._provider)
        af.addRow("", self._provider_hint)
        af.addRow("Anthropic API key", self._api_key)
        af.addRow("Anthropic model", self._model)
        af.addRow("Endpoint base URL", self._llm_base_url)
        af.addRow("Endpoint API key", self._llm_key)
        _model_row = QWidget()
        _model_lay = QHBoxLayout(_model_row)
        _model_lay.setContentsMargins(0, 0, 0, 0)
        _model_lay.addWidget(self._llm_model, 1)
        _model_lay.addWidget(self._llm_refresh)
        af.addRow("Endpoint model", _model_row)
        af.addRow("Max output tokens", self._llm_max_tokens)
        af.addRow("", self._llm_tools)
        af.addRow("", self._think)
        af.addRow("Thinking budget (tokens)", self._think_budget)
        af.addRow("Agent max turns", self._max_turns)
        af.addRow("Agent history messages", self._hist)
        af.addRow("Agent effort level", self._effort_combo)
        af.addRow("Agent temperature (0-1)", self._agent_temp)
        self._agent_form_block.setVisible(controller.agent_enabled)
        if not controller.agent_enabled:
            self._no_agent_note = QLabel(
                "This RawView build has <b>no in-app Anthropic agent</b>. "
                "Use Cursor (or another assistant) beside the app for conversational RE help."
            )
            self._no_agent_note.setWordWrap(True)
            self._no_agent_note.setTextFormat(Qt.TextFormat.RichText)
            form.addRow(self._no_agent_note)
        form.addRow(self._agent_form_block)

        general_inner = QWidget()
        general_inner.setLayout(form)
        general_scroll = QScrollArea()
        general_scroll.setWidgetResizable(True)
        general_scroll.setWidget(general_inner)
        general_scroll.setFrameShape(QFrame.Shape.NoFrame)
        general_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        general_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        general_scroll.setMinimumHeight(260)
        sp = QSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        general_scroll.setSizePolicy(sp)
        general_page = QWidget()
        gwrap = QVBoxLayout(general_page)
        gwrap.setContentsMargins(4, 4, 4, 4)
        gwrap.addWidget(general_scroll, stretch=1)

        self._ui_state = QSettings(str(user_data_dir() / "ui_state.ini"), QSettings.Format.IniFormat)
        self._shortcut_edits: dict[str, QLineEdit] = {}
        keyboard_page = self._build_keyboard_tab()

        tabs = QTabWidget()
        tabs.setDocumentMode(True)
        tabs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        tabs.addTab(general_page, "General")
        tabs.addTab(keyboard_page, "Keyboard")

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)
        root.addWidget(tabs, stretch=1)
        root.addWidget(buttons)

        self._load_from_settings(controller.settings)
        self._dl_signals = _DownloadSignals()
        self._dl_signals.progress.connect(self._on_dl_progress)
        self._dl_signals.finished.connect(self._on_dl_finished)
        self._java_dl_signals = _DownloadSignals()
        self._java_dl_signals.progress.connect(self._on_java_dl_progress)
        self._java_dl_signals.finished.connect(self._on_java_dl_finished)

    def _build_keyboard_tab(self) -> QWidget:
        page = QWidget()
        vl = QVBoxLayout(page)
        vl.setContentsMargins(4, 4, 4, 4)
        overrides = load_shortcut_map(self._ui_state)
        shortcut_ids = [
            sid
            for sid in SHORTCUT_DEFAULTS
            if self._ctrl.agent_enabled or sid not in AGENT_RELATED_SHORTCUT_IDS
        ]
        table = QTableWidget(len(shortcut_ids), 2)
        table.setHorizontalHeaderLabels(["Action", "Shortcut (portable text)"])
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for row, sid in enumerate(shortcut_ids):
            desc, default = SHORTCUT_DEFAULTS[sid]
            table.setItem(row, 0, QTableWidgetItem(desc))
            ed = QLineEdit()
            ed.setText(overrides.get(sid, default))
            ed.setPlaceholderText(default)
            table.setCellWidget(row, 1, ed)
            self._shortcut_edits[sid] = ed
        table.setMinimumHeight(220)
        table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        vl.addWidget(table, stretch=1)
        btn_row = QHBoxLayout()
        reset = QPushButton("Reset all shortcuts to defaults")
        reset.clicked.connect(self._reset_shortcut_fields)
        btn_row.addWidget(reset)
        btn_row.addStretch(1)
        vl.addLayout(btn_row)
        hint = QLabel(
            "Examples: Ctrl+O, Ctrl+Shift+W. Stored next to the window layout in ui_state.ini."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: palette(mid); font-size: 11px;")
        vl.addWidget(hint)
        return page

    def _reset_shortcut_fields(self) -> None:
        for sid, ed in self._shortcut_edits.items():
            _desc, default = SHORTCUT_DEFAULTS[sid]
            ed.setText(default)

    def _validate_and_save_shortcuts(self) -> bool:
        out: dict[str, str] = {}
        for sid, ed in self._shortcut_edits.items():
            raw = ed.text().strip()
            _desc, default = SHORTCUT_DEFAULTS[sid]
            if not raw or raw == default:
                continue
            ks = QKeySequence(raw, QKeySequence.SequenceFormat.PortableText)
            if ks.isEmpty():
                QMessageBox.warning(
                    self,
                    "Invalid shortcut",
                    f"Could not parse shortcut for {sid}: {raw!r}",
                )
                return False
            out[sid] = ks.toString(QKeySequence.SequenceFormat.PortableText)
        save_shortcut_map(self._ui_state, out)
        return True

    def _load_from_settings(self, s: Settings) -> None:
        if s.ghidra_install_dir:
            self._ghidra_dir.setText(str(s.ghidra_install_dir))
        self._ghidra_url.setText(s.ghidra_bundle_url or DEFAULT_GHIDRA_ZIP_URL)
        self._java.setText(s.java_executable)
        self._heap.setText(s.ghidra_jvm_max_heap)
        self._port.setValue(s.py4j_port)
        self._project.setText(str(s.rawview_project_dir))
        if s.rawview_java_classes_dir:
            self._classes.setText(str(s.rawview_java_classes_dir))
        if s.rawview_java_classpath:
            self._classpath.setPlainText(s.rawview_java_classpath)
        self._api_key.setText(s.anthropic_api_key)
        _pidx = self._provider.findData(s.llm_provider or "anthropic")
        self._provider.setCurrentIndex(_pidx if _pidx >= 0 else 0)
        self._llm_base_url.setText(s.llm_base_url)
        self._llm_key.setText(s.llm_api_key)
        self._llm_model.setCurrentText(s.llm_model)
        self._llm_max_tokens.setValue(int(s.llm_max_tokens))
        self._llm_tools.setChecked(bool(s.llm_supports_tools))
        self._provider.currentIndexChanged.connect(self._on_provider_changed)
        self._on_provider_changed()
        self._model.setCurrentText(s.anthropic_model)
        self._max_turns.setValue(s.agent_max_turns)
        self._hist.setValue(s.agent_history_messages)
        self._agent_temp.setValue(float(s.agent_temperature))
        self._think.setChecked(s.agent_extended_thinking)
        self._think_budget.setValue(s.agent_thinking_budget_tokens)
        self._on_model_changed(s.anthropic_model)
        effort_idx = self._effort_combo.findData(s.agent_effort)
        if effort_idx >= 0:
            self._effort_combo.setCurrentIndex(effort_idx)
        self._auto_bridge.setChecked(s.rawview_auto_start_bridge)
        tid = normalize_theme_id(s.rawview_theme)
        idx = self._theme.findData(tid)
        if idx >= 0:
            self._theme.setCurrentIndex(idx)

    def _on_provider_changed(self, *_: object) -> None:
        """Show only the fields the selected backend actually uses."""
        preset = preset_by_id(str(self._provider.currentData() or "anthropic"))
        is_anthropic = preset.kind == "anthropic"
        self._api_key.setVisible(is_anthropic)
        self._model.setVisible(is_anthropic)
        for w in (
            self._llm_base_url,
            self._llm_key,
            self._llm_model,
            self._llm_refresh,
            self._llm_tools,
            self._llm_max_tokens,
        ):
            w.setVisible(not is_anthropic)
        # Anthropic thinking/effort controls are meaningless on other backends.
        self._think.setEnabled(is_anthropic)
        self._effort_combo.setEnabled(is_anthropic)
        if not is_anthropic:
            self._think_budget.setEnabled(False)
        else:
            self._on_model_changed(self._model.currentText())
        if not is_anthropic:
            if preset.base_url and not self._llm_base_url.text().strip():
                self._llm_base_url.setText(preset.base_url)
            if preset.suggested_model and not self._llm_model.currentText().strip():
                self._llm_model.setCurrentText(preset.suggested_model)
            self._llm_key.setPlaceholderText(
                "required" if preset.requires_key else "not needed for a local server"
            )
        self._provider_hint.setText(preset.hint)
        # Labels sit in the form layout next to their widget; hide them in step.
        layout = self._api_key.parentWidget().layout() if self._api_key.parentWidget() else None
        if isinstance(layout, QFormLayout):
            for w in (
                self._api_key,
                self._model,
                self._llm_base_url,
                self._llm_key,
                self._llm_tools,
                self._llm_max_tokens,
            ):
                lbl = layout.labelForField(w)
                if lbl is not None:
                    lbl.setVisible(w.isVisible())

    def _refresh_llm_models(self) -> None:
        """Populate the model list from the endpoint's own /models route."""
        preset = preset_by_id(str(self._provider.currentData() or "anthropic"))
        base_url = self._llm_base_url.text().strip() or preset.base_url
        if not base_url:
            QMessageBox.warning(self, "Refresh models", "Enter a base URL first.")
            return
        self._llm_refresh.setEnabled(False)
        try:
            models = discover_models(base_url, self._llm_key.text().strip())
        except ProviderError as e:
            QMessageBox.warning(self, "Refresh models", str(e))
            return
        finally:
            self._llm_refresh.setEnabled(True)
        if not models:
            QMessageBox.information(self, "Refresh models", "The endpoint listed no models.")
            return
        current = self._llm_model.currentText().strip()
        self._llm_model.clear()
        self._llm_model.addItems(models)
        self._llm_model.setCurrentText(current if current in models else models[0])

    def _on_model_changed(self, model: str) -> None:
        is_adaptive = model_uses_adaptive_thinking(model)
        self._think_budget.setEnabled(not is_adaptive)
        self._think_budget.setToolTip(
            "Not used for this model; it uses adaptive thinking (self-selects budget)."
            if is_adaptive else
            "Max tokens the model may use for thinking (for models that don't support adaptive thinking)."
        )

    def _browse_ghidra(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Ghidra installation root")
        if d:
            self._ghidra_dir.setText(d)

    def _browse_project(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Ghidra projects directory")
        if d:
            self._project.setText(d)

    def _browse_classes(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Compiled Java classes root (io/rawview/...)")
        if d:
            self._classes.setText(d)

    def _download_ghidra(self) -> None:
        url = self._ghidra_url.text().strip() or DEFAULT_GHIDRA_ZIP_URL
        reply = QMessageBox.question(
            self,
            "Download Ghidra",
            "This downloads a large official Ghidra release zip into your user data folder and extracts it.\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        def work() -> None:
            try:

                def prog(a: int, b: int, c: str) -> None:
                    self._dl_signals.progress.emit(a, b, c)

                root = download_and_extract_ghidra(
                    zip_url=url,
                    dest_parent=user_data_dir() / "ghidra_bundle",
                    progress=prog,
                )
                self._dl_signals.finished.emit(True, str(root))
            except Exception as e:
                self._dl_signals.finished.emit(False, str(e))

        threading.Thread(target=work, name="rawview-ghidra-dl", daemon=True).start()
        QMessageBox.information(
            self,
            "Download started",
            "Download runs in the background. This dialog will update when finished.",
        )

    def _download_java(self) -> None:
        reply = QMessageBox.question(
            self,
            "Download JDK",
            "This downloads Eclipse Temurin OpenJDK 21 (official Adoptium build) into your user data folder.\n"
            "It is used only by RawView and does not require administrator rights.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        def work() -> None:
            try:

                def prog(a: int, b: int, c: str) -> None:
                    self._java_dl_signals.progress.emit(a, b, c)

                java_exe = download_temurin_jdk(
                    dest_parent=user_data_dir() / "temurin_bundle",
                    progress=prog,
                )
                self._java_dl_signals.finished.emit(True, str(java_exe))
            except Exception as e:
                self._java_dl_signals.finished.emit(False, str(e))

        threading.Thread(target=work, name="rawview-java-dl", daemon=True).start()
        QMessageBox.information(
            self,
            "Download started",
            "JDK download runs in the background. This dialog title will show progress.",
        )

    def _on_java_dl_progress(self, a: int, b: int, c: str) -> None:
        self.setWindowTitle(f"RawView Settings - {c}")

    def _on_java_dl_finished(self, ok: bool, msg: str) -> None:
        self.setWindowTitle("RawView Settings")
        if ok:
            self._java.setText(msg)
            save_user_settings_file({"JAVA_EXECUTABLE": msg})
            self._ctrl.reload_settings()
            QMessageBox.information(self, "JDK installed", f"JAVA_EXECUTABLE set to:\n{msg}")
        else:
            QMessageBox.warning(self, "JDK download failed", msg)

    def _on_dl_progress(self, a: int, b: int, c: str) -> None:
        self.setWindowTitle(f"RawView Settings - {c}")

    def _on_dl_finished(self, ok: bool, msg: str) -> None:
        self.setWindowTitle("RawView Settings")
        if ok:
            self._ghidra_dir.setText(msg)
            save_user_settings_file({"GHIDRA_INSTALL_DIR": msg, "GHIDRA_BUNDLE_URL": self._ghidra_url.text().strip()})
            self._ctrl.reload_settings()
            QMessageBox.information(self, "Ghidra", f"Installed at:\n{msg}")
        else:
            QMessageBox.warning(self, "Download failed", msg)

    def _save(self) -> None:
        if not self._validate_and_save_shortcuts():
            return
        data: dict[str, str] = {}
        gd = self._ghidra_dir.text().strip()
        if gd:
            p = Path(gd)
            if not is_valid_ghidra_root(p):
                QMessageBox.warning(
                    self,
                    "Invalid Ghidra directory",
                    "The selected folder does not look like a Ghidra root (expected "
                    "`Ghidra/` and `support/` subfolders).",
                )
                return
            data["GHIDRA_INSTALL_DIR"] = gd
        else:
            data["GHIDRA_INSTALL_DIR"] = ""
        url = self._ghidra_url.text().strip()
        if url:
            data["GHIDRA_BUNDLE_URL"] = url
        data["JAVA_EXECUTABLE"] = self._java.text().strip() or "java"
        heap = self._heap.text().strip() or "8g"
        try:
            heap = parse_ghidra_jvm_max_heap(heap)
        except ValueError as e:
            QMessageBox.warning(self, "Invalid heap size", str(e))
            return
        data["GHIDRA_JVM_MAX_HEAP"] = heap
        data["PY4J_PORT"] = str(self._port.value())
        data["RAWVIEW_PROJECT_DIR"] = self._project.text().strip() or str(user_data_dir() / "ghidra_projects")
        cls = self._classes.text().strip()
        data["RAWVIEW_JAVA_CLASSES_DIR"] = cls if cls else ""
        cp = self._classpath.toPlainText().strip()
        data["RAWVIEW_JAVA_CLASSPATH"] = cp if cp else ""
        data["RAWVIEW_AUTO_START_BRIDGE"] = "true" if self._auto_bridge.isChecked() else "false"
        data["RAWVIEW_THEME"] = str(self._theme.currentData() or "tokyo_night")

        if self._ctrl.agent_enabled:
            data["LLM_PROVIDER"] = str(self._provider.currentData() or "anthropic")
            data["LLM_BASE_URL"] = self._llm_base_url.text().strip()
            data["LLM_API_KEY"] = self._llm_key.text().strip()
            data["LLM_MODEL"] = self._llm_model.currentText().strip()
            data["LLM_MAX_TOKENS"] = str(self._llm_max_tokens.value())
            data["LLM_SUPPORTS_TOOLS"] = "true" if self._llm_tools.isChecked() else "false"
            data["ANTHROPIC_API_KEY"] = self._api_key.text().strip()
            data["ANTHROPIC_MODEL"] = self._model.currentText().strip() or "claude-opus-5"
            data["AGENT_MAX_TURNS"] = str(self._max_turns.value())
            data["AGENT_HISTORY_MESSAGES"] = str(self._hist.value())
            data["AGENT_TEMPERATURE"] = str(round(float(self._agent_temp.value()), 4))
            data["AGENT_EXTENDED_THINKING"] = "true" if self._think.isChecked() else "false"
            data["AGENT_THINKING_BUDGET_TOKENS"] = str(self._think_budget.value())
            data["AGENT_EFFORT"] = str(self._effort_combo.currentData() or "medium")
        save_user_settings_file(data)
        self._ctrl.reload_settings()
        self.accept()


def open_settings_dialog(parent, controller: RawViewQtController) -> bool:
    """Show modal settings. Returns True if the user saved."""
    dlg = SettingsDialog(parent, controller)
    return dlg.exec() == QDialog.DialogCode.Accepted
