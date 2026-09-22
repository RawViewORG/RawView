"""Qt stylesheets and decompiler palettes keyed by ``RAWVIEW_THEME``."""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtWidgets import QApplication

from rawview.theme_ids import THEME_IDS


def theme_display_name(theme_id: str) -> str:
    return {
        "tokyo_night": "Tokyo Night (dark)",
        "gruvbox": "Gruvbox (dark)",
        "catppuccin_mocha": "Catppuccin Mocha (dark)",
        "nord": "Nord (dark)",
        "dracula": "Dracula (dark)",
        "onedark": "One Dark (dark)",
        "solarized_dark": "Solarized Dark",
        "kanagawa": "Kanagawa (dark)",
        "light": "Light",
        "system": "System default",
    }.get(theme_id, theme_id)


def normalize_theme_id(raw: str) -> str:
    t = (raw or "").strip().lower().replace("-", "_")
    if t in THEME_IDS:
        return t
    return "tokyo_night"


def pseudocode_palette(theme_id: str) -> dict[str, str]:
    tid = normalize_theme_id(theme_id)
    if tid == "light":
        return {
            "keyword": "#005cc5",
            "string": "#22863a",
            "number": "#e36209",
            "comment": "#6a737d",
            "preprocessor": "#6f42c1",
        }
    if tid == "system":
        return {
            "keyword": "#0066cc",
            "string": "#008000",
            "number": "#a31545",
            "comment": "#808080",
            "preprocessor": "#800080",
        }
    if tid == "gruvbox":
        return {
            "keyword": "#fabd2f",
            "string": "#b8bb26",
            "number": "#fe8019",
            "comment": "#928374",
            "preprocessor": "#d3869b",
        }
    if tid == "catppuccin_mocha":
        return {
            "keyword": "#cba6f7",
            "string": "#a6e3a1",
            "number": "#fab387",
            "comment": "#6c7086",
            "preprocessor": "#f5c2e7",
        }
    if tid == "nord":
        return {
            "keyword": "#88c0d0",
            "string": "#a3be8c",
            "number": "#d08770",
            "comment": "#616e88",
            "preprocessor": "#b48ead",
        }
    if tid == "dracula":
        return {
            "keyword": "#ff79c6",
            "string": "#50fa7b",
            "number": "#ffb86c",
            "comment": "#6272a4",
            "preprocessor": "#bd93f9",
        }
    if tid == "onedark":
        return {
            "keyword": "#c678dd",
            "string": "#98c379",
            "number": "#d19a66",
            "comment": "#5c6370",
            "preprocessor": "#e06c75",
        }
    if tid == "solarized_dark":
        return {
            "keyword": "#268bd2",
            "string": "#859900",
            "number": "#cb4b16",
            "comment": "#586e75",
            "preprocessor": "#6c71c4",
        }
    if tid == "kanagawa":
        return {
            "keyword": "#7e9cd8",
            "string": "#98bb6c",
            "number": "#ffa066",
            "comment": "#727169",
            "preprocessor": "#957fb8",
        }
    return {
        "keyword": "#7aa2f7",
        "string": "#9ece6a",
        "number": "#e0af68",
        "comment": "#565f89",
        "preprocessor": "#bb9af7",
    }


@dataclass
class CfgPalette:
    bg: str
    node_bg: str
    node_border: str
    node_hover: str
    header_bg: str
    header_sep: str
    text_addr: str
    text_header: str
    text_body: str
    text_more: str
    edge_cond: str
    edge_fall: str
    edge_uncond: str
    edge_other: str


def cfg_palette(theme_id: str) -> CfgPalette:
    """Return CFG graph colors for the given theme."""
    tid = normalize_theme_id(theme_id)
    if tid == "gruvbox":
        return CfgPalette(
            bg="#282828", node_bg="#3c3836", node_border="#504945",
            node_hover="#83a598", header_bg="#32302f", header_sep="#504945",
            text_addr="#83a598", text_header="#d5c4a1", text_body="#ebdbb2",
            text_more="#928374", edge_cond="#b8bb26", edge_fall="#fe8019",
            edge_uncond="#83a598", edge_other="#665c54",
        )
    if tid == "catppuccin_mocha":
        return CfgPalette(
            bg="#1e1e2e", node_bg="#313244", node_border="#45475a",
            node_hover="#89b4fa", header_bg="#27273a", header_sep="#45475a",
            text_addr="#89b4fa", text_header="#cdd6f4", text_body="#bac2de",
            text_more="#585b70", edge_cond="#a6e3a1", edge_fall="#fab387",
            edge_uncond="#89b4fa", edge_other="#585b70",
        )
    if tid == "nord":
        return CfgPalette(
            bg="#2e3440", node_bg="#3b4252", node_border="#434c5e",
            node_hover="#88c0d0", header_bg="#353b4a", header_sep="#434c5e",
            text_addr="#88c0d0", text_header="#eceff4", text_body="#d8dee9",
            text_more="#616e88", edge_cond="#a3be8c", edge_fall="#d08770",
            edge_uncond="#88c0d0", edge_other="#4c566a",
        )
    if tid == "dracula":
        return CfgPalette(
            bg="#282a36", node_bg="#44475a", node_border="#6272a4",
            node_hover="#bd93f9", header_bg="#383a4a", header_sep="#6272a4",
            text_addr="#bd93f9", text_header="#f8f8f2", text_body="#e2e2f0",
            text_more="#6272a4", edge_cond="#50fa7b", edge_fall="#ffb86c",
            edge_uncond="#bd93f9", edge_other="#44475a",
        )
    if tid == "onedark":
        return CfgPalette(
            bg="#282c34", node_bg="#3e4451", node_border="#5c6370",
            node_hover="#61afef", header_bg="#353b45", header_sep="#5c6370",
            text_addr="#61afef", text_header="#abb2bf", text_body="#98a0b0",
            text_more="#5c6370", edge_cond="#98c379", edge_fall="#d19a66",
            edge_uncond="#61afef", edge_other="#3e4451",
        )
    if tid == "solarized_dark":
        return CfgPalette(
            bg="#002b36", node_bg="#073642", node_border="#586e75",
            node_hover="#268bd2", header_bg="#073642", header_sep="#586e75",
            text_addr="#268bd2", text_header="#93a1a1", text_body="#839496",
            text_more="#657b83", edge_cond="#859900", edge_fall="#cb4b16",
            edge_uncond="#268bd2", edge_other="#586e75",
        )
    if tid == "kanagawa":
        return CfgPalette(
            bg="#1f1f28", node_bg="#2a2a37", node_border="#363646",
            node_hover="#7e9cd8", header_bg="#252532", header_sep="#363646",
            text_addr="#7e9cd8", text_header="#dcd7ba", text_body="#c8c093",
            text_more="#54546d", edge_cond="#98bb6c", edge_fall="#ffa066",
            edge_uncond="#7e9cd8", edge_other="#363646",
        )
    # Default: tokyo_night
    return CfgPalette(
        bg="#1a1b26", node_bg="#24283b", node_border="#414868",
        node_hover="#7aa2f7", header_bg="#292e42", header_sep="#3b4261",
        text_addr="#7dcfff", text_header="#7aa2f7", text_body="#a9b1d6",
        text_more="#565f89", edge_cond="#9ece6a", edge_fall="#e0af68",
        edge_uncond="#7aa2f7", edge_other="#565f89",
    )


def _dark_stylesheet(
    *,
    base: str,
    panel: str,
    input_: str,
    accent: str,
    border: str,
    border2: str,
    text: str,
    muted: str,
    hover: str,
    selected: str,
) -> str:
    """Shared stylesheet template for all dark themes."""
    return f"""
        QMainWindow, QDialog {{ background-color: {base}; color: {text}; }}
        QWidget {{ background-color: {base}; color: {text}; }}
        QDockWidget::title {{
            background: {panel};
            color: {accent};
            font-weight: bold;
            padding: 5px 10px;
            text-align: left;
        }}
        QTabWidget::pane {{
            border: 1px solid {border};
            border-top: none;
            margin-top: -1px;
        }}
        QTabBar::tab {{
            background: {base};
            color: {muted};
            padding: 6px 13px;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
            margin-right: 1px;
            border: 1px solid transparent;
            border-bottom: none;
        }}
        QTabBar::tab:selected {{
            background: {panel};
            color: {text};
            border-color: {border};
        }}
        QTabBar::tab:hover:!selected {{ background: {hover}; color: {text}; }}
        QLineEdit, QPlainTextEdit, QTextEdit {{
            background: {input_};
            border: 1px solid {border};
            border-radius: 6px;
            padding: 4px 7px;
            color: {text};
            selection-background-color: {selected};
        }}
        QLineEdit:focus {{ border-color: {accent}; }}
        QComboBox, QAbstractSpinBox {{
            background: {input_};
            color: {text};
            border: 1px solid {border};
            border-radius: 6px;
            padding: 3px 7px;
        }}
        QComboBox::drop-down {{
            subcontrol-origin: padding;
            subcontrol-position: center right;
            width: 20px;
            border: none;
        }}
        QListWidget {{
            background: {input_};
            border: 1px solid {border};
            border-radius: 6px;
            outline: none;
            color: {text};
        }}
        QListWidget::item {{ padding: 3px 6px; }}
        QListWidget::item:hover {{ background: {hover}; }}
        QListWidget::item:selected {{ background: {selected}; color: {text}; }}
        QTableWidget {{
            background: {input_};
            border: 1px solid {border};
            border-radius: 6px;
            gridline-color: {border2};
            outline: none;
            color: {text};
        }}
        QTableWidget::item {{ padding: 2px 6px; }}
        QTableWidget::item:hover {{ background: {hover}; }}
        QTableWidget::item:selected {{ background: {selected}; color: {text}; }}
        QTableWidget QTableCornerButton::section {{ background: {panel}; border: none; }}
        QHeaderView::section {{
            background: {panel};
            color: {muted};
            border: none;
            border-right: 1px solid {border2};
            border-bottom: 1px solid {border};
            padding: 4px 8px;
        }}
        QHeaderView::section:hover {{ background: {hover}; color: {text}; }}
        QHeaderView::section:checked {{ color: {accent}; }}
        QPushButton {{
            background: {panel};
            border: 1px solid {border};
            padding: 5px 11px;
            border-radius: 6px;
            color: {text};
        }}
        QPushButton:hover {{ background: {hover}; border-color: {accent}; }}
        QPushButton:pressed {{ background: {input_}; }}
        QPushButton:disabled {{ color: {muted}; border-color: {border2}; }}
        QMenuBar {{
            background: {base};
            color: {text};
            padding: 2px;
        }}
        QMenuBar::item {{ padding: 4px 10px; border-radius: 4px; }}
        QMenuBar::item:selected {{ background: {hover}; }}
        QMenu {{
            background: {panel};
            color: {text};
            border: 1px solid {border};
            border-radius: 6px;
            padding: 4px 0;
        }}
        QMenu::item {{ padding: 6px 24px 6px 12px; border-radius: 3px; margin: 1px 4px; }}
        QMenu::item:selected {{ background: {selected}; }}
        QMenu::separator {{ height: 1px; background: {border}; margin: 4px 8px; }}
        QStatusBar {{
            background: {base};
            color: {muted};
            border-top: 1px solid {border2};
        }}
        QStatusBar::item {{ border: none; }}
        QScrollBar:vertical {{
            background: {base};
            width: 8px;
            margin: 0;
        }}
        QScrollBar::handle:vertical {{
            background: {border};
            min-height: 24px;
            border-radius: 4px;
            margin: 2px;
        }}
        QScrollBar::handle:vertical:hover {{ background: {muted}; }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; border: none; }}
        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: none; }}
        QScrollBar:horizontal {{
            background: {base};
            height: 8px;
            margin: 0;
        }}
        QScrollBar::handle:horizontal {{
            background: {border};
            min-width: 24px;
            border-radius: 4px;
            margin: 2px;
        }}
        QScrollBar::handle:horizontal:hover {{ background: {muted}; }}
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; border: none; }}
        QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ background: none; }}
        QProgressBar {{
            border: 1px solid {border};
            border-radius: 4px;
            background: {input_};
            text-align: center;
            color: {text};
            font-size: 10px;
            max-height: 14px;
        }}
        QProgressBar::chunk {{
            background: {accent};
            border-radius: 3px;
        }}
        QSplitter::handle {{ background: {border2}; }}
        QSplitter::handle:horizontal {{ width: 2px; }}
        QSplitter::handle:vertical {{ height: 2px; }}
        QToolTip {{
            background: {panel};
            color: {text};
            border: 1px solid {border};
            border-radius: 4px;
            padding: 4px 8px;
        }}
    """


def main_window_stylesheet(theme_id: str) -> str:
    tid = normalize_theme_id(theme_id)
    if tid == "light":
        return """
            QMainWindow { background-color: #f6f8fa; color: #24292f; }
            QWidget { background-color: #f6f8fa; color: #24292f; }
            QDockWidget::title { background: #eaeef2; padding: 6px; color: #24292f; }
            QTabWidget::pane { border: 1px solid #d0d7de; border-top: none; border-radius: 0 0 8px 8px; margin-top: -1px; }
            QTabBar::tab { background: #eaeef2; padding: 8px 14px; color: #57606a;
                border-top-left-radius: 8px; border-top-right-radius: 8px; margin-right: 2px; }
            QTabBar::tab:selected { background: #ffffff; color: #0969da; border: 1px solid #d0d7de; border-bottom: none;
                border-top-left-radius: 8px; border-top-right-radius: 8px; }
            QLineEdit, QPlainTextEdit, QTextEdit {
                background: #ffffff; border: 1px solid #d0d7de; border-radius: 8px; padding: 4px; color: #24292f;
            }
            QComboBox, QAbstractSpinBox {
                background: #ffffff; color: #24292f; border: 1px solid #d0d7de; border-radius: 8px; padding: 3px 6px;
            }
            QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: center right; width: 20px; border: none; }
            QListWidget { background: #ffffff; border: 1px solid #d0d7de; color: #24292f; border-radius: 8px; outline: none; }
            QTableWidget { background: #ffffff; gridline-color: #d0d7de; border: 1px solid #d0d7de; color: #24292f;
                border-radius: 8px; outline: none; }
            QHeaderView::section { background: #eaeef2; color: #24292f; padding: 4px; border: 1px solid #d0d7de; }
            QPushButton { background: #f6f8fa; border: 1px solid #d0d7de; padding: 6px 12px; border-radius: 8px; color: #24292f; }
            QPushButton:hover { background: #eaeef2; }
            QMenuBar { background: #f6f8fa; color: #24292f; }
            QMenu { background: #ffffff; color: #24292f; }
            QStatusBar { background: #eaeef2; color: #24292f; }
        """
    if tid == "system":
        return """
            QMainWindow { background-color: palette(base); color: palette(window-text); }
            QWidget { background-color: palette(base); color: palette(window-text); }
            QDockWidget::title { background: palette(midlight); padding: 6px; }
            QTabWidget::pane { border: 1px solid palette(mid); border-top: none; border-radius: 0 0 8px 8px; margin-top: -1px; }
            QTabBar::tab { background: palette(button); padding: 8px 14px;
                border-top-left-radius: 8px; border-top-right-radius: 8px; margin-right: 2px; }
            QTabBar::tab:selected { background: palette(base);
                border-top-left-radius: 8px; border-top-right-radius: 8px; }
            QLineEdit, QPlainTextEdit, QTextEdit {
                background: palette(base); border: 1px solid palette(mid); border-radius: 8px; padding: 4px;
            }
            QComboBox, QAbstractSpinBox {
                background: palette(base); color: palette(text); border: 1px solid palette(mid); border-radius: 8px; padding: 3px 6px;
            }
            QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: center right; width: 20px; border: none; }
            QListWidget { background: palette(base); border: 1px solid palette(mid); border-radius: 8px; outline: none; }
            QTableWidget { background: palette(base); gridline-color: palette(mid); border: 1px solid palette(mid);
                border-radius: 8px; outline: none; }
            QPushButton { background: palette(button); border: 1px solid palette(mid); padding: 6px 12px; border-radius: 8px; }
            QPushButton:hover { background: palette(midlight); }
        """
    if tid == "gruvbox":
        return _dark_stylesheet(
            base="#282828", panel="#3c3836", input_="#32302f",
            accent="#83a598", border="#504945", border2="#3d3835",
            text="#ebdbb2", muted="#928374", hover="#3c3836", selected="#4a4440",
        )
    if tid == "catppuccin_mocha":
        return _dark_stylesheet(
            base="#1e1e2e", panel="#313244", input_="#181825",
            accent="#89b4fa", border="#45475a", border2="#313244",
            text="#cdd6f4", muted="#6c7086", hover="#292a3e", selected="#2d3a5e",
        )
    if tid == "nord":
        return _dark_stylesheet(
            base="#2e3440", panel="#3b4252", input_="#2e3440",
            accent="#88c0d0", border="#4c566a", border2="#434c5e",
            text="#eceff4", muted="#616e88", hover="#3b4252", selected="#3d5070",
        )
    if tid == "dracula":
        return _dark_stylesheet(
            base="#282a36", panel="#44475a", input_="#21222c",
            accent="#bd93f9", border="#6272a4", border2="#44475a",
            text="#f8f8f2", muted="#6272a4", hover="#3a3d50", selected="#44467a",
        )
    if tid == "onedark":
        return _dark_stylesheet(
            base="#282c34", panel="#2c323c", input_="#21252b",
            accent="#61afef", border="#3e4451", border2="#2c323c",
            text="#abb2bf", muted="#5c6370", hover="#2c323c", selected="#2e3f5c",
        )
    if tid == "solarized_dark":
        return _dark_stylesheet(
            base="#002b36", panel="#073642", input_="#002b36",
            accent="#268bd2", border="#586e75", border2="#073642",
            text="#839496", muted="#586e75", hover="#094656", selected="#0d4a5e",
        )
    if tid == "kanagawa":
        return _dark_stylesheet(
            base="#1f1f28", panel="#2a2a37", input_="#16161d",
            accent="#7e9cd8", border="#54546d", border2="#363646",
            text="#dcd7ba", muted="#727169", hover="#252530", selected="#2d3652",
        )
    # Tokyo Night (default)
    return _dark_stylesheet(
        base="#1a1b26", panel="#24283b", input_="#16161e",
        accent="#7aa2f7", border="#414868", border2="#292e42",
        text="#c0caf5", muted="#565f89", hover="#1e2338", selected="#2d3a5e",
    )


@dataclass(frozen=True)
class _AgentDockChrome:
    """Embed colors for the Agent dock (must stay aligned with ``main_window_stylesheet`` per theme)."""

    root_bg: str
    root_fg: str
    activity_bg: str
    activity_border: str
    muted: str
    thinking_fg: str
    thinking_bg: str
    thinking_border: str
    stream_fg: str
    stream_bg: str
    feed_bg: str
    feed_fg: str
    feed_border: str
    prompt_bg: str
    prompt_fg: str
    prompt_border: str
    html_body_bg: str
    html_body_fg: str
    html_rvt: str
    html_rva: str
    html_tool_bg: str
    html_tool_border: str
    html_pre_fg: str
    html_meta: str
    html_link: str
    html_notice: str
    html_code_bg: str


_AGENT_DOCK_CHROME: dict[str, _AgentDockChrome] = {
    "tokyo_night": _AgentDockChrome(
        root_bg="#1a1b26",
        root_fg="#c0caf5",
        activity_bg="#1f212d",
        activity_border="#3a3f55",
        muted="#aab6d6",
        thinking_fg="#9aa7b8",
        thinking_bg="#171923",
        thinking_border="#3d4358",
        stream_fg="#d0d5e0",
        stream_bg="#1b1d28",
        feed_bg="#16161e",
        feed_fg="#c8ccd8",
        feed_border="#2c2f3d",
        prompt_bg="#1e2130",
        prompt_fg="#d8dbe6",
        prompt_border="#2c2f3d",
        html_body_bg="#16161e",
        html_body_fg="#c8ccd8",
        html_rvt="#8b92a8",
        html_rva="#d8dbe6",
        html_tool_bg="#1e2130",
        html_tool_border="#5b7aa8",
        html_pre_fg="#b8bfd4",
        html_meta="#6b7080",
        html_link="#8eb8e5",
        html_notice="#c9b87a",
        html_code_bg="#252836",
    ),
    "gruvbox": _AgentDockChrome(
        root_bg="#282828",
        root_fg="#ebdbb2",
        activity_bg="#32302f",
        activity_border="#504945",
        muted="#bdae93",
        thinking_fg="#d5c4a1",
        thinking_bg="#3c3836",
        thinking_border="#504945",
        stream_fg="#ebdbb2",
        stream_bg="#32302f",
        feed_bg="#3c3836",
        feed_fg="#ebdbb2",
        feed_border="#504945",
        prompt_bg="#3c3836",
        prompt_fg="#ebdbb2",
        prompt_border="#504945",
        html_body_bg="#3c3836",
        html_body_fg="#ebdbb2",
        html_rvt="#928374",
        html_rva="#ebdbb2",
        html_tool_bg="#504945",
        html_tool_border="#83a598",
        html_pre_fg="#d5c4a1",
        html_meta="#928374",
        html_link="#83a598",
        html_notice="#fabd2f",
        html_code_bg="#504945",
    ),
    "catppuccin_mocha": _AgentDockChrome(
        root_bg="#1e1e2e",
        root_fg="#cdd6f4",
        activity_bg="#252536",
        activity_border="#45475a",
        muted="#9399b2",
        thinking_fg="#a6adc8",
        thinking_bg="#181825",
        thinking_border="#45475a",
        stream_fg="#cdd6f4",
        stream_bg="#313244",
        feed_bg="#313244",
        feed_fg="#cdd6f4",
        feed_border="#45475a",
        prompt_bg="#313244",
        prompt_fg="#cdd6f4",
        prompt_border="#45475a",
        html_body_bg="#313244",
        html_body_fg="#cdd6f4",
        html_rvt="#6c7086",
        html_rva="#cdd6f4",
        html_tool_bg="#45475a",
        html_tool_border="#89b4fa",
        html_pre_fg="#bac2de",
        html_meta="#6c7086",
        html_link="#89b4fa",
        html_notice="#f9e2af",
        html_code_bg="#45475a",
    ),
    "nord": _AgentDockChrome(
        root_bg="#2e3440",
        root_fg="#eceff4",
        activity_bg="#3b4252",
        activity_border="#4c566a",
        muted="#d8dee9",
        thinking_fg="#e5e9f0",
        thinking_bg="#434c5e",
        thinking_border="#4c566a",
        stream_fg="#eceff4",
        stream_bg="#3b4252",
        feed_bg="#3b4252",
        feed_fg="#eceff4",
        feed_border="#4c566a",
        prompt_bg="#3b4252",
        prompt_fg="#eceff4",
        prompt_border="#4c566a",
        html_body_bg="#3b4252",
        html_body_fg="#eceff4",
        html_rvt="#616e88",
        html_rva="#eceff4",
        html_tool_bg="#434c5e",
        html_tool_border="#88c0d0",
        html_pre_fg="#e5e9f0",
        html_meta="#616e88",
        html_link="#88c0d0",
        html_notice="#ebcb8b",
        html_code_bg="#434c5e",
    ),
    "dracula": _AgentDockChrome(
        root_bg="#282a36",
        root_fg="#f8f8f2",
        activity_bg="#343746",
        activity_border="#6272a4",
        muted="#bd93f9",
        thinking_fg="#bdc7e0",
        thinking_bg="#44475a",
        thinking_border="#6272a4",
        stream_fg="#f8f8f2",
        stream_bg="#44475a",
        feed_bg="#44475a",
        feed_fg="#f8f8f2",
        feed_border="#6272a4",
        prompt_bg="#44475a",
        prompt_fg="#f8f8f2",
        prompt_border="#6272a4",
        html_body_bg="#44475a",
        html_body_fg="#f8f8f2",
        html_rvt="#6272a4",
        html_rva="#f8f8f2",
        html_tool_bg="#6272a4",
        html_tool_border="#bd93f9",
        html_pre_fg="#e0e0f0",
        html_meta="#6272a4",
        html_link="#8be9fd",
        html_notice="#ffb86c",
        html_code_bg="#6272a4",
    ),
    "onedark": _AgentDockChrome(
        root_bg="#282c34",
        root_fg="#abb2bf",
        activity_bg="#2c323c",
        activity_border="#3e4451",
        muted="#6b7280",
        thinking_fg="#9da5b4",
        thinking_bg="#21252b",
        thinking_border="#3e4451",
        stream_fg="#abb2bf",
        stream_bg="#2c323c",
        feed_bg="#3e4451",
        feed_fg="#abb2bf",
        feed_border="#181a1f",
        prompt_bg="#3e4451",
        prompt_fg="#abb2bf",
        prompt_border="#181a1f",
        html_body_bg="#3e4451",
        html_body_fg="#abb2bf",
        html_rvt="#5c6370",
        html_rva="#c8ccd4",
        html_tool_bg="#2c323c",
        html_tool_border="#61afef",
        html_pre_fg="#abb2bf",
        html_meta="#5c6370",
        html_link="#61afef",
        html_notice="#e5c07b",
        html_code_bg="#2c323c",
    ),
    "solarized_dark": _AgentDockChrome(
        root_bg="#002b36",
        root_fg="#839496",
        activity_bg="#073642",
        activity_border="#586e75",
        muted="#93a1a1",
        thinking_fg="#93a1a1",
        thinking_bg="#073642",
        thinking_border="#586e75",
        stream_fg="#839496",
        stream_bg="#073642",
        feed_bg="#073642",
        feed_fg="#839496",
        feed_border="#586e75",
        prompt_bg="#073642",
        prompt_fg="#839496",
        prompt_border="#586e75",
        html_body_bg="#073642",
        html_body_fg="#839496",
        html_rvt="#586e75",
        html_rva="#eee8d5",
        html_tool_bg="#094656",
        html_tool_border="#268bd2",
        html_pre_fg="#93a1a1",
        html_meta="#586e75",
        html_link="#268bd2",
        html_notice="#b58900",
        html_code_bg="#094656",
    ),
    "kanagawa": _AgentDockChrome(
        root_bg="#1f1f28",
        root_fg="#dcd7ba",
        activity_bg="#2a2a37",
        activity_border="#54546d",
        muted="#9cabca",
        thinking_fg="#a4a09f",
        thinking_bg="#16161d",
        thinking_border="#54546d",
        stream_fg="#dcd7ba",
        stream_bg="#2a2a37",
        feed_bg="#2a2a37",
        feed_fg="#dcd7ba",
        feed_border="#54546d",
        prompt_bg="#2a2a37",
        prompt_fg="#dcd7ba",
        prompt_border="#54546d",
        html_body_bg="#2a2a37",
        html_body_fg="#dcd7ba",
        html_rvt="#727169",
        html_rva="#dcd7ba",
        html_tool_bg="#363646",
        html_tool_border="#7e9cd8",
        html_pre_fg="#c8c093",
        html_meta="#727169",
        html_link="#7e9cd8",
        html_notice="#e6c384",
        html_code_bg="#363646",
    ),
    "light": _AgentDockChrome(
        root_bg="#f6f8fa",
        root_fg="#24292f",
        activity_bg="#eaeef2",
        activity_border="#d0d7de",
        muted="#57606a",
        thinking_fg="#57606a",
        thinking_bg="#ffffff",
        thinking_border="#d0d7de",
        stream_fg="#24292f",
        stream_bg="#ffffff",
        feed_bg="#ffffff",
        feed_fg="#24292f",
        feed_border="#d0d7de",
        prompt_bg="#ffffff",
        prompt_fg="#24292f",
        prompt_border="#d0d7de",
        html_body_bg="#ffffff",
        html_body_fg="#24292f",
        html_rvt="#57606a",
        html_rva="#24292f",
        html_tool_bg="#eaeef2",
        html_tool_border="#0969da",
        html_pre_fg="#24292f",
        html_meta="#57606a",
        html_link="#0969da",
        html_notice="#9a6700",
        html_code_bg="#f6f8fa",
    ),
}


def agent_dock_stylesheet(theme_id: str) -> str:
    """Qt stylesheet for the embedded Agent panel (object names on widgets in ``MainWindow``)."""
    tid = normalize_theme_id(theme_id)
    if tid == "system":
        return """
            QWidget#agent_dock_root { background-color: palette(base); color: palette(window-text); }
            QFrame#agent_activity { background-color: palette(alternate-base); border: 1px solid palette(mid);
                border-radius: 8px; }
            QLabel#agent_gen_label { color: palette(mid); font-size: 10pt; }
            QLabel#agent_live_thinking { color: palette(mid); font-family: Consolas, monospace; font-size: 9pt;
                font-style: italic; background: palette(window); border-radius: 4px; padding: 6px;
                border: 1px solid palette(mid); }
            QLabel#agent_live_stream { color: palette(text); font-family: Consolas, monospace; font-size: 9.5pt;
                background: palette(base); border-radius: 4px; padding: 6px; border: 1px solid palette(mid); }
            QTextBrowser#agent_feed { background-color: palette(base); color: palette(text);
                border: 1px solid palette(mid); border-radius: 6px; }
            QFrame#agent_input_frame { background-color: palette(base); border: 1px solid palette(mid);
                border-radius: 6px; }
            QTextEdit#agent_prompt { background-color: transparent; color: palette(text);
                border: none; padding: 2px; }
        """
    c = _AGENT_DOCK_CHROME.get(tid) or _AGENT_DOCK_CHROME["tokyo_night"]
    return f"""
        QWidget#agent_dock_root {{ background-color: {c.root_bg}; color: {c.root_fg}; }}
        QFrame#agent_activity {{ background-color: {c.activity_bg}; border: 1px solid {c.activity_border}; border-radius: 8px; }}
        QLabel#agent_gen_label {{ color: {c.muted}; font-size: 10pt; }}
        QLabel#agent_live_thinking {{
            color: {c.thinking_fg}; font-family: Consolas, monospace; font-size: 9pt; font-style: italic;
            background: {c.thinking_bg}; border-radius: 4px; padding: 6px; border: 1px solid {c.thinking_border};
        }}
        QLabel#agent_live_stream {{
            color: {c.stream_fg}; font-family: Consolas, monospace; font-size: 9.5pt;
            background: {c.stream_bg}; border-radius: 4px; padding: 6px; border: 1px solid {c.activity_border};
        }}
        QTextBrowser#agent_feed {{
            background-color: {c.feed_bg}; color: {c.feed_fg}; border: 1px solid {c.feed_border}; border-radius: 6px;
        }}
        QFrame#agent_input_frame {{
            background-color: {c.prompt_bg}; border: 1px solid {c.prompt_border}; border-radius: 6px;
        }}
        QTextEdit#agent_prompt {{
            background-color: transparent; color: {c.prompt_fg}; border: none; padding: 2px;
        }}
        QLabel#agent_head_label {{ color: {c.root_fg}; font-weight: bold; font-size: 11pt; }}
        QLabel#agent_provider_chip {{
            color: {c.html_link}; background: {c.html_tool_bg}; border: 1px solid {c.activity_border};
            border-radius: 9px; padding: 1px 9px; font-size: 8.5pt; font-weight: bold;
        }}
        QLabel#agent_chat_title {{ color: {c.muted}; font-style: italic; }}
        QPushButton#btn_send_stop {{
            background: {c.html_tool_bg}; color: {c.root_fg}; border: 1px solid {c.activity_border};
            border-radius: 6px; padding: 4px 14px; font-weight: bold;
        }}
        QPushButton#btn_send_stop:hover {{ border: 1px solid {c.html_link}; }}
        QPushButton#btn_send_stop:disabled {{ color: {c.html_meta}; }}
        QStackedWidget {{ background: {c.feed_bg}; }}
        QLabel#agent_welcome_title {{ color: {c.root_fg}; font-size: 15pt; font-weight: bold; }}
        QLabel#agent_welcome_sub {{ color: {c.muted}; font-size: 10pt; }}
        QPushButton#agent_welcome_pill {{
            color: {c.html_link}; background: {c.html_tool_bg}; border: 1px solid {c.activity_border};
            border-radius: 14px; padding: 7px 16px; font-size: 10pt;
        }}
        QPushButton#agent_welcome_pill:hover {{
            border: 1px solid {c.html_link}; background: {c.prompt_bg};
        }}
        QPushButton#agent_quick_pill {{
            color: {c.muted}; background: {c.html_tool_bg}; border: 1px solid {c.activity_border};
            border-radius: 11px; padding: 3px 11px; font-size: 8.5pt;
        }}
        QPushButton#agent_quick_pill:hover {{ color: {c.root_fg}; border: 1px solid {c.html_link}; }}
    """


def agent_feed_document_default_stylesheet(theme_id: str) -> str:
    """Default CSS for rich text in the Agent feed (must track ``agent_dock_stylesheet`` colors)."""
    tid = normalize_theme_id(theme_id)
    if tid == "system":
        return (
            "body{font-family:'Segoe UI',Consolas,sans-serif;font-size:10pt;}"
            ".rvpre{white-space:pre-wrap;font-family:Consolas,monospace;font-size:9.5pt;}"
            "code,pre{font-family:Consolas,monospace;font-size:9.5pt;}"
            ".rvu{border-left:2px solid #888;padding-left:6px;margin:4px 0;}"
            ".rvavatar{font-size:10pt;margin-right:4px;}"
            "a.rvlink:hover{text-decoration:underline;}"
        )
    c = _AGENT_DOCK_CHROME.get(tid) or _AGENT_DOCK_CHROME["tokyo_night"]
    # Qt's rich-text engine honours background/border/padding/margin but ignores border-radius, so
    # the message "cards" are flat fills with an accent left edge rather than rounded bubbles - the
    # rounding lives on the widget frame. The point is clear role separation and breathing room.
    return (
        f"body{{font-family:'Segoe UI',Consolas,sans-serif;font-size:10pt;color:{c.html_body_fg};"
        f"background:{c.html_body_bg};}}"
        # assistant: soft card, accent left edge
        f".rva{{color:{c.html_rva};line-height:1.5;background:{c.html_tool_bg};"
        f"border-left:3px solid {c.html_tool_border};padding:8px 12px;margin:8px 0;}}"
        # user: distinct tint, quieter left edge
        f".rvu{{color:{c.html_rva};line-height:1.5;background:{c.html_body_bg};"
        f"border-left:3px solid {c.html_link};padding:8px 12px;margin:8px 0;}}"
        # thinking: muted, dashed edge, sits back
        f".rvt{{color:{c.html_rvt};font-style:italic;background:{c.thinking_bg};"
        f"border-left:2px dashed {c.html_meta};padding:6px 12px;margin:6px 0;line-height:1.45;}}"
        f".rvavatar{{font-size:10pt;margin-right:6px;font-weight:bold;}}"
        f".rvtool{{background:{c.html_tool_bg};border-left:3px solid {c.html_tool_border};"
        f"padding:8px 12px;margin:8px 0;}}"
        f".rvtool-fold{{border-left-color:{c.html_meta};}}"
        ".rvweb .rvweb-primary{margin-top:6px;word-break:break-all;}"
        f".rvpre{{white-space:pre-wrap;font-family:Consolas,monospace;font-size:9.5pt;color:{c.html_pre_fg};"
        f"background:{c.html_code_bg};padding:8px;margin-top:6px;}}"
        f".rvmeta{{color:{c.html_meta};font-size:8.5pt;letter-spacing:0.3px;}}"
        f".rvlink{{color:{c.html_link};text-decoration:none;}}"
        f".rvnotice{{color:{c.html_notice};font-size:9.5pt;background:{c.thinking_bg};"
        f"border-left:3px solid {c.html_notice};padding:6px 12px;margin:6px 0;}}"
        "a.rvlink:hover{text-decoration:underline;}"
        f"code{{font-family:Consolas,monospace;background:{c.html_code_bg};padding:1px 4px;"
        f"font-size:9.5pt;}}"
        f"pre{{background:{c.html_code_bg};padding:8px;}}"
    )


def apply_application_style(app: QApplication, theme_id: str) -> None:
    """Set QStyle so custom palettes look consistent; ``system`` follows the OS style."""
    tid = normalize_theme_id(theme_id)
    if tid == "system":
        app.setStyle("")
    else:
        app.setStyle("Fusion")


@dataclass(frozen=True)
class SplashPalette:
    panel: str
    grad_a: str
    grad_b: str
    grad_c: str
    text: str
    accent: str
    muted: str
    status: str
    border: str
    btn_bg: str
    btn_hover: str
    bar_track: str
    bar_a: str
    bar_b: str


def splash_palette(theme_id: str) -> SplashPalette:
    """Return splash-screen color palette for the given theme."""
    tid = normalize_theme_id(theme_id)
    if tid == "gruvbox":
        return SplashPalette(
            panel="#282828", grad_a="#1d2021", grad_b="#282828", grad_c="#1d2021",
            text="#ebdbb2", accent="#83a598", muted="#928374", status="#bdae93",
            border="#3d3835", btn_bg="#504945", btn_hover="#665c54",
            bar_track="#3c3836", bar_a="#83a598", bar_b="#d3869b",
        )
    if tid == "catppuccin_mocha":
        return SplashPalette(
            panel="#1e1e2e", grad_a="#181825", grad_b="#1e1e2e", grad_c="#11111b",
            text="#cdd6f4", accent="#89b4fa", muted="#6c7086", status="#bac2de",
            border="#313244", btn_bg="#45475a", btn_hover="#585b70",
            bar_track="#313244", bar_a="#89b4fa", bar_b="#cba6f7",
        )
    if tid == "nord":
        return SplashPalette(
            panel="#2e3440", grad_a="#242933", grad_b="#2e3440", grad_c="#1e232c",
            text="#eceff4", accent="#88c0d0", muted="#616e88", status="#d8dee9",
            border="#434c5e", btn_bg="#4c566a", btn_hover="#5e6a80",
            bar_track="#3b4252", bar_a="#88c0d0", bar_b="#b48ead",
        )
    if tid == "dracula":
        return SplashPalette(
            panel="#282a36", grad_a="#1e1f29", grad_b="#282a36", grad_c="#191a22",
            text="#f8f8f2", accent="#bd93f9", muted="#6272a4", status="#e2e2f0",
            border="#44475a", btn_bg="#44475a", btn_hover="#6272a4",
            bar_track="#383a4a", bar_a="#bd93f9", bar_b="#ff79c6",
        )
    if tid == "onedark":
        return SplashPalette(
            panel="#282c34", grad_a="#1d2027", grad_b="#282c34", grad_c="#1a1d22",
            text="#abb2bf", accent="#61afef", muted="#5c6370", status="#98a0b0",
            border="#3e4451", btn_bg="#3e4451", btn_hover="#5c6370",
            bar_track="#2c323c", bar_a="#61afef", bar_b="#c678dd",
        )
    if tid == "solarized_dark":
        return SplashPalette(
            panel="#002b36", grad_a="#001f27", grad_b="#002b36", grad_c="#001a23",
            text="#839496", accent="#268bd2", muted="#586e75", status="#657b83",
            border="#073642", btn_bg="#073642", btn_hover="#586e75",
            bar_track="#073642", bar_a="#268bd2", bar_b="#6c71c4",
        )
    if tid == "kanagawa":
        return SplashPalette(
            panel="#1f1f28", grad_a="#16161d", grad_b="#1f1f28", grad_c="#13131b",
            text="#dcd7ba", accent="#7e9cd8", muted="#727169", status="#c8c093",
            border="#363646", btn_bg="#54546d", btn_hover="#727169",
            bar_track="#2a2a37", bar_a="#7e9cd8", bar_b="#957fb8",
        )
    if tid == "light":
        return SplashPalette(
            panel="#f0f4f8", grad_a="#e8eef5", grad_b="#f0f4f8", grad_c="#dde6ef",
            text="#24292f", accent="#0969da", muted="#57606a", status="#57606a",
            border="#c8d0da", btn_bg="#e2e8f0", btn_hover="#cdd4de",
            bar_track="#d0d9e4", bar_a="#0969da", bar_b="#0550ae",
        )
    # Tokyo Night (default, also covers "system")
    return SplashPalette(
        panel="#1a1b26", grad_a="#16161e", grad_b="#1a1b26", grad_c="#13141c",
        text="#c0caf5", accent="#7aa2f7", muted="#565f89", status="#a9b1d6",
        border="#3b4261", btn_bg="#414868", btn_hover="#565f89",
        bar_track="#24283b", bar_a="#7aa2f7", bar_b="#bb9af7",
    )
