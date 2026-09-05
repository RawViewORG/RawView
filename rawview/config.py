from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from rawview.theme_ids import THEME_IDS as _RAWVIEW_THEME_IDS_TUPLE

_RAWVIEW_THEME_IDS = frozenset(_RAWVIEW_THEME_IDS_TUPLE)


def user_data_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))) / "RawView"
    elif sys.platform == "darwin":
        # ~/Library/Application Support is where a macOS app is expected to keep this,
        # but an XDG dir already in place belongs to someone who ran from source before
        # there were mac packages - keep using it rather than stranding their sessions.
        legacy = Path(os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))) / "RawView"
        base = legacy if legacy.is_dir() else Path(os.path.expanduser("~/Library/Application Support")) / "RawView"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))) / "RawView"
    base.mkdir(parents=True, exist_ok=True)
    return base


def user_settings_env_path() -> Path:
    """Per-user settings file (preferred for the Qt app)."""
    return user_data_dir() / "rawview.env"


def _default_project_dir() -> Path:
    return user_data_dir() / "ghidra_projects"


def parse_ghidra_jvm_max_heap(value: str | None) -> str:
    """
    Return a valid ``-Xmx`` *value* only (no ``-Xmx`` prefix), e.g. ``8g`` or ``8192m``.

    Suffix ``g``, ``m``, or ``k`` is required so bare numbers are not mistaken for bytes.
    """
    if value is None:
        return "8g"
    s = str(value).strip()
    if not s:
        return "8g"
    if not re.fullmatch(r"[0-9]+[gGmMkK]", s):
        raise ValueError(
            "GHIDRA_JVM_MAX_HEAP must look like 8g, 16g, or 8192m (suffix g, m, or k required)."
        )
    return s[:-1] + s[-1].lower()


def _env_files() -> tuple[Path, ...]:
    """Later entries override earlier (cwd `.env` wins over user file for developers)."""
    user = user_settings_env_path()
    cwd = Path.cwd() / ".env"
    repo_rawview = Path.cwd() / "rawview.env"
    return (user, repo_rawview, cwd)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_env_files(),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    anthropic_api_key: str = Field(default="", validation_alias="ANTHROPIC_API_KEY")
    anthropic_model: str = Field(default="claude-opus-5", validation_alias="ANTHROPIC_MODEL")

    # Which backend the agent talks to. "anthropic" keeps the fields above, so existing
    # installs and rawview.env files are unaffected. Every other preset is served by the
    # OpenAI-compatible adapter and uses the llm_* fields below.
    llm_provider: str = Field(default="anthropic", validation_alias="LLM_PROVIDER")
    llm_base_url: str = Field(
        default="",
        validation_alias="LLM_BASE_URL",
        description="Override the preset's base URL (required for the 'custom' preset).",
    )
    llm_api_key: str = Field(default="", validation_alias="LLM_API_KEY")
    llm_model: str = Field(default="", validation_alias="LLM_MODEL")
    llm_max_tokens: int = Field(default=4096, validation_alias="LLM_MAX_TOKENS")
    llm_supports_tools: bool = Field(
        default=True,
        validation_alias="LLM_SUPPORTS_TOOLS",
        description="Turn off for local models whose chat template cannot emit tool calls.",
    )

    ghidra_install_dir: Path | None = Field(default=None, validation_alias="GHIDRA_INSTALL_DIR")
    ghidra_bundle_url: str = Field(
        default="",
        validation_alias="GHIDRA_BUNDLE_URL",
        description="Override URL for the Ghidra public zip download.",
    )

    rawview_sandbox: str = Field(default="bwrap", validation_alias="RAWVIEW_SANDBOX")

    rawview_auto_start_bridge: bool = Field(default=True, validation_alias="RAWVIEW_AUTO_START_BRIDGE")

    @field_validator("rawview_sandbox", mode="before")
    @classmethod
    def _normalize_sandbox(cls, v: object) -> object:
        if v is None:
            return "bwrap"
        val = str(v).strip().lower()
        return val if val in ("none", "bwrap") else "bwrap"

    @field_validator("ghidra_install_dir", mode="before")
    @classmethod
    def _empty_ghidra_dir_none(cls, v: object) -> object:
        if v is None or v == "":
            return None
        return v

    @field_validator("rawview_java_classes_dir", mode="before")
    @classmethod
    def _empty_java_classes_none(cls, v: object) -> object:
        if v is None or v == "":
            return None
        return v

    @field_validator("ghidra_jvm_max_heap", mode="before")
    @classmethod
    def _normalize_jvm_heap(cls, v: object) -> str:
        if v is None or (isinstance(v, str) and not str(v).strip()):
            return "8g"
        return parse_ghidra_jvm_max_heap(str(v))

    java_executable: str = Field(default="java", validation_alias="JAVA_EXECUTABLE")
    ghidra_jvm_max_heap: str = Field(default="8g", validation_alias="GHIDRA_JVM_MAX_HEAP")
    py4j_port: int = Field(default=25333, validation_alias="PY4J_PORT")
    rawview_project_dir: Path = Field(default_factory=_default_project_dir, validation_alias="RAWVIEW_PROJECT_DIR")

    rawview_java_classpath: str | None = Field(default=None, validation_alias="RAWVIEW_JAVA_CLASSPATH")
    rawview_java_classes_dir: Path | None = Field(default=None, validation_alias="RAWVIEW_JAVA_CLASSES_DIR")

    agent_max_turns: int = Field(default=32, validation_alias="AGENT_MAX_TURNS")
    agent_history_messages: int = Field(default=64, validation_alias="AGENT_HISTORY_MESSAGES")
    agent_effort: str = Field(default="medium", validation_alias="AGENT_EFFORT")
    agent_extended_thinking: bool = Field(default=True, validation_alias="AGENT_EXTENDED_THINKING")
    agent_thinking_budget_tokens: int = Field(
        default=4096,
        ge=1024,
        le=100_000,
        validation_alias="AGENT_THINKING_BUDGET_TOKENS",
    )
    # Anthropic Messages API default is 1.0; lower values favor analytical / tool-stable behavior per docs.
    agent_temperature: float = Field(
        default=0.3,
        ge=0.0,
        le=1.0,
        validation_alias="AGENT_TEMPERATURE",
    )

    rawview_theme: str = Field(default="tokyo_night", validation_alias="RAWVIEW_THEME")

    discord_client_id: str = Field(default="1519331610510622893", validation_alias="DISCORD_CLIENT_ID")

    @field_validator("rawview_theme", mode="before")
    @classmethod
    def _normalize_theme(cls, v: object) -> object:
        if v is None or str(v).strip() == "":
            return "tokyo_night"
        t = str(v).strip().lower().replace("-", "_")
        return t if t in _RAWVIEW_THEME_IDS else "tokyo_night"


def load_settings() -> Settings:
    return Settings()


def save_user_settings_file(updates: dict[str, str]) -> Path:
    """
    Write key=value pairs to the user `rawview.env` file (merges over existing keys).
    Empty string values remove that key from the file.
    """
    path = user_settings_env_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    existing: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                existing[k.strip()] = v.strip()
    for k, v in updates.items():
        if v == "":
            existing.pop(k, None)
        else:
            existing[k] = v
    lines_out = ["# RawView user settings (written by the Settings dialog)", ""]
    for k in sorted(existing.keys()):
        lines_out.append(f"{k}={existing[k]}")
    lines_out.append("")
    path.write_text("\n".join(lines_out), encoding="utf-8")
    return path
