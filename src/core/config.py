"""Configuration management for Debloatr.

This module handles loading, saving, and validating configuration
from JSON files and environment variables.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Default paths
DEFAULT_CONFIG_DIR = Path(os.environ.get("APPDATA", "~")) / "Debloatr"
DEFAULT_CONFIG_FILE = "config.json"
DEFAULT_SIGNATURES_DIR = "signatures"
DEFAULT_PROFILES_DIR = "profiles"
DEFAULT_QUARANTINE_DIR = "quarantine"
DEFAULT_SNAPSHOTS_DIR = "snapshots"
DEFAULT_LOGS_DIR = "logs"


@dataclass
class ScanConfig:
    """Configuration for scanning behavior."""

    scan_programs: bool = True
    scan_services: bool = True
    scan_tasks: bool = True
    scan_startup: bool = True
    scan_drivers: bool = True
    scan_telemetry: bool = True
    scan_uwp: bool = True
    include_microsoft: bool = True
    include_portable: bool = True


@dataclass
class ActionConfig:
    """Configuration for action behavior."""

    default_mode: str = "DRY_RUN"  # SCAN_ONLY, DRY_RUN, INTERACTIVE, BATCH_CONFIRM
    require_confirmation: bool = True
    create_restore_point: bool = True
    staging_days_oem: int = 7  # Days to wait before allowing OEM removal
    enable_quarantine: bool = True
    command_timeout_seconds: int = 60  # Timeout for PowerShell/subprocess commands


@dataclass
class ClassificationConfig:
    """Configuration for classification behavior."""

    use_signatures: bool = True
    use_heuristics: bool = True
    use_llm: bool = False
    llm_endpoint: str = ""
    llm_api_key: str = ""
    auto_classify_unknown_as: str = "UNKNOWN"  # Classification for unknowns
    heuristic_threshold: float = 0.6  # Score threshold for BLOAT classification


@dataclass
class UIConfig:
    """Configuration for user interface."""

    theme: str = "system"  # system, light, dark
    show_risk_warnings: bool = True
    confirm_before_action: bool = True
    show_explanations: bool = True


@dataclass
class Config:
    """Main configuration container for Debloatr.

    Attributes:
        config_dir: Base directory for all Debloatr data
        signatures_dir: Directory containing signature databases
        profiles_dir: Directory containing configuration profiles
        quarantine_dir: Directory for quarantined files
        snapshots_dir: Directory for rollback snapshots
        logs_dir: Directory for log files
        scan: Scanning configuration
        actions: Action configuration
        classification: Classification configuration
        ui: UI configuration
        protected_components: List of component names to never modify
        blocked_publishers: List of publishers to always flag
        custom_signatures: List of custom signature file paths
    """

    config_dir: Path = field(default_factory=lambda: DEFAULT_CONFIG_DIR.expanduser())
    signatures_dir: Path = field(default_factory=lambda: Path(DEFAULT_SIGNATURES_DIR))
    profiles_dir: Path = field(default_factory=lambda: Path(DEFAULT_PROFILES_DIR))
    quarantine_dir: Path = field(default_factory=lambda: Path(DEFAULT_QUARANTINE_DIR))
    snapshots_dir: Path = field(default_factory=lambda: Path(DEFAULT_SNAPSHOTS_DIR))
    logs_dir: Path = field(default_factory=lambda: Path(DEFAULT_LOGS_DIR))

    scan: ScanConfig = field(default_factory=ScanConfig)
    actions: ActionConfig = field(default_factory=ActionConfig)
    classification: ClassificationConfig = field(default_factory=ClassificationConfig)
    ui: UIConfig = field(default_factory=UIConfig)

    protected_components: list[str] = field(default_factory=list)
    blocked_publishers: list[str] = field(default_factory=list)
    custom_signatures: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Resolve relative paths to absolute paths."""
        if not self.signatures_dir.is_absolute():
            self.signatures_dir = self.config_dir / self.signatures_dir
        if not self.profiles_dir.is_absolute():
            self.profiles_dir = self.config_dir / self.profiles_dir
        if not self.quarantine_dir.is_absolute():
            self.quarantine_dir = self.config_dir / self.quarantine_dir
        if not self.snapshots_dir.is_absolute():
            self.snapshots_dir = self.config_dir / self.snapshots_dir
        if not self.logs_dir.is_absolute():
            self.logs_dir = self.config_dir / self.logs_dir

    def ensure_directories(self) -> None:
        """Create all required directories if they don't exist."""
        for directory in [
            self.config_dir,
            self.signatures_dir,
            self.profiles_dir,
            self.quarantine_dir,
            self.snapshots_dir,
            self.logs_dir,
        ]:
            directory.mkdir(parents=True, exist_ok=True)

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary for JSON serialization."""
        return {
            "config_dir": str(self.config_dir),
            "signatures_dir": str(self.signatures_dir),
            "profiles_dir": str(self.profiles_dir),
            "quarantine_dir": str(self.quarantine_dir),
            "snapshots_dir": str(self.snapshots_dir),
            "logs_dir": str(self.logs_dir),
            "scan": {
                "scan_programs": self.scan.scan_programs,
                "scan_services": self.scan.scan_services,
                "scan_tasks": self.scan.scan_tasks,
                "scan_startup": self.scan.scan_startup,
                "scan_drivers": self.scan.scan_drivers,
                "scan_telemetry": self.scan.scan_telemetry,
                "scan_uwp": self.scan.scan_uwp,
                "include_microsoft": self.scan.include_microsoft,
                "include_portable": self.scan.include_portable,
            },
            "actions": {
                "default_mode": self.actions.default_mode,
                "require_confirmation": self.actions.require_confirmation,
                "create_restore_point": self.actions.create_restore_point,
                "staging_days_oem": self.actions.staging_days_oem,
                "enable_quarantine": self.actions.enable_quarantine,
                "command_timeout_seconds": self.actions.command_timeout_seconds,
            },
            "classification": {
                "use_signatures": self.classification.use_signatures,
                "use_heuristics": self.classification.use_heuristics,
                "use_llm": self.classification.use_llm,
                "llm_endpoint": self.classification.llm_endpoint,
                "auto_classify_unknown_as": self.classification.auto_classify_unknown_as,
                "heuristic_threshold": self.classification.heuristic_threshold,
            },
            "ui": {
                "theme": self.ui.theme,
                "show_risk_warnings": self.ui.show_risk_warnings,
                "confirm_before_action": self.ui.confirm_before_action,
                "show_explanations": self.ui.show_explanations,
            },
            "protected_components": self.protected_components,
            "blocked_publishers": self.blocked_publishers,
            "custom_signatures": self.custom_signatures,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        """Create configuration from dictionary."""
        config = cls()

        if "config_dir" in data:
            config.config_dir = Path(data["config_dir"])

        # Load scan config
        if "scan" in data:
            scan_data = data["scan"]
            config.scan = ScanConfig(
                scan_programs=scan_data.get("scan_programs", True),
                scan_services=scan_data.get("scan_services", True),
                scan_tasks=scan_data.get("scan_tasks", True),
                scan_startup=scan_data.get("scan_startup", True),
                scan_drivers=scan_data.get("scan_drivers", True),
                scan_telemetry=scan_data.get("scan_telemetry", True),
                scan_uwp=scan_data.get("scan_uwp", True),
                include_microsoft=scan_data.get("include_microsoft", True),
                include_portable=scan_data.get("include_portable", True),
            )

        # Load actions config
        if "actions" in data:
            actions_data = data["actions"]
            config.actions = ActionConfig(
                default_mode=actions_data.get("default_mode", "DRY_RUN"),
                require_confirmation=actions_data.get("require_confirmation", True),
                create_restore_point=actions_data.get("create_restore_point", True),
                staging_days_oem=actions_data.get("staging_days_oem", 7),
                enable_quarantine=actions_data.get("enable_quarantine", True),
                command_timeout_seconds=actions_data.get("command_timeout_seconds", 60),
            )

        # Load classification config
        if "classification" in data:
            class_data = data["classification"]
            config.classification = ClassificationConfig(
                use_signatures=class_data.get("use_signatures", True),
                use_heuristics=class_data.get("use_heuristics", True),
                use_llm=class_data.get("use_llm", False),
                llm_endpoint=class_data.get("llm_endpoint", ""),
                llm_api_key=class_data.get("llm_api_key", ""),
                auto_classify_unknown_as=class_data.get("auto_classify_unknown_as", "UNKNOWN"),
                heuristic_threshold=class_data.get("heuristic_threshold", 0.6),
            )

        # Load UI config
        if "ui" in data:
            ui_data = data["ui"]
            config.ui = UIConfig(
                theme=ui_data.get("theme", "system"),
                show_risk_warnings=ui_data.get("show_risk_warnings", True),
                confirm_before_action=ui_data.get("confirm_before_action", True),
                show_explanations=ui_data.get("show_explanations", True),
            )

        # Load lists
        config.protected_components = data.get("protected_components", [])
        config.blocked_publishers = data.get("blocked_publishers", [])
        config.custom_signatures = data.get("custom_signatures", [])

        # Re-run post_init to resolve paths
        config.__post_init__()

        return config


def load_config(config_path: Path | None = None) -> Config:
    """Load configuration from file.

    Args:
        config_path: Path to config file. If None, uses default location.

    Returns:
        Config object with loaded settings.

    Raises:
        FileNotFoundError: If specified config file doesn't exist.
        json.JSONDecodeError: If config file contains invalid JSON.
    """
    if config_path is None:
        config_path = DEFAULT_CONFIG_DIR.expanduser() / DEFAULT_CONFIG_FILE

    if not config_path.exists():
        # Return default config if no config file exists
        return Config()

    with open(config_path, encoding="utf-8") as f:
        data = json.load(f)

    return Config.from_dict(data)


def save_config(config: Config, config_path: Path | None = None) -> None:
    """Save configuration to file.

    Args:
        config: Config object to save.
        config_path: Path to config file. If None, uses default location.
    """
    if config_path is None:
        config_path = config.config_dir / DEFAULT_CONFIG_FILE

    # Ensure directory exists
    config_path.parent.mkdir(parents=True, exist_ok=True)

    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config.to_dict(), f, indent=2)


def get_default_config() -> Config:
    """Get the default configuration.

    Returns:
        A new Config object with default settings.
    """
    return Config()
