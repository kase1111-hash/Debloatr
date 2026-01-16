"""Tests for configuration management."""

import json
import pytest
from pathlib import Path
from tempfile import TemporaryDirectory

from src.core.config import (
    Config,
    ScanConfig,
    ActionConfig,
    ClassificationConfig,
    UIConfig,
    load_config,
    save_config,
    get_default_config,
)


class TestScanConfig:
    """Tests for ScanConfig."""

    def test_default_values(self):
        """Test default scan configuration values."""
        config = ScanConfig()

        assert config.scan_programs is True
        assert config.scan_services is True
        assert config.scan_tasks is True
        assert config.scan_startup is True
        assert config.scan_drivers is True
        assert config.scan_telemetry is True
        assert config.scan_uwp is True
        assert config.include_microsoft is True
        assert config.include_portable is True


class TestActionConfig:
    """Tests for ActionConfig."""

    def test_default_values(self):
        """Test default action configuration values."""
        config = ActionConfig()

        assert config.default_mode == "DRY_RUN"
        assert config.require_confirmation is True
        assert config.create_restore_point is True
        assert config.staging_days_oem == 7
        assert config.enable_quarantine is True


class TestClassificationConfig:
    """Tests for ClassificationConfig."""

    def test_default_values(self):
        """Test default classification configuration values."""
        config = ClassificationConfig()

        assert config.use_signatures is True
        assert config.use_heuristics is True
        assert config.use_llm is False
        assert config.llm_endpoint == ""
        assert config.auto_classify_unknown_as == "UNKNOWN"
        assert config.heuristic_threshold == 0.6


class TestConfig:
    """Tests for main Config class."""

    def test_default_config(self):
        """Test default configuration creation."""
        config = Config()

        assert config.scan is not None
        assert config.actions is not None
        assert config.classification is not None
        assert config.ui is not None
        assert config.protected_components == []
        assert config.blocked_publishers == []

    def test_ensure_directories(self):
        """Test directory creation."""
        with TemporaryDirectory() as tmpdir:
            config = Config(config_dir=Path(tmpdir) / "debloatr")
            config.ensure_directories()

            assert config.config_dir.exists()
            assert config.signatures_dir.exists()
            assert config.profiles_dir.exists()
            assert config.quarantine_dir.exists()
            assert config.snapshots_dir.exists()
            assert config.logs_dir.exists()

    def test_to_dict(self):
        """Test configuration serialization to dictionary."""
        config = Config()
        data = config.to_dict()

        assert "config_dir" in data
        assert "scan" in data
        assert "actions" in data
        assert "classification" in data
        assert "ui" in data
        assert data["scan"]["scan_programs"] is True
        assert data["actions"]["default_mode"] == "DRY_RUN"

    def test_from_dict(self):
        """Test configuration deserialization from dictionary."""
        data = {
            "scan": {
                "scan_programs": False,
                "scan_services": True,
            },
            "actions": {
                "default_mode": "INTERACTIVE",
            },
            "protected_components": ["important-app"],
        }

        config = Config.from_dict(data)

        assert config.scan.scan_programs is False
        assert config.scan.scan_services is True
        assert config.actions.default_mode == "INTERACTIVE"
        assert "important-app" in config.protected_components

    def test_roundtrip(self):
        """Test configuration roundtrip through dict."""
        original = Config()
        original.scan.scan_programs = False
        original.actions.default_mode = "BATCH_CONFIRM"
        original.protected_components = ["test-component"]

        data = original.to_dict()
        restored = Config.from_dict(data)

        assert restored.scan.scan_programs == original.scan.scan_programs
        assert restored.actions.default_mode == original.actions.default_mode
        assert restored.protected_components == original.protected_components


class TestConfigFileOperations:
    """Tests for config file save/load operations."""

    def test_save_and_load_config(self):
        """Test saving and loading configuration from file."""
        with TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"

            # Create and save config
            config = Config(config_dir=Path(tmpdir))
            config.scan.scan_programs = False
            config.actions.default_mode = "INTERACTIVE"
            save_config(config, config_path)

            # Verify file exists
            assert config_path.exists()

            # Load and verify
            loaded = load_config(config_path)
            assert loaded.scan.scan_programs is False
            assert loaded.actions.default_mode == "INTERACTIVE"

    def test_load_nonexistent_returns_default(self):
        """Test loading from nonexistent file returns default config."""
        with TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "nonexistent.json"
            config = load_config(config_path)

            # Should return default config
            assert config.scan.scan_programs is True
            assert config.actions.default_mode == "DRY_RUN"

    def test_get_default_config(self):
        """Test get_default_config function."""
        config = get_default_config()

        assert isinstance(config, Config)
        assert config.scan.scan_programs is True
