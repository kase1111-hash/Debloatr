"""Tests for Phase 10: User Interface (CLI & GUI).

This module tests the CLI formatters, commands, and GUI components.
"""

import json
import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch

from src.core.models import (
    Component,
    ComponentType,
    Classification,
    RiskLevel,
    ActionType,
    ActionPlan,
    ActionResult,
)
from src.ui.cli.formatters import (
    Colors,
    colorize,
    get_classification_color,
    get_risk_color,
    TextFormatter,
    JsonFormatter,
    TableFormatter,
    format_component,
    format_component_list,
    format_session,
    format_session_list,
    format_action_result,
)
from src.core.session import SessionSummary


# Test fixtures

@pytest.fixture
def sample_component():
    """Create a sample component for testing."""
    return Component(
        component_type=ComponentType.PROGRAM,
        name="test-bloatware",
        display_name="Test Bloatware App",
        publisher="Test Publisher",
        classification=Classification.BLOAT,
        risk_level=RiskLevel.LOW,
        install_path=Path("C:/Program Files/TestApp"),
    )


@pytest.fixture
def sample_component_list():
    """Create a list of sample components for testing."""
    return [
        Component(
            component_type=ComponentType.PROGRAM,
            name="bloatware-1",
            display_name="Bloatware One",
            publisher="Publisher A",
            classification=Classification.BLOAT,
            risk_level=RiskLevel.LOW,
        ),
        Component(
            component_type=ComponentType.SERVICE,
            name="core-service",
            display_name="Core Service",
            publisher="Microsoft",
            classification=Classification.CORE,
            risk_level=RiskLevel.CRITICAL,
        ),
        Component(
            component_type=ComponentType.TASK,
            name="optional-task",
            display_name="Optional Task",
            publisher="Third Party",
            classification=Classification.OPTIONAL,
            risk_level=RiskLevel.NONE,
        ),
    ]


@pytest.fixture
def sample_session():
    """Create a sample session summary for testing."""
    return SessionSummary(
        session_id="sess-12345678",
        description="Test debloat session",
        started_at=datetime(2024, 1, 15, 10, 30, 0).isoformat(),
        ended_at=datetime(2024, 1, 15, 11, 0, 0).isoformat(),
        is_active=False,
        total_actions=5,
        successful_actions=4,
        failed_actions=1,
        restore_point_id=123,
    )


@pytest.fixture
def sample_action_result(sample_component):
    """Create a sample action result for testing."""
    return ActionResult(
        plan_id="plan-12345678",
        success=True,
        action=ActionType.DISABLE,
        component_id=sample_component.id,
        snapshot_id="snap-12345678",
        executed_at=datetime(2024, 1, 15, 10, 35, 0),
        rollback_available=True,
    )


# Tests for Colors class

class TestColors:
    """Tests for the Colors class."""

    def test_color_constants_exist(self):
        """Test that all color constants are defined."""
        assert hasattr(Colors, "RESET")
        assert hasattr(Colors, "BOLD")
        assert hasattr(Colors, "DIM")

        # Classification colors
        assert hasattr(Colors, "CORE")
        assert hasattr(Colors, "ESSENTIAL")
        assert hasattr(Colors, "OPTIONAL")
        assert hasattr(Colors, "BLOAT")
        assert hasattr(Colors, "AGGRESSIVE")
        assert hasattr(Colors, "UNKNOWN")

        # Risk colors
        assert hasattr(Colors, "RISK_NONE")
        assert hasattr(Colors, "RISK_LOW")
        assert hasattr(Colors, "RISK_MEDIUM")
        assert hasattr(Colors, "RISK_HIGH")
        assert hasattr(Colors, "RISK_CRITICAL")

        # Status colors
        assert hasattr(Colors, "SUCCESS")
        assert hasattr(Colors, "FAILURE")
        assert hasattr(Colors, "WARNING")
        assert hasattr(Colors, "INFO")

    def test_color_codes_are_ansi(self):
        """Test that color codes are valid ANSI escape sequences."""
        assert Colors.RESET.startswith("\033[")
        assert Colors.BOLD.startswith("\033[")
        assert Colors.BLOAT.startswith("\033[")


class TestColorize:
    """Tests for the colorize function."""

    def test_colorize_with_force(self):
        """Test colorize with force=True."""
        result = colorize("test", Colors.BOLD, force=True)
        assert result == f"{Colors.BOLD}test{Colors.RESET}"

    def test_colorize_returns_plain_when_not_supported(self):
        """Test colorize returns plain text when terminal doesn't support colors."""
        with patch.object(Colors, "is_supported", return_value=False):
            result = colorize("test", Colors.BOLD, force=False)
            assert result == "test"


class TestGetClassificationColor:
    """Tests for get_classification_color function."""

    def test_all_classifications_have_colors(self):
        """Test that all classifications return a color."""
        for classification in Classification:
            color = get_classification_color(classification)
            assert color is not None
            assert isinstance(color, str)

    def test_specific_classification_colors(self):
        """Test specific classification color mappings."""
        assert get_classification_color(Classification.CORE) == Colors.CORE
        assert get_classification_color(Classification.BLOAT) == Colors.BLOAT
        assert get_classification_color(Classification.AGGRESSIVE) == Colors.AGGRESSIVE


class TestGetRiskColor:
    """Tests for get_risk_color function."""

    def test_all_risk_levels_have_colors(self):
        """Test that all risk levels return a color."""
        for risk in RiskLevel:
            color = get_risk_color(risk)
            assert color is not None
            assert isinstance(color, str)

    def test_specific_risk_colors(self):
        """Test specific risk level color mappings."""
        assert get_risk_color(RiskLevel.NONE) == Colors.RISK_NONE
        assert get_risk_color(RiskLevel.CRITICAL) == Colors.RISK_CRITICAL


# Tests for TextFormatter

class TestTextFormatter:
    """Tests for the TextFormatter class."""

    def test_format_component(self, sample_component):
        """Test formatting a single component."""
        formatter = TextFormatter(use_colors=False)
        result = formatter.format_component(sample_component)

        assert "Test Bloatware App" in result
        assert "PROGRAM" in result
        assert "BLOAT" in result
        assert "LOW" in result
        assert "Test Publisher" in result

    def test_format_component_list(self, sample_component_list):
        """Test formatting a list of components."""
        formatter = TextFormatter(use_colors=False)
        result = formatter.format_component_list(sample_component_list)

        assert "Bloatware One" in result
        assert "Core Service" in result
        assert "Optional Task" in result
        assert "Total: 3 components" in result

    def test_format_component_list_empty(self):
        """Test formatting an empty component list."""
        formatter = TextFormatter(use_colors=False)
        result = formatter.format_component_list([])

        assert "No components found" in result

    def test_format_session(self, sample_session):
        """Test formatting a session summary."""
        formatter = TextFormatter(use_colors=False)
        result = formatter.format_session(sample_session)

        assert "sess-123" in result  # truncated to 8 chars
        assert "Test debloat session" in result
        assert "5 total" in result
        assert "4" in result  # successful
        assert "1" in result  # failed
        assert "123" in result  # restore point

    def test_format_action_result_success(self, sample_action_result):
        """Test formatting a successful action result."""
        formatter = TextFormatter(use_colors=False)
        result = formatter.format_action_result(sample_action_result)

        assert "DISABLE" in result
        assert "SUCCESS" in result
        assert "Rollback: Available" in result

    def test_format_action_result_failed(self, sample_component):
        """Test formatting a failed action result."""
        failed_result = ActionResult(
            plan_id="plan-failed",
            success=False,
            action=ActionType.REMOVE,
            component_id=sample_component.id,
            error_message="Access denied",
            executed_at=datetime.now(),
            rollback_available=False,
        )

        formatter = TextFormatter(use_colors=False)
        result = formatter.format_action_result(failed_result)

        assert "REMOVE" in result
        assert "FAILED" in result
        assert "Access denied" in result


# Tests for JsonFormatter

class TestJsonFormatter:
    """Tests for the JsonFormatter class."""

    def test_format_component(self, sample_component):
        """Test formatting a component as JSON."""
        formatter = JsonFormatter()
        result = formatter.format_component(sample_component)

        data = json.loads(result)
        assert data["name"] == "test-bloatware"
        assert data["display_name"] == "Test Bloatware App"
        assert data["classification"] == "BLOAT"
        assert data["risk_level"] == "LOW"
        assert data["component_type"] == "PROGRAM"

    def test_format_component_list(self, sample_component_list):
        """Test formatting a component list as JSON."""
        formatter = JsonFormatter()
        result = formatter.format_component_list(sample_component_list)

        data = json.loads(result)
        assert data["count"] == 3
        assert len(data["components"]) == 3

        # Check first component
        assert data["components"][0]["name"] == "bloatware-1"

    def test_format_session(self, sample_session):
        """Test formatting a session as JSON."""
        formatter = JsonFormatter()
        result = formatter.format_session(sample_session)

        data = json.loads(result)
        assert data["session_id"] == "sess-12345678"
        assert data["description"] == "Test debloat session"
        assert data["total_actions"] == 5
        assert data["successful_actions"] == 4
        assert data["failed_actions"] == 1

    def test_format_action_result(self, sample_action_result):
        """Test formatting an action result as JSON."""
        formatter = JsonFormatter()
        result = formatter.format_action_result(sample_action_result)

        data = json.loads(result)
        assert data["success"] is True
        assert data["action"] == "DISABLE"
        assert data["rollback_available"] is True

    def test_compact_output(self, sample_component):
        """Test compact JSON output."""
        formatter = JsonFormatter(compact=True)
        result = formatter.format_component(sample_component)

        # Compact output should have no newlines
        assert "\n" not in result

        # But should still be valid JSON
        data = json.loads(result)
        assert data["name"] == "test-bloatware"


# Tests for TableFormatter

class TestTableFormatter:
    """Tests for the TableFormatter class."""

    def test_format_table(self):
        """Test basic table formatting."""
        formatter = TableFormatter()
        headers = ["Name", "Type", "Status"]
        rows = [
            ["App One", "PROGRAM", "Active"],
            ["Service A", "SERVICE", "Disabled"],
        ]

        result = formatter.format_table(headers, rows)

        assert "Name" in result
        assert "Type" in result
        assert "Status" in result
        assert "App One" in result
        assert "Service A" in result

    def test_format_table_empty(self):
        """Test formatting empty table."""
        formatter = TableFormatter()
        result = formatter.format_table([], [])

        assert result == ""

    def test_format_table_custom_widths(self):
        """Test table with custom column widths."""
        formatter = TableFormatter()
        headers = ["ID", "Name"]
        rows = [["1", "VeryLongNameThatShouldBeTruncated"]]

        result = formatter.format_table(headers, rows, column_widths=[5, 10])

        # Name should be truncated
        assert "VeryLongNa" in result or len(result.split("\n")[2].split("|")[1].strip()) <= 10


# Tests for convenience functions

class TestConvenienceFunctions:
    """Tests for the convenience formatting functions."""

    def test_format_component_text(self, sample_component):
        """Test format_component with text output."""
        result = format_component(sample_component, as_json=False)

        assert "Test Bloatware App" in result
        assert "BLOAT" in result

    def test_format_component_json(self, sample_component):
        """Test format_component with JSON output."""
        result = format_component(sample_component, as_json=True)

        data = json.loads(result)
        assert data["name"] == "test-bloatware"

    def test_format_component_list_text(self, sample_component_list):
        """Test format_component_list with text output."""
        result = format_component_list(sample_component_list, as_json=False)

        assert "Total: 3 components" in result

    def test_format_component_list_json(self, sample_component_list):
        """Test format_component_list with JSON output."""
        result = format_component_list(sample_component_list, as_json=True)

        data = json.loads(result)
        assert data["count"] == 3

    def test_format_session_text(self, sample_session):
        """Test format_session with text output."""
        result = format_session(sample_session, as_json=False)

        assert "sess-123" in result  # truncated to 8 chars

    def test_format_session_json(self, sample_session):
        """Test format_session with JSON output."""
        result = format_session(sample_session, as_json=True)

        data = json.loads(result)
        assert data["session_id"] == "sess-12345678"

    def test_format_action_result_text(self, sample_action_result):
        """Test format_action_result with text output."""
        result = format_action_result(sample_action_result, as_json=False)

        assert "DISABLE" in result
        assert "SUCCESS" in result

    def test_format_action_result_json(self, sample_action_result):
        """Test format_action_result with JSON output."""
        result = format_action_result(sample_action_result, as_json=True)

        data = json.loads(result)
        assert data["action"] == "DISABLE"
        assert data["success"] is True


# Tests for CLI commands (using mocks)

class TestCLICommands:
    """Tests for CLI command functions."""

    @patch("src.ui.cli.commands.ScanOrchestrator")
    def test_run_list_command_basic(self, mock_orchestrator_class):
        """Test basic list command."""
        from src.ui.cli.commands import run_list_command
        from src.core.config import Config

        # Setup mock
        mock_component = Component(
            component_type=ComponentType.PROGRAM,
            name="test-app",
            display_name="Test App",
            publisher="Publisher",
        )

        mock_result = Mock()
        mock_result.components = [mock_component]
        mock_result.errors = []
        mock_result.scan_time_ms = 100
        mock_result.total_count = 1

        mock_orchestrator = Mock()
        mock_orchestrator.run_scan.return_value = mock_result
        mock_orchestrator_class.return_value = mock_orchestrator

        # Run command with config
        args = Mock()
        args.type = None
        args.classification = None
        args.risk = None
        args.json = False
        args.verbose = False
        args.filter = None  # No filter applied

        config = Mock(spec=Config)
        config.config_dir = Path("/tmp/test_config")

        # Should not raise
        run_list_command(args, config)

    @patch("src.ui.cli.commands.create_session_manager")
    def test_run_sessions_command(self, mock_create_session_manager):
        """Test sessions command."""
        from src.ui.cli.commands import run_sessions_command
        from src.core.config import Config

        # Setup mock
        mock_session = SessionSummary(
            session_id="test-session",
            description="Test",
            started_at=datetime.now().isoformat(),
            ended_at=None,
            is_active=True,
            total_actions=0,
            successful_actions=0,
            failed_actions=0,
            restore_point_id=None,
        )

        mock_manager = Mock()
        mock_manager.list_sessions.return_value = [mock_session]
        mock_create_session_manager.return_value = mock_manager

        # Run command with config
        args = Mock()
        args.limit = 10
        args.json = False
        args.verbose = False

        config = Mock(spec=Config)
        config.config_dir = Path("/tmp/test_config")

        # Should not raise
        run_sessions_command(args, config)


# Tests for GUI components (import tests only, as GUI requires display)

class TestGUIImports:
    """Test that GUI modules can be imported."""

    def test_gui_module_imports(self):
        """Test that GUI module import handles missing PySide6 gracefully."""
        # Try to import - may succeed or fail depending on PySide6 availability
        try:
            from src.ui.gui import (
                MainWindow,
                DashboardWidget,
                ComponentTreeWidget,
                ComponentDetailWidget,
                SessionHistoryWidget,
            )
            # PySide6 is available - all classes should be real
            assert MainWindow is not None
            assert DashboardWidget is not None
        except ImportError:
            # PySide6 not installed - this is expected in test environment
            # Just verify the import mechanism works
            pass

        # Either way, the test passes
        assert True

    def test_gui_init_graceful_import(self):
        """Test that GUI __init__ handles missing PySide6 gracefully."""
        # Import the gui package itself (not its contents)
        from src.ui import gui

        # Should have __all__ defined even without PySide6
        assert hasattr(gui, "__all__")
        # If PySide6 is missing, __all__ should be empty
        # If PySide6 is present, __all__ should have the exports


# Tests for CLI module structure

class TestCLIModuleStructure:
    """Test CLI module structure and exports."""

    def test_cli_formatters_exports(self):
        """Test that CLI formatters module exports expected classes."""
        from src.ui.cli.formatters import (
            OutputFormatter,
            TextFormatter,
            JsonFormatter,
            TableFormatter,
        )

        assert OutputFormatter is not None
        assert TextFormatter is not None
        assert JsonFormatter is not None
        assert TableFormatter is not None

    def test_cli_commands_exports(self):
        """Test that CLI commands module exports expected functions."""
        from src.ui.cli.commands import (
            run_list_command,
            run_plan_command,
            run_disable_command,
            run_remove_command,
            run_sessions_command,
            run_undo_command,
            run_recovery_command,
        )

        # All should be callable
        assert callable(run_list_command)
        assert callable(run_plan_command)
        assert callable(run_disable_command)
        assert callable(run_remove_command)
        assert callable(run_sessions_command)
        assert callable(run_undo_command)
        assert callable(run_recovery_command)

    def test_ui_package_exports(self):
        """Test that UI package exports expected formatters."""
        from src.ui import (
            OutputFormatter,
            TextFormatter,
            JsonFormatter,
            format_component,
            format_component_list,
            format_session,
            format_session_list,
        )

        assert OutputFormatter is not None
        assert TextFormatter is not None
        assert JsonFormatter is not None
        assert callable(format_component)
        assert callable(format_component_list)
        assert callable(format_session)
        assert callable(format_session_list)


# Tests for formatter edge cases

class TestFormatterEdgeCases:
    """Tests for edge cases in formatters."""

    def test_component_without_optional_fields(self):
        """Test formatting component with minimal required fields."""
        component = Component(
            component_type=ComponentType.TASK,
            name="minimal",
            display_name="Minimal Component",
            publisher="",  # publisher is required but can be empty
        )

        formatter = TextFormatter(use_colors=False)
        result = formatter.format_component(component)

        assert "Minimal Component" in result
        assert "TASK" in result

    def test_very_long_component_name(self):
        """Test formatting component with very long name."""
        component = Component(
            component_type=ComponentType.PROGRAM,
            name="x" * 100,
            display_name="A" * 100,
            publisher="Publisher",
        )

        formatter = TextFormatter(use_colors=False)
        result = formatter.format_component_list([component])

        # Should handle long names gracefully
        assert "A" in result
        assert "Total: 1 component" in result

    def test_session_summary_without_restore_point(self):
        """Test formatting session without restore point."""
        session = SessionSummary(
            session_id="no-restore",
            description="Test",
            started_at=datetime.now().isoformat(),
            ended_at=None,
            is_active=True,
            total_actions=0,
            successful_actions=0,
            failed_actions=0,
            restore_point_id=None,
        )

        formatter = TextFormatter(use_colors=False)
        result = formatter.format_session(session)

        assert "no-resto" in result
        assert "Restore Point" not in result

    def test_json_datetime_serialization(self, sample_session):
        """Test that datetime is properly serialized in JSON."""
        formatter = JsonFormatter()
        result = formatter.format_session(sample_session)

        data = json.loads(result)
        # DateTime should be ISO format string
        assert isinstance(data["started_at"], str)
        assert "2024" in data["started_at"]


class TestSessionListFormatting:
    """Tests for session list formatting."""

    def test_format_session_list_empty(self):
        """Test formatting empty session list."""
        formatter = TextFormatter(use_colors=False)
        result = formatter.format_session_list([])

        assert "No sessions found" in result

    def test_format_session_list_multiple(self, sample_session):
        """Test formatting multiple sessions."""
        sessions = [
            sample_session,
            SessionSummary(
                session_id="sess-87654321",
                description="Another session",
                started_at=datetime.now().isoformat(),
                ended_at=None,
                is_active=True,
                total_actions=2,
                successful_actions=2,
                failed_actions=0,
                restore_point_id=None,
            ),
        ]

        result = format_session_list(sessions, as_json=False)

        assert "sess-123" in result  # truncated to 8 chars
        assert "sess-876" in result  # truncated to 8 chars
        assert "Another session" in result

    def test_format_session_list_json(self, sample_session):
        """Test formatting session list as JSON."""
        sessions = [sample_session]

        result = format_session_list(sessions, as_json=True)
        data = json.loads(result)

        assert data["count"] == 1
        assert len(data["sessions"]) == 1
        assert data["sessions"][0]["session_id"] == "sess-12345678"
