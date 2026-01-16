"""Output formatters for CLI output.

This module provides formatters for displaying components, sessions,
and results in various formats (text, JSON, tables).
"""

import json
from abc import ABC, abstractmethod
from dataclasses import asdict
from datetime import datetime
from typing import Any, Optional
import sys

from src.core.models import (
    Component,
    ComponentType,
    Classification,
    RiskLevel,
    ActionType,
    ActionPlan,
    ActionResult,
    Session,
)
from src.core.session import SessionSummary, ActionSummary
from src.core.rollback import RollbackResult, SessionRollbackResult


# ANSI color codes for terminal output
class Colors:
    """ANSI color codes for terminal output."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Classification colors
    CORE = "\033[94m"      # Blue
    ESSENTIAL = "\033[96m"  # Cyan
    OPTIONAL = "\033[92m"   # Green
    BLOAT = "\033[93m"      # Yellow
    AGGRESSIVE = "\033[91m" # Red
    UNKNOWN = "\033[90m"    # Gray

    # Risk colors
    RISK_NONE = "\033[92m"     # Green
    RISK_LOW = "\033[96m"      # Cyan
    RISK_MEDIUM = "\033[93m"   # Yellow
    RISK_HIGH = "\033[91m"     # Red
    RISK_CRITICAL = "\033[95m" # Magenta

    # Status colors
    SUCCESS = "\033[92m"  # Green
    FAILURE = "\033[91m"  # Red
    WARNING = "\033[93m"  # Yellow
    INFO = "\033[94m"     # Blue

    @classmethod
    def is_supported(cls) -> bool:
        """Check if terminal supports colors."""
        return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def colorize(text: str, color: str, force: bool = False) -> str:
    """Apply color to text if supported.

    Args:
        text: Text to colorize
        color: ANSI color code
        force: Force color even if not supported

    Returns:
        Colored text or plain text
    """
    if force or Colors.is_supported():
        return f"{color}{text}{Colors.RESET}"
    return text


def get_classification_color(classification: Classification) -> str:
    """Get color for a classification."""
    color_map = {
        Classification.CORE: Colors.CORE,
        Classification.ESSENTIAL: Colors.ESSENTIAL,
        Classification.OPTIONAL: Colors.OPTIONAL,
        Classification.BLOAT: Colors.BLOAT,
        Classification.AGGRESSIVE: Colors.AGGRESSIVE,
        Classification.UNKNOWN: Colors.UNKNOWN,
    }
    return color_map.get(classification, Colors.RESET)


def get_risk_color(risk: RiskLevel) -> str:
    """Get color for a risk level."""
    color_map = {
        RiskLevel.NONE: Colors.RISK_NONE,
        RiskLevel.LOW: Colors.RISK_LOW,
        RiskLevel.MEDIUM: Colors.RISK_MEDIUM,
        RiskLevel.HIGH: Colors.RISK_HIGH,
        RiskLevel.CRITICAL: Colors.RISK_CRITICAL,
    }
    return color_map.get(risk, Colors.RESET)


class OutputFormatter(ABC):
    """Abstract base class for output formatters."""

    @abstractmethod
    def format_component(self, component: Component) -> str:
        """Format a single component."""
        pass

    @abstractmethod
    def format_component_list(self, components: list[Component]) -> str:
        """Format a list of components."""
        pass

    @abstractmethod
    def format_session(self, session: SessionSummary) -> str:
        """Format a session summary."""
        pass

    @abstractmethod
    def format_action_result(self, result: ActionResult) -> str:
        """Format an action result."""
        pass


class TextFormatter(OutputFormatter):
    """Plain text formatter with optional colors."""

    def __init__(self, use_colors: bool = True, verbose: bool = False):
        """Initialize the text formatter.

        Args:
            use_colors: Whether to use ANSI colors
            verbose: Whether to show verbose output
        """
        self.use_colors = use_colors and Colors.is_supported()
        self.verbose = verbose

    def _colorize(self, text: str, color: str) -> str:
        """Apply color if enabled."""
        if self.use_colors:
            return colorize(text, color, force=True)
        return text

    def format_component(self, component: Component) -> str:
        """Format a single component."""
        lines = []

        # Header
        name = self._colorize(component.display_name, Colors.BOLD)
        lines.append(f"{name}")
        lines.append(f"  ID: {component.id[:8]}...")

        # Type
        lines.append(f"  Type: {component.component_type.name}")

        # Publisher
        if component.publisher:
            lines.append(f"  Publisher: {component.publisher}")

        # Classification
        class_color = get_classification_color(component.classification)
        class_text = self._colorize(component.classification.value, class_color)
        lines.append(f"  Classification: {class_text}")

        # Risk level
        risk_color = get_risk_color(component.risk_level)
        risk_text = self._colorize(component.risk_level.name, risk_color)
        lines.append(f"  Risk Level: {risk_text}")

        # Install path
        if component.install_path:
            lines.append(f"  Path: {component.install_path}")

        return "\n".join(lines)

    def format_component_list(self, components: list[Component]) -> str:
        """Format a list of components as a table."""
        if not components:
            return "No components found."

        lines = []

        # Header
        header = f"{'ID':<12} {'Name':<30} {'Type':<10} {'Class':<12} {'Risk':<10}"
        lines.append(self._colorize(header, Colors.BOLD))
        lines.append("-" * 76)

        # Rows
        for comp in components:
            class_color = get_classification_color(comp.classification)
            risk_color = get_risk_color(comp.risk_level)

            class_text = self._colorize(comp.classification.value[:10], class_color)
            risk_text = self._colorize(comp.risk_level.name[:8], risk_color)

            name = comp.display_name[:28] if len(comp.display_name) > 28 else comp.display_name
            line = f"{comp.id[:10]:<12} {name:<30} {comp.component_type.name[:8]:<10} {class_text:<12} {risk_text:<10}"
            lines.append(line)

        lines.append("-" * 76)
        lines.append(f"Total: {len(components)} components")

        return "\n".join(lines)

    def format_session(self, session: SessionSummary) -> str:
        """Format a session summary."""
        lines = []

        # Status indicator
        if session.is_active:
            status = self._colorize("ACTIVE", Colors.SUCCESS)
        else:
            status = self._colorize("ENDED", Colors.DIM)

        lines.append(f"Session: {session.session_id[:8]}... [{status}]")
        lines.append(f"  Description: {session.description or '(none)'}")
        lines.append(f"  Started: {session.started_at}")

        if session.ended_at:
            lines.append(f"  Ended: {session.ended_at}")

        # Action counts
        success_text = self._colorize(str(session.successful_actions), Colors.SUCCESS)
        failed_text = self._colorize(str(session.failed_actions), Colors.FAILURE)
        lines.append(f"  Actions: {session.total_actions} total ({success_text} succeeded, {failed_text} failed)")

        if session.restore_point_id:
            lines.append(f"  Restore Point: #{session.restore_point_id}")

        return "\n".join(lines)

    def format_session_list(self, sessions: list[SessionSummary]) -> str:
        """Format a list of sessions."""
        if not sessions:
            return "No sessions found."

        lines = []

        for session in sessions:
            lines.append(self.format_session(session))
            lines.append("")

        return "\n".join(lines)

    def format_action_result(self, result: ActionResult) -> str:
        """Format an action result."""
        if result.success:
            status = self._colorize("SUCCESS", Colors.SUCCESS)
        else:
            status = self._colorize("FAILED", Colors.FAILURE)

        lines = [
            f"Action: {result.action.value} [{status}]",
            f"  Component: {result.component_id[:8]}...",
        ]

        if result.snapshot_id:
            lines.append(f"  Snapshot: {result.snapshot_id[:8]}...")

        if result.error_message:
            error = self._colorize(result.error_message, Colors.FAILURE)
            lines.append(f"  Error: {error}")

        if result.rollback_available:
            lines.append(f"  Rollback: Available")

        return "\n".join(lines)

    def format_action_plan(self, plan: ActionPlan) -> str:
        """Format an action plan."""
        lines = []

        # Header
        action_text = self._colorize(plan.action.value, Colors.BOLD)
        lines.append(f"Action Plan: {action_text}")
        lines.append(f"  Component: {plan.component.display_name}")
        lines.append(f"  Plan ID: {plan.plan_id[:8]}...")

        # Requirements
        if plan.requires_admin:
            lines.append(f"  {self._colorize('Requires Admin', Colors.WARNING)}")
        if plan.requires_reboot:
            lines.append(f"  {self._colorize('Requires Reboot', Colors.WARNING)}")

        # Risk level
        risk_color = get_risk_color(plan.estimated_risk)
        risk_text = self._colorize(plan.estimated_risk.name, risk_color)
        lines.append(f"  Estimated Risk: {risk_text}")

        # Steps
        lines.append("\n  Steps:")
        for i, step in enumerate(plan.steps, 1):
            lines.append(f"    {i}. {step}")

        # Warnings
        if plan.warnings:
            lines.append("\n  Warnings:")
            for warning in plan.warnings:
                warn_text = self._colorize(f"    ! {warning}", Colors.WARNING)
                lines.append(warn_text)

        return "\n".join(lines)

    def format_rollback_result(self, result: RollbackResult) -> str:
        """Format a rollback result."""
        if result.success:
            status = self._colorize("SUCCESS", Colors.SUCCESS)
        else:
            status = self._colorize("FAILED", Colors.FAILURE)

        lines = [
            f"Rollback: {result.original_action} [{status}]",
            f"  Component: {result.component_name}",
        ]

        if result.error_message:
            error = self._colorize(result.error_message, Colors.FAILURE)
            lines.append(f"  Error: {error}")

        if result.requires_reboot:
            lines.append(f"  {self._colorize('Reboot Required', Colors.WARNING)}")

        if result.partial:
            lines.append(f"  {self._colorize('Partial Rollback', Colors.WARNING)}")

        return "\n".join(lines)

    def format_session_rollback_result(self, result: SessionRollbackResult) -> str:
        """Format a session rollback result."""
        if result.success:
            status = self._colorize("SUCCESS", Colors.SUCCESS)
        else:
            status = self._colorize("PARTIAL", Colors.WARNING)

        lines = [
            f"Session Rollback: {result.session_id[:8]}... [{status}]",
            f"  Total Actions: {result.total_actions}",
            f"  Successful: {self._colorize(str(result.successful_rollbacks), Colors.SUCCESS)}",
            f"  Failed: {self._colorize(str(result.failed_rollbacks), Colors.FAILURE)}",
        ]

        if result.requires_reboot:
            lines.append(f"  {self._colorize('Reboot Required', Colors.WARNING)}")

        return "\n".join(lines)


class JsonFormatter(OutputFormatter):
    """JSON output formatter."""

    def __init__(self, indent: int = 2, compact: bool = False):
        """Initialize the JSON formatter.

        Args:
            indent: Indentation level
            compact: Whether to use compact output
        """
        self.indent = None if compact else indent

    def _serialize(self, obj: Any) -> Any:
        """Serialize an object for JSON output."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, "value"):  # Enum
            return obj.value
        if hasattr(obj, "name"):  # Enum with name
            return obj.name
        if hasattr(obj, "__dataclass_fields__"):
            return asdict(obj)
        return str(obj)

    def format_component(self, component: Component) -> str:
        """Format a single component as JSON."""
        data = {
            "id": component.id,
            "name": component.name,
            "display_name": component.display_name,
            "publisher": component.publisher,
            "component_type": component.component_type.name,
            "classification": component.classification.value,
            "risk_level": component.risk_level.name,
            "install_path": str(component.install_path) if component.install_path else None,
            "metadata": component.metadata,
            "discovered_at": component.discovered_at.isoformat(),
        }
        return json.dumps(data, indent=self.indent, default=self._serialize)

    def format_component_list(self, components: list[Component]) -> str:
        """Format a list of components as JSON."""
        data = {
            "count": len(components),
            "components": [
                {
                    "id": c.id,
                    "name": c.name,
                    "display_name": c.display_name,
                    "publisher": c.publisher,
                    "component_type": c.component_type.name,
                    "classification": c.classification.value,
                    "risk_level": c.risk_level.name,
                }
                for c in components
            ],
        }
        return json.dumps(data, indent=self.indent, default=self._serialize)

    def format_session(self, session: SessionSummary) -> str:
        """Format a session summary as JSON."""
        data = {
            "session_id": session.session_id,
            "description": session.description,
            "started_at": session.started_at,
            "ended_at": session.ended_at,
            "is_active": session.is_active,
            "total_actions": session.total_actions,
            "successful_actions": session.successful_actions,
            "failed_actions": session.failed_actions,
            "restore_point_id": session.restore_point_id,
        }
        return json.dumps(data, indent=self.indent, default=self._serialize)

    def format_session_list(self, sessions: list[SessionSummary]) -> str:
        """Format a list of sessions as JSON."""
        data = {
            "count": len(sessions),
            "sessions": [
                {
                    "session_id": s.session_id,
                    "description": s.description,
                    "started_at": s.started_at,
                    "ended_at": s.ended_at,
                    "is_active": s.is_active,
                    "total_actions": s.total_actions,
                }
                for s in sessions
            ],
        }
        return json.dumps(data, indent=self.indent, default=self._serialize)

    def format_action_result(self, result: ActionResult) -> str:
        """Format an action result as JSON."""
        data = {
            "plan_id": result.plan_id,
            "success": result.success,
            "action": result.action.value if isinstance(result.action, ActionType) else str(result.action),
            "component_id": result.component_id,
            "snapshot_id": result.snapshot_id,
            "error_message": result.error_message,
            "executed_at": result.executed_at.isoformat() if isinstance(result.executed_at, datetime) else str(result.executed_at),
            "rollback_available": result.rollback_available,
        }
        return json.dumps(data, indent=self.indent, default=self._serialize)


class TableFormatter:
    """Table-based output formatter."""

    def __init__(self, max_width: int = 80):
        """Initialize the table formatter.

        Args:
            max_width: Maximum table width
        """
        self.max_width = max_width

    def format_table(
        self,
        headers: list[str],
        rows: list[list[str]],
        column_widths: Optional[list[int]] = None,
    ) -> str:
        """Format data as a table.

        Args:
            headers: Column headers
            rows: Table rows
            column_widths: Optional column widths

        Returns:
            Formatted table string
        """
        if not headers or not rows:
            return ""

        # Calculate column widths if not provided
        if column_widths is None:
            column_widths = []
            for i, header in enumerate(headers):
                max_len = len(header)
                for row in rows:
                    if i < len(row):
                        max_len = max(max_len, len(str(row[i])))
                column_widths.append(min(max_len, 40))

        # Build table
        lines = []

        # Header
        header_cells = []
        for i, header in enumerate(headers):
            width = column_widths[i] if i < len(column_widths) else 10
            header_cells.append(header[:width].ljust(width))
        lines.append(" | ".join(header_cells))

        # Separator
        separators = ["-" * w for w in column_widths]
        lines.append("-+-".join(separators))

        # Rows
        for row in rows:
            row_cells = []
            for i, cell in enumerate(row):
                width = column_widths[i] if i < len(column_widths) else 10
                cell_str = str(cell)[:width].ljust(width)
                row_cells.append(cell_str)
            lines.append(" | ".join(row_cells))

        return "\n".join(lines)


# Convenience functions

def format_component(component: Component, as_json: bool = False) -> str:
    """Format a component.

    Args:
        component: Component to format
        as_json: Whether to output JSON

    Returns:
        Formatted string
    """
    if as_json:
        return JsonFormatter().format_component(component)
    return TextFormatter().format_component(component)


def format_component_list(components: list[Component], as_json: bool = False) -> str:
    """Format a list of components.

    Args:
        components: Components to format
        as_json: Whether to output JSON

    Returns:
        Formatted string
    """
    if as_json:
        return JsonFormatter().format_component_list(components)
    return TextFormatter().format_component_list(components)


def format_session(session: SessionSummary, as_json: bool = False) -> str:
    """Format a session.

    Args:
        session: Session to format
        as_json: Whether to output JSON

    Returns:
        Formatted string
    """
    if as_json:
        return JsonFormatter().format_session(session)
    return TextFormatter().format_session(session)


def format_session_list(sessions: list[SessionSummary], as_json: bool = False) -> str:
    """Format a list of sessions.

    Args:
        sessions: Sessions to format
        as_json: Whether to output JSON

    Returns:
        Formatted string
    """
    if as_json:
        return JsonFormatter().format_session_list(sessions)
    return TextFormatter().format_session_list(sessions)


def format_action_result(result: ActionResult, as_json: bool = False) -> str:
    """Format an action result.

    Args:
        result: Result to format
        as_json: Whether to output JSON

    Returns:
        Formatted string
    """
    if as_json:
        return JsonFormatter().format_action_result(result)
    return TextFormatter().format_action_result(result)


def format_scan_result(result: Any, as_json: bool = False) -> str:
    """Format a scan result.

    Args:
        result: Scan result to format
        as_json: Whether to output JSON

    Returns:
        Formatted string
    """
    if as_json:
        data = {
            "scan_time_ms": result.scan_time_ms,
            "total_components": result.total_count,
            "summary": result.get_summary(),
            "errors": result.errors,
        }
        return json.dumps(data, indent=2)

    formatter = TextFormatter()
    lines = [
        f"Scan completed in {result.scan_time_ms:.1f}ms",
        f"Total components: {result.total_count}",
        "",
        "Summary by classification:",
    ]

    for classification, count in result.get_summary().items():
        lines.append(f"  {classification}: {count}")

    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    return "\n".join(lines)
