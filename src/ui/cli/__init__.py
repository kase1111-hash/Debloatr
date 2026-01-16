"""CLI module for Debloatr."""

from .commands import (
    run_disable_command,
    run_list_command,
    run_plan_command,
    run_recovery_command,
    run_remove_command,
    run_sessions_command,
    run_undo_command,
)
from .formatters import (
    JsonFormatter,
    OutputFormatter,
    TableFormatter,
    TextFormatter,
    format_action_result,
    format_component,
    format_component_list,
    format_scan_result,
    format_session,
    format_session_list,
)

__all__ = [
    # Formatters
    "OutputFormatter",
    "TextFormatter",
    "JsonFormatter",
    "TableFormatter",
    "format_component",
    "format_component_list",
    "format_session",
    "format_session_list",
    "format_action_result",
    "format_scan_result",
    # Commands
    "run_list_command",
    "run_plan_command",
    "run_disable_command",
    "run_remove_command",
    "run_sessions_command",
    "run_undo_command",
    "run_recovery_command",
]
