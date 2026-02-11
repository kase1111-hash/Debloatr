#!/usr/bin/env python3
"""Debloatr - Bloatware Scanner & Debloater.

Entry point for the command-line interface and GUI.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from src.core.config import Config, load_config, save_config
from src.core.logging_config import get_logger, setup_logging
from src.core.orchestrator import ScanOrchestrator


def create_argument_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="debloatd",
        description="Bloatware Scanner & Debloater for Windows",
        epilog="For more information, see the documentation.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0-alpha",
    )

    parser.add_argument(
        "--config",
        type=Path,
        help="Path to configuration file",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="Increase verbosity (use -vv for debug)",
    )

    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress console output",
    )

    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch graphical user interface",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON (global flag for all commands)",
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan system for bloatware")
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    scan_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Write results to file",
    )
    scan_parser.add_argument(
        "--type",
        "-t",
        choices=["programs", "services", "tasks", "startup", "drivers", "telemetry", "uwp"],
        action="append",
        help="Scan specific component types (can be repeated)",
    )

    # List command
    list_parser = subparsers.add_parser("list", help="List discovered components")
    list_parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON",
    )
    list_parser.add_argument(
        "--filter",
        "-f",
        choices=["core", "essential", "optional", "bloat", "aggressive", "unknown"],
        help="Filter by classification",
    )
    list_parser.add_argument(
        "--risk",
        "-r",
        choices=["none", "low", "medium", "high", "critical"],
        help="Filter by risk level",
    )

    # Plan command
    plan_parser = subparsers.add_parser("plan", help="Show action plan for component")
    plan_parser.add_argument("component_id", help="Component ID to plan for")
    plan_parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON",
    )

    # Action commands
    disable_parser = subparsers.add_parser("disable", help="Disable a component")
    disable_parser.add_argument("component_id", help="Component ID to disable")
    disable_parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip confirmation prompt",
    )

    remove_parser = subparsers.add_parser("remove", help="Remove a component")
    remove_parser.add_argument("component_id", help="Component ID to remove")
    remove_parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip confirmation prompt (still requires typing REMOVE)",
    )

    # Session commands
    sessions_parser = subparsers.add_parser("sessions", help="List all debloat sessions")
    sessions_parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON",
    )

    undo_parser = subparsers.add_parser("undo", help="Undo a session or action")
    undo_parser.add_argument(
        "session_id",
        nargs="?",
        help="Session ID to undo (omit for last session)",
    )
    undo_parser.add_argument(
        "--last",
        action="store_true",
        help="Undo the last session",
    )
    undo_parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip confirmation prompt",
    )

    # Recovery command
    recovery_parser = subparsers.add_parser("recovery", help="Boot recovery mode")
    recovery_parser.add_argument(
        "--last-session",
        action="store_true",
        help="Rollback the last session",
    )

    # Config command
    config_parser = subparsers.add_parser("config", help="Manage configuration")
    config_parser.add_argument(
        "--init",
        action="store_true",
        help="Create default configuration file",
    )
    config_parser.add_argument(
        "--show",
        action="store_true",
        help="Show current configuration",
    )

    return parser


def get_log_level(verbose: int) -> int:
    """Get logging level from verbosity count."""
    if verbose >= 2:
        return logging.DEBUG
    elif verbose >= 1:
        return logging.INFO
    return logging.WARNING


def run_scan(args: argparse.Namespace, config: Config) -> int:
    """Execute the scan command."""
    from src.ui.cli.formatters import format_scan_result

    logger = get_logger("main")
    logger.info("Starting system scan...")

    orchestrator = ScanOrchestrator(config)

    # Run scan with optional module filter
    result = orchestrator.run_scan(modules=args.type)

    # Output results
    if args.json:
        output = {
            "scan_time_ms": result.scan_time_ms,
            "total_components": result.total_count,
            "summary": result.get_summary(),
            "components": [
                {
                    "id": c.id,
                    "name": c.name,
                    "display_name": c.display_name,
                    "publisher": c.publisher,
                    "type": c.component_type.name,
                    "classification": c.classification.value,
                    "risk_level": c.risk_level.name,
                }
                for c in result.components
            ],
            "errors": result.errors,
        }

        json_output = json.dumps(output, indent=2, default=str)

        if args.output:
            args.output.write_text(json_output)
            print(f"Results written to {args.output}")
        else:
            print(json_output)
    else:
        # Text output
        print(format_scan_result(result))

        if args.output:
            args.output.write_text(format_scan_result(result))
            print(f"\nResults also written to {args.output}")

    return 0


def run_config(args: argparse.Namespace, config: Config) -> int:
    """Execute the config command."""
    if args.init:
        save_config(config)
        print(f"Configuration saved to {config.config_dir / 'config.json'}")
        return 0

    if args.show:
        print(json.dumps(config.to_dict(), indent=2))
        return 0

    print("Use --init to create config or --show to display current config")
    return 1


def run_gui(config: Config) -> int:
    """Launch the graphical user interface."""
    try:
        from src.ui.gui.main import run_gui_app

        return run_gui_app(config)
    except ImportError as e:
        print(f"Error: GUI dependencies not installed: {e}")
        print("Install with: pip install PySide6")
        return 1


def main() -> int:
    """Main entry point."""
    parser = create_argument_parser()
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config) if args.config else load_config()

    # Setup logging
    log_level = get_log_level(args.verbose)
    setup_logging(
        config.logs_dir,
        log_level=log_level,
        console_output=not args.quiet,
    )

    # Ensure directories exist
    config.ensure_directories()

    # Launch GUI if requested
    if args.gui:
        return run_gui(config)

    # Import CLI commands
    from src.ui.cli.commands import (
        run_disable_command,
        run_list_command,
        run_plan_command,
        run_recovery_command,
        run_remove_command,
        run_sessions_command,
        run_undo_command,
    )

    # Execute command
    if args.command == "scan":
        return run_scan(args, config)
    elif args.command == "list":
        return run_list_command(args, config)
    elif args.command == "plan":
        return run_plan_command(args, config)
    elif args.command == "disable":
        return run_disable_command(args, config)
    elif args.command == "remove":
        return run_remove_command(args, config)
    elif args.command == "sessions":
        return run_sessions_command(args, config)
    elif args.command == "undo":
        return run_undo_command(args, config)
    elif args.command == "recovery":
        return run_recovery_command(args, config)
    elif args.command == "config":
        return run_config(args, config)
    elif args.command is None:
        parser.print_help()
        return 0
    else:
        print(f"Error: Unknown command '{args.command}'")
        return 1


if __name__ == "__main__":
    sys.exit(main())
