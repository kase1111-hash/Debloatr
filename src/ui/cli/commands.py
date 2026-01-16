"""CLI command implementations.

This module provides the command handlers for all CLI commands.
"""

import argparse
from typing import Any

from src.actions.executor import create_execution_engine
from src.actions.planner import create_default_planner
from src.core.config import Config
from src.core.models import (
    ActionType,
    Classification,
    Component,
    ExecutionMode,
    RiskLevel,
)
from src.core.orchestrator import ScanOrchestrator
from src.core.recovery import create_recovery_mode
from src.core.restore import create_restore_point_for_session
from src.core.rollback import create_rollback_manager
from src.core.session import create_session_manager

from .formatters import (
    JsonFormatter,
    TextFormatter,
    format_component_list,
    format_session_list,
)

# Global component cache for lookups
_component_cache: dict[str, Component] = {}


def _get_formatter(args: argparse.Namespace) -> TextFormatter | JsonFormatter:
    """Get the appropriate formatter based on args."""
    if getattr(args, "json", False):
        return JsonFormatter()
    return TextFormatter()


def _load_components(config: Config, args: argparse.Namespace) -> list[Component]:
    """Load components from a previous scan or run a new scan."""
    global _component_cache

    # Try to load from cache file
    cache_file = config.config_dir / "component_cache.json"

    if cache_file.exists():
        import json

        try:
            with open(cache_file) as f:
                data = json.load(f)
            components = []
            for item in data.get("components", []):
                from src.core.models import ComponentType

                comp = Component(
                    component_type=ComponentType[item["component_type"]],
                    name=item["name"],
                    display_name=item["display_name"],
                    publisher=item["publisher"],
                    classification=Classification(item["classification"]),
                    risk_level=RiskLevel[item["risk_level"]],
                    id=item["id"],
                )
                components.append(comp)
                _component_cache[comp.id] = comp
            return components
        except Exception:
            pass

    # Run a scan if no cache
    orchestrator = ScanOrchestrator(config)
    result = orchestrator.run_scan()

    # Cache the components
    _component_cache = {c.id: c for c in result.components}

    # Save to cache file
    try:
        import json

        data = {
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
                for c in result.components
            ]
        }
        with open(cache_file, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

    return result.components


def _find_component(
    component_id: str, config: Config, args: argparse.Namespace
) -> Component | None:
    """Find a component by ID (full or partial)."""
    global _component_cache

    # Check cache first
    if component_id in _component_cache:
        return _component_cache[component_id]

    # Partial match
    for comp_id, comp in _component_cache.items():
        if comp_id.startswith(component_id):
            return comp

    # Load components if cache is empty
    if not _component_cache:
        components = _load_components(config, args)
        for comp in components:
            if comp.id == component_id or comp.id.startswith(component_id):
                return comp

    return None


def run_list_command(args: argparse.Namespace, config: Config) -> int:
    """Execute the list command.

    Args:
        args: Command-line arguments
        config: Configuration object

    Returns:
        Exit code
    """
    # Load components
    components = _load_components(config, args)

    # Apply filters
    if args.filter:
        filter_class = Classification(args.filter.upper())
        components = [c for c in components if c.classification == filter_class]

    if args.risk:
        risk_map = {
            "none": RiskLevel.NONE,
            "low": RiskLevel.LOW,
            "medium": RiskLevel.MEDIUM,
            "high": RiskLevel.HIGH,
            "critical": RiskLevel.CRITICAL,
        }
        filter_risk = risk_map.get(args.risk.lower())
        if filter_risk:
            components = [c for c in components if c.risk_level == filter_risk]

    # Output
    output = format_component_list(components, as_json=getattr(args, "json", False))
    print(output)

    return 0


def run_plan_command(args: argparse.Namespace, config: Config) -> int:
    """Execute the plan command.

    Args:
        args: Command-line arguments
        config: Configuration object

    Returns:
        Exit code
    """
    # Find the component
    component = _find_component(args.component_id, config, args)
    if not component:
        print(f"Error: Component not found: {args.component_id}")
        return 1

    # Create planner
    planner = create_default_planner()

    # Get available actions
    availability = planner.get_available_actions(component)

    print(f"\nComponent: {component.display_name}")
    print(f"ID: {component.id}")
    print(f"Classification: {component.classification.value}")
    print(f"Risk Level: {component.risk_level.name}")
    print()

    # Show available actions
    print("Available Actions:")
    for action in availability.available_actions:
        print(f"  - {action.value}")

    # Show blocked actions
    if availability.blocked_actions:
        print("\nBlocked Actions:")
        for action, reason in availability.blocked_actions.items():
            print(f"  - {action.value}: {reason}")

    # Show warnings
    if availability.warnings:
        print("\nWarnings:")
        for warning in availability.warnings:
            print(f"  ! {warning}")

    # Generate a sample plan for DISABLE if available
    if ActionType.DISABLE in availability.available_actions:
        print("\nSample Plan (DISABLE):")
        try:
            plan = planner.create_action_plan(component, ActionType.DISABLE)
            text_formatter = TextFormatter()
            print(text_formatter.format_action_plan(plan))
        except Exception as e:
            print(f"  Error generating plan: {e}")

    return 0


def run_disable_command(args: argparse.Namespace, config: Config) -> int:
    """Execute the disable command.

    Args:
        args: Command-line arguments
        config: Configuration object

    Returns:
        Exit code
    """
    # Find the component
    component = _find_component(args.component_id, config, args)
    if not component:
        print(f"Error: Component not found: {args.component_id}")
        return 1

    # Create planner and check availability
    planner = create_default_planner()
    availability = planner.get_available_actions(component)

    if ActionType.DISABLE not in availability.available_actions:
        reason = availability.blocked_actions.get(ActionType.DISABLE, "Unknown reason")
        print(f"Error: Cannot disable {component.display_name}: {reason}")
        return 1

    # Confirmation
    print(f"\nAbout to disable: {component.display_name}")
    print(f"Classification: {component.classification.value}")
    print(f"Risk Level: {component.risk_level.name}")

    if availability.warnings:
        print("\nWarnings:")
        for warning in availability.warnings:
            print(f"  ! {warning}")

    response = input("\nProceed? [y/N] ").strip().lower()
    if response != "y":
        print("Cancelled.")
        return 0

    # Create session and execute
    session_manager = create_session_manager(config)

    # Create restore point
    restore_point = create_restore_point_for_session(
        f"Disable {component.display_name}",
        dry_run=False,
    )

    session = session_manager.create_session(
        description=f"Disable {component.display_name}",
        restore_point_id=str(restore_point) if restore_point else None,
    )

    # Create execution engine
    engine = create_execution_engine(mode=ExecutionMode.INTERACTIVE)
    engine._current_session = session

    # Create and execute plan
    plan = planner.create_action_plan(component, ActionType.DISABLE)
    result = engine.execute(plan)

    # Add to session
    if result.action_result:
        session_manager.add_action(
            session.session_id,
            result.action_result,
            component.display_name,
        )

    session_manager.end_session(session.session_id)

    # Output result
    if result.success:
        print(f"\n✓ Successfully disabled: {component.display_name}")
        if result.requires_reboot:
            print("  Note: A reboot is required to complete the operation.")
        print(f"\n  Session ID: {session.session_id[:8]}...")
        print("  Use 'debloatd undo --last' to undo this action.")
    else:
        print(f"\n✗ Failed to disable: {component.display_name}")
        print(f"  Error: {result.error_message}")

    return 0 if result.success else 1


def run_remove_command(args: argparse.Namespace, config: Config) -> int:
    """Execute the remove command.

    Args:
        args: Command-line arguments
        config: Configuration object

    Returns:
        Exit code
    """
    # Find the component
    component = _find_component(args.component_id, config, args)
    if not component:
        print(f"Error: Component not found: {args.component_id}")
        return 1

    # Create planner and check availability
    planner = create_default_planner()
    availability = planner.get_available_actions(component)

    if ActionType.REMOVE not in availability.available_actions:
        reason = availability.blocked_actions.get(ActionType.REMOVE, "Unknown reason")
        print(f"Error: Cannot remove {component.display_name}: {reason}")
        return 1

    # Strong confirmation for removal
    print(f"\n⚠ WARNING: About to REMOVE: {component.display_name}")
    print(f"Classification: {component.classification.value}")
    print(f"Risk Level: {component.risk_level.name}")
    print("\nThis action may not be fully reversible!")

    if availability.warnings:
        print("\nWarnings:")
        for warning in availability.warnings:
            print(f"  ! {warning}")

    response = input("\nType 'REMOVE' to confirm: ").strip()
    if response != "REMOVE":
        print("Cancelled.")
        return 0

    # Create session and execute
    session_manager = create_session_manager(config)

    # Create restore point
    restore_point = create_restore_point_for_session(
        f"Remove {component.display_name}",
        dry_run=False,
    )

    session = session_manager.create_session(
        description=f"Remove {component.display_name}",
        restore_point_id=str(restore_point) if restore_point else None,
    )

    # Create execution engine
    engine = create_execution_engine(mode=ExecutionMode.INTERACTIVE)
    engine._current_session = session

    # Create and execute plan
    plan = planner.create_action_plan(component, ActionType.REMOVE)
    result = engine.execute(plan)

    # Add to session
    if result.action_result:
        session_manager.add_action(
            session.session_id,
            result.action_result,
            component.display_name,
        )

    session_manager.end_session(session.session_id)

    # Output result
    if result.success:
        print(f"\n✓ Successfully removed: {component.display_name}")
        if result.requires_reboot:
            print("  Note: A reboot is required to complete the operation.")
        print(f"\n  Session ID: {session.session_id[:8]}...")
    else:
        print(f"\n✗ Failed to remove: {component.display_name}")
        print(f"  Error: {result.error_message}")

    return 0 if result.success else 1


def run_sessions_command(args: argparse.Namespace, config: Config) -> int:
    """Execute the sessions command.

    Args:
        args: Command-line arguments
        config: Configuration object

    Returns:
        Exit code
    """
    session_manager = create_session_manager(config)
    sessions = session_manager.list_sessions()

    if not sessions:
        print("No sessions found.")
        return 0

    output = format_session_list(sessions, as_json=getattr(args, "json", False))
    print(output)

    return 0


def run_undo_command(args: argparse.Namespace, config: Config) -> int:
    """Execute the undo command.

    Args:
        args: Command-line arguments
        config: Configuration object

    Returns:
        Exit code
    """
    session_manager = create_session_manager(config)
    rollback_manager = create_rollback_manager(config)

    # Determine which session to undo
    if args.last or not args.session_id:
        last_session = session_manager.get_last_session()
        if not last_session:
            print("No sessions found to undo.")
            return 1
        session_id = last_session.session_id
        print(f"Undoing last session: {last_session.description}")
    else:
        session_id = args.session_id
        # Support partial ID
        sessions = session_manager.list_sessions()
        for s in sessions:
            if s.session_id.startswith(session_id):
                session_id = s.session_id
                break

    # Get session details
    session = session_manager.get_session(session_id)
    if not session:
        print(f"Session not found: {session_id}")
        return 1

    # Get rollbackable actions
    actions = session_manager.get_rollbackable_actions(session_id)
    if not actions:
        print("No rollbackable actions in this session.")
        return 0

    # Confirmation
    print(f"\nSession: {session_id[:8]}...")
    print(f"Description: {session.description}")
    print(f"Actions to rollback: {len(actions)}")

    for action in actions:
        print(f"  - {action.action}: {action.component_name}")

    response = input("\nProceed with rollback? [y/N] ").strip().lower()
    if response != "y":
        print("Cancelled.")
        return 0

    # Perform rollback
    result = rollback_manager.rollback_session(session_id)

    # Output result
    formatter = TextFormatter()
    print("\n" + formatter.format_session_rollback_result(result))

    if result.success:
        print("\n✓ Session rollback complete.")
    else:
        print("\n⚠ Session rollback had failures.")
        for r in result.results:
            if not r.success:
                print(f"  - {r.component_name}: {r.error_message}")

    if result.requires_reboot:
        print("\nNote: A reboot is required to complete the rollback.")

    return 0 if result.success else 1


def run_recovery_command(args: argparse.Namespace, config: Config) -> int:
    """Execute the recovery command.

    Args:
        args: Command-line arguments
        config: Configuration object

    Returns:
        Exit code
    """
    recovery = create_recovery_mode(config)

    # Check for --last-session flag
    if getattr(args, "last_session", False):
        print("Rolling back last session...")
        result = recovery.rollback_last_session()

        if result.success:
            print("\n✓ Recovery successful.")
            print(f"  Method: {result.method}")
            if result.requires_reboot:
                print("  Note: A reboot is required.")
        else:
            print("\n✗ Recovery failed.")
            print(f"  Error: {result.error_message}")

        return 0 if result.success else 1

    # Interactive recovery mode
    print("=" * 50)
    print("Debloatr Recovery Mode")
    print("=" * 50)
    print()

    status = recovery.get_status()

    if status.is_safe_mode:
        print("Running in Safe Mode")
        print()

    print("Recovery Status:")
    print(f"  Sessions available: {status.has_sessions}")
    print(f"  Rollbackable actions: {status.rollbackable_actions}")
    print(f"  Debloatr restore points: {status.debloatr_restore_points}")
    print(f"  System Restore enabled: {status.system_restore_enabled}")
    print()

    if not status.recovery_available:
        print("No recovery options available.")
        print("Consider using Windows System Restore (rstrui.exe)")
        return 1

    # Show options
    options = recovery.list_recovery_options()

    print("Recovery Options:")
    print()

    option_num = 1
    choices: list[tuple[str, Any]] = []

    if status.rollbackable_actions > 0:
        print(f"  {option_num}. Rollback last session ({status.rollbackable_actions} actions)")
        choices.append(("rollback_last", None))
        option_num += 1

    for session in options["sessions"][:3]:
        print(f"  {option_num}. Rollback session: {session['description'][:30]}")
        choices.append(("rollback_session", session["session_id"]))
        option_num += 1

    for point in options["restore_points"][:3]:
        print(f"  {option_num}. System Restore: {point['description'][:30]}")
        choices.append(("restore", point["sequence_number"]))
        option_num += 1

    print(f"  {option_num}. Exit")
    choices.append(("exit", None))

    print()
    choice = input("Select option: ").strip()

    try:
        choice_idx = int(choice) - 1
        if choice_idx < 0 or choice_idx >= len(choices):
            print("Invalid choice.")
            return 1

        action, value = choices[choice_idx]

        if action == "exit":
            return 0
        elif action == "rollback_last":
            result = recovery.rollback_last_session()
        elif action == "rollback_session":
            result = recovery.rollback_session(value)
        elif action == "restore":
            confirm = input("This will restart your computer. Continue? [y/N] ").strip().lower()
            if confirm != "y":
                print("Cancelled.")
                return 0
            result = recovery.restore_to_point(value, confirm=True)
        else:
            print("Unknown action.")
            return 1

        if result.success:
            print("\n✓ Recovery operation completed.")
            if result.requires_reboot:
                print("  System will restart...")
        else:
            print(f"\n✗ Recovery failed: {result.error_message}")

        return 0 if result.success else 1

    except ValueError:
        print("Invalid input.")
        return 1
