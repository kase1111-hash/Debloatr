"""Execution Engine - Orchestrates action execution with modes.

This module provides the execution engine that coordinates action
execution with different modes (scan-only, dry-run, interactive, batch).
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from src.actions.contain import ContainHandler
from src.actions.disable import DisableHandler
from src.actions.planner import ActionPlanner
from src.actions.remove import RemoveHandler
from src.core.models import (
    ActionPlan,
    ActionResult,
    ActionType,
    Component,
    ExecutionMode,
    Session,
)

logger = logging.getLogger("debloatr.actions.executor")


@dataclass
class ExecutionContext:
    """Context for action execution.

    Attributes:
        component: Component being acted on
        action: Action being performed
        plan: Action plan being executed
        session: Current session
        dry_run: Whether this is a dry run
        require_confirmation: Whether confirmation is required
        context_data: Additional context data
    """

    component: Component
    action: ActionType
    plan: ActionPlan
    session: Session
    dry_run: bool = False
    require_confirmation: bool = False
    context_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionResult:
    """Result of executing an action plan.

    Attributes:
        success: Whether execution succeeded
        action_result: The action result
        snapshot_id: ID of the created snapshot
        execution_time_ms: Time taken in milliseconds
        requires_reboot: Whether reboot is needed
        error_message: Error message if failed
        was_simulated: Whether this was a dry run
    """

    success: bool
    action_result: ActionResult | None = None
    snapshot_id: str | None = None
    execution_time_ms: float = 0.0
    requires_reboot: bool = False
    error_message: str | None = None
    was_simulated: bool = False


class ExecutionEngine:
    """Engine for executing action plans.

    Coordinates action execution with different modes:
    - SCAN_ONLY: No execution, just return plan
    - DRY_RUN: Simulate execution without changes
    - INTERACTIVE: Prompt for confirmation before each action
    - BATCH_CONFIRM: Confirm batch, then execute all

    Example:
        engine = ExecutionEngine(mode=ExecutionMode.INTERACTIVE)
        engine.start_session("Remove bloatware")
        result = engine.execute(plan)
        if result.success:
            print("Action completed successfully")
        engine.end_session()
    """

    def __init__(
        self,
        mode: ExecutionMode = ExecutionMode.DRY_RUN,
        planner: ActionPlanner | None = None,
        confirmation_callback: Callable[[ExecutionContext], bool] | None = None,
        progress_callback: Callable[[str, float], None] | None = None,
    ) -> None:
        """Initialize the execution engine.

        Args:
            mode: Execution mode
            planner: Action planner for validation
            confirmation_callback: Function to call for user confirmation
            progress_callback: Function to report progress (message, percent)
        """
        self.mode = mode
        self.planner = planner or ActionPlanner()
        self.confirmation_callback = confirmation_callback
        self.progress_callback = progress_callback

        # Initialize action handlers
        is_dry_run = mode in [ExecutionMode.SCAN_ONLY, ExecutionMode.DRY_RUN]
        self.disable_handler = DisableHandler(dry_run=is_dry_run)
        self.contain_handler = ContainHandler(dry_run=is_dry_run)
        self.remove_handler = RemoveHandler(dry_run=is_dry_run)

        # Session management
        self._current_session: Session | None = None
        self._action_log: list[ActionResult] = []

    def start_session(self, description: str = "") -> Session:
        """Start a new execution session.

        Args:
            description: Session description

        Returns:
            New Session object
        """
        self._current_session = Session(description=description)
        self._action_log = []
        logger.info(f"Started session: {self._current_session.session_id}")
        return self._current_session

    def end_session(self) -> Session:
        """End the current session.

        Returns:
            The ended session

        Raises:
            RuntimeError: If no session is active
        """
        if not self._current_session:
            raise RuntimeError("No active session")

        self._current_session.end_session()
        self._current_session.actions = self._action_log.copy()
        session = self._current_session
        self._current_session = None
        logger.info(f"Ended session: {session.session_id}")
        return session

    @property
    def current_session(self) -> Session | None:
        """Get the current session."""
        return self._current_session

    def execute(
        self,
        plan: ActionPlan,
        context: dict[str, Any] | None = None,
    ) -> ExecutionResult:
        """Execute an action plan.

        Args:
            plan: ActionPlan to execute
            context: Additional context for execution

        Returns:
            ExecutionResult with outcome details
        """
        context = context or {}
        start_time = datetime.now()

        # Ensure we have a session
        if not self._current_session:
            self.start_session("Auto-started session")

        # Validate the plan
        is_valid, issues = self.planner.validate_plan(plan)
        if not is_valid:
            return ExecutionResult(
                success=False,
                error_message=f"Invalid plan: {'; '.join(issues)}",
            )

        # Create execution context
        exec_context = ExecutionContext(
            component=plan.component,
            action=plan.action,
            plan=plan,
            session=self._current_session,
            dry_run=self.mode in [ExecutionMode.SCAN_ONLY, ExecutionMode.DRY_RUN],
            require_confirmation=self.mode == ExecutionMode.INTERACTIVE,
            context_data=context,
        )

        # Handle different modes
        if self.mode == ExecutionMode.SCAN_ONLY:
            return self._simulate_execution(exec_context)

        if self.mode == ExecutionMode.DRY_RUN:
            return self._dry_run_execution(exec_context)

        if self.mode == ExecutionMode.INTERACTIVE:
            # Require confirmation before execution
            if self.confirmation_callback:
                if not self.confirmation_callback(exec_context):
                    return ExecutionResult(
                        success=False,
                        error_message="User cancelled action",
                    )

        # Execute the action
        result = self._execute_action(exec_context)

        # Calculate execution time
        end_time = datetime.now()
        result.execution_time_ms = (end_time - start_time).total_seconds() * 1000

        return result

    def execute_batch(
        self,
        plans: list[ActionPlan],
        context: dict[str, Any] | None = None,
    ) -> list[ExecutionResult]:
        """Execute multiple action plans.

        Args:
            plans: List of ActionPlans to execute
            context: Additional context for execution

        Returns:
            List of ExecutionResults
        """
        context = context or {}
        results: list[ExecutionResult] = []

        # Ensure we have a session
        if not self._current_session:
            self.start_session("Batch execution")

        # For batch confirm mode, get confirmation upfront
        if self.mode == ExecutionMode.BATCH_CONFIRM:
            if self.confirmation_callback:
                # Create a combined context for batch confirmation
                batch_context = ExecutionContext(
                    component=plans[0].component if plans else None,
                    action=plans[0].action if plans else ActionType.IGNORE,
                    plan=plans[0] if plans else None,
                    session=self._current_session,
                    context_data={"batch_size": len(plans), "plans": plans},
                )
                if not self.confirmation_callback(batch_context):
                    return [
                        ExecutionResult(success=False, error_message="User cancelled batch")
                        for _ in plans
                    ]

        # Execute each plan
        total = len(plans)
        for i, plan in enumerate(plans):
            if self.progress_callback:
                progress = (i / total) * 100
                self.progress_callback(f"Executing {plan.component.name}...", progress)

            result = self.execute(plan, context)
            results.append(result)

            # Stop on failure if configured
            if not result.success and context.get("stop_on_failure", False):
                logger.warning("Stopping batch execution due to failure")
                # Add cancelled results for remaining plans
                for _remaining in plans[i + 1 :]:
                    results.append(
                        ExecutionResult(
                            success=False,
                            error_message="Cancelled due to previous failure",
                        )
                    )
                break

        if self.progress_callback:
            self.progress_callback("Batch execution complete", 100)

        return results

    def _simulate_execution(self, context: ExecutionContext) -> ExecutionResult:
        """Simulate execution without any changes (SCAN_ONLY mode)."""
        logger.info(
            f"[SCAN_ONLY] Would execute: {context.action.value} on {context.component.name}"
        )

        return ExecutionResult(
            success=True,
            was_simulated=True,
            action_result=ActionResult(
                plan_id=context.plan.plan_id,
                success=True,
                action=context.action,
                component_id=context.component.id,
            ),
        )

    def _dry_run_execution(self, context: ExecutionContext) -> ExecutionResult:
        """Execute in dry-run mode (simulate with detailed output)."""
        logger.info(f"[DRY RUN] Executing: {context.action.value} on {context.component.name}")

        # Run through the handlers in dry-run mode
        result = self._execute_action(context)
        result.was_simulated = True

        return result

    def _execute_action(self, context: ExecutionContext) -> ExecutionResult:
        """Execute the actual action."""
        component = context.component
        action = context.action
        plan = context.plan

        try:
            # Dispatch to appropriate handler
            if action == ActionType.DISABLE:
                handler_result = self.disable_handler.disable_component(
                    component, context.context_data
                )
                success = handler_result.success
                requires_reboot = handler_result.requires_reboot
                error_message = handler_result.error_message
                snapshot = handler_result.snapshot

            elif action == ActionType.CONTAIN:
                handler_result = self.contain_handler.contain_component(
                    component, context.context_data
                )
                success = handler_result.success
                requires_reboot = False
                error_message = handler_result.error_message
                snapshot = handler_result.snapshot

            elif action == ActionType.REMOVE:
                handler_result = self.remove_handler.remove_component(
                    component, context.context_data
                )
                success = handler_result.success
                requires_reboot = handler_result.requires_reboot
                error_message = handler_result.error_message
                snapshot = handler_result.snapshot

            elif action == ActionType.REPLACE:
                # Replace is a combination of remove + install replacement
                # For now, just mark as not implemented
                return ExecutionResult(
                    success=False,
                    error_message="REPLACE action not yet implemented",
                )

            elif action == ActionType.IGNORE:
                success = True
                requires_reboot = False
                error_message = None
                snapshot = None

            else:
                return ExecutionResult(
                    success=False,
                    error_message=f"Unknown action type: {action}",
                )

            # Create action result
            action_result = ActionResult(
                plan_id=plan.plan_id,
                success=success,
                action=action,
                component_id=component.id,
                snapshot_id=snapshot.snapshot_id if snapshot else None,
                error_message=error_message,
                rollback_available=snapshot is not None,
            )

            # Add to session log
            self._action_log.append(action_result)

            return ExecutionResult(
                success=success,
                action_result=action_result,
                snapshot_id=snapshot.snapshot_id if snapshot else None,
                requires_reboot=requires_reboot,
                error_message=error_message,
            )

        except Exception as e:
            logger.error(f"Error executing action {action.value}: {e}")
            action_result = ActionResult(
                plan_id=plan.plan_id,
                success=False,
                action=action,
                component_id=component.id,
                error_message=str(e),
            )
            self._action_log.append(action_result)

            return ExecutionResult(
                success=False,
                action_result=action_result,
                error_message=str(e),
            )

    def get_session_summary(self) -> dict[str, Any]:
        """Get summary of current or last session.

        Returns:
            Dictionary with session statistics
        """
        actions = self._action_log

        return {
            "total_actions": len(actions),
            "successful": sum(1 for a in actions if a.success),
            "failed": sum(1 for a in actions if not a.success),
            "by_action_type": self._count_by_action_type(actions),
            "requires_reboot": any(
                r.requires_reboot for r in self._action_log if hasattr(r, "requires_reboot")
            ),
        }

    def _count_by_action_type(self, actions: list[ActionResult]) -> dict[str, int]:
        """Count actions by type."""
        counts: dict[str, int] = {}
        for action in actions:
            action_type = action.action.value
            counts[action_type] = counts.get(action_type, 0) + 1
        return counts


def create_execution_engine(
    mode: ExecutionMode = ExecutionMode.DRY_RUN,
) -> ExecutionEngine:
    """Create an execution engine.

    Args:
        mode: Execution mode

    Returns:
        ExecutionEngine instance
    """
    return ExecutionEngine(mode=mode)


def create_interactive_engine(
    confirmation_callback: Callable[[ExecutionContext], bool],
    progress_callback: Callable[[str, float], None] | None = None,
) -> ExecutionEngine:
    """Create an interactive execution engine.

    Args:
        confirmation_callback: Function to confirm actions
        progress_callback: Optional progress reporting function

    Returns:
        ExecutionEngine in interactive mode
    """
    return ExecutionEngine(
        mode=ExecutionMode.INTERACTIVE,
        confirmation_callback=confirmation_callback,
        progress_callback=progress_callback,
    )
