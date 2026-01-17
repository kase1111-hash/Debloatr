"""Action Planner - Plans and validates component actions.

This module provides the action planning system that determines
which actions are available for a component and generates
detailed execution plans.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from src.analysis.risk import RiskAnalyzer
from src.core.models import (
    ActionPlan,
    ActionType,
    Classification,
    Component,
    ComponentType,
    RiskLevel,
)

logger = logging.getLogger("debloatr.actions.planner")


@dataclass
class SafetyRule:
    """A safety rule that restricts actions.

    Attributes:
        rule_id: Unique identifier for the rule
        name: Human-readable rule name
        description: Explanation of the rule
        applies_to: Component types this rule applies to (None = all)
        blocked_actions: Actions blocked by this rule
        condition: Function that returns True if rule should apply
        message: Warning message when rule blocks an action
    """

    rule_id: str
    name: str
    description: str
    blocked_actions: list[ActionType]
    condition: callable  # (Component, dict) -> bool
    applies_to: list[ComponentType] | None = None
    message: str = ""


# Define safety rules
SAFETY_RULES: list[SafetyRule] = [
    SafetyRule(
        rule_id="CORE_LOCKED",
        name="Core components are read-only",
        description="Components classified as CORE cannot be modified",
        blocked_actions=[
            ActionType.DISABLE,
            ActionType.CONTAIN,
            ActionType.REMOVE,
            ActionType.REPLACE,
        ],
        condition=lambda c, ctx: c.classification == Classification.CORE,
        message="Core system component - modifications locked for safety",
    ),
    SafetyRule(
        rule_id="ESSENTIAL_WARN",
        name="Essential components require confirmation",
        description="Components classified as ESSENTIAL require explicit confirmation",
        blocked_actions=[ActionType.REMOVE],
        condition=lambda c, ctx: c.classification == Classification.ESSENTIAL,
        message="Essential component - removal may impact system functionality",
    ),
    SafetyRule(
        rule_id="CRITICAL_RISK",
        name="Critical risk blocks all actions",
        description="Components with CRITICAL risk level cannot be modified",
        blocked_actions=[
            ActionType.DISABLE,
            ActionType.CONTAIN,
            ActionType.REMOVE,
            ActionType.REPLACE,
        ],
        condition=lambda c, ctx: c.risk_level == RiskLevel.CRITICAL,
        message="Critical system component - modifications blocked",
    ),
    SafetyRule(
        rule_id="HIGH_RISK_NO_REMOVE",
        name="High risk blocks removal",
        description="Components with HIGH risk cannot be removed",
        blocked_actions=[ActionType.REMOVE],
        condition=lambda c, ctx: c.risk_level == RiskLevel.HIGH,
        message="High-risk component - removal not recommended",
    ),
    SafetyRule(
        rule_id="DRIVER_DISABLE_FIRST",
        name="Drivers require disable before remove",
        description="Drivers must be disabled before they can be removed",
        blocked_actions=[ActionType.REMOVE],
        condition=lambda c, ctx: (
            c.component_type == ComponentType.DRIVER and ctx.get("is_running", True)
        ),
        applies_to=[ComponentType.DRIVER],
        message="Driver is running - disable before removal",
    ),
    SafetyRule(
        rule_id="BOOT_CRITICAL",
        name="Boot-critical components protected",
        description="Components required for boot cannot be modified",
        blocked_actions=[ActionType.DISABLE, ActionType.REMOVE],
        condition=lambda c, ctx: ctx.get("is_boot_critical", False),
        message="Boot-critical component - modifications blocked",
    ),
    SafetyRule(
        rule_id="SECURITY_PROTECTED",
        name="Security components protected",
        description="Security-related components have restricted actions",
        blocked_actions=[ActionType.REMOVE],
        condition=lambda c, ctx: ctx.get("is_security_component", False),
        message="Security component - removal blocked",
    ),
]


@dataclass
class ActionAvailability:
    """Information about action availability for a component.

    Attributes:
        component_id: ID of the component
        available_actions: List of actions that can be performed
        blocked_actions: Dictionary of blocked actions with reasons
        requires_confirmation: Actions that need user confirmation
        requires_staging: Whether changes should be staged
        warnings: General warnings about the component
    """

    component_id: str
    available_actions: list[ActionType] = field(default_factory=list)
    blocked_actions: dict[ActionType, str] = field(default_factory=dict)
    requires_confirmation: list[ActionType] = field(default_factory=list)
    requires_staging: bool = False
    warnings: list[str] = field(default_factory=list)


class ActionPlanner:
    """Planner for determining and creating action plans.

    Evaluates safety rules, risk levels, and component properties
    to determine which actions are available and generates
    detailed execution plans.

    Example:
        planner = ActionPlanner()
        availability = planner.get_available_actions(component)
        if ActionType.DISABLE in availability.available_actions:
            plan = planner.create_action_plan(component, ActionType.DISABLE)
    """

    def __init__(
        self,
        safety_rules: list[SafetyRule] | None = None,
        risk_analyzer: RiskAnalyzer | None = None,
        require_staging_for_oem: bool = True,
        staging_days: int = 7,
    ) -> None:
        """Initialize the action planner.

        Args:
            safety_rules: Custom safety rules (defaults to SAFETY_RULES)
            risk_analyzer: Risk analyzer for assessments
            require_staging_for_oem: Whether OEM tools require staging
            staging_days: Number of days for staging period
        """
        self.safety_rules = safety_rules or SAFETY_RULES.copy()
        self.risk_analyzer = risk_analyzer or RiskAnalyzer()
        self.require_staging_for_oem = require_staging_for_oem
        self.staging_days = staging_days

    def get_available_actions(
        self,
        component: Component,
        context: dict[str, Any] | None = None,
    ) -> ActionAvailability:
        """Determine which actions are available for a component.

        Args:
            component: Component to evaluate
            context: Additional context about the component

        Returns:
            ActionAvailability with available and blocked actions
        """
        context = context or {}
        availability = ActionAvailability(component_id=component.id)

        # Get risk assessment
        assessment = self.risk_analyzer.analyze(component, context)

        # Start with all actions potentially available
        all_actions = [
            ActionType.DISABLE,
            ActionType.CONTAIN,
            ActionType.REMOVE,
            ActionType.REPLACE,
            ActionType.IGNORE,
        ]

        # IGNORE is always available
        availability.available_actions.append(ActionType.IGNORE)

        # Check each action against safety rules
        for action in all_actions:
            if action == ActionType.IGNORE:
                continue

            blocked = False
            for rule in self.safety_rules:
                # Check if rule applies to this component type
                if rule.applies_to and component.component_type not in rule.applies_to:
                    continue

                # Check if rule blocks this action
                if action not in rule.blocked_actions:
                    continue

                # Check if rule condition is met
                try:
                    if rule.condition(component, context):
                        blocked = True
                        availability.blocked_actions[action] = rule.message
                        logger.debug(
                            f"Action {action.value} blocked for {component.name} "
                            f"by rule {rule.rule_id}"
                        )
                        break
                except Exception as e:
                    logger.warning(f"Error evaluating rule {rule.rule_id}: {e}")

            if not blocked:
                availability.available_actions.append(action)

        # Determine which actions require confirmation
        if component.classification == Classification.ESSENTIAL:
            if ActionType.DISABLE in availability.available_actions:
                availability.requires_confirmation.append(ActionType.DISABLE)

        if component.risk_level >= RiskLevel.MEDIUM:
            for action in [ActionType.DISABLE, ActionType.REMOVE]:
                if action in availability.available_actions:
                    if action not in availability.requires_confirmation:
                        availability.requires_confirmation.append(action)

        # Check if staging is required
        if self.require_staging_for_oem and context.get("is_oem_preinstall", False):
            availability.requires_staging = True
            availability.warnings.append(
                f"OEM software changes will be staged for {self.staging_days} days"
            )

        if component.component_type == ComponentType.DRIVER:
            availability.requires_staging = True
            availability.warnings.append("Driver changes will be staged")

        if assessment.requires_staging:
            availability.requires_staging = True

        # Add warnings from risk assessment
        availability.warnings.extend(assessment.warnings)

        return availability

    def create_action_plan(
        self,
        component: Component,
        action: ActionType,
        context: dict[str, Any] | None = None,
    ) -> ActionPlan:
        """Create a detailed action plan for a component.

        Args:
            component: Component to act on
            action: Action to perform
            context: Additional context

        Returns:
            ActionPlan with execution steps

        Raises:
            ValueError: If action is not available for the component
        """
        context = context or {}

        # Verify action is available
        availability = self.get_available_actions(component, context)
        if action not in availability.available_actions:
            reason = availability.blocked_actions.get(action, "Unknown reason")
            raise ValueError(f"Action {action.value} not available: {reason}")

        # Get risk assessment
        assessment = self.risk_analyzer.analyze(component, context)

        # Generate execution steps based on action and component type
        steps = self._generate_steps(component, action, context)

        # Determine requirements
        requires_admin = self._requires_admin(component, action)
        requires_reboot = self._requires_reboot(component, action, context)

        # Collect warnings
        warnings = list(availability.warnings)
        if action == ActionType.REMOVE:
            warnings.append("This action may not be fully reversible")
        if requires_reboot:
            warnings.append("A system restart will be required")

        return ActionPlan(
            component=component,
            action=action,
            steps=steps,
            requires_admin=requires_admin,
            requires_reboot=requires_reboot,
            estimated_risk=assessment.overall_risk,
            warnings=warnings,
        )

    def _generate_steps(
        self,
        component: Component,
        action: ActionType,
        context: dict[str, Any],
    ) -> list[str]:
        """Generate execution steps for an action.

        Args:
            component: Component to act on
            action: Action to perform
            context: Additional context

        Returns:
            List of step descriptions
        """
        steps: list[str] = []

        if action == ActionType.DISABLE:
            steps.extend(self._generate_disable_steps(component, context))
        elif action == ActionType.CONTAIN:
            steps.extend(self._generate_contain_steps(component, context))
        elif action == ActionType.REMOVE:
            steps.extend(self._generate_remove_steps(component, context))
        elif action == ActionType.REPLACE:
            steps.extend(self._generate_replace_steps(component, context))
        elif action == ActionType.IGNORE:
            steps.append("Mark component as reviewed - no action taken")

        return steps

    def _generate_disable_steps(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> list[str]:
        """Generate steps for disabling a component."""
        steps: list[str] = []

        if component.component_type == ComponentType.SERVICE:
            steps.append("Create snapshot of service configuration")
            steps.append("Stop the service if running")
            steps.append("Set service startup type to Disabled")
            steps.append("Verify service is stopped")

        elif component.component_type == ComponentType.TASK:
            steps.append("Create snapshot of task definition")
            steps.append("Disable the scheduled task")
            steps.append("Verify task is disabled")

        elif component.component_type == ComponentType.STARTUP:
            steps.append("Create snapshot of startup entry")
            entry_type = context.get("entry_type", "registry")
            if entry_type == "registry":
                steps.append("Rename or remove registry startup value")
            else:
                steps.append("Move startup shortcut to quarantine")
            steps.append("Verify startup entry is disabled")

        elif component.component_type == ComponentType.DRIVER:
            steps.append("Create snapshot of driver configuration")
            steps.append("Stop the driver if running")
            steps.append("Set driver startup type to Disabled")
            steps.append("Verify driver is stopped")
            steps.append("Note: Changes take effect after reboot")

        elif component.component_type == ComponentType.PROGRAM:
            steps.append("Create snapshot of program state")
            steps.append("Disable associated services")
            steps.append("Disable associated scheduled tasks")
            steps.append("Disable startup entries")
            steps.append("Verify program autostart is disabled")

        else:
            steps.append("Create snapshot of component state")
            steps.append("Disable component")
            steps.append("Verify component is disabled")

        return steps

    def _generate_contain_steps(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> list[str]:
        """Generate steps for containing a component."""
        steps: list[str] = []

        steps.append("Create snapshot of current state")

        # Firewall containment
        if context.get("has_network_access", False):
            steps.append("Create outbound firewall block rule")
            steps.append("Block all network access for component executable")

        # ACL containment
        if component.install_path:
            steps.append("Apply deny execute ACL to component path")
            steps.append("Prevent component from running")

        steps.append("Verify containment is effective")
        steps.append("Log containment action for audit")

        return steps

    def _generate_remove_steps(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> list[str]:
        """Generate steps for removing a component."""
        steps: list[str] = []

        steps.append("Create full snapshot for rollback")
        steps.append("Create System Restore point")

        if component.component_type == ComponentType.PROGRAM:
            is_uwp = context.get("is_uwp", False)
            uninstall_string = context.get("uninstall_string", "")

            if is_uwp:
                steps.append("Remove UWP package using Remove-AppxPackage")
                steps.append("Remove provisioned package if present")
            elif uninstall_string:
                steps.append("Execute native uninstaller")
                steps.append("Wait for uninstall to complete")
            else:
                steps.append("WARNING: No native uninstaller available")
                steps.append("Move program files to quarantine")

            steps.append("Remove leftover registry entries")
            steps.append("Remove leftover files and folders")

        elif component.component_type == ComponentType.SERVICE:
            steps.append("Stop the service")
            steps.append("Mark service for deletion")
            steps.append("Remove service binary if standalone")
            steps.append("Clean up service registry entries")

        elif component.component_type == ComponentType.TASK:
            steps.append("Delete the scheduled task")
            steps.append("Remove task action files if standalone")

        elif component.component_type == ComponentType.STARTUP:
            steps.append("Remove startup entry completely")
            steps.append("Remove associated files if applicable")

        elif component.component_type == ComponentType.DRIVER:
            steps.append("Ensure driver is disabled first")
            steps.append("Uninstall driver using pnputil")
            steps.append("Remove driver files")
            steps.append("Clean up driver registry entries")

        else:
            steps.append("Remove component files and configuration")

        steps.append("Verify removal is complete")
        steps.append("Log removal action for audit")

        return steps

    def _generate_replace_steps(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> list[str]:
        """Generate steps for replacing a component."""
        steps: list[str] = []

        replacement = context.get("replacement", None)
        if not replacement:
            steps.append("WARNING: No replacement specified")
            return steps

        steps.append("Create full snapshot for rollback")
        steps.append(f"Download/locate replacement: {replacement}")
        steps.append("Disable original component")
        steps.append("Install replacement component")
        steps.append("Configure replacement to match original settings")
        steps.append("Verify replacement is functional")
        steps.append("Log replacement action for audit")

        return steps

    def _requires_admin(
        self,
        component: Component,
        action: ActionType,
    ) -> bool:
        """Determine if an action requires admin privileges."""
        # Most system modifications require admin
        if action in [ActionType.DISABLE, ActionType.REMOVE, ActionType.REPLACE]:
            return True

        if action == ActionType.CONTAIN:
            return True  # Firewall/ACL changes need admin

        # Services and drivers always need admin
        if component.component_type in [ComponentType.SERVICE, ComponentType.DRIVER]:
            return True

        # Machine-level startup entries need admin
        if component.component_type == ComponentType.STARTUP:
            return True  # Conservative: assume machine-level

        return False

    def _requires_reboot(
        self,
        component: Component,
        action: ActionType,
        context: dict[str, Any],
    ) -> bool:
        """Determine if an action requires a reboot."""
        # Driver changes typically require reboot
        if component.component_type == ComponentType.DRIVER:
            if action in [ActionType.DISABLE, ActionType.REMOVE]:
                return True

        # Some services require reboot to fully stop
        if component.component_type == ComponentType.SERVICE:
            if context.get("is_boot_start", False):
                return True

        # Kernel-level changes require reboot
        if context.get("is_kernel_component", False):
            return True

        return False

    def add_safety_rule(self, rule: SafetyRule) -> None:
        """Add a custom safety rule.

        Args:
            rule: SafetyRule to add
        """
        self.safety_rules.append(rule)
        logger.info(f"Added safety rule: {rule.rule_id}")

    def remove_safety_rule(self, rule_id: str) -> bool:
        """Remove a safety rule.

        Args:
            rule_id: ID of the rule to remove

        Returns:
            True if removed, False if not found
        """
        for i, rule in enumerate(self.safety_rules):
            if rule.rule_id == rule_id:
                del self.safety_rules[i]
                logger.info(f"Removed safety rule: {rule_id}")
                return True
        return False

    def validate_plan(self, plan: ActionPlan) -> tuple[bool, list[str]]:
        """Validate an action plan before execution.

        Args:
            plan: ActionPlan to validate

        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues: list[str] = []

        # Check component still exists and is valid
        if not plan.component:
            issues.append("Plan references invalid component")

        # Check action is still available
        availability = self.get_available_actions(plan.component)
        if plan.action not in availability.available_actions:
            reason = availability.blocked_actions.get(plan.action, "Unknown")
            issues.append(f"Action no longer available: {reason}")

        # Check steps are defined
        if not plan.steps:
            issues.append("Plan has no execution steps")

        # Validate plan age (plans shouldn't be too old)
        age_hours = (datetime.now() - plan.created_at).total_seconds() / 3600
        if age_hours > 24:
            issues.append(f"Plan is {age_hours:.1f} hours old - recommend regenerating")

        return len(issues) == 0, issues


def create_default_planner() -> ActionPlanner:
    """Create an action planner with default settings.

    Returns:
        Configured ActionPlanner instance
    """
    return ActionPlanner()
