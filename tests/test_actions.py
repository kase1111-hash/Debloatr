"""Unit tests for actions module."""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.core.models import (
    Component,
    ComponentType,
    Classification,
    RiskLevel,
    ActionType,
    ActionPlan,
    ExecutionMode,
)
from src.actions.planner import (
    ActionPlanner,
    ActionAvailability,
    SafetyRule,
    SAFETY_RULES,
    create_default_planner,
)
from src.actions.disable import DisableHandler, DisableResult, create_disable_handler
from src.actions.contain import ContainHandler, ContainResult, create_contain_handler
from src.actions.remove import RemoveHandler, RemoveResult, create_remove_handler
from src.actions.executor import (
    ExecutionEngine,
    ExecutionContext,
    ExecutionResult,
    create_execution_engine,
    create_interactive_engine,
)


class TestSafetyRules:
    """Tests for safety rules."""

    def test_all_rules_defined(self) -> None:
        """Test that expected safety rules are defined."""
        rule_ids = [r.rule_id for r in SAFETY_RULES]
        assert "CORE_LOCKED" in rule_ids
        assert "ESSENTIAL_WARN" in rule_ids
        assert "CRITICAL_RISK" in rule_ids
        assert "HIGH_RISK_NO_REMOVE" in rule_ids

    def test_rule_has_required_fields(self) -> None:
        """Test that all rules have required fields."""
        for rule in SAFETY_RULES:
            assert rule.rule_id
            assert rule.name
            assert rule.description
            assert rule.blocked_actions
            assert rule.condition


class TestActionPlanner:
    """Tests for ActionPlanner class."""

    def test_init_default(self) -> None:
        """Test creating planner with defaults."""
        planner = ActionPlanner()
        assert len(planner.safety_rules) > 0
        assert planner.require_staging_for_oem is True

    def test_get_available_actions_normal_component(self) -> None:
        """Test available actions for a normal component."""
        planner = ActionPlanner()

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="test-app",
            display_name="Test App",
            publisher="Test",
            classification=Classification.BLOAT,
            risk_level=RiskLevel.LOW,
        )

        availability = planner.get_available_actions(component)

        assert ActionType.IGNORE in availability.available_actions
        assert ActionType.DISABLE in availability.available_actions
        assert ActionType.REMOVE in availability.available_actions

    def test_get_available_actions_core_locked(self) -> None:
        """Test that CORE components are locked."""
        planner = ActionPlanner()

        component = Component(
            component_type=ComponentType.SERVICE,
            name="core-service",
            display_name="Core Service",
            publisher="Microsoft",
            classification=Classification.CORE,
            risk_level=RiskLevel.CRITICAL,
        )

        availability = planner.get_available_actions(component)

        # Only IGNORE should be available for CORE
        assert ActionType.IGNORE in availability.available_actions
        assert ActionType.DISABLE not in availability.available_actions
        assert ActionType.REMOVE not in availability.available_actions
        assert ActionType.DISABLE in availability.blocked_actions

    def test_get_available_actions_critical_risk(self) -> None:
        """Test that CRITICAL risk components are protected."""
        planner = ActionPlanner()

        component = Component(
            component_type=ComponentType.SERVICE,
            name="critical-service",
            display_name="Critical Service",
            publisher="Microsoft",
            classification=Classification.UNKNOWN,
            risk_level=RiskLevel.CRITICAL,
        )

        availability = planner.get_available_actions(component)

        assert ActionType.DISABLE not in availability.available_actions
        assert ActionType.REMOVE not in availability.available_actions

    def test_get_available_actions_high_risk_no_remove(self) -> None:
        """Test that HIGH risk components can't be removed."""
        planner = ActionPlanner()

        component = Component(
            component_type=ComponentType.SERVICE,
            name="high-risk-service",
            display_name="High Risk Service",
            publisher="Test",
            classification=Classification.BLOAT,
            risk_level=RiskLevel.HIGH,
        )

        availability = planner.get_available_actions(component)

        # DISABLE should be available, but not REMOVE
        assert ActionType.DISABLE in availability.available_actions
        assert ActionType.REMOVE not in availability.available_actions

    def test_requires_confirmation_essential(self) -> None:
        """Test that ESSENTIAL components require confirmation."""
        planner = ActionPlanner()

        component = Component(
            component_type=ComponentType.SERVICE,
            name="essential-service",
            display_name="Essential Service",
            publisher="Test",
            classification=Classification.ESSENTIAL,
            risk_level=RiskLevel.MEDIUM,
        )

        availability = planner.get_available_actions(component)

        assert ActionType.DISABLE in availability.requires_confirmation

    def test_requires_staging_oem(self) -> None:
        """Test that OEM components require staging."""
        planner = ActionPlanner(require_staging_for_oem=True)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="oem-app",
            display_name="OEM App",
            publisher="HP Inc.",
            classification=Classification.BLOAT,
            risk_level=RiskLevel.LOW,
        )

        context = {"is_oem_preinstall": True}
        availability = planner.get_available_actions(component, context)

        assert availability.requires_staging is True

    def test_requires_staging_driver(self) -> None:
        """Test that drivers require staging."""
        planner = ActionPlanner()

        component = Component(
            component_type=ComponentType.DRIVER,
            name="test-driver",
            display_name="Test Driver",
            publisher="Test",
            classification=Classification.BLOAT,
            risk_level=RiskLevel.LOW,
        )

        availability = planner.get_available_actions(component)

        assert availability.requires_staging is True

    def test_create_action_plan(self) -> None:
        """Test creating an action plan."""
        planner = ActionPlanner()

        component = Component(
            component_type=ComponentType.SERVICE,
            name="test-service",
            display_name="Test Service",
            publisher="Test",
            classification=Classification.BLOAT,
            risk_level=RiskLevel.LOW,
        )

        plan = planner.create_action_plan(component, ActionType.DISABLE)

        assert plan.component == component
        assert plan.action == ActionType.DISABLE
        assert len(plan.steps) > 0
        assert plan.requires_admin is True

    def test_create_action_plan_blocked_action(self) -> None:
        """Test that creating plan for blocked action raises error."""
        planner = ActionPlanner()

        component = Component(
            component_type=ComponentType.SERVICE,
            name="core-service",
            display_name="Core Service",
            publisher="Microsoft",
            classification=Classification.CORE,
            risk_level=RiskLevel.CRITICAL,
        )

        with pytest.raises(ValueError, match="not available"):
            planner.create_action_plan(component, ActionType.DISABLE)

    def test_validate_plan(self) -> None:
        """Test plan validation."""
        planner = ActionPlanner()

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="test-app",
            display_name="Test App",
            publisher="Test",
            classification=Classification.BLOAT,
            risk_level=RiskLevel.LOW,
        )

        plan = planner.create_action_plan(component, ActionType.DISABLE)
        is_valid, issues = planner.validate_plan(plan)

        assert is_valid is True
        assert len(issues) == 0

    def test_add_custom_safety_rule(self) -> None:
        """Test adding a custom safety rule."""
        planner = ActionPlanner()
        initial_count = len(planner.safety_rules)

        custom_rule = SafetyRule(
            rule_id="CUSTOM_RULE",
            name="Custom Rule",
            description="A custom safety rule",
            blocked_actions=[ActionType.REMOVE],
            condition=lambda c, ctx: "custom" in c.name.lower(),
        )

        planner.add_safety_rule(custom_rule)
        assert len(planner.safety_rules) == initial_count + 1

    def test_remove_safety_rule(self) -> None:
        """Test removing a safety rule."""
        planner = ActionPlanner()
        initial_count = len(planner.safety_rules)

        removed = planner.remove_safety_rule("CORE_LOCKED")
        assert removed is True
        assert len(planner.safety_rules) == initial_count - 1


class TestDisableHandler:
    """Tests for DisableHandler class."""

    def test_init_default(self) -> None:
        """Test creating handler with defaults."""
        handler = DisableHandler()
        assert handler.dry_run is False
        assert handler.create_snapshots is True

    def test_init_dry_run(self) -> None:
        """Test creating handler in dry-run mode."""
        handler = DisableHandler(dry_run=True)
        assert handler.dry_run is True

    def test_disable_service_dry_run(self) -> None:
        """Test disabling service in dry-run mode."""
        handler = DisableHandler(dry_run=True)

        component = Component(
            component_type=ComponentType.SERVICE,
            name="test-service",
            display_name="Test Service",
            publisher="Test",
        )

        context = {"service_name": "TestService"}
        result = handler.disable_service(component, context)

        assert result.success is True
        assert result.component_type == ComponentType.SERVICE

    def test_disable_task_dry_run(self) -> None:
        """Test disabling task in dry-run mode."""
        handler = DisableHandler(dry_run=True)

        component = Component(
            component_type=ComponentType.TASK,
            name="test-task",
            display_name="Test Task",
            publisher="Test",
        )

        context = {"task_path": "\\Test\\TestTask"}
        result = handler.disable_task(component, context)

        assert result.success is True
        assert result.component_type == ComponentType.TASK

    def test_disable_startup_dry_run(self) -> None:
        """Test disabling startup entry in dry-run mode."""
        handler = DisableHandler(dry_run=True)

        component = Component(
            component_type=ComponentType.STARTUP,
            name="test-startup",
            display_name="Test Startup",
            publisher="Test",
        )

        context = {
            "entry_type": "registry",
            "registry_key": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value_name": "TestStartup",
        }
        result = handler.disable_startup(component, context)

        assert result.success is True
        assert result.component_type == ComponentType.STARTUP

    def test_disable_driver_dry_run(self) -> None:
        """Test disabling driver in dry-run mode."""
        handler = DisableHandler(dry_run=True)

        component = Component(
            component_type=ComponentType.DRIVER,
            name="test-driver",
            display_name="Test Driver",
            publisher="Test",
        )

        context = {"driver_name": "TestDriver"}
        result = handler.disable_driver(component, context)

        assert result.success is True
        assert result.requires_reboot is True

    def test_disable_component_dispatch(self) -> None:
        """Test that disable_component dispatches correctly."""
        handler = DisableHandler(dry_run=True)

        service = Component(
            component_type=ComponentType.SERVICE,
            name="svc",
            display_name="Service",
            publisher="Test",
        )
        result = handler.disable_component(service, {"service_name": "svc"})
        assert result.component_type == ComponentType.SERVICE

        task = Component(
            component_type=ComponentType.TASK,
            name="task",
            display_name="Task",
            publisher="Test",
        )
        result = handler.disable_component(task, {"task_path": "\\Task"})
        assert result.component_type == ComponentType.TASK


class TestContainHandler:
    """Tests for ContainHandler class."""

    def test_init_default(self) -> None:
        """Test creating handler with defaults."""
        handler = ContainHandler()
        assert handler.dry_run is False
        assert handler.rule_prefix == "Debloatr_Block_"

    def test_contain_component_dry_run(self) -> None:
        """Test containing component in dry-run mode."""
        handler = ContainHandler(dry_run=True)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="test-app",
            display_name="Test App",
            publisher="Test",
            install_path=Path("C:/Program Files/Test/test.exe"),
        )

        context = {"executables": ["C:/Program Files/Test/test.exe"]}
        result = handler.contain_component(component, context)

        assert result.success is True
        assert result.firewall_rule_name is not None

    def test_contain_with_firewall_dry_run(self) -> None:
        """Test firewall containment in dry-run mode."""
        handler = ContainHandler(dry_run=True)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="test-app",
            display_name="Test App",
            publisher="Test",
            install_path=Path("C:/Test/app.exe"),
        )

        result = handler.contain_with_firewall(component, {"executables": ["C:/Test/app.exe"]})
        assert result.success is True

    def test_contain_with_acl_dry_run(self) -> None:
        """Test ACL containment in dry-run mode."""
        handler = ContainHandler(dry_run=True)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="test-app",
            display_name="Test App",
            publisher="Test",
            install_path=Path("C:/Test/app.exe"),
        )

        result = handler.contain_with_acl(component, {"executables": ["C:/Test/app.exe"]})
        assert result.success is True

    def test_contain_no_executables(self) -> None:
        """Test containment fails without executables."""
        handler = ContainHandler(dry_run=True)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="test-app",
            display_name="Test App",
            publisher="Test",
        )

        result = handler.contain_component(component, {})
        assert result.success is False
        assert "No executables" in result.error_message


class TestRemoveHandler:
    """Tests for RemoveHandler class."""

    def test_init_default(self) -> None:
        """Test creating handler with defaults."""
        handler = RemoveHandler()
        assert handler.dry_run is False
        assert handler.create_restore_point is True

    def test_remove_program_dry_run(self) -> None:
        """Test removing program in dry-run mode."""
        handler = RemoveHandler(dry_run=True)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="test-app",
            display_name="Test App",
            publisher="Test",
        )

        context = {"uninstall_string": "msiexec /x {GUID}"}
        result = handler.remove_program(component, context)

        assert result.success is True
        assert result.component_type == ComponentType.PROGRAM

    def test_remove_uwp_dry_run(self) -> None:
        """Test removing UWP app in dry-run mode."""
        handler = RemoveHandler(dry_run=True)

        component = Component(
            component_type=ComponentType.UWP,
            name="Microsoft.BingWeather",
            display_name="Weather",
            publisher="Microsoft",
        )

        context = {"package_name": "Microsoft.BingWeather"}
        result = handler.remove_uwp(component, context)

        assert result.success is True
        assert result.component_type == ComponentType.UWP

    def test_remove_service_dry_run(self) -> None:
        """Test removing service in dry-run mode."""
        handler = RemoveHandler(dry_run=True)

        component = Component(
            component_type=ComponentType.SERVICE,
            name="test-service",
            display_name="Test Service",
            publisher="Test",
        )

        result = handler.remove_service(component, {"service_name": "TestService"})
        assert result.success is True
        assert result.component_type == ComponentType.SERVICE

    def test_remove_task_dry_run(self) -> None:
        """Test removing task in dry-run mode."""
        handler = RemoveHandler(dry_run=True)

        component = Component(
            component_type=ComponentType.TASK,
            name="test-task",
            display_name="Test Task",
            publisher="Test",
        )

        result = handler.remove_task(component, {"task_path": "\\Test\\Task"})
        assert result.success is True

    def test_remove_driver_dry_run(self) -> None:
        """Test removing driver in dry-run mode."""
        handler = RemoveHandler(dry_run=True)

        component = Component(
            component_type=ComponentType.DRIVER,
            name="test-driver",
            display_name="Test Driver",
            publisher="Test",
        )

        result = handler.remove_driver(component, {"driver_name": "TestDriver"})
        assert result.success is True
        assert result.requires_reboot is True


class TestExecutionEngine:
    """Tests for ExecutionEngine class."""

    def test_init_default(self) -> None:
        """Test creating engine with defaults."""
        engine = ExecutionEngine()
        assert engine.mode == ExecutionMode.DRY_RUN

    def test_init_custom_mode(self) -> None:
        """Test creating engine with custom mode."""
        engine = ExecutionEngine(mode=ExecutionMode.INTERACTIVE)
        assert engine.mode == ExecutionMode.INTERACTIVE

    def test_start_end_session(self) -> None:
        """Test session management."""
        engine = ExecutionEngine()

        session = engine.start_session("Test session")
        assert session is not None
        assert engine.current_session == session

        ended = engine.end_session()
        assert ended.session_id == session.session_id
        assert ended.ended_at is not None
        assert engine.current_session is None

    def test_end_session_without_start(self) -> None:
        """Test ending session without starting raises error."""
        engine = ExecutionEngine()

        with pytest.raises(RuntimeError, match="No active session"):
            engine.end_session()

    def test_execute_dry_run(self) -> None:
        """Test execution in dry-run mode."""
        engine = ExecutionEngine(mode=ExecutionMode.DRY_RUN)

        component = Component(
            component_type=ComponentType.SERVICE,
            name="test-service",
            display_name="Test Service",
            publisher="Test",
            classification=Classification.BLOAT,
            risk_level=RiskLevel.LOW,
        )

        plan = engine.planner.create_action_plan(component, ActionType.DISABLE)
        result = engine.execute(plan)

        assert result.success is True
        assert result.was_simulated is True

    def test_execute_scan_only(self) -> None:
        """Test execution in scan-only mode."""
        engine = ExecutionEngine(mode=ExecutionMode.SCAN_ONLY)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="test-app",
            display_name="Test App",
            publisher="Test",
            classification=Classification.BLOAT,
            risk_level=RiskLevel.LOW,
        )

        plan = engine.planner.create_action_plan(component, ActionType.DISABLE)
        result = engine.execute(plan)

        assert result.success is True
        assert result.was_simulated is True

    def test_execute_interactive_confirmed(self) -> None:
        """Test interactive mode with confirmation."""
        # Use DRY_RUN mode since we're not on Windows
        # The key test is that confirmation callback is called
        confirmation_called = [False]

        def confirm_callback(ctx: ExecutionContext) -> bool:
            confirmation_called[0] = True
            return True

        # Test that confirmation is requested in interactive mode
        engine = ExecutionEngine(mode=ExecutionMode.DRY_RUN)
        engine.confirmation_callback = confirm_callback
        engine.mode = ExecutionMode.INTERACTIVE

        component = Component(
            component_type=ComponentType.SERVICE,
            name="test-service",
            display_name="Test Service",
            publisher="Test",
            classification=Classification.BLOAT,
            risk_level=RiskLevel.LOW,
        )

        plan = engine.planner.create_action_plan(component, ActionType.DISABLE)
        result = engine.execute(plan)

        # Verify confirmation was requested
        assert confirmation_called[0] is True

    def test_execute_interactive_cancelled(self) -> None:
        """Test interactive mode with cancellation."""
        engine = ExecutionEngine(
            mode=ExecutionMode.INTERACTIVE,
            confirmation_callback=lambda ctx: False,  # Always cancel
        )

        component = Component(
            component_type=ComponentType.SERVICE,
            name="test-service",
            display_name="Test Service",
            publisher="Test",
            classification=Classification.BLOAT,
            risk_level=RiskLevel.LOW,
        )

        plan = engine.planner.create_action_plan(component, ActionType.DISABLE)
        result = engine.execute(plan)

        assert result.success is False
        assert "cancelled" in result.error_message.lower()

    def test_execute_batch(self) -> None:
        """Test batch execution."""
        engine = ExecutionEngine(mode=ExecutionMode.DRY_RUN)

        components = [
            Component(
                component_type=ComponentType.SERVICE,
                name=f"service-{i}",
                display_name=f"Service {i}",
                publisher="Test",
                classification=Classification.BLOAT,
                risk_level=RiskLevel.LOW,
            )
            for i in range(3)
        ]

        plans = [
            engine.planner.create_action_plan(c, ActionType.DISABLE)
            for c in components
        ]

        results = engine.execute_batch(plans)

        assert len(results) == 3
        assert all(r.success for r in results)

    def test_get_session_summary(self) -> None:
        """Test getting session summary."""
        engine = ExecutionEngine(mode=ExecutionMode.DRY_RUN)
        engine.start_session("Test")

        component = Component(
            component_type=ComponentType.SERVICE,
            name="test-service",
            display_name="Test Service",
            publisher="Test",
            classification=Classification.BLOAT,
            risk_level=RiskLevel.LOW,
        )

        plan = engine.planner.create_action_plan(component, ActionType.DISABLE)
        engine.execute(plan)

        summary = engine.get_session_summary()

        assert summary["total_actions"] == 1
        assert summary["successful"] == 1


class TestFactoryFunctions:
    """Tests for factory functions."""

    def test_create_default_planner(self) -> None:
        """Test create_default_planner."""
        planner = create_default_planner()
        assert isinstance(planner, ActionPlanner)

    def test_create_disable_handler(self) -> None:
        """Test create_disable_handler."""
        handler = create_disable_handler(dry_run=True)
        assert isinstance(handler, DisableHandler)
        assert handler.dry_run is True

    def test_create_contain_handler(self) -> None:
        """Test create_contain_handler."""
        handler = create_contain_handler(dry_run=True)
        assert isinstance(handler, ContainHandler)
        assert handler.dry_run is True

    def test_create_remove_handler(self) -> None:
        """Test create_remove_handler."""
        handler = create_remove_handler(dry_run=True)
        assert isinstance(handler, RemoveHandler)
        assert handler.dry_run is True

    def test_create_execution_engine(self) -> None:
        """Test create_execution_engine."""
        engine = create_execution_engine(mode=ExecutionMode.BATCH_CONFIRM)
        assert isinstance(engine, ExecutionEngine)
        assert engine.mode == ExecutionMode.BATCH_CONFIRM

    def test_create_interactive_engine(self) -> None:
        """Test create_interactive_engine."""
        callback = lambda ctx: True
        engine = create_interactive_engine(confirmation_callback=callback)

        assert isinstance(engine, ExecutionEngine)
        assert engine.mode == ExecutionMode.INTERACTIVE
        assert engine.confirmation_callback == callback
