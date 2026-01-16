"""Tests for core data models."""

import pytest
from datetime import datetime
from pathlib import Path

from src.core.models import (
    ComponentType,
    Classification,
    RiskLevel,
    ActionType,
    ExecutionMode,
    ReinstallBehavior,
    Component,
    ClassificationResult,
    ActionPlan,
    ActionResult,
    Snapshot,
    Session,
    SignatureMatchRule,
    Signature,
)


class TestEnums:
    """Tests for enum types."""

    def test_component_type_values(self):
        """Test ComponentType enum has all expected values."""
        assert ComponentType.PROGRAM.name == "PROGRAM"
        assert ComponentType.SERVICE.name == "SERVICE"
        assert ComponentType.TASK.name == "TASK"
        assert ComponentType.STARTUP.name == "STARTUP"
        assert ComponentType.DRIVER.name == "DRIVER"
        assert ComponentType.UWP.name == "UWP"
        assert ComponentType.TELEMETRY.name == "TELEMETRY"

    def test_classification_values(self):
        """Test Classification enum has all expected values."""
        assert Classification.CORE.value == "CORE"
        assert Classification.ESSENTIAL.value == "ESSENTIAL"
        assert Classification.OPTIONAL.value == "OPTIONAL"
        assert Classification.BLOAT.value == "BLOAT"
        assert Classification.AGGRESSIVE.value == "AGGRESSIVE"
        assert Classification.UNKNOWN.value == "UNKNOWN"

    def test_risk_level_comparison(self):
        """Test RiskLevel comparison operators."""
        assert RiskLevel.NONE < RiskLevel.LOW
        assert RiskLevel.LOW < RiskLevel.MEDIUM
        assert RiskLevel.MEDIUM < RiskLevel.HIGH
        assert RiskLevel.HIGH < RiskLevel.CRITICAL

        assert RiskLevel.CRITICAL > RiskLevel.NONE
        assert RiskLevel.MEDIUM >= RiskLevel.LOW
        assert RiskLevel.LOW <= RiskLevel.LOW

    def test_action_type_values(self):
        """Test ActionType enum has all expected values."""
        assert ActionType.DISABLE.value == "DISABLE"
        assert ActionType.CONTAIN.value == "CONTAIN"
        assert ActionType.REMOVE.value == "REMOVE"
        assert ActionType.REPLACE.value == "REPLACE"
        assert ActionType.IGNORE.value == "IGNORE"

    def test_execution_mode_values(self):
        """Test ExecutionMode enum has all expected values."""
        assert ExecutionMode.SCAN_ONLY.value == "SCAN_ONLY"
        assert ExecutionMode.DRY_RUN.value == "DRY_RUN"
        assert ExecutionMode.INTERACTIVE.value == "INTERACTIVE"
        assert ExecutionMode.BATCH_CONFIRM.value == "BATCH_CONFIRM"


class TestComponent:
    """Tests for Component dataclass."""

    def test_component_creation(self):
        """Test basic component creation."""
        component = Component(
            component_type=ComponentType.PROGRAM,
            name="test-program",
            display_name="Test Program",
            publisher="Test Publisher",
        )

        assert component.name == "test-program"
        assert component.display_name == "Test Program"
        assert component.publisher == "Test Publisher"
        assert component.component_type == ComponentType.PROGRAM
        assert component.classification == Classification.UNKNOWN
        assert component.risk_level == RiskLevel.NONE
        assert component.id is not None
        assert len(component.id) == 36  # UUID format

    def test_component_with_all_fields(self):
        """Test component creation with all fields."""
        component = Component(
            component_type=ComponentType.SERVICE,
            name="test-service",
            display_name="Test Service",
            publisher="Test Corp",
            install_path=Path("C:/Program Files/Test"),
            classification=Classification.BLOAT,
            risk_level=RiskLevel.LOW,
            metadata={"key": "value"},
        )

        assert component.install_path == Path("C:/Program Files/Test")
        assert component.classification == Classification.BLOAT
        assert component.risk_level == RiskLevel.LOW
        assert component.metadata == {"key": "value"}

    def test_component_equality(self):
        """Test component equality based on ID."""
        component1 = Component(
            component_type=ComponentType.PROGRAM,
            name="test",
            display_name="Test",
            publisher="Test",
        )
        component2 = Component(
            component_type=ComponentType.PROGRAM,
            name="test",
            display_name="Test",
            publisher="Test",
        )

        # Different IDs means not equal
        assert component1 != component2

        # Same ID means equal
        component2.id = component1.id
        assert component1 == component2

    def test_component_hash(self):
        """Test component hashing for use in sets/dicts."""
        component = Component(
            component_type=ComponentType.PROGRAM,
            name="test",
            display_name="Test",
            publisher="Test",
        )

        # Should be hashable
        component_set = {component}
        assert component in component_set


class TestClassificationResult:
    """Tests for ClassificationResult dataclass."""

    def test_classification_result_creation(self):
        """Test basic classification result creation."""
        result = ClassificationResult(
            classification=Classification.BLOAT,
            source="signature",
            confidence=1.0,
            signature_id="test-sig-001",
        )

        assert result.classification == Classification.BLOAT
        assert result.source == "signature"
        assert result.confidence == 1.0
        assert result.signature_id == "test-sig-001"

    def test_classification_result_with_heuristics(self):
        """Test classification result with heuristic flags."""
        result = ClassificationResult(
            classification=Classification.BLOAT,
            source="heuristic",
            confidence=0.7,
            heuristic_flags=["AUTOSTART_NO_UI", "TELEMETRY_PATTERN"],
        )

        assert result.source == "heuristic"
        assert len(result.heuristic_flags) == 2
        assert "TELEMETRY_PATTERN" in result.heuristic_flags


class TestActionPlan:
    """Tests for ActionPlan dataclass."""

    def test_action_plan_creation(self):
        """Test basic action plan creation."""
        component = Component(
            component_type=ComponentType.SERVICE,
            name="test-service",
            display_name="Test Service",
            publisher="Test",
        )

        plan = ActionPlan(
            component=component,
            action=ActionType.DISABLE,
            steps=["Stop service", "Set startup type to Disabled"],
            requires_admin=True,
        )

        assert plan.component == component
        assert plan.action == ActionType.DISABLE
        assert len(plan.steps) == 2
        assert plan.requires_admin is True
        assert plan.plan_id is not None


class TestSession:
    """Tests for Session dataclass."""

    def test_session_creation(self):
        """Test basic session creation."""
        session = Session(description="Test session")

        assert session.description == "Test session"
        assert session.is_active is True
        assert session.session_id is not None
        assert len(session.actions) == 0

    def test_session_end(self):
        """Test ending a session."""
        session = Session()
        assert session.is_active is True

        session.end_session()
        assert session.is_active is False
        assert session.ended_at is not None


class TestSignature:
    """Tests for Signature dataclass."""

    def test_signature_creation(self):
        """Test basic signature creation."""
        match_rules = SignatureMatchRule(
            name_pattern="^Test.*",
            publisher_pattern="Test Corp",
        )

        signature = Signature(
            signature_id="test-001",
            publisher="Test Corp",
            component_name="Test Component",
            component_type=ComponentType.PROGRAM,
            match_rules=match_rules,
            classification=Classification.BLOAT,
            safe_actions=[ActionType.DISABLE],
        )

        assert signature.signature_id == "test-001"
        assert signature.classification == Classification.BLOAT
        assert ActionType.DISABLE in signature.safe_actions
