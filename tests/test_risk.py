"""Unit tests for risk analyzer module."""

import pytest
from pathlib import Path

from src.core.models import Component, ComponentType, RiskLevel
from src.analysis.risk import (
    RiskAnalyzer,
    RiskAssessment,
    RiskDimension,
    DimensionScore,
    create_default_analyzer,
)


class TestRiskDimension:
    """Tests for RiskDimension enum."""

    def test_all_dimensions_defined(self) -> None:
        """Test that all five dimensions are defined."""
        assert RiskDimension.BOOT_STABILITY
        assert RiskDimension.HARDWARE_FUNCTION
        assert RiskDimension.UPDATE_PIPELINE
        assert RiskDimension.SECURITY_SURFACE
        assert RiskDimension.USER_EXPERIENCE


class TestDimensionScore:
    """Tests for DimensionScore dataclass."""

    def test_score_creation(self) -> None:
        """Test creating a dimension score."""
        score = DimensionScore(
            dimension=RiskDimension.BOOT_STABILITY,
            level=RiskLevel.HIGH,
            confidence=0.9,
            factors=["Is boot-critical service"],
            explanation="High risk to boot stability",
        )

        assert score.dimension == RiskDimension.BOOT_STABILITY
        assert score.level == RiskLevel.HIGH
        assert score.confidence == 0.9
        assert len(score.factors) == 1

    def test_score_defaults(self) -> None:
        """Test DimensionScore default values."""
        score = DimensionScore(
            dimension=RiskDimension.USER_EXPERIENCE,
            level=RiskLevel.NONE,
        )

        assert score.confidence == 1.0
        assert score.factors == []
        assert score.explanation == ""


class TestRiskAssessment:
    """Tests for RiskAssessment dataclass."""

    def test_assessment_defaults(self) -> None:
        """Test RiskAssessment default values."""
        assessment = RiskAssessment(component_id="test-123")

        assert assessment.component_id == "test-123"
        assert assessment.overall_risk == RiskLevel.NONE
        assert assessment.composite_score == 0.0
        assert assessment.safe_to_disable is True
        assert assessment.safe_to_remove is True
        assert assessment.requires_staging is False
        assert assessment.warnings == []


class TestRiskAnalyzer:
    """Tests for RiskAnalyzer class."""

    def test_init_default(self) -> None:
        """Test creating analyzer with defaults."""
        analyzer = RiskAnalyzer()

        # Check default weights exist
        assert RiskDimension.BOOT_STABILITY in analyzer.dimension_weights
        assert RiskDimension.HARDWARE_FUNCTION in analyzer.dimension_weights
        assert RiskDimension.UPDATE_PIPELINE in analyzer.dimension_weights
        assert RiskDimension.SECURITY_SURFACE in analyzer.dimension_weights
        assert RiskDimension.USER_EXPERIENCE in analyzer.dimension_weights

        # Weights should sum to approximately 1.0
        total = sum(analyzer.dimension_weights.values())
        assert abs(total - 1.0) < 0.001

    def test_init_custom_weights(self) -> None:
        """Test creating analyzer with custom weights."""
        custom_weights = {
            RiskDimension.BOOT_STABILITY: 0.4,
            RiskDimension.HARDWARE_FUNCTION: 0.2,
            RiskDimension.UPDATE_PIPELINE: 0.2,
            RiskDimension.SECURITY_SURFACE: 0.1,
            RiskDimension.USER_EXPERIENCE: 0.1,
        }

        analyzer = RiskAnalyzer(dimension_weights=custom_weights)

        # Should normalize weights
        total = sum(analyzer.dimension_weights.values())
        assert abs(total - 1.0) < 0.001

    def test_analyze_low_risk_component(self) -> None:
        """Test analyzing a low-risk component."""
        analyzer = RiskAnalyzer()

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="notepad-alternative",
            display_name="Simple Notepad",
            publisher="Open Source Project",
        )

        assessment = analyzer.analyze(component, {})

        assert assessment.overall_risk <= RiskLevel.LOW
        assert assessment.safe_to_disable is True
        assert assessment.safe_to_remove is True

    def test_analyze_boot_critical_service(self) -> None:
        """Test analyzing a boot-critical service."""
        analyzer = RiskAnalyzer()

        component = Component(
            component_type=ComponentType.SERVICE,
            name="rpcss",
            display_name="Remote Procedure Call",
            publisher="Microsoft Corporation",
        )

        assessment = analyzer.analyze(component, {})

        assert assessment.overall_risk == RiskLevel.CRITICAL
        assert assessment.safe_to_disable is False
        assert assessment.safe_to_remove is False
        assert len(assessment.warnings) > 0

    def test_analyze_driver(self) -> None:
        """Test analyzing a system driver."""
        analyzer = RiskAnalyzer()

        component = Component(
            component_type=ComponentType.DRIVER,
            name="usbhub",
            display_name="USB Hub Driver",
            publisher="Microsoft Corporation",
        )

        context = {
            "is_microsoft_signed": True,
            "driver_type": "system",
        }

        assessment = analyzer.analyze(component, context)

        # Drivers should have elevated risk
        assert assessment.overall_risk >= RiskLevel.MEDIUM
        assert assessment.requires_staging is True

    def test_analyze_windows_update_service(self) -> None:
        """Test analyzing Windows Update service."""
        analyzer = RiskAnalyzer()

        component = Component(
            component_type=ComponentType.SERVICE,
            name="wuauserv",
            display_name="Windows Update",
            publisher="Microsoft Corporation",
        )

        assessment = analyzer.analyze(component, {})

        # Should be critical for update pipeline
        update_score = assessment.dimension_scores.get(RiskDimension.UPDATE_PIPELINE)
        assert update_score is not None
        assert update_score.level == RiskLevel.CRITICAL

    def test_analyze_security_component(self) -> None:
        """Test analyzing a security component."""
        analyzer = RiskAnalyzer()

        component = Component(
            component_type=ComponentType.SERVICE,
            name="windefend",
            display_name="Windows Defender Antivirus Service",
            publisher="Microsoft Corporation",
        )

        assessment = analyzer.analyze(component, {})

        # Should have critical security risk
        security_score = assessment.dimension_scores.get(RiskDimension.SECURITY_SURFACE)
        assert security_score is not None
        assert security_score.level == RiskLevel.CRITICAL

    def test_analyze_hardware_service(self) -> None:
        """Test analyzing a hardware-related service."""
        analyzer = RiskAnalyzer()

        component = Component(
            component_type=ComponentType.SERVICE,
            name="audiosrv",
            display_name="Windows Audio",
            publisher="Microsoft Corporation",
        )

        assessment = analyzer.analyze(component, {})

        # Should have elevated hardware risk
        hw_score = assessment.dimension_scores.get(RiskDimension.HARDWARE_FUNCTION)
        assert hw_score is not None
        assert hw_score.level >= RiskLevel.MEDIUM

    def test_analyze_ux_component(self) -> None:
        """Test analyzing a UX-related component."""
        analyzer = RiskAnalyzer()

        component = Component(
            component_type=ComponentType.SERVICE,
            name="themes",
            display_name="Themes",
            publisher="Microsoft Corporation",
        )

        assessment = analyzer.analyze(component, {})

        # Should affect UX dimension
        ux_score = assessment.dimension_scores.get(RiskDimension.USER_EXPERIENCE)
        assert ux_score is not None
        assert ux_score.level >= RiskLevel.LOW

    def test_analyze_with_dependents(self) -> None:
        """Test analyzing component with dependents."""
        analyzer = RiskAnalyzer()

        component = Component(
            component_type=ComponentType.SERVICE,
            name="some-service",
            display_name="Some Service",
            publisher="Test",
        )

        context = {
            "has_dependents": True,
            "dependents": ["service1", "service2", "rpcss"],  # includes boot-critical
        }

        assessment = analyzer.analyze(component, context)

        # Should have elevated risk due to boot-critical dependent
        assert assessment.overall_risk >= RiskLevel.HIGH

    def test_analyze_third_party_driver(self) -> None:
        """Test analyzing a third-party driver."""
        analyzer = RiskAnalyzer()

        component = Component(
            component_type=ComponentType.DRIVER,
            name="gpu-driver",
            display_name="Third Party GPU Driver",
            publisher="GPU Vendor Inc",
        )

        context = {"is_microsoft_signed": False}

        assessment = analyzer.analyze(component, context)

        # Third-party driver should have high hardware risk
        hw_score = assessment.dimension_scores.get(RiskDimension.HARDWARE_FUNCTION)
        assert hw_score is not None
        assert hw_score.level >= RiskLevel.HIGH

    def test_analyze_oem_component_requires_staging(self) -> None:
        """Test that OEM components require staging."""
        analyzer = RiskAnalyzer()

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="hp-app",
            display_name="HP Application",
            publisher="HP Inc.",
        )

        context = {"is_oem_preinstall": True}

        assessment = analyzer.analyze(component, context)

        assert assessment.requires_staging is True

    def test_composite_score_calculation(self) -> None:
        """Test composite score calculation."""
        analyzer = RiskAnalyzer()

        # Test with a mixed-risk component
        component = Component(
            component_type=ComponentType.SERVICE,
            name="mixed-risk",
            display_name="Mixed Risk Service",
            publisher="Test",
        )

        assessment = analyzer.analyze(component, {})

        # Composite score should be between 0 and 1
        assert 0.0 <= assessment.composite_score <= 1.0

    def test_safe_to_disable_threshold(self) -> None:
        """Test safe_to_disable based on risk level."""
        analyzer = RiskAnalyzer()

        # Low risk - should be safe to disable
        low_risk = Component(
            component_type=ComponentType.PROGRAM,
            name="optional-app",
            display_name="Optional App",
            publisher="Test",
        )

        low_assessment = analyzer.analyze(low_risk, {})
        assert low_assessment.safe_to_disable is True

        # Critical risk - should not be safe
        critical_risk = Component(
            component_type=ComponentType.SERVICE,
            name="lsass",
            display_name="Local Security Authority",
            publisher="Microsoft Corporation",
        )

        critical_assessment = analyzer.analyze(critical_risk, {})
        assert critical_assessment.safe_to_disable is False

    def test_safe_to_remove_threshold(self) -> None:
        """Test safe_to_remove is more restrictive than safe_to_disable."""
        analyzer = RiskAnalyzer()

        # Medium risk - safe to disable but not remove
        component = Component(
            component_type=ComponentType.SERVICE,
            name="some-helper",
            display_name="Some Helper Service",
            publisher="Test",
        )

        # Add context to push to medium risk
        context = {
            "has_dependents": True,
            "dependents": ["app1", "app2"],
        }

        assessment = analyzer.analyze(component, context)

        # safe_to_remove should be more restrictive
        if assessment.overall_risk == RiskLevel.MEDIUM:
            assert assessment.safe_to_disable is True
            assert assessment.safe_to_remove is False

    def test_recommendation_text(self) -> None:
        """Test that recommendations are generated."""
        analyzer = RiskAnalyzer()

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="test-app",
            display_name="Test App",
            publisher="Test",
        )

        assessment = analyzer.analyze(component, {})

        assert assessment.recommendation != ""

    def test_dimension_report(self) -> None:
        """Test generating a dimension report."""
        analyzer = RiskAnalyzer()

        component = Component(
            component_type=ComponentType.SERVICE,
            name="test-service",
            display_name="Test Service",
            publisher="Test",
        )

        assessment = analyzer.analyze(component, {})
        report = analyzer.get_dimension_report(assessment)

        assert "Risk Assessment Report" in report
        assert "BOOT_STABILITY" in report
        assert "HARDWARE_FUNCTION" in report
        assert "UPDATE_PIPELINE" in report
        assert "SECURITY_SURFACE" in report
        assert "USER_EXPERIENCE" in report
        assert "Safe to Disable:" in report
        assert "Recommendation:" in report

    def test_warnings_collection(self) -> None:
        """Test that warnings are collected for high-risk components."""
        analyzer = RiskAnalyzer()

        # Boot-critical service should generate warnings
        component = Component(
            component_type=ComponentType.SERVICE,
            name="plugplay",
            display_name="Plug and Play",
            publisher="Microsoft Corporation",
        )

        assessment = analyzer.analyze(component, {})

        # Should have at least one warning
        if assessment.overall_risk >= RiskLevel.HIGH:
            assert len(assessment.warnings) > 0


class TestCreateDefaultAnalyzer:
    """Tests for create_default_analyzer function."""

    def test_create_default_analyzer(self) -> None:
        """Test creating a default analyzer."""
        analyzer = create_default_analyzer()

        assert isinstance(analyzer, RiskAnalyzer)

        # Should have all dimension weights
        assert len(analyzer.dimension_weights) == 5


class TestPatternMatching:
    """Tests for pattern matching in risk analysis."""

    def test_boot_pattern_detection(self) -> None:
        """Test detection of boot-related patterns."""
        analyzer = RiskAnalyzer()

        component = Component(
            component_type=ComponentType.SERVICE,
            name="bootmgr-helper",
            display_name="Boot Manager Helper",
            publisher="Test",
        )

        assessment = analyzer.analyze(component, {})

        boot_score = assessment.dimension_scores.get(RiskDimension.BOOT_STABILITY)
        assert boot_score is not None
        assert boot_score.level >= RiskLevel.HIGH

    def test_update_pattern_detection(self) -> None:
        """Test detection of update-related patterns."""
        analyzer = RiskAnalyzer()

        component = Component(
            component_type=ComponentType.SERVICE,
            name="windows-update-helper",
            display_name="Windows Update Helper",
            publisher="Test",
        )

        assessment = analyzer.analyze(component, {})

        update_score = assessment.dimension_scores.get(RiskDimension.UPDATE_PIPELINE)
        assert update_score is not None
        assert update_score.level >= RiskLevel.MEDIUM

    def test_security_pattern_detection(self) -> None:
        """Test detection of security-related patterns."""
        analyzer = RiskAnalyzer()

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="firewall-config",
            display_name="Firewall Configuration",
            publisher="Test",
        )

        assessment = analyzer.analyze(component, {})

        security_score = assessment.dimension_scores.get(RiskDimension.SECURITY_SURFACE)
        assert security_score is not None
        assert security_score.level >= RiskLevel.LOW
