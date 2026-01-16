"""Risk Analyzer - Multi-dimensional risk assessment for components.

This module implements the 5-dimension risk assessment system:
1. Boot Stability - Impact on system boot process
2. Hardware Function - Impact on hardware/driver functionality
3. Update Pipeline - Impact on Windows Update/security patches
4. Security Surface - Security implications of modification
5. User Experience - Impact on user-facing functionality
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Callable
import logging
import re

from src.core.models import Component, ComponentType, RiskLevel, Classification

logger = logging.getLogger("debloatr.analysis.risk")


class RiskDimension(Enum):
    """The five risk assessment dimensions."""

    BOOT_STABILITY = "boot_stability"
    HARDWARE_FUNCTION = "hardware_function"
    UPDATE_PIPELINE = "update_pipeline"
    SECURITY_SURFACE = "security_surface"
    USER_EXPERIENCE = "user_experience"


@dataclass
class DimensionScore:
    """Score for a single risk dimension.

    Attributes:
        dimension: The risk dimension
        level: Risk level for this dimension
        confidence: Confidence in this assessment (0.0-1.0)
        factors: List of factors that contributed to this score
        explanation: Human-readable explanation
    """

    dimension: RiskDimension
    level: RiskLevel
    confidence: float = 1.0
    factors: list[str] = field(default_factory=list)
    explanation: str = ""


@dataclass
class RiskAssessment:
    """Complete risk assessment for a component.

    Attributes:
        component_id: ID of the assessed component
        dimension_scores: Scores for each dimension
        overall_risk: Highest risk level across all dimensions
        composite_score: Weighted composite score (0.0-1.0)
        safe_to_disable: Whether it's safe to disable this component
        safe_to_remove: Whether it's safe to remove this component
        requires_staging: Whether changes should be staged (delayed)
        warnings: List of specific warnings
        recommendation: Overall recommendation text
    """

    component_id: str
    dimension_scores: dict[RiskDimension, DimensionScore] = field(default_factory=dict)
    overall_risk: RiskLevel = RiskLevel.NONE
    composite_score: float = 0.0
    safe_to_disable: bool = True
    safe_to_remove: bool = True
    requires_staging: bool = False
    warnings: list[str] = field(default_factory=list)
    recommendation: str = ""


# Boot-critical component patterns
BOOT_CRITICAL_PATTERNS = [
    r".*boot.*",
    r".*ntoskrnl.*",
    r".*winload.*",
    r".*bootmgr.*",
    r".*hal\.dll.*",
    r".*ntdll.*",
    r".*kernel32.*",
    r".*csrss.*",
    r".*smss.*",
    r".*wininit.*",
    r".*lsass.*",
    r".*services\.exe.*",
]

BOOT_CRITICAL_SERVICES = [
    "rpcss",
    "lsm",
    "dcomlaunch",
    "plugplay",
    "eventlog",
    "power",
    "profils",
    "samss",
    "schedule",
    "seclogon",
    "sens",
    "wuauserv",
    "bfe",
    "mpssvc",
]

# Hardware-related patterns
HARDWARE_PATTERNS = [
    r".*driver.*",
    r".*hid.*",
    r".*usb.*",
    r".*pci.*",
    r".*acpi.*",
    r".*display.*",
    r".*audio.*",
    r".*network.*adapter.*",
    r".*bluetooth.*",
    r".*storage.*",
    r".*disk.*",
    r".*nvme.*",
    r".*sata.*",
]

HARDWARE_SERVICES = [
    "hidserv",
    "usbhub",
    "disk",
    "partmgr",
    "volmgr",
    "mountmgr",
    "audiosrv",
    "audioendpointbuilder",
    "wudfrd",
    "bthserv",
    "netman",
]

# Update/security patterns
UPDATE_PATTERNS = [
    r".*update.*",
    r".*windows.*update.*",
    r".*wuauserv.*",
    r".*bits.*",
    r".*cryptsvc.*",
    r".*trustedinstaller.*",
    r".*msiserver.*",
]

UPDATE_SERVICES = [
    "wuauserv",
    "bits",
    "cryptsvc",
    "trustedinstaller",
    "msiserver",
    "appidsvc",
]

# Security-related patterns
SECURITY_PATTERNS = [
    r".*defender.*",
    r".*antivirus.*",
    r".*firewall.*",
    r".*security.*",
    r".*malware.*",
    r".*protection.*",
    r".*smartscreen.*",
    r".*uac.*",
]

SECURITY_SERVICES = [
    "windefend",
    "wscsvc",
    "seclogon",
    "mpssvc",
    "bfe",
    "eventlog",
    "wersvc",
    "cryptsvc",
]

# User experience patterns
UX_CRITICAL_PATTERNS = [
    r".*explorer.*",
    r".*shell.*",
    r".*dwm.*",
    r".*theme.*",
    r".*startmenu.*",
    r".*taskbar.*",
    r".*notification.*",
    r".*search.*",
]

UX_SERVICES = [
    "themes",
    "uxsms",
    "fontcache",
    "spooler",
    "shellhwdetection",
    "stisvc",
    "wlansvc",
]


def _matches_patterns(value: str, patterns: list[str]) -> bool:
    """Check if value matches any of the patterns."""
    value_lower = value.lower()
    for pattern in patterns:
        if re.match(pattern, value_lower, re.IGNORECASE):
            return True
    return False


def _is_in_list(value: str, items: list[str]) -> bool:
    """Check if value is in the list (case-insensitive)."""
    return value.lower() in [i.lower() for i in items]


class RiskAnalyzer:
    """Analyzer for assessing component modification risks.

    Evaluates components across 5 risk dimensions to determine
    the safety of disabling or removing them.

    Example:
        analyzer = RiskAnalyzer()
        assessment = analyzer.analyze(component, context)
        if assessment.safe_to_disable:
            print("Safe to disable")
        print(f"Overall risk: {assessment.overall_risk}")
    """

    def __init__(
        self,
        dimension_weights: Optional[dict[RiskDimension, float]] = None,
    ) -> None:
        """Initialize the risk analyzer.

        Args:
            dimension_weights: Custom weights for each dimension (must sum to 1.0)
        """
        self.dimension_weights = dimension_weights or {
            RiskDimension.BOOT_STABILITY: 0.30,
            RiskDimension.HARDWARE_FUNCTION: 0.25,
            RiskDimension.UPDATE_PIPELINE: 0.20,
            RiskDimension.SECURITY_SURFACE: 0.15,
            RiskDimension.USER_EXPERIENCE: 0.10,
        }

        # Ensure weights sum to 1.0
        total = sum(self.dimension_weights.values())
        if abs(total - 1.0) > 0.001:
            logger.warning(f"Dimension weights sum to {total}, normalizing")
            for dim in self.dimension_weights:
                self.dimension_weights[dim] /= total

    def analyze(
        self,
        component: Component,
        context: Optional[dict[str, Any]] = None,
    ) -> RiskAssessment:
        """Analyze risk for a component.

        Args:
            component: Component to analyze
            context: Additional context (dependencies, network access, etc.)

        Returns:
            RiskAssessment with detailed risk information
        """
        context = context or {}

        # Analyze each dimension
        scores: dict[RiskDimension, DimensionScore] = {}

        scores[RiskDimension.BOOT_STABILITY] = self._analyze_boot_stability(
            component, context
        )
        scores[RiskDimension.HARDWARE_FUNCTION] = self._analyze_hardware_function(
            component, context
        )
        scores[RiskDimension.UPDATE_PIPELINE] = self._analyze_update_pipeline(
            component, context
        )
        scores[RiskDimension.SECURITY_SURFACE] = self._analyze_security_surface(
            component, context
        )
        scores[RiskDimension.USER_EXPERIENCE] = self._analyze_user_experience(
            component, context
        )

        # Calculate overall risk (highest dimension wins)
        overall_risk = max(s.level for s in scores.values())

        # Calculate composite score
        composite = self._calculate_composite_score(scores)

        # Determine safety
        safe_to_disable = overall_risk <= RiskLevel.MEDIUM
        safe_to_remove = overall_risk <= RiskLevel.LOW

        # Check if staging is required
        requires_staging = self._requires_staging(component, context, overall_risk)

        # Collect warnings
        warnings = self._collect_warnings(scores, component, context)

        # Build recommendation
        recommendation = self._build_recommendation(
            component, overall_risk, safe_to_disable, safe_to_remove
        )

        return RiskAssessment(
            component_id=component.id,
            dimension_scores=scores,
            overall_risk=overall_risk,
            composite_score=composite,
            safe_to_disable=safe_to_disable,
            safe_to_remove=safe_to_remove,
            requires_staging=requires_staging,
            warnings=warnings,
            recommendation=recommendation,
        )

    def _analyze_boot_stability(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> DimensionScore:
        """Analyze impact on system boot process.

        Args:
            component: Component to analyze
            context: Additional context

        Returns:
            DimensionScore for boot stability
        """
        factors: list[str] = []
        level = RiskLevel.NONE

        name = component.name or ""
        display_name = component.display_name or ""
        path_str = str(component.install_path) if component.install_path else ""

        # Check boot-critical patterns
        if _matches_patterns(name, BOOT_CRITICAL_PATTERNS):
            factors.append("Matches boot-critical name pattern")
            level = max(level, RiskLevel.CRITICAL)

        if _matches_patterns(path_str, BOOT_CRITICAL_PATTERNS):
            factors.append("Located in boot-critical path")
            level = max(level, RiskLevel.CRITICAL)

        # Check boot-critical services
        if component.component_type == ComponentType.SERVICE:
            if _is_in_list(name, BOOT_CRITICAL_SERVICES):
                factors.append("Is a boot-critical service")
                level = max(level, RiskLevel.CRITICAL)

        # Check dependencies
        dependents = context.get("dependents", [])
        if dependents:
            boot_dependent = any(
                _is_in_list(d, BOOT_CRITICAL_SERVICES) for d in dependents
            )
            if boot_dependent:
                factors.append("Has boot-critical dependents")
                level = max(level, RiskLevel.HIGH)

        # Check if in boot chain
        if context.get("is_boot_start", False):
            factors.append("Starts during boot")
            level = max(level, RiskLevel.HIGH)

        # Check driver type
        if component.component_type == ComponentType.DRIVER:
            driver_type = context.get("driver_type", "")
            if driver_type.lower() in ["boot", "system"]:
                factors.append(f"Is a {driver_type} driver")
                level = max(level, RiskLevel.CRITICAL)

        explanation = (
            f"Boot stability risk: {level.name}. "
            f"Factors: {', '.join(factors) if factors else 'None detected'}"
        )

        return DimensionScore(
            dimension=RiskDimension.BOOT_STABILITY,
            level=level,
            factors=factors,
            explanation=explanation,
        )

    def _analyze_hardware_function(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> DimensionScore:
        """Analyze impact on hardware functionality.

        Args:
            component: Component to analyze
            context: Additional context

        Returns:
            DimensionScore for hardware function
        """
        factors: list[str] = []
        level = RiskLevel.NONE

        name = component.name or ""
        display_name = component.display_name or ""

        # Drivers are inherently hardware-related
        if component.component_type == ComponentType.DRIVER:
            factors.append("Is a system driver")
            level = max(level, RiskLevel.MEDIUM)

            # Check if Microsoft-signed
            if not context.get("is_microsoft_signed", False):
                factors.append("Third-party driver")
                level = max(level, RiskLevel.HIGH)

        # Check hardware patterns
        if _matches_patterns(name, HARDWARE_PATTERNS):
            factors.append("Matches hardware-related pattern")
            level = max(level, RiskLevel.MEDIUM)

        if _matches_patterns(display_name, HARDWARE_PATTERNS):
            factors.append("Display name suggests hardware function")
            level = max(level, RiskLevel.LOW)

        # Check hardware services
        if component.component_type == ComponentType.SERVICE:
            if _is_in_list(name, HARDWARE_SERVICES):
                factors.append("Is a hardware-related service")
                level = max(level, RiskLevel.HIGH)

        # Check associated hardware
        hardware_ids = context.get("associated_hardware", [])
        if hardware_ids:
            factors.append(f"Associated with {len(hardware_ids)} hardware device(s)")
            level = max(level, RiskLevel.HIGH)

        explanation = (
            f"Hardware function risk: {level.name}. "
            f"Factors: {', '.join(factors) if factors else 'None detected'}"
        )

        return DimensionScore(
            dimension=RiskDimension.HARDWARE_FUNCTION,
            level=level,
            factors=factors,
            explanation=explanation,
        )

    def _analyze_update_pipeline(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> DimensionScore:
        """Analyze impact on Windows Update and patching.

        Args:
            component: Component to analyze
            context: Additional context

        Returns:
            DimensionScore for update pipeline
        """
        factors: list[str] = []
        level = RiskLevel.NONE

        name = component.name or ""
        display_name = component.display_name or ""

        # Check update patterns
        if _matches_patterns(name, UPDATE_PATTERNS):
            factors.append("Matches update-related pattern")
            level = max(level, RiskLevel.HIGH)

        if _matches_patterns(display_name, UPDATE_PATTERNS):
            factors.append("Display name suggests update function")
            level = max(level, RiskLevel.MEDIUM)

        # Check update services
        if component.component_type == ComponentType.SERVICE:
            if _is_in_list(name, UPDATE_SERVICES):
                factors.append("Is a Windows Update service")
                level = max(level, RiskLevel.CRITICAL)

        # Check if component is update-related
        if context.get("is_update_component", False):
            factors.append("Identified as update component")
            level = max(level, RiskLevel.HIGH)

        # Check if component would be restored by updates
        if context.get("restored_by_updates", False):
            factors.append("Would be restored by Windows Update")
            level = max(level, RiskLevel.LOW)  # Lower risk since it's reversible

        explanation = (
            f"Update pipeline risk: {level.name}. "
            f"Factors: {', '.join(factors) if factors else 'None detected'}"
        )

        return DimensionScore(
            dimension=RiskDimension.UPDATE_PIPELINE,
            level=level,
            factors=factors,
            explanation=explanation,
        )

    def _analyze_security_surface(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> DimensionScore:
        """Analyze security implications of modification.

        Args:
            component: Component to analyze
            context: Additional context

        Returns:
            DimensionScore for security surface
        """
        factors: list[str] = []
        level = RiskLevel.NONE

        name = component.name or ""
        display_name = component.display_name or ""

        # Check security patterns
        if _matches_patterns(name, SECURITY_PATTERNS):
            factors.append("Matches security-related pattern")
            level = max(level, RiskLevel.HIGH)

        if _matches_patterns(display_name, SECURITY_PATTERNS):
            factors.append("Display name suggests security function")
            level = max(level, RiskLevel.MEDIUM)

        # Check security services
        if component.component_type == ComponentType.SERVICE:
            if _is_in_list(name, SECURITY_SERVICES):
                factors.append("Is a security service")
                level = max(level, RiskLevel.CRITICAL)

        # Check if it's Windows Defender or other AV
        publisher = (component.publisher or "").lower()
        if "microsoft" in publisher and "defender" in name.lower():
            factors.append("Is Windows Defender component")
            level = max(level, RiskLevel.CRITICAL)

        # Check if it affects firewall
        if context.get("affects_firewall", False):
            factors.append("Affects Windows Firewall")
            level = max(level, RiskLevel.HIGH)

        # Check if it handles credentials
        if context.get("handles_credentials", False):
            factors.append("Handles user credentials")
            level = max(level, RiskLevel.CRITICAL)

        explanation = (
            f"Security surface risk: {level.name}. "
            f"Factors: {', '.join(factors) if factors else 'None detected'}"
        )

        return DimensionScore(
            dimension=RiskDimension.SECURITY_SURFACE,
            level=level,
            factors=factors,
            explanation=explanation,
        )

    def _analyze_user_experience(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> DimensionScore:
        """Analyze impact on user-facing functionality.

        Args:
            component: Component to analyze
            context: Additional context

        Returns:
            DimensionScore for user experience
        """
        factors: list[str] = []
        level = RiskLevel.NONE

        name = component.name or ""
        display_name = component.display_name or ""

        # Check UX patterns
        if _matches_patterns(name, UX_CRITICAL_PATTERNS):
            factors.append("Matches UX-critical pattern")
            level = max(level, RiskLevel.HIGH)

        if _matches_patterns(display_name, UX_CRITICAL_PATTERNS):
            factors.append("Display name suggests UX function")
            level = max(level, RiskLevel.MEDIUM)

        # Check UX services
        if component.component_type == ComponentType.SERVICE:
            if _is_in_list(name, UX_SERVICES):
                factors.append("Is a UX-related service")
                level = max(level, RiskLevel.MEDIUM)

        # Check if it has visible UI
        if context.get("has_visible_ui", False):
            factors.append("Has visible user interface")
            level = max(level, RiskLevel.LOW)

        # Check if it's user-requested (not preinstalled)
        if context.get("user_installed", False):
            factors.append("User-installed application")
            level = max(level, RiskLevel.LOW)

        # Check if it's essential for daily use
        if context.get("is_essential_for_user", False):
            factors.append("Essential for user's workflow")
            level = max(level, RiskLevel.MEDIUM)

        explanation = (
            f"User experience risk: {level.name}. "
            f"Factors: {', '.join(factors) if factors else 'None detected'}"
        )

        return DimensionScore(
            dimension=RiskDimension.USER_EXPERIENCE,
            level=level,
            factors=factors,
            explanation=explanation,
        )

    def _calculate_composite_score(
        self,
        scores: dict[RiskDimension, DimensionScore],
    ) -> float:
        """Calculate weighted composite risk score.

        Args:
            scores: Dictionary of dimension scores

        Returns:
            Composite score between 0.0 and 1.0
        """
        total = 0.0
        for dimension, score in scores.items():
            weight = self.dimension_weights.get(dimension, 0.0)
            # Convert RiskLevel to numeric value (0-4)
            level_value = score.level.value / RiskLevel.CRITICAL.value
            total += weight * level_value

        return min(total, 1.0)

    def _requires_staging(
        self,
        component: Component,
        context: dict[str, Any],
        risk_level: RiskLevel,
    ) -> bool:
        """Determine if changes should be staged.

        Args:
            component: Component being modified
            context: Additional context
            risk_level: Overall risk level

        Returns:
            True if staging is required
        """
        # High-risk changes should be staged
        if risk_level >= RiskLevel.HIGH:
            return True

        # OEM tools require staging
        if context.get("is_oem_preinstall", False):
            return True

        # Drivers should be staged
        if component.component_type == ComponentType.DRIVER:
            return True

        return False

    def _collect_warnings(
        self,
        scores: dict[RiskDimension, DimensionScore],
        component: Component,
        context: dict[str, Any],
    ) -> list[str]:
        """Collect warnings from all dimensions.

        Args:
            scores: Dimension scores
            component: Component being analyzed
            context: Additional context

        Returns:
            List of warning messages
        """
        warnings: list[str] = []

        # Collect critical and high-risk warnings
        for dimension, score in scores.items():
            if score.level >= RiskLevel.HIGH:
                warnings.append(
                    f"{dimension.value}: {score.level.name} risk - "
                    f"{', '.join(score.factors)}"
                )

        # Add specific warnings
        if context.get("has_dependents", False):
            dependents = context.get("dependents", [])
            warnings.append(
                f"Has {len(dependents)} dependent components that may be affected"
            )

        if component.component_type == ComponentType.DRIVER:
            warnings.append("Modifying drivers may cause hardware malfunction")

        if scores.get(RiskDimension.BOOT_STABILITY, DimensionScore(
            dimension=RiskDimension.BOOT_STABILITY,
            level=RiskLevel.NONE
        )).level >= RiskLevel.HIGH:
            warnings.append("Changes may prevent system from booting properly")

        return warnings

    def _build_recommendation(
        self,
        component: Component,
        risk_level: RiskLevel,
        safe_to_disable: bool,
        safe_to_remove: bool,
    ) -> str:
        """Build recommendation text.

        Args:
            component: Component being analyzed
            risk_level: Overall risk level
            safe_to_disable: Whether disabling is safe
            safe_to_remove: Whether removal is safe

        Returns:
            Recommendation string
        """
        if risk_level == RiskLevel.CRITICAL:
            return (
                "DO NOT MODIFY: This component is critical for system operation. "
                "Modifying it may render the system unbootable or unstable."
            )
        elif risk_level == RiskLevel.HIGH:
            return (
                "CAUTION: High-risk component. Disable only if you understand "
                "the consequences. Create a system restore point first. "
                "Removal is not recommended."
            )
        elif risk_level == RiskLevel.MEDIUM:
            return (
                "MODERATE RISK: Can be disabled with some risk. "
                "Monitor system stability after changes. "
                "Removal may cause issues for dependent components."
            )
        elif risk_level == RiskLevel.LOW:
            return (
                "LOW RISK: Safe to disable. "
                "Removal is generally safe but consider keeping "
                "if the component provides any useful functionality."
            )
        else:
            return (
                "SAFE: This component can be safely disabled or removed. "
                "No significant impact on system stability or functionality."
            )

    def get_dimension_report(
        self,
        assessment: RiskAssessment,
    ) -> str:
        """Generate a detailed report for an assessment.

        Args:
            assessment: RiskAssessment to report on

        Returns:
            Formatted report string
        """
        lines = [
            f"Risk Assessment Report",
            f"=" * 50,
            f"Component ID: {assessment.component_id}",
            f"Overall Risk: {assessment.overall_risk.name}",
            f"Composite Score: {assessment.composite_score:.1%}",
            f"",
            f"Dimension Analysis:",
            f"-" * 30,
        ]

        for dimension, score in assessment.dimension_scores.items():
            lines.append(f"\n{dimension.value.upper()}:")
            lines.append(f"  Risk Level: {score.level.name}")
            lines.append(f"  Factors: {', '.join(score.factors) if score.factors else 'None'}")
            lines.append(f"  {score.explanation}")

        lines.append(f"\n" + "-" * 30)
        lines.append(f"Safe to Disable: {'Yes' if assessment.safe_to_disable else 'No'}")
        lines.append(f"Safe to Remove: {'Yes' if assessment.safe_to_remove else 'No'}")
        lines.append(f"Requires Staging: {'Yes' if assessment.requires_staging else 'No'}")

        if assessment.warnings:
            lines.append(f"\nWarnings:")
            for warning in assessment.warnings:
                lines.append(f"  - {warning}")

        lines.append(f"\nRecommendation:")
        lines.append(f"  {assessment.recommendation}")

        return "\n".join(lines)


def create_default_analyzer() -> RiskAnalyzer:
    """Create a risk analyzer with default settings.

    Returns:
        Configured RiskAnalyzer instance
    """
    return RiskAnalyzer()
