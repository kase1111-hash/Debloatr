"""Heuristics Engine - Confidence-based bloatware detection.

This module implements heuristic rules for classifying components
that don't match any signature in the database.
"""

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.core.models import Classification, Component, ComponentType

logger = logging.getLogger("debloatr.classification.heuristics")


class HeuristicCategory(Enum):
    """Categories of heuristic rules."""

    AUTOSTART = "autostart"
    NETWORK = "network"
    TELEMETRY = "telemetry"
    BEHAVIOR = "behavior"
    BUNDLING = "bundling"
    INJECTION = "injection"
    RESOURCE = "resource"


@dataclass
class HeuristicRule:
    """A heuristic rule for bloatware detection.

    Attributes:
        rule_id: Unique identifier for the rule
        name: Human-readable rule name
        description: Explanation of what this rule detects
        category: Category of the rule
        weight: Weight for scoring (0.0-1.0)
        check: Function that evaluates the component
    """

    rule_id: str
    name: str
    description: str
    category: HeuristicCategory
    weight: float
    check: Callable[[Component, dict[str, Any]], bool]


@dataclass
class HeuristicResult:
    """Result of running heuristics on a component.

    Attributes:
        component_id: ID of the analyzed component
        triggered_rules: List of rule IDs that triggered
        scores: Dictionary of rule_id -> score contribution
        total_score: Combined bloat score (0.0-1.0)
        suggested_classification: Suggested classification based on score
        explanation: Human-readable explanation
    """

    component_id: str
    triggered_rules: list[str] = field(default_factory=list)
    scores: dict[str, float] = field(default_factory=dict)
    total_score: float = 0.0
    suggested_classification: Classification = Classification.UNKNOWN
    explanation: str = ""


# Telemetry-related patterns
TELEMETRY_NAME_PATTERNS = [
    r".*telemetry.*",
    r".*diagnostic.*",
    r".*ceip.*",
    r".*customer.*experience.*",
    r".*usage.*report.*",
    r".*analytics.*",
    r".*metric.*",
    r".*tracking.*",
    r".*beacon.*",
]

TELEMETRY_PATH_PATTERNS = [
    r".*\\telemetry\\.*",
    r".*\\diagnostics\\.*",
    r".*\\analytics\\.*",
    r".*\\metrics\\.*",
]

# Update/self-healing patterns
SELF_HEALING_PATTERNS = [
    r".*update.*service.*",
    r".*updater.*",
    r".*helper.*service.*",
    r".*watchdog.*",
    r".*monitor.*service.*",
    r".*scheduler.*",
]

# Overlay/injection patterns
INJECTION_PATTERNS = [
    r".*overlay.*",
    r".*hook.*",
    r".*inject.*",
    r".*gameoverlay.*",
    r".*reshade.*",
]

# Ad/promotional patterns
AD_PATTERNS = [
    r".*promo.*",
    r".*offer.*",
    r".*trial.*",
    r".*recommend.*",
    r".*suggestion.*",
]

# Known resource-heavy prefixes
RESOURCE_HEAVY_PUBLISHERS = [
    "adobe",
    "autodesk",
    "norton",
    "mcafee",
    "avast",
    "avg",
]


def _check_autostart_no_ui(component: Component, context: dict[str, Any]) -> bool:
    """Check if component autostarts but has no visible UI.

    Components that run automatically but provide no user-facing interface
    are often telemetry or background services that could be bloatware.
    """
    has_autostart = context.get("has_autostart", False)
    has_visible_ui = context.get("has_visible_ui", True)

    # Services and tasks typically don't have UI
    if component.component_type in [ComponentType.SERVICE, ComponentType.TASK]:
        has_visible_ui = context.get("has_visible_ui", False)

    return has_autostart and not has_visible_ui


def _check_network_no_value(component: Component, context: dict[str, Any]) -> bool:
    """Check if component has network access without providing network features.

    Components that phone home without providing network-related functionality
    to the user are suspicious.
    """
    has_network = context.get("has_network_access", False)
    provides_network = context.get("provides_network_feature", False)

    return has_network and not provides_network


def _check_self_healing(component: Component, context: dict[str, Any]) -> bool:
    """Check if component exhibits self-healing behavior.

    Components that reinstall or re-enable themselves after removal
    are aggressive bloatware.
    """
    reinstalls = context.get("reinstalls_after_removal", False)
    has_watchdog = context.get("has_watchdog_process", False)

    # Also check name patterns
    name = (component.name or "").lower()
    display_name = (component.display_name or "").lower()

    for pattern in SELF_HEALING_PATTERNS:
        if re.match(pattern, name, re.IGNORECASE) or re.match(pattern, display_name, re.IGNORECASE):
            return True

    return reinstalls or has_watchdog


def _check_account_required(component: Component, context: dict[str, Any]) -> bool:
    """Check if component requires login but is local-only.

    Apps that require account creation but don't provide cloud features
    are often collecting data unnecessarily.
    """
    requires_login = context.get("requires_login", False)
    is_local_only = context.get("is_local_only", True)

    return requires_login and is_local_only


def _check_bundled_unrelated(component: Component, context: dict[str, Any]) -> bool:
    """Check if component was bundled with unrelated software.

    Software that gets installed alongside unrelated applications
    is often unwanted.
    """
    is_bundled = context.get("is_bundled", False)
    related_to_parent = context.get("related_to_parent", True)

    return is_bundled and not related_to_parent


def _check_telemetry_pattern(component: Component, context: dict[str, Any]) -> bool:
    """Check if component matches telemetry behavior patterns.

    Uses name and path pattern matching to identify telemetry components.
    """
    name = (component.name or "").lower()
    display_name = (component.display_name or "").lower()
    path_str = str(component.install_path).lower() if component.install_path else ""

    # Check name patterns
    for pattern in TELEMETRY_NAME_PATTERNS:
        if re.match(pattern, name, re.IGNORECASE):
            return True
        if re.match(pattern, display_name, re.IGNORECASE):
            return True

    # Check path patterns
    for pattern in TELEMETRY_PATH_PATTERNS:
        if re.match(pattern, path_str, re.IGNORECASE):
            return True

    # Check explicit telemetry flag
    if context.get("is_telemetry", False):
        return True

    return False


def _check_overlay_injector(component: Component, context: dict[str, Any]) -> bool:
    """Check if component injects into other processes.

    Overlay software and DLL injectors can cause system instability
    and are often unwanted.
    """
    injects = context.get("injects_into_processes", False)

    # Check name patterns
    name = (component.name or "").lower()
    display_name = (component.display_name or "").lower()

    for pattern in INJECTION_PATTERNS:
        if re.match(pattern, name, re.IGNORECASE):
            return True
        if re.match(pattern, display_name, re.IGNORECASE):
            return True

    return injects


def _check_high_resource_usage(component: Component, context: dict[str, Any]) -> bool:
    """Check if component uses excessive system resources.

    Components that consume significant CPU, memory, or disk
    without user benefit are problematic.
    """
    cpu_percent = context.get("cpu_usage_percent", 0.0)
    memory_mb = context.get("memory_usage_mb", 0)
    disk_mb = context.get("disk_usage_mb", 0)

    # Thresholds for "high" resource usage
    high_cpu = cpu_percent > 5.0  # >5% sustained CPU
    high_memory = memory_mb > 500  # >500MB RAM
    high_disk = disk_mb > 1000  # >1GB disk

    return high_cpu or high_memory or high_disk


def _check_startup_persistence(component: Component, context: dict[str, Any]) -> bool:
    """Check if component has multiple persistence mechanisms.

    Components that use multiple methods to ensure they run
    (service + scheduled task + startup entry) are aggressive.
    """
    persistence_count = context.get("persistence_mechanisms", 0)
    return persistence_count >= 2


def _check_promotional_content(component: Component, context: dict[str, Any]) -> bool:
    """Check if component appears to show ads or promotions.

    Software that displays promotional content is often bloatware.
    """
    shows_ads = context.get("shows_advertisements", False)

    # Check name patterns
    name = (component.name or "").lower()
    display_name = (component.display_name or "").lower()

    for pattern in AD_PATTERNS:
        if re.match(pattern, name, re.IGNORECASE):
            return True
        if re.match(pattern, display_name, re.IGNORECASE):
            return True

    return shows_ads


def _check_oem_preinstall(component: Component, context: dict[str, Any]) -> bool:
    """Check if component is OEM preinstalled software.

    OEM software is often bloatware that provides duplicate
    functionality or upsells services.
    """
    is_oem = context.get("is_oem_preinstall", False)

    # Check for common OEM publisher patterns
    publisher = (component.publisher or "").lower()
    oem_publishers = [
        "hewlett-packard",
        "hp inc",
        "hp ",
        "dell",
        "alienware",
        "lenovo",
        "thinkpad",
        "asus",
        "acer",
        "msi",
        "samsung",
        "toshiba",
        "sony",
    ]

    for oem in oem_publishers:
        if oem in publisher:
            return True

    return is_oem


def _check_unsigned_or_unknown(component: Component, context: dict[str, Any]) -> bool:
    """Check if component is unsigned or from unknown publisher.

    Unsigned software or software with no clear publisher
    is more likely to be unwanted.
    """
    is_signed = context.get("is_signed", True)
    publisher = component.publisher or ""

    return not is_signed or publisher.lower() in ["", "unknown", "n/a"]


# Define all heuristic rules
HEURISTIC_RULES: dict[str, HeuristicRule] = {
    "AUTOSTART_NO_UI": HeuristicRule(
        rule_id="AUTOSTART_NO_UI",
        name="Autostart without UI",
        description="Component starts automatically but has no visible user interface",
        category=HeuristicCategory.AUTOSTART,
        weight=0.3,
        check=_check_autostart_no_ui,
    ),
    "NETWORK_NO_VALUE": HeuristicRule(
        rule_id="NETWORK_NO_VALUE",
        name="Network access without network features",
        description="Component accesses the network but doesn't provide network functionality",
        category=HeuristicCategory.NETWORK,
        weight=0.4,
        check=_check_network_no_value,
    ),
    "SELF_HEALING": HeuristicRule(
        rule_id="SELF_HEALING",
        name="Self-healing behavior",
        description="Component reinstalls or re-enables itself after removal",
        category=HeuristicCategory.BEHAVIOR,
        weight=0.5,
        check=_check_self_healing,
    ),
    "ACCOUNT_REQUIRED": HeuristicRule(
        rule_id="ACCOUNT_REQUIRED",
        name="Account required for local app",
        description="Component requires login but only provides local functionality",
        category=HeuristicCategory.BEHAVIOR,
        weight=0.3,
        check=_check_account_required,
    ),
    "BUNDLED_UNRELATED": HeuristicRule(
        rule_id="BUNDLED_UNRELATED",
        name="Bundled unrelated software",
        description="Component was installed alongside unrelated software",
        category=HeuristicCategory.BUNDLING,
        weight=0.4,
        check=_check_bundled_unrelated,
    ),
    "TELEMETRY_PATTERN": HeuristicRule(
        rule_id="TELEMETRY_PATTERN",
        name="Telemetry behavior pattern",
        description="Component matches known telemetry behavior patterns",
        category=HeuristicCategory.TELEMETRY,
        weight=0.6,
        check=_check_telemetry_pattern,
    ),
    "OVERLAY_INJECTOR": HeuristicRule(
        rule_id="OVERLAY_INJECTOR",
        name="Overlay/injection pattern",
        description="Component injects into other processes",
        category=HeuristicCategory.INJECTION,
        weight=0.5,
        check=_check_overlay_injector,
    ),
    "HIGH_RESOURCE_USAGE": HeuristicRule(
        rule_id="HIGH_RESOURCE_USAGE",
        name="High resource usage",
        description="Component uses excessive CPU, memory, or disk resources",
        category=HeuristicCategory.RESOURCE,
        weight=0.35,
        check=_check_high_resource_usage,
    ),
    "STARTUP_PERSISTENCE": HeuristicRule(
        rule_id="STARTUP_PERSISTENCE",
        name="Multiple persistence mechanisms",
        description="Component uses multiple methods to ensure it runs at startup",
        category=HeuristicCategory.AUTOSTART,
        weight=0.45,
        check=_check_startup_persistence,
    ),
    "PROMOTIONAL_CONTENT": HeuristicRule(
        rule_id="PROMOTIONAL_CONTENT",
        name="Promotional/advertising content",
        description="Component displays advertisements or promotional content",
        category=HeuristicCategory.BEHAVIOR,
        weight=0.55,
        check=_check_promotional_content,
    ),
    "OEM_PREINSTALL": HeuristicRule(
        rule_id="OEM_PREINSTALL",
        name="OEM preinstalled software",
        description="Component is preinstalled by the device manufacturer",
        category=HeuristicCategory.BUNDLING,
        weight=0.25,
        check=_check_oem_preinstall,
    ),
    "UNSIGNED_UNKNOWN": HeuristicRule(
        rule_id="UNSIGNED_UNKNOWN",
        name="Unsigned or unknown publisher",
        description="Component is unsigned or has no clear publisher",
        category=HeuristicCategory.BEHAVIOR,
        weight=0.2,
        check=_check_unsigned_or_unknown,
    ),
}


class HeuristicsEngine:
    """Engine for applying heuristic rules to classify components.

    Uses weighted scoring to determine bloatware likelihood and
    suggest classifications for components without signature matches.

    Example:
        engine = HeuristicsEngine()
        result = engine.analyze(component, context)
        print(f"Bloat score: {result.total_score}")
        print(f"Suggested: {result.suggested_classification}")
    """

    def __init__(
        self,
        rules: dict[str, HeuristicRule] | None = None,
        threshold_bloat: float = 0.4,
        threshold_aggressive: float = 0.7,
    ) -> None:
        """Initialize the heuristics engine.

        Args:
            rules: Custom rules to use (defaults to HEURISTIC_RULES)
            threshold_bloat: Score threshold for BLOAT classification
            threshold_aggressive: Score threshold for AGGRESSIVE classification
        """
        self.rules = rules or HEURISTIC_RULES.copy()
        self.threshold_bloat = threshold_bloat
        self.threshold_aggressive = threshold_aggressive

    def analyze(
        self,
        component: Component,
        context: dict[str, Any] | None = None,
    ) -> HeuristicResult:
        """Analyze a component using heuristic rules.

        Args:
            component: Component to analyze
            context: Additional context about the component
                (e.g., has_network_access, cpu_usage_percent, etc.)

        Returns:
            HeuristicResult with scores and suggested classification
        """
        context = context or {}
        triggered_rules: list[str] = []
        scores: dict[str, float] = {}

        # Run each rule
        for rule_id, rule in self.rules.items():
            try:
                if rule.check(component, context):
                    triggered_rules.append(rule_id)
                    scores[rule_id] = rule.weight
                    logger.debug(f"Rule {rule_id} triggered for {component.name}")
            except Exception as e:
                logger.warning(f"Error running heuristic {rule_id}: {e}")

        # Calculate total score
        total_score = self._calculate_score(scores)

        # Suggest classification
        suggested = self._suggest_classification(total_score)

        # Build explanation
        explanation = self._build_explanation(triggered_rules, total_score, suggested)

        return HeuristicResult(
            component_id=component.id,
            triggered_rules=triggered_rules,
            scores=scores,
            total_score=total_score,
            suggested_classification=suggested,
            explanation=explanation,
        )

    def _calculate_score(self, scores: dict[str, float]) -> float:
        """Calculate normalized bloat score.

        Args:
            scores: Dictionary of rule scores

        Returns:
            Normalized score between 0.0 and 1.0
        """
        if not scores:
            return 0.0

        # Sum of triggered weights
        triggered_weight = sum(scores.values())

        # Maximum possible score
        max_weight = sum(r.weight for r in self.rules.values())

        if max_weight == 0:
            return 0.0

        # Normalize to 0-1 range
        return min(triggered_weight / max_weight, 1.0)

    def _suggest_classification(self, score: float) -> Classification:
        """Suggest classification based on bloat score.

        Args:
            score: Calculated bloat score

        Returns:
            Suggested Classification enum value
        """
        if score >= self.threshold_aggressive:
            return Classification.AGGRESSIVE
        elif score >= self.threshold_bloat:
            return Classification.BLOAT
        elif score > 0:
            return Classification.OPTIONAL
        else:
            return Classification.UNKNOWN

    def _build_explanation(
        self,
        triggered_rules: list[str],
        score: float,
        classification: Classification,
    ) -> str:
        """Build human-readable explanation.

        Args:
            triggered_rules: List of triggered rule IDs
            score: Calculated bloat score
            classification: Suggested classification

        Returns:
            Explanation string
        """
        if not triggered_rules:
            return "No bloatware indicators detected"

        rule_names = [self.rules[r].name for r in triggered_rules if r in self.rules]

        explanation = (
            f"Bloat score: {score:.1%}. "
            f"Triggered {len(triggered_rules)} indicators: {', '.join(rule_names)}. "
            f"Suggested classification: {classification.value}"
        )

        return explanation

    def add_rule(self, rule: HeuristicRule) -> None:
        """Add a custom heuristic rule.

        Args:
            rule: HeuristicRule to add
        """
        self.rules[rule.rule_id] = rule
        logger.info(f"Added heuristic rule: {rule.rule_id}")

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a heuristic rule.

        Args:
            rule_id: ID of the rule to remove

        Returns:
            True if removed, False if not found
        """
        if rule_id in self.rules:
            del self.rules[rule_id]
            logger.info(f"Removed heuristic rule: {rule_id}")
            return True
        return False

    def get_rule_categories(self) -> dict[HeuristicCategory, list[str]]:
        """Get rules grouped by category.

        Returns:
            Dictionary mapping categories to rule IDs
        """
        categories: dict[HeuristicCategory, list[str]] = {}
        for rule_id, rule in self.rules.items():
            if rule.category not in categories:
                categories[rule.category] = []
            categories[rule.category].append(rule_id)
        return categories

    def get_rules_by_weight(self, min_weight: float = 0.0) -> list[HeuristicRule]:
        """Get rules sorted by weight.

        Args:
            min_weight: Minimum weight threshold

        Returns:
            List of rules with weight >= min_weight, sorted descending
        """
        return sorted(
            [r for r in self.rules.values() if r.weight >= min_weight],
            key=lambda r: r.weight,
            reverse=True,
        )


def create_checker_for_engine(
    heuristics_engine: HeuristicsEngine,
    context_provider: Callable[[Component], dict[str, Any]] | None = None,
) -> Callable[[Component], tuple[str, float]]:
    """Create a checker function compatible with ClassificationEngine.

    Args:
        heuristics_engine: HeuristicsEngine instance
        context_provider: Optional function to provide context for components

    Returns:
        Checker function for registering with ClassificationEngine
    """

    def checker(component: Component) -> tuple[str, float]:
        context = context_provider(component) if context_provider else {}
        result = heuristics_engine.analyze(component, context)

        if result.triggered_rules:
            flag_name = f"heuristic:{','.join(result.triggered_rules[:3])}"
            return (flag_name, result.total_score)

        return ("", 0.0)

    return checker
