"""Classification Engine - Core classification logic.

This module provides the classification engine that combines
signature matching, heuristics, and optional LLM analysis
to classify discovered components.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from src.classification.signatures import SignatureDatabase
from src.core.models import (
    ActionType,
    Classification,
    Component,
)

logger = logging.getLogger("debloatr.classification.engine")


class ClassificationSource(Enum):
    """Source of a classification decision."""

    SIGNATURE = "signature"  # Matched a known signature
    HEURISTIC = "heuristic"  # Based on heuristic rules
    LLM = "llm"  # LLM advisory classification
    MANUAL = "manual"  # User-specified classification
    NONE = "none"  # No classification


@dataclass
class ClassificationDecision:
    """A classification decision with full context.

    Attributes:
        component: The classified component
        classification: The assigned classification
        source: How the classification was determined
        confidence: Confidence score (0.0-1.0)
        signature_id: Matching signature ID (if signature-based)
        heuristic_flags: Triggered heuristic flags
        explanation: Human-readable explanation
        safe_actions: Actions safe to perform
        unsafe_actions: Actions that may cause issues
        related_components: IDs of related components
        timestamp: When classification was made
    """

    component: Component
    classification: Classification
    source: ClassificationSource = ClassificationSource.NONE
    confidence: float = 0.0
    signature_id: str | None = None
    heuristic_flags: list[str] = field(default_factory=list)
    explanation: str = ""
    safe_actions: list[ActionType] = field(default_factory=list)
    unsafe_actions: list[ActionType] = field(default_factory=list)
    related_components: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


class ClassificationEngine:
    """Engine for classifying system components.

    Combines multiple classification methods:
    1. Signature matching (deterministic, highest priority)
    2. Heuristic rules (confidence-based)
    3. LLM analysis (optional, advisory only)

    Example:
        engine = ClassificationEngine()
        engine.load_signatures(Path("data/signatures"))
        decision = engine.classify(component)
        print(f"{decision.classification.value}: {decision.explanation}")
    """

    def __init__(
        self,
        signature_db: SignatureDatabase | None = None,
        enable_heuristics: bool = True,
        heuristic_threshold: float = 0.6,
    ) -> None:
        """Initialize the classification engine.

        Args:
            signature_db: Pre-loaded signature database.
            enable_heuristics: Whether to use heuristic classification.
            heuristic_threshold: Minimum score for heuristic classification.
        """
        self.signature_db = signature_db or SignatureDatabase()
        self.enable_heuristics = enable_heuristics
        self.heuristic_threshold = heuristic_threshold

        # Heuristic checkers (will be populated by heuristics module)
        self._heuristic_checkers: list[Callable[[Component], tuple[str, float]]] = []

        # Classification cache
        self._cache: dict[str, ClassificationDecision] = {}

    def load_signatures(self, path: Path) -> int:
        """Load signatures from file or directory.

        Args:
            path: Path to signature file or directory.

        Returns:
            Number of signatures loaded.
        """
        if path.is_dir():
            return self.signature_db.load_from_directory(path)
        else:
            return self.signature_db.load_from_file(path)

    def classify(
        self,
        component: Component,
        use_cache: bool = True,
    ) -> ClassificationDecision:
        """Classify a component.

        Args:
            component: Component to classify.
            use_cache: Whether to use cached results.

        Returns:
            ClassificationDecision with full context.
        """
        # Check cache
        if use_cache and component.id in self._cache:
            return self._cache[component.id]

        # Try signature match first (highest priority)
        decision = self._classify_by_signature(component)

        # Try heuristics if no signature match
        if decision is None and self.enable_heuristics:
            decision = self._classify_by_heuristics(component)

        # Default to UNKNOWN if no classification
        if decision is None:
            decision = ClassificationDecision(
                component=component,
                classification=Classification.UNKNOWN,
                source=ClassificationSource.NONE,
                confidence=0.0,
                explanation="No matching signature or heuristic patterns found",
            )

        # Update component classification
        component.classification = decision.classification

        # Cache result
        self._cache[component.id] = decision

        return decision

    def classify_batch(
        self,
        components: list[Component],
    ) -> list[ClassificationDecision]:
        """Classify multiple components.

        Args:
            components: List of components to classify.

        Returns:
            List of classification decisions.
        """
        return [self.classify(c) for c in components]

    def _classify_by_signature(
        self,
        component: Component,
    ) -> ClassificationDecision | None:
        """Attempt to classify by signature match.

        Args:
            component: Component to classify.

        Returns:
            ClassificationDecision if matched, None otherwise.
        """
        match = self.signature_db.match_component(component)

        if match is None:
            return None

        signature = match.signature

        # Build explanation
        explanation = (
            f"Matched signature '{signature.component_name}' " f"by {match.match_type} pattern"
        )
        if signature.breakage_notes:
            explanation += f". Note: {signature.breakage_notes}"

        return ClassificationDecision(
            component=component,
            classification=signature.classification,
            source=ClassificationSource.SIGNATURE,
            confidence=match.match_score,
            signature_id=signature.signature_id,
            explanation=explanation,
            safe_actions=list(signature.safe_actions),
            unsafe_actions=list(signature.unsafe_actions),
            related_components=list(signature.related_components),
        )

    def _classify_by_heuristics(
        self,
        component: Component,
    ) -> ClassificationDecision | None:
        """Attempt to classify by heuristic rules.

        Args:
            component: Component to classify.

        Returns:
            ClassificationDecision if threshold met, None otherwise.
        """
        if not self._heuristic_checkers:
            return None

        triggered_flags: list[str] = []
        total_score = 0.0

        for checker in self._heuristic_checkers:
            try:
                flag_name, score = checker(component)
                if score > 0:
                    triggered_flags.append(flag_name)
                    total_score += score
            except Exception as e:
                logger.debug(f"Heuristic checker error: {e}")

        if not triggered_flags:
            return None

        # Normalize score
        max_possible = len(self._heuristic_checkers)
        normalized_score = min(total_score / max_possible, 1.0)

        if normalized_score < self.heuristic_threshold:
            return None

        # Determine classification based on score
        if normalized_score >= 0.8:
            classification = Classification.AGGRESSIVE
        elif normalized_score >= 0.6:
            classification = Classification.BLOAT
        else:
            classification = Classification.OPTIONAL

        explanation = (
            f"Heuristic classification based on {len(triggered_flags)} flags: "
            f"{', '.join(triggered_flags)}"
        )

        return ClassificationDecision(
            component=component,
            classification=classification,
            source=ClassificationSource.HEURISTIC,
            confidence=normalized_score,
            heuristic_flags=triggered_flags,
            explanation=explanation,
            safe_actions=[ActionType.DISABLE],
            unsafe_actions=[ActionType.REMOVE] if normalized_score < 0.8 else [],
        )

    def register_heuristic(
        self,
        checker: Callable[[Component], tuple[str, float]],
    ) -> None:
        """Register a heuristic checker function.

        Args:
            checker: Function that takes a Component and returns
                     (flag_name, score) tuple.
        """
        self._heuristic_checkers.append(checker)

    def get_related_components(
        self,
        component: Component,
    ) -> list[str]:
        """Get IDs of components related to a classified component.

        Args:
            component: Classified component.

        Returns:
            List of related component signature IDs.
        """
        decision = self._cache.get(component.id)
        if decision and decision.signature_id:
            signature = self.signature_db.get_signature(decision.signature_id)
            if signature:
                return list(signature.related_components)
        return []

    def get_safe_actions(
        self,
        component: Component,
    ) -> list[ActionType]:
        """Get safe actions for a classified component.

        Args:
            component: Classified component.

        Returns:
            List of safe action types.
        """
        decision = self._cache.get(component.id)
        if decision:
            return list(decision.safe_actions)

        # Default safe actions based on classification
        if component.classification == Classification.BLOAT:
            return [ActionType.DISABLE]
        elif component.classification == Classification.AGGRESSIVE:
            return [ActionType.DISABLE, ActionType.REMOVE]
        elif component.classification == Classification.OPTIONAL:
            return [ActionType.DISABLE]

        return []

    def get_unsafe_actions(
        self,
        component: Component,
    ) -> list[ActionType]:
        """Get unsafe actions for a classified component.

        Args:
            component: Classified component.

        Returns:
            List of unsafe action types.
        """
        decision = self._cache.get(component.id)
        if decision:
            return list(decision.unsafe_actions)
        return []

    def explain_classification(
        self,
        component: Component,
    ) -> str:
        """Get a human-readable explanation for a classification.

        Args:
            component: Classified component.

        Returns:
            Explanation string.
        """
        decision = self._cache.get(component.id)
        if decision:
            return decision.explanation

        return "Component has not been classified yet"

    def reclassify(
        self,
        component: Component,
        classification: Classification,
        reason: str = "",
    ) -> ClassificationDecision:
        """Manually override a component's classification.

        Args:
            component: Component to reclassify.
            classification: New classification.
            reason: Reason for override.

        Returns:
            New classification decision.
        """
        decision = ClassificationDecision(
            component=component,
            classification=classification,
            source=ClassificationSource.MANUAL,
            confidence=1.0,
            explanation=f"Manual classification: {reason}" if reason else "Manual classification",
        )

        component.classification = classification
        self._cache[component.id] = decision

        return decision

    def clear_cache(self) -> None:
        """Clear the classification cache."""
        self._cache.clear()

    @property
    def cache_size(self) -> int:
        """Get the number of cached classifications."""
        return len(self._cache)

    def get_statistics(self) -> dict[str, Any]:
        """Get classification statistics.

        Returns:
            Dictionary with statistics.
        """
        stats: dict[str, int] = {
            "total_classified": len(self._cache),
            "by_source": {},
            "by_classification": {},
        }

        for decision in self._cache.values():
            # Count by source
            source = decision.source.value
            stats["by_source"][source] = stats["by_source"].get(source, 0) + 1

            # Count by classification
            cls = decision.classification.value
            stats["by_classification"][cls] = stats["by_classification"].get(cls, 0) + 1

        return stats


def create_default_engine(signatures_path: Path | None = None) -> ClassificationEngine:
    """Create a classification engine with default settings.

    Args:
        signatures_path: Optional path to load signatures from.

    Returns:
        Configured ClassificationEngine.
    """
    engine = ClassificationEngine(
        enable_heuristics=True,
        heuristic_threshold=0.6,
    )

    if signatures_path and signatures_path.exists():
        engine.load_signatures(signatures_path)

    return engine
