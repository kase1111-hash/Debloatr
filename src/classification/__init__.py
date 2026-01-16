"""Classification engine for categorizing discovered components."""

from .signatures import SignatureDatabase, SignatureMatch
from .engine import (
    ClassificationEngine,
    ClassificationSource,
    ClassificationDecision,
    create_default_engine,
)
from .heuristics import (
    HeuristicsEngine,
    HeuristicRule,
    HeuristicResult,
    HeuristicCategory,
    HEURISTIC_RULES,
    create_checker_for_engine,
)

__all__ = [
    # Signature Database
    "SignatureDatabase",
    "SignatureMatch",
    # Classification Engine
    "ClassificationEngine",
    "ClassificationSource",
    "ClassificationDecision",
    "create_default_engine",
    # Heuristics Engine
    "HeuristicsEngine",
    "HeuristicRule",
    "HeuristicResult",
    "HeuristicCategory",
    "HEURISTIC_RULES",
    "create_checker_for_engine",
]
