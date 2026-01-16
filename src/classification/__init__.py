"""Classification engine for categorizing discovered components."""

from .engine import (
    ClassificationDecision,
    ClassificationEngine,
    ClassificationSource,
    create_default_engine,
)
from .heuristics import (
    HEURISTIC_RULES,
    HeuristicCategory,
    HeuristicResult,
    HeuristicRule,
    HeuristicsEngine,
    create_checker_for_engine,
)
from .signatures import SignatureDatabase, SignatureMatch

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
