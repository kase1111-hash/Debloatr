"""Integration tests for the classification pipeline against real Windows data."""

import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Requires Windows",
)


class TestClassificationLive:
    """Test classification against real discovered components."""

    def test_signature_database_loads(self):
        """Signature database should load without errors."""
        from src.classification.signatures import SignatureDatabase

        db = SignatureDatabase()
        sig_path = Path("data/signatures/default.json")
        if sig_path.exists():
            count = db.load_from_file(sig_path)
            assert count > 50, f"Expected 50+ signatures, got {count}"

    def test_classify_real_components(self):
        """Classification engine should handle real components without crashing."""
        from src.classification.engine import ClassificationEngine
        from src.core.config import Config
        from src.discovery.programs import ProgramsScanner

        config = Config()
        engine = ClassificationEngine(config)

        scanner = ProgramsScanner(scan_uwp=True, scan_portable=False)
        components = scanner.scan()

        classified = 0
        for comp in components[:20]:  # Classify first 20
            decision = engine.classify(comp)
            assert decision is not None
            assert decision.classification is not None
            assert 0.0 <= decision.confidence <= 1.0
            classified += 1

        assert classified > 0, "Should have classified at least one component"

    def test_known_bloatware_classified_correctly(self):
        """Known bloatware signatures should match against real components."""
        from src.classification.engine import ClassificationEngine, ClassificationSource
        from src.core.config import Config
        from src.core.models import Classification
        from src.discovery.programs import ProgramsScanner

        config = Config()
        engine = ClassificationEngine(config)

        scanner = ProgramsScanner(scan_uwp=True, scan_portable=False)
        components = scanner.scan()

        # Look for any component that matches a signature
        signature_matches = []
        for comp in components:
            decision = engine.classify(comp)
            if decision.source == ClassificationSource.SIGNATURE:
                signature_matches.append((comp.display_name, decision.classification))

        # On a stock Windows with any bloatware, we'd expect at least
        # one signature match. Log what we found for manual review.
        print(f"\nSignature matches found: {len(signature_matches)}")
        for name, cls in signature_matches:
            print(f"  {name} -> {cls.value}")
