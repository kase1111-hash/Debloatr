"""Unit tests for classification engine module."""

import json
from pathlib import Path

from src.classification.engine import (
    ClassificationDecision,
    ClassificationEngine,
    ClassificationSource,
    create_default_engine,
)
from src.core.models import (
    ActionType,
    Classification,
    Component,
    ComponentType,
)


class TestClassificationSource:
    """Tests for ClassificationSource enum."""

    def test_source_values(self) -> None:
        """Test classification source values."""
        assert ClassificationSource.SIGNATURE.value == "signature"
        assert ClassificationSource.HEURISTIC.value == "heuristic"
        assert ClassificationSource.LLM.value == "llm"
        assert ClassificationSource.MANUAL.value == "manual"
        assert ClassificationSource.NONE.value == "none"


class TestClassificationDecision:
    """Tests for ClassificationDecision dataclass."""

    def test_decision_creation(self) -> None:
        """Test creating a ClassificationDecision."""
        component = Component(
            component_type=ComponentType.PROGRAM,
            name="test-app",
            display_name="Test App",
            publisher="Test",
        )

        decision = ClassificationDecision(
            component=component,
            classification=Classification.BLOAT,
            source=ClassificationSource.SIGNATURE,
            confidence=0.9,
            signature_id="test-sig-001",
            explanation="Matched test signature",
        )

        assert decision.component == component
        assert decision.classification == Classification.BLOAT
        assert decision.source == ClassificationSource.SIGNATURE
        assert decision.confidence == 0.9
        assert decision.signature_id == "test-sig-001"
        assert decision.explanation == "Matched test signature"

    def test_decision_defaults(self) -> None:
        """Test ClassificationDecision default values."""
        component = Component(
            component_type=ComponentType.SERVICE,
            name="test-svc",
            display_name="Test Service",
            publisher="Test",
        )

        decision = ClassificationDecision(
            component=component,
            classification=Classification.UNKNOWN,
        )

        assert decision.source == ClassificationSource.NONE
        assert decision.confidence == 0.0
        assert decision.signature_id is None
        assert decision.heuristic_flags == []
        assert decision.explanation == ""
        assert decision.safe_actions == []
        assert decision.unsafe_actions == []
        assert decision.related_components == []


class TestClassificationEngine:
    """Tests for ClassificationEngine class."""

    def test_init_default(self) -> None:
        """Test creating engine with defaults."""
        engine = ClassificationEngine()
        assert engine.enable_heuristics is True
        assert engine.heuristic_threshold == 0.6
        assert engine.cache_size == 0

    def test_init_custom(self) -> None:
        """Test creating engine with custom settings."""
        engine = ClassificationEngine(
            enable_heuristics=False,
            heuristic_threshold=0.8,
        )
        assert engine.enable_heuristics is False
        assert engine.heuristic_threshold == 0.8

    def test_load_signatures(self, tmp_path: Path) -> None:
        """Test loading signatures into engine."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {"signature_id": "sig-1", "component_name": "App 1"},
            {"signature_id": "sig-2", "component_name": "App 2"},
        ]
        sig_file.write_text(json.dumps(sig_data))

        engine = ClassificationEngine()
        count = engine.load_signatures(sig_file)

        assert count == 2
        assert engine.signature_db.count == 2

    def test_load_signatures_from_directory(self, tmp_path: Path) -> None:
        """Test loading signatures from directory."""
        sig1 = tmp_path / "sigs1.json"
        sig1.write_text('[{"signature_id": "sig-1"}]')
        sig2 = tmp_path / "sigs2.json"
        sig2.write_text('[{"signature_id": "sig-2"}]')

        engine = ClassificationEngine()
        count = engine.load_signatures(tmp_path)

        assert count == 2

    def test_classify_by_signature(self, tmp_path: Path) -> None:
        """Test classification by signature match."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "cortana-001",
                "publisher": "Microsoft",
                "component_name": "Cortana",
                "component_type": "program",
                "match_rules": {"name_pattern": ".*[Cc]ortana.*"},
                "classification": "BLOAT",
                "safe_actions": ["disable"],
                "unsafe_actions": ["remove"],
                "breakage_notes": "May affect Windows Search",
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        engine = ClassificationEngine()
        engine.load_signatures(sig_file)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="Microsoft.Windows.Cortana",
            display_name="Cortana",
            publisher="Microsoft Corporation",
        )

        decision = engine.classify(component)

        assert decision.classification == Classification.BLOAT
        assert decision.source == ClassificationSource.SIGNATURE
        assert decision.confidence == 0.9
        assert decision.signature_id == "cortana-001"
        assert "Cortana" in decision.explanation
        assert "Windows Search" in decision.explanation
        assert ActionType.DISABLE in decision.safe_actions
        assert ActionType.REMOVE in decision.unsafe_actions

    def test_classify_no_match_returns_unknown(self, tmp_path: Path) -> None:
        """Test classification returns UNKNOWN when no match."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "specific-001",
                "component_type": "program",
                "match_rules": {"name_pattern": "^VerySpecificName$"},
                "classification": "BLOAT",
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        engine = ClassificationEngine()
        engine.load_signatures(sig_file)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="completely-different",
            display_name="Different App",
            publisher="Unknown",
        )

        decision = engine.classify(component)

        assert decision.classification == Classification.UNKNOWN
        assert decision.source == ClassificationSource.NONE
        assert decision.confidence == 0.0

    def test_classify_updates_component(self, tmp_path: Path) -> None:
        """Test that classify updates component's classification."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "bloat-001",
                "component_type": "service",
                "match_rules": {"name_pattern": ".*BloatService.*"},
                "classification": "BLOAT",
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        engine = ClassificationEngine()
        engine.load_signatures(sig_file)

        component = Component(
            component_type=ComponentType.SERVICE,
            name="TestBloatService",
            display_name="Test Bloat Service",
            publisher="Test",
        )

        assert component.classification == Classification.UNKNOWN

        engine.classify(component)

        assert component.classification == Classification.BLOAT

    def test_classify_caching(self, tmp_path: Path) -> None:
        """Test that classification results are cached."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "cache-001",
                "component_type": "program",
                "match_rules": {"name_pattern": ".*CacheTest.*"},
                "classification": "OPTIONAL",
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        engine = ClassificationEngine()
        engine.load_signatures(sig_file)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="CacheTestApp",
            display_name="Cache Test App",
            publisher="Test",
        )

        # First call
        decision1 = engine.classify(component)
        assert engine.cache_size == 1

        # Second call should return cached result
        decision2 = engine.classify(component)
        assert decision1 is decision2  # Same object from cache

    def test_classify_skip_cache(self, tmp_path: Path) -> None:
        """Test classification with cache disabled."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "nocache-001",
                "component_type": "program",
                "match_rules": {"name_pattern": ".*NoCacheTest.*"},
                "classification": "BLOAT",
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        engine = ClassificationEngine()
        engine.load_signatures(sig_file)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="NoCacheTestApp",
            display_name="No Cache Test",
            publisher="Test",
        )

        decision1 = engine.classify(component, use_cache=True)
        decision2 = engine.classify(component, use_cache=False)

        # Both decisions have same values but decision2 was recalculated
        assert decision1.classification == decision2.classification

    def test_classify_batch(self, tmp_path: Path) -> None:
        """Test batch classification."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "batch-001",
                "component_type": "program",
                "match_rules": {"name_pattern": ".*Bloat.*"},
                "classification": "BLOAT",
            },
            {
                "signature_id": "batch-002",
                "component_type": "service",
                "match_rules": {"name_pattern": ".*Aggro.*"},
                "classification": "AGGRESSIVE",
            },
        ]
        sig_file.write_text(json.dumps(sig_data))

        engine = ClassificationEngine()
        engine.load_signatures(sig_file)

        components = [
            Component(
                component_type=ComponentType.PROGRAM,
                name="BloatApp",
                display_name="Bloat App",
                publisher="Test",
            ),
            Component(
                component_type=ComponentType.SERVICE,
                name="AggroService",
                display_name="Aggro Service",
                publisher="Test",
            ),
            Component(
                component_type=ComponentType.PROGRAM,
                name="UnknownApp",
                display_name="Unknown App",
                publisher="Test",
            ),
        ]

        decisions = engine.classify_batch(components)

        assert len(decisions) == 3
        assert decisions[0].classification == Classification.BLOAT
        assert decisions[1].classification == Classification.AGGRESSIVE
        assert decisions[2].classification == Classification.UNKNOWN

    def test_reclassify_manual_override(self, tmp_path: Path) -> None:
        """Test manual reclassification."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "reclassify-001",
                "component_type": "program",
                "match_rules": {"name_pattern": ".*TestApp.*"},
                "classification": "BLOAT",
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        engine = ClassificationEngine()
        engine.load_signatures(sig_file)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="TestApp",
            display_name="Test App",
            publisher="Test",
        )

        # Initial classification
        decision1 = engine.classify(component)
        assert decision1.classification == Classification.BLOAT

        # Manual override
        decision2 = engine.reclassify(
            component,
            Classification.ESSENTIAL,
            reason="User marked as essential",
        )

        assert decision2.classification == Classification.ESSENTIAL
        assert decision2.source == ClassificationSource.MANUAL
        assert decision2.confidence == 1.0
        assert "User marked as essential" in decision2.explanation
        assert component.classification == Classification.ESSENTIAL

        # Cache should be updated
        decision3 = engine.classify(component)
        assert decision3.classification == Classification.ESSENTIAL

    def test_explain_classification(self, tmp_path: Path) -> None:
        """Test getting classification explanation."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "explain-001",
                "component_name": "Explainable App",
                "component_type": "program",
                "match_rules": {"name_pattern": ".*Explainable.*"},
                "classification": "BLOAT",
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        engine = ClassificationEngine()
        engine.load_signatures(sig_file)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="ExplainableApp",
            display_name="Explainable App",
            publisher="Test",
        )

        engine.classify(component)
        explanation = engine.explain_classification(component)

        assert "Explainable App" in explanation

    def test_explain_unclassified_component(self) -> None:
        """Test explanation for unclassified component."""
        engine = ClassificationEngine()

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="never-classified",
            display_name="Never Classified",
            publisher="Test",
        )

        explanation = engine.explain_classification(component)
        assert "not been classified" in explanation

    def test_get_safe_actions(self, tmp_path: Path) -> None:
        """Test getting safe actions for classified component."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "safe-001",
                "component_type": "program",
                "match_rules": {"name_pattern": ".*SafeTest.*"},
                "classification": "BLOAT",
                "safe_actions": ["disable", "contain"],
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        engine = ClassificationEngine()
        engine.load_signatures(sig_file)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="SafeTestApp",
            display_name="Safe Test App",
            publisher="Test",
        )

        engine.classify(component)
        safe_actions = engine.get_safe_actions(component)

        assert ActionType.DISABLE in safe_actions
        assert ActionType.CONTAIN in safe_actions

    def test_get_safe_actions_default_by_classification(self) -> None:
        """Test default safe actions based on classification."""
        engine = ClassificationEngine()

        bloat_component = Component(
            component_type=ComponentType.PROGRAM,
            name="bloat-app",
            display_name="Bloat App",
            publisher="Test",
            classification=Classification.BLOAT,
        )

        aggro_component = Component(
            component_type=ComponentType.PROGRAM,
            name="aggro-app",
            display_name="Aggro App",
            publisher="Test",
            classification=Classification.AGGRESSIVE,
        )

        # For BLOAT: DISABLE should be safe
        safe_actions = engine.get_safe_actions(bloat_component)
        assert ActionType.DISABLE in safe_actions

        # For AGGRESSIVE: both DISABLE and REMOVE should be safe
        safe_actions = engine.get_safe_actions(aggro_component)
        assert ActionType.DISABLE in safe_actions
        assert ActionType.REMOVE in safe_actions

    def test_get_unsafe_actions(self, tmp_path: Path) -> None:
        """Test getting unsafe actions for classified component."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "unsafe-001",
                "component_type": "program",
                "match_rules": {"name_pattern": ".*UnsafeTest.*"},
                "classification": "OPTIONAL",
                "unsafe_actions": ["remove"],
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        engine = ClassificationEngine()
        engine.load_signatures(sig_file)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="UnsafeTestApp",
            display_name="Unsafe Test App",
            publisher="Test",
        )

        engine.classify(component)
        unsafe_actions = engine.get_unsafe_actions(component)

        assert ActionType.REMOVE in unsafe_actions

    def test_get_related_components(self, tmp_path: Path) -> None:
        """Test getting related components."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "main-001",
                "component_name": "Main App",
                "component_type": "program",
                "match_rules": {"name_pattern": ".*MainApp.*"},
                "classification": "BLOAT",
                "related_components": ["helper-001", "helper-002"],
            }
        ]
        sig_file.write_text(json.dumps(sig_data))

        engine = ClassificationEngine()
        engine.load_signatures(sig_file)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="MainApp",
            display_name="Main App",
            publisher="Test",
        )

        engine.classify(component)
        related = engine.get_related_components(component)

        assert "helper-001" in related
        assert "helper-002" in related

    def test_clear_cache(self, tmp_path: Path) -> None:
        """Test clearing classification cache."""
        sig_file = tmp_path / "sigs.json"
        sig_file.write_text('[{"signature_id": "clear-001"}]')

        engine = ClassificationEngine()
        engine.load_signatures(sig_file)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="test-app",
            display_name="Test App",
            publisher="Test",
        )

        engine.classify(component)
        assert engine.cache_size == 1

        engine.clear_cache()
        assert engine.cache_size == 0

    def test_get_statistics(self, tmp_path: Path) -> None:
        """Test getting classification statistics."""
        sig_file = tmp_path / "sigs.json"
        sig_data = [
            {
                "signature_id": "stat-001",
                "component_type": "program",
                "match_rules": {"name_pattern": ".*Bloat.*"},
                "classification": "BLOAT",
            },
            {
                "signature_id": "stat-002",
                "component_type": "service",
                "match_rules": {"name_pattern": ".*Aggro.*"},
                "classification": "AGGRESSIVE",
            },
        ]
        sig_file.write_text(json.dumps(sig_data))

        engine = ClassificationEngine()
        engine.load_signatures(sig_file)

        components = [
            Component(
                component_type=ComponentType.PROGRAM,
                name="BloatApp1",
                display_name="Bloat 1",
                publisher="T",
            ),
            Component(
                component_type=ComponentType.PROGRAM,
                name="BloatApp2",
                display_name="Bloat 2",
                publisher="T",
            ),
            Component(
                component_type=ComponentType.SERVICE,
                name="AggroSvc",
                display_name="Aggro",
                publisher="T",
            ),
        ]

        for c in components:
            engine.classify(c)

        stats = engine.get_statistics()

        assert stats["total_classified"] == 3
        assert stats["by_source"]["signature"] == 3
        assert stats["by_classification"]["BLOAT"] == 2
        assert stats["by_classification"]["AGGRESSIVE"] == 1


class TestHeuristicClassification:
    """Tests for heuristic classification."""

    def test_register_heuristic(self) -> None:
        """Test registering a heuristic checker."""
        engine = ClassificationEngine()

        def test_heuristic(component: Component) -> tuple[str, float]:
            if "telemetry" in component.name.lower():
                return ("telemetry_keyword", 0.5)
            return ("", 0.0)

        engine.register_heuristic(test_heuristic)
        assert len(engine._heuristic_checkers) == 1

    def test_heuristic_classification(self) -> None:
        """Test classification via heuristics."""
        engine = ClassificationEngine(
            enable_heuristics=True,
            heuristic_threshold=0.5,
        )

        # Register heuristics
        def telemetry_check(component: Component) -> tuple[str, float]:
            if "telemetry" in component.name.lower():
                return ("telemetry_keyword", 0.7)
            return ("", 0.0)

        def suspicious_publisher(component: Component) -> tuple[str, float]:
            if "unknown" in component.publisher.lower():
                return ("suspicious_publisher", 0.3)
            return ("", 0.0)

        engine.register_heuristic(telemetry_check)
        engine.register_heuristic(suspicious_publisher)

        component = Component(
            component_type=ComponentType.SERVICE,
            name="TelemetryService",
            display_name="Telemetry Service",
            publisher="Unknown Publisher",
        )

        decision = engine.classify(component)

        assert decision.source == ClassificationSource.HEURISTIC
        assert decision.confidence > 0.0
        assert "telemetry_keyword" in decision.heuristic_flags

    def test_heuristic_below_threshold(self) -> None:
        """Test heuristic below threshold returns UNKNOWN."""
        engine = ClassificationEngine(
            enable_heuristics=True,
            heuristic_threshold=0.8,  # High threshold
        )

        def weak_heuristic(component: Component) -> tuple[str, float]:
            return ("weak_signal", 0.2)

        engine.register_heuristic(weak_heuristic)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="test-app",
            display_name="Test App",
            publisher="Test",
        )

        decision = engine.classify(component)

        assert decision.classification == Classification.UNKNOWN

    def test_heuristics_disabled(self) -> None:
        """Test that disabled heuristics are not used."""
        engine = ClassificationEngine(enable_heuristics=False)

        def always_trigger(component: Component) -> tuple[str, float]:
            return ("always_trigger", 1.0)

        engine.register_heuristic(always_trigger)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="test-app",
            display_name="Test App",
            publisher="Test",
        )

        decision = engine.classify(component)

        # Should be UNKNOWN since heuristics are disabled
        assert decision.classification == Classification.UNKNOWN
        assert decision.source == ClassificationSource.NONE


class TestCreateDefaultEngine:
    """Tests for create_default_engine factory function."""

    def test_create_default_engine(self) -> None:
        """Test creating default engine without signatures."""
        engine = create_default_engine()

        assert engine.enable_heuristics is True
        assert engine.heuristic_threshold == 0.6
        assert engine.signature_db.count == 0

    def test_create_default_engine_with_signatures(self, tmp_path: Path) -> None:
        """Test creating default engine with signatures path."""
        sig_file = tmp_path / "sigs.json"
        sig_file.write_text('[{"signature_id": "default-001"}]')

        engine = create_default_engine(signatures_path=sig_file)

        assert engine.signature_db.count == 1

    def test_create_default_engine_with_nonexistent_path(self, tmp_path: Path) -> None:
        """Test creating default engine with nonexistent path."""
        nonexistent = tmp_path / "nonexistent.json"

        engine = create_default_engine(signatures_path=nonexistent)

        # Should not crash, just have no signatures
        assert engine.signature_db.count == 0
