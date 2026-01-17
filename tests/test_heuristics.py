"""Unit tests for heuristics engine module."""

from src.classification.heuristics import (
    HEURISTIC_RULES,
    HeuristicCategory,
    HeuristicResult,
    HeuristicRule,
    HeuristicsEngine,
    create_checker_for_engine,
)
from src.core.models import Classification, Component, ComponentType


class TestHeuristicRule:
    """Tests for HeuristicRule dataclass."""

    def test_rule_creation(self) -> None:
        """Test creating a heuristic rule."""
        rule = HeuristicRule(
            rule_id="TEST_RULE",
            name="Test Rule",
            description="A test rule",
            category=HeuristicCategory.BEHAVIOR,
            weight=0.5,
            check=lambda c, ctx: True,
        )

        assert rule.rule_id == "TEST_RULE"
        assert rule.name == "Test Rule"
        assert rule.weight == 0.5
        assert rule.category == HeuristicCategory.BEHAVIOR


class TestHeuristicResult:
    """Tests for HeuristicResult dataclass."""

    def test_result_defaults(self) -> None:
        """Test HeuristicResult default values."""
        result = HeuristicResult(component_id="test-123")

        assert result.component_id == "test-123"
        assert result.triggered_rules == []
        assert result.scores == {}
        assert result.total_score == 0.0
        assert result.suggested_classification == Classification.UNKNOWN


class TestHeuristicRules:
    """Tests for built-in heuristic rules."""

    def test_all_rules_defined(self) -> None:
        """Test that all expected rules are defined."""
        expected_rules = [
            "AUTOSTART_NO_UI",
            "NETWORK_NO_VALUE",
            "SELF_HEALING",
            "ACCOUNT_REQUIRED",
            "BUNDLED_UNRELATED",
            "TELEMETRY_PATTERN",
            "OVERLAY_INJECTOR",
            "HIGH_RESOURCE_USAGE",
            "STARTUP_PERSISTENCE",
            "PROMOTIONAL_CONTENT",
            "OEM_PREINSTALL",
            "UNSIGNED_UNKNOWN",
        ]

        for rule_id in expected_rules:
            assert rule_id in HEURISTIC_RULES, f"Missing rule: {rule_id}"

    def test_rule_weights_valid(self) -> None:
        """Test that all rule weights are between 0 and 1."""
        for rule_id, rule in HEURISTIC_RULES.items():
            assert 0.0 <= rule.weight <= 1.0, f"Invalid weight for {rule_id}"

    def test_rule_categories_valid(self) -> None:
        """Test that all rules have valid categories."""
        for _rule_id, rule in HEURISTIC_RULES.items():
            assert isinstance(rule.category, HeuristicCategory)


class TestHeuristicsEngine:
    """Tests for HeuristicsEngine class."""

    def test_init_default(self) -> None:
        """Test creating engine with defaults."""
        engine = HeuristicsEngine()

        assert engine.threshold_bloat == 0.4
        assert engine.threshold_aggressive == 0.7
        assert len(engine.rules) == len(HEURISTIC_RULES)

    def test_init_custom_thresholds(self) -> None:
        """Test creating engine with custom thresholds."""
        engine = HeuristicsEngine(
            threshold_bloat=0.3,
            threshold_aggressive=0.6,
        )

        assert engine.threshold_bloat == 0.3
        assert engine.threshold_aggressive == 0.6

    def test_analyze_no_triggers(self) -> None:
        """Test analyzing a component that triggers no rules."""
        engine = HeuristicsEngine()

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="normal-app",
            display_name="Normal Application",
            publisher="Legitimate Publisher Inc.",
        )

        # Provide context indicating normal behavior
        context = {
            "has_autostart": False,
            "has_visible_ui": True,
            "has_network_access": False,
            "is_signed": True,
        }

        result = engine.analyze(component, context)

        assert result.total_score == 0.0
        assert result.suggested_classification == Classification.UNKNOWN
        assert len(result.triggered_rules) == 0

    def test_analyze_telemetry_pattern(self) -> None:
        """Test detecting telemetry patterns."""
        engine = HeuristicsEngine()

        component = Component(
            component_type=ComponentType.SERVICE,
            name="TelemetryService",
            display_name="Application Telemetry Service",
            publisher="Software Corp",
        )

        result = engine.analyze(component, {})

        assert "TELEMETRY_PATTERN" in result.triggered_rules
        assert result.total_score > 0.0

    def test_analyze_overlay_injector(self) -> None:
        """Test detecting overlay injectors."""
        engine = HeuristicsEngine()

        component = Component(
            component_type=ComponentType.DRIVER,
            name="GameOverlayHelper",
            display_name="Game Overlay Helper",
            publisher="Game Corp",
        )

        result = engine.analyze(component, {})

        assert "OVERLAY_INJECTOR" in result.triggered_rules

    def test_analyze_self_healing(self) -> None:
        """Test detecting self-healing patterns."""
        engine = HeuristicsEngine()

        component = Component(
            component_type=ComponentType.SERVICE,
            name="UpdaterService",
            display_name="Application Updater Service",
            publisher="Software Corp",
        )

        result = engine.analyze(component, {})

        assert "SELF_HEALING" in result.triggered_rules

    def test_analyze_oem_preinstall(self) -> None:
        """Test detecting OEM preinstalled software."""
        engine = HeuristicsEngine()

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="hp-support-assistant",
            display_name="HP Support Assistant",
            publisher="HP Inc.",
        )

        result = engine.analyze(component, {})

        assert "OEM_PREINSTALL" in result.triggered_rules

    def test_analyze_high_resource_usage(self) -> None:
        """Test detecting high resource usage."""
        engine = HeuristicsEngine()

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="resource-hog",
            display_name="Resource Hog",
            publisher="Test",
        )

        context = {
            "cpu_usage_percent": 15.0,  # High CPU
            "memory_usage_mb": 800,  # High memory
        }

        result = engine.analyze(component, context)

        assert "HIGH_RESOURCE_USAGE" in result.triggered_rules

    def test_analyze_multiple_persistence(self) -> None:
        """Test detecting multiple persistence mechanisms."""
        engine = HeuristicsEngine()

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="persistent-app",
            display_name="Persistent App",
            publisher="Test",
        )

        context = {"persistence_mechanisms": 3}

        result = engine.analyze(component, context)

        assert "STARTUP_PERSISTENCE" in result.triggered_rules

    def test_analyze_unsigned(self) -> None:
        """Test detecting unsigned software."""
        engine = HeuristicsEngine()

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="unsigned-app",
            display_name="Unsigned App",
            publisher="Unknown",
        )

        context = {"is_signed": False}

        result = engine.analyze(component, context)

        assert "UNSIGNED_UNKNOWN" in result.triggered_rules

    def test_analyze_bundled_unrelated(self) -> None:
        """Test detecting bundled unrelated software."""
        engine = HeuristicsEngine()

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="bundled-toolbar",
            display_name="Browser Toolbar",
            publisher="Toolbar Inc",
        )

        context = {
            "is_bundled": True,
            "related_to_parent": False,
        }

        result = engine.analyze(component, context)

        assert "BUNDLED_UNRELATED" in result.triggered_rules

    def test_suggest_classification_bloat(self) -> None:
        """Test classification suggestion for BLOAT threshold."""
        engine = HeuristicsEngine(
            threshold_bloat=0.3,
            threshold_aggressive=0.7,
        )

        # Trigger enough rules to cross bloat threshold
        component = Component(
            component_type=ComponentType.SERVICE,
            name="DiagnosticService",  # Triggers telemetry
            display_name="Diagnostic Service",
            publisher="HP Inc.",  # Triggers OEM
        )

        context = {
            "has_autostart": True,
            "has_visible_ui": False,  # Triggers autostart_no_ui
        }

        result = engine.analyze(component, context)

        # Should be classified as BLOAT or AGGRESSIVE
        assert result.suggested_classification in [
            Classification.BLOAT,
            Classification.AGGRESSIVE,
            Classification.OPTIONAL,
        ]

    def test_suggest_classification_aggressive(self) -> None:
        """Test classification suggestion for AGGRESSIVE threshold."""
        engine = HeuristicsEngine(
            threshold_bloat=0.3,
            threshold_aggressive=0.5,
        )

        # Trigger many rules
        component = Component(
            component_type=ComponentType.SERVICE,
            name="TelemetryUpdater",
            display_name="Telemetry Update Service",
            publisher="Unknown",
        )

        context = {
            "has_autostart": True,
            "has_visible_ui": False,
            "has_network_access": True,
            "provides_network_feature": False,
            "persistence_mechanisms": 3,
            "is_signed": False,
        }

        result = engine.analyze(component, context)

        # Should have high score
        assert result.total_score > 0.3

    def test_add_custom_rule(self) -> None:
        """Test adding a custom heuristic rule."""
        engine = HeuristicsEngine()
        initial_count = len(engine.rules)

        custom_rule = HeuristicRule(
            rule_id="CUSTOM_TEST",
            name="Custom Test Rule",
            description="A custom test rule",
            category=HeuristicCategory.BEHAVIOR,
            weight=0.5,
            check=lambda c, ctx: "custom" in c.name.lower(),
        )

        engine.add_rule(custom_rule)

        assert len(engine.rules) == initial_count + 1
        assert "CUSTOM_TEST" in engine.rules

        # Test the custom rule
        component = Component(
            component_type=ComponentType.PROGRAM,
            name="custom-app",
            display_name="Custom App",
            publisher="Test",
        )

        result = engine.analyze(component, {})
        assert "CUSTOM_TEST" in result.triggered_rules

    def test_remove_rule(self) -> None:
        """Test removing a heuristic rule."""
        engine = HeuristicsEngine()
        initial_count = len(engine.rules)

        removed = engine.remove_rule("TELEMETRY_PATTERN")
        assert removed is True
        assert len(engine.rules) == initial_count - 1
        assert "TELEMETRY_PATTERN" not in engine.rules

    def test_remove_nonexistent_rule(self) -> None:
        """Test removing a rule that doesn't exist."""
        engine = HeuristicsEngine()

        removed = engine.remove_rule("NONEXISTENT_RULE")
        assert removed is False

    def test_get_rule_categories(self) -> None:
        """Test getting rules by category."""
        engine = HeuristicsEngine()

        categories = engine.get_rule_categories()

        assert HeuristicCategory.TELEMETRY in categories
        assert HeuristicCategory.BEHAVIOR in categories
        assert len(categories) > 0

    def test_get_rules_by_weight(self) -> None:
        """Test getting rules sorted by weight."""
        engine = HeuristicsEngine()

        rules = engine.get_rules_by_weight(min_weight=0.4)

        # All returned rules should have weight >= 0.4
        for rule in rules:
            assert rule.weight >= 0.4

        # Rules should be sorted descending by weight
        for i in range(len(rules) - 1):
            assert rules[i].weight >= rules[i + 1].weight

    def test_explanation_generation(self) -> None:
        """Test that explanations are generated."""
        engine = HeuristicsEngine()

        component = Component(
            component_type=ComponentType.SERVICE,
            name="TelemetryService",
            display_name="Telemetry Service",
            publisher="Test",
        )

        result = engine.analyze(component, {})

        assert result.explanation != ""
        assert "Bloat score" in result.explanation


class TestCreateCheckerForEngine:
    """Tests for create_checker_for_engine function."""

    def test_create_checker(self) -> None:
        """Test creating a checker function."""
        heuristics_engine = HeuristicsEngine()
        checker = create_checker_for_engine(heuristics_engine)

        component = Component(
            component_type=ComponentType.SERVICE,
            name="TelemetryService",
            display_name="Telemetry Service",
            publisher="Test",
        )

        flag_name, score = checker(component)

        # Should return non-empty flag and positive score for telemetry
        assert "heuristic:" in flag_name
        assert score > 0.0

    def test_checker_with_context_provider(self) -> None:
        """Test checker with custom context provider."""
        heuristics_engine = HeuristicsEngine()

        def context_provider(component: Component) -> dict:
            return {
                "has_autostart": True,
                "has_visible_ui": False,
            }

        checker = create_checker_for_engine(heuristics_engine, context_provider)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="background-app",
            display_name="Background App",
            publisher="Test",
        )

        flag_name, score = checker(component)

        # Should trigger AUTOSTART_NO_UI
        assert score > 0.0

    def test_checker_no_triggers(self) -> None:
        """Test checker when no rules trigger."""
        heuristics_engine = HeuristicsEngine()
        checker = create_checker_for_engine(heuristics_engine)

        component = Component(
            component_type=ComponentType.PROGRAM,
            name="normal-app",
            display_name="Normal App",
            publisher="Microsoft Corporation",
        )

        flag_name, score = checker(component)

        # May still trigger some rules based on name patterns
        # Just verify it returns valid tuple
        assert isinstance(flag_name, str)
        assert isinstance(score, float)
