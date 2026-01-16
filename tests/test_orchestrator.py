"""Tests for the scan orchestrator."""

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from src.core.config import Config
from src.core.models import Classification, Component, ComponentType
from src.core.orchestrator import ModuleScanResult, ScanOrchestrator, ScanResult
from src.discovery.base import BaseDiscoveryModule


class MockDiscoveryModule(BaseDiscoveryModule):
    """Mock discovery module for testing."""

    def __init__(
        self,
        name: str = "mock",
        components: list[Component] = None,
        should_fail: bool = False,
        available: bool = True,
    ):
        self._name = name
        self._components = components or []
        self._should_fail = should_fail
        self._available = available

    def get_module_name(self) -> str:
        return self._name

    def scan(self) -> list[Component]:
        if self._should_fail:
            raise OSError("Mock scan failure")
        return self._components

    def is_available(self) -> bool:
        return self._available


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_empty_result(self):
        """Test empty scan result."""
        result = ScanResult()

        assert result.total_count == 0
        assert result.components == []
        assert result.errors == []

    def test_total_count(self):
        """Test total component count."""
        components = [
            Component(
                component_type=ComponentType.PROGRAM,
                name=f"test-{i}",
                display_name=f"Test {i}",
                publisher="Test",
            )
            for i in range(5)
        ]

        result = ScanResult(components=components)
        assert result.total_count == 5

    def test_get_by_classification(self):
        """Test filtering by classification."""
        components = [
            Component(
                component_type=ComponentType.PROGRAM,
                name="bloat-1",
                display_name="Bloat 1",
                publisher="Test",
                classification=Classification.BLOAT,
            ),
            Component(
                component_type=ComponentType.PROGRAM,
                name="core-1",
                display_name="Core 1",
                publisher="Test",
                classification=Classification.CORE,
            ),
            Component(
                component_type=ComponentType.PROGRAM,
                name="bloat-2",
                display_name="Bloat 2",
                publisher="Test",
                classification=Classification.BLOAT,
            ),
        ]

        result = ScanResult(components=components)
        bloat = result.get_by_classification(Classification.BLOAT)

        assert len(bloat) == 2
        assert all(c.classification == Classification.BLOAT for c in bloat)

    def test_get_summary(self):
        """Test summary generation."""
        components = [
            Component(
                component_type=ComponentType.PROGRAM,
                name="bloat-1",
                display_name="Bloat 1",
                publisher="Test",
                classification=Classification.BLOAT,
            ),
            Component(
                component_type=ComponentType.PROGRAM,
                name="unknown-1",
                display_name="Unknown 1",
                publisher="Test",
                classification=Classification.UNKNOWN,
            ),
            Component(
                component_type=ComponentType.PROGRAM,
                name="bloat-2",
                display_name="Bloat 2",
                publisher="Test",
                classification=Classification.BLOAT,
            ),
        ]

        result = ScanResult(components=components)
        summary = result.get_summary()

        assert summary["BLOAT"] == 2
        assert summary["UNKNOWN"] == 1


class TestModuleScanResult:
    """Tests for ModuleScanResult dataclass."""

    def test_success_result(self):
        """Test successful module result."""
        result = ModuleScanResult(
            module_name="test",
            components=[],
            scan_time_ms=100.0,
        )

        assert result.success is True
        assert result.count == 0

    def test_error_result(self):
        """Test failed module result."""
        result = ModuleScanResult(
            module_name="test",
            error="Something went wrong",
        )

        assert result.success is False


class TestScanOrchestrator:
    """Tests for ScanOrchestrator."""

    @pytest.fixture
    def config(self):
        """Create a test configuration."""
        with TemporaryDirectory() as tmpdir:
            yield Config(config_dir=Path(tmpdir))

    def test_register_module(self, config):
        """Test module registration."""
        orchestrator = ScanOrchestrator(config)
        module = MockDiscoveryModule(name="programs")

        orchestrator.register_module(module)

        assert "programs" in orchestrator.get_registered_modules()

    def test_register_unavailable_module(self, config):
        """Test that unavailable modules are not registered."""
        orchestrator = ScanOrchestrator(config)
        module = MockDiscoveryModule(name="unavailable", available=False)

        orchestrator.register_module(module)

        assert "unavailable" not in orchestrator.get_registered_modules()

    def test_run_scan_empty(self, config):
        """Test scan with no registered modules."""
        orchestrator = ScanOrchestrator(config)
        result = orchestrator.run_scan()

        assert result.total_count == 0
        assert result.completed_at is not None

    def test_run_scan_with_module(self, config):
        """Test scan with a registered module."""
        components = [
            Component(
                component_type=ComponentType.PROGRAM,
                name="test-program",
                display_name="Test Program",
                publisher="Test",
            )
        ]

        orchestrator = ScanOrchestrator(config)
        orchestrator.register_module(
            MockDiscoveryModule(
                name="programs",
                components=components,
            )
        )

        result = orchestrator.run_scan()

        assert result.total_count == 1
        assert "programs" in result.module_results
        assert result.module_results["programs"].success is True

    def test_run_scan_with_failing_module(self, config):
        """Test scan with a failing module."""
        orchestrator = ScanOrchestrator(config)
        orchestrator.register_module(
            MockDiscoveryModule(
                name="failing",
                should_fail=True,
            )
        )

        result = orchestrator.run_scan()

        assert result.total_count == 0
        assert len(result.errors) == 1
        assert "failing" in result.module_results
        assert result.module_results["failing"].success is False

    def test_run_scan_specific_modules(self, config):
        """Test running specific modules only."""
        orchestrator = ScanOrchestrator(config)
        orchestrator.register_module(MockDiscoveryModule(name="programs"))
        orchestrator.register_module(MockDiscoveryModule(name="services"))
        orchestrator.register_module(MockDiscoveryModule(name="tasks"))

        result = orchestrator.run_scan(modules=["programs", "services"])

        assert "programs" in result.module_results
        assert "services" in result.module_results
        assert "tasks" not in result.module_results

    def test_run_single_module(self, config):
        """Test running a single module by name."""
        components = [
            Component(
                component_type=ComponentType.SERVICE,
                name="test-service",
                display_name="Test Service",
                publisher="Test",
            )
        ]

        orchestrator = ScanOrchestrator(config)
        orchestrator.register_module(
            MockDiscoveryModule(
                name="services",
                components=components,
            )
        )

        result = orchestrator.run_single_module("services")

        assert result.success is True
        assert result.count == 1

    def test_run_single_module_not_found(self, config):
        """Test running a nonexistent module."""
        orchestrator = ScanOrchestrator(config)

        with pytest.raises(ValueError, match="Module not found"):
            orchestrator.run_single_module("nonexistent")

    def test_progress_callback(self, config):
        """Test progress callback is called."""
        progress_calls = []

        def callback(module_name: str, current: int, total: int):
            progress_calls.append((module_name, current, total))

        orchestrator = ScanOrchestrator(config)
        orchestrator.register_module(MockDiscoveryModule(name="module1"))
        orchestrator.register_module(MockDiscoveryModule(name="module2"))

        orchestrator.run_scan(progress_callback=callback)

        assert len(progress_calls) == 2
        assert progress_calls[0] == ("module1", 1, 2)
        assert progress_calls[1] == ("module2", 2, 2)
