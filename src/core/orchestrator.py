"""Scan Orchestrator - coordinates all discovery modules.

The orchestrator is responsible for:
- Managing discovery module lifecycle
- Coordinating scan execution
- Aggregating results from all modules
- Providing progress feedback
- Integrating classification after discovery
"""

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import Config
from .logging_config import get_logger, log_scan_result
from .models import Classification, Component

# Type alias for progress callback
ProgressCallback = Callable[[str, int, int], None]


@dataclass
class ScanResult:
    """Result of a complete system scan.

    Attributes:
        components: All discovered components
        scan_time_ms: Total scan duration in milliseconds
        module_results: Per-module scan results
        started_at: Scan start timestamp
        completed_at: Scan completion timestamp
        errors: Any errors encountered during scanning
    """

    components: list[Component] = field(default_factory=list)
    scan_time_ms: float = 0.0
    module_results: dict[str, "ModuleScanResult"] = field(default_factory=dict)
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: datetime | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def total_count(self) -> int:
        """Get total number of discovered components."""
        return len(self.components)

    def get_by_classification(self, classification: Classification) -> list[Component]:
        """Get components with a specific classification."""
        return [c for c in self.components if c.classification == classification]

    def get_summary(self) -> dict[str, int]:
        """Get count summary by classification."""
        summary: dict[str, int] = {}
        for component in self.components:
            key = component.classification.value
            summary[key] = summary.get(key, 0) + 1
        return summary


@dataclass
class ModuleScanResult:
    """Result from a single discovery module.

    Attributes:
        module_name: Name of the discovery module
        components: Components discovered by this module
        scan_time_ms: Module scan duration in milliseconds
        error: Error message if scan failed
    """

    module_name: str
    components: list[Component] = field(default_factory=list)
    scan_time_ms: float = 0.0
    error: str | None = None

    @property
    def success(self) -> bool:
        """Check if the module scan succeeded."""
        return self.error is None

    @property
    def count(self) -> int:
        """Get number of components discovered."""
        return len(self.components)


class ScanOrchestrator:
    """Orchestrates discovery modules and manages scan execution.

    The orchestrator coordinates all discovery modules, manages their
    execution, and aggregates results into a unified scan result.

    Example:
        orchestrator = ScanOrchestrator(config)
        orchestrator.register_module(ProgramsScanner())
        orchestrator.register_module(ServicesScanner())

        result = orchestrator.run_scan()
        print(f"Found {result.total_count} components")
    """

    def __init__(self, config: Config, auto_register: bool = True) -> None:
        """Initialize the orchestrator.

        Args:
            config: Application configuration.
            auto_register: Whether to automatically register all discovery modules.
        """
        self.config = config
        self.modules: list = []  # List of BaseDiscoveryModule
        self.logger = get_logger("main")
        self._classification_engine: Any = None

        if auto_register:
            self._register_default_modules()

    def register_module(self, module: Any) -> None:
        """Register a discovery module.

        Args:
            module: Discovery module to register.
        """
        if module.is_available():
            self.modules.append(module)
            self.logger.debug(f"Registered discovery module: {module.get_module_name()}")
        else:
            self.logger.warning(f"Discovery module not available: {module.get_module_name()}")

    def get_registered_modules(self) -> list[str]:
        """Get names of all registered modules.

        Returns:
            List of module names.
        """
        return [m.get_module_name() for m in self.modules]

    def run_scan(
        self,
        modules: list[str] | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> ScanResult:
        """Run a complete system scan.

        Args:
            modules: Optional list of specific modules to run.
                    If None, runs all registered modules.
            progress_callback: Optional callback for progress updates.
                             Called with (module_name, current, total).

        Returns:
            ScanResult containing all discovered components.
        """
        result = ScanResult(started_at=datetime.now())
        start_time = time.perf_counter()

        # Determine which modules to run
        modules_to_run = self.modules
        if modules:
            modules_to_run = [m for m in self.modules if m.get_module_name() in modules]

        total_modules = len(modules_to_run)
        self.logger.info(f"Starting scan with {total_modules} modules")

        for idx, module in enumerate(modules_to_run):
            module_name = module.get_module_name()

            # Report progress
            if progress_callback:
                progress_callback(module_name, idx + 1, total_modules)

            # Run module scan
            module_result = self._run_module(module)
            result.module_results[module_name] = module_result

            if module_result.success:
                result.components.extend(module_result.components)
            else:
                result.errors.append(f"{module_name}: {module_result.error}")

        # Classify discovered components
        if result.components:
            self.logger.info("Classifying discovered components...")
            self.classify_components(result.components)

        # Finalize result
        result.scan_time_ms = (time.perf_counter() - start_time) * 1000
        result.completed_at = datetime.now()

        self.logger.info(
            f"Scan complete: {result.total_count} components in {result.scan_time_ms:.1f}ms"
        )

        return result

    def _run_module(self, module: Any) -> ModuleScanResult:
        """Run a single discovery module.

        Args:
            module: The module to run.

        Returns:
            ModuleScanResult with discovered components or error.
        """
        module_name = module.get_module_name()
        start_time = time.perf_counter()

        try:
            self.logger.debug(f"Running module: {module_name}")
            components = module.scan()
            scan_time = (time.perf_counter() - start_time) * 1000

            log_scan_result(module_name, len(components), scan_time)

            return ModuleScanResult(
                module_name=module_name,
                components=components,
                scan_time_ms=scan_time,
            )

        except PermissionError as e:
            self.logger.error(f"Permission denied in {module_name}: {e}")
            return ModuleScanResult(
                module_name=module_name,
                error=f"Permission denied: {e}",
            )

        except OSError as e:
            self.logger.error(f"OS error in {module_name}: {e}")
            return ModuleScanResult(
                module_name=module_name,
                error=f"OS error: {e}",
            )

        except Exception as e:
            self.logger.exception(f"Unexpected error in {module_name}")
            return ModuleScanResult(
                module_name=module_name,
                error=f"Unexpected error: {e}",
            )

    def run_single_module(self, module_name: str) -> ModuleScanResult:
        """Run a single discovery module by name.

        Args:
            module_name: Name of the module to run.

        Returns:
            ModuleScanResult from the specified module.

        Raises:
            ValueError: If module name is not registered.
        """
        for module in self.modules:
            if module.get_module_name() == module_name:
                return self._run_module(module)

        raise ValueError(f"Module not found: {module_name}")

    def _register_default_modules(self) -> None:
        """Register all available discovery modules."""
        try:
            from src.discovery import (
                DriversScanner,
                ProgramsScanner,
                ServicesScanner,
                StartupScanner,
                TasksScanner,
                TelemetryScanner,
            )

            # Register each module, checking availability
            module_classes = [
                ProgramsScanner,
                ServicesScanner,
                TasksScanner,
                StartupScanner,
                DriversScanner,
                TelemetryScanner,
            ]

            for module_class in module_classes:
                try:
                    module = module_class()
                    self.register_module(module)
                except Exception as e:
                    self.logger.warning(f"Failed to register {module_class.__name__}: {e}")

            self.logger.info(f"Registered {len(self.modules)} discovery modules")

        except ImportError as e:
            self.logger.error(f"Failed to import discovery modules: {e}")

    def _get_classification_engine(self) -> Any:
        """Get or create the classification engine.

        Returns:
            ClassificationEngine instance with loaded signatures.
        """
        if self._classification_engine is None:
            try:
                from src.classification.engine import ClassificationEngine
                from src.classification.heuristics import (
                    HeuristicsEngine,
                    create_checker_for_engine,
                )

                self._classification_engine = ClassificationEngine(
                    enable_heuristics=True,
                    heuristic_threshold=0.6,
                )

                # Load signatures from config directory
                signatures_path = Path(self.config.config_dir) / "signatures"
                if not signatures_path.exists():
                    # Try data/signatures relative to project root
                    signatures_path = Path(__file__).parent.parent.parent / "data" / "signatures"

                if signatures_path.exists():
                    count = self._classification_engine.load_signatures(signatures_path)
                    self.logger.info(f"Loaded {count} signatures from {signatures_path}")

                # Register heuristics checker
                heuristics_engine = HeuristicsEngine()
                checker = create_checker_for_engine(heuristics_engine)
                self._classification_engine.register_heuristic(checker)
                self.logger.debug("Registered heuristics checker")

            except ImportError as e:
                self.logger.warning(f"Classification engine not available: {e}")
                self._classification_engine = None

        return self._classification_engine

    def classify_components(self, components: list[Component]) -> list[Component]:
        """Classify a list of components.

        Args:
            components: List of components to classify.

        Returns:
            The same list with classifications applied.
        """
        engine = self._get_classification_engine()
        if engine is None:
            self.logger.warning("Classification engine not available, skipping classification")
            return components

        classified_count = 0
        for component in components:
            try:
                decision = engine.classify(component)
                component.classification = decision.classification
                if decision.classification != Classification.UNKNOWN:
                    classified_count += 1
            except Exception as e:
                self.logger.debug(f"Classification error for {component.name}: {e}")

        self.logger.info(f"Classified {classified_count}/{len(components)} components")
        return components
