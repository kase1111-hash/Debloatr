"""Integration tests for the full scan pipeline on real Windows."""

import sys
import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Requires Windows",
)


class TestScanPipelineLive:
    """Test the orchestrator-driven scan pipeline end-to-end."""

    def test_full_scan_completes(self, real_config):
        """Full scan through orchestrator should complete."""
        from src.core.orchestrator import ScanOrchestrator

        orchestrator = ScanOrchestrator(real_config)

        registered = orchestrator.get_registered_modules()
        assert len(registered) > 0, "Expected at least one registered module"

        result = orchestrator.run_scan()

        assert result.total_count > 0, "Expected scan to find components"
        assert result.scan_time_ms > 0, "Expected nonzero scan time"
        assert len(result.module_results) > 0, "Expected module results"

        # Print summary for manual review
        print(f"\nScan completed in {result.scan_time_ms:.0f}ms")
        print(f"Total components: {result.total_count}")
        for mr in result.module_results:
            status = f"{len(mr.components)} found" if not mr.error else f"ERROR: {mr.error}"
            print(f"  {mr.module_name}: {status}")

    def test_scan_with_module_filter(self, real_config):
        """Scan with specific module filter should work."""
        from src.core.orchestrator import ScanOrchestrator

        orchestrator = ScanOrchestrator(real_config)

        # Scan only programs
        result = orchestrator.run_scan(modules=["programs"])

        assert len(result.module_results) == 1
        assert result.module_results[0].module_name == "programs"

    def test_scan_with_classification(self, real_config):
        """Scan should produce classified components."""
        from src.core.models import Classification
        from src.core.orchestrator import ScanOrchestrator

        orchestrator = ScanOrchestrator(real_config)
        result = orchestrator.run_scan(modules=["programs"])

        classified = [
            c for c in result.all_components
            if c.classification != Classification.UNKNOWN
        ]
        print(f"\nClassified {len(classified)} of {result.total_count} components")

    def test_progress_callback(self, real_config):
        """Progress callback should be called during scan."""
        from src.core.orchestrator import ScanOrchestrator

        orchestrator = ScanOrchestrator(real_config)

        progress_calls = []

        def on_progress(module: str, current: int, total: int):
            progress_calls.append((module, current, total))

        orchestrator.run_scan(progress_callback=on_progress)

        assert len(progress_calls) > 0, "Expected progress callbacks"
