"""Integration tests for ProgramsScanner against real Windows.

These tests run without mocks — they execute actual registry reads
and PowerShell commands to validate the scanner works on real systems.
"""

import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Requires Windows",
)


class TestProgramsScannerLive:
    """Test ProgramsScanner against real Windows APIs."""

    def test_scanner_is_available(self):
        """Scanner should report available on Windows."""
        from src.discovery.programs import ProgramsScanner

        scanner = ProgramsScanner(scan_portable=False)
        assert scanner.is_available() is True

    def test_scan_discovers_programs(self):
        """Scan should discover at least some installed programs."""
        from src.discovery.programs import ProgramsScanner

        scanner = ProgramsScanner(scan_uwp=False, scan_portable=False)
        components = scanner.scan()

        # Every Windows installation has at least a few programs
        assert len(components) > 0, "Expected to find installed programs"

    def test_scan_discovers_uwp_apps(self):
        """Scan should discover UWP/Store apps."""
        from src.discovery.programs import ProgramsScanner

        scanner = ProgramsScanner(scan_uwp=True, scan_portable=False)
        components = scanner.scan()

        uwp_apps = [c for c in components if c.metadata.get("is_uwp")]
        # Windows 10/11 always has UWP apps
        assert len(uwp_apps) > 0, "Expected to find UWP apps"

    def test_component_fields_populated(self):
        """Discovered components should have basic fields set."""
        from src.core.models import ComponentType
        from src.discovery.programs import ProgramsScanner

        scanner = ProgramsScanner(scan_uwp=False, scan_portable=False)
        components = scanner.scan()

        for comp in components[:10]:  # Check first 10
            assert comp.component_type == ComponentType.PROGRAM
            assert comp.display_name, f"Missing display_name for {comp.name}"
            assert comp.id, f"Missing id for {comp.name}"

    def test_scan_with_all_options(self):
        """Full scan with all options enabled should not crash."""
        from src.discovery.programs import ProgramsScanner

        scanner = ProgramsScanner(
            scan_uwp=True,
            scan_portable=True,
            calculate_sizes=True,
        )
        # Should complete without exception
        components = scanner.scan()
        assert isinstance(components, list)
