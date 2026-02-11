"""Integration tests for ServicesScanner against real Windows."""

import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Requires Windows",
)


class TestServicesScannerLive:
    """Test ServicesScanner against real Windows APIs."""

    def test_scanner_is_available(self):
        """Scanner should report available on Windows."""
        from src.discovery.services import ServicesScanner

        scanner = ServicesScanner()
        assert scanner.is_available() is True

    def test_scan_discovers_services(self):
        """Scan should discover Windows services."""
        from src.discovery.services import ServicesScanner

        scanner = ServicesScanner()
        components = scanner.scan()

        # Every Windows installation has many services
        assert len(components) > 10, "Expected to find many services"

    def test_known_services_found(self):
        """Should find well-known Windows services."""
        from src.discovery.services import ServicesScanner

        scanner = ServicesScanner()
        components = scanner.scan()

        service_names = {c.name.lower() for c in components}
        # These services exist on virtually every Windows installation
        known = {"wuauserv", "bits", "wsearch", "spooler"}
        found = known & service_names
        assert len(found) >= 2, f"Expected known services, found: {found}"

    def test_service_metadata_populated(self):
        """Services should have metadata like startup_type."""
        from src.discovery.services import ServicesScanner

        scanner = ServicesScanner()
        components = scanner.scan()

        for comp in components[:5]:
            assert comp.display_name, f"Missing display_name: {comp.name}"
