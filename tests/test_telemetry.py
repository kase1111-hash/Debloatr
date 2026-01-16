"""Tests for the telemetry scanner."""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.core.models import ComponentType
from src.discovery.telemetry import (
    TelemetryComponent,
    TelemetryScanner,
    ConnectionType,
    EndpointCategory,
    NetworkEndpoint,
    get_components_by_category,
    get_advertising_components,
    MICROSOFT_TELEMETRY_ENDPOINTS,
    THIRD_PARTY_TELEMETRY_ENDPOINTS,
    ADVERTISING_ENDPOINTS,
    TELEMETRY_PROCESS_NAMES,
)


class TestConnectionType:
    """Tests for ConnectionType enum."""

    def test_enum_values(self):
        """Test enum values exist."""
        assert ConnectionType.PERSISTENT.value == "Persistent"
        assert ConnectionType.PERIODIC.value == "Periodic"
        assert ConnectionType.ON_DEMAND.value == "OnDemand"
        assert ConnectionType.UNKNOWN.value == "Unknown"


class TestEndpointCategory:
    """Tests for EndpointCategory enum."""

    def test_enum_values(self):
        """Test enum values exist."""
        assert EndpointCategory.MICROSOFT.value == "Microsoft"
        assert EndpointCategory.THIRD_PARTY.value == "ThirdParty"
        assert EndpointCategory.ADVERTISING.value == "Advertising"
        assert EndpointCategory.ANALYTICS.value == "Analytics"
        assert EndpointCategory.UPDATE.value == "Update"


class TestNetworkEndpoint:
    """Tests for NetworkEndpoint dataclass."""

    def test_basic_creation(self):
        """Test basic NetworkEndpoint creation."""
        endpoint = NetworkEndpoint(
            address="telemetry.microsoft.com",
            port=443,
        )

        assert endpoint.address == "telemetry.microsoft.com"
        assert endpoint.port == 443
        assert endpoint.protocol == "TCP"
        assert endpoint.category == EndpointCategory.UNKNOWN

    def test_full_endpoint(self):
        """Test endpoint with all fields."""
        endpoint = NetworkEndpoint(
            address="telemetry.microsoft.com",
            port=443,
            protocol="TCP",
            hostname="telemetry.microsoft.com",
            category=EndpointCategory.MICROSOFT,
            is_known_telemetry=True,
        )

        assert endpoint.is_known_telemetry is True
        assert endpoint.category == EndpointCategory.MICROSOFT


class TestTelemetryComponent:
    """Tests for TelemetryComponent dataclass."""

    def test_basic_creation(self):
        """Test basic TelemetryComponent creation."""
        component = TelemetryComponent(
            component_type=ComponentType.TELEMETRY,
            name="diagtrack",
            display_name="DiagTrack",
            publisher="Microsoft",
            process_name="DiagTrack",
        )

        assert component.name == "diagtrack"
        assert component.process_name == "DiagTrack"
        assert component.component_type == ComponentType.TELEMETRY
        assert component.connection_type == ConnectionType.UNKNOWN

    def test_component_with_endpoints(self):
        """Test component with network endpoints."""
        endpoints = [
            NetworkEndpoint("telemetry.microsoft.com", 443, category=EndpointCategory.MICROSOFT),
            NetworkEndpoint("watson.microsoft.com", 443, category=EndpointCategory.MICROSOFT),
        ]

        component = TelemetryComponent(
            component_type=ComponentType.TELEMETRY,
            name="telemetry-service",
            display_name="Telemetry Service",
            publisher="Microsoft",
            process_name="TelemetryService",
            remote_endpoints=endpoints,
            is_known_telemetry=True,
            telemetry_category=EndpointCategory.MICROSOFT,
        )

        assert len(component.remote_endpoints) == 2
        assert component.is_known_telemetry is True

    def test_full_component(self):
        """Test component with all details."""
        component = TelemetryComponent(
            component_type=ComponentType.TELEMETRY,
            name="full-telemetry",
            display_name="Full Telemetry",
            publisher="Full Corp",
            process_name="FullTelemetry",
            process_path=Path("C:/Program Files/Full/telemetry.exe"),
            process_id=1234,
            remote_endpoints=[],
            connection_type=ConnectionType.PERSISTENT,
            bytes_sent=1024,
            bytes_received=2048,
            associated_service="FullService",
            associated_program="Full Application",
            is_background_process=True,
            is_known_telemetry=True,
            telemetry_category=EndpointCategory.THIRD_PARTY,
        )

        assert component.process_id == 1234
        assert component.bytes_sent == 1024
        assert component.is_background_process is True


class TestTelemetryScanner:
    """Tests for TelemetryScanner."""

    def test_module_name(self):
        """Test module name is correct."""
        scanner = TelemetryScanner()
        assert scanner.get_module_name() == "telemetry"

    def test_module_description(self):
        """Test module description."""
        scanner = TelemetryScanner()
        desc = scanner.get_description()
        assert "telemetry" in desc.lower()

    def test_requires_admin(self):
        """Test admin requirement."""
        scanner = TelemetryScanner()
        assert scanner.requires_admin() is True

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_is_available_on_windows(self):
        """Test availability on Windows."""
        scanner = TelemetryScanner()
        assert scanner.is_available() is True

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows only")
    def test_is_not_available_on_non_windows(self):
        """Test unavailability on non-Windows."""
        scanner = TelemetryScanner()
        assert scanner.is_available() is False

    def test_scanner_options(self):
        """Test scanner initialization options."""
        scanner = TelemetryScanner(
            include_microsoft_telemetry=False,
            include_update_connections=True,
            minimum_connections=5,
        )

        assert scanner.include_microsoft_telemetry is False
        assert scanner.include_update_connections is True
        assert scanner.minimum_connections == 5

    def test_check_endpoint_microsoft(self):
        """Test Microsoft endpoint detection."""
        scanner = TelemetryScanner()

        is_telemetry, category = scanner._check_endpoint("telemetry.microsoft.com")
        assert is_telemetry is True
        assert category == EndpointCategory.MICROSOFT

        is_telemetry, category = scanner._check_endpoint("watson.microsoft.com")
        assert is_telemetry is True
        assert category == EndpointCategory.MICROSOFT

    def test_check_endpoint_third_party(self):
        """Test third-party endpoint detection."""
        scanner = TelemetryScanner()

        is_telemetry, category = scanner._check_endpoint("telemetry.nvidia.com")
        assert is_telemetry is True
        assert category == EndpointCategory.THIRD_PARTY

        is_telemetry, category = scanner._check_endpoint("google-analytics.com")
        assert is_telemetry is True
        assert category == EndpointCategory.THIRD_PARTY

    def test_check_endpoint_advertising(self):
        """Test advertising endpoint detection."""
        scanner = TelemetryScanner()

        is_telemetry, category = scanner._check_endpoint("ads.google.com")
        assert is_telemetry is True
        assert category == EndpointCategory.ADVERTISING

        is_telemetry, category = scanner._check_endpoint("ad.doubleclick.net")
        assert is_telemetry is True
        assert category == EndpointCategory.ADVERTISING

    def test_check_endpoint_unknown(self):
        """Test unknown endpoint."""
        scanner = TelemetryScanner()

        is_telemetry, category = scanner._check_endpoint("www.example.com")
        assert is_telemetry is False
        assert category == EndpointCategory.UNKNOWN

    def test_check_endpoint_pattern_match(self):
        """Test pattern-based endpoint detection."""
        scanner = TelemetryScanner()

        is_telemetry, category = scanner._check_endpoint("some-analytics-service.com")
        assert is_telemetry is True
        assert category == EndpointCategory.ANALYTICS

        is_telemetry, category = scanner._check_endpoint("crash-report.example.com")
        assert is_telemetry is True

    def test_is_known_telemetry_process(self):
        """Test known telemetry process detection."""
        scanner = TelemetryScanner()

        assert scanner._is_known_telemetry_process("DiagTrack") is True
        assert scanner._is_known_telemetry_process("diagtrack") is True
        assert scanner._is_known_telemetry_process("CompatTelRunner") is True
        assert scanner._is_known_telemetry_process("NvTelemetryContainer") is True
        assert scanner._is_known_telemetry_process("notepad") is False

    def test_detect_publisher(self):
        """Test publisher detection."""
        scanner = TelemetryScanner()

        assert scanner._detect_publisher("DiagTrack", "C:\\Windows\\System32\\diagtrack.exe") == "Microsoft"
        assert scanner._detect_publisher("NvContainer", "C:\\Program Files\\NVIDIA\\container.exe") == "NVIDIA"
        assert scanner._detect_publisher("ChromeUpdate", "C:\\Program Files\\Google\\update.exe") == "Google"
        assert scanner._detect_publisher("SomeApp", "C:\\Apps\\someapp.exe") == "Unknown"

    def test_normalize_name(self):
        """Test name normalization."""
        scanner = TelemetryScanner()

        assert scanner._normalize_name("DiagTrack") == "diagtrack"
        assert scanner._normalize_name("Some Process") == "some-process"

    def test_is_telemetry_endpoint(self):
        """Test public telemetry endpoint check."""
        scanner = TelemetryScanner()

        assert scanner.is_telemetry_endpoint("telemetry.microsoft.com") is True
        assert scanner.is_telemetry_endpoint("www.google.com") is False

    def test_get_known_telemetry_endpoints(self):
        """Test getting known endpoints."""
        scanner = TelemetryScanner()
        endpoints = scanner.get_known_telemetry_endpoints()

        assert "microsoft" in endpoints
        assert "third_party" in endpoints
        assert "advertising" in endpoints
        assert len(endpoints["microsoft"]) > 0


class TestTelemetryScannerMocked:
    """Tests for TelemetryScanner with mocked APIs."""

    def test_process_connections_telemetry(self):
        """Test processing connections with telemetry."""
        scanner = TelemetryScanner()

        connections = [
            {
                "ProcessName": "DiagTrack",
                "ProcessPath": "C:\\Windows\\System32\\diagtrack.exe",
                "RemoteAddress": "telemetry.microsoft.com",
                "RemotePort": 443,
            },
        ]

        component = scanner._process_connections(1234, connections)

        assert component is not None
        assert component.process_name == "DiagTrack"
        assert component.is_known_telemetry is True
        assert len(component.remote_endpoints) >= 1

    def test_process_connections_localhost_skipped(self):
        """Test that localhost connections are skipped."""
        scanner = TelemetryScanner()

        connections = [
            {
                "ProcessName": "SomeApp",
                "ProcessPath": "C:\\Apps\\someapp.exe",
                "RemoteAddress": "127.0.0.1",
                "RemotePort": 8080,
            },
        ]

        component = scanner._process_connections(1234, connections)

        # Should be None since no external telemetry connections
        assert component is None

    def test_process_connections_non_telemetry(self):
        """Test processing non-telemetry connections."""
        scanner = TelemetryScanner()

        connections = [
            {
                "ProcessName": "notepad",
                "ProcessPath": "C:\\Windows\\notepad.exe",
                "RemoteAddress": "www.example.com",
                "RemotePort": 80,
            },
        ]

        component = scanner._process_connections(1234, connections)

        # Should be None since not a telemetry connection
        assert component is None

    def test_process_connections_empty(self):
        """Test processing empty connections."""
        scanner = TelemetryScanner()

        component = scanner._process_connections(1234, [])
        assert component is None

    def test_process_connections_no_process_name(self):
        """Test processing connections without process name."""
        scanner = TelemetryScanner()

        connections = [
            {
                "ProcessName": "",
                "RemoteAddress": "telemetry.microsoft.com",
                "RemotePort": 443,
            },
        ]

        component = scanner._process_connections(1234, connections)
        assert component is None


class TestTelemetryHelperFunctions:
    """Tests for telemetry helper functions."""

    def test_get_components_by_category(self):
        """Test filtering components by category."""
        components = [
            TelemetryComponent(
                component_type=ComponentType.TELEMETRY,
                name="ms", display_name="MS", publisher="Microsoft",
                process_name="ms",
                telemetry_category=EndpointCategory.MICROSOFT,
            ),
            TelemetryComponent(
                component_type=ComponentType.TELEMETRY,
                name="ad", display_name="Ad", publisher="Ads",
                process_name="ad",
                telemetry_category=EndpointCategory.ADVERTISING,
            ),
            TelemetryComponent(
                component_type=ComponentType.TELEMETRY,
                name="ms2", display_name="MS2", publisher="Microsoft",
                process_name="ms2",
                telemetry_category=EndpointCategory.MICROSOFT,
            ),
        ]

        ms_components = get_components_by_category(components, EndpointCategory.MICROSOFT)
        assert len(ms_components) == 2

        ad_components = get_components_by_category(components, EndpointCategory.ADVERTISING)
        assert len(ad_components) == 1

    def test_get_advertising_components(self):
        """Test filtering advertising components."""
        components = [
            TelemetryComponent(
                component_type=ComponentType.TELEMETRY,
                name="normal", display_name="Normal", publisher="Test",
                process_name="normal",
                telemetry_category=EndpointCategory.MICROSOFT,
            ),
            TelemetryComponent(
                component_type=ComponentType.TELEMETRY,
                name="ads", display_name="Ads", publisher="Ads",
                process_name="ads",
                telemetry_category=EndpointCategory.ADVERTISING,
            ),
            TelemetryComponent(
                component_type=ComponentType.TELEMETRY,
                name="mixed", display_name="Mixed", publisher="Test",
                process_name="mixed",
                telemetry_category=EndpointCategory.ANALYTICS,
                remote_endpoints=[
                    NetworkEndpoint("ads.google.com", 443, category=EndpointCategory.ADVERTISING),
                ],
            ),
        ]

        ad_components = get_advertising_components(components)
        assert len(ad_components) == 2


class TestKnownEndpoints:
    """Tests for known endpoint lists."""

    def test_microsoft_endpoints_not_empty(self):
        """Test Microsoft endpoints list is populated."""
        assert len(MICROSOFT_TELEMETRY_ENDPOINTS) > 10

    def test_third_party_endpoints_not_empty(self):
        """Test third-party endpoints list is populated."""
        assert len(THIRD_PARTY_TELEMETRY_ENDPOINTS) > 5

    def test_advertising_endpoints_not_empty(self):
        """Test advertising endpoints list is populated."""
        assert len(ADVERTISING_ENDPOINTS) > 5

    def test_telemetry_process_names_not_empty(self):
        """Test telemetry process names list is populated."""
        assert len(TELEMETRY_PROCESS_NAMES) > 5
        assert "DiagTrack" in TELEMETRY_PROCESS_NAMES


class TestTelemetryScannerIntegration:
    """Integration tests for TelemetryScanner (Windows only)."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_scan_returns_list(self):
        """Test that scan returns a list on Windows."""
        scanner = TelemetryScanner(
            include_microsoft_telemetry=True,
            minimum_connections=1,
        )
        result = scanner.scan()

        assert isinstance(result, list)

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows only")
    def test_scan_returns_empty_on_non_windows(self):
        """Test that scan returns empty list on non-Windows."""
        scanner = TelemetryScanner()
        result = scanner.scan()

        assert result == []
