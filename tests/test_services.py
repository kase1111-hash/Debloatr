"""Tests for the Windows services scanner."""

import sys
from pathlib import Path

import pytest

from src.core.models import ComponentType
from src.discovery.services import (
    RecoveryAction,
    ServiceAccountType,
    ServicesScanner,
    ServiceStartType,
    ServiceState,
    WindowsService,
    get_service_dependency_chain,
    get_services_by_account,
)


class TestServiceEnums:
    """Tests for service-related enums."""

    def test_start_type_from_int(self):
        """Test ServiceStartType conversion from integers."""
        assert ServiceStartType.from_value(0) == ServiceStartType.BOOT
        assert ServiceStartType.from_value(1) == ServiceStartType.SYSTEM
        assert ServiceStartType.from_value(2) == ServiceStartType.AUTOMATIC
        assert ServiceStartType.from_value(3) == ServiceStartType.MANUAL
        assert ServiceStartType.from_value(4) == ServiceStartType.DISABLED
        assert ServiceStartType.from_value(99) == ServiceStartType.UNKNOWN

    def test_start_type_from_string(self):
        """Test ServiceStartType conversion from strings."""
        assert ServiceStartType.from_value("Boot") == ServiceStartType.BOOT
        assert ServiceStartType.from_value("Auto") == ServiceStartType.AUTOMATIC
        assert ServiceStartType.from_value("Automatic") == ServiceStartType.AUTOMATIC
        assert (
            ServiceStartType.from_value("Automatic (Delayed Start)")
            == ServiceStartType.AUTOMATIC_DELAYED
        )
        assert ServiceStartType.from_value("Manual") == ServiceStartType.MANUAL
        assert ServiceStartType.from_value("Disabled") == ServiceStartType.DISABLED

    def test_service_state_from_string(self):
        """Test ServiceState conversion from strings."""
        assert ServiceState.from_string("Running") == ServiceState.RUNNING
        assert ServiceState.from_string("Stopped") == ServiceState.STOPPED
        assert ServiceState.from_string("Paused") == ServiceState.PAUSED
        assert ServiceState.from_string("running") == ServiceState.RUNNING
        assert ServiceState.from_string("unknown_state") == ServiceState.UNKNOWN

    def test_account_type_from_string(self):
        """Test ServiceAccountType conversion from strings."""
        assert ServiceAccountType.from_string("LocalSystem") == ServiceAccountType.LOCAL_SYSTEM
        assert (
            ServiceAccountType.from_string("NT AUTHORITY\\LocalService")
            == ServiceAccountType.LOCAL_SERVICE
        )
        assert (
            ServiceAccountType.from_string("NT AUTHORITY\\NetworkService")
            == ServiceAccountType.NETWORK_SERVICE
        )
        assert (
            ServiceAccountType.from_string("NT SERVICE\\SomeService")
            == ServiceAccountType.VIRTUAL_ACCOUNT
        )
        assert ServiceAccountType.from_string("DOMAIN\\User") == ServiceAccountType.USER_ACCOUNT
        assert ServiceAccountType.from_string("") == ServiceAccountType.UNKNOWN


class TestRecoveryAction:
    """Tests for RecoveryAction dataclass."""

    def test_basic_creation(self):
        """Test basic RecoveryAction creation."""
        action = RecoveryAction(action_type="restart", delay_ms=60000)

        assert action.action_type == "restart"
        assert action.delay_ms == 60000
        assert action.command == ""

    def test_run_command_action(self):
        """Test RecoveryAction with command."""
        action = RecoveryAction(
            action_type="run_command", delay_ms=30000, command="C:\\Scripts\\restart.bat"
        )

        assert action.action_type == "run_command"
        assert action.command == "C:\\Scripts\\restart.bat"


class TestWindowsService:
    """Tests for WindowsService dataclass."""

    def test_basic_creation(self):
        """Test basic WindowsService creation."""
        service = WindowsService(
            component_type=ComponentType.SERVICE,
            name="test-service",
            display_name="Test Service",
            publisher="Test Publisher",
            service_name="TestService",
        )

        assert service.name == "test-service"
        assert service.display_name == "Test Service"
        assert service.service_name == "TestService"
        assert service.component_type == ComponentType.SERVICE
        assert service.start_type == ServiceStartType.UNKNOWN
        assert service.current_state == ServiceState.UNKNOWN

    def test_full_service_details(self):
        """Test service with all details."""
        recovery = [RecoveryAction("restart", 60000)]

        service = WindowsService(
            component_type=ComponentType.SERVICE,
            name="full-service",
            display_name="Full Service",
            publisher="Full Corp",
            service_name="FullService",
            start_type=ServiceStartType.AUTOMATIC,
            current_state=ServiceState.RUNNING,
            binary_path=Path("C:/Program Files/App/service.exe"),
            account_context="LocalSystem",
            account_type=ServiceAccountType.LOCAL_SYSTEM,
            dependencies=["RpcSs", "EventLog"],
            dependents=["DependentService1"],
            network_ports=[8080, 443],
            has_network_access=True,
            recovery_actions=recovery,
            description="A full test service",
            can_stop=True,
            can_pause=True,
            process_id=1234,
        )

        assert service.start_type == ServiceStartType.AUTOMATIC
        assert service.current_state == ServiceState.RUNNING
        assert service.binary_path == Path("C:/Program Files/App/service.exe")
        assert service.account_type == ServiceAccountType.LOCAL_SYSTEM
        assert len(service.dependencies) == 2
        assert "RpcSs" in service.dependencies
        assert len(service.network_ports) == 2
        assert service.has_network_access is True
        assert service.process_id == 1234

    def test_driver_service(self):
        """Test driver service creation."""
        service = WindowsService(
            component_type=ComponentType.SERVICE,
            name="driver-service",
            display_name="Driver Service",
            publisher="Hardware Corp",
            service_name="DriverSvc",
            is_driver=True,
            start_type=ServiceStartType.BOOT,
        )

        assert service.is_driver is True
        assert service.start_type == ServiceStartType.BOOT


class TestServicesScanner:
    """Tests for ServicesScanner."""

    def test_module_name(self):
        """Test module name is correct."""
        scanner = ServicesScanner()
        assert scanner.get_module_name() == "services"

    def test_module_description(self):
        """Test module description."""
        scanner = ServicesScanner()
        desc = scanner.get_description()
        assert "service" in desc.lower()

    def test_requires_admin(self):
        """Test admin requirement."""
        scanner = ServicesScanner()
        assert scanner.requires_admin() is False

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_is_available_on_windows(self):
        """Test availability on Windows."""
        scanner = ServicesScanner()
        assert scanner.is_available() is True

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows only")
    def test_is_not_available_on_non_windows(self):
        """Test unavailability on non-Windows."""
        scanner = ServicesScanner()
        assert scanner.is_available() is False

    def test_scanner_options(self):
        """Test scanner initialization options."""
        scanner = ServicesScanner(
            include_drivers=True,
            analyze_network=False,
            build_dependency_graph=False,
        )

        assert scanner.include_drivers is True
        assert scanner.analyze_network is False
        assert scanner.build_dependency_graph is False

    def test_parse_binary_path_quoted(self):
        """Test parsing quoted binary paths."""
        scanner = ServicesScanner()

        path = scanner._parse_binary_path('"C:\\Program Files\\App\\service.exe" -arg')
        assert path == Path("C:\\Program Files\\App\\service.exe")

    def test_parse_binary_path_unquoted(self):
        """Test parsing unquoted binary paths."""
        scanner = ServicesScanner()

        path = scanner._parse_binary_path("C:\\Windows\\System32\\svchost.exe -k netsvcs")
        assert path == Path("C:\\Windows\\System32\\svchost.exe")

    def test_parse_binary_path_sys_driver(self):
        """Test parsing driver paths."""
        scanner = ServicesScanner()

        path = scanner._parse_binary_path("C:\\Windows\\System32\\drivers\\driver.sys")
        assert path == Path("C:\\Windows\\System32\\drivers\\driver.sys")

    def test_parse_binary_path_empty(self):
        """Test parsing empty path."""
        scanner = ServicesScanner()
        assert scanner._parse_binary_path("") is None
        assert scanner._parse_binary_path(None) is None

    def test_detect_publisher_microsoft(self):
        """Test detecting Microsoft as publisher."""
        scanner = ServicesScanner()

        path = Path("C:\\Windows\\System32\\svchost.exe")
        publisher = scanner._detect_publisher(path, "Windows Service")

        assert publisher == "Microsoft"

    def test_detect_publisher_nvidia(self):
        """Test detecting NVIDIA as publisher."""
        scanner = ServicesScanner()

        path = Path("C:\\Program Files\\NVIDIA Corporation\\NvContainer\\nvcontainer.exe")
        publisher = scanner._detect_publisher(path, "NVIDIA Container")

        assert publisher == "NVIDIA"

    def test_detect_publisher_unknown(self):
        """Test unknown publisher detection."""
        scanner = ServicesScanner()

        path = Path("C:\\SomeApp\\service.exe")
        publisher = scanner._detect_publisher(path, "Some Service")

        assert publisher == "Unknown"

    def test_critical_services_list(self):
        """Test critical services list."""
        scanner = ServicesScanner()
        critical = scanner.get_critical_services()

        assert "rpcss" in critical
        assert "eventlog" in critical
        assert "wuauserv" in critical
        assert len(critical) > 10

    def test_telemetry_services_list(self):
        """Test telemetry services list."""
        scanner = ServicesScanner()
        telemetry = scanner.get_telemetry_services()

        assert "diagtrack" in telemetry
        assert len(telemetry) > 0

    def test_is_critical_service(self):
        """Test critical service detection."""
        scanner = ServicesScanner()

        assert scanner.is_critical_service("RpcSs") is True
        assert scanner.is_critical_service("rpcss") is True
        assert scanner.is_critical_service("SomeRandomService") is False

    def test_is_telemetry_service(self):
        """Test telemetry service detection."""
        scanner = ServicesScanner()

        assert scanner.is_telemetry_service("DiagTrack") is True
        assert scanner.is_telemetry_service("diagtrack") is True
        assert scanner.is_telemetry_service("SomeService") is False

    def test_parse_delay(self):
        """Test delay parsing from sc.exe output."""
        scanner = ServicesScanner()

        assert scanner._parse_delay("RESTART -- Delay = 60000 milliseconds") == 60000
        assert scanner._parse_delay("RESTART -- Delay = 0 milliseconds") == 0
        assert scanner._parse_delay("RESTART -- no delay info") == 0


class TestServicesScannerMocked:
    """Tests for ServicesScanner with mocked APIs."""

    def test_process_service(self):
        """Test processing raw service data."""
        scanner = ServicesScanner(analyze_network=False)

        raw = {
            "Name": "TestService",
            "DisplayName": "Test Service Display",
            "Description": "A test service",
            "PathName": '"C:\\Program Files\\Test\\service.exe" -run',
            "StartMode": "Auto",
            "State": "Running",
            "StartName": "LocalSystem",
            "ServiceType": "Own Process",
            "ProcessId": 1234,
            "AcceptStop": True,
            "AcceptPause": False,
            "Dependencies": "RpcSs,EventLog",
            "DependentServices": "",
        }

        service = scanner._process_service(raw)

        assert service is not None
        assert service.service_name == "TestService"
        assert service.display_name == "Test Service Display"
        assert service.start_type == ServiceStartType.AUTOMATIC
        assert service.current_state == ServiceState.RUNNING
        assert service.account_type == ServiceAccountType.LOCAL_SYSTEM
        assert "RpcSs" in service.dependencies
        assert service.process_id == 1234

    def test_process_service_driver(self):
        """Test processing a driver service."""
        scanner = ServicesScanner(analyze_network=False)

        raw = {
            "Name": "SomeDriver",
            "DisplayName": "Some Driver",
            "PathName": "C:\\Windows\\System32\\drivers\\somedriver.sys",
            "StartMode": "Boot",
            "State": "Running",
            "StartName": "",
            "ServiceType": "Kernel Driver",
        }

        service = scanner._process_service(raw)

        assert service is not None
        assert service.is_driver is True
        assert service.start_type == ServiceStartType.BOOT

    def test_process_service_minimal(self):
        """Test processing service with minimal data."""
        scanner = ServicesScanner(analyze_network=False)

        raw = {
            "Name": "MinimalService",
        }

        service = scanner._process_service(raw)

        assert service is not None
        assert service.service_name == "MinimalService"
        assert service.display_name == "MinimalService"
        assert service.start_type == ServiceStartType.UNKNOWN

    def test_process_service_empty_name(self):
        """Test processing service with empty name returns None."""
        scanner = ServicesScanner()

        raw = {"Name": ""}
        assert scanner._process_service(raw) is None

        raw = {}
        assert scanner._process_service(raw) is None

    def test_populate_dependents(self):
        """Test dependency graph population."""
        scanner = ServicesScanner()

        services = [
            WindowsService(
                component_type=ComponentType.SERVICE,
                name="svc-a",
                display_name="Service A",
                publisher="Test",
                service_name="SvcA",
                dependencies=["SvcB", "SvcC"],
            ),
            WindowsService(
                component_type=ComponentType.SERVICE,
                name="svc-b",
                display_name="Service B",
                publisher="Test",
                service_name="SvcB",
                dependencies=[],
            ),
            WindowsService(
                component_type=ComponentType.SERVICE,
                name="svc-c",
                display_name="Service C",
                publisher="Test",
                service_name="SvcC",
                dependencies=["SvcB"],
            ),
        ]

        scanner._populate_dependents(services)

        # SvcB should have SvcA and SvcC as dependents
        svc_b = next(s for s in services if s.service_name == "SvcB")
        assert "SvcA" in svc_b.dependents
        assert "SvcC" in svc_b.dependents

        # SvcC should have SvcA as dependent
        svc_c = next(s for s in services if s.service_name == "SvcC")
        assert "SvcA" in svc_c.dependents


class TestDependencyChain:
    """Tests for dependency chain functions."""

    def test_get_dependency_chain_simple(self):
        """Test simple dependency chain."""
        services = [
            WindowsService(
                component_type=ComponentType.SERVICE,
                name="a",
                display_name="A",
                publisher="Test",
                service_name="A",
                dependencies=["B"],
            ),
            WindowsService(
                component_type=ComponentType.SERVICE,
                name="b",
                display_name="B",
                publisher="Test",
                service_name="B",
                dependencies=[],
            ),
        ]

        chain = get_service_dependency_chain(services, "A")

        assert chain == ["B", "A"]

    def test_get_dependency_chain_deep(self):
        """Test deep dependency chain."""
        services = [
            WindowsService(
                component_type=ComponentType.SERVICE,
                name="a",
                display_name="A",
                publisher="Test",
                service_name="A",
                dependencies=["B"],
            ),
            WindowsService(
                component_type=ComponentType.SERVICE,
                name="b",
                display_name="B",
                publisher="Test",
                service_name="B",
                dependencies=["C"],
            ),
            WindowsService(
                component_type=ComponentType.SERVICE,
                name="c",
                display_name="C",
                publisher="Test",
                service_name="C",
                dependencies=[],
            ),
        ]

        chain = get_service_dependency_chain(services, "A")

        assert chain == ["C", "B", "A"]

    def test_get_dependency_chain_no_deps(self):
        """Test service with no dependencies."""
        services = [
            WindowsService(
                component_type=ComponentType.SERVICE,
                name="standalone",
                display_name="Standalone",
                publisher="Test",
                service_name="Standalone",
                dependencies=[],
            ),
        ]

        chain = get_service_dependency_chain(services, "Standalone")

        assert chain == ["Standalone"]

    def test_get_services_by_account(self):
        """Test filtering services by account type."""
        services = [
            WindowsService(
                component_type=ComponentType.SERVICE,
                name="a",
                display_name="A",
                publisher="Test",
                service_name="A",
                account_type=ServiceAccountType.LOCAL_SYSTEM,
            ),
            WindowsService(
                component_type=ComponentType.SERVICE,
                name="b",
                display_name="B",
                publisher="Test",
                service_name="B",
                account_type=ServiceAccountType.NETWORK_SERVICE,
            ),
            WindowsService(
                component_type=ComponentType.SERVICE,
                name="c",
                display_name="C",
                publisher="Test",
                service_name="C",
                account_type=ServiceAccountType.LOCAL_SYSTEM,
            ),
        ]

        local_system = get_services_by_account(services, ServiceAccountType.LOCAL_SYSTEM)

        assert len(local_system) == 2
        assert all(s.account_type == ServiceAccountType.LOCAL_SYSTEM for s in local_system)


class TestServicesScannerIntegration:
    """Integration tests for ServicesScanner (Windows only)."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_scan_returns_list(self):
        """Test that scan returns a list on Windows."""
        scanner = ServicesScanner(
            include_drivers=False,
            analyze_network=False,
        )
        result = scanner.scan()

        assert isinstance(result, list)
        # Should find services on any Windows system
        assert len(result) > 0

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_scan_services_have_required_fields(self):
        """Test that scanned services have required fields."""
        scanner = ServicesScanner(
            include_drivers=False,
            analyze_network=False,
        )
        result = scanner.scan()

        for service in result[:10]:  # Check first 10 services
            assert isinstance(service, WindowsService)
            assert service.service_name, "Service should have a service name"
            assert service.display_name, "Service should have a display name"
            assert service.component_type == ComponentType.SERVICE

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_scan_finds_common_services(self):
        """Test that common Windows services are found."""
        scanner = ServicesScanner(
            include_drivers=False,
            analyze_network=False,
        )
        result = scanner.scan()

        service_names = [s.service_name.lower() for s in result]

        # These services should exist on any Windows system
        assert any("eventlog" in name for name in service_names)

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows only")
    def test_scan_returns_empty_on_non_windows(self):
        """Test that scan returns empty list on non-Windows."""
        scanner = ServicesScanner()
        result = scanner.scan()

        assert result == []
