"""Tests for the drivers scanner."""

import sys
from pathlib import Path

import pytest

from src.core.models import ComponentType
from src.discovery.drivers import (
    DriversScanner,
    DriverType,
    SignatureStatus,
    SystemDriver,
    get_drivers_by_type,
    get_third_party_drivers,
)


class TestDriverType:
    """Tests for DriverType enum."""

    def test_from_string(self):
        """Test DriverType from string."""
        assert DriverType.from_string("Kernel") == DriverType.KERNEL
        assert DriverType.from_string("kernel") == DriverType.KERNEL
        assert DriverType.from_string("FileSystem") == DriverType.FILESYSTEM
        assert DriverType.from_string("File System Filter") == DriverType.FILESYSTEM
        assert DriverType.from_string("User") == DriverType.USER
        assert DriverType.from_string("Boot") == DriverType.BOOT
        assert DriverType.from_string("Unknown Type") == DriverType.UNKNOWN


class TestSignatureStatus:
    """Tests for SignatureStatus enum."""

    def test_from_bool(self):
        """Test SignatureStatus from boolean."""
        assert SignatureStatus.from_bool(True) == SignatureStatus.VALID
        assert SignatureStatus.from_bool(False) == SignatureStatus.UNSIGNED
        assert SignatureStatus.from_bool(None) == SignatureStatus.UNKNOWN


class TestSystemDriver:
    """Tests for SystemDriver dataclass."""

    def test_basic_creation(self):
        """Test basic SystemDriver creation."""
        driver = SystemDriver(
            component_type=ComponentType.DRIVER,
            name="test-driver",
            display_name="Test Driver",
            publisher="Test Publisher",
            driver_name="testdrv",
        )

        assert driver.name == "test-driver"
        assert driver.driver_name == "testdrv"
        assert driver.component_type == ComponentType.DRIVER
        assert driver.driver_type == DriverType.UNKNOWN
        assert driver.signature_status == SignatureStatus.UNKNOWN

    def test_microsoft_signed_driver(self):
        """Test Microsoft-signed driver."""
        driver = SystemDriver(
            component_type=ComponentType.DRIVER,
            name="win-driver",
            display_name="Windows Driver",
            publisher="Microsoft",
            driver_name="windrv",
            signer="Microsoft Windows",
            signature_status=SignatureStatus.VALID,
            is_microsoft_signed=True,
            is_inbox_driver=True,
        )

        assert driver.is_microsoft_signed is True
        assert driver.is_inbox_driver is True
        assert driver.signature_status == SignatureStatus.VALID

    def test_third_party_driver(self):
        """Test third-party driver."""
        driver = SystemDriver(
            component_type=ComponentType.DRIVER,
            name="nvidia-driver",
            display_name="NVIDIA Display Driver",
            publisher="NVIDIA Corporation",
            driver_name="nvlddmkm",
            driver_type=DriverType.KERNEL,
            signer="NVIDIA Corporation",
            signature_status=SignatureStatus.VALID,
            is_microsoft_signed=False,
            driver_path=Path("C:/Windows/System32/drivers/nvlddmkm.sys"),
        )

        assert driver.is_microsoft_signed is False
        assert driver.driver_type == DriverType.KERNEL
        assert driver.driver_path is not None

    def test_overlay_injector_driver(self):
        """Test overlay injector detection."""
        driver = SystemDriver(
            component_type=ComponentType.DRIVER,
            name="gameoverlay",
            display_name="Game Overlay Driver",
            publisher="Gaming Corp",
            driver_name="gameoverlay",
            is_overlay_injector=True,
        )

        assert driver.is_overlay_injector is True

    def test_full_driver_details(self):
        """Test driver with all details."""
        driver = SystemDriver(
            component_type=ComponentType.DRIVER,
            name="full-driver",
            display_name="Full Driver",
            publisher="Full Corp",
            driver_name="fulldrv",
            driver_type=DriverType.KERNEL,
            signer="Full Corp",
            signature_status=SignatureStatus.VALID,
            associated_hardware=["PCI\\VEN_1234&DEV_5678"],
            load_order="Network",
            is_running=True,
            driver_path=Path("C:/Windows/System32/drivers/fulldrv.sys"),
            driver_version="1.2.3.4",
            driver_date="2024-01-15",
            inf_name="fulldrv.inf",
        )

        assert driver.driver_version == "1.2.3.4"
        assert len(driver.associated_hardware) == 1
        assert driver.is_running is True


class TestDriversScanner:
    """Tests for DriversScanner."""

    def test_module_name(self):
        """Test module name is correct."""
        scanner = DriversScanner()
        assert scanner.get_module_name() == "drivers"

    def test_module_description(self):
        """Test module description."""
        scanner = DriversScanner()
        desc = scanner.get_description()
        assert "driver" in desc.lower()

    def test_requires_admin(self):
        """Test admin requirement."""
        scanner = DriversScanner()
        assert scanner.requires_admin() is True

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_is_available_on_windows(self):
        """Test availability on Windows."""
        scanner = DriversScanner()
        assert scanner.is_available() is True

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows only")
    def test_is_not_available_on_non_windows(self):
        """Test unavailability on non-Windows."""
        scanner = DriversScanner()
        assert scanner.is_available() is False

    def test_scanner_options(self):
        """Test scanner initialization options."""
        scanner = DriversScanner(
            include_microsoft_drivers=True,
            include_inbox_drivers=True,
            detect_overlay_injectors=False,
        )

        assert scanner.include_microsoft_drivers is True
        assert scanner.include_inbox_drivers is True
        assert scanner.detect_overlay_injectors is False

    def test_is_microsoft_provider(self):
        """Test Microsoft provider detection."""
        scanner = DriversScanner()

        assert scanner._is_microsoft_provider("Microsoft Corporation") is True
        assert scanner._is_microsoft_provider("Microsoft Windows") is True
        assert scanner._is_microsoft_provider("Windows") is True
        assert scanner._is_microsoft_provider("NVIDIA Corporation") is False
        assert scanner._is_microsoft_provider("") is False

    def test_normalize_name(self):
        """Test name normalization."""
        scanner = DriversScanner()

        assert scanner._normalize_name("Test Driver") == "test-driver"
        assert scanner._normalize_name("Test_Driver-v2") == "test_driver-v2"

    def test_check_overlay_injector(self):
        """Test overlay injector detection."""
        scanner = DriversScanner()

        # Test overlay detection
        driver = SystemDriver(
            component_type=ComponentType.DRIVER,
            name="steam-overlay",
            display_name="Steam Overlay",
            publisher="Valve",
            driver_name="steamoverlay",
        )
        scanner._check_overlay_injector(driver)
        assert driver.is_overlay_injector is True

        # Test non-overlay
        driver2 = SystemDriver(
            component_type=ComponentType.DRIVER,
            name="normal-driver",
            display_name="Normal Driver",
            publisher="Normal Corp",
            driver_name="normaldrv",
        )
        scanner._check_overlay_injector(driver2)
        assert driver2.is_overlay_injector is False

    def test_check_overlay_injector_by_path(self):
        """Test overlay injector detection by path."""
        scanner = DriversScanner()

        driver = SystemDriver(
            component_type=ComponentType.DRIVER,
            name="some-driver",
            display_name="Some Driver",
            publisher="Gaming Corp",
            driver_name="somedrv",
            driver_path=Path("C:/Program Files/Game/overlay/hook.sys"),
        )
        scanner._check_overlay_injector(driver)
        assert driver.is_overlay_injector is True

    def test_is_problematic_publisher(self):
        """Test problematic publisher detection."""
        scanner = DriversScanner()

        driver = SystemDriver(
            component_type=ComponentType.DRIVER,
            name="winring0",
            display_name="WinRing0 Driver",
            publisher="WinRing0",
            driver_name="winring0",
            signer="WinRing0",
        )
        assert scanner.is_problematic_publisher(driver) is True

        driver2 = SystemDriver(
            component_type=ComponentType.DRIVER,
            name="normal",
            display_name="Normal Driver",
            publisher="Normal Corp",
            driver_name="normal",
            signer="Normal Corp",
        )
        assert scanner.is_problematic_publisher(driver2) is False


class TestDriversScannerMocked:
    """Tests for DriversScanner with mocked APIs."""

    def test_process_driver(self):
        """Test processing raw driver data."""
        scanner = DriversScanner()

        raw = {
            "Driver": "testdrv.inf",
            "OriginalFileName": "C:\\Windows\\System32\\drivers\\testdrv.sys",
            "ClassName": "Kernel Driver",
            "ClassDescription": "Test Kernel Driver",
            "ProviderName": "Test Corp",
            "Date": "2024-01-15",
            "Version": "1.0.0.0",
            "Inbox": False,
        }

        driver = scanner._process_driver(raw)

        assert driver is not None
        assert driver.display_name == "Test Kernel Driver"
        assert driver.driver_type == DriverType.KERNEL
        assert driver.is_inbox_driver is False
        assert driver.driver_version == "1.0.0.0"

    def test_process_driver_inbox(self):
        """Test processing inbox driver."""
        scanner = DriversScanner()

        raw = {
            "Driver": "windriver.inf",
            "OriginalFileName": "C:\\Windows\\System32\\drivers\\windriver.sys",
            "ClassName": "System",
            "ProviderName": "Microsoft",
            "Inbox": True,
        }

        driver = scanner._process_driver(raw)

        assert driver is not None
        assert driver.is_inbox_driver is True
        assert driver.is_microsoft_signed is True

    def test_process_driver_minimal(self):
        """Test processing driver with minimal data."""
        scanner = DriversScanner()

        raw = {
            "Driver": "minimal.inf",
        }

        driver = scanner._process_driver(raw)

        assert driver is not None
        assert driver.driver_name == "minimal.inf"

    def test_process_driver_empty(self):
        """Test processing empty driver data."""
        scanner = DriversScanner()

        assert scanner._process_driver({}) is None
        assert scanner._process_driver({"Driver": ""}) is None

    def test_get_unsigned_drivers(self):
        """Test filtering unsigned drivers."""
        scanner = DriversScanner()

        drivers = [
            SystemDriver(
                component_type=ComponentType.DRIVER,
                name="signed",
                display_name="Signed",
                publisher="Test",
                driver_name="signed",
                signature_status=SignatureStatus.VALID,
            ),
            SystemDriver(
                component_type=ComponentType.DRIVER,
                name="unsigned",
                display_name="Unsigned",
                publisher="Test",
                driver_name="unsigned",
                signature_status=SignatureStatus.UNSIGNED,
            ),
        ]

        unsigned = scanner.get_unsigned_drivers(drivers)
        assert len(unsigned) == 1
        assert unsigned[0].driver_name == "unsigned"

    def test_get_overlay_injectors(self):
        """Test filtering overlay injectors."""
        scanner = DriversScanner()

        drivers = [
            SystemDriver(
                component_type=ComponentType.DRIVER,
                name="normal",
                display_name="Normal",
                publisher="Test",
                driver_name="normal",
                is_overlay_injector=False,
            ),
            SystemDriver(
                component_type=ComponentType.DRIVER,
                name="overlay",
                display_name="Overlay",
                publisher="Test",
                driver_name="overlay",
                is_overlay_injector=True,
            ),
        ]

        overlays = scanner.get_overlay_injectors(drivers)
        assert len(overlays) == 1
        assert overlays[0].driver_name == "overlay"


class TestDriverHelperFunctions:
    """Tests for driver helper functions."""

    def test_get_drivers_by_type(self):
        """Test filtering drivers by type."""
        drivers = [
            SystemDriver(
                component_type=ComponentType.DRIVER,
                name="kernel1",
                display_name="Kernel1",
                publisher="Test",
                driver_name="kernel1",
                driver_type=DriverType.KERNEL,
            ),
            SystemDriver(
                component_type=ComponentType.DRIVER,
                name="fs",
                display_name="FS",
                publisher="Test",
                driver_name="fs",
                driver_type=DriverType.FILESYSTEM,
            ),
            SystemDriver(
                component_type=ComponentType.DRIVER,
                name="kernel2",
                display_name="Kernel2",
                publisher="Test",
                driver_name="kernel2",
                driver_type=DriverType.KERNEL,
            ),
        ]

        kernel = get_drivers_by_type(drivers, DriverType.KERNEL)
        assert len(kernel) == 2

        fs = get_drivers_by_type(drivers, DriverType.FILESYSTEM)
        assert len(fs) == 1

    def test_get_third_party_drivers(self):
        """Test filtering third-party drivers."""
        drivers = [
            SystemDriver(
                component_type=ComponentType.DRIVER,
                name="ms",
                display_name="MS",
                publisher="Microsoft",
                driver_name="ms",
                is_microsoft_signed=True,
                is_inbox_driver=True,
            ),
            SystemDriver(
                component_type=ComponentType.DRIVER,
                name="third",
                display_name="Third",
                publisher="Third Corp",
                driver_name="third",
                is_microsoft_signed=False,
                is_inbox_driver=False,
            ),
        ]

        third_party = get_third_party_drivers(drivers)
        assert len(third_party) == 1
        assert third_party[0].driver_name == "third"


class TestDriversScannerIntegration:
    """Integration tests for DriversScanner (Windows only)."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_scan_returns_list(self):
        """Test that scan returns a list on Windows."""
        scanner = DriversScanner(
            include_microsoft_drivers=False,
            include_inbox_drivers=False,
        )
        result = scanner.scan()

        assert isinstance(result, list)

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows only")
    def test_scan_returns_empty_on_non_windows(self):
        """Test that scan returns empty list on non-Windows."""
        scanner = DriversScanner()
        result = scanner.scan()

        assert result == []
