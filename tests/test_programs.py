"""Tests for the installed programs scanner."""

import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.core.models import ComponentType
from src.discovery.programs import (
    InstalledProgram,
    ProgramsScanner,
)


class TestInstalledProgram:
    """Tests for InstalledProgram dataclass."""

    def test_basic_creation(self):
        """Test basic InstalledProgram creation."""
        program = InstalledProgram(
            component_type=ComponentType.PROGRAM,
            name="test-program",
            display_name="Test Program",
            publisher="Test Publisher",
        )

        assert program.name == "test-program"
        assert program.display_name == "Test Program"
        assert program.publisher == "Test Publisher"
        assert program.is_uwp is False
        assert program.is_portable is False
        assert program.size_bytes == 0

    def test_uwp_program(self):
        """Test UWP program creation."""
        program = InstalledProgram(
            component_type=ComponentType.UWP,
            name="Microsoft.Calculator",
            display_name="Calculator",
            publisher="Microsoft",
            is_uwp=True,
            package_family_name="Microsoft.Calculator_8wekyb3d8bbwe",
        )

        assert program.is_uwp is True
        assert program.component_type == ComponentType.UWP
        assert program.package_family_name == "Microsoft.Calculator_8wekyb3d8bbwe"

    def test_portable_program(self):
        """Test portable program creation."""
        program = InstalledProgram(
            component_type=ComponentType.PROGRAM,
            name="portable-app",
            display_name="Portable App",
            publisher="Unknown",
            is_portable=True,
            install_path=Path("C:/PortableApps/SomeApp"),
        )

        assert program.is_portable is True
        assert program.install_path == Path("C:/PortableApps/SomeApp")

    def test_full_program_details(self):
        """Test program with all details."""
        install_date = datetime(2024, 1, 15)
        executables = [Path("C:/Program Files/App/app.exe")]

        program = InstalledProgram(
            component_type=ComponentType.PROGRAM,
            name="full-app",
            display_name="Full Application",
            publisher="Full Corp",
            install_path=Path("C:/Program Files/App"),
            install_date=install_date,
            size_bytes=1024 * 1024 * 50,  # 50 MB
            version="1.2.3",
            executables=executables,
            uninstall_string="C:/Program Files/App/uninstall.exe",
            quiet_uninstall_string="C:/Program Files/App/uninstall.exe /S",
            update_mechanism="App Update Service",
            registry_key="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\App",
            product_code="{12345678-1234-1234-1234-123456789012}",
        )

        assert program.install_date == install_date
        assert program.size_bytes == 1024 * 1024 * 50
        assert program.version == "1.2.3"
        assert len(program.executables) == 1
        assert program.update_mechanism == "App Update Service"
        assert program.product_code == "{12345678-1234-1234-1234-123456789012}"


class TestProgramsScanner:
    """Tests for ProgramsScanner."""

    def test_module_name(self):
        """Test module name is correct."""
        scanner = ProgramsScanner()
        assert scanner.get_module_name() == "programs"

    def test_module_description(self):
        """Test module description."""
        scanner = ProgramsScanner()
        desc = scanner.get_description()
        assert "programs" in desc.lower()
        assert "UWP" in desc or "uwp" in desc.lower()

    def test_requires_admin(self):
        """Test admin requirement."""
        scanner = ProgramsScanner()
        # Basic scanning doesn't require admin
        assert scanner.requires_admin() is False

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_is_available_on_windows(self):
        """Test availability on Windows."""
        scanner = ProgramsScanner()
        assert scanner.is_available() is True

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows only")
    def test_is_not_available_on_non_windows(self):
        """Test unavailability on non-Windows."""
        scanner = ProgramsScanner()
        assert scanner.is_available() is False

    def test_scanner_options(self):
        """Test scanner initialization options."""
        scanner = ProgramsScanner(
            scan_uwp=False,
            scan_portable=False,
            calculate_sizes=False,
        )

        assert scanner.scan_uwp is False
        assert scanner.scan_portable is False
        assert scanner.calculate_sizes is False

    def test_normalize_name(self):
        """Test name normalization."""
        scanner = ProgramsScanner()

        assert scanner._normalize_name("Test Program") == "test-program"
        assert scanner._normalize_name("Test  Multiple   Spaces") == "test-multiple-spaces"
        assert scanner._normalize_name("Test (Version 1.0)") == "test-version-10"
        assert scanner._normalize_name("Test_Underscore") == "test_underscore"

    def test_format_uwp_display_name(self):
        """Test UWP display name formatting."""
        scanner = ProgramsScanner()

        assert (
            scanner._format_uwp_display_name("Microsoft.WindowsCalculator") == "Windows Calculator"
        )
        assert scanner._format_uwp_display_name("Microsoft.Paint") == "Paint"
        assert scanner._format_uwp_display_name("CompanyName.AppName") == "App Name"

    def test_format_portable_display_name(self):
        """Test portable display name formatting."""
        scanner = ProgramsScanner()

        assert scanner._format_portable_display_name("SomeApp-1.0.0") == "Some App"
        assert scanner._format_portable_display_name("MyProgram_v2") == "My Program v2"
        assert scanner._format_portable_display_name("SimpleApp") == "Simple App"

    def test_detect_update_mechanism(self):
        """Test update mechanism detection."""
        scanner = ProgramsScanner()

        assert scanner._detect_update_mechanism("Google Chrome", "Google", None) == "Google Update"
        assert (
            scanner._detect_update_mechanism("Firefox", "Mozilla", None)
            == "Mozilla Maintenance Service"
        )
        assert (
            scanner._detect_update_mechanism("Adobe Reader", "Adobe", None)
            == "Adobe Update Manager"
        )
        assert scanner._detect_update_mechanism("Notepad++", "Don Ho", None) is None


class TestProgramsScannerMocked:
    """Tests for ProgramsScanner with mocked Windows APIs."""

    @pytest.fixture
    def mock_winreg(self):
        """Create a mock winreg module."""
        mock = MagicMock()

        # Mock registry keys
        mock.HKEY_LOCAL_MACHINE = 0x80000002
        mock.HKEY_CURRENT_USER = 0x80000001
        mock.KEY_READ = 0x20019

        return mock

    def test_parse_uwp_package(self):
        """Test UWP package parsing."""
        scanner = ProgramsScanner(calculate_sizes=False)

        package = {
            "Name": "Microsoft.WindowsCalculator",
            "PackageFullName": "Microsoft.WindowsCalculator_10.0.0.0_x64__8wekyb3d8bbwe",
            "PackageFamilyName": "Microsoft.WindowsCalculator_8wekyb3d8bbwe",
            "Publisher": "CN=Microsoft Corporation, O=Microsoft Corporation",
            "Version": "10.0.0.0",
            "InstallLocation": "C:\\Program Files\\WindowsApps\\Calculator",
            "IsFramework": False,
        }

        result = scanner._parse_uwp_package(package)

        assert result is not None
        assert result.name == "Microsoft.WindowsCalculator"
        assert result.display_name == "Windows Calculator"
        assert result.publisher == "Microsoft Corporation"
        assert result.is_uwp is True
        assert result.version == "10.0.0.0"

    def test_parse_uwp_package_framework(self):
        """Test that framework packages are skipped."""
        scanner = ProgramsScanner()

        package = {
            "Name": "Microsoft.VCLibs.140.00",
            "IsFramework": True,
        }

        result = scanner._parse_uwp_package(package)
        assert result is None

    def test_parse_uwp_package_system(self):
        """Test that system packages are skipped."""
        scanner = ProgramsScanner()

        package = {
            "Name": "Microsoft.NET.Native.Runtime.2.2",
            "IsFramework": False,
        }

        result = scanner._parse_uwp_package(package)
        assert result is None

    def test_calculate_directory_size(self, tmp_path):
        """Test directory size calculation."""
        scanner = ProgramsScanner()

        # Create test files
        (tmp_path / "file1.txt").write_text("Hello")  # 5 bytes
        (tmp_path / "file2.txt").write_text("World!")  # 6 bytes
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "file3.txt").write_text("Test")  # 4 bytes

        size = scanner._calculate_directory_size(tmp_path)

        assert size == 15  # 5 + 6 + 4

    def test_calculate_directory_size_empty(self, tmp_path):
        """Test size calculation for empty directory."""
        scanner = ProgramsScanner()
        size = scanner._calculate_directory_size(tmp_path)
        assert size == 0

    def test_calculate_directory_size_nonexistent(self):
        """Test size calculation for nonexistent directory."""
        scanner = ProgramsScanner()
        size = scanner._calculate_directory_size(Path("/nonexistent/path"))
        assert size == 0

    def test_find_executables(self, tmp_path):
        """Test executable finding."""
        scanner = ProgramsScanner()

        # Create test executables
        (tmp_path / "app.exe").touch()
        (tmp_path / "helper.exe").touch()
        (tmp_path / "readme.txt").touch()
        (tmp_path / "uninstall.exe").touch()  # Should be filtered

        subdir = tmp_path / "bin"
        subdir.mkdir()
        (subdir / "tool.exe").touch()

        executables = scanner._find_executables(tmp_path)

        # Should find app.exe, helper.exe, tool.exe but not uninstall.exe
        exe_names = [e.name for e in executables]
        assert "app.exe" in exe_names
        assert "helper.exe" in exe_names
        assert "tool.exe" in exe_names
        assert "uninstall.exe" not in exe_names
        assert "readme.txt" not in exe_names

    def test_find_executables_empty(self, tmp_path):
        """Test finding executables in empty directory."""
        scanner = ProgramsScanner()
        executables = scanner._find_executables(tmp_path)
        assert executables == []

    def test_check_portable_app_directory(self, tmp_path):
        """Test portable app directory detection."""
        scanner = ProgramsScanner(calculate_sizes=False)

        # Create a portable app structure
        app_dir = tmp_path / "MyPortableApp"
        app_dir.mkdir()
        (app_dir / "MyApp.exe").touch()
        (app_dir / "config.ini").touch()

        result = scanner._check_portable_app_directory(app_dir)

        assert result is not None
        assert result.is_portable is True
        assert "MyPortableApp" in result.name or "myportableapp" in result.name
        assert len(result.executables) > 0

    def test_check_portable_app_directory_no_exe(self, tmp_path):
        """Test that directories without executables are skipped."""
        scanner = ProgramsScanner()

        # Create a directory without executables
        data_dir = tmp_path / "DataFolder"
        data_dir.mkdir()
        (data_dir / "data.txt").touch()

        result = scanner._check_portable_app_directory(data_dir)
        assert result is None


class TestProgramsScannerIntegration:
    """Integration tests for ProgramsScanner (Windows only)."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_scan_returns_list(self):
        """Test that scan returns a list on Windows."""
        scanner = ProgramsScanner(
            scan_uwp=False,
            scan_portable=False,
            calculate_sizes=False,
        )
        result = scanner.scan()

        assert isinstance(result, list)
        # Should find at least some programs on any Windows system
        # (might be 0 in some test environments)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_scan_programs_have_required_fields(self):
        """Test that scanned programs have required fields."""
        scanner = ProgramsScanner(
            scan_uwp=False,
            scan_portable=False,
            calculate_sizes=False,
        )
        result = scanner.scan()

        for program in result[:5]:  # Check first 5 programs
            assert program.name, "Program should have a name"
            assert program.display_name, "Program should have a display name"
            assert program.publisher, "Program should have a publisher"
            assert program.component_type in [ComponentType.PROGRAM, ComponentType.UWP]

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows only")
    def test_scan_returns_empty_on_non_windows(self):
        """Test that scan returns empty list on non-Windows."""
        scanner = ProgramsScanner()
        result = scanner.scan()

        assert result == []
