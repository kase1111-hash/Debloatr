"""Tests for the startup entries scanner."""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.core.models import ComponentType
from src.discovery.startup import (
    StartupEntry,
    StartupScanner,
    StartupEntryType,
    StartupScope,
    get_entries_by_type,
    get_entries_by_scope,
    get_disabled_entries,
    REGISTRY_STARTUP_PATHS,
    WINLOGON_VALUES,
)


class TestStartupEntryType:
    """Tests for StartupEntryType enum."""

    def test_enum_values(self):
        """Test enum values exist."""
        assert StartupEntryType.RUN.value == "Run"
        assert StartupEntryType.RUN_ONCE.value == "RunOnce"
        assert StartupEntryType.SHELL_FOLDER.value == "ShellFolder"
        assert StartupEntryType.WINLOGON.value == "Winlogon"
        assert StartupEntryType.ACTIVE_SETUP.value == "ActiveSetup"


class TestStartupScope:
    """Tests for StartupScope enum."""

    def test_enum_values(self):
        """Test enum values exist."""
        assert StartupScope.MACHINE.value == "Machine"
        assert StartupScope.USER.value == "User"


class TestStartupEntry:
    """Tests for StartupEntry dataclass."""

    def test_basic_creation(self):
        """Test basic StartupEntry creation."""
        entry = StartupEntry(
            component_type=ComponentType.STARTUP,
            name="test-entry",
            display_name="Test Entry",
            publisher="Test Publisher",
            entry_type=StartupEntryType.RUN,
            entry_name="TestEntry",
        )

        assert entry.name == "test-entry"
        assert entry.entry_type == StartupEntryType.RUN
        assert entry.component_type == ComponentType.STARTUP
        assert entry.scope == StartupScope.USER

    def test_registry_entry(self):
        """Test registry-based startup entry."""
        entry = StartupEntry(
            component_type=ComponentType.STARTUP,
            name="reg-entry",
            display_name="Registry Entry",
            publisher="Test",
            entry_type=StartupEntryType.RUN,
            entry_name="RegEntry",
            target_path=Path("C:/Program Files/App/app.exe"),
            arguments="--minimized",
            scope=StartupScope.MACHINE,
            registry_key="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            registry_value="RegEntry",
        )

        assert entry.registry_key == "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        assert entry.scope == StartupScope.MACHINE
        assert entry.target_path == Path("C:/Program Files/App/app.exe")

    def test_folder_entry(self):
        """Test startup folder entry."""
        entry = StartupEntry(
            component_type=ComponentType.STARTUP,
            name="folder-entry",
            display_name="Folder Entry",
            publisher="Test",
            entry_type=StartupEntryType.SHELL_FOLDER,
            entry_name="app.lnk",
            target_path=Path("C:/Program Files/App/app.exe"),
            scope=StartupScope.USER,
            folder_path=Path("C:/Users/User/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"),
        )

        assert entry.entry_type == StartupEntryType.SHELL_FOLDER
        assert entry.folder_path is not None

    def test_full_command_property(self):
        """Test full_command property."""
        entry = StartupEntry(
            component_type=ComponentType.STARTUP,
            name="cmd-entry",
            display_name="Cmd Entry",
            publisher="Test",
            entry_type=StartupEntryType.RUN,
            entry_name="CmdEntry",
            target_path=Path("C:/app.exe"),
            arguments="--arg1 --arg2",
        )

        assert '"C:\\app.exe" --arg1 --arg2' in entry.full_command or "C:\\app.exe --arg1 --arg2" in entry.full_command

    def test_full_command_no_args(self):
        """Test full_command with no arguments."""
        entry = StartupEntry(
            component_type=ComponentType.STARTUP,
            name="no-args",
            display_name="No Args",
            publisher="Test",
            entry_type=StartupEntryType.RUN,
            entry_name="NoArgs",
            target_path=Path("C:/app.exe"),
        )

        assert entry.full_command == "C:\\app.exe"

    def test_full_task_details(self):
        """Test entry with all details."""
        entry = StartupEntry(
            component_type=ComponentType.STARTUP,
            name="full-entry",
            display_name="Full Entry",
            publisher="Full Corp",
            entry_type=StartupEntryType.RUN,
            entry_name="FullEntry",
            target_path=Path("C:/Program Files/Full/full.exe"),
            arguments="--start",
            scope=StartupScope.MACHINE,
            registry_key="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            registry_value="FullEntry",
            is_enabled=True,
            is_approved=False,
            description="A full test entry",
            working_directory=Path("C:/Program Files/Full"),
        )

        assert entry.is_approved is False
        assert entry.working_directory == Path("C:/Program Files/Full")


class TestStartupScanner:
    """Tests for StartupScanner."""

    def test_module_name(self):
        """Test module name is correct."""
        scanner = StartupScanner()
        assert scanner.get_module_name() == "startup"

    def test_module_description(self):
        """Test module description."""
        scanner = StartupScanner()
        desc = scanner.get_description()
        assert "startup" in desc.lower()

    def test_requires_admin(self):
        """Test admin requirement."""
        scanner = StartupScanner()
        assert scanner.requires_admin() is False

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_is_available_on_windows(self):
        """Test availability on Windows."""
        scanner = StartupScanner()
        assert scanner.is_available() is True

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows only")
    def test_is_not_available_on_non_windows(self):
        """Test unavailability on non-Windows."""
        scanner = StartupScanner()
        assert scanner.is_available() is False

    def test_scanner_options(self):
        """Test scanner initialization options."""
        scanner = StartupScanner(
            scan_winlogon=False,
            scan_active_setup=False,
            include_disabled=False,
        )

        assert scanner.scan_winlogon is False
        assert scanner.scan_active_setup is False
        assert scanner.include_disabled is False

    def test_normalize_name(self):
        """Test name normalization."""
        scanner = StartupScanner()

        assert scanner._normalize_name("Test Entry") == "test-entry"
        assert scanner._normalize_name("Test_Entry-v2") == "test_entry-v2"
        assert scanner._normalize_name("Entry (Startup)") == "entry-startup"

    def test_parse_command_line_quoted(self):
        """Test parsing quoted command line."""
        scanner = StartupScanner()

        path, args = scanner._parse_command_line('"C:\\Program Files\\App\\app.exe" --run')

        assert path == Path("C:\\Program Files\\App\\app.exe")
        assert args == "--run"

    def test_parse_command_line_unquoted(self):
        """Test parsing unquoted command line."""
        scanner = StartupScanner()

        path, args = scanner._parse_command_line("C:\\Windows\\System32\\app.exe -silent")

        assert path == Path("C:\\Windows\\System32\\app.exe")
        assert args == "-silent"

    def test_parse_command_line_no_args(self):
        """Test parsing command line without arguments."""
        scanner = StartupScanner()

        path, args = scanner._parse_command_line("C:\\app.exe")

        assert path == Path("C:\\app.exe")
        assert args == ""

    def test_parse_command_line_empty(self):
        """Test parsing empty command line."""
        scanner = StartupScanner()

        path, args = scanner._parse_command_line("")

        assert path is None
        assert args == ""

    def test_detect_publisher_microsoft(self):
        """Test detecting Microsoft as publisher."""
        scanner = StartupScanner()

        publisher = scanner._detect_publisher(Path("C:\\Windows\\System32\\app.exe"))
        assert publisher == "Microsoft"

    def test_detect_publisher_adobe(self):
        """Test detecting Adobe as publisher."""
        scanner = StartupScanner()

        publisher = scanner._detect_publisher(Path("C:\\Program Files\\Adobe\\Reader\\reader.exe"))
        assert publisher == "Adobe"

    def test_detect_publisher_unknown(self):
        """Test unknown publisher detection."""
        scanner = StartupScanner()

        publisher = scanner._detect_publisher(Path("C:\\SomeApp\\app.exe"))
        assert publisher == "Unknown"

    def test_detect_publisher_none(self):
        """Test publisher detection with None path."""
        scanner = StartupScanner()

        publisher = scanner._detect_publisher(None)
        assert publisher == "Unknown"

    def test_is_default_winlogon_shell(self):
        """Test default Winlogon Shell detection."""
        scanner = StartupScanner()

        assert scanner._is_default_winlogon_value("Shell", Path("explorer.exe")) is True
        assert scanner._is_default_winlogon_value("Shell", Path("C:\\Windows\\explorer.exe")) is True
        assert scanner._is_default_winlogon_value("Shell", Path("malware.exe")) is False

    def test_is_default_winlogon_userinit(self):
        """Test default Winlogon Userinit detection."""
        scanner = StartupScanner()

        assert scanner._is_default_winlogon_value("Userinit", Path("userinit.exe")) is True
        assert scanner._is_default_winlogon_value("Userinit", Path("C:\\Windows\\System32\\userinit.exe")) is True
        assert scanner._is_default_winlogon_value("Userinit", Path("malware.exe")) is False


class TestStartupScannerMocked:
    """Tests for StartupScanner with mocked APIs."""

    def test_parse_executable(self, tmp_path):
        """Test parsing executable in startup folder."""
        scanner = StartupScanner()

        exe_path = tmp_path / "app.exe"
        exe_path.touch()

        entry = scanner._parse_executable(exe_path, tmp_path, StartupScope.USER)

        assert entry is not None
        assert entry.entry_type == StartupEntryType.SHELL_FOLDER
        assert entry.target_path == exe_path
        assert entry.scope == StartupScope.USER

    def test_parse_startup_folder_item_exe(self, tmp_path):
        """Test parsing .exe in startup folder."""
        scanner = StartupScanner()

        exe_path = tmp_path / "startup.exe"
        exe_path.touch()

        entry = scanner._parse_startup_folder_item(exe_path, tmp_path, StartupScope.USER)

        assert entry is not None
        assert entry.entry_name == "startup.exe"

    def test_parse_startup_folder_item_bat(self, tmp_path):
        """Test parsing .bat in startup folder."""
        scanner = StartupScanner()

        bat_path = tmp_path / "startup.bat"
        bat_path.touch()

        entry = scanner._parse_startup_folder_item(bat_path, tmp_path, StartupScope.USER)

        assert entry is not None
        assert entry.entry_name == "startup.bat"

    def test_parse_startup_folder_item_unsupported(self, tmp_path):
        """Test parsing unsupported file type."""
        scanner = StartupScanner()

        txt_path = tmp_path / "readme.txt"
        txt_path.touch()

        entry = scanner._parse_startup_folder_item(txt_path, tmp_path, StartupScope.USER)

        assert entry is None


class TestStartupHelperFunctions:
    """Tests for startup helper functions."""

    def test_get_entries_by_type(self):
        """Test filtering entries by type."""
        entries = [
            StartupEntry(
                component_type=ComponentType.STARTUP,
                name="run1", display_name="Run1", publisher="Test",
                entry_type=StartupEntryType.RUN, entry_name="Run1",
            ),
            StartupEntry(
                component_type=ComponentType.STARTUP,
                name="folder1", display_name="Folder1", publisher="Test",
                entry_type=StartupEntryType.SHELL_FOLDER, entry_name="Folder1",
            ),
            StartupEntry(
                component_type=ComponentType.STARTUP,
                name="run2", display_name="Run2", publisher="Test",
                entry_type=StartupEntryType.RUN, entry_name="Run2",
            ),
        ]

        run_entries = get_entries_by_type(entries, StartupEntryType.RUN)
        assert len(run_entries) == 2

        folder_entries = get_entries_by_type(entries, StartupEntryType.SHELL_FOLDER)
        assert len(folder_entries) == 1

    def test_get_entries_by_scope(self):
        """Test filtering entries by scope."""
        entries = [
            StartupEntry(
                component_type=ComponentType.STARTUP,
                name="machine", display_name="Machine", publisher="Test",
                entry_type=StartupEntryType.RUN, entry_name="Machine",
                scope=StartupScope.MACHINE,
            ),
            StartupEntry(
                component_type=ComponentType.STARTUP,
                name="user", display_name="User", publisher="Test",
                entry_type=StartupEntryType.RUN, entry_name="User",
                scope=StartupScope.USER,
            ),
        ]

        machine_entries = get_entries_by_scope(entries, StartupScope.MACHINE)
        assert len(machine_entries) == 1
        assert machine_entries[0].entry_name == "Machine"

        user_entries = get_entries_by_scope(entries, StartupScope.USER)
        assert len(user_entries) == 1

    def test_get_disabled_entries(self):
        """Test filtering disabled entries."""
        entries = [
            StartupEntry(
                component_type=ComponentType.STARTUP,
                name="enabled", display_name="Enabled", publisher="Test",
                entry_type=StartupEntryType.RUN, entry_name="Enabled",
                is_enabled=True, is_approved=True,
            ),
            StartupEntry(
                component_type=ComponentType.STARTUP,
                name="disabled", display_name="Disabled", publisher="Test",
                entry_type=StartupEntryType.RUN, entry_name="Disabled",
                is_enabled=False, is_approved=True,
            ),
            StartupEntry(
                component_type=ComponentType.STARTUP,
                name="not-approved", display_name="Not Approved", publisher="Test",
                entry_type=StartupEntryType.RUN, entry_name="NotApproved",
                is_enabled=True, is_approved=False,
            ),
        ]

        disabled = get_disabled_entries(entries)
        assert len(disabled) == 2


class TestStartupScannerIntegration:
    """Integration tests for StartupScanner (Windows only)."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_scan_returns_list(self):
        """Test that scan returns a list on Windows."""
        scanner = StartupScanner()
        result = scanner.scan()

        assert isinstance(result, list)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_scan_entries_have_required_fields(self):
        """Test that scanned entries have required fields."""
        scanner = StartupScanner()
        result = scanner.scan()

        for entry in result[:10]:  # Check first 10 entries
            assert isinstance(entry, StartupEntry)
            assert entry.entry_name, "Entry should have a name"
            assert entry.entry_type in StartupEntryType
            assert entry.scope in StartupScope

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows only")
    def test_scan_returns_empty_on_non_windows(self):
        """Test that scan returns empty list on non-Windows."""
        scanner = StartupScanner()
        result = scanner.scan()

        assert result == []
