"""Startup Entries Scanner - Discovery module for Windows startup items.

This module scans for startup entries from multiple sources:
- Registry Run/RunOnce keys
- Startup folders (user and machine)
- Shell extensions
- Winlogon hooks
"""

import logging
import os
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from src.core.models import Component, ComponentType
from src.discovery.base import BaseDiscoveryModule

logger = logging.getLogger("debloatr.discovery.startup")


class StartupEntryType(Enum):
    """Types of startup entries."""

    RUN = "Run"  # HKLM/HKCU Run key
    RUN_ONCE = "RunOnce"  # Run once keys
    RUN_SERVICES = "RunServices"  # Legacy RunServices key
    SHELL_FOLDER = "ShellFolder"  # Startup folder shortcut
    SHELL_EXTENSION = "ShellExtension"  # Shell extension
    WINLOGON = "Winlogon"  # Winlogon hooks
    ACTIVE_SETUP = "ActiveSetup"  # Active Setup
    APP_INIT = "AppInit"  # AppInit_DLLs
    KNOWN_DLLS = "KnownDLLs"  # Known DLLs
    UNKNOWN = "Unknown"


class StartupScope(Enum):
    """Scope of startup entry (machine vs user)."""

    MACHINE = "Machine"  # Applies to all users (HKLM)
    USER = "User"  # Applies to current user only (HKCU)


@dataclass
class StartupEntry(Component):
    """Represents a Windows startup entry.

    Extends the base Component with startup-specific metadata.

    Attributes:
        entry_type: Type of startup entry
        entry_name: Name of the registry value or shortcut
        target_path: Path to the executable/script
        arguments: Command line arguments
        scope: Machine or User scope
        registry_key: Full registry key path (if registry-based)
        registry_value: Registry value name
        folder_path: Startup folder path (if folder-based)
        is_enabled: Whether entry is enabled
        is_approved: Windows startup approval status
        description: Entry description (from shortcut or registry)
        working_directory: Working directory for execution
    """

    entry_type: StartupEntryType = StartupEntryType.UNKNOWN
    entry_name: str = ""
    target_path: Path | None = None
    arguments: str = ""
    scope: StartupScope = StartupScope.USER
    registry_key: str = ""
    registry_value: str = ""
    folder_path: Path | None = None
    is_enabled: bool = True
    is_approved: bool = True
    description: str = ""
    working_directory: Path | None = None

    def __post_init__(self) -> None:
        """Set component type to STARTUP."""
        self.component_type = ComponentType.STARTUP

    @property
    def full_command(self) -> str:
        """Get the full command line."""
        if self.target_path:
            if self.arguments:
                return f'"{self.target_path}" {self.arguments}'
            return str(self.target_path)
        return ""


# Registry paths to scan for startup entries
REGISTRY_STARTUP_PATHS = {
    # Standard Run keys
    "Run": [
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", StartupEntryType.RUN),
        (r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", StartupEntryType.RUN),
    ],
    "RunOnce": [
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", StartupEntryType.RUN_ONCE),
        (
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            StartupEntryType.RUN_ONCE,
        ),
    ],
    # Legacy keys
    "RunServices": [
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices", StartupEntryType.RUN_SERVICES),
        (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            StartupEntryType.RUN_SERVICES,
        ),
    ],
    # Winlogon
    "Winlogon": [
        (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", StartupEntryType.WINLOGON),
    ],
    # Active Setup
    "ActiveSetup": [
        (r"SOFTWARE\Microsoft\Active Setup\Installed Components", StartupEntryType.ACTIVE_SETUP),
        (
            r"SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components",
            StartupEntryType.ACTIVE_SETUP,
        ),
    ],
}

# Winlogon values that can contain startup commands
WINLOGON_VALUES = ["Shell", "Userinit", "Taskman", "AppSetup"]

# Startup folder paths
STARTUP_FOLDERS = {
    StartupScope.USER: [
        Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup",
    ],
    StartupScope.MACHINE: [
        Path(os.environ.get("PROGRAMDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup",
    ],
}


class StartupScanner(BaseDiscoveryModule):
    """Discovery module for scanning Windows startup entries.

    Scans multiple locations for startup entries including:
    - Registry Run/RunOnce keys
    - Startup folders
    - Winlogon hooks
    - Active Setup entries

    Example:
        scanner = StartupScanner()
        entries = scanner.scan()
        for entry in entries:
            print(f"{entry.entry_name} ({entry.entry_type.value})")
    """

    def __init__(
        self,
        scan_winlogon: bool = True,
        scan_active_setup: bool = True,
        include_disabled: bool = True,
    ) -> None:
        """Initialize the startup scanner.

        Args:
            scan_winlogon: Whether to scan Winlogon hooks.
            scan_active_setup: Whether to scan Active Setup.
            include_disabled: Whether to include disabled entries.
        """
        self.scan_winlogon = scan_winlogon
        self.scan_active_setup = scan_active_setup
        self.include_disabled = include_disabled
        self._is_windows = os.name == "nt"

    def get_module_name(self) -> str:
        """Return the module identifier."""
        return "startup"

    def get_description(self) -> str:
        """Return module description."""
        return "Scans Windows startup entries from registry and folders"

    def is_available(self) -> bool:
        """Check if this module can run on the current system."""
        return self._is_windows

    def requires_admin(self) -> bool:
        """Check if admin privileges are required."""
        return False  # Can read most entries without admin

    def scan(self) -> list[Component]:
        """Scan for all startup entries.

        Returns:
            List of discovered StartupEntry components.
        """
        if not self._is_windows:
            logger.warning("Startup scanner is only available on Windows")
            return []

        entries: list[Component] = []
        seen_keys: set[str] = set()

        logger.info("Scanning startup entries...")

        # Scan registry Run keys
        logger.info("Scanning registry Run keys...")
        reg_entries = self._scan_registry_run_keys()
        for entry in reg_entries:
            key = f"{entry.registry_key}|{entry.registry_value}".lower()
            if key not in seen_keys:
                seen_keys.add(key)
                entries.append(entry)

        # Scan Winlogon hooks
        if self.scan_winlogon:
            logger.info("Scanning Winlogon hooks...")
            winlogon_entries = self._scan_winlogon()
            for entry in winlogon_entries:
                key = f"winlogon|{entry.entry_name}".lower()
                if key not in seen_keys:
                    seen_keys.add(key)
                    entries.append(entry)

        # Scan Active Setup
        if self.scan_active_setup:
            logger.info("Scanning Active Setup...")
            active_setup_entries = self._scan_active_setup()
            for entry in active_setup_entries:
                key = f"activesetup|{entry.registry_value}".lower()
                if key not in seen_keys:
                    seen_keys.add(key)
                    entries.append(entry)

        # Scan startup folders
        logger.info("Scanning startup folders...")
        folder_entries = self._scan_startup_folders()
        for entry in folder_entries:
            key = f"folder|{entry.entry_name}".lower()
            if key not in seen_keys:
                seen_keys.add(key)
                entries.append(entry)

        # Check approval status
        self._check_approval_status(entries)

        logger.info(f"Found {len(entries)} startup entries")
        return entries

    def _scan_registry_run_keys(self) -> list[StartupEntry]:
        """Scan registry Run and RunOnce keys."""
        entries: list[StartupEntry] = []

        try:
            import winreg
        except ImportError:
            logger.error("winreg module not available")
            return entries

        # Scan both HKLM and HKCU
        hives = [
            (winreg.HKEY_LOCAL_MACHINE, "HKLM", StartupScope.MACHINE),
            (winreg.HKEY_CURRENT_USER, "HKCU", StartupScope.USER),
        ]

        for hive, hive_name, scope in hives:
            for category in ["Run", "RunOnce", "RunServices"]:
                if category not in REGISTRY_STARTUP_PATHS:
                    continue

                for reg_path, entry_type in REGISTRY_STARTUP_PATHS[category]:
                    entries.extend(
                        self._scan_registry_key(hive, hive_name, reg_path, entry_type, scope)
                    )

        return entries

    def _scan_registry_key(
        self,
        hive: Any,
        hive_name: str,
        reg_path: str,
        entry_type: StartupEntryType,
        scope: StartupScope,
    ) -> list[StartupEntry]:
        """Scan a single registry key for startup entries."""
        import winreg

        entries: list[StartupEntry] = []

        try:
            key = winreg.OpenKey(hive, reg_path, 0, winreg.KEY_READ)
        except OSError:
            return entries

        try:
            i = 0
            while True:
                try:
                    name, value, value_type = winreg.EnumValue(key, i)
                    i += 1

                    if not name or not value:
                        continue

                    # Parse command line
                    target_path, arguments = self._parse_command_line(str(value))

                    # Detect publisher
                    publisher = self._detect_publisher(target_path)

                    # Create internal name
                    internal_name = self._normalize_name(name)

                    entry = StartupEntry(
                        component_type=ComponentType.STARTUP,
                        name=internal_name,
                        display_name=name,
                        publisher=publisher,
                        install_path=target_path,
                        entry_type=entry_type,
                        entry_name=name,
                        target_path=target_path,
                        arguments=arguments,
                        scope=scope,
                        registry_key=f"{hive_name}\\{reg_path}",
                        registry_value=name,
                        is_enabled=True,
                    )
                    entries.append(entry)

                except OSError:
                    break

        finally:
            winreg.CloseKey(key)

        return entries

    def _scan_winlogon(self) -> list[StartupEntry]:
        """Scan Winlogon registry key for startup hooks."""
        entries: list[StartupEntry] = []

        try:
            import winreg
        except ImportError:
            return entries

        reg_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

        for hive, hive_name, scope in [
            (winreg.HKEY_LOCAL_MACHINE, "HKLM", StartupScope.MACHINE),
        ]:
            try:
                key = winreg.OpenKey(hive, reg_path, 0, winreg.KEY_READ)
            except OSError:
                continue

            try:
                for value_name in WINLOGON_VALUES:
                    try:
                        value, _ = winreg.QueryValueEx(key, value_name)
                        if not value:
                            continue

                        # Winlogon values can contain multiple comma-separated entries
                        for cmd in str(value).split(","):
                            cmd = cmd.strip()
                            if not cmd:
                                continue

                            target_path, arguments = self._parse_command_line(cmd)

                            # Skip default Windows values
                            if target_path and self._is_default_winlogon_value(
                                value_name, target_path
                            ):
                                continue

                            publisher = self._detect_publisher(target_path)
                            internal_name = f"winlogon-{value_name.lower()}"

                            entry = StartupEntry(
                                component_type=ComponentType.STARTUP,
                                name=internal_name,
                                display_name=f"Winlogon {value_name}",
                                publisher=publisher,
                                install_path=target_path,
                                entry_type=StartupEntryType.WINLOGON,
                                entry_name=value_name,
                                target_path=target_path,
                                arguments=arguments,
                                scope=scope,
                                registry_key=f"{hive_name}\\{reg_path}",
                                registry_value=value_name,
                            )
                            entries.append(entry)

                    except OSError:
                        continue

            finally:
                winreg.CloseKey(key)

        return entries

    def _scan_active_setup(self) -> list[StartupEntry]:
        """Scan Active Setup registry keys."""
        entries: list[StartupEntry] = []

        try:
            import winreg
        except ImportError:
            return entries

        for reg_path, _entry_type in REGISTRY_STARTUP_PATHS.get("ActiveSetup", []):
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_READ)
            except OSError:
                continue

            try:
                subkey_count, _, _ = winreg.QueryInfoKey(key)

                for i in range(subkey_count):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey_path = f"{reg_path}\\{subkey_name}"

                        entry = self._parse_active_setup_entry(subkey_path, subkey_name)
                        if entry:
                            entries.append(entry)

                    except OSError:
                        continue

            finally:
                winreg.CloseKey(key)

        return entries

    def _parse_active_setup_entry(
        self,
        subkey_path: str,
        subkey_name: str,
    ) -> StartupEntry | None:
        """Parse an Active Setup registry entry."""
        import winreg

        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path, 0, winreg.KEY_READ)
        except OSError:
            return None

        try:
            # Get StubPath value (the command to run)
            try:
                stub_path, _ = winreg.QueryValueEx(key, "StubPath")
            except OSError:
                return None

            if not stub_path:
                return None

            # Get display name
            try:
                display_name, _ = winreg.QueryValueEx(key, "")
            except OSError:
                display_name = subkey_name

            # Check if installed (IsInstalled != 0 means it has run)
            try:
                is_installed, _ = winreg.QueryValueEx(key, "IsInstalled")
                is_enabled = is_installed != 0
            except OSError:
                is_enabled = True

            target_path, arguments = self._parse_command_line(str(stub_path))
            publisher = self._detect_publisher(target_path)
            internal_name = self._normalize_name(display_name or subkey_name)

            return StartupEntry(
                component_type=ComponentType.STARTUP,
                name=internal_name,
                display_name=display_name or subkey_name,
                publisher=publisher,
                install_path=target_path,
                entry_type=StartupEntryType.ACTIVE_SETUP,
                entry_name=subkey_name,
                target_path=target_path,
                arguments=arguments,
                scope=StartupScope.MACHINE,
                registry_key=f"HKLM\\{subkey_path}",
                registry_value=subkey_name,
                is_enabled=is_enabled,
            )

        finally:
            winreg.CloseKey(key)

    def _scan_startup_folders(self) -> list[StartupEntry]:
        """Scan startup folders for shortcuts."""
        entries: list[StartupEntry] = []

        for scope, folders in STARTUP_FOLDERS.items():
            for folder in folders:
                if not folder.exists():
                    continue

                try:
                    for item in folder.iterdir():
                        entry = self._parse_startup_folder_item(item, folder, scope)
                        if entry:
                            entries.append(entry)
                except PermissionError:
                    logger.debug(f"Permission denied accessing {folder}")

        return entries

    def _parse_startup_folder_item(
        self,
        item: Path,
        folder: Path,
        scope: StartupScope,
    ) -> StartupEntry | None:
        """Parse an item from a startup folder."""
        if item.suffix.lower() == ".lnk":
            return self._parse_shortcut(item, folder, scope)
        elif item.suffix.lower() in [".exe", ".bat", ".cmd", ".vbs", ".ps1"]:
            return self._parse_executable(item, folder, scope)
        return None

    def _parse_shortcut(
        self,
        shortcut_path: Path,
        folder: Path,
        scope: StartupScope,
    ) -> StartupEntry | None:
        """Parse a Windows shortcut (.lnk) file."""
        # Reading .lnk files requires COM or special library
        # For now, just record the shortcut existence
        try:
            import subprocess

            # Use PowerShell to read shortcut target
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                f"""
                $sh = New-Object -ComObject WScript.Shell
                $shortcut = $sh.CreateShortcut('{shortcut_path}')
                @{{
                    TargetPath = $shortcut.TargetPath
                    Arguments = $shortcut.Arguments
                    WorkingDirectory = $shortcut.WorkingDirectory
                    Description = $shortcut.Description
                }} | ConvertTo-Json -Compress
                """.replace("\n", " "),
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
                ),
            )

            if result.returncode != 0:
                return None

            import json

            data = json.loads(result.stdout)

            target = data.get("TargetPath", "")
            if not target:
                return None

            target_path = Path(target)
            arguments = data.get("Arguments", "") or ""
            description = data.get("Description", "") or ""
            working_dir = data.get("WorkingDirectory", "")

            publisher = self._detect_publisher(target_path)
            internal_name = self._normalize_name(shortcut_path.stem)

            return StartupEntry(
                component_type=ComponentType.STARTUP,
                name=internal_name,
                display_name=shortcut_path.stem,
                publisher=publisher,
                install_path=target_path,
                entry_type=StartupEntryType.SHELL_FOLDER,
                entry_name=shortcut_path.name,
                target_path=target_path,
                arguments=arguments,
                scope=scope,
                folder_path=folder,
                description=description,
                working_directory=Path(working_dir) if working_dir else None,
            )

        except Exception as e:
            logger.debug(f"Error parsing shortcut {shortcut_path}: {e}")
            return None

    def _parse_executable(
        self,
        exe_path: Path,
        folder: Path,
        scope: StartupScope,
    ) -> StartupEntry | None:
        """Parse a direct executable in startup folder."""
        publisher = self._detect_publisher(exe_path)
        internal_name = self._normalize_name(exe_path.stem)

        return StartupEntry(
            component_type=ComponentType.STARTUP,
            name=internal_name,
            display_name=exe_path.stem,
            publisher=publisher,
            install_path=exe_path,
            entry_type=StartupEntryType.SHELL_FOLDER,
            entry_name=exe_path.name,
            target_path=exe_path,
            scope=scope,
            folder_path=folder,
        )

    def _check_approval_status(self, entries: list[Component]) -> None:
        """Check Windows startup approval status for entries.

        Windows 10+ stores approval status in registry.
        """
        try:
            import winreg

            approval_path = (
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
            )

            for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                try:
                    key = winreg.OpenKey(hive, approval_path, 0, winreg.KEY_READ)
                except OSError:
                    continue

                try:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            i += 1

                            # Approval data: first byte 02 = enabled, 03 = disabled
                            is_approved = True
                            if isinstance(value, bytes) and len(value) >= 1:
                                is_approved = value[0] != 0x03

                            # Find matching entry
                            for entry in entries:
                                if isinstance(entry, StartupEntry):
                                    if entry.entry_name == name:
                                        entry.is_approved = is_approved

                        except OSError:
                            break

                finally:
                    winreg.CloseKey(key)

        except ImportError:
            pass

    def _parse_command_line(self, cmd: str) -> tuple[Path | None, str]:
        """Parse a command line into path and arguments.

        Args:
            cmd: Full command line string.

        Returns:
            Tuple of (executable path, arguments).
        """
        if not cmd:
            return None, ""

        cmd = cmd.strip()

        # Expand environment variables
        cmd = os.path.expandvars(cmd)

        # Handle quoted paths
        if cmd.startswith('"'):
            match = re.match(r'"([^"]+)"(.*)', cmd)
            if match:
                return Path(match.group(1)), match.group(2).strip()

        # Handle unquoted paths with arguments
        # Look for known executable extensions
        for ext in [".exe", ".bat", ".cmd", ".vbs", ".ps1", ".dll"]:
            idx = cmd.lower().find(ext)
            if idx != -1:
                path = cmd[: idx + len(ext)]
                args = cmd[idx + len(ext) :].strip()
                return Path(path), args

        # No extension found - try splitting on first space
        parts = cmd.split(None, 1)
        if parts:
            return Path(parts[0]), parts[1] if len(parts) > 1 else ""

        return None, ""

    def _is_default_winlogon_value(self, value_name: str, target: Path) -> bool:
        """Check if a Winlogon value is a default Windows value."""
        target_lower = str(target).lower()

        defaults = {
            "Shell": ["explorer.exe"],
            "Userinit": ["userinit.exe", "userinit,"],
        }

        if value_name in defaults:
            for default in defaults[value_name]:
                if default in target_lower:
                    return True

        return False

    def _detect_publisher(self, path: Path | None) -> str:
        """Detect publisher from path."""
        if not path:
            return "Unknown"

        path_lower = str(path).lower()

        publishers = {
            "Microsoft": ["microsoft", "\\windows\\", "\\system32\\"],
            "Adobe": ["adobe"],
            "Google": ["google"],
            "Apple": ["apple"],
            "Intel": ["intel"],
            "NVIDIA": ["nvidia"],
            "HP": ["hp", "hewlett"],
            "Dell": ["dell"],
            "Lenovo": ["lenovo"],
            "Realtek": ["realtek"],
        }

        for publisher, patterns in publishers.items():
            for pattern in patterns:
                if pattern in path_lower:
                    return publisher

        return "Unknown"

    def _normalize_name(self, name: str) -> str:
        """Normalize an entry name."""
        name = name.lower()
        name = re.sub(r"[^\w\s-]", "", name)
        name = re.sub(r"\s+", "-", name)
        return name.strip("-")


def get_entries_by_type(
    entries: list[StartupEntry],
    entry_type: StartupEntryType,
) -> list[StartupEntry]:
    """Get all entries of a specific type.

    Args:
        entries: List of all entries.
        entry_type: Entry type to filter by.

    Returns:
        List of entries with that type.
    """
    return [e for e in entries if e.entry_type == entry_type]


def get_entries_by_scope(
    entries: list[StartupEntry],
    scope: StartupScope,
) -> list[StartupEntry]:
    """Get all entries with a specific scope.

    Args:
        entries: List of all entries.
        scope: Scope to filter by.

    Returns:
        List of entries with that scope.
    """
    return [e for e in entries if e.scope == scope]


def get_disabled_entries(entries: list[StartupEntry]) -> list[StartupEntry]:
    """Get all disabled startup entries.

    Args:
        entries: List of all entries.

    Returns:
        List of disabled entries.
    """
    return [e for e in entries if not e.is_enabled or not e.is_approved]
