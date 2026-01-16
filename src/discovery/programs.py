"""Installed Software Scanner - Discovery module for installed programs.

This module scans for installed software from multiple sources:
- Windows Registry (Uninstall keys)
- Windows Store (UWP/AppX packages)
- Portable applications (filesystem heuristics)
"""

import os
import re
import subprocess
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
import logging

from src.core.models import Component, ComponentType, Classification, RiskLevel
from src.discovery.base import BaseDiscoveryModule

logger = logging.getLogger("debloatr.discovery.programs")

# Registry paths for installed programs
UNINSTALL_REGISTRY_PATHS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
]

# Registry hives to check
REGISTRY_HIVES = ["HKLM", "HKCU"]

# Common portable app locations
PORTABLE_APP_LOCATIONS = [
    Path(os.environ.get("APPDATA", "")) / "Portable",
    Path(os.environ.get("LOCALAPPDATA", "")) / "Programs",
    Path(os.environ.get("LOCALAPPDATA", "")) / "Apps",
    Path(os.environ.get("USERPROFILE", "")) / "PortableApps",
]

# Patterns to identify executables
EXECUTABLE_PATTERNS = ["*.exe", "*.msc", "*.cmd", "*.bat"]

# Known update mechanisms
UPDATE_MECHANISMS = {
    "chrome": "Google Update",
    "firefox": "Mozilla Maintenance Service",
    "adobe": "Adobe Update Manager",
    "java": "Java Update Scheduler",
    "dropbox": "Dropbox Update",
}


@dataclass
class InstalledProgram(Component):
    """Represents an installed program discovered on the system.

    Extends the base Component with program-specific metadata.

    Attributes:
        install_date: Date when the program was installed
        size_bytes: Total installation size in bytes
        version: Program version string
        executables: List of executable files in the installation
        uninstall_string: Command to uninstall the program
        quiet_uninstall_string: Silent uninstall command (if available)
        update_mechanism: Detected update mechanism (if any)
        is_uwp: Whether this is a UWP/Store app
        is_portable: Whether this is a portable application
        is_system_component: Whether this is a Windows system component
        registry_key: Full registry key path where this was found
        product_code: MSI product code (if MSI-based)
        package_family_name: UWP package family name (if UWP)
    """

    install_date: Optional[datetime] = None
    size_bytes: int = 0
    version: str = ""
    executables: list[Path] = field(default_factory=list)
    uninstall_string: str = ""
    quiet_uninstall_string: str = ""
    update_mechanism: Optional[str] = None
    is_uwp: bool = False
    is_portable: bool = False
    is_system_component: bool = False
    registry_key: str = ""
    product_code: str = ""
    package_family_name: str = ""

    def __post_init__(self) -> None:
        """Set component type based on whether it's UWP or regular program."""
        if self.is_uwp:
            self.component_type = ComponentType.UWP
        else:
            self.component_type = ComponentType.PROGRAM


class ProgramsScanner(BaseDiscoveryModule):
    """Discovery module for scanning installed programs.

    Scans multiple sources to discover installed software:
    1. Windows Registry (traditional Win32 programs)
    2. Windows Store (UWP/AppX packages)
    3. Portable applications (filesystem-based detection)

    Example:
        scanner = ProgramsScanner()
        programs = scanner.scan()
        for program in programs:
            print(f"{program.display_name} - {program.publisher}")
    """

    def __init__(
        self,
        scan_uwp: bool = True,
        scan_portable: bool = True,
        calculate_sizes: bool = True,
    ) -> None:
        """Initialize the programs scanner.

        Args:
            scan_uwp: Whether to scan for UWP/Store apps.
            scan_portable: Whether to scan for portable applications.
            calculate_sizes: Whether to calculate installation sizes.
        """
        self.scan_uwp = scan_uwp
        self.scan_portable = scan_portable
        self.calculate_sizes = calculate_sizes
        self._is_windows = os.name == "nt"

    def get_module_name(self) -> str:
        """Return the module identifier."""
        return "programs"

    def get_description(self) -> str:
        """Return module description."""
        return "Scans for installed programs, UWP apps, and portable applications"

    def is_available(self) -> bool:
        """Check if this module can run on the current system."""
        return self._is_windows

    def requires_admin(self) -> bool:
        """Check if admin privileges are required."""
        # Full scanning requires admin for HKLM access
        return False  # Basic scanning works without admin

    def scan(self) -> list[Component]:
        """Scan for all installed programs.

        Returns:
            List of discovered InstalledProgram components.
        """
        if not self._is_windows:
            logger.warning("Programs scanner is only available on Windows")
            return []

        programs: list[Component] = []
        seen_names: set[str] = set()

        # Scan registry for traditional programs
        logger.info("Scanning registry for installed programs...")
        registry_programs = self._scan_registry()
        for program in registry_programs:
            key = f"{program.name}|{program.publisher}".lower()
            if key not in seen_names:
                seen_names.add(key)
                programs.append(program)

        logger.info(f"Found {len(programs)} programs in registry")

        # Scan for UWP apps
        if self.scan_uwp:
            logger.info("Scanning for UWP/Store apps...")
            uwp_apps = self._scan_uwp_apps()
            for app in uwp_apps:
                key = f"{app.name}|{app.publisher}".lower()
                if key not in seen_names:
                    seen_names.add(key)
                    programs.append(app)

            logger.info(f"Found {len(uwp_apps)} UWP apps")

        # Scan for portable apps
        if self.scan_portable:
            logger.info("Scanning for portable applications...")
            portable_apps = self._scan_portable_apps()
            for app in portable_apps:
                key = f"{app.name}|{app.publisher}".lower()
                if key not in seen_names:
                    seen_names.add(key)
                    programs.append(app)

            logger.info(f"Found {len(portable_apps)} portable apps")

        logger.info(f"Total programs discovered: {len(programs)}")
        return programs

    def _scan_registry(self) -> list[InstalledProgram]:
        """Scan Windows registry for installed programs.

        Returns:
            List of programs found in registry.
        """
        programs: list[InstalledProgram] = []

        try:
            import winreg
        except ImportError:
            logger.error("winreg module not available")
            return programs

        for hive_name in REGISTRY_HIVES:
            hive = winreg.HKEY_LOCAL_MACHINE if hive_name == "HKLM" else winreg.HKEY_CURRENT_USER

            for reg_path in UNINSTALL_REGISTRY_PATHS:
                try:
                    programs.extend(
                        self._scan_registry_key(hive, hive_name, reg_path)
                    )
                except OSError as e:
                    logger.debug(f"Could not access {hive_name}\\{reg_path}: {e}")

        return programs

    def _scan_registry_key(
        self,
        hive: Any,
        hive_name: str,
        reg_path: str,
    ) -> list[InstalledProgram]:
        """Scan a specific registry key for programs.

        Args:
            hive: Registry hive handle.
            hive_name: Name of the hive (HKLM/HKCU).
            reg_path: Registry path to scan.

        Returns:
            List of programs found in this key.
        """
        import winreg

        programs: list[InstalledProgram] = []

        try:
            key = winreg.OpenKey(hive, reg_path, 0, winreg.KEY_READ)
        except OSError:
            return programs

        try:
            subkey_count, _, _ = winreg.QueryInfoKey(key)

            for i in range(subkey_count):
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    subkey_path = f"{reg_path}\\{subkey_name}"

                    program = self._parse_registry_entry(
                        hive, hive_name, subkey_path
                    )
                    if program:
                        programs.append(program)

                except OSError as e:
                    logger.debug(f"Error reading subkey {i}: {e}")

        finally:
            winreg.CloseKey(key)

        return programs

    def _parse_registry_entry(
        self,
        hive: Any,
        hive_name: str,
        subkey_path: str,
    ) -> Optional[InstalledProgram]:
        """Parse a single registry entry into an InstalledProgram.

        Args:
            hive: Registry hive handle.
            hive_name: Name of the hive.
            subkey_path: Path to the subkey.

        Returns:
            InstalledProgram if valid entry, None otherwise.
        """
        import winreg

        try:
            subkey = winreg.OpenKey(hive, subkey_path, 0, winreg.KEY_READ)
        except OSError:
            return None

        try:
            # Get required fields
            display_name = self._get_registry_value(subkey, "DisplayName")
            if not display_name:
                return None

            # Skip system components and updates
            system_component = self._get_registry_value(subkey, "SystemComponent")
            if system_component == 1:
                return None

            # Skip Windows updates
            if display_name.startswith("KB") or "Update for" in display_name:
                release_type = self._get_registry_value(subkey, "ReleaseType")
                if release_type in ["Update", "Security Update", "Hotfix"]:
                    return None

            # Get other fields
            publisher = self._get_registry_value(subkey, "Publisher") or "Unknown"
            install_location = self._get_registry_value(subkey, "InstallLocation")
            uninstall_string = self._get_registry_value(subkey, "UninstallString") or ""
            quiet_uninstall = self._get_registry_value(subkey, "QuietUninstallString") or ""
            version = self._get_registry_value(subkey, "DisplayVersion") or ""
            install_date_str = self._get_registry_value(subkey, "InstallDate")
            estimated_size = self._get_registry_value(subkey, "EstimatedSize") or 0

            # Parse install date
            install_date = None
            if install_date_str:
                try:
                    install_date = datetime.strptime(str(install_date_str), "%Y%m%d")
                except ValueError:
                    pass

            # Get install path
            install_path = None
            if install_location:
                install_path = Path(install_location)

            # Calculate or estimate size
            size_bytes = estimated_size * 1024  # Registry stores KB
            if self.calculate_sizes and install_path and install_path.exists():
                calculated_size = self._calculate_directory_size(install_path)
                if calculated_size > 0:
                    size_bytes = calculated_size

            # Find executables
            executables: list[Path] = []
            if install_path and install_path.exists():
                executables = self._find_executables(install_path)

            # Detect update mechanism
            update_mechanism = self._detect_update_mechanism(
                display_name, publisher, install_path
            )

            # Create internal name from display name
            name = self._normalize_name(display_name)

            # Get product code if available
            product_code = ""
            subkey_name = subkey_path.split("\\")[-1]
            if subkey_name.startswith("{") and subkey_name.endswith("}"):
                product_code = subkey_name

            return InstalledProgram(
                component_type=ComponentType.PROGRAM,
                name=name,
                display_name=display_name,
                publisher=publisher,
                install_path=install_path,
                install_date=install_date,
                size_bytes=size_bytes,
                version=version,
                executables=executables,
                uninstall_string=uninstall_string,
                quiet_uninstall_string=quiet_uninstall,
                update_mechanism=update_mechanism,
                is_uwp=False,
                is_portable=False,
                is_system_component=False,
                registry_key=f"{hive_name}\\{subkey_path}",
                product_code=product_code,
            )

        except OSError as e:
            logger.debug(f"Error parsing registry entry: {e}")
            return None

        finally:
            winreg.CloseKey(subkey)

    def _get_registry_value(self, key: Any, value_name: str) -> Any:
        """Safely get a registry value.

        Args:
            key: Open registry key handle.
            value_name: Name of the value to retrieve.

        Returns:
            The value if found, None otherwise.
        """
        import winreg

        try:
            value, _ = winreg.QueryValueEx(key, value_name)
            return value
        except OSError:
            return None

    def _scan_uwp_apps(self) -> list[InstalledProgram]:
        """Scan for UWP/Windows Store applications.

        Uses PowerShell Get-AppxPackage to enumerate installed apps.

        Returns:
            List of UWP apps found.
        """
        apps: list[InstalledProgram] = []

        try:
            # Run PowerShell command to get AppX packages
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                "Get-AppxPackage | Select-Object Name, PackageFullName, "
                "PackageFamilyName, Publisher, Version, InstallLocation, "
                "IsFramework, SignatureKind | ConvertTo-Json -Compress"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
            )

            if result.returncode != 0:
                logger.error(f"PowerShell error: {result.stderr}")
                return apps

            # Parse JSON output
            if not result.stdout.strip():
                return apps

            packages = json.loads(result.stdout)

            # Handle single package (not a list)
            if isinstance(packages, dict):
                packages = [packages]

            for pkg in packages:
                app = self._parse_uwp_package(pkg)
                if app:
                    apps.append(app)

        except subprocess.TimeoutExpired:
            logger.error("PowerShell command timed out")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse PowerShell output: {e}")
        except FileNotFoundError:
            logger.error("PowerShell not found")
        except Exception as e:
            logger.error(f"Error scanning UWP apps: {e}")

        return apps

    def _parse_uwp_package(self, pkg: dict[str, Any]) -> Optional[InstalledProgram]:
        """Parse a UWP package dictionary into an InstalledProgram.

        Args:
            pkg: Package information dictionary from PowerShell.

        Returns:
            InstalledProgram if valid, None otherwise.
        """
        # Skip framework packages
        if pkg.get("IsFramework", False):
            return None

        name = pkg.get("Name", "")
        if not name:
            return None

        # Skip system/framework packages
        if name.startswith("Microsoft.NET.") or name.startswith("Microsoft.VCLibs."):
            return None

        # Parse publisher (remove CN= prefix)
        publisher_raw = pkg.get("Publisher", "Unknown")
        publisher = publisher_raw
        if publisher_raw.startswith("CN="):
            # Extract the CN value
            match = re.match(r"CN=([^,]+)", publisher_raw)
            if match:
                publisher = match.group(1)

        # Get install location
        install_location = pkg.get("InstallLocation", "")
        install_path = Path(install_location) if install_location else None

        # Calculate size
        size_bytes = 0
        if self.calculate_sizes and install_path and install_path.exists():
            size_bytes = self._calculate_directory_size(install_path)

        # Create display name from package name
        display_name = self._format_uwp_display_name(name)

        return InstalledProgram(
            component_type=ComponentType.UWP,
            name=name,
            display_name=display_name,
            publisher=publisher,
            install_path=install_path,
            size_bytes=size_bytes,
            version=pkg.get("Version", ""),
            is_uwp=True,
            is_portable=False,
            package_family_name=pkg.get("PackageFamilyName", ""),
            uninstall_string=f"Remove-AppxPackage -Package {pkg.get('PackageFullName', '')}",
        )

    def _format_uwp_display_name(self, package_name: str) -> str:
        """Format a UWP package name into a readable display name.

        Args:
            package_name: Raw package name (e.g., "Microsoft.WindowsCalculator")

        Returns:
            Formatted display name (e.g., "Windows Calculator")
        """
        # Remove publisher prefix
        if "." in package_name:
            parts = package_name.split(".")
            # Take everything after the first part (publisher)
            name = ".".join(parts[1:]) if len(parts) > 1 else package_name
        else:
            name = package_name

        # Add spaces before capital letters
        name = re.sub(r"([a-z])([A-Z])", r"\1 \2", name)

        # Replace common patterns
        name = name.replace(".", " ")
        name = name.replace("_", " ")

        return name.strip()

    def _scan_portable_apps(self) -> list[InstalledProgram]:
        """Scan for portable applications.

        Looks for executables in common portable app locations
        that don't have corresponding registry entries.

        Returns:
            List of portable apps found.
        """
        apps: list[InstalledProgram] = []

        for location in PORTABLE_APP_LOCATIONS:
            if not location.exists():
                continue

            try:
                for item in location.iterdir():
                    if item.is_dir():
                        app = self._check_portable_app_directory(item)
                        if app:
                            apps.append(app)
            except PermissionError:
                logger.debug(f"Permission denied accessing {location}")

        return apps

    def _check_portable_app_directory(
        self, directory: Path
    ) -> Optional[InstalledProgram]:
        """Check if a directory contains a portable application.

        Args:
            directory: Directory to check.

        Returns:
            InstalledProgram if portable app found, None otherwise.
        """
        executables = self._find_executables(directory, max_depth=2)

        if not executables:
            return None

        # Use directory name as the app name
        name = directory.name
        display_name = self._format_portable_display_name(name)

        # Calculate size
        size_bytes = 0
        if self.calculate_sizes:
            size_bytes = self._calculate_directory_size(directory)

        # Try to detect publisher from exe metadata
        publisher = "Unknown"
        if executables:
            publisher = self._get_exe_publisher(executables[0]) or "Unknown"

        return InstalledProgram(
            component_type=ComponentType.PROGRAM,
            name=self._normalize_name(name),
            display_name=display_name,
            publisher=publisher,
            install_path=directory,
            size_bytes=size_bytes,
            executables=executables,
            is_uwp=False,
            is_portable=True,
        )

    def _format_portable_display_name(self, directory_name: str) -> str:
        """Format a directory name into a display name.

        Args:
            directory_name: Name of the portable app directory.

        Returns:
            Formatted display name.
        """
        # Remove version numbers
        name = re.sub(r"[-_]?\d+(\.\d+)*$", "", directory_name)

        # Add spaces
        name = re.sub(r"([a-z])([A-Z])", r"\1 \2", name)
        name = name.replace("-", " ").replace("_", " ")

        return name.strip()

    def _find_executables(
        self, directory: Path, max_depth: int = 3
    ) -> list[Path]:
        """Find executable files in a directory.

        Args:
            directory: Directory to search.
            max_depth: Maximum directory depth to search.

        Returns:
            List of paths to executable files.
        """
        executables: list[Path] = []

        if not directory.exists():
            return executables

        try:
            for pattern in EXECUTABLE_PATTERNS:
                # Only search to max_depth
                for depth in range(max_depth + 1):
                    glob_pattern = "/".join(["*"] * depth + [pattern]) if depth > 0 else pattern
                    executables.extend(directory.glob(glob_pattern))

            # Filter out uninstallers and updaters
            executables = [
                exe for exe in executables
                if not any(
                    skip in exe.name.lower()
                    for skip in ["unins", "uninst", "update", "setup", "install"]
                )
            ]

        except PermissionError:
            logger.debug(f"Permission denied scanning {directory}")

        return executables[:10]  # Limit to first 10 executables

    def _calculate_directory_size(self, directory: Path) -> int:
        """Calculate total size of a directory in bytes.

        Args:
            directory: Directory to measure.

        Returns:
            Total size in bytes.
        """
        total_size = 0

        try:
            for item in directory.rglob("*"):
                if item.is_file():
                    try:
                        total_size += item.stat().st_size
                    except (OSError, PermissionError):
                        pass
        except (OSError, PermissionError):
            pass

        return total_size

    def _detect_update_mechanism(
        self,
        display_name: str,
        publisher: str,
        install_path: Optional[Path],
    ) -> Optional[str]:
        """Detect the update mechanism used by a program.

        Args:
            display_name: Program display name.
            publisher: Program publisher.
            install_path: Installation path.

        Returns:
            Name of update mechanism if detected, None otherwise.
        """
        name_lower = display_name.lower()
        publisher_lower = publisher.lower()

        for keyword, mechanism in UPDATE_MECHANISMS.items():
            if keyword in name_lower or keyword in publisher_lower:
                return mechanism

        return None

    def _get_exe_publisher(self, exe_path: Path) -> Optional[str]:
        """Get publisher information from an executable's metadata.

        Args:
            exe_path: Path to the executable.

        Returns:
            Publisher name if found, None otherwise.
        """
        # This would require win32api or similar to read PE metadata
        # For now, return None and let the caller use a default
        return None

    def _normalize_name(self, display_name: str) -> str:
        """Normalize a display name into an internal name.

        Args:
            display_name: Human-readable display name.

        Returns:
            Normalized internal name (lowercase, no spaces).
        """
        name = display_name.lower()
        name = re.sub(r"[^\w\s-]", "", name)  # Remove special chars
        name = re.sub(r"\s+", "-", name)  # Replace spaces with hyphens
        return name.strip("-")
