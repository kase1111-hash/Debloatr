"""Drivers Scanner - Discovery module for Windows drivers and helpers.

This module scans for system drivers and helper components including:
- Kernel drivers (not signed by Microsoft)
- User-mode helper services
- Overlay injectors (DLL injection patterns)
"""

import os
import re
import subprocess
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional
import logging

from src.core.models import Component, ComponentType, Classification, RiskLevel
from src.discovery.base import BaseDiscoveryModule

logger = logging.getLogger("debloatr.discovery.drivers")


class DriverType(Enum):
    """Types of Windows drivers."""

    KERNEL = "Kernel"  # Kernel-mode driver
    FILESYSTEM = "FileSystem"  # Filesystem filter driver
    USER = "User"  # User-mode driver
    BOOT = "Boot"  # Boot-start driver
    SYSTEM = "System"  # System-start driver
    UNKNOWN = "Unknown"

    @classmethod
    def from_string(cls, value: str) -> "DriverType":
        """Convert string to DriverType."""
        value_lower = value.lower()
        if "kernel" in value_lower:
            return cls.KERNEL
        elif "file" in value_lower:
            return cls.FILESYSTEM
        elif "user" in value_lower:
            return cls.USER
        elif "boot" in value_lower:
            return cls.BOOT
        elif "system" in value_lower:
            return cls.SYSTEM
        return cls.UNKNOWN


class SignatureStatus(Enum):
    """Driver signature verification status."""

    VALID = "Valid"  # Properly signed
    INVALID = "Invalid"  # Signature invalid/tampered
    UNSIGNED = "Unsigned"  # No signature
    UNKNOWN = "Unknown"  # Could not verify

    @classmethod
    def from_bool(cls, is_signed: Optional[bool]) -> "SignatureStatus":
        """Convert boolean to SignatureStatus."""
        if is_signed is None:
            return cls.UNKNOWN
        return cls.VALID if is_signed else cls.UNSIGNED


@dataclass
class SystemDriver(Component):
    """Represents a Windows system driver.

    Extends the base Component with driver-specific metadata.

    Attributes:
        driver_name: Internal driver name
        driver_type: Type of driver (Kernel, FileSystem, etc.)
        signer: Who signed the driver
        signature_status: Signature verification status
        associated_hardware: List of associated hardware device IDs
        load_order: Driver load order group
        is_running: Whether driver is currently running
        driver_path: Path to the driver file
        driver_version: Driver version string
        driver_date: Driver date string
        inf_name: INF file name
        is_microsoft_signed: Whether signed by Microsoft
        is_inbox_driver: Whether it's a Windows inbox driver
        is_overlay_injector: Whether this appears to be an overlay injector
    """

    driver_name: str = ""
    driver_type: DriverType = DriverType.UNKNOWN
    signer: str = ""
    signature_status: SignatureStatus = SignatureStatus.UNKNOWN
    associated_hardware: list[str] = field(default_factory=list)
    load_order: str = ""
    is_running: bool = False
    driver_path: Optional[Path] = None
    driver_version: str = ""
    driver_date: str = ""
    inf_name: str = ""
    is_microsoft_signed: bool = False
    is_inbox_driver: bool = False
    is_overlay_injector: bool = False

    def __post_init__(self) -> None:
        """Set component type to DRIVER."""
        self.component_type = ComponentType.DRIVER


# Known overlay injector patterns
OVERLAY_INJECTOR_PATTERNS = [
    r".*overlay.*",
    r".*hook.*",
    r".*inject.*",
    r".*gameoverlay.*",
    r".*steamoverlay.*",
    r".*discordoverlay.*",
    r".*rivatuner.*",
    r".*afterburner.*",
    r".*fraps.*",
    r".*reshade.*",
    r".*sweetfx.*",
]

# Known problematic driver publishers
PROBLEMATIC_PUBLISHERS = [
    "WinRing0",  # Hardware access driver (common in mining/overclocking)
    "SpeedFan",
    "HWiNFO",
    "CPU-Z",
    "GPU-Z",
]

# Known telemetry-related driver names
TELEMETRY_DRIVER_PATTERNS = [
    r".*telemetry.*",
    r".*diagnostic.*",
    r".*ceip.*",
]


class DriversScanner(BaseDiscoveryModule):
    """Discovery module for scanning Windows drivers.

    Scans for system drivers and helper components, focusing on
    non-Microsoft signed drivers and potential overlay injectors.

    Example:
        scanner = DriversScanner()
        drivers = scanner.scan()
        for driver in drivers:
            print(f"{driver.driver_name} - Signed by: {driver.signer}")
    """

    def __init__(
        self,
        include_microsoft_drivers: bool = False,
        include_inbox_drivers: bool = False,
        detect_overlay_injectors: bool = True,
    ) -> None:
        """Initialize the drivers scanner.

        Args:
            include_microsoft_drivers: Whether to include Microsoft-signed drivers.
            include_inbox_drivers: Whether to include Windows inbox drivers.
            detect_overlay_injectors: Whether to detect overlay injector patterns.
        """
        self.include_microsoft_drivers = include_microsoft_drivers
        self.include_inbox_drivers = include_inbox_drivers
        self.detect_overlay_injectors = detect_overlay_injectors
        self._is_windows = os.name == "nt"

    def get_module_name(self) -> str:
        """Return the module identifier."""
        return "drivers"

    def get_description(self) -> str:
        """Return module description."""
        return "Scans Windows drivers with signature and overlay detection"

    def is_available(self) -> bool:
        """Check if this module can run on the current system."""
        return self._is_windows

    def requires_admin(self) -> bool:
        """Check if admin privileges are required."""
        return True  # Full driver enumeration requires admin

    def scan(self) -> list[Component]:
        """Scan for all system drivers.

        Returns:
            List of discovered SystemDriver components.
        """
        if not self._is_windows:
            logger.warning("Drivers scanner is only available on Windows")
            return []

        drivers: list[Component] = []
        seen_names: set[str] = set()

        logger.info("Scanning system drivers...")

        # Get drivers via PowerShell/driverquery
        raw_drivers = self._get_drivers_powershell()

        if not raw_drivers:
            logger.warning("No drivers found via PowerShell, trying driverquery...")
            raw_drivers = self._get_drivers_driverquery()

        if not raw_drivers:
            logger.error("Failed to enumerate drivers")
            return drivers

        logger.info(f"Found {len(raw_drivers)} raw drivers")

        for raw_driver in raw_drivers:
            driver = self._process_driver(raw_driver)
            if driver:
                # Skip if already seen
                if driver.driver_name.lower() in seen_names:
                    continue
                seen_names.add(driver.driver_name.lower())

                # Skip Microsoft-signed unless requested
                if driver.is_microsoft_signed and not self.include_microsoft_drivers:
                    continue

                # Skip inbox drivers unless requested
                if driver.is_inbox_driver and not self.include_inbox_drivers:
                    continue

                # Detect overlay injectors
                if self.detect_overlay_injectors:
                    self._check_overlay_injector(driver)

                drivers.append(driver)

        logger.info(f"Processed {len(drivers)} third-party drivers")
        return drivers

    def _get_drivers_powershell(self) -> list[dict[str, Any]]:
        """Get drivers using PowerShell Get-WindowsDriver.

        Returns:
            List of driver dictionaries.
        """
        drivers: list[dict[str, Any]] = []

        try:
            # Get drivers with signature info
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                """
                Get-WindowsDriver -Online -All | Select-Object
                    Driver,
                    OriginalFileName,
                    Inbox,
                    ClassName,
                    ClassDescription,
                    BootCritical,
                    ProviderName,
                    Date,
                    Version
                | ConvertTo-Json -Compress
                """.replace("\n", " ")
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
            )

            if result.returncode != 0:
                logger.debug(f"Get-WindowsDriver error: {result.stderr}")
                return drivers

            if not result.stdout.strip():
                return drivers

            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]

            drivers = data

        except subprocess.TimeoutExpired:
            logger.error("PowerShell command timed out")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse PowerShell output: {e}")
        except Exception as e:
            logger.error(f"Error getting drivers via PowerShell: {e}")

        return drivers

    def _get_drivers_driverquery(self) -> list[dict[str, Any]]:
        """Get drivers using driverquery command (fallback).

        Returns:
            List of driver dictionaries.
        """
        drivers: list[dict[str, Any]] = []

        try:
            cmd = ["driverquery", "/v", "/fo", "csv"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
            )

            if result.returncode != 0:
                logger.error(f"driverquery error: {result.stderr}")
                return drivers

            # Parse CSV output
            lines = result.stdout.strip().split("\n")
            if len(lines) < 2:
                return drivers

            # Parse header
            import csv
            from io import StringIO

            reader = csv.DictReader(StringIO(result.stdout))
            for row in reader:
                drivers.append({
                    "Driver": row.get("Module Name", ""),
                    "OriginalFileName": row.get("Path", ""),
                    "ClassName": row.get("Type", ""),
                    "ProviderName": "",
                    "Date": row.get("Link Date", ""),
                    "State": row.get("State", ""),
                    "Inbox": False,
                })

        except Exception as e:
            logger.error(f"Error getting drivers via driverquery: {e}")

        return drivers

    def _process_driver(self, raw: dict[str, Any]) -> Optional[SystemDriver]:
        """Process a raw driver dictionary into a SystemDriver.

        Args:
            raw: Raw driver data.

        Returns:
            SystemDriver if valid, None otherwise.
        """
        driver_name = raw.get("Driver", "")
        if not driver_name:
            driver_name = raw.get("OriginalFileName", "")
            if driver_name:
                driver_name = Path(driver_name).stem

        if not driver_name:
            return None

        # Get file path
        original_file = raw.get("OriginalFileName", "") or ""
        driver_path = Path(original_file) if original_file else None

        # Determine driver type
        class_name = raw.get("ClassName", "") or ""
        driver_type = DriverType.from_string(class_name)

        # Get provider/signer
        provider = raw.get("ProviderName", "") or ""

        # Check if Microsoft signed
        is_microsoft = self._is_microsoft_provider(provider)

        # Check if inbox driver
        is_inbox = bool(raw.get("Inbox", False))

        # Get signature status (need separate check)
        sig_status = SignatureStatus.UNKNOWN
        if is_microsoft or is_inbox:
            sig_status = SignatureStatus.VALID

        # Create display name
        display_name = raw.get("ClassDescription", "") or driver_name

        # Normalize internal name
        internal_name = self._normalize_name(driver_name)

        return SystemDriver(
            component_type=ComponentType.DRIVER,
            name=internal_name,
            display_name=display_name,
            publisher=provider if provider else "Unknown",
            install_path=driver_path,
            driver_name=driver_name,
            driver_type=driver_type,
            signer=provider,
            signature_status=sig_status,
            driver_path=driver_path,
            driver_version=raw.get("Version", "") or "",
            driver_date=str(raw.get("Date", "")) if raw.get("Date") else "",
            inf_name=raw.get("Driver", "") or "",
            is_microsoft_signed=is_microsoft,
            is_inbox_driver=is_inbox,
            is_running=raw.get("State", "").lower() == "running" if raw.get("State") else True,
        )

    def _is_microsoft_provider(self, provider: str) -> bool:
        """Check if provider is Microsoft.

        Args:
            provider: Provider name.

        Returns:
            True if Microsoft, False otherwise.
        """
        if not provider:
            return False

        provider_lower = provider.lower()
        return any(ms in provider_lower for ms in [
            "microsoft",
            "windows",
            "ms-windows",
        ])

    def _check_overlay_injector(self, driver: SystemDriver) -> None:
        """Check if a driver appears to be an overlay injector.

        Args:
            driver: Driver to check.
        """
        check_strings = [
            driver.driver_name.lower(),
            driver.display_name.lower(),
            str(driver.driver_path).lower() if driver.driver_path else "",
        ]

        for check_str in check_strings:
            for pattern in OVERLAY_INJECTOR_PATTERNS:
                if re.match(pattern, check_str):
                    driver.is_overlay_injector = True
                    return

    def _normalize_name(self, name: str) -> str:
        """Normalize a driver name."""
        name = name.lower()
        name = re.sub(r"[^\w\s-]", "", name)
        name = re.sub(r"\s+", "-", name)
        return name.strip("-")

    def get_unsigned_drivers(self, drivers: list[SystemDriver]) -> list[SystemDriver]:
        """Get all unsigned drivers.

        Args:
            drivers: List of drivers to filter.

        Returns:
            List of unsigned drivers.
        """
        return [
            d for d in drivers
            if d.signature_status in [SignatureStatus.UNSIGNED, SignatureStatus.INVALID]
        ]

    def get_overlay_injectors(self, drivers: list[SystemDriver]) -> list[SystemDriver]:
        """Get all overlay injector drivers.

        Args:
            drivers: List of drivers to filter.

        Returns:
            List of overlay injector drivers.
        """
        return [d for d in drivers if d.is_overlay_injector]

    def is_problematic_publisher(self, driver: SystemDriver) -> bool:
        """Check if a driver is from a problematic publisher.

        Args:
            driver: Driver to check.

        Returns:
            True if problematic, False otherwise.
        """
        for pub in PROBLEMATIC_PUBLISHERS:
            if pub.lower() in driver.signer.lower():
                return True
            if pub.lower() in driver.display_name.lower():
                return True
        return False


def get_drivers_by_type(
    drivers: list[SystemDriver],
    driver_type: DriverType,
) -> list[SystemDriver]:
    """Get all drivers of a specific type.

    Args:
        drivers: List of all drivers.
        driver_type: Type to filter by.

    Returns:
        List of drivers of that type.
    """
    return [d for d in drivers if d.driver_type == driver_type]


def get_third_party_drivers(drivers: list[SystemDriver]) -> list[SystemDriver]:
    """Get all non-Microsoft drivers.

    Args:
        drivers: List of all drivers.

    Returns:
        List of third-party drivers.
    """
    return [d for d in drivers if not d.is_microsoft_signed and not d.is_inbox_driver]
