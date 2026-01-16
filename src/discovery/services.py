"""Windows Services Scanner - Discovery module for Windows services.

This module scans for Windows services and collects metadata including:
- Service configuration (name, display name, start type)
- Binary/executable path
- Account context (LocalSystem, NetworkService, etc.)
- Dependencies and dependents
- Network access patterns
- Recovery/restart behavior
"""

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from src.core.models import Component, ComponentType
from src.discovery.base import BaseDiscoveryModule

logger = logging.getLogger("debloatr.discovery.services")


class ServiceStartType(Enum):
    """Windows service start types."""

    BOOT = "Boot"  # Loaded by boot loader
    SYSTEM = "System"  # Loaded by I/O subsystem
    AUTOMATIC = "Automatic"  # Started by SCM at boot
    AUTOMATIC_DELAYED = "Automatic (Delayed Start)"  # Started after boot
    MANUAL = "Manual"  # Started on demand
    DISABLED = "Disabled"  # Cannot be started
    UNKNOWN = "Unknown"

    @classmethod
    def from_value(cls, value: int | str) -> "ServiceStartType":
        """Convert Windows start type value to enum.

        Args:
            value: Start type as int (0-4) or string.

        Returns:
            Corresponding ServiceStartType enum.
        """
        if isinstance(value, str):
            value_lower = value.lower()
            if "boot" in value_lower:
                return cls.BOOT
            elif "system" in value_lower:
                return cls.SYSTEM
            elif "auto" in value_lower:
                if "delayed" in value_lower:
                    return cls.AUTOMATIC_DELAYED
                return cls.AUTOMATIC
            elif "manual" in value_lower or "demand" in value_lower:
                return cls.MANUAL
            elif "disabled" in value_lower:
                return cls.DISABLED
            return cls.UNKNOWN

        # Integer mapping
        mapping = {
            0: cls.BOOT,
            1: cls.SYSTEM,
            2: cls.AUTOMATIC,
            3: cls.MANUAL,
            4: cls.DISABLED,
        }
        return mapping.get(value, cls.UNKNOWN)


class ServiceState(Enum):
    """Windows service runtime states."""

    RUNNING = "Running"
    STOPPED = "Stopped"
    PAUSED = "Paused"
    START_PENDING = "Start Pending"
    STOP_PENDING = "Stop Pending"
    PAUSE_PENDING = "Pause Pending"
    CONTINUE_PENDING = "Continue Pending"
    UNKNOWN = "Unknown"

    @classmethod
    def from_string(cls, state: str) -> "ServiceState":
        """Convert state string to enum."""
        state_lower = state.lower()
        for member in cls:
            if member.value.lower() == state_lower:
                return member
        return cls.UNKNOWN


class ServiceAccountType(Enum):
    """Common Windows service account types."""

    LOCAL_SYSTEM = "LocalSystem"
    LOCAL_SERVICE = "LocalService"
    NETWORK_SERVICE = "NetworkService"
    VIRTUAL_ACCOUNT = "VirtualAccount"
    MANAGED_SERVICE_ACCOUNT = "ManagedServiceAccount"
    USER_ACCOUNT = "UserAccount"
    UNKNOWN = "Unknown"

    @classmethod
    def from_string(cls, account: str) -> "ServiceAccountType":
        """Convert account string to enum."""
        if not account:
            return cls.UNKNOWN

        account_lower = account.lower()

        if "localsystem" in account_lower or account_lower == "system":
            return cls.LOCAL_SYSTEM
        elif "localservice" in account_lower or "local service" in account_lower:
            return cls.LOCAL_SERVICE
        elif "networkservice" in account_lower or "network service" in account_lower:
            return cls.NETWORK_SERVICE
        elif account_lower.startswith("nt service\\"):
            return cls.VIRTUAL_ACCOUNT
        elif account_lower.endswith("$"):
            return cls.MANAGED_SERVICE_ACCOUNT
        elif "\\" in account or "@" in account:
            return cls.USER_ACCOUNT

        return cls.UNKNOWN


@dataclass
class RecoveryAction:
    """Represents a service recovery action."""

    action_type: str  # "restart", "run_command", "reboot", "none"
    delay_ms: int = 0  # Delay before action
    command: str = ""  # Command to run (if action_type is "run_command")


@dataclass
class WindowsService(Component):
    """Represents a Windows service discovered on the system.

    Extends the base Component with service-specific metadata.

    Attributes:
        service_name: Internal service name (used by SCM)
        start_type: How the service starts (Auto, Manual, Disabled, etc.)
        current_state: Current runtime state
        binary_path: Path to the service executable
        account_context: Account the service runs under
        account_type: Type of account (LocalSystem, etc.)
        dependencies: Services this service depends on
        dependents: Services that depend on this service
        network_ports: Network ports the service listens on
        has_network_access: Whether service has network capabilities
        recovery_actions: Actions on service failure
        description: Service description
        can_stop: Whether service can be stopped
        can_pause: Whether service can be paused
        accepts_shutdown: Whether service accepts shutdown
        is_driver: Whether this is a kernel/filesystem driver
        parent_program: Name of parent program (if detected)
        process_id: Current process ID (if running)
    """

    service_name: str = ""
    start_type: ServiceStartType = ServiceStartType.UNKNOWN
    current_state: ServiceState = ServiceState.UNKNOWN
    binary_path: Path | None = None
    account_context: str = ""
    account_type: ServiceAccountType = ServiceAccountType.UNKNOWN
    dependencies: list[str] = field(default_factory=list)
    dependents: list[str] = field(default_factory=list)
    network_ports: list[int] = field(default_factory=list)
    has_network_access: bool = False
    recovery_actions: list[RecoveryAction] = field(default_factory=list)
    description: str = ""
    can_stop: bool = True
    can_pause: bool = False
    accepts_shutdown: bool = True
    is_driver: bool = False
    parent_program: str = ""
    process_id: int | None = None

    def __post_init__(self) -> None:
        """Set component type to SERVICE."""
        self.component_type = ComponentType.SERVICE


# Known critical Windows services that should never be disabled
CRITICAL_SERVICES = {
    "wuauserv": "Windows Update",
    "bits": "Background Intelligent Transfer Service",
    "rpcss": "Remote Procedure Call",
    "dcomlaunch": "DCOM Server Process Launcher",
    "lsm": "Local Session Manager",
    "samss": "Security Accounts Manager",
    "eventlog": "Windows Event Log",
    "plugplay": "Plug and Play",
    "power": "Power",
    "profservice": "User Profile Service",
    "schedule": "Task Scheduler",
    "sppsvc": "Software Protection",
    "windefend": "Windows Defender",
    "mpssvc": "Windows Firewall",
    "bfe": "Base Filtering Engine",
    "cryptsvc": "Cryptographic Services",
    "dnscache": "DNS Client",
    "lanmanserver": "Server",
    "lanmanworkstation": "Workstation",
    "netlogon": "Netlogon",
    "nsi": "Network Store Interface Service",
    "w32time": "Windows Time",
}

# Known telemetry/tracking services
TELEMETRY_SERVICES = {
    "diagtrack": "Connected User Experiences and Telemetry",
    "dmwappushservice": "Device Management WAP Push",
    "diagnosticshub.standardcollector.service": "Diagnostics Hub",
    "nvtelemetrycontainer": "NVIDIA Telemetry",
    "adobearmservice": "Adobe ARM",
}

# Map publishers to their common service patterns
PUBLISHER_SERVICE_PATTERNS = {
    "Microsoft": ["microsoft", "windows", "mssql", "dotnet"],
    "Adobe": ["adobe", "acrobat", "creative cloud"],
    "Google": ["google", "chrome", "gupdate"],
    "NVIDIA": ["nvidia", "nv"],
    "Intel": ["intel", "igfx"],
    "AMD": ["amd", "radeon"],
    "Realtek": ["realtek", "rtk"],
}


class ServicesScanner(BaseDiscoveryModule):
    """Discovery module for scanning Windows services.

    Scans for Windows services and collects detailed metadata including
    dependencies, network access, and recovery configuration.

    Example:
        scanner = ServicesScanner()
        services = scanner.scan()
        for svc in services:
            print(f"{svc.display_name} ({svc.start_type.value})")
    """

    def __init__(
        self,
        include_drivers: bool = False,
        analyze_network: bool = True,
        build_dependency_graph: bool = True,
    ) -> None:
        """Initialize the services scanner.

        Args:
            include_drivers: Whether to include kernel/filesystem drivers.
            analyze_network: Whether to analyze network access patterns.
            build_dependency_graph: Whether to build the full dependency graph.
        """
        self.include_drivers = include_drivers
        self.analyze_network = analyze_network
        self.build_dependency_graph = build_dependency_graph
        self._is_windows = os.name == "nt"
        self._network_ports_cache: dict[int, list[int]] = {}

    def get_module_name(self) -> str:
        """Return the module identifier."""
        return "services"

    def get_description(self) -> str:
        """Return module description."""
        return "Scans Windows services with dependency and network analysis"

    def is_available(self) -> bool:
        """Check if this module can run on the current system."""
        return self._is_windows

    def requires_admin(self) -> bool:
        """Check if admin privileges are required."""
        # Full scanning works better with admin but basic works without
        return False

    def scan(self) -> list[Component]:
        """Scan for all Windows services.

        Returns:
            List of discovered WindowsService components.
        """
        if not self._is_windows:
            logger.warning("Services scanner is only available on Windows")
            return []

        services: list[Component] = []

        logger.info("Scanning Windows services...")

        # Get basic service list via PowerShell
        raw_services = self._get_services_powershell()

        if not raw_services:
            logger.warning("No services found via PowerShell, trying WMI...")
            raw_services = self._get_services_wmi()

        if not raw_services:
            logger.error("Failed to enumerate services")
            return services

        logger.info(f"Found {len(raw_services)} raw services")

        # Build network ports cache if analyzing network
        if self.analyze_network:
            self._build_network_ports_cache()

        # Process each service
        for raw_svc in raw_services:
            service = self._process_service(raw_svc)
            if service:
                # Skip drivers unless explicitly requested
                if service.is_driver and not self.include_drivers:
                    continue
                services.append(service)

        # Build dependency graph if requested
        if self.build_dependency_graph:
            self._populate_dependents(services)

        logger.info(f"Processed {len(services)} services")
        return services

    def _get_services_powershell(self) -> list[dict[str, Any]]:
        """Get services using PowerShell.

        Returns:
            List of service dictionaries.
        """
        services: list[dict[str, Any]] = []

        try:
            # Comprehensive PowerShell command to get service details
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                """
                Get-CimInstance Win32_Service | Select-Object
                    Name,
                    DisplayName,
                    Description,
                    PathName,
                    StartMode,
                    State,
                    StartName,
                    ServiceType,
                    ProcessId,
                    AcceptStop,
                    AcceptPause,
                    @{N='Dependencies';E={($_.ServiceDependencies -join ',')}},
                    @{N='DependentServices';E={(Get-Service $_.Name -ErrorAction SilentlyContinue).DependentServices.Name -join ','}}
                | ConvertTo-Json -Compress
                """.replace(
                    "\n", " "
                ),
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
                ),
            )

            if result.returncode != 0:
                logger.error(f"PowerShell error: {result.stderr}")
                return services

            if not result.stdout.strip():
                return services

            data = json.loads(result.stdout)

            # Handle single service (not a list)
            if isinstance(data, dict):
                data = [data]

            services = data

        except subprocess.TimeoutExpired:
            logger.error("PowerShell command timed out")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse PowerShell output: {e}")
        except FileNotFoundError:
            logger.error("PowerShell not found")
        except Exception as e:
            logger.error(f"Error getting services via PowerShell: {e}")

        return services

    def _get_services_wmi(self) -> list[dict[str, Any]]:
        """Get services using WMI (fallback method).

        Returns:
            List of service dictionaries.
        """
        services: list[dict[str, Any]] = []

        try:
            import wmi

            c = wmi.WMI()

            for svc in c.Win32_Service():
                services.append(
                    {
                        "Name": svc.Name,
                        "DisplayName": svc.DisplayName,
                        "Description": svc.Description,
                        "PathName": svc.PathName,
                        "StartMode": svc.StartMode,
                        "State": svc.State,
                        "StartName": svc.StartName,
                        "ServiceType": svc.ServiceType,
                        "ProcessId": svc.ProcessId,
                        "AcceptStop": svc.AcceptStop,
                        "AcceptPause": svc.AcceptPause,
                    }
                )

        except ImportError:
            logger.debug("WMI module not available")
        except Exception as e:
            logger.error(f"Error getting services via WMI: {e}")

        return services

    def _process_service(self, raw: dict[str, Any]) -> WindowsService | None:
        """Process a raw service dictionary into a WindowsService.

        Args:
            raw: Raw service data from PowerShell/WMI.

        Returns:
            WindowsService if valid, None otherwise.
        """
        name = raw.get("Name", "")
        if not name:
            return None

        display_name = raw.get("DisplayName", name)
        description = raw.get("Description", "") or ""

        # Parse binary path
        path_name = raw.get("PathName", "") or ""
        binary_path = self._parse_binary_path(path_name)

        # Parse start type
        start_mode = raw.get("StartMode", "Unknown") or "Unknown"
        start_type = ServiceStartType.from_value(start_mode)

        # Parse current state
        state = raw.get("State", "Unknown") or "Unknown"
        current_state = ServiceState.from_string(state)

        # Parse account context
        account = raw.get("StartName", "") or ""
        account_type = ServiceAccountType.from_string(account)

        # Parse dependencies
        deps_str = raw.get("Dependencies", "") or ""
        dependencies = [d.strip() for d in deps_str.split(",") if d.strip()]

        # Parse dependents
        dependents_str = raw.get("DependentServices", "") or ""
        dependents = [d.strip() for d in dependents_str.split(",") if d.strip()]

        # Check if this is a driver
        service_type = raw.get("ServiceType", "") or ""
        is_driver = "driver" in service_type.lower() if service_type else False

        # Determine publisher from path
        publisher = self._detect_publisher(binary_path, display_name)

        # Check network access
        process_id = raw.get("ProcessId")
        network_ports: list[int] = []
        has_network = False

        if self.analyze_network and process_id and process_id > 0:
            network_ports = self._network_ports_cache.get(process_id, [])
            has_network = len(network_ports) > 0

        # Get recovery actions
        recovery_actions = self._get_recovery_actions(name)

        # Create normalized internal name
        internal_name = name.lower().replace(" ", "-")

        return WindowsService(
            component_type=ComponentType.SERVICE,
            name=internal_name,
            display_name=display_name,
            publisher=publisher,
            install_path=binary_path,
            service_name=name,
            start_type=start_type,
            current_state=current_state,
            binary_path=binary_path,
            account_context=account,
            account_type=account_type,
            dependencies=dependencies,
            dependents=dependents,
            network_ports=network_ports,
            has_network_access=has_network,
            recovery_actions=recovery_actions,
            description=description,
            can_stop=bool(raw.get("AcceptStop", True)),
            can_pause=bool(raw.get("AcceptPause", False)),
            is_driver=is_driver,
            process_id=process_id if process_id and process_id > 0 else None,
        )

    def _parse_binary_path(self, path_name: str) -> Path | None:
        """Parse a service binary path.

        Windows service paths can include:
        - Quoted paths: "C:\\Program Files\\app.exe" -arg
        - Unquoted paths: C:\\Windows\\System32\\svchost.exe -k netsvcs
        - Environment variables: %SystemRoot%\\System32\\...

        Args:
            path_name: Raw path from registry/WMI.

        Returns:
            Parsed Path object, or None if invalid.
        """
        if not path_name:
            return None

        # Expand environment variables
        path_name = os.path.expandvars(path_name)

        # Handle quoted paths
        if path_name.startswith('"'):
            match = re.match(r'"([^"]+)"', path_name)
            if match:
                return Path(match.group(1))

        # Handle unquoted paths - find the executable
        # Look for common executable extensions
        for ext in [".exe", ".sys", ".dll"]:
            idx = path_name.lower().find(ext)
            if idx != -1:
                return Path(path_name[: idx + len(ext)])

        # Fallback: take up to first space (if no extension found)
        parts = path_name.split()
        if parts:
            return Path(parts[0])

        return None

    def _detect_publisher(
        self,
        binary_path: Path | None,
        display_name: str,
    ) -> str:
        """Detect the publisher of a service.

        Args:
            binary_path: Path to service binary.
            display_name: Service display name.

        Returns:
            Publisher name.
        """
        if not binary_path:
            return "Unknown"

        path_str = str(binary_path).lower()

        # Check path for common publishers
        for publisher, patterns in PUBLISHER_SERVICE_PATTERNS.items():
            for pattern in patterns:
                if pattern in path_str:
                    return publisher

        # Check if it's a Windows system service
        if "\\windows\\" in path_str or "\\system32\\" in path_str:
            return "Microsoft"

        # Check display name
        display_lower = display_name.lower()
        for publisher, patterns in PUBLISHER_SERVICE_PATTERNS.items():
            for pattern in patterns:
                if pattern in display_lower:
                    return publisher

        return "Unknown"

    def _build_network_ports_cache(self) -> None:
        """Build a cache mapping process IDs to network ports."""
        self._network_ports_cache.clear()

        try:
            # Use netstat to get listening ports
            cmd = ["netstat", "-ano", "-p", "TCP"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
                ),
            )

            if result.returncode != 0:
                return

            for line in result.stdout.splitlines():
                # Parse netstat output
                # Format: TCP    0.0.0.0:135    0.0.0.0:0    LISTENING    1234
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "TCP" and "LISTENING" in parts:
                    try:
                        local_addr = parts[1]
                        pid = int(parts[-1])

                        # Extract port from address
                        if ":" in local_addr:
                            port = int(local_addr.split(":")[-1])

                            if pid not in self._network_ports_cache:
                                self._network_ports_cache[pid] = []
                            if port not in self._network_ports_cache[pid]:
                                self._network_ports_cache[pid].append(port)

                    except (ValueError, IndexError):
                        continue

        except Exception as e:
            logger.debug(f"Error building network cache: {e}")

    def _get_recovery_actions(self, service_name: str) -> list[RecoveryAction]:
        """Get recovery actions for a service.

        Args:
            service_name: Name of the service.

        Returns:
            List of recovery actions.
        """
        actions: list[RecoveryAction] = []

        try:
            # Query service recovery config via sc.exe
            cmd = ["sc.exe", "qfailure", service_name]
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
                return actions

            # Parse output
            # Format:
            # FAILURE_ACTIONS         : RESTART -- Delay = 60000 milliseconds
            for line in result.stdout.splitlines():
                if "RESTART" in line:
                    delay = self._parse_delay(line)
                    actions.append(RecoveryAction("restart", delay))
                elif "RUN PROCESS" in line:
                    delay = self._parse_delay(line)
                    actions.append(RecoveryAction("run_command", delay))
                elif "REBOOT" in line:
                    delay = self._parse_delay(line)
                    actions.append(RecoveryAction("reboot", delay))

        except Exception as e:
            logger.debug(f"Error getting recovery actions for {service_name}: {e}")

        return actions

    def _parse_delay(self, line: str) -> int:
        """Parse delay value from sc.exe output line.

        Args:
            line: Output line containing delay.

        Returns:
            Delay in milliseconds.
        """
        match = re.search(r"Delay\s*=\s*(\d+)", line)
        if match:
            return int(match.group(1))
        return 0

    def _populate_dependents(self, services: list[Component]) -> None:
        """Populate the dependents field for all services.

        This builds a reverse dependency map so each service knows
        what other services depend on it.

        Args:
            services: List of WindowsService components.
        """
        # Build reverse dependency map
        dependents_map: dict[str, list[str]] = {}

        for svc in services:
            if not isinstance(svc, WindowsService):
                continue

            for dep in svc.dependencies:
                dep_lower = dep.lower()
                if dep_lower not in dependents_map:
                    dependents_map[dep_lower] = []
                dependents_map[dep_lower].append(svc.service_name)

        # Update each service with its dependents
        for svc in services:
            if not isinstance(svc, WindowsService):
                continue

            svc_lower = svc.service_name.lower()
            if svc_lower in dependents_map:
                # Merge with any existing dependents
                existing = set(svc.dependents)
                existing.update(dependents_map[svc_lower])
                svc.dependents = list(existing)

    def get_critical_services(self) -> dict[str, str]:
        """Get the list of critical Windows services.

        Returns:
            Dictionary mapping service name to description.
        """
        return CRITICAL_SERVICES.copy()

    def get_telemetry_services(self) -> dict[str, str]:
        """Get the list of known telemetry services.

        Returns:
            Dictionary mapping service name to description.
        """
        return TELEMETRY_SERVICES.copy()

    def is_critical_service(self, service_name: str) -> bool:
        """Check if a service is critical to system operation.

        Args:
            service_name: Service name to check.

        Returns:
            True if critical, False otherwise.
        """
        return service_name.lower() in CRITICAL_SERVICES

    def is_telemetry_service(self, service_name: str) -> bool:
        """Check if a service is a known telemetry service.

        Args:
            service_name: Service name to check.

        Returns:
            True if telemetry service, False otherwise.
        """
        return service_name.lower() in TELEMETRY_SERVICES


def get_service_dependency_chain(
    services: list[WindowsService],
    service_name: str,
) -> list[str]:
    """Get the full dependency chain for a service.

    Args:
        services: List of all services.
        service_name: Service to get dependencies for.

    Returns:
        List of service names in dependency order.
    """
    # Build service lookup
    svc_map = {svc.service_name.lower(): svc for svc in services}

    visited: set[str] = set()
    chain: list[str] = []

    def visit(name: str) -> None:
        name_lower = name.lower()
        if name_lower in visited:
            return
        visited.add(name_lower)

        svc = svc_map.get(name_lower)
        if svc:
            for dep in svc.dependencies:
                visit(dep)

        chain.append(name)

    visit(service_name)
    return chain


def get_services_by_account(
    services: list[WindowsService],
    account_type: ServiceAccountType,
) -> list[WindowsService]:
    """Get all services running under a specific account type.

    Args:
        services: List of all services.
        account_type: Account type to filter by.

    Returns:
        List of services using that account type.
    """
    return [svc for svc in services if svc.account_type == account_type]
