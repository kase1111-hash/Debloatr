"""Telemetry Scanner - Discovery module for telemetry and network activity.

This module scans for telemetry and network tracking components including:
- Processes with persistent network connections
- Known telemetry endpoint connections
- Background web helper processes
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

logger = logging.getLogger("debloatr.discovery.telemetry")


class ConnectionType(Enum):
    """Types of network connections."""

    PERSISTENT = "Persistent"  # Long-lived connection
    PERIODIC = "Periodic"  # Regular interval connection
    ON_DEMAND = "OnDemand"  # Connection on specific events
    UNKNOWN = "Unknown"


class EndpointCategory(Enum):
    """Categories of telemetry endpoints."""

    MICROSOFT = "Microsoft"
    THIRD_PARTY = "ThirdParty"
    ADVERTISING = "Advertising"
    ANALYTICS = "Analytics"
    UPDATE = "Update"
    UNKNOWN = "Unknown"


@dataclass
class NetworkEndpoint:
    """Represents a remote network endpoint."""

    address: str  # IP or hostname
    port: int
    protocol: str = "TCP"
    hostname: str = ""
    category: EndpointCategory = EndpointCategory.UNKNOWN
    is_known_telemetry: bool = False


@dataclass
class TelemetryComponent(Component):
    """Represents a telemetry/tracking component.

    Extends the base Component with telemetry-specific metadata.

    Attributes:
        process_name: Name of the process
        process_path: Path to the executable
        process_id: Current process ID
        remote_endpoints: List of remote connections
        connection_type: Type of network connection
        bytes_sent: Bytes sent (if available)
        bytes_received: Bytes received (if available)
        associated_service: Name of associated Windows service
        associated_program: Name of parent program
        is_background_process: Whether this runs in background
        is_known_telemetry: Whether this is a known telemetry process
        telemetry_category: Category of telemetry
    """

    process_name: str = ""
    process_path: Optional[Path] = None
    process_id: Optional[int] = None
    remote_endpoints: list[NetworkEndpoint] = field(default_factory=list)
    connection_type: ConnectionType = ConnectionType.UNKNOWN
    bytes_sent: int = 0
    bytes_received: int = 0
    associated_service: str = ""
    associated_program: str = ""
    is_background_process: bool = False
    is_known_telemetry: bool = False
    telemetry_category: EndpointCategory = EndpointCategory.UNKNOWN

    def __post_init__(self) -> None:
        """Set component type to TELEMETRY."""
        self.component_type = ComponentType.TELEMETRY


# Known Microsoft telemetry endpoints
MICROSOFT_TELEMETRY_ENDPOINTS = [
    # Windows telemetry
    "vortex.data.microsoft.com",
    "vortex-win.data.microsoft.com",
    "telecommand.telemetry.microsoft.com",
    "telecommand.telemetry.microsoft.com.nsatc.net",
    "oca.telemetry.microsoft.com",
    "oca.telemetry.microsoft.com.nsatc.net",
    "sqm.telemetry.microsoft.com",
    "sqm.telemetry.microsoft.com.nsatc.net",
    "watson.telemetry.microsoft.com",
    "watson.telemetry.microsoft.com.nsatc.net",
    "redir.metaservices.microsoft.com",
    "choice.microsoft.com",
    "choice.microsoft.com.nsatc.net",
    "df.telemetry.microsoft.com",
    "reports.wes.df.telemetry.microsoft.com",
    "wes.df.telemetry.microsoft.com",
    "services.wes.df.telemetry.microsoft.com",
    "sqm.df.telemetry.microsoft.com",
    "telemetry.microsoft.com",
    "watson.ppe.telemetry.microsoft.com",
    "telemetry.appex.bing.net",
    "telemetry.urs.microsoft.com",
    "telemetry.appex.bing.net:443",
    "settings-sandbox.data.microsoft.com",
    "vortex-sandbox.data.microsoft.com",
    "survey.watson.microsoft.com",
    "watson.live.com",
    "watson.microsoft.com",
    "statsfe2.ws.microsoft.com",
    "corpext.msitadfs.glbdns2.microsoft.com",
    "compatexchange.cloudapp.net",
    "cs1.wpc.v0cdn.net",
    "a-0001.a-msedge.net",
    "statsfe2.update.microsoft.com.akadns.net",
    "diagnostics.support.microsoft.com",
    # Cortana
    "www.bing.com",
    "bing.com",
    # Office telemetry
    "officeclient.microsoft.com",
    "config.office.com",
    "pipe.aria.microsoft.com",
    "nexus.officeapps.live.com",
    "nexusrules.officeapps.live.com",
]

# Known third-party telemetry endpoints
THIRD_PARTY_TELEMETRY_ENDPOINTS = [
    # NVIDIA
    "telemetry.nvidia.com",
    "gfe.nvidia.com",
    "gfwsl.geforce.com",
    "nvgs.nvidia.cn",
    # Adobe
    "cc-api-data.adobe.io",
    "ic.adobe.io",
    "adamatch-sec.adobe.com",
    "sstats.adobe.com",
    "adobeereg.com",
    # Google
    "www.google-analytics.com",
    "google-analytics.com",
    "ssl.google-analytics.com",
    "clientservices.googleapis.com",
    "update.googleapis.com",
    "clients1.google.com",
    "clients2.google.com",
    "clients3.google.com",
    "clients4.google.com",
    # Other
    "metrics.icloud.com",
    "data.flurry.com",
    "app-measurement.com",
    "crashlytics.com",
    "browser.pipe.aria.microsoft.com",
]

# Known advertising endpoints
ADVERTISING_ENDPOINTS = [
    "ads.microsoft.com",
    "ad.doubleclick.net",
    "ads.google.com",
    "adservice.google.com",
    "pagead2.googlesyndication.com",
    "analytics.google.com",
    "facebook.com",
    "connect.facebook.net",
    "advertising.amazon.com",
]

# Known telemetry process names
TELEMETRY_PROCESS_NAMES = [
    "DiagTrack",
    "dmwappushservice",
    "diagnosticshub.standardcollector.service",
    "CompatTelRunner",
    "wsqmcons",
    "PerfWatson2",
    "WmiPrvSE",  # Can be used for telemetry
    "backgroundTaskHost",
    "NvTelemetryContainer",
    "Adobe Desktop Service",
    "AdobeARM",
    "GoogleUpdate",
    "SoftwareReporterTool",
    "CrashReportClient",
]


class TelemetryScanner(BaseDiscoveryModule):
    """Discovery module for scanning telemetry and network tracking.

    Scans for processes with network connections and identifies
    known telemetry patterns.

    Example:
        scanner = TelemetryScanner()
        telemetry = scanner.scan()
        for t in telemetry:
            print(f"{t.process_name} -> {len(t.remote_endpoints)} endpoints")
    """

    def __init__(
        self,
        include_microsoft_telemetry: bool = True,
        include_update_connections: bool = False,
        minimum_connections: int = 1,
    ) -> None:
        """Initialize the telemetry scanner.

        Args:
            include_microsoft_telemetry: Whether to include Microsoft telemetry.
            include_update_connections: Whether to include update-related connections.
            minimum_connections: Minimum connections to report a process.
        """
        self.include_microsoft_telemetry = include_microsoft_telemetry
        self.include_update_connections = include_update_connections
        self.minimum_connections = minimum_connections
        self._is_windows = os.name == "nt"

        # Build endpoint lookup
        self._telemetry_endpoints: set[str] = set()
        self._build_endpoint_lookup()

    def _build_endpoint_lookup(self) -> None:
        """Build the telemetry endpoint lookup set."""
        for endpoint in MICROSOFT_TELEMETRY_ENDPOINTS:
            self._telemetry_endpoints.add(endpoint.lower())
        for endpoint in THIRD_PARTY_TELEMETRY_ENDPOINTS:
            self._telemetry_endpoints.add(endpoint.lower())
        for endpoint in ADVERTISING_ENDPOINTS:
            self._telemetry_endpoints.add(endpoint.lower())

    def get_module_name(self) -> str:
        """Return the module identifier."""
        return "telemetry"

    def get_description(self) -> str:
        """Return module description."""
        return "Scans for telemetry processes and network tracking"

    def is_available(self) -> bool:
        """Check if this module can run on the current system."""
        return self._is_windows

    def requires_admin(self) -> bool:
        """Check if admin privileges are required."""
        return True  # Need admin for full netstat -b output

    def scan(self) -> list[Component]:
        """Scan for telemetry components.

        Returns:
            List of discovered TelemetryComponent components.
        """
        if not self._is_windows:
            logger.warning("Telemetry scanner is only available on Windows")
            return []

        components: list[Component] = []
        seen_processes: set[str] = set()

        logger.info("Scanning for telemetry connections...")

        # Get network connections with process info
        connections = self._get_network_connections()

        if not connections:
            logger.warning("No network connections found")
            return components

        logger.info(f"Found {len(connections)} network connections")

        # Group connections by process
        process_connections: dict[str, list[dict]] = {}
        for conn in connections:
            pid = conn.get("ProcessId", 0)
            if pid:
                if pid not in process_connections:
                    process_connections[pid] = []
                process_connections[pid].append(conn)

        # Process each unique process
        for pid, conns in process_connections.items():
            if len(conns) < self.minimum_connections:
                continue

            component = self._process_connections(pid, conns)
            if component:
                key = f"{component.process_name}|{component.process_path}"
                if key in seen_processes:
                    continue
                seen_processes.add(key)

                # Filter based on options
                if not self.include_microsoft_telemetry:
                    if component.telemetry_category == EndpointCategory.MICROSOFT:
                        continue

                if not self.include_update_connections:
                    if component.telemetry_category == EndpointCategory.UPDATE:
                        continue

                components.append(component)

        logger.info(f"Found {len(components)} telemetry components")
        return components

    def _get_network_connections(self) -> list[dict[str, Any]]:
        """Get network connections with process information.

        Returns:
            List of connection dictionaries.
        """
        connections: list[dict[str, Any]] = []

        try:
            # Use PowerShell to get connections with process info
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                """
                Get-NetTCPConnection -State Established |
                ForEach-Object {
                    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                    [PSCustomObject]@{
                        LocalAddress = $_.LocalAddress
                        LocalPort = $_.LocalPort
                        RemoteAddress = $_.RemoteAddress
                        RemotePort = $_.RemotePort
                        State = $_.State
                        ProcessId = $_.OwningProcess
                        ProcessName = if ($proc) { $proc.Name } else { "" }
                        ProcessPath = if ($proc) { $proc.Path } else { "" }
                    }
                } | ConvertTo-Json -Compress
                """.replace("\n", " ")
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
            )

            if result.returncode != 0:
                logger.debug(f"PowerShell error: {result.stderr}")
                return connections

            if not result.stdout.strip():
                return connections

            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]

            connections = data

        except subprocess.TimeoutExpired:
            logger.error("PowerShell command timed out")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse output: {e}")
        except Exception as e:
            logger.error(f"Error getting connections: {e}")

        return connections

    def _process_connections(
        self,
        pid: int,
        connections: list[dict],
    ) -> Optional[TelemetryComponent]:
        """Process connections for a single process.

        Args:
            pid: Process ID.
            connections: List of connections for this process.

        Returns:
            TelemetryComponent if telemetry-related, None otherwise.
        """
        if not connections:
            return None

        # Get process info from first connection
        first_conn = connections[0]
        process_name = first_conn.get("ProcessName", "")
        process_path = first_conn.get("ProcessPath", "")

        if not process_name:
            return None

        # Build endpoint list
        endpoints: list[NetworkEndpoint] = []
        has_telemetry = False
        categories: set[EndpointCategory] = set()

        for conn in connections:
            remote_addr = conn.get("RemoteAddress", "")
            remote_port = conn.get("RemotePort", 0)

            if not remote_addr or remote_addr.startswith("127.") or remote_addr == "::1":
                continue  # Skip localhost

            # Check if known telemetry endpoint
            is_telemetry, category = self._check_endpoint(remote_addr)

            if is_telemetry:
                has_telemetry = True
                categories.add(category)

            endpoint = NetworkEndpoint(
                address=remote_addr,
                port=remote_port,
                protocol="TCP",
                category=category,
                is_known_telemetry=is_telemetry,
            )
            endpoints.append(endpoint)

        # Also check if process name indicates telemetry
        is_known_process = self._is_known_telemetry_process(process_name)

        # Only return if telemetry-related
        if not has_telemetry and not is_known_process:
            return None

        # Determine primary category
        primary_category = EndpointCategory.UNKNOWN
        if EndpointCategory.ADVERTISING in categories:
            primary_category = EndpointCategory.ADVERTISING
        elif EndpointCategory.ANALYTICS in categories:
            primary_category = EndpointCategory.ANALYTICS
        elif EndpointCategory.MICROSOFT in categories:
            primary_category = EndpointCategory.MICROSOFT
        elif EndpointCategory.THIRD_PARTY in categories:
            primary_category = EndpointCategory.THIRD_PARTY
        elif is_known_process:
            primary_category = EndpointCategory.MICROSOFT

        # Detect publisher
        publisher = self._detect_publisher(process_name, process_path)

        # Normalize name
        internal_name = self._normalize_name(process_name)

        return TelemetryComponent(
            component_type=ComponentType.TELEMETRY,
            name=internal_name,
            display_name=process_name,
            publisher=publisher,
            install_path=Path(process_path) if process_path else None,
            process_name=process_name,
            process_path=Path(process_path) if process_path else None,
            process_id=pid,
            remote_endpoints=endpoints,
            connection_type=ConnectionType.PERSISTENT,
            is_background_process=True,
            is_known_telemetry=has_telemetry or is_known_process,
            telemetry_category=primary_category,
        )

    def _check_endpoint(self, address: str) -> tuple[bool, EndpointCategory]:
        """Check if an address is a known telemetry endpoint.

        Args:
            address: IP or hostname.

        Returns:
            Tuple of (is_telemetry, category).
        """
        address_lower = address.lower()

        # Check Microsoft endpoints
        for endpoint in MICROSOFT_TELEMETRY_ENDPOINTS:
            if endpoint.lower() in address_lower or address_lower in endpoint.lower():
                return True, EndpointCategory.MICROSOFT

        # Check third-party endpoints
        for endpoint in THIRD_PARTY_TELEMETRY_ENDPOINTS:
            if endpoint.lower() in address_lower or address_lower in endpoint.lower():
                return True, EndpointCategory.THIRD_PARTY

        # Check advertising endpoints
        for endpoint in ADVERTISING_ENDPOINTS:
            if endpoint.lower() in address_lower or address_lower in endpoint.lower():
                return True, EndpointCategory.ADVERTISING

        # Check for common telemetry patterns
        telemetry_patterns = [
            r".*telemetry.*",
            r".*analytics.*",
            r".*tracking.*",
            r".*metrics.*",
            r".*diagnostic.*",
            r".*crash.*report.*",
        ]

        for pattern in telemetry_patterns:
            if re.match(pattern, address_lower):
                return True, EndpointCategory.ANALYTICS

        return False, EndpointCategory.UNKNOWN

    def _is_known_telemetry_process(self, process_name: str) -> bool:
        """Check if a process name is a known telemetry process.

        Args:
            process_name: Process name.

        Returns:
            True if known telemetry process.
        """
        name_lower = process_name.lower()
        for known in TELEMETRY_PROCESS_NAMES:
            if known.lower() in name_lower:
                return True
        return False

    def _detect_publisher(self, process_name: str, process_path: str) -> str:
        """Detect publisher from process info.

        Args:
            process_name: Process name.
            process_path: Process path.

        Returns:
            Publisher name.
        """
        combined = f"{process_name} {process_path}".lower()

        publishers = {
            "Microsoft": ["microsoft", "windows", "system32"],
            "NVIDIA": ["nvidia"],
            "Adobe": ["adobe"],
            "Google": ["google", "chrome"],
            "Intel": ["intel"],
            "Apple": ["apple", "itunes", "icloud"],
        }

        for publisher, patterns in publishers.items():
            for pattern in patterns:
                if pattern in combined:
                    return publisher

        return "Unknown"

    def _normalize_name(self, name: str) -> str:
        """Normalize a process name."""
        name = name.lower()
        name = re.sub(r"[^\w\s-]", "", name)
        name = re.sub(r"\s+", "-", name)
        return name.strip("-")

    def get_known_telemetry_endpoints(self) -> dict[str, list[str]]:
        """Get all known telemetry endpoints.

        Returns:
            Dictionary of category -> endpoints.
        """
        return {
            "microsoft": MICROSOFT_TELEMETRY_ENDPOINTS.copy(),
            "third_party": THIRD_PARTY_TELEMETRY_ENDPOINTS.copy(),
            "advertising": ADVERTISING_ENDPOINTS.copy(),
        }

    def is_telemetry_endpoint(self, address: str) -> bool:
        """Check if an address is a known telemetry endpoint.

        Args:
            address: Address to check.

        Returns:
            True if telemetry endpoint.
        """
        is_telemetry, _ = self._check_endpoint(address)
        return is_telemetry


def get_components_by_category(
    components: list[TelemetryComponent],
    category: EndpointCategory,
) -> list[TelemetryComponent]:
    """Get components by telemetry category.

    Args:
        components: List of components.
        category: Category to filter by.

    Returns:
        Filtered list.
    """
    return [c for c in components if c.telemetry_category == category]


def get_advertising_components(
    components: list[TelemetryComponent],
) -> list[TelemetryComponent]:
    """Get all advertising-related components.

    Args:
        components: List of components.

    Returns:
        Advertising components.
    """
    return [
        c for c in components
        if c.telemetry_category == EndpointCategory.ADVERTISING
        or any(e.category == EndpointCategory.ADVERTISING for e in c.remote_endpoints)
    ]
