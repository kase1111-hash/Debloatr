"""DNS Privacy Checker - Detects DNS configuration and privacy issues.

Checks the current DNS configuration and warns about plaintext DNS
leaks. Can detect and recommend DNS-over-HTTPS (DoH) configuration
on Windows 11, and suggest secure DNS providers.

Stock Windows sends all DNS queries in plaintext, exposing browsing
activity to ISPs and network observers. This module helps detect
and fix that.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from src.core.powershell import SafePowerShell, create_powershell

logger = logging.getLogger("debloatr.discovery.dns_privacy")


# Well-known secure DNS providers with DoH support
SECURE_DNS_PROVIDERS: dict[str, dict[str, Any]] = {
    "Cloudflare": {
        "primary_v4": "1.1.1.1",
        "secondary_v4": "1.0.0.1",
        "primary_v6": "2606:4700:4700::1111",
        "secondary_v6": "2606:4700:4700::1001",
        "doh_template": "https://cloudflare-dns.com/dns-query",
        "privacy_policy": "No logging of client IP. Logs purged within 24h.",
        "supports_doh": True,
    },
    "Quad9": {
        "primary_v4": "9.9.9.9",
        "secondary_v4": "149.112.112.112",
        "primary_v6": "2620:fe::fe",
        "secondary_v6": "2620:fe::9",
        "doh_template": "https://dns.quad9.net/dns-query",
        "privacy_policy": "Non-profit. No personal data logged. Malware blocking.",
        "supports_doh": True,
    },
    "Mullvad": {
        "primary_v4": "194.242.2.2",
        "secondary_v4": "194.242.2.3",
        "primary_v6": "2a07:e340::2",
        "secondary_v6": "2a07:e340::3",
        "doh_template": "https://dns.mullvad.net/dns-query",
        "privacy_policy": "No logging. Ad/tracker blocking available.",
        "supports_doh": True,
    },
    "Google": {
        "primary_v4": "8.8.8.8",
        "secondary_v4": "8.8.4.4",
        "primary_v6": "2001:4860:4860::8888",
        "secondary_v6": "2001:4860:4860::8844",
        "doh_template": "https://dns.google/dns-query",
        "privacy_policy": "Logs temporary data. Some data shared across Google services.",
        "supports_doh": True,
    },
}

# Known ISP DNS servers (common default gateways that indicate ISP DNS)
ISP_DNS_INDICATORS = [
    "192.168.",  # Local router (likely forwarding to ISP)
    "10.",       # Local network
    "172.16.",   # Local network
]

# Known secure DoH server IPs for detection
KNOWN_DOH_SERVERS: set[str] = set()
for provider in SECURE_DNS_PROVIDERS.values():
    KNOWN_DOH_SERVERS.add(provider["primary_v4"])
    KNOWN_DOH_SERVERS.add(provider["secondary_v4"])


@dataclass
class DNSStatus:
    """Current DNS configuration status.

    Attributes:
        interface_name: Network interface name
        dns_servers: List of configured DNS server addresses
        is_dhcp_assigned: Whether DNS was assigned by DHCP
        is_plaintext: Whether DNS queries are sent in plaintext
        doh_enabled: Whether DNS-over-HTTPS is enabled
        doh_template: DoH template URL if configured
        provider_name: Name of recognized DNS provider (if any)
        privacy_risk: Risk level ("high", "medium", "low")
        recommendations: List of recommended actions
    """

    interface_name: str
    dns_servers: list[str] = field(default_factory=list)
    is_dhcp_assigned: bool = False
    is_plaintext: bool = True
    doh_enabled: bool = False
    doh_template: str = ""
    provider_name: str = ""
    privacy_risk: str = "high"
    recommendations: list[str] = field(default_factory=list)


@dataclass
class DNSPrivacyReport:
    """Full DNS privacy assessment report.

    Attributes:
        interfaces: DNS status per network interface
        overall_risk: Overall privacy risk level
        overall_recommendations: Summary recommendations
        windows_version_supports_doh: Whether the OS supports native DoH
    """

    interfaces: list[DNSStatus] = field(default_factory=list)
    overall_risk: str = "high"
    overall_recommendations: list[str] = field(default_factory=list)
    windows_version_supports_doh: bool = False


class DNSPrivacyChecker:
    """Checks DNS configuration for privacy issues.

    Detects plaintext DNS, identifies DNS providers, checks for
    DoH support, and provides recommendations for secure DNS.

    Example:
        checker = DNSPrivacyChecker()
        report = checker.check()
        for iface in report.interfaces:
            print(f"{iface.interface_name}: risk={iface.privacy_risk}")
            for rec in iface.recommendations:
                print(f"  - {rec}")
    """

    def __init__(self, dry_run: bool = False) -> None:
        """Initialize the DNS privacy checker.

        Args:
            dry_run: If True, use simulated data
        """
        self.dry_run = dry_run
        self._ps = create_powershell(dry_run=dry_run)
        self._is_windows = os.name == "nt"

    def check(self) -> DNSPrivacyReport:
        """Perform a full DNS privacy check.

        Returns:
            DNSPrivacyReport with findings and recommendations
        """
        report = DNSPrivacyReport()

        # Check Windows version for DoH support (Win11 21H2+)
        report.windows_version_supports_doh = self._check_doh_support()

        if not self._is_windows:
            report.overall_risk = "unknown"
            report.overall_recommendations = ["DNS privacy check only available on Windows"]
            return report

        # Get DNS configuration for each interface
        interfaces = self._get_dns_config()

        for iface_data in interfaces:
            status = self._analyze_interface(iface_data, report.windows_version_supports_doh)
            report.interfaces.append(status)

        # Determine overall risk
        if not report.interfaces:
            report.overall_risk = "unknown"
            report.overall_recommendations = ["Could not determine DNS configuration"]
        else:
            risks = [i.privacy_risk for i in report.interfaces]
            if "high" in risks:
                report.overall_risk = "high"
            elif "medium" in risks:
                report.overall_risk = "medium"
            else:
                report.overall_risk = "low"

            # Build overall recommendations
            if report.overall_risk == "high":
                report.overall_recommendations.append(
                    "DNS queries are sent in plaintext — your ISP can see every domain you visit"
                )
                if report.windows_version_supports_doh:
                    report.overall_recommendations.append(
                        "Enable DNS-over-HTTPS in Windows Settings > Network > DNS"
                    )
                report.overall_recommendations.append(
                    "Switch to a privacy-respecting DNS provider (Cloudflare 1.1.1.1, Quad9, or Mullvad)"
                )
            elif report.overall_risk == "medium":
                report.overall_recommendations.append(
                    "DNS provider is known but DoH is not enabled — queries are still visible on the network"
                )
                if report.windows_version_supports_doh:
                    report.overall_recommendations.append(
                        "Enable DNS-over-HTTPS to encrypt DNS queries"
                    )

        return report

    def get_secure_providers(self) -> dict[str, dict[str, Any]]:
        """Get list of recommended secure DNS providers.

        Returns:
            Dictionary of provider name -> configuration details
        """
        return SECURE_DNS_PROVIDERS.copy()

    def configure_secure_dns(
        self,
        provider: str = "Cloudflare",
        interface_alias: str | None = None,
    ) -> dict[str, Any]:
        """Configure a secure DNS provider on the system.

        Args:
            provider: Name of the provider from SECURE_DNS_PROVIDERS
            interface_alias: Specific interface to configure (None = all active)

        Returns:
            Dictionary with success status and details
        """
        if provider not in SECURE_DNS_PROVIDERS:
            return {"success": False, "error": f"Unknown provider: {provider}"}

        config = SECURE_DNS_PROVIDERS[provider]

        if self.dry_run:
            logger.info(f"[DRY RUN] Would configure DNS to {provider}")
            return {"success": True, "dry_run": True, "provider": provider}

        if not self._is_windows:
            return {"success": False, "error": "Only available on Windows"}

        # Get target interfaces
        if interface_alias:
            interfaces = [interface_alias]
        else:
            interfaces = self._get_active_interfaces()

        if not interfaces:
            return {"success": False, "error": "No active network interfaces found"}

        results: list[dict[str, Any]] = []
        for iface in interfaces:
            result = self._set_dns_for_interface(iface, config)
            results.append({"interface": iface, **result})

        all_success = all(r.get("success", False) for r in results)
        return {
            "success": all_success,
            "provider": provider,
            "interfaces": results,
        }

    def _check_doh_support(self) -> bool:
        """Check if Windows version supports native DoH."""
        if not self._is_windows:
            return False

        result = self._ps.run(
            "[System.Environment]::OSVersion.Version.Build"
        )
        if result.success:
            try:
                build = int(result.output.strip())
                # DoH is available in Windows 11 (build 22000+)
                # and Windows 10 Insider builds 19628+
                return build >= 19628
            except ValueError:
                pass
        return False

    def _get_dns_config(self) -> list[dict[str, Any]]:
        """Get DNS configuration for all network interfaces."""
        result = self._ps.run(
            "Get-DnsClientServerAddress -AddressFamily IPv4 | "
            "Where-Object { $_.ServerAddresses.Count -gt 0 } | "
            "Select-Object InterfaceAlias, ServerAddresses, "
            "@{N='InterfaceIndex';E={$_.InterfaceIndex}} | "
            "ConvertTo-Json -Compress"
        )

        if not result.success or not result.output:
            return []

        try:
            data = json.loads(result.output)
            if isinstance(data, dict):
                data = [data]
            return data
        except (json.JSONDecodeError, TypeError):
            return []

    def _analyze_interface(
        self,
        iface_data: dict[str, Any],
        doh_available: bool,
    ) -> DNSStatus:
        """Analyze DNS configuration for a single interface."""
        name = iface_data.get("InterfaceAlias", "Unknown")
        servers = iface_data.get("ServerAddresses", [])

        status = DNSStatus(
            interface_name=name,
            dns_servers=servers,
        )

        if not servers:
            status.privacy_risk = "unknown"
            status.recommendations.append("No DNS servers configured")
            return status

        # Check if DHCP-assigned
        is_dhcp = self._is_dhcp_dns(iface_data)
        status.is_dhcp_assigned = is_dhcp

        # Identify provider
        for server in servers:
            provider = self._identify_provider(server)
            if provider:
                status.provider_name = provider
                break

        # Check if using local/ISP DNS
        is_local = any(
            any(server.startswith(prefix) for prefix in ISP_DNS_INDICATORS)
            for server in servers
        )

        # Check DoH status
        if doh_available:
            doh_status = self._check_doh_status(iface_data.get("InterfaceIndex"))
            status.doh_enabled = doh_status.get("enabled", False)
            status.doh_template = doh_status.get("template", "")

        # Determine risk and recommendations
        if status.doh_enabled:
            status.is_plaintext = False
            status.privacy_risk = "low"
        elif status.provider_name and not is_local:
            status.is_plaintext = True
            status.privacy_risk = "medium"
            status.recommendations.append(
                f"Using {status.provider_name} but without DoH encryption"
            )
            if doh_available:
                status.recommendations.append("Enable DoH to encrypt DNS queries")
        else:
            status.is_plaintext = True
            status.privacy_risk = "high"
            if is_dhcp or is_local:
                status.recommendations.append(
                    "Using ISP/router DNS — your ISP can monitor all your DNS queries"
                )
            status.recommendations.append(
                "Switch to a privacy-respecting DNS provider"
            )
            if doh_available:
                status.recommendations.append(
                    "Enable DNS-over-HTTPS for encrypted DNS"
                )

        return status

    def _identify_provider(self, server_ip: str) -> str:
        """Identify a DNS provider by IP address."""
        for name, config in SECURE_DNS_PROVIDERS.items():
            if server_ip in (config["primary_v4"], config["secondary_v4"]):
                return name
        return ""

    def _is_dhcp_dns(self, iface_data: dict[str, Any]) -> bool:
        """Check if DNS is assigned via DHCP for an interface."""
        idx = iface_data.get("InterfaceIndex")
        if idx is None:
            return False

        result = self._ps.run(
            f"(Get-DnsClient -InterfaceIndex {idx} -ErrorAction SilentlyContinue)"
            f".ConnectionSpecificDnsSuffix"
        )
        # If there's a connection-specific suffix, likely DHCP
        return bool(result.success and result.output.strip())

    def _check_doh_status(self, interface_index: int | None) -> dict[str, Any]:
        """Check DNS-over-HTTPS status for an interface."""
        if interface_index is None:
            return {"enabled": False}

        result = self._ps.run(
            f"Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | "
            f"ConvertTo-Json -Compress"
        )

        if result.success and result.output:
            try:
                data = json.loads(result.output)
                if isinstance(data, dict):
                    data = [data]
                if data:
                    return {
                        "enabled": True,
                        "template": data[0].get("DohTemplate", ""),
                    }
            except (json.JSONDecodeError, TypeError):
                pass

        return {"enabled": False}

    def _get_active_interfaces(self) -> list[str]:
        """Get names of active network interfaces."""
        result = self._ps.run(
            "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | "
            "Select-Object -ExpandProperty Name"
        )

        if result.success and result.output:
            return [n.strip() for n in result.output.strip().split("\n") if n.strip()]
        return []

    def _set_dns_for_interface(
        self,
        interface_alias: str,
        config: dict[str, Any],
    ) -> dict[str, Any]:
        """Set DNS servers for a specific interface."""
        primary = config["primary_v4"]
        secondary = config["secondary_v4"]

        result = self._ps.run(
            f"Set-DnsClientServerAddress -InterfaceAlias '{interface_alias}' "
            f"-ServerAddresses ('{primary}', '{secondary}') -ErrorAction Stop"
        )

        if not result.success:
            return {"success": False, "error": result.error}

        # If DoH template is available and supported, configure it
        doh_template = config.get("doh_template", "")
        if doh_template and self._check_doh_support():
            # Add DoH server configuration
            for server_ip in (primary, secondary):
                self._ps.run(
                    f"Add-DnsClientDohServerAddress -ServerAddress '{server_ip}' "
                    f"-DohTemplate '{doh_template}' -AllowFallbackToUdp $false "
                    f"-AutoUpgrade $true -ErrorAction SilentlyContinue"
                )

        return {"success": True}


def create_dns_checker(dry_run: bool = False) -> DNSPrivacyChecker:
    """Create a DNS privacy checker.

    Args:
        dry_run: If True, use simulated data

    Returns:
        DNSPrivacyChecker instance
    """
    return DNSPrivacyChecker(dry_run=dry_run)
