"""Hosts File Telemetry Blocker - System-wide telemetry endpoint blocking.

Blocks telemetry, advertising, and tracking endpoints by adding entries
to the Windows hosts file (C:\\Windows\\System32\\drivers\\etc\\hosts).

This provides system-wide blocking that works regardless of which
application is making the connection — better than per-app firewall rules.

All changes are reversible via snapshot/rollback.
"""

import logging
import os
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from src.core.models import ActionType, Snapshot
from src.core.powershell import SafePowerShell, create_powershell

logger = logging.getLogger("debloatr.actions.hosts_blocker")

# Sinkhole address — 0.0.0.0 is preferred over 127.0.0.1 because
# it fails instantly rather than waiting for a connection timeout.
SINKHOLE = "0.0.0.0"

# Marker comments to identify Debloatr-managed entries
BLOCK_START = "# >>> Debloatr Telemetry Block Start >>>"
BLOCK_END = "# <<< Debloatr Telemetry Block End <<<"

# Default hosts file location
HOSTS_FILE = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"

# Domains to block, organized by category
TELEMETRY_DOMAINS: dict[str, list[str]] = {
    "microsoft_telemetry": [
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
        "browser.pipe.aria.microsoft.com",
        "pipe.aria.microsoft.com",
    ],
    "microsoft_advertising": [
        "ads.microsoft.com",
        "adnxs.com",
        "adnexus.net",
        "flex.msn.com",
        "g.msn.com",
        "h1.msn.com",
        "ntp.msn.com",
        "arc.msn.com",
        "ris.api.iris.microsoft.com",
    ],
    "nvidia_telemetry": [
        "telemetry.nvidia.com",
        "gfe.nvidia.com",
        "gfwsl.geforce.com",
        "nvgs.nvidia.cn",
    ],
    "adobe_telemetry": [
        "cc-api-data.adobe.io",
        "ic.adobe.io",
        "adamatch-sec.adobe.com",
        "sstats.adobe.com",
        "adobeereg.com",
    ],
    "google_tracking": [
        "www.google-analytics.com",
        "google-analytics.com",
        "ssl.google-analytics.com",
        "app-measurement.com",
    ],
    "advertising_general": [
        "ad.doubleclick.net",
        "pagead2.googlesyndication.com",
        "adservice.google.com",
        "connect.facebook.net",
        "advertising.amazon.com",
        "data.flurry.com",
        "crashlytics.com",
    ],
}


@dataclass
class HostsBlockResult:
    """Result of a hosts file blocking operation.

    Attributes:
        success: Whether the operation succeeded
        domains_blocked: Number of domains added to hosts file
        domains_already_blocked: Number already present
        backup_path: Path to the backup of the original hosts file
        error_message: Error message if failed
        snapshot: Snapshot for rollback
        categories_applied: Which categories were applied
    """

    success: bool
    domains_blocked: int = 0
    domains_already_blocked: int = 0
    backup_path: Path | None = None
    error_message: str | None = None
    snapshot: Snapshot | None = None
    categories_applied: list[str] = field(default_factory=list)


class HostsFileBlocker:
    """Manages telemetry blocking via the Windows hosts file.

    Adds sinkhole entries (0.0.0.0) for known telemetry, advertising,
    and tracking domains. All entries are clearly marked with comment
    blocks so they can be identified and removed.

    Example:
        blocker = HostsFileBlocker()
        result = blocker.block_telemetry(["microsoft_telemetry", "advertising_general"])
        if result.success:
            print(f"Blocked {result.domains_blocked} domains")

        # To undo:
        blocker.unblock_all()
    """

    def __init__(
        self,
        dry_run: bool = False,
        hosts_path: Path | None = None,
        backup_dir: Path | None = None,
    ) -> None:
        """Initialize the hosts file blocker.

        Args:
            dry_run: If True, simulate without modifying the hosts file
            hosts_path: Override the default hosts file path
            backup_dir: Directory for hosts file backups
        """
        self.dry_run = dry_run
        self.hosts_path = hosts_path or HOSTS_FILE
        self.backup_dir = backup_dir or (
            Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "Debloatr" / "backups"
        )
        self._ps = create_powershell(dry_run=dry_run)

    def block_telemetry(
        self,
        categories: list[str] | None = None,
        custom_domains: list[str] | None = None,
    ) -> HostsBlockResult:
        """Block telemetry domains by adding hosts file entries.

        Args:
            categories: List of category keys from TELEMETRY_DOMAINS.
                       If None, blocks all categories.
            custom_domains: Additional custom domains to block.

        Returns:
            HostsBlockResult with operation details
        """
        # Determine which domains to block
        if categories is None:
            categories = list(TELEMETRY_DOMAINS.keys())

        domains_to_block: list[str] = []
        valid_categories: list[str] = []

        for category in categories:
            if category in TELEMETRY_DOMAINS:
                domains_to_block.extend(TELEMETRY_DOMAINS[category])
                valid_categories.append(category)
            else:
                logger.warning(f"Unknown telemetry category: {category}")

        if custom_domains:
            domains_to_block.extend(custom_domains)

        # Deduplicate
        domains_to_block = list(dict.fromkeys(domains_to_block))

        if not domains_to_block:
            return HostsBlockResult(
                success=False,
                error_message="No domains to block",
            )

        if self.dry_run:
            logger.info(f"[DRY RUN] Would block {len(domains_to_block)} domains in hosts file")
            return HostsBlockResult(
                success=True,
                domains_blocked=len(domains_to_block),
                categories_applied=valid_categories,
            )

        # Read current hosts file
        try:
            current_content = self._read_hosts()
        except Exception as e:
            return HostsBlockResult(
                success=False,
                error_message=f"Cannot read hosts file: {e}",
            )

        # Create backup
        backup_path = self._backup_hosts(current_content)

        # Create snapshot
        snapshot = Snapshot(
            component_id="hosts-file-blocker",
            action=ActionType.CONTAIN,
            captured_state={
                "original_content": current_content,
                "backup_path": str(backup_path) if backup_path else None,
                "categories": valid_categories,
            },
        )

        # Check which domains are already blocked
        existing_entries = self._parse_existing_blocks(current_content)
        already_blocked = 0
        new_domains: list[str] = []

        for domain in domains_to_block:
            if domain.lower() in existing_entries:
                already_blocked += 1
            else:
                new_domains.append(domain)

        if not new_domains:
            return HostsBlockResult(
                success=True,
                domains_blocked=0,
                domains_already_blocked=already_blocked,
                backup_path=backup_path,
                snapshot=snapshot,
                categories_applied=valid_categories,
            )

        # Build the block to append
        block_lines = [
            "",
            BLOCK_START,
            f"# Added by Debloatr on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"# Categories: {', '.join(valid_categories)}",
        ]
        for domain in new_domains:
            block_lines.append(f"{SINKHOLE} {domain}")
        block_lines.append(BLOCK_END)
        block_lines.append("")

        # Write the updated hosts file
        new_content = current_content.rstrip("\n") + "\n" + "\n".join(block_lines)

        try:
            self._write_hosts(new_content)
            # Flush DNS cache
            self._flush_dns()

            logger.info(f"Blocked {len(new_domains)} telemetry domains in hosts file")
            return HostsBlockResult(
                success=True,
                domains_blocked=len(new_domains),
                domains_already_blocked=already_blocked,
                backup_path=backup_path,
                snapshot=snapshot,
                categories_applied=valid_categories,
            )

        except Exception as e:
            logger.error(f"Failed to write hosts file: {e}")
            return HostsBlockResult(
                success=False,
                error_message=f"Failed to write hosts file: {e}",
                backup_path=backup_path,
                snapshot=snapshot,
            )

    def unblock_all(self) -> HostsBlockResult:
        """Remove all Debloatr-managed entries from the hosts file.

        Returns:
            HostsBlockResult with operation details
        """
        if self.dry_run:
            logger.info("[DRY RUN] Would remove all Debloatr blocks from hosts file")
            return HostsBlockResult(success=True)

        try:
            current_content = self._read_hosts()
        except Exception as e:
            return HostsBlockResult(
                success=False,
                error_message=f"Cannot read hosts file: {e}",
            )

        # Backup before modification
        backup_path = self._backup_hosts(current_content)

        # Remove Debloatr blocks
        cleaned = self._remove_debloatr_blocks(current_content)

        if cleaned == current_content:
            return HostsBlockResult(
                success=True,
                domains_blocked=0,
                backup_path=backup_path,
            )

        try:
            self._write_hosts(cleaned)
            self._flush_dns()
            logger.info("Removed all Debloatr telemetry blocks from hosts file")
            return HostsBlockResult(success=True, backup_path=backup_path)
        except Exception as e:
            return HostsBlockResult(
                success=False,
                error_message=f"Failed to write hosts file: {e}",
                backup_path=backup_path,
            )

    def get_blocked_domains(self) -> list[str]:
        """Get list of domains currently blocked by Debloatr.

        Returns:
            List of blocked domain names
        """
        try:
            content = self._read_hosts()
        except Exception:
            return []

        domains: list[str] = []
        in_block = False

        for line in content.splitlines():
            if BLOCK_START in line:
                in_block = True
                continue
            if BLOCK_END in line:
                in_block = False
                continue
            if in_block and not line.startswith("#") and line.strip():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == SINKHOLE:
                    domains.append(parts[1])

        return domains

    def get_available_categories(self) -> dict[str, int]:
        """Get available blocking categories and their domain counts.

        Returns:
            Dictionary of category name -> number of domains
        """
        return {cat: len(domains) for cat, domains in TELEMETRY_DOMAINS.items()}

    def _read_hosts(self) -> str:
        """Read the current hosts file content."""
        return self.hosts_path.read_text(encoding="utf-8", errors="replace")

    def _write_hosts(self, content: str) -> None:
        """Write content to the hosts file.

        Uses PowerShell with admin privileges since the hosts file
        is protected by system ACLs.
        """
        # Use PowerShell to write since hosts file is ACL-protected
        # Escape the content for PowerShell
        escaped = content.replace("'", "''")
        result = self._ps.run(
            f"Set-Content -Path '{self.hosts_path}' -Value '{escaped}' "
            f"-Encoding UTF8 -Force -ErrorAction Stop"
        )
        if not result.success:
            raise OSError(f"PowerShell write failed: {result.error}")

    def _backup_hosts(self, content: str) -> Path | None:
        """Create a backup of the hosts file."""
        try:
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = self.backup_dir / f"hosts_backup_{timestamp}"
            backup_path.write_text(content, encoding="utf-8")
            return backup_path
        except Exception as e:
            logger.warning(f"Failed to backup hosts file: {e}")
            return None

    def _parse_existing_blocks(self, content: str) -> set[str]:
        """Parse domains already blocked in the hosts file."""
        blocked: set[str] = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                # Check if it's a sinkhole entry
                if parts[0] in ("0.0.0.0", "127.0.0.1"):
                    blocked.add(parts[1].lower())
        return blocked

    def _remove_debloatr_blocks(self, content: str) -> str:
        """Remove all Debloatr-managed blocks from hosts content."""
        lines = content.splitlines()
        result_lines: list[str] = []
        in_block = False

        for line in lines:
            if BLOCK_START in line:
                in_block = True
                continue
            if BLOCK_END in line:
                in_block = False
                continue
            if not in_block:
                result_lines.append(line)

        # Remove trailing blank lines that may have been added
        while result_lines and result_lines[-1].strip() == "":
            result_lines.pop()

        return "\n".join(result_lines) + "\n"

    def _flush_dns(self) -> None:
        """Flush the Windows DNS resolver cache."""
        self._ps.run_command(["ipconfig", "/flushdns"])


def create_hosts_blocker(dry_run: bool = False) -> HostsFileBlocker:
    """Create a hosts file blocker.

    Args:
        dry_run: If True, simulate without changes

    Returns:
        HostsFileBlocker instance
    """
    return HostsFileBlocker(dry_run=dry_run)
