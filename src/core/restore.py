"""System Restore Integration - Windows System Restore point management.

This module provides integration with Windows System Restore for
creating restore points before batch operations and restoring to
previous states.
"""

import logging
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Any

logger = logging.getLogger("debloatr.core.restore")


@dataclass
class RestorePoint:
    """Information about a Windows System Restore point.

    Attributes:
        sequence_number: Unique sequence number
        description: Description of the restore point
        creation_time: When the restore point was created
        restore_point_type: Type of restore point
        event_type: Event that triggered the restore point
    """

    sequence_number: int
    description: str
    creation_time: datetime
    restore_point_type: str
    event_type: str


class RestorePointType:
    """Constants for System Restore point types."""

    APPLICATION_INSTALL = 0
    APPLICATION_UNINSTALL = 1
    DEVICE_DRIVER_INSTALL = 10
    MODIFY_SETTINGS = 12
    CANCELLED_OPERATION = 13


class SystemRestoreManager:
    """Manager for Windows System Restore operations.

    Provides methods to create restore points, list available points,
    and check System Restore status.

    Example:
        manager = SystemRestoreManager()

        if manager.is_enabled():
            restore_id = manager.create_restore_point("Before debloat operation")
            # ... perform operations ...

            # If needed, restore
            manager.restore_to_point(restore_id)
    """

    def __init__(self, dry_run: bool = False) -> None:
        """Initialize the System Restore manager.

        Args:
            dry_run: If True, simulate operations without changes
        """
        self.dry_run = dry_run
        self._is_windows = os.name == "nt"

    def is_available(self) -> bool:
        """Check if System Restore is available on this system.

        Returns:
            True if System Restore is available
        """
        if not self._is_windows:
            return False

        result = self._run_powershell(
            "Get-ComputerRestorePoint -ErrorAction SilentlyContinue | " "Select-Object -First 1"
        )

        # System Restore is available even if no points exist
        # Check if the command didn't fail due to access denied
        return "Access" not in result.get("error", "") or result["success"]

    def is_enabled(self) -> bool:
        """Check if System Restore is enabled for the system drive.

        Returns:
            True if System Restore is enabled
        """
        if not self._is_windows:
            return False

        result = self._run_powershell(
            "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore' "
            "-Name 'RPSessionInterval' -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty RPSessionInterval"
        )

        if result["success"]:
            try:
                # If RPSessionInterval is 0, System Restore is disabled
                interval = int(result["output"].strip())
                return interval != 0
            except (ValueError, AttributeError):
                pass

        # Try alternative check
        result = self._run_powershell(
            "(Get-WmiObject -Class SystemRestoreConfig -Namespace 'root\\default' "
            "-ErrorAction SilentlyContinue).RPSessionInterval"
        )

        if result["success"] and result["output"]:
            try:
                return int(result["output"].strip()) != 0
            except ValueError:
                pass

        # Assume enabled if we can't determine
        return True

    def get_protection_status(self) -> dict[str, Any]:
        """Get System Protection status for all drives.

        Returns:
            Dictionary with drive protection status
        """
        if not self._is_windows:
            return {"enabled": False, "error": "Not Windows"}

        result = self._run_powershell(
            'Get-WmiObject -Class Win32_Volume -Filter "DriveType=3" | '
            "ForEach-Object { "
            "$protection = (vssadmin list shadowstorage /for=$($_.DriveLetter) 2>&1); "
            "@{Drive=$_.DriveLetter; Protected=($protection -notmatch 'No shadow')} "
            "} | ConvertTo-Json"
        )

        if result["success"] and result["output"]:
            try:
                import json

                return {"drives": json.loads(result["output"])}
            except Exception:
                pass

        return {"enabled": self.is_enabled()}

    def create_restore_point(
        self,
        description: str,
        restore_point_type: int = RestorePointType.MODIFY_SETTINGS,
    ) -> int | None:
        """Create a System Restore point.

        Args:
            description: Description for the restore point
            restore_point_type: Type of restore point

        Returns:
            Sequence number of created restore point, or None if failed
        """
        if not self._is_windows:
            logger.warning("System Restore only available on Windows")
            return None

        if self.dry_run:
            logger.info(f"[DRY RUN] Would create restore point: {description}")
            return 0

        # Enable the ability to create restore points in quick succession
        # (Windows normally limits to one per 24 hours)
        self._run_powershell(
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore' "
            "-Name 'SystemRestorePointCreationFrequency' -Value 0 -Type DWord -Force "
            "-ErrorAction SilentlyContinue"
        )

        # Create the restore point
        result = self._run_powershell(
            f"Checkpoint-Computer -Description '{description}' "
            f"-RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop"
        )

        if not result["success"]:
            logger.error(f"Failed to create restore point: {result['error']}")
            return None

        # Get the sequence number of the created restore point
        points = self.list_restore_points(limit=1)
        if points:
            logger.info(f"Created restore point: {description} (#{points[0].sequence_number})")
            return points[0].sequence_number

        return None

    def list_restore_points(self, limit: int = 20) -> list[RestorePoint]:
        """List available System Restore points.

        Args:
            limit: Maximum number of points to return

        Returns:
            List of RestorePoint objects (newest first)
        """
        if not self._is_windows:
            return []

        result = self._run_powershell(
            f"Get-ComputerRestorePoint | Sort-Object -Property SequenceNumber -Descending | "
            f"Select-Object -First {limit} | "
            f"Select-Object SequenceNumber, Description, CreationTime, RestorePointType, EventType | "
            f"ConvertTo-Json"
        )

        if not result["success"] or not result["output"]:
            return []

        try:
            import json

            data = json.loads(result["output"])

            # Handle single result (not a list)
            if isinstance(data, dict):
                data = [data]

            points: list[RestorePoint] = []
            for item in data:
                try:
                    # Parse WMI date format
                    creation_str = str(item.get("CreationTime", ""))
                    if "/Date(" in creation_str:
                        # Extract timestamp from /Date(timestamp)/
                        timestamp = int(
                            creation_str.split("(")[1].split(")")[0].split("+")[0].split("-")[0]
                        )
                        creation_time = datetime.fromtimestamp(timestamp / 1000)
                    else:
                        creation_time = datetime.now()

                    point = RestorePoint(
                        sequence_number=int(item.get("SequenceNumber", 0)),
                        description=str(item.get("Description", "")),
                        creation_time=creation_time,
                        restore_point_type=self._get_restore_type_name(
                            item.get("RestorePointType", 0)
                        ),
                        event_type=self._get_event_type_name(item.get("EventType", 0)),
                    )
                    points.append(point)
                except Exception as e:
                    logger.debug(f"Error parsing restore point: {e}")
                    continue

            return points

        except Exception as e:
            logger.error(f"Failed to parse restore points: {e}")
            return []

    def get_restore_point(self, sequence_number: int) -> RestorePoint | None:
        """Get a specific restore point by sequence number.

        Args:
            sequence_number: Sequence number of the restore point

        Returns:
            RestorePoint or None if not found
        """
        points = self.list_restore_points(limit=100)
        for point in points:
            if point.sequence_number == sequence_number:
                return point
        return None

    def delete_restore_point(self, sequence_number: int) -> bool:
        """Delete a specific restore point.

        Args:
            sequence_number: Sequence number to delete

        Returns:
            True if deleted successfully
        """
        if not self._is_windows:
            return False

        if self.dry_run:
            logger.info(f"[DRY RUN] Would delete restore point #{sequence_number}")
            return True

        # Use vssadmin to delete the shadow copy
        result = self._run_command("vssadmin delete shadows /shadow={sequence_number} /quiet")

        # Alternative: use WMI
        if not result["success"]:
            result = self._run_powershell(
                f"(Get-WmiObject -Class SystemRestore -Namespace 'root\\default' | "
                f"Where-Object {{ $_.SequenceNumber -eq {sequence_number} }}).Delete()"
            )

        return result["success"]

    def restore_to_point(
        self,
        sequence_number: int,
        confirm: bool = True,
    ) -> dict[str, Any]:
        """Initiate system restore to a specific point.

        NOTE: This will restart the computer and cannot be undone.
        The function returns information about the operation but
        the actual restore happens after reboot.

        Args:
            sequence_number: Sequence number to restore to
            confirm: If False, won't actually initiate restore

        Returns:
            Dictionary with operation status
        """
        if not self._is_windows:
            return {"success": False, "error": "Not Windows"}

        # Verify the restore point exists
        point = self.get_restore_point(sequence_number)
        if not point:
            return {
                "success": False,
                "error": f"Restore point #{sequence_number} not found",
            }

        if self.dry_run or not confirm:
            return {
                "success": True,
                "dry_run": True,
                "point": {
                    "sequence_number": point.sequence_number,
                    "description": point.description,
                    "creation_time": point.creation_time.isoformat(),
                },
                "message": f"Would restore to: {point.description}",
            }

        # Initiate system restore
        # This will trigger a reboot
        result = self._run_powershell(
            f"Restore-Computer -RestorePoint {sequence_number} -Confirm:$false"
        )

        if result["success"]:
            return {
                "success": True,
                "point": {
                    "sequence_number": point.sequence_number,
                    "description": point.description,
                },
                "message": "System restore initiated. Computer will restart.",
            }
        else:
            return {
                "success": False,
                "error": result["error"],
            }

    def get_debloatr_restore_points(self) -> list[RestorePoint]:
        """Get restore points created by Debloatr.

        Returns:
            List of Debloatr-created restore points
        """
        all_points = self.list_restore_points(limit=100)
        return [
            p
            for p in all_points
            if "Debloatr" in p.description or "debloat" in p.description.lower()
        ]

    def _get_restore_type_name(self, type_code: int) -> str:
        """Get human-readable name for restore point type."""
        type_names = {
            0: "Application Install",
            1: "Application Uninstall",
            10: "Device Driver Install",
            12: "Modify Settings",
            13: "Cancelled Operation",
        }
        return type_names.get(type_code, f"Unknown ({type_code})")

    def _get_event_type_name(self, event_code: int) -> str:
        """Get human-readable name for event type."""
        event_names = {
            100: "Beginning Nested Restore",
            101: "Ending Nested Restore",
            102: "Beginning System Change",
            103: "Ending System Change",
        }
        return event_names.get(event_code, f"Event {event_code}")

    def _run_powershell(self, command: str) -> dict[str, Any]:
        """Run a PowerShell command."""
        if not self._is_windows:
            return {"success": False, "output": "", "error": "Not Windows"}

        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                timeout=120,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
                ),
            )

            return {
                "success": result.returncode == 0,
                "output": result.stdout.strip(),
                "error": result.stderr.strip() if result.returncode != 0 else "",
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "output": "", "error": "Command timed out"}
        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}

    def _run_command(self, command: str) -> dict[str, Any]:
        """Run a shell command."""
        if not self._is_windows:
            return {"success": False, "output": "", "error": "Not Windows"}

        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
                ),
            )

            return {
                "success": result.returncode == 0,
                "output": result.stdout.strip(),
                "error": result.stderr.strip() if result.returncode != 0 else "",
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "output": "", "error": "Command timed out"}
        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}


def create_system_restore_manager(dry_run: bool = False) -> SystemRestoreManager:
    """Create a System Restore manager.

    Args:
        dry_run: If True, simulate operations without changes

    Returns:
        SystemRestoreManager instance
    """
    return SystemRestoreManager(dry_run=dry_run)


def create_restore_point_for_session(
    session_description: str,
    dry_run: bool = False,
) -> int | None:
    """Convenience function to create a restore point for a debloat session.

    Args:
        session_description: Description of the session
        dry_run: If True, simulate without creating

    Returns:
        Sequence number of created restore point, or None
    """
    manager = SystemRestoreManager(dry_run=dry_run)

    if not manager.is_enabled():
        logger.warning("System Restore is not enabled")
        return None

    description = f"Debloatr: {session_description}"
    return manager.create_restore_point(description)
