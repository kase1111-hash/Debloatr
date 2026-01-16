"""Recovery Mode - Boot-safe recovery for system restoration.

This module provides recovery functionality that can be used to
restore system state after problematic debloat operations, including
support for Safe Mode recovery.
"""

import os
import sys
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional
import logging
import json

from src.core.models import ActionType
from src.core.config import Config, get_default_config
from src.core.session import SessionManager, SessionSummary, create_session_manager
from src.core.snapshot import SnapshotManager, create_snapshot_manager
from src.core.rollback import RollbackManager, SessionRollbackResult, create_rollback_manager
from src.core.restore import SystemRestoreManager, RestorePoint, create_system_restore_manager

logger = logging.getLogger("debloatr.core.recovery")


@dataclass
class RecoveryStatus:
    """Status of system recovery capabilities.

    Attributes:
        has_sessions: Whether there are sessions to rollback
        last_session_id: ID of the last session
        last_session_description: Description of the last session
        last_session_actions: Number of actions in last session
        rollbackable_actions: Number of rollbackable actions
        has_restore_points: Whether system restore points exist
        debloatr_restore_points: Number of Debloatr-created restore points
        system_restore_enabled: Whether System Restore is enabled
        is_safe_mode: Whether running in Safe Mode
        recovery_available: Whether any recovery option is available
    """

    has_sessions: bool
    last_session_id: Optional[str]
    last_session_description: Optional[str]
    last_session_actions: int
    rollbackable_actions: int
    has_restore_points: bool
    debloatr_restore_points: int
    system_restore_enabled: bool
    is_safe_mode: bool
    recovery_available: bool


@dataclass
class RecoveryResult:
    """Result of a recovery operation.

    Attributes:
        success: Whether recovery succeeded
        method: Recovery method used
        details: Details about the recovery
        error_message: Error message if failed
        requires_reboot: Whether reboot is needed
    """

    success: bool
    method: str
    details: dict[str, Any]
    error_message: Optional[str] = None
    requires_reboot: bool = False


class RecoveryMode:
    """Boot-safe recovery mode for Debloatr.

    Provides recovery functionality that works even in Safe Mode,
    allowing users to recover from problematic debloat operations.

    Usage from command line:
        debloatd --recovery              # Interactive recovery
        debloatd --recovery --last       # Rollback last session
        debloatd --recovery --session ID # Rollback specific session
        debloatd --recovery --restore N  # Restore to point N

    Example:
        recovery = RecoveryMode()
        status = recovery.get_status()

        if status.recovery_available:
            result = recovery.rollback_last_session()
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        dry_run: bool = False,
    ) -> None:
        """Initialize recovery mode.

        Args:
            config: Configuration object
            dry_run: If True, simulate operations without changes
        """
        self.config = config or get_default_config()
        self.dry_run = dry_run
        self._is_windows = os.name == "nt"

        # Initialize managers
        self.session_manager = create_session_manager(config)
        self.snapshot_manager = create_snapshot_manager(config)
        self.rollback_manager = create_rollback_manager(config, dry_run=dry_run)
        self.restore_manager = create_system_restore_manager(dry_run=dry_run)

        # Recovery log file
        self._recovery_log = self.config.logs_dir / "recovery.log"

    def is_safe_mode(self) -> bool:
        """Check if Windows is running in Safe Mode.

        Returns:
            True if running in Safe Mode
        """
        if not self._is_windows:
            return False

        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\SafeBoot\Option",
            )
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            return False
        except Exception:
            # Alternative check via GetSystemMetrics
            try:
                result = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-Command",
                     "(Get-WmiObject Win32_ComputerSystem).BootupState"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                return "safe" in result.stdout.lower()
            except Exception:
                return False

    def get_status(self) -> RecoveryStatus:
        """Get current recovery status and available options.

        Returns:
            RecoveryStatus with available recovery options
        """
        # Get session info
        sessions = self.session_manager.list_sessions(limit=10)
        last_session = sessions[0] if sessions else None

        rollbackable_count = 0
        if last_session:
            actions = self.session_manager.get_rollbackable_actions(
                last_session.session_id
            )
            rollbackable_count = len(actions)

        # Get restore point info
        restore_points = self.restore_manager.list_restore_points(limit=10)
        debloatr_points = self.restore_manager.get_debloatr_restore_points()

        # Check if System Restore is enabled
        restore_enabled = self.restore_manager.is_enabled()

        # Check Safe Mode
        is_safe_mode = self.is_safe_mode()

        # Determine if recovery is available
        recovery_available = (
            rollbackable_count > 0 or
            len(debloatr_points) > 0 or
            (restore_enabled and len(restore_points) > 0)
        )

        return RecoveryStatus(
            has_sessions=len(sessions) > 0,
            last_session_id=last_session.session_id if last_session else None,
            last_session_description=last_session.description if last_session else None,
            last_session_actions=last_session.total_actions if last_session else 0,
            rollbackable_actions=rollbackable_count,
            has_restore_points=len(restore_points) > 0,
            debloatr_restore_points=len(debloatr_points),
            system_restore_enabled=restore_enabled,
            is_safe_mode=is_safe_mode,
            recovery_available=recovery_available,
        )

    def rollback_last_session(
        self,
        stop_on_failure: bool = False,
    ) -> RecoveryResult:
        """Rollback the most recent session.

        Args:
            stop_on_failure: If True, stop on first failure

        Returns:
            RecoveryResult with outcome
        """
        self._log_recovery_action("rollback_last_session", {})

        result = self.rollback_manager.rollback_last_session(stop_on_failure)

        if result.success:
            self._log_recovery_action("rollback_complete", {
                "session_id": result.session_id,
                "successful": result.successful_rollbacks,
                "failed": result.failed_rollbacks,
            })
            return RecoveryResult(
                success=True,
                method="session_rollback",
                details={
                    "session_id": result.session_id,
                    "total_actions": result.total_actions,
                    "successful_rollbacks": result.successful_rollbacks,
                    "failed_rollbacks": result.failed_rollbacks,
                },
                requires_reboot=result.requires_reboot,
            )
        else:
            error_messages = [
                r.error_message for r in result.results
                if r.error_message
            ]
            return RecoveryResult(
                success=False,
                method="session_rollback",
                details={
                    "session_id": result.session_id,
                    "successful_rollbacks": result.successful_rollbacks,
                    "failed_rollbacks": result.failed_rollbacks,
                },
                error_message="; ".join(error_messages) if error_messages else "Rollback failed",
            )

    def rollback_session(
        self,
        session_id: str,
        stop_on_failure: bool = False,
    ) -> RecoveryResult:
        """Rollback a specific session.

        Args:
            session_id: ID of the session to rollback
            stop_on_failure: If True, stop on first failure

        Returns:
            RecoveryResult with outcome
        """
        self._log_recovery_action("rollback_session", {"session_id": session_id})

        result = self.rollback_manager.rollback_session(session_id, stop_on_failure)

        if result.success:
            return RecoveryResult(
                success=True,
                method="session_rollback",
                details={
                    "session_id": result.session_id,
                    "total_actions": result.total_actions,
                    "successful_rollbacks": result.successful_rollbacks,
                    "failed_rollbacks": result.failed_rollbacks,
                },
                requires_reboot=result.requires_reboot,
            )
        else:
            error_messages = [
                r.error_message for r in result.results
                if r.error_message
            ]
            return RecoveryResult(
                success=False,
                method="session_rollback",
                details={
                    "session_id": result.session_id,
                    "successful_rollbacks": result.successful_rollbacks,
                    "failed_rollbacks": result.failed_rollbacks,
                },
                error_message="; ".join(error_messages) if error_messages else "Rollback failed",
            )

    def restore_to_point(
        self,
        sequence_number: int,
        confirm: bool = False,
    ) -> RecoveryResult:
        """Restore system to a System Restore point.

        WARNING: This will restart the computer.

        Args:
            sequence_number: Restore point sequence number
            confirm: If True, actually initiate restore

        Returns:
            RecoveryResult with outcome
        """
        self._log_recovery_action("restore_to_point", {
            "sequence_number": sequence_number,
            "confirm": confirm,
        })

        point = self.restore_manager.get_restore_point(sequence_number)
        if not point:
            return RecoveryResult(
                success=False,
                method="system_restore",
                details={},
                error_message=f"Restore point #{sequence_number} not found",
            )

        if self.dry_run or not confirm:
            return RecoveryResult(
                success=True,
                method="system_restore",
                details={
                    "dry_run": True,
                    "sequence_number": sequence_number,
                    "description": point.description,
                    "creation_time": point.creation_time.isoformat(),
                },
            )

        result = self.restore_manager.restore_to_point(sequence_number, confirm=True)

        if result.get("success"):
            return RecoveryResult(
                success=True,
                method="system_restore",
                details=result,
                requires_reboot=True,
            )
        else:
            return RecoveryResult(
                success=False,
                method="system_restore",
                details=result,
                error_message=result.get("error", "System restore failed"),
            )

    def list_recovery_options(self) -> dict[str, Any]:
        """List all available recovery options.

        Returns:
            Dictionary with recovery options
        """
        options: dict[str, Any] = {
            "sessions": [],
            "restore_points": [],
            "recommendations": [],
        }

        # List sessions with rollbackable actions
        sessions = self.session_manager.list_sessions(limit=10)
        for session in sessions:
            actions = self.session_manager.get_rollbackable_actions(session.session_id)
            if actions:
                options["sessions"].append({
                    "session_id": session.session_id,
                    "description": session.description,
                    "started_at": session.started_at,
                    "rollbackable_actions": len(actions),
                    "total_actions": session.total_actions,
                })

        # List Debloatr restore points
        debloatr_points = self.restore_manager.get_debloatr_restore_points()
        for point in debloatr_points:
            options["restore_points"].append({
                "sequence_number": point.sequence_number,
                "description": point.description,
                "creation_time": point.creation_time.isoformat(),
            })

        # Add non-Debloatr restore points
        all_points = self.restore_manager.list_restore_points(limit=5)
        for point in all_points:
            if point not in debloatr_points:
                options["restore_points"].append({
                    "sequence_number": point.sequence_number,
                    "description": point.description,
                    "creation_time": point.creation_time.isoformat(),
                    "external": True,
                })

        # Add recommendations
        status = self.get_status()
        if status.rollbackable_actions > 0:
            options["recommendations"].append({
                "action": "rollback_last_session",
                "description": f"Rollback last session ({status.rollbackable_actions} actions)",
                "command": "debloatd --recovery --last",
            })

        if status.debloatr_restore_points > 0:
            options["recommendations"].append({
                "action": "system_restore",
                "description": "Restore to Debloatr restore point",
                "command": f"debloatd --recovery --restore {debloatr_points[0].sequence_number}" if debloatr_points else "",
            })

        return options

    def auto_recovery(self) -> RecoveryResult:
        """Perform automatic recovery based on best available option.

        This method tries recovery in order:
        1. Rollback last session
        2. Use most recent Debloatr restore point
        3. Use most recent system restore point

        Returns:
            RecoveryResult with outcome
        """
        self._log_recovery_action("auto_recovery", {})

        status = self.get_status()

        # Try session rollback first
        if status.rollbackable_actions > 0:
            logger.info("Attempting session rollback...")
            result = self.rollback_last_session()
            if result.success:
                return result

        # Try Debloatr restore point
        debloatr_points = self.restore_manager.get_debloatr_restore_points()
        if debloatr_points:
            logger.info("Attempting Debloatr restore point...")
            return self.restore_to_point(debloatr_points[0].sequence_number, confirm=True)

        # Try any restore point
        all_points = self.restore_manager.list_restore_points(limit=1)
        if all_points:
            logger.info("Attempting system restore point...")
            return self.restore_to_point(all_points[0].sequence_number, confirm=True)

        return RecoveryResult(
            success=False,
            method="auto_recovery",
            details={},
            error_message="No recovery options available",
        )

    def create_recovery_script(self, output_path: Optional[Path] = None) -> Path:
        """Create a standalone recovery script.

        Creates a batch file that can be run from Safe Mode to
        perform recovery without needing the full Debloatr installation.

        Args:
            output_path: Path for the script (defaults to config directory)

        Returns:
            Path to the created script
        """
        output_path = output_path or self.config.config_dir / "recovery.bat"

        # Get last session info
        last_session = self.session_manager.get_last_session()
        session_id = last_session.session_id if last_session else ""

        # Create batch script content
        script = f'''@echo off
echo Debloatr Recovery Script
echo ========================
echo.

REM Check for admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as Administrator
    pause
    exit /b 1
)

echo Recovery Options:
echo 1. Rollback last Debloatr session
echo 2. Open System Restore
echo 3. Exit
echo.

set /p choice="Enter choice (1-3): "

if "%choice%"=="1" (
    echo.
    echo Attempting to rollback last session...
    cd /d "{self.config.config_dir}"
    python -m debloatd --recovery --last
    if %errorLevel% neq 0 (
        echo.
        echo Session rollback failed. Try System Restore instead.
    )
    pause
    exit /b
)

if "%choice%"=="2" (
    echo.
    echo Opening System Restore...
    rstrui.exe
    exit /b
)

if "%choice%"=="3" (
    exit /b
)

echo Invalid choice
pause
'''

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(script)

        logger.info(f"Created recovery script: {output_path}")
        return output_path

    def register_boot_recovery(self) -> bool:
        """Register recovery check to run at boot.

        Creates a scheduled task that checks for recovery needs at startup.
        This provides automatic recovery capability.

        Returns:
            True if registered successfully
        """
        if not self._is_windows:
            return False

        if self.dry_run:
            logger.info("[DRY RUN] Would register boot recovery")
            return True

        # Create the boot recovery check script
        script_path = self.config.config_dir / "boot_recovery_check.py"
        script_content = f'''"""Boot recovery check for Debloatr."""
import sys
sys.path.insert(0, r"{Path(__file__).parent.parent}")

from src.core.recovery import RecoveryMode

def main():
    recovery = RecoveryMode()
    status = recovery.get_status()

    # Only auto-recover if there was a very recent session (within 1 hour)
    # that failed or has issues
    if status.rollbackable_actions > 0:
        # Log that recovery is available
        with open(r"{self.config.logs_dir / 'boot_check.log'}", "a") as f:
            f.write(f"Recovery available: {{status.rollbackable_actions}} actions\\n")

if __name__ == "__main__":
    main()
'''

        script_path.parent.mkdir(parents=True, exist_ok=True)
        with open(script_path, "w") as f:
            f.write(script_content)

        # Create scheduled task
        task_name = "DebloatrBootRecoveryCheck"
        result = subprocess.run(
            ["schtasks", "/Create",
             "/TN", task_name,
             "/TR", f'python "{script_path}"',
             "/SC", "ONSTART",
             "/RU", "SYSTEM",
             "/F"],
            capture_output=True,
            text=True,
        )

        return result.returncode == 0

    def unregister_boot_recovery(self) -> bool:
        """Unregister the boot recovery task.

        Returns:
            True if unregistered successfully
        """
        if not self._is_windows:
            return False

        if self.dry_run:
            logger.info("[DRY RUN] Would unregister boot recovery")
            return True

        task_name = "DebloatrBootRecoveryCheck"
        result = subprocess.run(
            ["schtasks", "/Delete", "/TN", task_name, "/F"],
            capture_output=True,
            text=True,
        )

        return result.returncode == 0

    def _log_recovery_action(self, action: str, details: dict[str, Any]) -> None:
        """Log a recovery action to the recovery log file."""
        try:
            self._recovery_log.parent.mkdir(parents=True, exist_ok=True)

            entry = {
                "timestamp": datetime.now().isoformat(),
                "action": action,
                "details": details,
            }

            with open(self._recovery_log, "a") as f:
                f.write(json.dumps(entry) + "\n")

        except Exception as e:
            logger.warning(f"Failed to log recovery action: {e}")


def create_recovery_mode(
    config: Optional[Config] = None,
    dry_run: bool = False,
) -> RecoveryMode:
    """Create a recovery mode instance.

    Args:
        config: Optional configuration object
        dry_run: If True, simulate operations without changes

    Returns:
        RecoveryMode instance
    """
    return RecoveryMode(config=config, dry_run=dry_run)


def run_recovery_interactive() -> int:
    """Run interactive recovery mode.

    Returns:
        Exit code (0 for success)
    """
    recovery = RecoveryMode()
    status = recovery.get_status()

    print("=" * 50)
    print("Debloatr Recovery Mode")
    print("=" * 50)
    print()

    if status.is_safe_mode:
        print("Running in Safe Mode")
        print()

    if not status.recovery_available:
        print("No recovery options available.")
        print("Consider using Windows System Restore (rstrui.exe)")
        return 1

    print("Recovery Status:")
    print(f"  Sessions available: {status.has_sessions}")
    print(f"  Rollbackable actions: {status.rollbackable_actions}")
    print(f"  Debloatr restore points: {status.debloatr_restore_points}")
    print(f"  System Restore enabled: {status.system_restore_enabled}")
    print()

    options = recovery.list_recovery_options()

    print("Available Options:")
    print()

    for i, rec in enumerate(options["recommendations"], 1):
        print(f"  {i}. {rec['description']}")
        print(f"     Command: {rec['command']}")
        print()

    return 0


def run_recovery_auto(last_session: bool = True) -> int:
    """Run automatic recovery.

    Args:
        last_session: If True, rollback last session; otherwise auto-select

    Returns:
        Exit code (0 for success)
    """
    recovery = RecoveryMode()

    if last_session:
        result = recovery.rollback_last_session()
    else:
        result = recovery.auto_recovery()

    if result.success:
        print(f"Recovery successful using {result.method}")
        if result.requires_reboot:
            print("A reboot is required to complete recovery.")
        return 0
    else:
        print(f"Recovery failed: {result.error_message}")
        return 1
