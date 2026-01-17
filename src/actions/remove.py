"""Remove Action Handler - Removes system components.

This module provides handlers for removing various component types
including programs, services, UWP apps, and other components.
"""

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from src.core.models import (
    ActionType,
    Component,
    ComponentType,
    Snapshot,
)

logger = logging.getLogger("debloatr.actions.remove")


@dataclass
class RemoveResult:
    """Result of a remove operation.

    Attributes:
        success: Whether the removal succeeded
        component_id: ID of the removed component
        component_type: Type of the component
        files_removed: List of files that were removed
        registry_cleaned: Whether registry was cleaned
        quarantine_path: Path to quarantined files (if any)
        error_message: Error message if failed
        requires_reboot: Whether reboot is needed
        snapshot: Snapshot for rollback
    """

    success: bool
    component_id: str
    component_type: ComponentType
    files_removed: list[str] = field(default_factory=list)
    registry_cleaned: bool = False
    quarantine_path: Path | None = None
    error_message: str | None = None
    requires_reboot: bool = False
    snapshot: Snapshot | None = None


class RemoveHandler:
    """Handler for removing system components.

    Provides methods to remove programs, services, UWP apps,
    and other components with proper state capture for potential recovery.

    Example:
        handler = RemoveHandler()
        result = handler.remove_component(component, context)
        if result.success:
            print(f"Component removed. Files quarantined to: {result.quarantine_path}")
    """

    def __init__(
        self,
        dry_run: bool = False,
        create_snapshots: bool = True,
        quarantine_path: Path | None = None,
        create_restore_point: bool = True,
    ) -> None:
        """Initialize the remove handler.

        Args:
            dry_run: If True, simulate actions without making changes
            create_snapshots: Whether to create snapshots for rollback
            quarantine_path: Path for quarantined files
            create_restore_point: Whether to create System Restore points
        """
        self.dry_run = dry_run
        self.create_snapshots = create_snapshots
        self.quarantine_path = (
            quarantine_path
            or Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "Debloatr" / "Quarantine"
        )
        self.create_restore_point = create_restore_point
        self._is_windows = os.name == "nt"

    def remove_component(
        self,
        component: Component,
        context: dict[str, Any] | None = None,
    ) -> RemoveResult:
        """Remove a component based on its type.

        Args:
            component: Component to remove
            context: Additional context

        Returns:
            RemoveResult with operation details
        """
        context = context or {}

        # Dispatch based on component type
        if component.component_type == ComponentType.PROGRAM:
            return self.remove_program(component, context)
        elif component.component_type == ComponentType.SERVICE:
            return self.remove_service(component, context)
        elif component.component_type == ComponentType.TASK:
            return self.remove_task(component, context)
        elif component.component_type == ComponentType.STARTUP:
            return self.remove_startup(component, context)
        elif component.component_type == ComponentType.DRIVER:
            return self.remove_driver(component, context)
        elif component.component_type == ComponentType.UWP:
            return self.remove_uwp(component, context)
        else:
            return RemoveResult(
                success=False,
                component_id=component.id,
                component_type=component.component_type,
                error_message=f"Unsupported component type: {component.component_type}",
            )

    def remove_program(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> RemoveResult:
        """Remove an installed program.

        Args:
            component: Program component
            context: Additional context (uninstall_string, is_uwp, etc.)

        Returns:
            RemoveResult
        """
        is_uwp = context.get("is_uwp", False)
        if is_uwp:
            return self.remove_uwp(component, context)

        uninstall_string = context.get("uninstall_string", "")
        install_path = component.install_path

        if self.dry_run:
            logger.info(f"[DRY RUN] Would remove program: {component.name}")
            return RemoveResult(
                success=True,
                component_id=component.id,
                component_type=ComponentType.PROGRAM,
            )

        if not self._is_windows:
            return RemoveResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.PROGRAM,
                error_message="Program removal only available on Windows",
            )

        # Create System Restore point
        if self.create_restore_point:
            self._create_restore_point(f"Before removing {component.name}")

        # Create snapshot
        snapshot = None
        if self.create_snapshots:
            snapshot = self._create_program_snapshot(component, context)

        errors: list[str] = []
        files_removed: list[str] = []
        quarantine_used: Path | None = None

        try:
            # Try native uninstaller first
            if uninstall_string:
                uninstall_result = self._run_uninstaller(uninstall_string)
                if not uninstall_result["success"]:
                    errors.append(f"Uninstaller failed: {uninstall_result['error']}")
                else:
                    logger.info(f"Uninstaller completed for {component.name}")

            # Remove remaining files
            if install_path and install_path.exists():
                quarantine_used = self._quarantine_files(install_path, component.name)
                files_removed.append(str(install_path))

            # Clean up registry
            registry_result = self._clean_registry(component, context)
            registry_cleaned = registry_result["success"]

            success = len(errors) == 0 or quarantine_used is not None

            return RemoveResult(
                success=success,
                component_id=component.id,
                component_type=ComponentType.PROGRAM,
                files_removed=files_removed,
                registry_cleaned=registry_cleaned,
                quarantine_path=quarantine_used,
                error_message="; ".join(errors) if errors else None,
                snapshot=snapshot,
            )

        except Exception as e:
            logger.error(f"Error removing program {component.name}: {e}")
            return RemoveResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.PROGRAM,
                error_message=str(e),
                snapshot=snapshot,
            )

    def remove_uwp(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> RemoveResult:
        """Remove a UWP/Store app.

        Args:
            component: UWP component
            context: Additional context (package_name, etc.)

        Returns:
            RemoveResult
        """
        package_name = context.get("package_name", component.name)

        if self.dry_run:
            logger.info(f"[DRY RUN] Would remove UWP app: {package_name}")
            return RemoveResult(
                success=True,
                component_id=component.id,
                component_type=ComponentType.UWP,
            )

        if not self._is_windows:
            return RemoveResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.UWP,
                error_message="UWP removal only available on Windows",
            )

        # Create snapshot
        snapshot = None
        if self.create_snapshots:
            snapshot = Snapshot(
                component_id=component.id,
                action=ActionType.REMOVE,
                captured_state={"package_name": package_name},
            )

        try:
            # Remove for current user
            result = self._run_powershell(
                f"Get-AppxPackage -Name '*{package_name}*' | Remove-AppxPackage -ErrorAction Stop"
            )

            # Also remove provisioned package (for all users)
            self._run_powershell(
                f"Get-AppxProvisionedPackage -Online | "
                f"Where-Object {{ $_.PackageName -like '*{package_name}*' }} | "
                f"Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue"
            )

            if result["success"]:
                logger.info(f"Successfully removed UWP app: {package_name}")
                return RemoveResult(
                    success=True,
                    component_id=component.id,
                    component_type=ComponentType.UWP,
                    snapshot=snapshot,
                )
            else:
                return RemoveResult(
                    success=False,
                    component_id=component.id,
                    component_type=ComponentType.UWP,
                    error_message=result["error"],
                    snapshot=snapshot,
                )

        except Exception as e:
            logger.error(f"Error removing UWP app {package_name}: {e}")
            return RemoveResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.UWP,
                error_message=str(e),
                snapshot=snapshot,
            )

    def remove_service(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> RemoveResult:
        """Remove a Windows service.

        Args:
            component: Service component
            context: Additional context (service_name, etc.)

        Returns:
            RemoveResult
        """
        service_name = context.get("service_name", component.name)

        if self.dry_run:
            logger.info(f"[DRY RUN] Would remove service: {service_name}")
            return RemoveResult(
                success=True,
                component_id=component.id,
                component_type=ComponentType.SERVICE,
            )

        if not self._is_windows:
            return RemoveResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.SERVICE,
                error_message="Service removal only available on Windows",
            )

        # Create snapshot
        snapshot = None
        if self.create_snapshots:
            previous_state = self._get_service_config(service_name)
            snapshot = Snapshot(
                component_id=component.id,
                action=ActionType.REMOVE,
                captured_state={"service": previous_state},
            )

        try:
            # Stop the service first
            self._run_command(f'net stop "{service_name}" /y')

            # Mark for deletion
            result = self._run_command(f'sc delete "{service_name}"')

            if result["success"]:
                logger.info(f"Successfully marked service for deletion: {service_name}")
                return RemoveResult(
                    success=True,
                    component_id=component.id,
                    component_type=ComponentType.SERVICE,
                    requires_reboot=True,  # May need reboot to fully remove
                    snapshot=snapshot,
                )
            else:
                return RemoveResult(
                    success=False,
                    component_id=component.id,
                    component_type=ComponentType.SERVICE,
                    error_message=result["error"],
                    snapshot=snapshot,
                )

        except Exception as e:
            logger.error(f"Error removing service {service_name}: {e}")
            return RemoveResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.SERVICE,
                error_message=str(e),
                snapshot=snapshot,
            )

    def remove_task(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> RemoveResult:
        """Remove a scheduled task.

        Args:
            component: Task component
            context: Additional context (task_path, etc.)

        Returns:
            RemoveResult
        """
        task_path = context.get("task_path", component.name)

        if self.dry_run:
            logger.info(f"[DRY RUN] Would remove task: {task_path}")
            return RemoveResult(
                success=True,
                component_id=component.id,
                component_type=ComponentType.TASK,
            )

        if not self._is_windows:
            return RemoveResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.TASK,
                error_message="Task removal only available on Windows",
            )

        # Create snapshot
        snapshot = None
        if self.create_snapshots:
            task_xml = self._export_task_xml(task_path)
            snapshot = Snapshot(
                component_id=component.id,
                action=ActionType.REMOVE,
                captured_state={"task_xml": task_xml, "task_path": task_path},
            )

        try:
            # Delete the task
            result = self._run_command(f'schtasks /Delete /TN "{task_path}" /F')

            if result["success"]:
                logger.info(f"Successfully removed task: {task_path}")
                return RemoveResult(
                    success=True,
                    component_id=component.id,
                    component_type=ComponentType.TASK,
                    snapshot=snapshot,
                )
            else:
                return RemoveResult(
                    success=False,
                    component_id=component.id,
                    component_type=ComponentType.TASK,
                    error_message=result["error"],
                    snapshot=snapshot,
                )

        except Exception as e:
            logger.error(f"Error removing task {task_path}: {e}")
            return RemoveResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.TASK,
                error_message=str(e),
                snapshot=snapshot,
            )

    def remove_startup(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> RemoveResult:
        """Remove a startup entry.

        Args:
            component: Startup component
            context: Additional context (entry_type, registry_key, etc.)

        Returns:
            RemoveResult
        """
        entry_type = context.get("entry_type", "registry")
        registry_key = context.get("registry_key", "")
        value_name = context.get("value_name", component.name)

        if self.dry_run:
            logger.info(f"[DRY RUN] Would remove startup: {value_name}")
            return RemoveResult(
                success=True,
                component_id=component.id,
                component_type=ComponentType.STARTUP,
            )

        if not self._is_windows:
            return RemoveResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.STARTUP,
                error_message="Startup removal only available on Windows",
            )

        # Create snapshot
        snapshot = None
        if self.create_snapshots:
            snapshot = Snapshot(
                component_id=component.id,
                action=ActionType.REMOVE,
                captured_state={
                    "entry_type": entry_type,
                    "registry_key": registry_key,
                    "value_name": value_name,
                },
            )

        try:
            if entry_type == "registry":
                result = self._run_powershell(
                    f"Remove-ItemProperty -Path '{registry_key}' -Name '{value_name}' "
                    f"-Force -ErrorAction Stop"
                )
            elif entry_type == "folder":
                shortcut_path = context.get("shortcut_path", "")
                if shortcut_path and Path(shortcut_path).exists():
                    quarantine = self._quarantine_files(Path(shortcut_path), value_name)
                    result = (
                        {"success": True}
                        if quarantine
                        else {"success": False, "error": "Quarantine failed"}
                    )
                else:
                    result = {"success": False, "error": "Shortcut not found"}
            else:
                result = {"success": False, "error": f"Unknown entry type: {entry_type}"}

            if result["success"]:
                logger.info(f"Successfully removed startup: {value_name}")
                return RemoveResult(
                    success=True,
                    component_id=component.id,
                    component_type=ComponentType.STARTUP,
                    snapshot=snapshot,
                )
            else:
                return RemoveResult(
                    success=False,
                    component_id=component.id,
                    component_type=ComponentType.STARTUP,
                    error_message=result.get("error", "Unknown error"),
                    snapshot=snapshot,
                )

        except Exception as e:
            logger.error(f"Error removing startup {value_name}: {e}")
            return RemoveResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.STARTUP,
                error_message=str(e),
                snapshot=snapshot,
            )

    def remove_driver(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> RemoveResult:
        """Remove a system driver.

        Args:
            component: Driver component
            context: Additional context (driver_name, inf_name, etc.)

        Returns:
            RemoveResult
        """
        driver_name = context.get("driver_name", component.name)
        inf_name = context.get("inf_name", "")

        if self.dry_run:
            logger.info(f"[DRY RUN] Would remove driver: {driver_name}")
            return RemoveResult(
                success=True,
                component_id=component.id,
                component_type=ComponentType.DRIVER,
                requires_reboot=True,
            )

        if not self._is_windows:
            return RemoveResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.DRIVER,
                error_message="Driver removal only available on Windows",
            )

        # Create restore point for driver removal
        if self.create_restore_point:
            self._create_restore_point(f"Before removing driver {driver_name}")

        # Create snapshot
        snapshot = None
        if self.create_snapshots:
            driver_config = self._get_driver_config(driver_name)
            snapshot = Snapshot(
                component_id=component.id,
                action=ActionType.REMOVE,
                captured_state={"driver": driver_config},
            )

        try:
            # Stop the driver first
            self._run_command(f'net stop "{driver_name}" /y')

            # Uninstall using pnputil if we have the INF name
            if inf_name:
                result = self._run_command(f'pnputil /delete-driver "{inf_name}" /uninstall /force')
            else:
                # Mark service for deletion
                result = self._run_command(f'sc delete "{driver_name}"')

            if result["success"]:
                logger.info(f"Successfully removed driver: {driver_name}")
                return RemoveResult(
                    success=True,
                    component_id=component.id,
                    component_type=ComponentType.DRIVER,
                    requires_reboot=True,
                    snapshot=snapshot,
                )
            else:
                return RemoveResult(
                    success=False,
                    component_id=component.id,
                    component_type=ComponentType.DRIVER,
                    error_message=result["error"],
                    snapshot=snapshot,
                )

        except Exception as e:
            logger.error(f"Error removing driver {driver_name}: {e}")
            return RemoveResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.DRIVER,
                error_message=str(e),
                snapshot=snapshot,
            )

    def _create_program_snapshot(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> Snapshot:
        """Create a snapshot for program removal."""
        state: dict[str, Any] = {
            "name": component.name,
            "display_name": component.display_name,
            "publisher": component.publisher,
            "install_path": str(component.install_path) if component.install_path else None,
            "uninstall_string": context.get("uninstall_string"),
        }

        # Capture registry entries
        if context.get("registry_key"):
            state["registry"] = self._export_registry(context["registry_key"])

        # Capture file list
        if component.install_path and component.install_path.exists():
            state["files"] = self._list_files(component.install_path)

        return Snapshot(
            component_id=component.id,
            action=ActionType.REMOVE,
            captured_state=state,
        )

    def _run_uninstaller(self, uninstall_string: str) -> dict[str, Any]:
        """Run a program's uninstaller."""
        try:
            # Parse and execute uninstall string
            # Handle common patterns like MsiExec.exe /X{GUID}
            if "msiexec" in uninstall_string.lower():
                # Add quiet flags for MSI uninstall
                if "/qn" not in uninstall_string.lower():
                    uninstall_string += " /qn /norestart"

            result = subprocess.run(
                uninstall_string,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout for uninstallers
                creationflags=(
                    subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
                ),
            )

            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr if result.returncode != 0 else "",
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Uninstaller timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _quarantine_files(self, path: Path, name: str) -> Path | None:
        """Move files to quarantine instead of deleting."""
        try:
            # Create quarantine directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = "".join(c for c in name if c.isalnum() or c in "-_")
            quarantine_dir = self.quarantine_path / f"{safe_name}_{timestamp}"
            quarantine_dir.mkdir(parents=True, exist_ok=True)

            # Move files to quarantine
            if path.is_file():
                dest = quarantine_dir / path.name
                shutil.move(str(path), str(dest))
            elif path.is_dir():
                dest = quarantine_dir / path.name
                shutil.move(str(path), str(dest))

            logger.info(f"Quarantined files to: {quarantine_dir}")
            return quarantine_dir

        except Exception as e:
            logger.error(f"Failed to quarantine files: {e}")
            return None

    def _clean_registry(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Clean up registry entries for a removed component."""
        try:
            registry_key = context.get("registry_key", "")
            if registry_key:
                result = self._run_powershell(
                    f"Remove-Item -Path '{registry_key}' -Recurse -Force -ErrorAction Stop"
                )
                return result

            return {"success": True}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _get_service_config(self, service_name: str) -> dict[str, Any]:
        """Get service configuration for snapshot."""
        result = self._run_command(f'sc qc "{service_name}"')
        return {"sc_output": result.get("output", "")}

    def _get_driver_config(self, driver_name: str) -> dict[str, Any]:
        """Get driver configuration for snapshot."""
        result = self._run_command(f'sc qc "{driver_name}"')
        return {"sc_output": result.get("output", "")}

    def _export_task_xml(self, task_path: str) -> str:
        """Export task definition as XML."""
        result = self._run_command(f'schtasks /Query /TN "{task_path}" /XML')
        return result.get("output", "")

    def _export_registry(self, registry_key: str) -> str:
        """Export registry key for snapshot."""
        result = self._run_powershell(
            f"Get-ItemProperty -Path '{registry_key}' | ConvertTo-Json -Compress"
        )
        return result.get("output", "")

    def _list_files(self, path: Path) -> list[str]:
        """List all files in a directory."""
        files: list[str] = []
        try:
            if path.is_dir():
                for item in path.rglob("*"):
                    if item.is_file():
                        files.append(str(item))
            elif path.is_file():
                files.append(str(path))
        except Exception as e:
            logger.warning(f"Error listing files: {e}")
        return files

    def _create_restore_point(self, description: str) -> bool:
        """Create a Windows System Restore point."""
        if self.dry_run:
            logger.info(f"[DRY RUN] Would create restore point: {description}")
            return True

        try:
            result = self._run_powershell(
                f"Checkpoint-Computer -Description '{description}' "
                f"-RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop"
            )
            if result["success"]:
                logger.info(f"Created restore point: {description}")
            return result["success"]
        except Exception as e:
            logger.warning(f"Failed to create restore point: {e}")
            return False

    def _run_powershell(self, command: str) -> dict[str, Any]:
        """Run a PowerShell command."""
        if self.dry_run:
            return {"success": True, "output": "", "error": ""}

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
        if self.dry_run:
            return {"success": True, "output": "", "error": ""}

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


def create_remove_handler(dry_run: bool = False) -> RemoveHandler:
    """Create a remove handler.

    Args:
        dry_run: If True, simulate actions

    Returns:
        RemoveHandler instance
    """
    return RemoveHandler(dry_run=dry_run)
