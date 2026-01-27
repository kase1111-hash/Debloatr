"""Disable Action Handler - Disables system components.

This module provides handlers for disabling various component types
including services, scheduled tasks, startup entries, and drivers.
"""

import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.core.models import (
    ActionType,
    Component,
    ComponentType,
    Snapshot,
)

logger = logging.getLogger("debloatr.actions.disable")


@dataclass
class DisableResult:
    """Result of a disable operation.

    Attributes:
        success: Whether the disable succeeded
        component_id: ID of the disabled component
        component_type: Type of the component
        previous_state: State before disable
        current_state: State after disable
        error_message: Error message if failed
        requires_reboot: Whether reboot is needed
        snapshot: Snapshot for rollback
    """

    success: bool
    component_id: str
    component_type: ComponentType
    previous_state: dict[str, Any] = field(default_factory=dict)
    current_state: dict[str, Any] = field(default_factory=dict)
    error_message: str | None = None
    requires_reboot: bool = False
    snapshot: Snapshot | None = None


class DisableHandler:
    """Handler for disabling system components.

    Provides methods to disable services, tasks, startup entries,
    and drivers with proper state capture for rollback.

    Example:
        handler = DisableHandler()
        result = handler.disable_component(component, context)
        if result.success:
            print("Component disabled successfully")
    """

    def __init__(
        self,
        dry_run: bool = False,
        create_snapshots: bool = True,
        command_timeout: int = 60,
    ) -> None:
        """Initialize the disable handler.

        Args:
            dry_run: If True, simulate actions without making changes
            create_snapshots: Whether to create snapshots for rollback
            command_timeout: Timeout in seconds for PowerShell/subprocess commands
        """
        self.dry_run = dry_run
        self.create_snapshots = create_snapshots
        self.command_timeout = command_timeout
        self._is_windows = os.name == "nt"

    def disable_component(
        self,
        component: Component,
        context: dict[str, Any] | None = None,
    ) -> DisableResult:
        """Disable a component based on its type.

        Args:
            component: Component to disable
            context: Additional context

        Returns:
            DisableResult with operation details
        """
        context = context or {}

        # Dispatch based on component type
        if component.component_type == ComponentType.SERVICE:
            return self.disable_service(component, context)
        elif component.component_type == ComponentType.TASK:
            return self.disable_task(component, context)
        elif component.component_type == ComponentType.STARTUP:
            return self.disable_startup(component, context)
        elif component.component_type == ComponentType.DRIVER:
            return self.disable_driver(component, context)
        elif component.component_type == ComponentType.PROGRAM:
            return self.disable_program(component, context)
        else:
            return DisableResult(
                success=False,
                component_id=component.id,
                component_type=component.component_type,
                error_message=f"Unsupported component type: {component.component_type}",
            )

    def disable_service(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> DisableResult:
        """Disable a Windows service.

        Args:
            component: Service component
            context: Additional context (service_name, etc.)

        Returns:
            DisableResult
        """
        service_name = context.get("service_name", component.name)

        # Capture previous state
        previous_state = self._get_service_state(service_name)

        if self.dry_run:
            logger.info(f"[DRY RUN] Would disable service: {service_name}")
            return DisableResult(
                success=True,
                component_id=component.id,
                component_type=ComponentType.SERVICE,
                previous_state=previous_state,
                current_state={"start_type": "Disabled", "status": "Stopped"},
            )

        if not self._is_windows:
            return DisableResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.SERVICE,
                error_message="Service disable only available on Windows",
            )

        # Create snapshot
        snapshot = None
        if self.create_snapshots:
            snapshot = Snapshot(
                component_id=component.id,
                action=ActionType.DISABLE,
                captured_state={"service": previous_state},
            )

        try:
            # Stop the service if running
            if previous_state.get("status") == "Running":
                stop_result = self._run_powershell(
                    f"Stop-Service -Name '{service_name}' -Force -ErrorAction Stop"
                )
                if not stop_result["success"]:
                    logger.warning(f"Failed to stop service: {stop_result['error']}")

            # Set startup type to Disabled
            disable_result = self._run_powershell(
                f"Set-Service -Name '{service_name}' -StartupType Disabled -ErrorAction Stop"
            )

            if not disable_result["success"]:
                return DisableResult(
                    success=False,
                    component_id=component.id,
                    component_type=ComponentType.SERVICE,
                    previous_state=previous_state,
                    error_message=disable_result["error"],
                    snapshot=snapshot,
                )

            # Get current state
            current_state = self._get_service_state(service_name)

            logger.info(f"Successfully disabled service: {service_name}")
            return DisableResult(
                success=True,
                component_id=component.id,
                component_type=ComponentType.SERVICE,
                previous_state=previous_state,
                current_state=current_state,
                snapshot=snapshot,
            )

        except Exception as e:
            logger.error(f"Error disabling service {service_name}: {e}")
            return DisableResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.SERVICE,
                previous_state=previous_state,
                error_message=str(e),
                snapshot=snapshot,
            )

    def disable_task(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> DisableResult:
        """Disable a scheduled task.

        Args:
            component: Task component
            context: Additional context (task_path, etc.)

        Returns:
            DisableResult
        """
        task_path = context.get("task_path", component.name)

        # Capture previous state
        previous_state = self._get_task_state(task_path)

        if self.dry_run:
            logger.info(f"[DRY RUN] Would disable task: {task_path}")
            return DisableResult(
                success=True,
                component_id=component.id,
                component_type=ComponentType.TASK,
                previous_state=previous_state,
                current_state={"state": "Disabled"},
            )

        if not self._is_windows:
            return DisableResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.TASK,
                error_message="Task disable only available on Windows",
            )

        # Create snapshot
        snapshot = None
        if self.create_snapshots:
            snapshot = Snapshot(
                component_id=component.id,
                action=ActionType.DISABLE,
                captured_state={"task": previous_state},
            )

        try:
            # Disable the task
            disable_result = self._run_powershell(
                f"Disable-ScheduledTask -TaskPath '{Path(task_path).parent}' "
                f"-TaskName '{Path(task_path).name}' -ErrorAction Stop"
            )

            if not disable_result["success"]:
                # Try alternative method with full path
                disable_result = self._run_powershell(
                    f"schtasks /Change /TN '{task_path}' /Disable"
                )

            if not disable_result["success"]:
                return DisableResult(
                    success=False,
                    component_id=component.id,
                    component_type=ComponentType.TASK,
                    previous_state=previous_state,
                    error_message=disable_result["error"],
                    snapshot=snapshot,
                )

            # Get current state
            current_state = self._get_task_state(task_path)

            logger.info(f"Successfully disabled task: {task_path}")
            return DisableResult(
                success=True,
                component_id=component.id,
                component_type=ComponentType.TASK,
                previous_state=previous_state,
                current_state=current_state,
                snapshot=snapshot,
            )

        except Exception as e:
            logger.error(f"Error disabling task {task_path}: {e}")
            return DisableResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.TASK,
                previous_state=previous_state,
                error_message=str(e),
                snapshot=snapshot,
            )

    def disable_startup(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> DisableResult:
        """Disable a startup entry.

        Args:
            component: Startup component
            context: Additional context (entry_type, registry_key, etc.)

        Returns:
            DisableResult
        """
        entry_type = context.get("entry_type", "registry")
        registry_key = context.get("registry_key", "")
        value_name = context.get("value_name", component.name)

        # Capture previous state
        previous_state = {
            "entry_type": entry_type,
            "registry_key": registry_key,
            "value_name": value_name,
            "enabled": True,
        }

        if self.dry_run:
            logger.info(f"[DRY RUN] Would disable startup: {value_name}")
            return DisableResult(
                success=True,
                component_id=component.id,
                component_type=ComponentType.STARTUP,
                previous_state=previous_state,
                current_state={"enabled": False},
            )

        if not self._is_windows:
            return DisableResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.STARTUP,
                error_message="Startup disable only available on Windows",
            )

        # Create snapshot
        snapshot = None
        if self.create_snapshots:
            if entry_type == "registry":
                reg_state = self._capture_registry_value(registry_key, value_name)
                snapshot = Snapshot(
                    component_id=component.id,
                    action=ActionType.DISABLE,
                    captured_state={"registry": reg_state},
                )
            else:
                snapshot = Snapshot(
                    component_id=component.id,
                    action=ActionType.DISABLE,
                    captured_state={"startup": previous_state},
                )

        try:
            if entry_type == "registry":
                # Rename the registry value to disable it
                disable_result = self._disable_registry_startup(registry_key, value_name)
            elif entry_type == "folder":
                # Move the shortcut to a disabled folder
                disable_result = self._disable_folder_startup(component, context)
            else:
                disable_result = {"success": False, "error": f"Unknown entry type: {entry_type}"}

            if not disable_result["success"]:
                return DisableResult(
                    success=False,
                    component_id=component.id,
                    component_type=ComponentType.STARTUP,
                    previous_state=previous_state,
                    error_message=disable_result["error"],
                    snapshot=snapshot,
                )

            logger.info(f"Successfully disabled startup: {value_name}")
            return DisableResult(
                success=True,
                component_id=component.id,
                component_type=ComponentType.STARTUP,
                previous_state=previous_state,
                current_state={"enabled": False},
                snapshot=snapshot,
            )

        except Exception as e:
            logger.error(f"Error disabling startup {value_name}: {e}")
            return DisableResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.STARTUP,
                previous_state=previous_state,
                error_message=str(e),
                snapshot=snapshot,
            )

    def disable_driver(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> DisableResult:
        """Disable a system driver.

        Args:
            component: Driver component
            context: Additional context (driver_name, etc.)

        Returns:
            DisableResult
        """
        driver_name = context.get("driver_name", component.name)

        # Capture previous state
        previous_state = self._get_driver_state(driver_name)

        if self.dry_run:
            logger.info(f"[DRY RUN] Would disable driver: {driver_name}")
            return DisableResult(
                success=True,
                component_id=component.id,
                component_type=ComponentType.DRIVER,
                previous_state=previous_state,
                current_state={"start_type": "Disabled"},
                requires_reboot=True,
            )

        if not self._is_windows:
            return DisableResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.DRIVER,
                error_message="Driver disable only available on Windows",
            )

        # Create snapshot
        snapshot = None
        if self.create_snapshots:
            snapshot = Snapshot(
                component_id=component.id,
                action=ActionType.DISABLE,
                captured_state={"driver": previous_state},
            )

        try:
            # Use sc.exe to disable the driver
            disable_result = self._run_command(f'sc config "{driver_name}" start= disabled')

            if not disable_result["success"]:
                return DisableResult(
                    success=False,
                    component_id=component.id,
                    component_type=ComponentType.DRIVER,
                    previous_state=previous_state,
                    error_message=disable_result["error"],
                    snapshot=snapshot,
                )

            # Get current state
            current_state = self._get_driver_state(driver_name)

            logger.info(f"Successfully disabled driver: {driver_name} (reboot required)")
            return DisableResult(
                success=True,
                component_id=component.id,
                component_type=ComponentType.DRIVER,
                previous_state=previous_state,
                current_state=current_state,
                requires_reboot=True,
                snapshot=snapshot,
            )

        except Exception as e:
            logger.error(f"Error disabling driver {driver_name}: {e}")
            return DisableResult(
                success=False,
                component_id=component.id,
                component_type=ComponentType.DRIVER,
                previous_state=previous_state,
                error_message=str(e),
                snapshot=snapshot,
            )

    def disable_program(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> DisableResult:
        """Disable a program by disabling its services, tasks, and startup entries.

        Args:
            component: Program component
            context: Additional context

        Returns:
            DisableResult
        """
        results: list[DisableResult] = []
        errors: list[str] = []

        # Disable associated services
        services = context.get("associated_services", [])
        for service_name in services:
            service_context = {"service_name": service_name}
            result = self.disable_service(component, service_context)
            results.append(result)
            if not result.success:
                errors.append(f"Service {service_name}: {result.error_message}")

        # Disable associated tasks
        tasks = context.get("associated_tasks", [])
        for task_path in tasks:
            task_context = {"task_path": task_path}
            result = self.disable_task(component, task_context)
            results.append(result)
            if not result.success:
                errors.append(f"Task {task_path}: {result.error_message}")

        # Disable associated startup entries
        startups = context.get("associated_startups", [])
        for startup in startups:
            startup_context = startup if isinstance(startup, dict) else {"value_name": startup}
            result = self.disable_startup(component, startup_context)
            results.append(result)
            if not result.success:
                errors.append(f"Startup: {result.error_message}")

        # Determine success:
        # - If operations were attempted: success only if no errors
        # - If no operations were attempted: success (no-op), but note it
        if len(results) == 0:
            # No associated services, tasks, or startups to disable
            return DisableResult(
                success=True,
                component_id=component.id,
                component_type=ComponentType.PROGRAM,
                previous_state={"sub_results": 0},
                current_state={"disabled_count": 0},
                error_message="No associated services, tasks, or startup entries to disable",
                requires_reboot=False,
            )

        success = len(errors) == 0
        requires_reboot = any(r.requires_reboot for r in results)

        return DisableResult(
            success=success,
            component_id=component.id,
            component_type=ComponentType.PROGRAM,
            previous_state={"sub_results": len(results)},
            current_state={"disabled_count": sum(1 for r in results if r.success)},
            error_message="; ".join(errors) if errors else None,
            requires_reboot=requires_reboot,
        )

    def _get_service_state(self, service_name: str) -> dict[str, Any]:
        """Get current state of a service."""
        if not self._is_windows:
            return {"status": "Unknown", "start_type": "Unknown"}

        result = self._run_powershell(
            f"Get-Service -Name '{service_name}' | "
            f"Select-Object Status, StartType | ConvertTo-Json"
        )

        if result["success"] and result["output"]:
            try:
                import json

                data = json.loads(result["output"])
                return {
                    "status": str(data.get("Status", "Unknown")),
                    "start_type": str(data.get("StartType", "Unknown")),
                }
            except Exception:
                pass

        return {"status": "Unknown", "start_type": "Unknown"}

    def _get_task_state(self, task_path: str) -> dict[str, Any]:
        """Get current state of a scheduled task."""
        if not self._is_windows:
            return {"state": "Unknown"}

        result = self._run_powershell(
            f"Get-ScheduledTask -TaskPath '{Path(task_path).parent}\\' "
            f"-TaskName '{Path(task_path).name}' -ErrorAction SilentlyContinue | "
            f"Select-Object State | ConvertTo-Json"
        )

        if result["success"] and result["output"]:
            try:
                import json

                data = json.loads(result["output"])
                return {"state": str(data.get("State", "Unknown"))}
            except Exception:
                pass

        return {"state": "Unknown"}

    def _get_driver_state(self, driver_name: str) -> dict[str, Any]:
        """Get current state of a driver."""
        if not self._is_windows:
            return {"start_type": "Unknown", "state": "Unknown"}

        result = self._run_command(f'sc qc "{driver_name}"')

        if result["success"] and result["output"]:
            output = result["output"]
            start_type = "Unknown"
            if "BOOT_START" in output:
                start_type = "Boot"
            elif "SYSTEM_START" in output:
                start_type = "System"
            elif "AUTO_START" in output:
                start_type = "Automatic"
            elif "DEMAND_START" in output:
                start_type = "Manual"
            elif "DISABLED" in output:
                start_type = "Disabled"

            return {"start_type": start_type}

        return {"start_type": "Unknown"}

    def _capture_registry_value(self, key: str, value_name: str) -> dict[str, Any]:
        """Capture a registry value for snapshot."""
        if not self._is_windows:
            return {}

        result = self._run_powershell(
            f"Get-ItemProperty -Path '{key}' -Name '{value_name}' -ErrorAction SilentlyContinue | "
            f"Select-Object -ExpandProperty '{value_name}'"
        )

        return {
            "key": key,
            "value_name": value_name,
            "value_data": result["output"] if result["success"] else None,
        }

    def _disable_registry_startup(self, registry_key: str, value_name: str) -> dict[str, Any]:
        """Disable a registry-based startup entry by renaming it."""
        # Rename the value to disable it (prefix with ~)
        result = self._run_powershell(
            f"$val = (Get-ItemProperty -Path '{registry_key}' -Name '{value_name}' "
            f"-ErrorAction SilentlyContinue).'{value_name}'; "
            f"if ($val) {{ "
            f"Remove-ItemProperty -Path '{registry_key}' -Name '{value_name}' -Force; "
            f"Set-ItemProperty -Path '{registry_key}' -Name '~{value_name}' -Value $val "
            f"}}"
        )

        return result

    def _disable_folder_startup(
        self, component: Component, context: dict[str, Any]
    ) -> dict[str, Any]:
        """Disable a folder-based startup entry by moving it."""
        shortcut_path = context.get("shortcut_path", "")
        if not shortcut_path:
            return {"success": False, "error": "No shortcut path provided"}

        # Create disabled folder if it doesn't exist
        startup_folder = Path(shortcut_path).parent
        disabled_folder = startup_folder / "_disabled"

        result = self._run_powershell(
            f"if (-not (Test-Path '{disabled_folder}')) {{ "
            f"New-Item -Path '{disabled_folder}' -ItemType Directory -Force | Out-Null "
            f"}}; "
            f"Move-Item -Path '{shortcut_path}' -Destination '{disabled_folder}' -Force"
        )

        return result

    def _run_powershell(self, command: str) -> dict[str, Any]:
        """Run a PowerShell command."""
        if self.dry_run:
            return {"success": True, "output": "", "error": ""}

        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                timeout=self.command_timeout,
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
            return {"success": False, "output": "", "error": f"Command timed out after {self.command_timeout}s"}
        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}

    def _run_command(self, command: str) -> dict[str, Any]:
        """Run a shell command."""
        if self.dry_run:
            return {"success": True, "output": "", "error": ""}

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                shell=True,
                timeout=self.command_timeout,
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
            return {"success": False, "output": "", "error": f"Command timed out after {self.command_timeout}s"}
        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}


def create_disable_handler(
    dry_run: bool = False,
    command_timeout: int = 60,
) -> DisableHandler:
    """Create a disable handler.

    Args:
        dry_run: If True, simulate actions
        command_timeout: Timeout in seconds for commands

    Returns:
        DisableHandler instance
    """
    return DisableHandler(dry_run=dry_run, command_timeout=command_timeout)
