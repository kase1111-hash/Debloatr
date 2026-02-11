"""Rollback Manager - Handles rollback operations for actions.

This module provides the RollbackManager class for rolling back
actions using captured snapshots.
"""

import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.core.config import Config, get_default_config
from src.core.models import (
    ActionResult,
    ActionType,
    Session,
    Snapshot,
)
from src.core.session import SessionManager, create_session_manager
from src.core.snapshot import SnapshotManager, create_snapshot_manager

logger = logging.getLogger("debloatr.core.rollback")


@dataclass
class RollbackResult:
    """Result of a rollback operation.

    Attributes:
        success: Whether the rollback succeeded
        action_id: ID of the original action
        snapshot_id: ID of the snapshot used
        component_id: ID of the component
        component_name: Name of the component
        original_action: The original action that was undone
        error_message: Error message if failed
        requires_reboot: Whether reboot is needed
        partial: Whether rollback was only partial
        details: Additional details about the rollback
    """

    success: bool
    action_id: str
    snapshot_id: str | None
    component_id: str
    component_name: str
    original_action: str
    error_message: str | None = None
    requires_reboot: bool = False
    partial: bool = False
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionRollbackResult:
    """Result of rolling back an entire session.

    Attributes:
        success: Overall success
        session_id: ID of the rolled-back session
        total_actions: Total actions attempted
        successful_rollbacks: Number of successful rollbacks
        failed_rollbacks: Number of failed rollbacks
        results: Individual rollback results
        requires_reboot: Whether reboot is needed
    """

    success: bool
    session_id: str
    total_actions: int
    successful_rollbacks: int
    failed_rollbacks: int
    results: list[RollbackResult] = field(default_factory=list)
    requires_reboot: bool = False


class RollbackManager:
    """Manager for rolling back actions.

    Provides methods to rollback individual actions or entire sessions
    using captured snapshots. Supports rollback for all action types:
    - DISABLE: Re-enable services, tasks, startup entries, drivers
    - CONTAIN: Remove firewall rules, restore ACLs
    - REMOVE: Restore from quarantine (partial support)

    Example:
        manager = RollbackManager()

        # Rollback a single action
        result = manager.rollback_action(action_result, snapshot)

        # Rollback entire session
        result = manager.rollback_session(session_id)

        # Rollback last session
        result = manager.rollback_last_session()
    """

    def __init__(
        self,
        config: Config | None = None,
        snapshot_manager: SnapshotManager | None = None,
        session_manager: SessionManager | None = None,
        dry_run: bool = False,
    ) -> None:
        """Initialize the rollback manager.

        Args:
            config: Configuration object
            snapshot_manager: SnapshotManager instance
            session_manager: SessionManager instance
            dry_run: If True, simulate rollback without changes
        """
        self.config = config or get_default_config()
        self.snapshot_manager = snapshot_manager or create_snapshot_manager(config)
        self.session_manager = session_manager or create_session_manager(config)
        self.dry_run = dry_run
        self._is_windows = os.name == "nt"

    def rollback_action(
        self,
        action_result: ActionResult,
        snapshot: Snapshot | None = None,
        component_name: str = "Unknown",
    ) -> RollbackResult:
        """Rollback a single action.

        Args:
            action_result: The ActionResult to rollback
            snapshot: The snapshot to restore from (loaded if not provided)
            component_name: Name of the component

        Returns:
            RollbackResult with rollback outcome
        """
        # Load snapshot if not provided
        if not snapshot and action_result.snapshot_id:
            snapshot = self.snapshot_manager.load_snapshot(action_result.snapshot_id)

        if not snapshot:
            return RollbackResult(
                success=False,
                action_id=action_result.plan_id,
                snapshot_id=action_result.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action=(
                    action_result.action.value
                    if isinstance(action_result.action, ActionType)
                    else str(action_result.action)
                ),
                error_message="Snapshot not found for rollback",
            )

        # Dispatch based on action type
        action = action_result.action
        if action == ActionType.DISABLE:
            return self._rollback_disable(action_result, snapshot, component_name)
        elif action == ActionType.CONTAIN:
            return self._rollback_contain(action_result, snapshot, component_name)
        elif action == ActionType.REMOVE:
            return self._rollback_remove(action_result, snapshot, component_name)
        else:
            return RollbackResult(
                success=False,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action=action.value if isinstance(action, ActionType) else str(action),
                error_message=f"Rollback not supported for action type: {action}",
            )

    def rollback_session(
        self,
        session_id: str,
        stop_on_failure: bool = False,
    ) -> SessionRollbackResult:
        """Rollback all actions in a session (in reverse order).

        Args:
            session_id: ID of the session to rollback
            stop_on_failure: If True, stop on first failure

        Returns:
            SessionRollbackResult with overall outcome
        """
        session = self.session_manager.get_session(session_id)
        if not session:
            return SessionRollbackResult(
                success=False,
                session_id=session_id,
                total_actions=0,
                successful_rollbacks=0,
                failed_rollbacks=0,
                results=[
                    RollbackResult(
                        success=False,
                        action_id="",
                        snapshot_id=None,
                        component_id="",
                        component_name="",
                        original_action="",
                        error_message=f"Session not found: {session_id}",
                    )
                ],
            )

        # Get rollbackable actions
        actions = self.session_manager.get_session_actions(session_id)
        rollbackable = [a for a in actions if a.rollback_available and a.success]

        # Reverse order for rollback
        rollbackable.reverse()

        results: list[RollbackResult] = []
        successful = 0
        failed = 0
        requires_reboot = False

        for action_summary in rollbackable:
            # Load the full action from session
            action_result = self._find_action_in_session(session, action_summary.plan_id)
            if not action_result:
                result = RollbackResult(
                    success=False,
                    action_id=action_summary.plan_id,
                    snapshot_id=action_summary.snapshot_id,
                    component_id=action_summary.component_id,
                    component_name=action_summary.component_name,
                    original_action=action_summary.action,
                    error_message="Action not found in session",
                )
                results.append(result)
                failed += 1
                if stop_on_failure:
                    break
                continue

            # Perform rollback
            result = self.rollback_action(
                action_result,
                component_name=action_summary.component_name,
            )
            results.append(result)

            if result.success:
                successful += 1
            else:
                failed += 1
                if stop_on_failure:
                    break

            if result.requires_reboot:
                requires_reboot = True

        return SessionRollbackResult(
            success=failed == 0,
            session_id=session_id,
            total_actions=len(rollbackable),
            successful_rollbacks=successful,
            failed_rollbacks=failed,
            results=results,
            requires_reboot=requires_reboot,
        )

    def rollback_last_session(self, stop_on_failure: bool = False) -> SessionRollbackResult:
        """Rollback the most recent session.

        Args:
            stop_on_failure: If True, stop on first failure

        Returns:
            SessionRollbackResult with overall outcome
        """
        last_session = self.session_manager.get_last_session()
        if not last_session:
            return SessionRollbackResult(
                success=False,
                session_id="",
                total_actions=0,
                successful_rollbacks=0,
                failed_rollbacks=0,
                results=[
                    RollbackResult(
                        success=False,
                        action_id="",
                        snapshot_id=None,
                        component_id="",
                        component_name="",
                        original_action="",
                        error_message="No sessions found",
                    )
                ],
            )

        return self.rollback_session(last_session.session_id, stop_on_failure)

    def _find_action_in_session(self, session: Session, plan_id: str) -> ActionResult | None:
        """Find an action in a session by plan ID."""
        for action in session.actions:
            if action.plan_id == plan_id:
                return action
        return None

    def _rollback_disable(
        self,
        action_result: ActionResult,
        snapshot: Snapshot,
        component_name: str,
    ) -> RollbackResult:
        """Rollback a DISABLE action by re-enabling the component."""
        state = snapshot.captured_state
        meta = state.get("_meta", {})
        component_type = meta.get("component_type", "UNKNOWN")

        if self.dry_run:
            logger.info(f"[DRY RUN] Would re-enable: {component_name}")
            return RollbackResult(
                success=True,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action="DISABLE",
            )

        if not self._is_windows:
            return RollbackResult(
                success=False,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action="DISABLE",
                error_message="Rollback only available on Windows",
            )

        # Dispatch based on component type
        if component_type == "SERVICE":
            return self._enable_service(action_result, snapshot, state, component_name)
        elif component_type == "TASK":
            return self._enable_task(action_result, snapshot, state, component_name)
        elif component_type == "STARTUP":
            return self._enable_startup(action_result, snapshot, state, component_name)
        elif component_type == "DRIVER":
            return self._enable_driver(action_result, snapshot, state, component_name)
        else:
            return RollbackResult(
                success=False,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action="DISABLE",
                error_message=f"Unknown component type: {component_type}",
            )

    def _enable_service(
        self,
        action_result: ActionResult,
        snapshot: Snapshot,
        state: dict[str, Any],
        component_name: str,
    ) -> RollbackResult:
        """Re-enable a disabled service."""
        service_name = state.get("service_name", component_name)
        status = state.get("status", {})

        # Determine original start type
        original_start_type = status.get("StartType", "Automatic")
        if isinstance(original_start_type, int):
            start_type_map = {0: "Boot", 1: "System", 2: "Automatic", 3: "Manual", 4: "Disabled"}
            original_start_type = start_type_map.get(original_start_type, "Automatic")

        try:
            # Restore original startup type
            result = self._run_powershell(
                f"Set-Service -Name '{service_name}' -StartupType '{original_start_type}' -ErrorAction Stop"
            )

            if not result["success"]:
                return RollbackResult(
                    success=False,
                    action_id=action_result.plan_id,
                    snapshot_id=snapshot.snapshot_id,
                    component_id=action_result.component_id,
                    component_name=component_name,
                    original_action="DISABLE",
                    error_message=f"Failed to set startup type: {result['error']}",
                )

            # Start the service if it was running
            original_status = status.get("Status", "")
            if original_status in ["Running", "4"]:  # 4 is Running enum value
                start_result = self._run_powershell(
                    f"Start-Service -Name '{service_name}' -ErrorAction SilentlyContinue"
                )
                if not start_result["success"]:
                    logger.warning(
                        f"Could not start service {service_name}: {start_result['error']}"
                    )

            logger.info(f"Re-enabled service: {service_name}")
            return RollbackResult(
                success=True,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action="DISABLE",
                details={"start_type": original_start_type},
            )

        except Exception as e:
            return RollbackResult(
                success=False,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action="DISABLE",
                error_message=str(e),
            )

    def _enable_task(
        self,
        action_result: ActionResult,
        snapshot: Snapshot,
        state: dict[str, Any],
        component_name: str,
    ) -> RollbackResult:
        """Re-enable a disabled scheduled task."""
        task_path = state.get("task_path", component_name)

        try:
            # Enable the task
            result = self._run_command(f'schtasks /Change /TN "{task_path}" /Enable')

            if not result["success"]:
                # Try PowerShell method
                task_name = Path(task_path).name.replace("'", "''")
                task_parent = str(Path(task_path).parent).replace("/", "\\")
                if not task_parent.endswith("\\"):
                    task_parent += "\\"
                result = self._run_powershell(
                    f"Enable-ScheduledTask -TaskPath '{task_parent}' -TaskName '{task_name}' -ErrorAction Stop"
                )

            if not result["success"]:
                return RollbackResult(
                    success=False,
                    action_id=action_result.plan_id,
                    snapshot_id=snapshot.snapshot_id,
                    component_id=action_result.component_id,
                    component_name=component_name,
                    original_action="DISABLE",
                    error_message=f"Failed to enable task: {result['error']}",
                )

            logger.info(f"Re-enabled task: {task_path}")
            return RollbackResult(
                success=True,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action="DISABLE",
            )

        except Exception as e:
            return RollbackResult(
                success=False,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action="DISABLE",
                error_message=str(e),
            )

    def _enable_startup(
        self,
        action_result: ActionResult,
        snapshot: Snapshot,
        state: dict[str, Any],
        component_name: str,
    ) -> RollbackResult:
        """Re-enable a disabled startup entry."""
        entry_name = state.get("entry_name", component_name)
        entry_type = state.get("entry_type", "registry")
        registry_key = state.get("registry_key", "")

        try:
            if entry_type == "registry":
                # Get the original value from snapshot
                reg_value = state.get("registry_value", {})
                value_data = reg_value.get("Value")
                _value_type = reg_value.get(
                    "Type", "String"
                )  # Reserved for typed registry restoration

                if value_data is not None:
                    # Restore the registry value
                    # First, try to remove any disabled version (~entry_name)
                    self._run_powershell(
                        f"Remove-ItemProperty -Path '{registry_key}' -Name '~{entry_name}' "
                        f"-Force -ErrorAction SilentlyContinue"
                    )

                    # Set the original value
                    result = self._run_powershell(
                        f"Set-ItemProperty -Path '{registry_key}' -Name '{entry_name}' "
                        f"-Value '{value_data}' -ErrorAction Stop"
                    )

                    if not result["success"]:
                        return RollbackResult(
                            success=False,
                            action_id=action_result.plan_id,
                            snapshot_id=snapshot.snapshot_id,
                            component_id=action_result.component_id,
                            component_name=component_name,
                            original_action="DISABLE",
                            error_message=f"Failed to restore registry: {result['error']}",
                        )
                else:
                    # Try to restore from disabled version
                    result = self._run_powershell(
                        f"$val = (Get-ItemProperty -Path '{registry_key}' -Name '~{entry_name}' "
                        f"-ErrorAction SilentlyContinue).'~{entry_name}'; "
                        f"if ($val) {{ "
                        f"Set-ItemProperty -Path '{registry_key}' -Name '{entry_name}' -Value $val; "
                        f"Remove-ItemProperty -Path '{registry_key}' -Name '~{entry_name}' -Force "
                        f"}}"
                    )

            elif entry_type == "folder":
                # Move shortcut back from disabled folder
                startup_folder = state.get("startup_folder", "")
                if startup_folder:
                    disabled_folder = Path(startup_folder) / "_disabled"
                    shortcut_name = state.get("shortcut_name", f"{entry_name}.lnk")

                    if (disabled_folder / shortcut_name).exists():
                        result = self._run_powershell(
                            f"Move-Item -Path '{disabled_folder / shortcut_name}' "
                            f"-Destination '{startup_folder}' -Force"
                        )
                    else:
                        return RollbackResult(
                            success=False,
                            action_id=action_result.plan_id,
                            snapshot_id=snapshot.snapshot_id,
                            component_id=action_result.component_id,
                            component_name=component_name,
                            original_action="DISABLE",
                            error_message="Disabled shortcut not found",
                        )

            logger.info(f"Re-enabled startup: {entry_name}")
            return RollbackResult(
                success=True,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action="DISABLE",
            )

        except Exception as e:
            return RollbackResult(
                success=False,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action="DISABLE",
                error_message=str(e),
            )

    def _enable_driver(
        self,
        action_result: ActionResult,
        snapshot: Snapshot,
        state: dict[str, Any],
        component_name: str,
    ) -> RollbackResult:
        """Re-enable a disabled driver."""
        driver_name = state.get("driver_name", component_name)
        info = state.get("info", {})

        # Determine original start mode
        original_start_mode = info.get("StartMode", "Manual")
        start_mode_map = {
            "Boot": "boot",
            "System": "system",
            "Auto": "auto",
            "Automatic": "auto",
            "Manual": "demand",
            "Disabled": "disabled",
        }
        sc_start_type = start_mode_map.get(original_start_mode, "demand")

        try:
            # Restore original startup type
            result = self._run_command(f'sc config "{driver_name}" start= {sc_start_type}')

            if not result["success"]:
                return RollbackResult(
                    success=False,
                    action_id=action_result.plan_id,
                    snapshot_id=snapshot.snapshot_id,
                    component_id=action_result.component_id,
                    component_name=component_name,
                    original_action="DISABLE",
                    error_message=f"Failed to restore driver: {result['error']}",
                )

            logger.info(f"Re-enabled driver: {driver_name} (reboot required)")
            return RollbackResult(
                success=True,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action="DISABLE",
                requires_reboot=True,
                details={"start_type": sc_start_type},
            )

        except Exception as e:
            return RollbackResult(
                success=False,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action="DISABLE",
                error_message=str(e),
            )

    def _rollback_contain(
        self,
        action_result: ActionResult,
        snapshot: Snapshot,
        component_name: str,
    ) -> RollbackResult:
        """Rollback a CONTAIN action by removing firewall rules and restoring ACLs."""
        state = snapshot.captured_state

        if self.dry_run:
            logger.info(f"[DRY RUN] Would remove containment from: {component_name}")
            return RollbackResult(
                success=True,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action="CONTAIN",
            )

        if not self._is_windows:
            return RollbackResult(
                success=False,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action="CONTAIN",
                error_message="Rollback only available on Windows",
            )

        errors: list[str] = []

        # Remove Debloatr firewall rules
        rule_prefix = f"Debloatr_Block_{component_name}"
        escaped_prefix = rule_prefix.replace("'", "''")
        fw_result = self._run_powershell(
            f"Get-NetFirewallRule | Where-Object {{ $_.DisplayName -like '{escaped_prefix}*' }} | "
            f"Remove-NetFirewallRule -ErrorAction SilentlyContinue"
        )
        if not fw_result["success"]:
            errors.append(f"Firewall: {fw_result['error']}")

        # Restore ACLs
        executables = state.get("executables", [])
        _acls = state.get("acls", {})  # Reserved for detailed ACL restoration

        for exe_path in executables:
            if not Path(exe_path).exists():
                continue

            # Remove deny execute ACL for Everyone
            acl_result = self._run_powershell(
                f"$acl = Get-Acl -Path '{exe_path}'; "
                f"$acl.Access | Where-Object {{ "
                f"$_.IdentityReference -eq 'Everyone' -and "
                f"$_.FileSystemRights -eq 'ExecuteFile' -and "
                f"$_.AccessControlType -eq 'Deny' }} | "
                f"ForEach-Object {{ $acl.RemoveAccessRule($_) }}; "
                f"Set-Acl -Path '{exe_path}' -AclObject $acl -ErrorAction SilentlyContinue"
            )
            if not acl_result["success"]:
                errors.append(f"ACL {exe_path}: {acl_result['error']}")

        success = len(errors) == 0
        logger.info(f"Removed containment from: {component_name}")

        return RollbackResult(
            success=success,
            action_id=action_result.plan_id,
            snapshot_id=snapshot.snapshot_id,
            component_id=action_result.component_id,
            component_name=component_name,
            original_action="CONTAIN",
            error_message="; ".join(errors) if errors else None,
        )

    def _rollback_remove(
        self,
        action_result: ActionResult,
        snapshot: Snapshot,
        component_name: str,
    ) -> RollbackResult:
        """Rollback a REMOVE action (limited support).

        REMOVE actions are only partially reversible:
        - Quarantined files can be restored
        - Registry can be restored if captured
        - UWP apps can be reinstalled from Store
        - Services and tasks may need manual reinstallation
        """
        state = snapshot.captured_state
        meta = state.get("_meta", {})
        component_type = meta.get("component_type", "UNKNOWN")

        if self.dry_run:
            logger.info(f"[DRY RUN] Would attempt to restore: {component_name}")
            return RollbackResult(
                success=True,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action="REMOVE",
                partial=True,
            )

        if not self._is_windows:
            return RollbackResult(
                success=False,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action="REMOVE",
                error_message="Rollback only available on Windows",
            )

        # Try to restore based on component type
        if component_type == "UWP":
            return self._restore_uwp(action_result, snapshot, state, component_name)
        elif component_type == "TASK":
            return self._restore_task(action_result, snapshot, state, component_name)
        elif component_type == "STARTUP":
            return self._restore_startup(action_result, snapshot, state, component_name)
        else:
            # For programs and services, we can only provide guidance
            return RollbackResult(
                success=False,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action="REMOVE",
                error_message=f"Automatic restoration not available for {component_type}. "
                f"Consider using System Restore or reinstalling the component.",
                partial=True,
                details={
                    "suggestion": "Use System Restore point or reinstall",
                    "component_type": component_type,
                },
            )

    def _restore_uwp(
        self,
        action_result: ActionResult,
        snapshot: Snapshot,
        state: dict[str, Any],
        component_name: str,
    ) -> RollbackResult:
        """Attempt to restore a removed UWP app."""
        package_name = state.get("package_name", component_name)

        # Try to reinstall from Store
        result = self._run_powershell(
            f"Get-AppxPackage -AllUsers -Name '*{package_name}*' | "
            f"ForEach-Object {{ Add-AppxPackage -DisableDevelopmentMode -Register "
            f'"$($_.InstallLocation)\\AppXManifest.xml" -ErrorAction SilentlyContinue }}'
        )

        if result["success"]:
            logger.info(f"Restored UWP app: {package_name}")
            return RollbackResult(
                success=True,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action="REMOVE",
            )
        else:
            return RollbackResult(
                success=False,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action="REMOVE",
                error_message=f"Could not restore UWP app. Reinstall from Microsoft Store: {package_name}",
                partial=True,
            )

    def _restore_task(
        self,
        action_result: ActionResult,
        snapshot: Snapshot,
        state: dict[str, Any],
        component_name: str,
    ) -> RollbackResult:
        """Attempt to restore a removed scheduled task from XML."""
        task_path = state.get("task_path", component_name)
        task_xml = state.get("task_xml", "")

        if not task_xml:
            return RollbackResult(
                success=False,
                action_id=action_result.plan_id,
                snapshot_id=snapshot.snapshot_id,
                component_id=action_result.component_id,
                component_name=component_name,
                original_action="REMOVE",
                error_message="Task XML not available for restoration",
            )

        # Create temp file with XML
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(task_xml)
            xml_path = f.name

        try:
            result = self._run_command(f'schtasks /Create /TN "{task_path}" /XML "{xml_path}"')

            if result["success"]:
                logger.info(f"Restored task: {task_path}")
                return RollbackResult(
                    success=True,
                    action_id=action_result.plan_id,
                    snapshot_id=snapshot.snapshot_id,
                    component_id=action_result.component_id,
                    component_name=component_name,
                    original_action="REMOVE",
                )
            else:
                return RollbackResult(
                    success=False,
                    action_id=action_result.plan_id,
                    snapshot_id=snapshot.snapshot_id,
                    component_id=action_result.component_id,
                    component_name=component_name,
                    original_action="REMOVE",
                    error_message=f"Failed to restore task: {result['error']}",
                )
        finally:
            Path(xml_path).unlink(missing_ok=True)

    def _restore_startup(
        self,
        action_result: ActionResult,
        snapshot: Snapshot,
        state: dict[str, Any],
        component_name: str,
    ) -> RollbackResult:
        """Attempt to restore a removed startup entry."""
        entry_type = state.get("entry_type", "registry")
        registry_key = state.get("registry_key", "")
        value_name = state.get("value_name", component_name)

        if entry_type == "registry" and registry_key:
            # Get value from snapshot
            # The captured_state might have the original value
            reg_data = state.get("registry_value", state.get("value_data"))

            if reg_data:
                result = self._run_powershell(
                    f"Set-ItemProperty -Path '{registry_key}' -Name '{value_name}' "
                    f"-Value '{reg_data}' -ErrorAction Stop"
                )

                if result["success"]:
                    logger.info(f"Restored startup entry: {value_name}")
                    return RollbackResult(
                        success=True,
                        action_id=action_result.plan_id,
                        snapshot_id=snapshot.snapshot_id,
                        component_id=action_result.component_id,
                        component_name=component_name,
                        original_action="REMOVE",
                    )

        return RollbackResult(
            success=False,
            action_id=action_result.plan_id,
            snapshot_id=snapshot.snapshot_id,
            component_id=action_result.component_id,
            component_name=component_name,
            original_action="REMOVE",
            error_message="Could not restore startup entry",
            partial=True,
        )

    def _run_powershell(self, command: str) -> dict[str, Any]:
        """Run a PowerShell command."""
        if self.dry_run:
            return {"success": True, "output": "", "error": ""}

        if not self._is_windows:
            return {"success": False, "output": "", "error": "Not Windows"}

        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                timeout=60,
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

        if not self._is_windows:
            return {"success": False, "output": "", "error": "Not Windows"}

        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
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


def create_rollback_manager(
    config: Config | None = None,
    dry_run: bool = False,
) -> RollbackManager:
    """Create a rollback manager with default or provided configuration.

    Args:
        config: Optional configuration object
        dry_run: If True, simulate rollback without changes

    Returns:
        RollbackManager instance
    """
    return RollbackManager(config=config, dry_run=dry_run)
