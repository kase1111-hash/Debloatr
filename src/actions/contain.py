"""Contain Action Handler - Contains components via firewall and ACLs.

This module provides handlers for containing components by blocking
their network access and preventing execution.
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
    Snapshot,
)

logger = logging.getLogger("debloatr.actions.contain")


@dataclass
class ContainResult:
    """Result of a contain operation.

    Attributes:
        success: Whether the contain succeeded
        component_id: ID of the contained component
        firewall_rule_name: Name of created firewall rule (if any)
        acl_applied: Whether ACL was applied
        previous_state: State before containment
        error_message: Error message if failed
        snapshot: Snapshot for rollback
    """

    success: bool
    component_id: str
    firewall_rule_name: str | None = None
    acl_applied: bool = False
    previous_state: dict[str, Any] = field(default_factory=dict)
    error_message: str | None = None
    snapshot: Snapshot | None = None


class ContainHandler:
    """Handler for containing system components.

    Contains components by:
    1. Creating firewall rules to block network access
    2. Applying ACLs to prevent execution

    Example:
        handler = ContainHandler()
        result = handler.contain_component(component, context)
        if result.success:
            print(f"Component contained with firewall rule: {result.firewall_rule_name}")
    """

    def __init__(
        self,
        dry_run: bool = False,
        create_snapshots: bool = True,
        rule_prefix: str = "Debloatr_Block_",
    ) -> None:
        """Initialize the contain handler.

        Args:
            dry_run: If True, simulate actions without making changes
            create_snapshots: Whether to create snapshots for rollback
            rule_prefix: Prefix for firewall rule names
        """
        self.dry_run = dry_run
        self.create_snapshots = create_snapshots
        self.rule_prefix = rule_prefix
        self._is_windows = os.name == "nt"

    def contain_component(
        self,
        component: Component,
        context: dict[str, Any] | None = None,
    ) -> ContainResult:
        """Contain a component using firewall and ACL restrictions.

        Args:
            component: Component to contain
            context: Additional context (executable paths, etc.)

        Returns:
            ContainResult with operation details
        """
        context = context or {}
        errors: list[str] = []

        # Get executable paths to block
        executables = self._get_executables(component, context)

        if not executables:
            return ContainResult(
                success=False,
                component_id=component.id,
                error_message="No executables found to contain",
            )

        # Capture previous state
        previous_state = self._capture_state(executables)

        if self.dry_run:
            logger.info(f"[DRY RUN] Would contain component: {component.name}")
            logger.info(f"[DRY RUN] Executables: {executables}")
            return ContainResult(
                success=True,
                component_id=component.id,
                firewall_rule_name=f"{self.rule_prefix}{component.name}",
                acl_applied=True,
                previous_state=previous_state,
            )

        if not self._is_windows:
            return ContainResult(
                success=False,
                component_id=component.id,
                error_message="Containment only available on Windows",
            )

        # Create snapshot
        snapshot = None
        if self.create_snapshots:
            snapshot = Snapshot(
                component_id=component.id,
                action=ActionType.CONTAIN,
                captured_state=previous_state,
            )

        # Apply firewall rules
        firewall_rule_name = None
        if context.get("block_network", True):
            fw_result = self._create_firewall_rules(component, executables)
            if fw_result["success"]:
                firewall_rule_name = fw_result["rule_name"]
            else:
                errors.append(f"Firewall: {fw_result['error']}")

        # Apply ACL restrictions
        acl_applied = False
        if context.get("block_execution", True):
            acl_result = self._apply_acl_restrictions(executables)
            if acl_result["success"]:
                acl_applied = True
            else:
                errors.append(f"ACL: {acl_result['error']}")

        success = firewall_rule_name is not None or acl_applied

        return ContainResult(
            success=success,
            component_id=component.id,
            firewall_rule_name=firewall_rule_name,
            acl_applied=acl_applied,
            previous_state=previous_state,
            error_message="; ".join(errors) if errors else None,
            snapshot=snapshot,
        )

    def contain_with_firewall(
        self,
        component: Component,
        context: dict[str, Any] | None = None,
    ) -> ContainResult:
        """Contain a component by blocking network access.

        Args:
            component: Component to contain
            context: Additional context

        Returns:
            ContainResult
        """
        context = context or {}
        context["block_network"] = True
        context["block_execution"] = False
        return self.contain_component(component, context)

    def contain_with_acl(
        self,
        component: Component,
        context: dict[str, Any] | None = None,
    ) -> ContainResult:
        """Contain a component by blocking execution.

        Args:
            component: Component to contain
            context: Additional context

        Returns:
            ContainResult
        """
        context = context or {}
        context["block_network"] = False
        context["block_execution"] = True
        return self.contain_component(component, context)

    def remove_containment(
        self,
        component: Component,
        context: dict[str, Any] | None = None,
    ) -> ContainResult:
        """Remove containment from a component.

        Args:
            component: Component to uncontain
            context: Additional context (firewall_rule_name, etc.)

        Returns:
            ContainResult
        """
        context = context or {}
        errors: list[str] = []

        executables = self._get_executables(component, context)

        if self.dry_run:
            logger.info(f"[DRY RUN] Would remove containment from: {component.name}")
            return ContainResult(
                success=True,
                component_id=component.id,
            )

        if not self._is_windows:
            return ContainResult(
                success=False,
                component_id=component.id,
                error_message="Containment removal only available on Windows",
            )

        # Remove firewall rules
        rule_name = context.get("firewall_rule_name", f"{self.rule_prefix}{component.name}")
        fw_result = self._remove_firewall_rules(rule_name)
        if not fw_result["success"]:
            errors.append(f"Firewall removal: {fw_result['error']}")

        # Remove ACL restrictions
        if executables:
            acl_result = self._remove_acl_restrictions(executables)
            if not acl_result["success"]:
                errors.append(f"ACL removal: {acl_result['error']}")

        success = len(errors) == 0

        return ContainResult(
            success=success,
            component_id=component.id,
            error_message="; ".join(errors) if errors else None,
        )

    def _get_executables(
        self,
        component: Component,
        context: dict[str, Any],
    ) -> list[Path]:
        """Get executable paths for a component."""
        executables: list[Path] = []

        # From context
        exe_paths = context.get("executables", [])
        for exe in exe_paths:
            if isinstance(exe, str):
                executables.append(Path(exe))
            elif isinstance(exe, Path):
                executables.append(exe)

        # From component install path
        if component.install_path:
            if component.install_path.is_file():
                executables.append(component.install_path)
            elif component.install_path.is_dir():
                # Find executables in directory
                for ext in ["*.exe", "*.dll"]:
                    executables.extend(component.install_path.glob(ext))

        # From context binary path
        binary_path = context.get("binary_path")
        if binary_path:
            executables.append(Path(binary_path))

        # Remove duplicates while preserving order
        seen: set[str] = set()
        unique: list[Path] = []
        for exe in executables:
            exe_str = str(exe).lower()
            if exe_str not in seen:
                seen.add(exe_str)
                unique.append(exe)

        return unique

    def _capture_state(self, executables: list[Path]) -> dict[str, Any]:
        """Capture current state for snapshot."""
        state: dict[str, Any] = {
            "executables": [str(e) for e in executables],
            "firewall_rules": [],
            "acl_states": {},
        }

        if self._is_windows:
            # Check existing firewall rules
            for exe in executables:
                rules = self._get_firewall_rules_for_path(exe)
                state["firewall_rules"].extend(rules)

            # Capture ACL states
            for exe in executables:
                if exe.exists():
                    acl = self._get_acl_state(exe)
                    state["acl_states"][str(exe)] = acl

        return state

    def _get_firewall_rules_for_path(self, path: Path) -> list[str]:
        """Get firewall rules affecting a path."""
        if not self._is_windows:
            return []

        result = self._run_powershell(
            f"Get-NetFirewallApplicationFilter | "
            f"Where-Object {{ $_.Program -like '*{path.name}*' }} | "
            f"ForEach-Object {{ (Get-NetFirewallRule -AssociatedNetFirewallApplicationFilter $_).DisplayName }}"
        )

        if result["success"] and result["output"]:
            return result["output"].strip().split("\n")
        return []

    def _get_acl_state(self, path: Path) -> dict[str, Any]:
        """Get ACL state for a path."""
        if not self._is_windows or not path.exists():
            return {}

        result = self._run_powershell(
            f"Get-Acl -Path '{path}' | "
            f"Select-Object -ExpandProperty Access | "
            f"ConvertTo-Json -Compress"
        )

        if result["success"] and result["output"]:
            try:
                import json

                return {"access": json.loads(result["output"])}
            except Exception:
                pass

        return {}

    def _create_firewall_rules(
        self,
        component: Component,
        executables: list[Path],
    ) -> dict[str, Any]:
        """Create firewall rules to block network access."""
        rule_name = f"{self.rule_prefix}{component.name}"

        if not executables:
            return {"success": False, "error": "No executables to block"}

        try:
            # Create outbound block rule for each executable
            for exe in executables:
                if not exe.exists():
                    logger.warning(f"Executable not found: {exe}")
                    continue

                # Create outbound block rule
                result = self._run_powershell(
                    f"New-NetFirewallRule "
                    f"-DisplayName '{rule_name}_{exe.stem}' "
                    f"-Direction Outbound "
                    f"-Action Block "
                    f"-Program '{exe}' "
                    f"-Enabled True "
                    f"-ErrorAction Stop"
                )

                if not result["success"]:
                    logger.warning(f"Failed to create firewall rule for {exe}: {result['error']}")

                # Also create inbound block rule
                self._run_powershell(
                    f"New-NetFirewallRule "
                    f"-DisplayName '{rule_name}_{exe.stem}_In' "
                    f"-Direction Inbound "
                    f"-Action Block "
                    f"-Program '{exe}' "
                    f"-Enabled True "
                    f"-ErrorAction SilentlyContinue"
                )

            logger.info(f"Created firewall rules for {component.name}")
            return {"success": True, "rule_name": rule_name}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _remove_firewall_rules(self, rule_name: str) -> dict[str, Any]:
        """Remove firewall rules by name prefix."""
        try:
            result = self._run_powershell(
                f"Get-NetFirewallRule | "
                f"Where-Object {{ $_.DisplayName -like '{rule_name}*' }} | "
                f"Remove-NetFirewallRule -ErrorAction Stop"
            )

            if result["success"]:
                logger.info(f"Removed firewall rules matching: {rule_name}*")
                return {"success": True}
            else:
                return {"success": False, "error": result["error"]}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _apply_acl_restrictions(self, executables: list[Path]) -> dict[str, Any]:
        """Apply deny execute ACL to executables."""
        try:
            for exe in executables:
                if not exe.exists():
                    continue

                # Add deny execute for Everyone
                result = self._run_powershell(
                    f"$acl = Get-Acl -Path '{exe}'; "
                    f"$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("
                    f"'Everyone', 'ExecuteFile', 'Deny'); "
                    f"$acl.AddAccessRule($rule); "
                    f"Set-Acl -Path '{exe}' -AclObject $acl -ErrorAction Stop"
                )

                if not result["success"]:
                    logger.warning(f"Failed to apply ACL to {exe}: {result['error']}")

            logger.info(f"Applied ACL restrictions to {len(executables)} executables")
            return {"success": True}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _remove_acl_restrictions(self, executables: list[Path]) -> dict[str, Any]:
        """Remove deny execute ACL from executables."""
        try:
            for exe in executables:
                if not exe.exists():
                    continue

                # Remove deny execute for Everyone
                result = self._run_powershell(
                    f"$acl = Get-Acl -Path '{exe}'; "
                    f"$acl.Access | Where-Object {{ "
                    f"$_.IdentityReference -eq 'Everyone' -and "
                    f"$_.FileSystemRights -eq 'ExecuteFile' -and "
                    f"$_.AccessControlType -eq 'Deny' }} | "
                    f"ForEach-Object {{ $acl.RemoveAccessRule($_) }}; "
                    f"Set-Acl -Path '{exe}' -AclObject $acl -ErrorAction Stop"
                )

                if not result["success"]:
                    logger.warning(f"Failed to remove ACL from {exe}: {result['error']}")

            logger.info(f"Removed ACL restrictions from {len(executables)} executables")
            return {"success": True}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_powershell(self, command: str) -> dict[str, Any]:
        """Run a PowerShell command."""
        if self.dry_run:
            return {"success": True, "output": "", "error": ""}

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


def create_contain_handler(dry_run: bool = False) -> ContainHandler:
    """Create a contain handler.

    Args:
        dry_run: If True, simulate actions

    Returns:
        ContainHandler instance
    """
    return ContainHandler(dry_run=dry_run)
