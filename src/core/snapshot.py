"""Snapshot Manager - Captures and stores state snapshots for rollback.

This module provides the SnapshotManager class for capturing, storing,
and retrieving snapshots of component state before modifications.
"""

import json
import os
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional
import logging
import shutil

from src.core.models import (
    Snapshot,
    ActionType,
    ComponentType,
)
from src.core.config import Config, get_default_config

logger = logging.getLogger("debloatr.core.snapshot")


@dataclass
class SnapshotMetadata:
    """Metadata for a stored snapshot.

    Attributes:
        snapshot_id: Unique identifier
        component_id: ID of the component
        component_name: Name of the component
        component_type: Type of the component
        action: Action that triggered the snapshot
        timestamp: When snapshot was taken
        session_id: ID of the session (if any)
        file_path: Path to the snapshot file
        size_bytes: Size of the snapshot file
    """

    snapshot_id: str
    component_id: str
    component_name: str
    component_type: str
    action: str
    timestamp: str
    session_id: Optional[str] = None
    file_path: Optional[str] = None
    size_bytes: int = 0


class SnapshotManager:
    """Manager for capturing and storing state snapshots.

    Provides methods to capture component state before modifications,
    store snapshots to disk, and retrieve them for rollback operations.

    Example:
        manager = SnapshotManager()
        snapshot = manager.capture_service_snapshot("MyService", component)
        manager.save_snapshot(snapshot, component_name="MyService")

        # Later, for rollback
        loaded = manager.load_snapshot(snapshot.snapshot_id)
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        snapshots_dir: Optional[Path] = None,
        max_snapshots: int = 100,
        retention_days: int = 30,
    ) -> None:
        """Initialize the snapshot manager.

        Args:
            config: Configuration object
            snapshots_dir: Override directory for snapshots
            max_snapshots: Maximum number of snapshots to keep
            retention_days: Days to retain snapshots
        """
        self.config = config or get_default_config()
        self.snapshots_dir = snapshots_dir or self.config.snapshots_dir
        self.max_snapshots = max_snapshots
        self.retention_days = retention_days
        self._is_windows = os.name == "nt"

        # Ensure snapshots directory exists
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)

        # Index file for quick lookup
        self._index_file = self.snapshots_dir / "snapshot_index.json"
        self._index: dict[str, SnapshotMetadata] = {}
        self._load_index()

    def _load_index(self) -> None:
        """Load snapshot index from disk."""
        if self._index_file.exists():
            try:
                with open(self._index_file, encoding="utf-8") as f:
                    data = json.load(f)
                    for snapshot_id, meta in data.items():
                        self._index[snapshot_id] = SnapshotMetadata(**meta)
            except Exception as e:
                logger.warning(f"Failed to load snapshot index: {e}")
                self._index = {}

    def _save_index(self) -> None:
        """Save snapshot index to disk."""
        try:
            data = {
                snapshot_id: asdict(meta)
                for snapshot_id, meta in self._index.items()
            }
            with open(self._index_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save snapshot index: {e}")

    def capture_snapshot(
        self,
        component_id: str,
        component_name: str,
        component_type: ComponentType,
        action: ActionType,
        state: dict[str, Any],
        session_id: Optional[str] = None,
    ) -> Snapshot:
        """Capture a snapshot of component state.

        Args:
            component_id: ID of the component
            component_name: Name of the component
            component_type: Type of the component
            action: Action that triggered the snapshot
            state: State dictionary to capture
            session_id: ID of the current session

        Returns:
            Snapshot object with captured state
        """
        snapshot = Snapshot(
            component_id=component_id,
            action=action,
            captured_state=state,
        )

        # Add extra metadata to state
        snapshot.captured_state["_meta"] = {
            "component_name": component_name,
            "component_type": component_type.name if isinstance(component_type, ComponentType) else str(component_type),
            "session_id": session_id,
            "capture_time": datetime.now().isoformat(),
        }

        return snapshot

    def capture_service_snapshot(
        self,
        service_name: str,
        component_id: str,
        session_id: Optional[str] = None,
    ) -> Snapshot:
        """Capture complete state of a Windows service.

        Args:
            service_name: Name of the service
            component_id: ID of the component
            session_id: Optional session ID

        Returns:
            Snapshot with service configuration
        """
        state: dict[str, Any] = {
            "service_name": service_name,
        }

        if self._is_windows:
            # Get service configuration
            state["config"] = self._get_service_config(service_name)
            # Get service status
            state["status"] = self._get_service_status(service_name)
            # Get recovery options
            state["recovery"] = self._get_service_recovery(service_name)
            # Get dependencies
            state["dependencies"] = self._get_service_dependencies(service_name)

        return self.capture_snapshot(
            component_id=component_id,
            component_name=service_name,
            component_type=ComponentType.SERVICE,
            action=ActionType.DISABLE,
            state=state,
            session_id=session_id,
        )

    def capture_task_snapshot(
        self,
        task_path: str,
        component_id: str,
        session_id: Optional[str] = None,
    ) -> Snapshot:
        """Capture complete state of a scheduled task.

        Args:
            task_path: Path of the task
            component_id: ID of the component
            session_id: Optional session ID

        Returns:
            Snapshot with task definition
        """
        state: dict[str, Any] = {
            "task_path": task_path,
        }

        if self._is_windows:
            # Export task as XML
            state["task_xml"] = self._export_task_xml(task_path)
            # Get task info
            state["task_info"] = self._get_task_info(task_path)

        return self.capture_snapshot(
            component_id=component_id,
            component_name=task_path,
            component_type=ComponentType.TASK,
            action=ActionType.DISABLE,
            state=state,
            session_id=session_id,
        )

    def capture_startup_snapshot(
        self,
        entry_name: str,
        entry_type: str,
        registry_key: str,
        component_id: str,
        session_id: Optional[str] = None,
    ) -> Snapshot:
        """Capture complete state of a startup entry.

        Args:
            entry_name: Name of the startup entry
            entry_type: Type of entry (registry or folder)
            registry_key: Registry key path (if registry type)
            component_id: ID of the component
            session_id: Optional session ID

        Returns:
            Snapshot with startup entry state
        """
        state: dict[str, Any] = {
            "entry_name": entry_name,
            "entry_type": entry_type,
            "registry_key": registry_key,
        }

        if self._is_windows and entry_type == "registry":
            # Capture registry value
            state["registry_value"] = self._capture_registry_value(
                registry_key, entry_name
            )

        return self.capture_snapshot(
            component_id=component_id,
            component_name=entry_name,
            component_type=ComponentType.STARTUP,
            action=ActionType.DISABLE,
            state=state,
            session_id=session_id,
        )

    def capture_driver_snapshot(
        self,
        driver_name: str,
        component_id: str,
        session_id: Optional[str] = None,
    ) -> Snapshot:
        """Capture complete state of a driver.

        Args:
            driver_name: Name of the driver
            component_id: ID of the component
            session_id: Optional session ID

        Returns:
            Snapshot with driver configuration
        """
        state: dict[str, Any] = {
            "driver_name": driver_name,
        }

        if self._is_windows:
            # Get driver configuration
            state["config"] = self._get_driver_config(driver_name)
            # Get driver info
            state["info"] = self._get_driver_info(driver_name)

        return self.capture_snapshot(
            component_id=component_id,
            component_name=driver_name,
            component_type=ComponentType.DRIVER,
            action=ActionType.DISABLE,
            state=state,
            session_id=session_id,
        )

    def capture_firewall_snapshot(
        self,
        component_name: str,
        executables: list[str],
        component_id: str,
        session_id: Optional[str] = None,
    ) -> Snapshot:
        """Capture firewall rules state before containment.

        Args:
            component_name: Name of the component
            executables: List of executable paths
            component_id: ID of the component
            session_id: Optional session ID

        Returns:
            Snapshot with firewall rules state
        """
        state: dict[str, Any] = {
            "component_name": component_name,
            "executables": executables,
            "existing_rules": [],
        }

        if self._is_windows:
            for exe in executables:
                rules = self._get_firewall_rules_for_path(exe)
                state["existing_rules"].extend(rules)

        return self.capture_snapshot(
            component_id=component_id,
            component_name=component_name,
            component_type=ComponentType.PROGRAM,
            action=ActionType.CONTAIN,
            state=state,
            session_id=session_id,
        )

    def capture_acl_snapshot(
        self,
        paths: list[str],
        component_id: str,
        component_name: str,
        session_id: Optional[str] = None,
    ) -> Snapshot:
        """Capture ACL state for paths.

        Args:
            paths: List of file/folder paths
            component_id: ID of the component
            component_name: Name of the component
            session_id: Optional session ID

        Returns:
            Snapshot with ACL state
        """
        state: dict[str, Any] = {
            "paths": paths,
            "acls": {},
        }

        if self._is_windows:
            for path in paths:
                if Path(path).exists():
                    state["acls"][path] = self._capture_acl_state(path)

        return self.capture_snapshot(
            component_id=component_id,
            component_name=component_name,
            component_type=ComponentType.PROGRAM,
            action=ActionType.CONTAIN,
            state=state,
            session_id=session_id,
        )

    def save_snapshot(
        self,
        snapshot: Snapshot,
        component_name: str,
        component_type: ComponentType,
        session_id: Optional[str] = None,
    ) -> str:
        """Save a snapshot to disk.

        Args:
            snapshot: Snapshot to save
            component_name: Name of the component
            component_type: Type of the component
            session_id: ID of the current session

        Returns:
            Path to the saved snapshot file
        """
        # Create snapshot filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = "".join(c for c in component_name if c.isalnum() or c in "-_")[:50]
        filename = f"{timestamp}_{safe_name}_{snapshot.snapshot_id[:8]}.json"
        filepath = self.snapshots_dir / filename

        # Prepare data for serialization
        data = {
            "snapshot_id": snapshot.snapshot_id,
            "component_id": snapshot.component_id,
            "action": snapshot.action.value if isinstance(snapshot.action, ActionType) else str(snapshot.action),
            "timestamp": snapshot.timestamp.isoformat() if isinstance(snapshot.timestamp, datetime) else str(snapshot.timestamp),
            "captured_state": snapshot.captured_state,
        }

        # Save to file
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

        # Update index
        metadata = SnapshotMetadata(
            snapshot_id=snapshot.snapshot_id,
            component_id=snapshot.component_id,
            component_name=component_name,
            component_type=component_type.name if isinstance(component_type, ComponentType) else str(component_type),
            action=snapshot.action.value if isinstance(snapshot.action, ActionType) else str(snapshot.action),
            timestamp=snapshot.timestamp.isoformat() if isinstance(snapshot.timestamp, datetime) else str(snapshot.timestamp),
            session_id=session_id,
            file_path=str(filepath),
            size_bytes=filepath.stat().st_size,
        )
        self._index[snapshot.snapshot_id] = metadata
        self._save_index()

        # Cleanup old snapshots if needed
        self._cleanup_old_snapshots()

        logger.info(f"Saved snapshot: {snapshot.snapshot_id} to {filepath}")
        return str(filepath)

    def load_snapshot(self, snapshot_id: str) -> Optional[Snapshot]:
        """Load a snapshot from disk.

        Args:
            snapshot_id: ID of the snapshot to load

        Returns:
            Snapshot object or None if not found
        """
        metadata = self._index.get(snapshot_id)
        if not metadata or not metadata.file_path:
            logger.warning(f"Snapshot not found in index: {snapshot_id}")
            return None

        filepath = Path(metadata.file_path)
        if not filepath.exists():
            logger.warning(f"Snapshot file not found: {filepath}")
            return None

        try:
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)

            snapshot = Snapshot(
                component_id=data["component_id"],
                action=ActionType(data["action"]) if data["action"] in [a.value for a in ActionType] else ActionType.IGNORE,
                captured_state=data["captured_state"],
                snapshot_id=data["snapshot_id"],
                timestamp=datetime.fromisoformat(data["timestamp"]),
            )

            logger.debug(f"Loaded snapshot: {snapshot_id}")
            return snapshot

        except Exception as e:
            logger.error(f"Failed to load snapshot {snapshot_id}: {e}")
            return None

    def get_snapshot_metadata(self, snapshot_id: str) -> Optional[SnapshotMetadata]:
        """Get metadata for a snapshot.

        Args:
            snapshot_id: ID of the snapshot

        Returns:
            SnapshotMetadata or None if not found
        """
        return self._index.get(snapshot_id)

    def list_snapshots(
        self,
        session_id: Optional[str] = None,
        component_id: Optional[str] = None,
        component_type: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> list[SnapshotMetadata]:
        """List snapshots with optional filtering.

        Args:
            session_id: Filter by session ID
            component_id: Filter by component ID
            component_type: Filter by component type
            action: Filter by action type
            limit: Maximum number of results

        Returns:
            List of matching SnapshotMetadata objects
        """
        results: list[SnapshotMetadata] = []

        for metadata in self._index.values():
            if session_id and metadata.session_id != session_id:
                continue
            if component_id and metadata.component_id != component_id:
                continue
            if component_type and metadata.component_type != component_type:
                continue
            if action and metadata.action != action:
                continue

            results.append(metadata)

        # Sort by timestamp descending
        results.sort(key=lambda m: m.timestamp, reverse=True)

        return results[:limit]

    def delete_snapshot(self, snapshot_id: str) -> bool:
        """Delete a snapshot from disk and index.

        Args:
            snapshot_id: ID of the snapshot to delete

        Returns:
            True if deleted, False if not found
        """
        metadata = self._index.get(snapshot_id)
        if not metadata:
            return False

        # Delete file
        if metadata.file_path:
            filepath = Path(metadata.file_path)
            if filepath.exists():
                filepath.unlink()

        # Remove from index
        del self._index[snapshot_id]
        self._save_index()

        logger.info(f"Deleted snapshot: {snapshot_id}")
        return True

    def delete_session_snapshots(self, session_id: str) -> int:
        """Delete all snapshots for a session.

        Args:
            session_id: ID of the session

        Returns:
            Number of snapshots deleted
        """
        count = 0
        to_delete = [
            snapshot_id
            for snapshot_id, meta in self._index.items()
            if meta.session_id == session_id
        ]

        for snapshot_id in to_delete:
            if self.delete_snapshot(snapshot_id):
                count += 1

        return count

    def _cleanup_old_snapshots(self) -> None:
        """Clean up old snapshots based on retention policy."""
        cutoff = datetime.now() - timedelta(days=self.retention_days)

        to_delete: list[str] = []
        for snapshot_id, metadata in self._index.items():
            try:
                timestamp = datetime.fromisoformat(metadata.timestamp)
                if timestamp < cutoff:
                    to_delete.append(snapshot_id)
            except Exception:
                pass

        # Also check if we exceed max snapshots
        if len(self._index) > self.max_snapshots:
            # Get oldest snapshots
            sorted_snapshots = sorted(
                self._index.items(),
                key=lambda x: x[1].timestamp,
            )
            excess = len(self._index) - self.max_snapshots
            for snapshot_id, _ in sorted_snapshots[:excess]:
                if snapshot_id not in to_delete:
                    to_delete.append(snapshot_id)

        for snapshot_id in to_delete:
            self.delete_snapshot(snapshot_id)

        if to_delete:
            logger.info(f"Cleaned up {len(to_delete)} old snapshots")

    # Windows-specific capture methods
    def _get_service_config(self, service_name: str) -> dict[str, Any]:
        """Get service configuration from registry and sc command."""
        result = self._run_command(f'sc qc "{service_name}"')
        return {"sc_output": result.get("output", "")}

    def _get_service_status(self, service_name: str) -> dict[str, Any]:
        """Get service status."""
        result = self._run_powershell(
            f"Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue | "
            f"Select-Object Status, StartType, Name | ConvertTo-Json"
        )
        if result["success"] and result["output"]:
            try:
                return json.loads(result["output"])
            except json.JSONDecodeError:
                pass
        return {}

    def _get_service_recovery(self, service_name: str) -> dict[str, Any]:
        """Get service recovery options."""
        result = self._run_command(f'sc qfailure "{service_name}"')
        return {"recovery_output": result.get("output", "")}

    def _get_service_dependencies(self, service_name: str) -> list[str]:
        """Get service dependencies."""
        result = self._run_powershell(
            f"(Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue).DependentServices.Name"
        )
        if result["success"] and result["output"]:
            return result["output"].strip().split("\n")
        return []

    def _export_task_xml(self, task_path: str) -> str:
        """Export scheduled task as XML."""
        result = self._run_command(f'schtasks /Query /TN "{task_path}" /XML')
        return result.get("output", "")

    def _get_task_info(self, task_path: str) -> dict[str, Any]:
        """Get scheduled task information."""
        result = self._run_powershell(
            f"Get-ScheduledTask -TaskPath '\\' -TaskName '{Path(task_path).name}' "
            f"-ErrorAction SilentlyContinue | Select-Object State, TaskPath, TaskName | ConvertTo-Json"
        )
        if result["success"] and result["output"]:
            try:
                return json.loads(result["output"])
            except json.JSONDecodeError:
                pass
        return {}

    def _capture_registry_value(
        self, registry_key: str, value_name: str
    ) -> dict[str, Any]:
        """Capture a registry value."""
        result = self._run_powershell(
            f"$val = Get-ItemProperty -Path '{registry_key}' -Name '{value_name}' "
            f"-ErrorAction SilentlyContinue | Select-Object -ExpandProperty '{value_name}'; "
            f"$type = (Get-Item -Path '{registry_key}').GetValueKind('{value_name}'); "
            f"@{{Value = $val; Type = $type.ToString()}} | ConvertTo-Json"
        )
        if result["success"] and result["output"]:
            try:
                return json.loads(result["output"])
            except json.JSONDecodeError:
                pass
        return {"Value": None, "Type": "Unknown"}

    def _get_driver_config(self, driver_name: str) -> dict[str, Any]:
        """Get driver configuration."""
        result = self._run_command(f'sc qc "{driver_name}"')
        return {"sc_output": result.get("output", "")}

    def _get_driver_info(self, driver_name: str) -> dict[str, Any]:
        """Get driver information."""
        result = self._run_powershell(
            f"Get-WmiObject Win32_SystemDriver -Filter \"Name='{driver_name}'\" "
            f"| Select-Object Name, State, StartMode, PathName | ConvertTo-Json"
        )
        if result["success"] and result["output"]:
            try:
                return json.loads(result["output"])
            except json.JSONDecodeError:
                pass
        return {}

    def _get_firewall_rules_for_path(self, exe_path: str) -> list[dict[str, Any]]:
        """Get firewall rules for a specific executable path."""
        result = self._run_powershell(
            f"Get-NetFirewallApplicationFilter | "
            f"Where-Object {{ $_.Program -eq '{exe_path}' }} | "
            f"ForEach-Object {{ Get-NetFirewallRule -AssociatedNetFirewallApplicationFilter $_ }} | "
            f"Select-Object Name, DisplayName, Direction, Action, Enabled | ConvertTo-Json"
        )
        if result["success"] and result["output"]:
            try:
                data = json.loads(result["output"])
                if isinstance(data, dict):
                    return [data]
                return data
            except json.JSONDecodeError:
                pass
        return []

    def _capture_acl_state(self, path: str) -> dict[str, Any]:
        """Capture ACL state for a path."""
        result = self._run_powershell(
            f"$acl = Get-Acl -Path '{path}' -ErrorAction SilentlyContinue; "
            f"@{{ Owner = $acl.Owner; Access = ($acl.Access | ConvertTo-Json -Compress) }} | ConvertTo-Json"
        )
        if result["success"] and result["output"]:
            try:
                return json.loads(result["output"])
            except json.JSONDecodeError:
                pass
        return {}

    def _run_powershell(self, command: str) -> dict[str, Any]:
        """Run a PowerShell command."""
        if not self._is_windows:
            return {"success": False, "output": "", "error": "Not Windows"}

        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                timeout=60,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
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
                timeout=60,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
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


def create_snapshot_manager(config: Optional[Config] = None) -> SnapshotManager:
    """Create a snapshot manager with default or provided configuration.

    Args:
        config: Optional configuration object

    Returns:
        SnapshotManager instance
    """
    return SnapshotManager(config=config)
