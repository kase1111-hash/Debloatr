"""Tests for Phase 9: Rollback & Recovery System."""

import json
import pytest
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.core.models import (
    Component,
    ComponentType,
    ActionType,
    ActionResult,
    Snapshot,
    Session,
    Classification,
)
from src.core.config import Config
from src.core.snapshot import SnapshotManager, SnapshotMetadata, create_snapshot_manager
from src.core.session import SessionManager, SessionSummary, ActionSummary, create_session_manager
from src.core.rollback import RollbackManager, RollbackResult, SessionRollbackResult, create_rollback_manager
from src.core.restore import SystemRestoreManager, RestorePoint, create_system_restore_manager
from src.core.recovery import RecoveryMode, RecoveryStatus, RecoveryResult, create_recovery_mode


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def test_config(temp_dir):
    """Create a test configuration."""
    config = Config()
    config.config_dir = temp_dir
    config.snapshots_dir = temp_dir / "snapshots"
    config.logs_dir = temp_dir / "logs"
    config.quarantine_dir = temp_dir / "quarantine"
    config.ensure_directories()
    return config


@pytest.fixture
def sample_component():
    """Create a sample component."""
    return Component(
        component_type=ComponentType.SERVICE,
        name="TestService",
        display_name="Test Service",
        publisher="Test Publisher",
        classification=Classification.BLOAT,
    )


@pytest.fixture
def sample_snapshot(sample_component):
    """Create a sample snapshot."""
    return Snapshot(
        component_id=sample_component.id,
        action=ActionType.DISABLE,
        captured_state={
            "service_name": "TestService",
            "status": {"Status": "Running", "StartType": "Automatic"},
            "_meta": {
                "component_name": "TestService",
                "component_type": "SERVICE",
            },
        },
    )


@pytest.fixture
def sample_action_result(sample_component, sample_snapshot):
    """Create a sample action result."""
    return ActionResult(
        plan_id="test-plan-001",
        success=True,
        action=ActionType.DISABLE,
        component_id=sample_component.id,
        snapshot_id=sample_snapshot.snapshot_id,
        rollback_available=True,
    )


# ============================================================================
# SnapshotManager Tests
# ============================================================================

class TestSnapshotManager:
    """Tests for SnapshotManager."""

    def test_create_snapshot_manager(self, test_config):
        """Test creating a snapshot manager."""
        manager = create_snapshot_manager(test_config)
        assert manager is not None
        assert manager.snapshots_dir.exists()

    def test_capture_snapshot(self, test_config, sample_component):
        """Test capturing a snapshot."""
        manager = SnapshotManager(config=test_config)

        snapshot = manager.capture_snapshot(
            component_id=sample_component.id,
            component_name="TestService",
            component_type=ComponentType.SERVICE,
            action=ActionType.DISABLE,
            state={"status": "running"},
        )

        assert snapshot is not None
        assert snapshot.component_id == sample_component.id
        assert snapshot.action == ActionType.DISABLE
        assert "status" in snapshot.captured_state
        assert "_meta" in snapshot.captured_state

    def test_save_and_load_snapshot(self, test_config, sample_component):
        """Test saving and loading a snapshot."""
        manager = SnapshotManager(config=test_config)

        # Capture and save
        snapshot = manager.capture_snapshot(
            component_id=sample_component.id,
            component_name="TestService",
            component_type=ComponentType.SERVICE,
            action=ActionType.DISABLE,
            state={"status": "running", "start_type": "auto"},
        )

        filepath = manager.save_snapshot(
            snapshot,
            component_name="TestService",
            component_type=ComponentType.SERVICE,
        )

        assert Path(filepath).exists()

        # Load
        loaded = manager.load_snapshot(snapshot.snapshot_id)
        assert loaded is not None
        assert loaded.snapshot_id == snapshot.snapshot_id
        assert loaded.component_id == sample_component.id
        assert "status" in loaded.captured_state

    def test_list_snapshots(self, test_config, sample_component):
        """Test listing snapshots."""
        manager = SnapshotManager(config=test_config)

        # Create multiple snapshots
        for i in range(3):
            snapshot = manager.capture_snapshot(
                component_id=f"component-{i}",
                component_name=f"Component{i}",
                component_type=ComponentType.SERVICE,
                action=ActionType.DISABLE,
                state={"index": i},
            )
            manager.save_snapshot(
                snapshot,
                component_name=f"Component{i}",
                component_type=ComponentType.SERVICE,
            )

        # List all
        snapshots = manager.list_snapshots()
        assert len(snapshots) == 3

        # Filter by action
        snapshots = manager.list_snapshots(action="DISABLE")
        assert len(snapshots) == 3

    def test_delete_snapshot(self, test_config, sample_component):
        """Test deleting a snapshot."""
        manager = SnapshotManager(config=test_config)

        snapshot = manager.capture_snapshot(
            component_id=sample_component.id,
            component_name="TestService",
            component_type=ComponentType.SERVICE,
            action=ActionType.DISABLE,
            state={"status": "running"},
        )
        manager.save_snapshot(
            snapshot,
            component_name="TestService",
            component_type=ComponentType.SERVICE,
        )

        # Verify it exists
        assert manager.get_snapshot_metadata(snapshot.snapshot_id) is not None

        # Delete
        result = manager.delete_snapshot(snapshot.snapshot_id)
        assert result is True

        # Verify it's gone
        assert manager.get_snapshot_metadata(snapshot.snapshot_id) is None


# ============================================================================
# SessionManager Tests
# ============================================================================

class TestSessionManager:
    """Tests for SessionManager."""

    def test_create_session_manager(self, test_config):
        """Test creating a session manager."""
        manager = create_session_manager(test_config)
        assert manager is not None
        assert manager.sessions_dir.exists()

    def test_create_session(self, test_config):
        """Test creating a session."""
        manager = SessionManager(config=test_config)

        session = manager.create_session("Test debloat session")

        assert session is not None
        assert session.description == "Test debloat session"
        assert session.is_active is True
        assert len(session.actions) == 0

    def test_add_action_to_session(self, test_config, sample_action_result):
        """Test adding an action to a session."""
        manager = SessionManager(config=test_config)

        session = manager.create_session("Test session")
        result = manager.add_action(
            session.session_id,
            sample_action_result,
            "TestService",
        )

        assert result is True

        # Verify action was added
        actions = manager.get_session_actions(session.session_id)
        assert len(actions) == 1
        assert actions[0].component_name == "TestService"

    def test_end_session(self, test_config):
        """Test ending a session."""
        manager = SessionManager(config=test_config)

        session = manager.create_session("Test session")
        assert session.is_active is True

        ended = manager.end_session(session.session_id)

        assert ended is not None
        assert ended.is_active is False
        assert ended.ended_at is not None

    def test_list_sessions(self, test_config):
        """Test listing sessions."""
        manager = SessionManager(config=test_config)

        # Create multiple sessions
        for i in range(3):
            session = manager.create_session(f"Session {i}")
            if i < 2:  # End first 2
                manager.end_session(session.session_id)

        # List all
        sessions = manager.list_sessions()
        assert len(sessions) == 3

        # List only active
        active = manager.list_sessions(include_ended=False)
        assert len(active) == 1

        # List only ended
        ended = manager.list_sessions(include_active=False)
        assert len(ended) == 2

    def test_get_rollbackable_actions(self, test_config, sample_action_result):
        """Test getting rollbackable actions."""
        manager = SessionManager(config=test_config)

        session = manager.create_session("Test session")

        # Add successful, rollbackable action
        manager.add_action(session.session_id, sample_action_result, "Service1")

        # Add failed action
        failed_action = ActionResult(
            plan_id="failed-001",
            success=False,
            action=ActionType.DISABLE,
            component_id="comp-2",
            rollback_available=False,
        )
        manager.add_action(session.session_id, failed_action, "Service2")

        # Get rollbackable
        rollbackable = manager.get_rollbackable_actions(session.session_id)
        assert len(rollbackable) == 1
        assert rollbackable[0].component_name == "Service1"

    def test_session_persistence(self, test_config, sample_action_result):
        """Test that sessions persist across manager instances."""
        # Create session with first manager
        manager1 = SessionManager(config=test_config)
        session = manager1.create_session("Persistent session")
        manager1.add_action(session.session_id, sample_action_result, "TestService")
        manager1.end_session(session.session_id)

        # Load with new manager
        manager2 = SessionManager(config=test_config)
        loaded = manager2.get_session(session.session_id)

        assert loaded is not None
        assert loaded.description == "Persistent session"
        assert len(loaded.actions) == 1


# ============================================================================
# RollbackManager Tests
# ============================================================================

class TestRollbackManager:
    """Tests for RollbackManager."""

    def test_create_rollback_manager(self, test_config):
        """Test creating a rollback manager."""
        manager = create_rollback_manager(test_config)
        assert manager is not None

    def test_rollback_dry_run(self, test_config, sample_action_result, sample_snapshot):
        """Test rollback in dry-run mode."""
        manager = RollbackManager(config=test_config, dry_run=True)

        result = manager.rollback_action(
            sample_action_result,
            sample_snapshot,
            component_name="TestService",
        )

        assert result is not None
        assert result.success is True
        assert result.original_action == "DISABLE"

    def test_rollback_without_snapshot(self, test_config, sample_action_result):
        """Test rollback fails without snapshot."""
        manager = RollbackManager(config=test_config)

        # Action without valid snapshot_id
        action = ActionResult(
            plan_id="test-001",
            success=True,
            action=ActionType.DISABLE,
            component_id="comp-1",
            snapshot_id=None,
            rollback_available=False,
        )

        result = manager.rollback_action(action, component_name="TestService")

        assert result.success is False
        assert "Snapshot not found" in result.error_message

    @patch('src.core.rollback.RollbackManager._run_powershell')
    def test_rollback_service_disable(self, mock_ps, test_config):
        """Test rolling back a disabled service."""
        mock_ps.return_value = {"success": True, "output": "", "error": ""}

        manager = RollbackManager(config=test_config)
        manager._is_windows = True

        snapshot = Snapshot(
            component_id="comp-1",
            action=ActionType.DISABLE,
            captured_state={
                "service_name": "TestService",
                "status": {"Status": "Running", "StartType": "Automatic"},
                "_meta": {"component_type": "SERVICE"},
            },
        )

        action = ActionResult(
            plan_id="test-001",
            success=True,
            action=ActionType.DISABLE,
            component_id="comp-1",
            snapshot_id=snapshot.snapshot_id,
            rollback_available=True,
        )

        result = manager.rollback_action(action, snapshot, "TestService")

        assert result.success is True
        assert mock_ps.called

    def test_rollback_session_dry_run(self, test_config, sample_action_result, sample_snapshot):
        """Test rolling back a session in dry-run mode."""
        # Set up session with action
        snapshot_manager = SnapshotManager(config=test_config)
        snapshot_manager.save_snapshot(
            sample_snapshot,
            component_name="TestService",
            component_type=ComponentType.SERVICE,
        )

        session_manager = SessionManager(config=test_config)
        session = session_manager.create_session("Test session")
        session_manager.add_action(
            session.session_id,
            sample_action_result,
            "TestService",
        )
        session_manager.end_session(session.session_id)

        # Rollback
        rollback_manager = RollbackManager(
            config=test_config,
            snapshot_manager=snapshot_manager,
            session_manager=session_manager,
            dry_run=True,
        )

        result = rollback_manager.rollback_session(session.session_id)

        assert result is not None
        assert result.session_id == session.session_id


# ============================================================================
# SystemRestoreManager Tests
# ============================================================================

class TestSystemRestoreManager:
    """Tests for SystemRestoreManager."""

    def test_create_system_restore_manager(self):
        """Test creating a system restore manager."""
        manager = create_system_restore_manager()
        assert manager is not None

    def test_create_restore_point_dry_run(self):
        """Test creating a restore point in dry-run mode."""
        manager = SystemRestoreManager(dry_run=True)

        result = manager.create_restore_point("Test restore point")

        # In dry run, returns 0
        assert result == 0

    @patch('src.core.restore.SystemRestoreManager._run_powershell')
    def test_list_restore_points(self, mock_ps):
        """Test listing restore points."""
        mock_ps.return_value = {
            "success": True,
            "output": json.dumps([
                {
                    "SequenceNumber": 1,
                    "Description": "Test Point",
                    "CreationTime": "/Date(1704067200000)/",
                    "RestorePointType": 12,
                    "EventType": 102,
                }
            ]),
            "error": "",
        }

        manager = SystemRestoreManager()
        manager._is_windows = True

        points = manager.list_restore_points()

        # Should parse the mock response
        assert isinstance(points, list)


# ============================================================================
# RecoveryMode Tests
# ============================================================================

class TestRecoveryMode:
    """Tests for RecoveryMode."""

    def test_create_recovery_mode(self, test_config):
        """Test creating recovery mode."""
        recovery = create_recovery_mode(test_config)
        assert recovery is not None

    def test_get_status_no_sessions(self, test_config):
        """Test getting status with no sessions."""
        recovery = RecoveryMode(config=test_config)

        status = recovery.get_status()

        assert status is not None
        assert status.has_sessions is False
        assert status.rollbackable_actions == 0

    def test_get_status_with_session(self, test_config, sample_action_result):
        """Test getting status with a session."""
        # Create a session
        session_manager = SessionManager(config=test_config)
        session = session_manager.create_session("Test session")
        session_manager.add_action(
            session.session_id,
            sample_action_result,
            "TestService",
        )

        recovery = RecoveryMode(config=test_config)
        status = recovery.get_status()

        assert status.has_sessions is True
        assert status.last_session_id == session.session_id
        assert status.rollbackable_actions == 1

    def test_list_recovery_options(self, test_config, sample_action_result, sample_snapshot):
        """Test listing recovery options."""
        # Set up session
        snapshot_manager = SnapshotManager(config=test_config)
        snapshot_manager.save_snapshot(
            sample_snapshot,
            component_name="TestService",
            component_type=ComponentType.SERVICE,
        )

        session_manager = SessionManager(config=test_config)
        session = session_manager.create_session("Test session")
        session_manager.add_action(
            session.session_id,
            sample_action_result,
            "TestService",
        )

        recovery = RecoveryMode(config=test_config)
        options = recovery.list_recovery_options()

        assert "sessions" in options
        assert "restore_points" in options
        assert "recommendations" in options
        assert len(options["sessions"]) >= 1

    def test_rollback_last_session_dry_run(self, test_config, sample_action_result, sample_snapshot):
        """Test rolling back last session in dry-run mode."""
        # Set up session
        snapshot_manager = SnapshotManager(config=test_config)
        snapshot_manager.save_snapshot(
            sample_snapshot,
            component_name="TestService",
            component_type=ComponentType.SERVICE,
        )

        session_manager = SessionManager(config=test_config)
        session = session_manager.create_session("Test session")
        session_manager.add_action(
            session.session_id,
            sample_action_result,
            "TestService",
        )
        session_manager.end_session(session.session_id)

        recovery = RecoveryMode(config=test_config, dry_run=True)
        result = recovery.rollback_last_session()

        assert result is not None
        assert result.method == "session_rollback"

    def test_create_recovery_script(self, test_config):
        """Test creating a recovery script."""
        recovery = RecoveryMode(config=test_config)

        script_path = recovery.create_recovery_script()

        assert script_path.exists()
        content = script_path.read_text()
        assert "Debloatr Recovery Script" in content


# ============================================================================
# Integration Tests
# ============================================================================

class TestRollbackIntegration:
    """Integration tests for the rollback system."""

    def test_full_rollback_workflow_dry_run(self, test_config, sample_component):
        """Test complete rollback workflow in dry-run mode."""
        # 1. Create managers
        snapshot_manager = SnapshotManager(config=test_config)
        session_manager = SessionManager(config=test_config)
        rollback_manager = RollbackManager(
            config=test_config,
            snapshot_manager=snapshot_manager,
            session_manager=session_manager,
            dry_run=True,
        )

        # 2. Capture snapshot
        snapshot = snapshot_manager.capture_snapshot(
            component_id=sample_component.id,
            component_name="TestService",
            component_type=ComponentType.SERVICE,
            action=ActionType.DISABLE,
            state={
                "service_name": "TestService",
                "status": {"Status": "Running", "StartType": "Automatic"},
            },
        )
        snapshot_manager.save_snapshot(
            snapshot,
            component_name="TestService",
            component_type=ComponentType.SERVICE,
        )

        # 3. Create session and add action
        session = session_manager.create_session("Integration test session")
        action_result = ActionResult(
            plan_id="integration-001",
            success=True,
            action=ActionType.DISABLE,
            component_id=sample_component.id,
            snapshot_id=snapshot.snapshot_id,
            rollback_available=True,
        )
        session_manager.add_action(
            session.session_id,
            action_result,
            "TestService",
        )
        session_manager.end_session(session.session_id)

        # 4. Rollback session
        result = rollback_manager.rollback_session(session.session_id)

        # 5. Verify
        assert result is not None
        assert result.total_actions == 1
        assert result.successful_rollbacks == 1

    def test_recovery_mode_integration(self, test_config, sample_component):
        """Test recovery mode with full workflow."""
        # Set up session with action
        snapshot_manager = SnapshotManager(config=test_config)
        session_manager = SessionManager(config=test_config)

        snapshot = snapshot_manager.capture_snapshot(
            component_id=sample_component.id,
            component_name="TestService",
            component_type=ComponentType.SERVICE,
            action=ActionType.DISABLE,
            state={"service_name": "TestService"},
        )
        snapshot_manager.save_snapshot(
            snapshot,
            component_name="TestService",
            component_type=ComponentType.SERVICE,
        )

        session = session_manager.create_session("Recovery test")
        action_result = ActionResult(
            plan_id="recovery-001",
            success=True,
            action=ActionType.DISABLE,
            component_id=sample_component.id,
            snapshot_id=snapshot.snapshot_id,
            rollback_available=True,
        )
        session_manager.add_action(
            session.session_id,
            action_result,
            "TestService",
        )
        session_manager.end_session(session.session_id)

        # Test recovery mode
        recovery = RecoveryMode(config=test_config, dry_run=True)

        # Check status
        status = recovery.get_status()
        assert status.recovery_available is True
        assert status.rollbackable_actions == 1

        # Get options
        options = recovery.list_recovery_options()
        assert len(options["sessions"]) >= 1
        assert len(options["recommendations"]) >= 1

        # Perform recovery
        result = recovery.rollback_last_session()
        assert result.method == "session_rollback"
