"""Core module - orchestration, models, and infrastructure."""

from .models import (
    ComponentType,
    Classification,
    RiskLevel,
    ActionType,
    ExecutionMode,
    Component,
    ClassificationResult,
    ActionPlan,
    ActionResult,
    Snapshot,
    Session,
)
from .config import Config, load_config
from .logging_config import setup_logging
from .snapshot import SnapshotManager, SnapshotMetadata, create_snapshot_manager
from .session import SessionManager, SessionSummary, ActionSummary, create_session_manager
from .rollback import RollbackManager, RollbackResult, SessionRollbackResult, create_rollback_manager
from .restore import SystemRestoreManager, RestorePoint, create_system_restore_manager
from .recovery import RecoveryMode, RecoveryStatus, RecoveryResult, create_recovery_mode

__all__ = [
    # Models
    "ComponentType",
    "Classification",
    "RiskLevel",
    "ActionType",
    "ExecutionMode",
    "Component",
    "ClassificationResult",
    "ActionPlan",
    "ActionResult",
    "Snapshot",
    "Session",
    # Config
    "Config",
    "load_config",
    "setup_logging",
    # Snapshot Management (Phase 9)
    "SnapshotManager",
    "SnapshotMetadata",
    "create_snapshot_manager",
    # Session Management (Phase 9)
    "SessionManager",
    "SessionSummary",
    "ActionSummary",
    "create_session_manager",
    # Rollback Management (Phase 9)
    "RollbackManager",
    "RollbackResult",
    "SessionRollbackResult",
    "create_rollback_manager",
    # System Restore (Phase 9)
    "SystemRestoreManager",
    "RestorePoint",
    "create_system_restore_manager",
    # Recovery Mode (Phase 9)
    "RecoveryMode",
    "RecoveryStatus",
    "RecoveryResult",
    "create_recovery_mode",
]
