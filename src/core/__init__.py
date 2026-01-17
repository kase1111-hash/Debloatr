"""Core module - orchestration, models, and infrastructure."""

from .config import Config, load_config
from .logging_config import setup_logging
from .models import (
    ActionPlan,
    ActionResult,
    ActionType,
    Classification,
    ClassificationResult,
    Component,
    ComponentType,
    ExecutionMode,
    RiskLevel,
    Session,
    Snapshot,
)
from .recovery import RecoveryMode, RecoveryResult, RecoveryStatus, create_recovery_mode
from .restore import RestorePoint, SystemRestoreManager, create_system_restore_manager
from .rollback import (
    RollbackManager,
    RollbackResult,
    SessionRollbackResult,
    create_rollback_manager,
)
from .session import ActionSummary, SessionManager, SessionSummary, create_session_manager
from .snapshot import SnapshotManager, SnapshotMetadata, create_snapshot_manager

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
