"""Core data models for Debloatr.

This module defines all enums, data classes, and type definitions used
throughout the application.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any
from uuid import uuid4


class ComponentType(Enum):
    """Types of system components that can be discovered."""

    PROGRAM = auto()
    SERVICE = auto()
    TASK = auto()
    STARTUP = auto()
    DRIVER = auto()
    UWP = auto()
    TELEMETRY = auto()


class Classification(Enum):
    """Classification levels for discovered components.

    Levels:
        CORE: Required for OS or hardware function (locked, no action)
        ESSENTIAL: User-facing critical functionality (warn before action)
        OPTIONAL: Legitimate but nonessential (user choice)
        BLOAT: Safe to disable/remove (recommend disable)
        AGGRESSIVE: Actively harmful to UX/privacy (recommend remove)
        UNKNOWN: Insufficient data for classification (manual review)
    """

    CORE = "CORE"
    ESSENTIAL = "ESSENTIAL"
    OPTIONAL = "OPTIONAL"
    BLOAT = "BLOAT"
    AGGRESSIVE = "AGGRESSIVE"
    UNKNOWN = "UNKNOWN"


class RiskLevel(Enum):
    """Risk levels for component modification.

    Levels:
        NONE: No dependencies, isolated component
        LOW: Optional feature, easily restored
        MEDIUM: Has dependents, available via reinstall
        HIGH: System feature, complex restoration
        CRITICAL: Boot/security/hardware required (locked)
    """

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __lt__(self, other: "RiskLevel") -> bool:
        if isinstance(other, RiskLevel):
            return self.value < other.value
        return NotImplemented

    def __le__(self, other: "RiskLevel") -> bool:
        if isinstance(other, RiskLevel):
            return self.value <= other.value
        return NotImplemented

    def __gt__(self, other: "RiskLevel") -> bool:
        if isinstance(other, RiskLevel):
            return self.value > other.value
        return NotImplemented

    def __ge__(self, other: "RiskLevel") -> bool:
        if isinstance(other, RiskLevel):
            return self.value >= other.value
        return NotImplemented


class ActionType(Enum):
    """Types of actions that can be performed on components.

    Actions:
        DISABLE: Stop service/task/startup; prevent auto-start (fully reversible)
        CONTAIN: Firewall block, ACL deny, execution prevention (fully reversible)
        REMOVE: Uninstall via native method or delete files (partially reversible)
        REPLACE: Swap component with lightweight alternative (fully reversible)
        IGNORE: Mark reviewed, take no action
    """

    DISABLE = "DISABLE"
    CONTAIN = "CONTAIN"
    REMOVE = "REMOVE"
    REPLACE = "REPLACE"
    IGNORE = "IGNORE"


class ExecutionMode(Enum):
    """Execution modes for the action engine.

    Modes:
        SCAN_ONLY: Discovery and classification only (no mutations)
        DRY_RUN: Generate action plan, no execution (no mutations)
        INTERACTIVE: Prompt before each action (per-approval mutations)
        BATCH_CONFIRM: Confirm batch, execute all (mutations after approval)
    """

    SCAN_ONLY = "SCAN_ONLY"
    DRY_RUN = "DRY_RUN"
    INTERACTIVE = "INTERACTIVE"
    BATCH_CONFIRM = "BATCH_CONFIRM"


class ReinstallBehavior(Enum):
    """How a component behaves after removal."""

    NONE = "none"  # Stays removed
    SELF_HEALING = "self_healing"  # Reinstalls itself
    UPDATE_RESTORED = "update_restored"  # Restored by updates


@dataclass
class Component:
    """Base class for all discovered system components.

    Attributes:
        id: Unique identifier (UUID)
        component_type: Type of component (program, service, etc.)
        name: Internal/system name
        display_name: Human-readable name
        publisher: Publisher/vendor name
        install_path: Installation directory or file path
        classification: Bloatware classification level
        risk_level: Risk level for modification
        metadata: Additional component-specific data
        discovered_at: Timestamp when component was discovered
    """

    component_type: ComponentType
    name: str
    display_name: str
    publisher: str
    install_path: Path | None = None
    classification: Classification = Classification.UNKNOWN
    risk_level: RiskLevel = RiskLevel.NONE
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid4()))
    discovered_at: datetime = field(default_factory=datetime.now)

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Component):
            return self.id == other.id
        return False


@dataclass
class ClassificationResult:
    """Result of classifying a component.

    Attributes:
        classification: The determined classification
        source: How classification was determined (signature/heuristic/llm/none)
        signature_id: ID of matching signature (if signature-based)
        confidence: Confidence score (0.0-1.0)
        explanation: Human-readable explanation
        heuristic_flags: List of triggered heuristic flags
    """

    classification: Classification
    source: str  # "signature", "heuristic", "llm", "none"
    confidence: float = 0.0
    signature_id: str | None = None
    explanation: str | None = None
    heuristic_flags: list[str] = field(default_factory=list)


@dataclass
class ActionPlan:
    """Plan for executing an action on a component.

    Attributes:
        plan_id: Unique identifier for this plan
        component: The target component
        action: The action to perform
        steps: Ordered list of execution steps
        requires_admin: Whether admin privileges are required
        requires_reboot: Whether a reboot is required
        estimated_risk: Risk assessment for this action
        warnings: List of warnings for the user
        created_at: Timestamp when plan was created
    """

    component: Component
    action: ActionType
    steps: list[str] = field(default_factory=list)
    requires_admin: bool = False
    requires_reboot: bool = False
    estimated_risk: RiskLevel = RiskLevel.NONE
    warnings: list[str] = field(default_factory=list)
    plan_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class ActionResult:
    """Result of executing an action.

    Attributes:
        plan_id: ID of the executed plan
        success: Whether the action succeeded
        action: The action that was performed
        component_id: ID of the affected component
        snapshot_id: ID of the pre-action snapshot (for rollback)
        error_message: Error message if action failed
        executed_at: Timestamp when action was executed
        rollback_available: Whether this action can be rolled back
    """

    plan_id: str
    success: bool
    action: ActionType
    component_id: str
    snapshot_id: str | None = None
    error_message: str | None = None
    executed_at: datetime = field(default_factory=datetime.now)
    rollback_available: bool = True


@dataclass
class Snapshot:
    """Snapshot of component state before modification.

    Attributes:
        snapshot_id: Unique identifier
        timestamp: When snapshot was taken
        component_id: ID of the component
        action: Action that triggered the snapshot
        captured_state: Dictionary containing all captured state
    """

    component_id: str
    action: ActionType
    captured_state: dict[str, Any]
    snapshot_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class Session:
    """A debloat session containing multiple actions.

    Attributes:
        session_id: Unique identifier
        started_at: Session start timestamp
        ended_at: Session end timestamp (None if active)
        actions: List of action results in this session
        restore_point_id: Windows System Restore point ID
        description: User-provided session description
    """

    actions: list[ActionResult] = field(default_factory=list)
    restore_point_id: str | None = None
    description: str = ""
    session_id: str = field(default_factory=lambda: str(uuid4()))
    started_at: datetime = field(default_factory=datetime.now)
    ended_at: datetime | None = None

    @property
    def is_active(self) -> bool:
        """Check if session is still active."""
        return self.ended_at is None

    def end_session(self) -> None:
        """Mark session as ended."""
        self.ended_at = datetime.now()


@dataclass
class SignatureMatchRule:
    """Rules for matching a component to a signature.

    Attributes:
        name_pattern: Regex pattern for component name
        publisher_pattern: Regex pattern for publisher
        path_pattern: Regex pattern for install path
        hash_sha256: List of SHA256 hashes to match
    """

    name_pattern: str | None = None
    publisher_pattern: str | None = None
    path_pattern: str | None = None
    hash_sha256: list[str] = field(default_factory=list)


@dataclass
class Signature:
    """A bloatware signature for deterministic classification.

    Attributes:
        signature_id: Unique identifier
        publisher: Publisher name
        component_name: Component name
        component_type: Type of component
        match_rules: Rules for matching components
        classification: Classification to assign
        related_components: IDs of related signatures
        safe_actions: Actions that are safe to perform
        unsafe_actions: Actions that may cause issues
        reinstall_behavior: How component behaves after removal
        breakage_notes: Notes about potential breakage
        evidence_url: URL with evidence for classification
        last_updated: When signature was last updated
    """

    signature_id: str
    publisher: str
    component_name: str
    component_type: ComponentType
    match_rules: SignatureMatchRule
    classification: Classification
    related_components: list[str] = field(default_factory=list)
    safe_actions: list[ActionType] = field(default_factory=list)
    unsafe_actions: list[ActionType] = field(default_factory=list)
    reinstall_behavior: ReinstallBehavior = ReinstallBehavior.NONE
    breakage_notes: str = ""
    evidence_url: str = ""
    last_updated: datetime = field(default_factory=datetime.now)
