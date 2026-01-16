"""Session Manager - Manages debloat sessions and persistence.

This module provides the SessionManager class for creating, tracking,
and persisting debloat sessions with their associated actions.
"""

import json
import os
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
import logging

from src.core.models import (
    Session,
    ActionResult,
    ActionType,
)
from src.core.config import Config, get_default_config

logger = logging.getLogger("debloatr.core.session")


@dataclass
class SessionSummary:
    """Summary information about a session.

    Attributes:
        session_id: Unique identifier
        description: User-provided description
        started_at: Start timestamp
        ended_at: End timestamp (None if active)
        total_actions: Total number of actions
        successful_actions: Number of successful actions
        failed_actions: Number of failed actions
        restore_point_id: Windows System Restore point ID
        is_active: Whether session is still active
    """

    session_id: str
    description: str
    started_at: str
    ended_at: Optional[str]
    total_actions: int
    successful_actions: int
    failed_actions: int
    restore_point_id: Optional[str]
    is_active: bool


@dataclass
class ActionSummary:
    """Summary information about an action.

    Attributes:
        plan_id: ID of the executed plan
        action: Action that was performed
        component_id: ID of the affected component
        component_name: Name of the component
        success: Whether the action succeeded
        snapshot_id: ID of the pre-action snapshot
        executed_at: Timestamp when action was executed
        rollback_available: Whether this action can be rolled back
        error_message: Error message if failed
    """

    plan_id: str
    action: str
    component_id: str
    component_name: str
    success: bool
    snapshot_id: Optional[str]
    executed_at: str
    rollback_available: bool
    error_message: Optional[str] = None


class SessionManager:
    """Manager for debloat sessions.

    Provides methods to create, track, and persist sessions with
    their associated actions. Sessions are stored as JSON files
    for persistence across application restarts.

    Example:
        manager = SessionManager()
        session = manager.create_session("Remove bloatware")

        # Perform actions...
        manager.add_action(session.session_id, action_result, "Component Name")

        # End session
        manager.end_session(session.session_id)

        # Later, list sessions
        sessions = manager.list_sessions()
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        sessions_dir: Optional[Path] = None,
        max_sessions: int = 50,
    ) -> None:
        """Initialize the session manager.

        Args:
            config: Configuration object
            sessions_dir: Override directory for sessions
            max_sessions: Maximum number of sessions to keep
        """
        self.config = config or get_default_config()
        self.sessions_dir = sessions_dir or self.config.snapshots_dir / "sessions"
        self.max_sessions = max_sessions

        # Ensure sessions directory exists
        self.sessions_dir.mkdir(parents=True, exist_ok=True)

        # Index file for quick lookup
        self._index_file = self.sessions_dir / "session_index.json"
        self._index: dict[str, SessionSummary] = {}
        self._active_sessions: dict[str, Session] = {}
        self._action_names: dict[str, dict[str, str]] = {}  # session_id -> {component_id -> name}
        self._load_index()

    def _load_index(self) -> None:
        """Load session index from disk."""
        if self._index_file.exists():
            try:
                with open(self._index_file, encoding="utf-8") as f:
                    data = json.load(f)
                    for session_id, summary in data.items():
                        self._index[session_id] = SessionSummary(**summary)
            except Exception as e:
                logger.warning(f"Failed to load session index: {e}")
                self._index = {}

    def _save_index(self) -> None:
        """Save session index to disk."""
        try:
            data = {
                session_id: asdict(summary)
                for session_id, summary in self._index.items()
            }
            with open(self._index_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save session index: {e}")

    def create_session(
        self,
        description: str = "",
        restore_point_id: Optional[str] = None,
    ) -> Session:
        """Create a new session.

        Args:
            description: User-provided session description
            restore_point_id: Windows System Restore point ID

        Returns:
            New Session object
        """
        session = Session(
            description=description,
            restore_point_id=restore_point_id,
        )

        # Store in active sessions
        self._active_sessions[session.session_id] = session
        self._action_names[session.session_id] = {}

        # Add to index
        summary = SessionSummary(
            session_id=session.session_id,
            description=description,
            started_at=session.started_at.isoformat(),
            ended_at=None,
            total_actions=0,
            successful_actions=0,
            failed_actions=0,
            restore_point_id=restore_point_id,
            is_active=True,
        )
        self._index[session.session_id] = summary
        self._save_index()

        # Save session file
        self._save_session(session)

        logger.info(f"Created session: {session.session_id} - {description}")
        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID.

        Args:
            session_id: ID of the session

        Returns:
            Session object or None if not found
        """
        # Check active sessions first
        if session_id in self._active_sessions:
            return self._active_sessions[session_id]

        # Load from disk
        return self._load_session(session_id)

    def add_action(
        self,
        session_id: str,
        action_result: ActionResult,
        component_name: str,
    ) -> bool:
        """Add an action result to a session.

        Args:
            session_id: ID of the session
            action_result: ActionResult to add
            component_name: Name of the component

        Returns:
            True if added successfully
        """
        session = self.get_session(session_id)
        if not session:
            logger.warning(f"Session not found: {session_id}")
            return False

        if not session.is_active:
            logger.warning(f"Cannot add action to ended session: {session_id}")
            return False

        # Add action to session
        session.actions.append(action_result)

        # Store component name for lookup
        if session_id not in self._action_names:
            self._action_names[session_id] = {}
        self._action_names[session_id][action_result.component_id] = component_name

        # Update index
        summary = self._index.get(session_id)
        if summary:
            summary.total_actions += 1
            if action_result.success:
                summary.successful_actions += 1
            else:
                summary.failed_actions += 1
            self._save_index()

        # Save session
        self._save_session(session)

        logger.debug(f"Added action to session {session_id}: {action_result.action.value}")
        return True

    def end_session(self, session_id: str) -> Optional[Session]:
        """End a session.

        Args:
            session_id: ID of the session to end

        Returns:
            The ended session or None if not found
        """
        session = self.get_session(session_id)
        if not session:
            logger.warning(f"Session not found: {session_id}")
            return None

        if not session.is_active:
            logger.warning(f"Session already ended: {session_id}")
            return session

        # End the session
        session.end_session()

        # Update index
        summary = self._index.get(session_id)
        if summary:
            summary.ended_at = session.ended_at.isoformat() if session.ended_at else None
            summary.is_active = False
            self._save_index()

        # Save session
        self._save_session(session)

        # Remove from active sessions
        if session_id in self._active_sessions:
            del self._active_sessions[session_id]

        logger.info(f"Ended session: {session_id}")
        return session

    def list_sessions(
        self,
        include_active: bool = True,
        include_ended: bool = True,
        limit: int = 50,
    ) -> list[SessionSummary]:
        """List sessions with optional filtering.

        Args:
            include_active: Include active sessions
            include_ended: Include ended sessions
            limit: Maximum number of results

        Returns:
            List of SessionSummary objects
        """
        results: list[SessionSummary] = []

        for summary in self._index.values():
            if summary.is_active and not include_active:
                continue
            if not summary.is_active and not include_ended:
                continue
            results.append(summary)

        # Sort by start time descending
        results.sort(key=lambda s: s.started_at, reverse=True)

        return results[:limit]

    def get_last_session(self) -> Optional[SessionSummary]:
        """Get the most recent session.

        Returns:
            Most recent SessionSummary or None
        """
        sessions = self.list_sessions(limit=1)
        return sessions[0] if sessions else None

    def get_session_actions(
        self,
        session_id: str,
    ) -> list[ActionSummary]:
        """Get all actions for a session.

        Args:
            session_id: ID of the session

        Returns:
            List of ActionSummary objects
        """
        session = self.get_session(session_id)
        if not session:
            return []

        # Get component names
        names = self._action_names.get(session_id, {})

        # Load names from session file if not in memory
        if not names:
            names = self._load_action_names(session_id)

        results: list[ActionSummary] = []
        for action in session.actions:
            summary = ActionSummary(
                plan_id=action.plan_id,
                action=action.action.value if isinstance(action.action, ActionType) else str(action.action),
                component_id=action.component_id,
                component_name=names.get(action.component_id, "Unknown"),
                success=action.success,
                snapshot_id=action.snapshot_id,
                executed_at=action.executed_at.isoformat() if isinstance(action.executed_at, datetime) else str(action.executed_at),
                rollback_available=action.rollback_available,
                error_message=action.error_message,
            )
            results.append(summary)

        return results

    def get_rollbackable_actions(self, session_id: str) -> list[ActionSummary]:
        """Get actions that can be rolled back.

        Args:
            session_id: ID of the session

        Returns:
            List of rollbackable ActionSummary objects
        """
        actions = self.get_session_actions(session_id)
        return [a for a in actions if a.rollback_available and a.success]

    def delete_session(self, session_id: str) -> bool:
        """Delete a session and its data.

        Args:
            session_id: ID of the session to delete

        Returns:
            True if deleted, False if not found
        """
        if session_id not in self._index:
            return False

        # Delete session file
        session_file = self._get_session_path(session_id)
        if session_file.exists():
            session_file.unlink()

        # Remove from index
        del self._index[session_id]
        self._save_index()

        # Remove from active sessions
        if session_id in self._active_sessions:
            del self._active_sessions[session_id]

        # Remove action names
        if session_id in self._action_names:
            del self._action_names[session_id]

        logger.info(f"Deleted session: {session_id}")
        return True

    def cleanup_old_sessions(self, keep_count: int = 20) -> int:
        """Clean up old sessions, keeping the most recent ones.

        Args:
            keep_count: Number of sessions to keep

        Returns:
            Number of sessions deleted
        """
        sessions = self.list_sessions(include_active=False, limit=1000)

        if len(sessions) <= keep_count:
            return 0

        to_delete = sessions[keep_count:]
        deleted = 0

        for summary in to_delete:
            if self.delete_session(summary.session_id):
                deleted += 1

        if deleted:
            logger.info(f"Cleaned up {deleted} old sessions")

        return deleted

    def _get_session_path(self, session_id: str) -> Path:
        """Get the file path for a session."""
        return self.sessions_dir / f"{session_id}.json"

    def _save_session(self, session: Session) -> None:
        """Save a session to disk."""
        filepath = self._get_session_path(session.session_id)

        # Prepare data for serialization
        data = {
            "session_id": session.session_id,
            "description": session.description,
            "started_at": session.started_at.isoformat() if isinstance(session.started_at, datetime) else str(session.started_at),
            "ended_at": session.ended_at.isoformat() if session.ended_at else None,
            "restore_point_id": session.restore_point_id,
            "actions": [
                {
                    "plan_id": a.plan_id,
                    "success": a.success,
                    "action": a.action.value if isinstance(a.action, ActionType) else str(a.action),
                    "component_id": a.component_id,
                    "snapshot_id": a.snapshot_id,
                    "error_message": a.error_message,
                    "executed_at": a.executed_at.isoformat() if isinstance(a.executed_at, datetime) else str(a.executed_at),
                    "rollback_available": a.rollback_available,
                }
                for a in session.actions
            ],
            "component_names": self._action_names.get(session.session_id, {}),
        }

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save session {session.session_id}: {e}")

    def _load_session(self, session_id: str) -> Optional[Session]:
        """Load a session from disk."""
        filepath = self._get_session_path(session_id)

        if not filepath.exists():
            return None

        try:
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)

            # Parse actions
            actions: list[ActionResult] = []
            for action_data in data.get("actions", []):
                action = ActionResult(
                    plan_id=action_data["plan_id"],
                    success=action_data["success"],
                    action=ActionType(action_data["action"]) if action_data["action"] in [a.value for a in ActionType] else ActionType.IGNORE,
                    component_id=action_data["component_id"],
                    snapshot_id=action_data.get("snapshot_id"),
                    error_message=action_data.get("error_message"),
                    executed_at=datetime.fromisoformat(action_data["executed_at"]) if action_data.get("executed_at") else datetime.now(),
                    rollback_available=action_data.get("rollback_available", False),
                )
                actions.append(action)

            # Create session
            session = Session(
                session_id=data["session_id"],
                description=data.get("description", ""),
                started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else datetime.now(),
                ended_at=datetime.fromisoformat(data["ended_at"]) if data.get("ended_at") else None,
                restore_point_id=data.get("restore_point_id"),
                actions=actions,
            )

            # Load component names
            self._action_names[session_id] = data.get("component_names", {})

            return session

        except Exception as e:
            logger.error(f"Failed to load session {session_id}: {e}")
            return None

    def _load_action_names(self, session_id: str) -> dict[str, str]:
        """Load component names for a session from disk."""
        filepath = self._get_session_path(session_id)

        if not filepath.exists():
            return {}

        try:
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
            return data.get("component_names", {})
        except Exception:
            return {}


def create_session_manager(config: Optional[Config] = None) -> SessionManager:
    """Create a session manager with default or provided configuration.

    Args:
        config: Optional configuration object

    Returns:
        SessionManager instance
    """
    return SessionManager(config=config)
