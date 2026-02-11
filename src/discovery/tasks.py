"""Scheduled Tasks Scanner - Discovery module for Windows scheduled tasks.

This module scans for scheduled tasks and collects metadata including:
- Task name, path, and state
- Trigger types and execution frequency
- Action paths and arguments
- Hidden and self-healing task detection
"""

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from src.core.models import Component, ComponentType
from src.discovery.base import BaseDiscoveryModule

logger = logging.getLogger("debloatr.discovery.tasks")


class TriggerType(Enum):
    """Types of task triggers."""

    BOOT = "Boot"  # At system startup
    LOGON = "Logon"  # At user logon
    IDLE = "Idle"  # When system is idle
    TIME = "Time"  # At specific time/schedule
    EVENT = "Event"  # On event log entry
    REGISTRATION = "Registration"  # When task is registered
    SESSION_STATE = "SessionState"  # On session state change
    CUSTOM = "Custom"  # Custom trigger
    UNKNOWN = "Unknown"

    @classmethod
    def from_xml_element(cls, element_tag: str) -> "TriggerType":
        """Convert XML trigger element tag to enum."""
        mapping = {
            "BootTrigger": cls.BOOT,
            "LogonTrigger": cls.LOGON,
            "IdleTrigger": cls.IDLE,
            "TimeTrigger": cls.TIME,
            "CalendarTrigger": cls.TIME,
            "EventTrigger": cls.EVENT,
            "RegistrationTrigger": cls.REGISTRATION,
            "SessionStateChangeTrigger": cls.SESSION_STATE,
        }
        return mapping.get(element_tag, cls.UNKNOWN)


class TaskState(Enum):
    """Task states."""

    UNKNOWN = 0
    DISABLED = 1
    QUEUED = 2
    READY = 3
    RUNNING = 4

    @classmethod
    def from_value(cls, value: int) -> "TaskState":
        """Convert integer state to enum."""
        for member in cls:
            if member.value == value:
                return member
        return cls.UNKNOWN


@dataclass
class TaskTrigger:
    """Represents a task trigger configuration."""

    trigger_type: TriggerType
    enabled: bool = True
    start_boundary: datetime | None = None
    end_boundary: datetime | None = None
    repetition_interval: str | None = None  # e.g., "PT1H" for hourly
    repetition_duration: str | None = None
    execution_time_limit: str | None = None
    delay: str | None = None  # Random delay


@dataclass
class TaskAction:
    """Represents a task action."""

    action_type: str  # "Exec", "ComHandler", "SendEmail", "ShowMessage"
    path: Path | None = None
    arguments: str = ""
    working_directory: Path | None = None


@dataclass
class ScheduledTask(Component):
    """Represents a Windows scheduled task.

    Extends the base Component with task-specific metadata.

    Attributes:
        task_path: Full task path (e.g., "\\Microsoft\\Windows\\...")
        task_name: Task name (last segment of path)
        triggers: List of task triggers
        actions: List of task actions
        state: Current task state
        is_enabled: Whether task is enabled
        is_hidden: Whether task is hidden
        run_level: "LeastPrivilege" or "HighestAvailable"
        author: Task author
        description: Task description
        last_run_time: Last execution time
        next_run_time: Next scheduled execution
        last_result: Last execution result code
        execution_time_limit: Max execution duration
        is_self_healing: Whether task appears to be self-healing
        self_healing_target: Component this task reinstalls/re-enables
        registration_date: When task was registered
        principal_user_id: User context for execution
    """

    task_path: str = ""
    task_name: str = ""
    triggers: list[TaskTrigger] = field(default_factory=list)
    actions: list[TaskAction] = field(default_factory=list)
    state: TaskState = TaskState.UNKNOWN
    is_enabled: bool = True
    is_hidden: bool = False
    run_level: str = "LeastPrivilege"
    author: str = ""
    description: str = ""
    last_run_time: datetime | None = None
    next_run_time: datetime | None = None
    last_result: int = 0
    execution_time_limit: str | None = None
    is_self_healing: bool = False
    self_healing_target: str = ""
    registration_date: datetime | None = None
    principal_user_id: str = ""

    def __post_init__(self) -> None:
        """Set component type to TASK."""
        self.component_type = ComponentType.TASK

    @property
    def execution_frequency(self) -> str:
        """Calculate human-readable execution frequency."""
        if not self.triggers:
            return "Unknown"

        trigger_types = [t.trigger_type for t in self.triggers]

        if TriggerType.BOOT in trigger_types:
            return "On boot"
        elif TriggerType.LOGON in trigger_types:
            return "On logon"
        elif TriggerType.IDLE in trigger_types:
            return "When idle"
        elif TriggerType.EVENT in trigger_types:
            return "On event"
        elif TriggerType.TIME in trigger_types:
            # Check for repetition
            for t in self.triggers:
                if t.trigger_type == TriggerType.TIME and t.repetition_interval:
                    interval = t.repetition_interval
                    if "PT" in interval:
                        # Parse ISO 8601 duration
                        if "M" in interval and "H" not in interval:
                            return "Every few minutes"
                        elif "H" in interval:
                            return "Hourly"
                    return "Periodic"
            return "Scheduled"

        return "Custom"


# Known self-healing task patterns
SELF_HEALING_PATTERNS = [
    r".*update.*check.*",
    r".*scheduled.*install.*",
    r".*auto.*update.*",
    r".*maintenance.*",
    r".*repair.*",
    r".*restore.*",
    r".*reinstall.*",
]

# Known telemetry/tracking task patterns
TELEMETRY_TASK_PATTERNS = [
    r".*telemetry.*",
    r".*ceip.*",  # Customer Experience Improvement Program
    r".*diagnostic.*",
    r".*feedback.*",
    r".*consolidator.*",
    r".*aitagent.*",
    r".*microsoft.*compatibility.*appraiser.*",
    r".*programdataupdater.*",
]

# Task paths that are typically bloatware
BLOAT_TASK_PATHS = [
    "\\Adobe",
    "\\Apple",
    "\\Google",
    "\\Intel",
    "\\NVIDIA",
    "\\HP",
    "\\Dell",
    "\\Lenovo",
]


class TasksScanner(BaseDiscoveryModule):
    """Discovery module for scanning Windows scheduled tasks.

    Scans for scheduled tasks and collects detailed metadata including
    triggers, actions, and self-healing detection.

    Example:
        scanner = TasksScanner()
        tasks = scanner.scan()
        for task in tasks:
            print(f"{task.task_name} - {task.execution_frequency}")
    """

    def __init__(
        self,
        include_microsoft_tasks: bool = False,
        detect_self_healing: bool = True,
    ) -> None:
        """Initialize the tasks scanner.

        Args:
            include_microsoft_tasks: Whether to include Microsoft system tasks.
            detect_self_healing: Whether to detect self-healing patterns.
        """
        self.include_microsoft_tasks = include_microsoft_tasks
        self.detect_self_healing = detect_self_healing
        self._is_windows = os.name == "nt"

    def get_module_name(self) -> str:
        """Return the module identifier."""
        return "tasks"

    def get_description(self) -> str:
        """Return module description."""
        return "Scans Windows scheduled tasks with trigger and action analysis"

    def is_available(self) -> bool:
        """Check if this module can run on the current system."""
        return self._is_windows

    def requires_admin(self) -> bool:
        """Check if admin privileges are required."""
        return False  # Basic scanning works without admin

    def scan(self) -> list[Component]:
        """Scan for all scheduled tasks.

        Returns:
            List of discovered ScheduledTask components.
        """
        if not self._is_windows:
            logger.warning("Tasks scanner is only available on Windows")
            return []

        tasks: list[Component] = []

        logger.info("Scanning scheduled tasks...")

        # Get tasks via PowerShell
        raw_tasks = self._get_tasks_powershell()

        if not raw_tasks:
            logger.warning("No tasks found via PowerShell")
            return tasks

        logger.info(f"Found {len(raw_tasks)} raw tasks")

        for raw_task in raw_tasks:
            task = self._process_task(raw_task)
            if task:
                # Skip Microsoft tasks unless explicitly requested
                if not self.include_microsoft_tasks:
                    if task.task_path.startswith("\\Microsoft\\"):
                        continue

                # Detect self-healing patterns
                if self.detect_self_healing:
                    self._check_self_healing(task)

                tasks.append(task)

        logger.info(f"Processed {len(tasks)} tasks")
        return tasks

    def _get_tasks_powershell(self) -> list[dict[str, Any]]:
        """Get scheduled tasks using PowerShell.

        Returns:
            List of task dictionaries.
        """
        tasks: list[dict[str, Any]] = []

        try:
            # Get task list with details
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                """
                Get-ScheduledTask | ForEach-Object {
                    $task = $_
                    $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                    [PSCustomObject]@{
                        TaskName = $task.TaskName
                        TaskPath = $task.TaskPath
                        State = [int]$task.State
                        Description = $task.Description
                        Author = $task.Author
                        Date = $task.Date
                        URI = $task.URI
                        Settings = @{
                            Hidden = $task.Settings.Hidden
                            Enabled = $task.Settings.Enabled
                            ExecutionTimeLimit = $task.Settings.ExecutionTimeLimit
                            RunOnlyIfIdle = $task.Settings.RunOnlyIfIdle
                        }
                        Principal = @{
                            UserId = $task.Principal.UserId
                            RunLevel = [string]$task.Principal.RunLevel
                        }
                        Actions = @($task.Actions | ForEach-Object {
                            @{
                                ActionType = $_.CimClass.CimClassName
                                Execute = $_.Execute
                                Arguments = $_.Arguments
                                WorkingDirectory = $_.WorkingDirectory
                            }
                        })
                        Triggers = @($task.Triggers | ForEach-Object {
                            @{
                                TriggerType = $_.CimClass.CimClassName
                                Enabled = $_.Enabled
                                StartBoundary = $_.StartBoundary
                                EndBoundary = $_.EndBoundary
                                Delay = $_.Delay
                                RepetitionInterval = if ($_.Repetition) { $_.Repetition.Interval } else { $null }
                                RepetitionDuration = if ($_.Repetition) { $_.Repetition.Duration } else { $null }
                            }
                        })
                        LastRunTime = if ($info) { $info.LastRunTime } else { $null }
                        NextRunTime = if ($info) { $info.NextRunTime } else { $null }
                        LastTaskResult = if ($info) { $info.LastTaskResult } else { 0 }
                    }
                } | ConvertTo-Json -Depth 5 -Compress
                """.replace("\n", " "),
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
                ),
            )

            if result.returncode != 0:
                logger.error(f"PowerShell error: {result.stderr}")
                return tasks

            if not result.stdout.strip():
                return tasks

            data = json.loads(result.stdout)

            # Handle single task
            if isinstance(data, dict):
                data = [data]

            tasks = data

        except subprocess.TimeoutExpired:
            logger.error("PowerShell command timed out")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse PowerShell output: {e}")
        except FileNotFoundError:
            logger.error("PowerShell not found")
        except Exception as e:
            logger.error(f"Error getting tasks via PowerShell: {e}")

        return tasks

    def _process_task(self, raw: dict[str, Any]) -> ScheduledTask | None:
        """Process a raw task dictionary into a ScheduledTask.

        Args:
            raw: Raw task data from PowerShell.

        Returns:
            ScheduledTask if valid, None otherwise.
        """
        task_name = raw.get("TaskName", "")
        if not task_name:
            return None

        task_path = raw.get("TaskPath", "\\")
        _full_path = f"{task_path}{task_name}"  # Reserved for hierarchical task handling

        # Get settings
        settings = raw.get("Settings", {}) or {}
        principal = raw.get("Principal", {}) or {}

        # Parse triggers
        triggers = self._parse_triggers(raw.get("Triggers", []) or [])

        # Parse actions
        actions = self._parse_actions(raw.get("Actions", []) or [])

        # Get primary action path for install_path
        primary_action_path = None
        if actions and actions[0].path:
            primary_action_path = actions[0].path

        # Parse dates
        last_run = self._parse_datetime(raw.get("LastRunTime"))
        next_run = self._parse_datetime(raw.get("NextRunTime"))
        reg_date = self._parse_datetime(raw.get("Date"))

        # Detect publisher from actions
        publisher = self._detect_publisher(actions, task_path)

        # Create internal name
        internal_name = self._normalize_name(task_name)

        return ScheduledTask(
            component_type=ComponentType.TASK,
            name=internal_name,
            display_name=task_name,
            publisher=publisher,
            install_path=primary_action_path,
            task_path=task_path,
            task_name=task_name,
            triggers=triggers,
            actions=actions,
            state=TaskState.from_value(raw.get("State", 0)),
            is_enabled=bool(settings.get("Enabled", True)),
            is_hidden=bool(settings.get("Hidden", False)),
            run_level=principal.get("RunLevel", "LeastPrivilege") or "LeastPrivilege",
            author=raw.get("Author", "") or "",
            description=raw.get("Description", "") or "",
            last_run_time=last_run,
            next_run_time=next_run,
            last_result=raw.get("LastTaskResult", 0) or 0,
            execution_time_limit=settings.get("ExecutionTimeLimit"),
            registration_date=reg_date,
            principal_user_id=principal.get("UserId", "") or "",
        )

    def _parse_triggers(self, raw_triggers: list[dict]) -> list[TaskTrigger]:
        """Parse raw trigger data into TaskTrigger objects."""
        triggers = []

        for raw in raw_triggers:
            trigger_type_str = raw.get("TriggerType", "")
            # Extract just the trigger type name
            if "MSFT_Task" in trigger_type_str:
                trigger_type_str = trigger_type_str.replace("MSFT_Task", "")

            trigger = TaskTrigger(
                trigger_type=TriggerType.from_xml_element(trigger_type_str),
                enabled=bool(raw.get("Enabled", True)),
                start_boundary=self._parse_datetime(raw.get("StartBoundary")),
                end_boundary=self._parse_datetime(raw.get("EndBoundary")),
                repetition_interval=raw.get("RepetitionInterval"),
                repetition_duration=raw.get("RepetitionDuration"),
                delay=raw.get("Delay"),
            )
            triggers.append(trigger)

        return triggers

    def _parse_actions(self, raw_actions: list[dict]) -> list[TaskAction]:
        """Parse raw action data into TaskAction objects."""
        actions = []

        for raw in raw_actions:
            action_type = raw.get("ActionType", "")
            if "MSFT_Task" in action_type:
                action_type = action_type.replace("MSFT_Task", "").replace("Action", "")

            execute = raw.get("Execute", "")
            path = Path(execute) if execute else None

            working_dir = raw.get("WorkingDirectory", "")
            work_path = Path(working_dir) if working_dir else None

            action = TaskAction(
                action_type=action_type or "Exec",
                path=path,
                arguments=raw.get("Arguments", "") or "",
                working_directory=work_path,
            )
            actions.append(action)

        return actions

    def _parse_datetime(self, value: Any) -> datetime | None:
        """Parse various datetime formats."""
        if not value:
            return None

        if isinstance(value, datetime):
            return value

        if isinstance(value, str):
            # Try ISO format
            try:
                # Handle "/Date(timestamp)/" format from PowerShell
                if "/Date(" in value:
                    match = re.search(r"/Date\((\d+)\)/", value)
                    if match:
                        ts = int(match.group(1)) / 1000
                        return datetime.fromtimestamp(ts)

                # Standard ISO format
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except (ValueError, OSError):
                pass

        return None

    def _detect_publisher(
        self,
        actions: list[TaskAction],
        task_path: str,
    ) -> str:
        """Detect the publisher of a task."""
        # Check task path for known publishers
        task_path_lower = task_path.lower()

        publisher_patterns = {
            "Microsoft": ["\\microsoft\\"],
            "Adobe": ["\\adobe"],
            "Google": ["\\google"],
            "Apple": ["\\apple"],
            "Intel": ["\\intel"],
            "NVIDIA": ["\\nvidia"],
            "HP": ["\\hp", "\\hewlett"],
            "Dell": ["\\dell"],
            "Lenovo": ["\\lenovo"],
        }

        for publisher, patterns in publisher_patterns.items():
            for pattern in patterns:
                if pattern in task_path_lower:
                    return publisher

        # Check action paths
        for action in actions:
            if action.path:
                path_lower = str(action.path).lower()
                for publisher, patterns in publisher_patterns.items():
                    for pattern in patterns:
                        if pattern.replace("\\", "") in path_lower:
                            return publisher

        return "Unknown"

    def _normalize_name(self, task_name: str) -> str:
        """Normalize a task name."""
        name = task_name.lower()
        name = re.sub(r"[^\w\s-]", "", name)
        name = re.sub(r"\s+", "-", name)
        return name.strip("-")

    def _check_self_healing(self, task: ScheduledTask) -> None:
        """Check if a task exhibits self-healing patterns.

        Self-healing tasks are those that reinstall or re-enable
        software that has been removed or disabled.
        """
        task_lower = task.task_name.lower()
        desc_lower = task.description.lower()

        # Check name patterns
        for pattern in SELF_HEALING_PATTERNS:
            if re.match(pattern, task_lower) or re.match(pattern, desc_lower):
                task.is_self_healing = True
                break

        # Check if it runs at boot/logon and executes an updater
        if not task.is_self_healing:
            boot_logon_triggers = any(
                t.trigger_type in [TriggerType.BOOT, TriggerType.LOGON] for t in task.triggers
            )

            if boot_logon_triggers:
                for action in task.actions:
                    if action.path:
                        path_lower = str(action.path).lower()
                        if any(kw in path_lower for kw in ["update", "install", "repair", "setup"]):
                            task.is_self_healing = True
                            task.self_healing_target = action.path.stem
                            break

    def is_telemetry_task(self, task: ScheduledTask) -> bool:
        """Check if a task is a telemetry/tracking task.

        Args:
            task: Task to check.

        Returns:
            True if telemetry task, False otherwise.
        """
        task_full = f"{task.task_path}{task.task_name}".lower()

        for pattern in TELEMETRY_TASK_PATTERNS:
            if re.match(pattern, task_full):
                return True

        return False

    def is_in_bloat_path(self, task: ScheduledTask) -> bool:
        """Check if a task is in a known bloatware path.

        Args:
            task: Task to check.

        Returns:
            True if in bloat path, False otherwise.
        """
        for bloat_path in BLOAT_TASK_PATHS:
            if task.task_path.startswith(bloat_path):
                return True
        return False


def get_tasks_by_trigger(
    tasks: list[ScheduledTask],
    trigger_type: TriggerType,
) -> list[ScheduledTask]:
    """Get all tasks with a specific trigger type.

    Args:
        tasks: List of all tasks.
        trigger_type: Trigger type to filter by.

    Returns:
        List of tasks with that trigger type.
    """
    return [task for task in tasks if any(t.trigger_type == trigger_type for t in task.triggers)]


def get_hidden_tasks(tasks: list[ScheduledTask]) -> list[ScheduledTask]:
    """Get all hidden tasks.

    Args:
        tasks: List of all tasks.

    Returns:
        List of hidden tasks.
    """
    return [task for task in tasks if task.is_hidden]


def get_self_healing_tasks(tasks: list[ScheduledTask]) -> list[ScheduledTask]:
    """Get all tasks that appear to be self-healing.

    Args:
        tasks: List of all tasks.

    Returns:
        List of self-healing tasks.
    """
    return [task for task in tasks if task.is_self_healing]
