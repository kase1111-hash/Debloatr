"""Tests for the scheduled tasks scanner."""

import sys
from datetime import datetime
from pathlib import Path

import pytest

from src.core.models import ComponentType
from src.discovery.tasks import (
    ScheduledTask,
    TaskAction,
    TasksScanner,
    TaskState,
    TaskTrigger,
    TriggerType,
    get_hidden_tasks,
    get_self_healing_tasks,
    get_tasks_by_trigger,
)


class TestTriggerType:
    """Tests for TriggerType enum."""

    def test_from_xml_element(self):
        """Test TriggerType from XML element names."""
        assert TriggerType.from_xml_element("BootTrigger") == TriggerType.BOOT
        assert TriggerType.from_xml_element("LogonTrigger") == TriggerType.LOGON
        assert TriggerType.from_xml_element("IdleTrigger") == TriggerType.IDLE
        assert TriggerType.from_xml_element("TimeTrigger") == TriggerType.TIME
        assert TriggerType.from_xml_element("CalendarTrigger") == TriggerType.TIME
        assert TriggerType.from_xml_element("EventTrigger") == TriggerType.EVENT
        assert TriggerType.from_xml_element("Unknown") == TriggerType.UNKNOWN


class TestTaskState:
    """Tests for TaskState enum."""

    def test_from_value(self):
        """Test TaskState from integer values."""
        assert TaskState.from_value(0) == TaskState.UNKNOWN
        assert TaskState.from_value(1) == TaskState.DISABLED
        assert TaskState.from_value(2) == TaskState.QUEUED
        assert TaskState.from_value(3) == TaskState.READY
        assert TaskState.from_value(4) == TaskState.RUNNING
        assert TaskState.from_value(99) == TaskState.UNKNOWN


class TestTaskTrigger:
    """Tests for TaskTrigger dataclass."""

    def test_basic_creation(self):
        """Test basic TaskTrigger creation."""
        trigger = TaskTrigger(
            trigger_type=TriggerType.BOOT,
            enabled=True,
        )

        assert trigger.trigger_type == TriggerType.BOOT
        assert trigger.enabled is True
        assert trigger.repetition_interval is None

    def test_full_trigger(self):
        """Test TaskTrigger with all fields."""
        trigger = TaskTrigger(
            trigger_type=TriggerType.TIME,
            enabled=True,
            start_boundary=datetime(2024, 1, 1, 8, 0),
            repetition_interval="PT1H",
            repetition_duration="P1D",
        )

        assert trigger.trigger_type == TriggerType.TIME
        assert trigger.repetition_interval == "PT1H"


class TestTaskAction:
    """Tests for TaskAction dataclass."""

    def test_basic_creation(self):
        """Test basic TaskAction creation."""
        action = TaskAction(
            action_type="Exec",
            path=Path("C:/Program Files/App/app.exe"),
            arguments="--background",
        )

        assert action.action_type == "Exec"
        assert action.path == Path("C:/Program Files/App/app.exe")
        assert action.arguments == "--background"


class TestScheduledTask:
    """Tests for ScheduledTask dataclass."""

    def test_basic_creation(self):
        """Test basic ScheduledTask creation."""
        task = ScheduledTask(
            component_type=ComponentType.TASK,
            name="test-task",
            display_name="Test Task",
            publisher="Test Publisher",
            task_path="\\Test\\",
            task_name="TestTask",
        )

        assert task.name == "test-task"
        assert task.task_path == "\\Test\\"
        assert task.task_name == "TestTask"
        assert task.component_type == ComponentType.TASK
        assert task.state == TaskState.UNKNOWN

    def test_execution_frequency_boot(self):
        """Test execution frequency for boot trigger."""
        task = ScheduledTask(
            component_type=ComponentType.TASK,
            name="boot-task",
            display_name="Boot Task",
            publisher="Test",
            task_path="\\",
            task_name="BootTask",
            triggers=[TaskTrigger(TriggerType.BOOT)],
        )

        assert task.execution_frequency == "On boot"

    def test_execution_frequency_logon(self):
        """Test execution frequency for logon trigger."""
        task = ScheduledTask(
            component_type=ComponentType.TASK,
            name="logon-task",
            display_name="Logon Task",
            publisher="Test",
            task_path="\\",
            task_name="LogonTask",
            triggers=[TaskTrigger(TriggerType.LOGON)],
        )

        assert task.execution_frequency == "On logon"

    def test_execution_frequency_periodic(self):
        """Test execution frequency for periodic trigger."""
        task = ScheduledTask(
            component_type=ComponentType.TASK,
            name="periodic-task",
            display_name="Periodic Task",
            publisher="Test",
            task_path="\\",
            task_name="PeriodicTask",
            triggers=[TaskTrigger(TriggerType.TIME, repetition_interval="PT1H")],
        )

        assert task.execution_frequency == "Hourly"

    def test_execution_frequency_unknown(self):
        """Test execution frequency with no triggers."""
        task = ScheduledTask(
            component_type=ComponentType.TASK,
            name="no-trigger-task",
            display_name="No Trigger Task",
            publisher="Test",
            task_path="\\",
            task_name="NoTriggerTask",
            triggers=[],
        )

        assert task.execution_frequency == "Unknown"

    def test_full_task(self):
        """Test task with all details."""
        task = ScheduledTask(
            component_type=ComponentType.TASK,
            name="full-task",
            display_name="Full Task",
            publisher="Full Corp",
            task_path="\\FullCorp\\",
            task_name="FullTask",
            triggers=[TaskTrigger(TriggerType.BOOT)],
            actions=[TaskAction("Exec", Path("C:/app.exe"), "--run")],
            state=TaskState.READY,
            is_enabled=True,
            is_hidden=True,
            run_level="HighestAvailable",
            author="Full Corp",
            description="A full test task",
            is_self_healing=True,
            self_healing_target="SomeApp",
        )

        assert task.state == TaskState.READY
        assert task.is_hidden is True
        assert task.is_self_healing is True
        assert task.self_healing_target == "SomeApp"


class TestTasksScanner:
    """Tests for TasksScanner."""

    def test_module_name(self):
        """Test module name is correct."""
        scanner = TasksScanner()
        assert scanner.get_module_name() == "tasks"

    def test_module_description(self):
        """Test module description."""
        scanner = TasksScanner()
        desc = scanner.get_description()
        assert "task" in desc.lower()

    def test_requires_admin(self):
        """Test admin requirement."""
        scanner = TasksScanner()
        assert scanner.requires_admin() is False

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_is_available_on_windows(self):
        """Test availability on Windows."""
        scanner = TasksScanner()
        assert scanner.is_available() is True

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows only")
    def test_is_not_available_on_non_windows(self):
        """Test unavailability on non-Windows."""
        scanner = TasksScanner()
        assert scanner.is_available() is False

    def test_scanner_options(self):
        """Test scanner initialization options."""
        scanner = TasksScanner(
            include_microsoft_tasks=True,
            detect_self_healing=False,
        )

        assert scanner.include_microsoft_tasks is True
        assert scanner.detect_self_healing is False

    def test_normalize_name(self):
        """Test name normalization."""
        scanner = TasksScanner()

        assert scanner._normalize_name("Test Task") == "test-task"
        assert scanner._normalize_name("Test-Task_v2") == "test-task_v2"
        assert scanner._normalize_name("Task (Daily)") == "task-daily"

    def test_detect_publisher_from_path(self):
        """Test publisher detection from task path."""
        scanner = TasksScanner()

        actions = [TaskAction("Exec", Path("C:/Program Files/Adobe/app.exe"))]
        assert scanner._detect_publisher(actions, "\\Adobe\\") == "Adobe"

        actions = [TaskAction("Exec", Path("C:/Program Files/Google/Chrome/update.exe"))]
        assert scanner._detect_publisher(actions, "\\Google\\") == "Google"

    def test_detect_publisher_microsoft(self):
        """Test Microsoft publisher detection."""
        scanner = TasksScanner()

        actions = []
        assert scanner._detect_publisher(actions, "\\Microsoft\\Windows\\") == "Microsoft"

    def test_is_telemetry_task(self):
        """Test telemetry task detection."""
        scanner = TasksScanner()

        task = ScheduledTask(
            component_type=ComponentType.TASK,
            name="telemetry",
            display_name="Telemetry",
            publisher="Test",
            task_path="\\Microsoft\\Windows\\",
            task_name="Telemetry",
        )

        assert scanner.is_telemetry_task(task) is True

        task2 = ScheduledTask(
            component_type=ComponentType.TASK,
            name="normal",
            display_name="Normal",
            publisher="Test",
            task_path="\\",
            task_name="Normal",
        )

        assert scanner.is_telemetry_task(task2) is False

    def test_is_in_bloat_path(self):
        """Test bloat path detection."""
        scanner = TasksScanner()

        task = ScheduledTask(
            component_type=ComponentType.TASK,
            name="adobe-task",
            display_name="Adobe Task",
            publisher="Adobe",
            task_path="\\Adobe",
            task_name="AdobeTask",
        )

        assert scanner.is_in_bloat_path(task) is True

        task2 = ScheduledTask(
            component_type=ComponentType.TASK,
            name="normal",
            display_name="Normal",
            publisher="Test",
            task_path="\\MyApp",
            task_name="Normal",
        )

        assert scanner.is_in_bloat_path(task2) is False


class TestTasksScannerMocked:
    """Tests for TasksScanner with mocked APIs."""

    def test_process_task(self):
        """Test processing raw task data."""
        scanner = TasksScanner()

        raw = {
            "TaskName": "TestTask",
            "TaskPath": "\\Test\\",
            "State": 3,  # READY
            "Description": "A test task",
            "Author": "Test Author",
            "Settings": {
                "Hidden": False,
                "Enabled": True,
            },
            "Principal": {
                "UserId": "SYSTEM",
                "RunLevel": "HighestAvailable",
            },
            "Actions": [
                {
                    "ActionType": "MSFT_TaskExecAction",
                    "Execute": "C:\\Program Files\\Test\\test.exe",
                    "Arguments": "--run",
                }
            ],
            "Triggers": [
                {
                    "TriggerType": "MSFT_TaskBootTrigger",
                    "Enabled": True,
                }
            ],
        }

        task = scanner._process_task(raw)

        assert task is not None
        assert task.task_name == "TestTask"
        assert task.task_path == "\\Test\\"
        assert task.state == TaskState.READY
        assert task.is_enabled is True
        assert len(task.actions) == 1
        assert len(task.triggers) == 1
        assert task.triggers[0].trigger_type == TriggerType.BOOT

    def test_process_task_minimal(self):
        """Test processing task with minimal data."""
        scanner = TasksScanner()

        raw = {"TaskName": "MinimalTask"}

        task = scanner._process_task(raw)

        assert task is not None
        assert task.task_name == "MinimalTask"
        assert task.state == TaskState.UNKNOWN

    def test_process_task_empty_name(self):
        """Test processing task with empty name."""
        scanner = TasksScanner()

        assert scanner._process_task({"TaskName": ""}) is None
        assert scanner._process_task({}) is None

    def test_parse_triggers(self):
        """Test trigger parsing."""
        scanner = TasksScanner()

        raw_triggers = [
            {
                "TriggerType": "MSFT_TaskLogonTrigger",
                "Enabled": True,
                "Delay": "PT5M",
            },
            {
                "TriggerType": "MSFT_TaskTimeTrigger",
                "Enabled": False,
                "RepetitionInterval": "PT1H",
            },
        ]

        triggers = scanner._parse_triggers(raw_triggers)

        assert len(triggers) == 2
        assert triggers[0].trigger_type == TriggerType.LOGON
        assert triggers[0].enabled is True
        assert triggers[1].trigger_type == TriggerType.TIME
        assert triggers[1].enabled is False
        assert triggers[1].repetition_interval == "PT1H"

    def test_parse_actions(self):
        """Test action parsing."""
        scanner = TasksScanner()

        raw_actions = [
            {
                "ActionType": "MSFT_TaskExecAction",
                "Execute": "C:\\app.exe",
                "Arguments": "--silent",
                "WorkingDirectory": "C:\\",
            }
        ]

        actions = scanner._parse_actions(raw_actions)

        assert len(actions) == 1
        assert actions[0].action_type == "Exec"
        assert actions[0].path == Path("C:\\app.exe")
        assert actions[0].arguments == "--silent"

    def test_check_self_healing_by_name(self):
        """Test self-healing detection by task name."""
        scanner = TasksScanner()

        task = ScheduledTask(
            component_type=ComponentType.TASK,
            name="auto-update-check",
            display_name="Auto Update Check",
            publisher="Test",
            task_path="\\",
            task_name="AutoUpdateCheck",
            triggers=[TaskTrigger(TriggerType.BOOT)],
            actions=[TaskAction("Exec", Path("C:/app/updater.exe"))],
        )

        scanner._check_self_healing(task)

        assert task.is_self_healing is True

    def test_check_self_healing_by_action(self):
        """Test self-healing detection by action path."""
        scanner = TasksScanner()

        task = ScheduledTask(
            component_type=ComponentType.TASK,
            name="some-task",
            display_name="Some Task",
            publisher="Test",
            task_path="\\",
            task_name="SomeTask",
            triggers=[TaskTrigger(TriggerType.LOGON)],
            actions=[TaskAction("Exec", Path("C:/Program Files/App/AppUpdate.exe"))],
        )

        scanner._check_self_healing(task)

        assert task.is_self_healing is True
        assert task.self_healing_target == "AppUpdate"


class TestTaskHelperFunctions:
    """Tests for task helper functions."""

    def test_get_tasks_by_trigger(self):
        """Test filtering tasks by trigger type."""
        tasks = [
            ScheduledTask(
                component_type=ComponentType.TASK,
                name="boot",
                display_name="Boot",
                publisher="Test",
                task_path="\\",
                task_name="Boot",
                triggers=[TaskTrigger(TriggerType.BOOT)],
            ),
            ScheduledTask(
                component_type=ComponentType.TASK,
                name="logon",
                display_name="Logon",
                publisher="Test",
                task_path="\\",
                task_name="Logon",
                triggers=[TaskTrigger(TriggerType.LOGON)],
            ),
            ScheduledTask(
                component_type=ComponentType.TASK,
                name="boot2",
                display_name="Boot2",
                publisher="Test",
                task_path="\\",
                task_name="Boot2",
                triggers=[TaskTrigger(TriggerType.BOOT)],
            ),
        ]

        boot_tasks = get_tasks_by_trigger(tasks, TriggerType.BOOT)
        assert len(boot_tasks) == 2

        logon_tasks = get_tasks_by_trigger(tasks, TriggerType.LOGON)
        assert len(logon_tasks) == 1

    def test_get_hidden_tasks(self):
        """Test filtering hidden tasks."""
        tasks = [
            ScheduledTask(
                component_type=ComponentType.TASK,
                name="visible",
                display_name="Visible",
                publisher="Test",
                task_path="\\",
                task_name="Visible",
                is_hidden=False,
            ),
            ScheduledTask(
                component_type=ComponentType.TASK,
                name="hidden",
                display_name="Hidden",
                publisher="Test",
                task_path="\\",
                task_name="Hidden",
                is_hidden=True,
            ),
        ]

        hidden = get_hidden_tasks(tasks)
        assert len(hidden) == 1
        assert hidden[0].task_name == "Hidden"

    def test_get_self_healing_tasks(self):
        """Test filtering self-healing tasks."""
        tasks = [
            ScheduledTask(
                component_type=ComponentType.TASK,
                name="normal",
                display_name="Normal",
                publisher="Test",
                task_path="\\",
                task_name="Normal",
                is_self_healing=False,
            ),
            ScheduledTask(
                component_type=ComponentType.TASK,
                name="healing",
                display_name="Healing",
                publisher="Test",
                task_path="\\",
                task_name="Healing",
                is_self_healing=True,
            ),
        ]

        healing = get_self_healing_tasks(tasks)
        assert len(healing) == 1
        assert healing[0].task_name == "Healing"


class TestTasksScannerIntegration:
    """Integration tests for TasksScanner (Windows only)."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_scan_returns_list(self):
        """Test that scan returns a list on Windows."""
        scanner = TasksScanner(include_microsoft_tasks=False)
        result = scanner.scan()

        assert isinstance(result, list)

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows only")
    def test_scan_returns_empty_on_non_windows(self):
        """Test that scan returns empty list on non-Windows."""
        scanner = TasksScanner()
        result = scanner.scan()

        assert result == []
