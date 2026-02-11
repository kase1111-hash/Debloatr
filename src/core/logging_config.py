"""Logging configuration for Debloatr.

This module sets up structured logging with file rotation,
separate logs for different concerns (main, actions, scan).
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

# Log format constants
DEFAULT_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
DETAILED_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(filename)s:%(lineno)d | %(message)s"
SIMPLE_FORMAT = "%(levelname)s: %(message)s"

# Default settings
DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_BACKUP_COUNT = 5


class DebloatrLogger:
    """Centralized logger management for Debloatr.

    Manages multiple log files for different concerns:
        - main.log: General application logging
        - actions.log: All action executions and rollbacks
        - scan.log: Discovery scan results
    """

    _instance: Optional["DebloatrLogger"] = None
    _initialized: bool = False

    def __new__(cls) -> "DebloatrLogger":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return

        self.logs_dir: Path | None = None
        self.log_level: int = DEFAULT_LOG_LEVEL
        self.loggers: dict[str, logging.Logger] = {}
        self._initialized = True

    def setup(
        self,
        logs_dir: Path,
        log_level: int = DEFAULT_LOG_LEVEL,
        console_output: bool = True,
    ) -> None:
        """Initialize logging with specified configuration.

        Args:
            logs_dir: Directory for log files.
            log_level: Logging level (e.g., logging.INFO).
            console_output: Whether to also log to console.
        """
        self.logs_dir = logs_dir
        self.log_level = log_level

        # Ensure logs directory exists
        logs_dir.mkdir(parents=True, exist_ok=True)

        # Setup root logger for debloatr
        root_logger = logging.getLogger("debloatr")
        root_logger.setLevel(log_level)

        # Clear any existing handlers
        root_logger.handlers.clear()

        # Main log file handler
        main_handler = self._create_file_handler(
            logs_dir / "main.log",
            DETAILED_FORMAT,
        )
        root_logger.addHandler(main_handler)

        # Console handler
        if console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(log_level)
            console_handler.setFormatter(logging.Formatter(SIMPLE_FORMAT))
            root_logger.addHandler(console_handler)

        # Store reference
        self.loggers["main"] = root_logger

        # Setup specialized loggers
        self._setup_action_logger(logs_dir)
        self._setup_scan_logger(logs_dir)

    def _create_file_handler(
        self,
        log_path: Path,
        format_string: str,
        max_bytes: int = DEFAULT_MAX_BYTES,
        backup_count: int = DEFAULT_BACKUP_COUNT,
    ) -> RotatingFileHandler:
        """Create a rotating file handler.

        Args:
            log_path: Path to the log file.
            format_string: Log format string.
            max_bytes: Maximum file size before rotation.
            backup_count: Number of backup files to keep.

        Returns:
            Configured RotatingFileHandler.
        """
        handler = RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        handler.setLevel(self.log_level)
        handler.setFormatter(logging.Formatter(format_string))
        return handler

    def _setup_action_logger(self, logs_dir: Path) -> None:
        """Setup the action-specific logger."""
        logger = logging.getLogger("debloatr.actions")
        logger.setLevel(self.log_level)
        logger.propagate = False  # Don't also log to main

        handler = self._create_file_handler(
            logs_dir / "actions.log",
            "%(asctime)s | %(levelname)-8s | ACTION | %(message)s",
        )
        logger.addHandler(handler)
        self.loggers["actions"] = logger

    def _setup_scan_logger(self, logs_dir: Path) -> None:
        """Setup the scan results logger."""
        logger = logging.getLogger("debloatr.scan")
        logger.setLevel(self.log_level)
        logger.propagate = False

        handler = self._create_file_handler(
            logs_dir / "scan.log",
            "%(asctime)s | %(levelname)-8s | SCAN | %(message)s",
        )
        logger.addHandler(handler)
        self.loggers["scan"] = logger

    def get_logger(self, name: str = "main") -> logging.Logger:
        """Get a logger by name.

        Args:
            name: Logger name ("main", "actions", "scan").

        Returns:
            The requested logger, or main logger if not found.
        """
        if name in self.loggers:
            return self.loggers[name]

        # Return a child logger of main
        return logging.getLogger(f"debloatr.{name}")


# Global logger instance
_logger_manager = DebloatrLogger()


def setup_logging(
    logs_dir: Path,
    log_level: int = DEFAULT_LOG_LEVEL,
    console_output: bool = True,
) -> None:
    """Initialize the logging system.

    This should be called once at application startup.

    Args:
        logs_dir: Directory for log files.
        log_level: Logging level (default: INFO).
        console_output: Whether to also log to console (default: True).
    """
    _logger_manager.setup(logs_dir, log_level, console_output)


def get_logger(name: str = "main") -> logging.Logger:
    """Get a logger instance.

    Args:
        name: Logger name. Options:
            - "main": General application logging
            - "actions": Action execution logging
            - "scan": Scan results logging

    Returns:
        Logger instance.
    """
    return _logger_manager.get_logger(name)


def log_action(
    action_type: str,
    component_name: str,
    success: bool,
    details: str = "",
) -> None:
    """Log an action execution.

    Args:
        action_type: Type of action (DISABLE, REMOVE, etc.).
        component_name: Name of the affected component.
        success: Whether the action succeeded.
        details: Additional details about the action.
    """
    logger = get_logger("actions")
    status = "SUCCESS" if success else "FAILED"
    message = f"{action_type} | {component_name} | {status}"
    if details:
        message += f" | {details}"

    if success:
        logger.info(message)
    else:
        logger.error(message)


def log_scan_result(
    module_name: str,
    component_count: int,
    duration_ms: float,
) -> None:
    """Log a scan module result.

    Args:
        module_name: Name of the discovery module.
        component_count: Number of components discovered.
        duration_ms: Scan duration in milliseconds.
    """
    logger = get_logger("scan")
    logger.info(f"{module_name} | Found {component_count} components in {duration_ms:.1f}ms")
