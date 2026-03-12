"""Safe PowerShell Executor - Centralized, injection-safe command execution.

This module provides a single, secure interface for executing PowerShell
commands. It uses -EncodedCommand (Base64-encoded UTF-16LE) to eliminate
all quoting and injection issues that arise from f-string interpolation.

All modules should use this instead of their own _run_powershell() methods.
"""

import base64
import logging
import os
import subprocess
from typing import Any

logger = logging.getLogger("debloatr.core.powershell")


class SafePowerShell:
    """Injection-safe PowerShell command executor.

    Uses -EncodedCommand to pass commands as Base64-encoded UTF-16LE,
    which eliminates all quoting, escaping, and injection concerns.

    Also provides a safe subprocess runner for non-PowerShell commands
    that enforces shell=False.

    Example:
        ps = SafePowerShell()
        result = ps.run("Get-Service -Name 'DiagTrack'")
        if result.success:
            print(result.output)
    """

    def __init__(
        self,
        dry_run: bool = False,
        timeout: int = 60,
    ) -> None:
        """Initialize the safe PowerShell executor.

        Args:
            dry_run: If True, simulate commands without executing
            timeout: Default timeout in seconds for commands
        """
        self.dry_run = dry_run
        self.timeout = timeout
        self._is_windows = os.name == "nt"

    def run(self, command: str, timeout: int | None = None) -> "PSResult":
        """Execute a PowerShell command safely using -EncodedCommand.

        The command string is encoded as UTF-16LE then Base64, and passed
        via -EncodedCommand. This avoids all shell parsing, quoting, and
        injection issues.

        Args:
            command: PowerShell command string to execute
            timeout: Override default timeout (seconds)

        Returns:
            PSResult with success, output, and error fields
        """
        if self.dry_run:
            logger.debug(f"[DRY RUN] PowerShell: {command[:200]}")
            return PSResult(success=True, output="", error="")

        if not self._is_windows:
            return PSResult(success=False, output="", error="PowerShell only available on Windows")

        effective_timeout = timeout or self.timeout

        try:
            # Encode command as UTF-16LE then Base64
            encoded = base64.b64encode(
                command.encode("utf-16-le")
            ).decode("ascii")

            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy", "Bypass",
                    "-EncodedCommand", encoded,
                ],
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                shell=False,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW
                    if hasattr(subprocess, "CREATE_NO_WINDOW")
                    else 0
                ),
            )

            return PSResult(
                success=result.returncode == 0,
                output=result.stdout.strip(),
                error=result.stderr.strip() if result.returncode != 0 else "",
            )

        except subprocess.TimeoutExpired:
            logger.warning(f"PowerShell command timed out after {effective_timeout}s")
            return PSResult(
                success=False,
                output="",
                error=f"Command timed out after {effective_timeout}s",
            )
        except Exception as e:
            logger.error(f"PowerShell execution error: {e}")
            return PSResult(success=False, output="", error=str(e))

    def run_command(self, args: list[str], timeout: int | None = None) -> "PSResult":
        """Execute a system command safely with shell=False.

        Use this for non-PowerShell commands (sc.exe, schtasks, net, etc.).
        Arguments are passed as a list, never through shell interpolation.

        Args:
            args: Command and arguments as a list (e.g. ["sc", "qc", "DiagTrack"])
            timeout: Override default timeout (seconds)

        Returns:
            PSResult with success, output, and error fields
        """
        if self.dry_run:
            logger.debug(f"[DRY RUN] Command: {' '.join(args)}")
            return PSResult(success=True, output="", error="")

        if not self._is_windows:
            return PSResult(success=False, output="", error="Only available on Windows")

        effective_timeout = timeout or self.timeout

        try:
            result = subprocess.run(
                args,
                shell=False,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW
                    if hasattr(subprocess, "CREATE_NO_WINDOW")
                    else 0
                ),
            )

            return PSResult(
                success=result.returncode == 0,
                output=result.stdout.strip(),
                error=result.stderr.strip() if result.returncode != 0 else "",
            )

        except subprocess.TimeoutExpired:
            return PSResult(
                success=False,
                output="",
                error=f"Command timed out after {effective_timeout}s",
            )
        except Exception as e:
            return PSResult(success=False, output="", error=str(e))

    def to_dict(self, result: "PSResult") -> dict[str, Any]:
        """Convert a PSResult to the legacy dict format for backward compatibility.

        Args:
            result: PSResult to convert

        Returns:
            Dictionary with success, output, error keys
        """
        return {
            "success": result.success,
            "output": result.output,
            "error": result.error,
        }


class PSResult:
    """Result of a PowerShell or system command execution.

    Attributes:
        success: Whether the command succeeded (returncode == 0)
        output: Captured stdout (stripped)
        error: Captured stderr if failed (stripped)
    """

    __slots__ = ("success", "output", "error")

    def __init__(self, success: bool, output: str, error: str) -> None:
        self.success = success
        self.output = output
        self.error = error

    def __bool__(self) -> bool:
        return self.success

    def __repr__(self) -> str:
        return f"PSResult(success={self.success}, output={self.output[:80]!r})"

    def to_dict(self) -> dict[str, Any]:
        """Convert to legacy dict format for backward compatibility."""
        return {
            "success": self.success,
            "output": self.output,
            "error": self.error,
        }


def create_powershell(dry_run: bool = False, timeout: int = 60) -> SafePowerShell:
    """Create a SafePowerShell executor.

    Args:
        dry_run: If True, simulate commands
        timeout: Default timeout in seconds

    Returns:
        SafePowerShell instance
    """
    return SafePowerShell(dry_run=dry_run, timeout=timeout)
