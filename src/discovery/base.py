"""Base interface for discovery modules.

All discovery modules must inherit from BaseDiscoveryModule and implement
the required methods for scanning system components.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.core.models import Component


class BaseDiscoveryModule(ABC):
    """Abstract base class for all discovery modules.

    Discovery modules are responsible for scanning and enumerating
    system components such as programs, services, tasks, etc.

    Subclasses must implement:
        - scan(): Perform the discovery scan
        - get_module_name(): Return the module identifier

    Example:
        class ProgramsScanner(BaseDiscoveryModule):
            def get_module_name(self) -> str:
                return "programs"

            def scan(self) -> list[Component]:
                # Enumerate installed programs
                return discovered_programs
    """

    @abstractmethod
    def scan(self) -> list["Component"]:
        """Scan and return discovered components.

        Returns:
            List of Component objects discovered by this module.

        Raises:
            PermissionError: If insufficient privileges for scanning.
            OSError: If a system error occurs during scanning.
        """
        pass

    @abstractmethod
    def get_module_name(self) -> str:
        """Return the module identifier.

        Returns:
            A string identifier for this discovery module.
            Examples: "programs", "services", "tasks", "startup"
        """
        pass

    def get_description(self) -> str:
        """Return a human-readable description of what this module scans.

        Returns:
            A description string. Default implementation returns
            a generic description based on the module name.
        """
        return f"Scans for {self.get_module_name()} on the system"

    def is_available(self) -> bool:
        """Check if this discovery module can run on the current system.

        Returns:
            True if the module can run, False otherwise.
            Default implementation always returns True.
        """
        return True

    def requires_admin(self) -> bool:
        """Check if this discovery module requires administrator privileges.

        Returns:
            True if admin privileges are required for full scanning,
            False otherwise. Default implementation returns False.
        """
        return False
