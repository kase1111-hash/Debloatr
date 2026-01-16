"""Discovery modules for scanning system components."""

from .base import BaseDiscoveryModule
from .programs import ProgramsScanner, InstalledProgram

__all__ = [
    "BaseDiscoveryModule",
    "ProgramsScanner",
    "InstalledProgram",
]
