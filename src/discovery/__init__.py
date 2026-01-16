"""Discovery modules for scanning system components."""

from .base import BaseDiscoveryModule
from .programs import ProgramsScanner, InstalledProgram
from .services import (
    ServicesScanner,
    WindowsService,
    ServiceStartType,
    ServiceState,
    ServiceAccountType,
    RecoveryAction,
)
from .tasks import (
    TasksScanner,
    ScheduledTask,
    TriggerType,
    TaskState,
    TaskTrigger,
    TaskAction,
)
from .startup import (
    StartupScanner,
    StartupEntry,
    StartupEntryType,
    StartupScope,
)
from .drivers import (
    DriversScanner,
    SystemDriver,
    DriverType,
    SignatureStatus,
)
from .telemetry import (
    TelemetryScanner,
    TelemetryComponent,
    ConnectionType,
    EndpointCategory,
    NetworkEndpoint,
)

__all__ = [
    "BaseDiscoveryModule",
    # Programs
    "ProgramsScanner",
    "InstalledProgram",
    # Services
    "ServicesScanner",
    "WindowsService",
    "ServiceStartType",
    "ServiceState",
    "ServiceAccountType",
    "RecoveryAction",
    # Tasks
    "TasksScanner",
    "ScheduledTask",
    "TriggerType",
    "TaskState",
    "TaskTrigger",
    "TaskAction",
    # Startup
    "StartupScanner",
    "StartupEntry",
    "StartupEntryType",
    "StartupScope",
    # Drivers
    "DriversScanner",
    "SystemDriver",
    "DriverType",
    "SignatureStatus",
    # Telemetry
    "TelemetryScanner",
    "TelemetryComponent",
    "ConnectionType",
    "EndpointCategory",
    "NetworkEndpoint",
]
