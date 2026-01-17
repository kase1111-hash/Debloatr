"""Discovery modules for scanning system components."""

from .base import BaseDiscoveryModule
from .drivers import (
    DriversScanner,
    DriverType,
    SignatureStatus,
    SystemDriver,
)
from .programs import InstalledProgram, ProgramsScanner
from .services import (
    RecoveryAction,
    ServiceAccountType,
    ServicesScanner,
    ServiceStartType,
    ServiceState,
    WindowsService,
)
from .startup import (
    StartupEntry,
    StartupEntryType,
    StartupScanner,
    StartupScope,
)
from .tasks import (
    ScheduledTask,
    TaskAction,
    TasksScanner,
    TaskState,
    TaskTrigger,
    TriggerType,
)
from .telemetry import (
    ConnectionType,
    EndpointCategory,
    NetworkEndpoint,
    TelemetryComponent,
    TelemetryScanner,
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
