# Debloatr - 10-Phase Coding Guide

**Target: Shop Grade Implementation**

This guide breaks down the development of the Bloatware Scanner & Debloater into 10 logical phases, each building upon the previous.

---

## Phase 1: Project Setup & Core Infrastructure

### Objective
Establish the foundational project structure, dependencies, and core data models.

### Tasks

1. **Create Project Structure**
   ```
   debloatd/
   ├── src/
   │   ├── __init__.py
   │   ├── core/
   │   │   ├── __init__.py
   │   │   ├── models.py          # Data classes/models
   │   │   ├── orchestrator.py    # Scan coordinator
   │   │   ├── config.py          # Configuration management
   │   │   └── logging_config.py  # Logging setup
   │   ├── discovery/
   │   │   └── __init__.py
   │   ├── classification/
   │   │   └── __init__.py
   │   ├── analysis/
   │   │   └── __init__.py
   │   ├── actions/
   │   │   └── __init__.py
   │   └── ui/
   │       └── __init__.py
   ├── data/
   │   ├── signatures/
   │   │   └── default.json
   │   └── profiles/
   │       └── default.json
   ├── tests/
   │   └── __init__.py
   ├── docs/
   ├── requirements.txt
   ├── setup.py
   └── debloatd.py
   ```

2. **Define Core Data Models** (`src/core/models.py`)
   - `ComponentType` enum: `PROGRAM`, `SERVICE`, `TASK`, `STARTUP`, `DRIVER`, `UWP`, `TELEMETRY`
   - `Classification` enum: `CORE`, `ESSENTIAL`, `OPTIONAL`, `BLOAT`, `AGGRESSIVE`, `UNKNOWN`
   - `RiskLevel` enum: `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
   - `ActionType` enum: `DISABLE`, `CONTAIN`, `REMOVE`, `REPLACE`, `IGNORE`
   - `Component` dataclass with common fields:
     ```python
     @dataclass
     class Component:
         id: str  # UUID
         component_type: ComponentType
         name: str
         display_name: str
         publisher: str
         install_path: Path
         classification: Classification = Classification.UNKNOWN
         risk_level: RiskLevel = RiskLevel.NONE
         metadata: dict = field(default_factory=dict)
     ```

3. **Setup Dependencies** (`requirements.txt`)
   ```
   pywin32>=305
   psutil>=5.9.0
   pydantic>=2.0
   PySide6>=6.5.0  # For GUI (Phase 10)
   ```

4. **Create Base Discovery Interface**
   ```python
   # src/discovery/base.py
   from abc import ABC, abstractmethod
   from typing import List
   from src.core.models import Component

   class BaseDiscoveryModule(ABC):
       @abstractmethod
       def scan(self) -> List[Component]:
           """Scan and return discovered components."""
           pass

       @abstractmethod
       def get_module_name(self) -> str:
           """Return the module identifier."""
           pass
   ```

5. **Implement Configuration System**
   - Load/save JSON configuration
   - Support for profiles
   - Environment-aware settings (dev/prod)

### Deliverables
- [ ] Project directory structure created
- [ ] All data models defined with type hints
- [ ] Base interfaces for all modules
- [ ] Configuration management working
- [ ] Logging infrastructure in place
- [ ] Unit test framework setup (pytest)

---

## Phase 2: Installed Software Scanner

### Objective
Implement the first discovery module to scan installed programs from registry and filesystem.

### Tasks

1. **Create Programs Scanner** (`src/discovery/programs.py`)
   - Query registry keys:
     - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
     - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
     - `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`

2. **Extract Metadata**
   ```python
   @dataclass
   class InstalledProgram(Component):
       install_date: Optional[datetime]
       size_bytes: int
       executables: List[Path]
       uninstall_string: str
       update_mechanism: Optional[str]
       is_uwp: bool = False
   ```

3. **Implement UWP App Detection**
   - Use `Get-AppxPackage` via PowerShell subprocess
   - Parse package manifest for metadata
   - Map UWP packages to `InstalledProgram` model

4. **Calculate Installation Size**
   - Recursively scan install directories
   - Handle access denied gracefully
   - Cache results for performance

5. **Detect Portable Applications**
   - Scan common locations: `%APPDATA%`, `%LOCALAPPDATA%`, `%PROGRAMDATA%`
   - Identify executables without registry entries
   - Flag with `is_portable = True`

### Deliverables
- [ ] Registry-based program scanner
- [ ] UWP/Store app scanner
- [ ] Portable app detector
- [ ] Size calculation utility
- [ ] Unit tests with mock registry data
- [ ] JSON output format working

---

## Phase 3: Services Scanner

### Objective
Enumerate Windows services with dependency tracking and network access analysis.

### Tasks

1. **Create Services Scanner** (`src/discovery/services.py`)
   - Use `pywin32` for SCM access
   - Query WMI `Win32_Service` for extended metadata

2. **Define Service Model**
   ```python
   @dataclass
   class WindowsService(Component):
       service_name: str
       start_type: str  # Auto/Manual/Disabled/Boot
       binary_path: Path
       account_context: str
       dependencies: List[str]
       dependents: List[str]
       network_ports: List[int]
       is_running: bool
       restart_behavior: dict
   ```

3. **Analyze Service Dependencies**
   - Build dependency graph
   - Identify critical dependency chains
   - Mark services with system dependents as higher risk

4. **Network Access Detection**
   - Cross-reference with `netstat` output
   - Check Windows Firewall rules for service paths
   - Identify services with outbound connections

5. **Map Services to Parent Programs**
   - Link services to their installer packages
   - Group related services (e.g., all Adobe services)

### Deliverables
- [ ] Complete service enumeration
- [ ] Dependency graph builder
- [ ] Network access analyzer
- [ ] Service-to-program mapping
- [ ] Unit tests with mock SCM data

---

## Phase 4: Scheduled Tasks & Startup Scanners

### Objective
Discover scheduled tasks and all startup entry points.

### Tasks

1. **Create Tasks Scanner** (`src/discovery/tasks.py`)
   - Use Task Scheduler COM interface
   - Parse task XML definitions

2. **Define Task Model**
   ```python
   @dataclass
   class ScheduledTask(Component):
       task_path: str
       trigger_type: str
       execution_frequency: str  # e.g., "daily", "on_boot", "on_login"
       action_path: Path
       action_arguments: str
       is_hidden: bool
       is_enabled: bool
       author: str
       last_run: Optional[datetime]
       next_run: Optional[datetime]
   ```

3. **Detect Self-Healing Patterns**
   - Identify tasks that reinstall/re-enable disabled components
   - Flag tasks that monitor other tasks
   - Track tasks created by OEM software

4. **Create Startup Scanner** (`src/discovery/startup.py`)
   - Scan all registry Run keys
   - Scan startup folders (user and machine)
   - Detect shell extensions and Winlogon hooks

5. **Define Startup Model**
   ```python
   @dataclass
   class StartupEntry(Component):
       entry_type: str  # Run/RunOnce/Shell/Winlogon/Folder
       target_path: Path
       arguments: str
       scope: str  # Machine/User
       registry_key: Optional[str]
       is_approved: bool  # Windows startup approval status
   ```

6. **Correlate Tasks with Startup Entries**
   - Link scheduled tasks to startup items
   - Identify redundant startup mechanisms

### Deliverables
- [ ] Scheduled task enumeration
- [ ] Task XML parser
- [ ] Self-healing pattern detector
- [ ] All startup entry sources scanned
- [ ] Task-startup correlation
- [ ] Unit tests for both modules

---

## Phase 5: Drivers & Telemetry Scanners

### Objective
Identify third-party drivers, helper services, and telemetry/network activity.

### Tasks

1. **Create Drivers Scanner** (`src/discovery/drivers.py`)
   - Use `driverquery /v` and `Get-WindowsDriver`
   - Focus on non-Microsoft signed drivers

2. **Define Driver Model**
   ```python
   @dataclass
   class SystemDriver(Component):
       driver_type: str  # Kernel/Filesystem/User
       signer: str
       signature_status: str  # Valid/Invalid/Unsigned
       associated_hardware: List[str]  # PnP device IDs
       load_order: int
       is_running: bool
   ```

3. **Detect Overlay Injectors**
   - Scan for DLL injection patterns
   - Identify known overlay software (game overlays, screen capture)
   - Check for AppInit_DLLs registry entries

4. **Create Telemetry Scanner** (`src/discovery/telemetry.py`)
   - Enumerate persistent network connections
   - Match against known telemetry endpoint database

5. **Define Telemetry Model**
   ```python
   @dataclass
   class TelemetryComponent(Component):
       process_name: str
       process_path: Path
       remote_endpoints: List[str]
       connection_type: str  # Persistent/Periodic
       bytes_sent: int
       bytes_received: int
       associated_service: Optional[str]
   ```

6. **Build Telemetry Endpoint Database**
   - Compile list of known telemetry domains
   - Include Microsoft, OEM, and third-party endpoints
   - Support custom additions via config

### Deliverables
- [ ] Driver enumeration with signature validation
- [ ] DLL injection detector
- [ ] Telemetry process scanner
- [ ] Network endpoint analyzer
- [ ] Known telemetry endpoint database
- [ ] Unit tests for both modules

---

## Phase 6: Signature Database & Classification Engine

### Objective
Implement the deterministic signature-based classification system.

### Tasks

1. **Define Signature Schema** (`data/signatures/schema.json`)
   ```json
   {
     "signature_id": "string (UUID)",
     "publisher": "string",
     "component_name": "string",
     "component_type": "enum",
     "match_rules": {
       "name_pattern": "regex",
       "publisher_pattern": "regex",
       "path_pattern": "regex",
       "hash_sha256": ["string"]
     },
     "classification": "enum",
     "related_components": ["signature_id"],
     "safe_actions": ["enum"],
     "unsafe_actions": ["enum"],
     "reinstall_behavior": "enum",
     "breakage_notes": "string",
     "evidence_url": "string",
     "last_updated": "ISO8601"
   }
   ```

2. **Create Signature Loader** (`src/classification/signatures.py`)
   - Load and validate JSON signatures
   - Verify SHA256 hash of signature file
   - Support multiple signature sources
   - Merge/override logic for custom signatures

3. **Build Classification Engine** (`src/classification/engine.py`)
   ```python
   class ClassificationEngine:
       def __init__(self, signature_db: SignatureDatabase):
           self.signatures = signature_db

       def classify(self, component: Component) -> ClassificationResult:
           # Try signature match first
           signature = self.signatures.match(component)
           if signature:
               return ClassificationResult(
                   classification=signature.classification,
                   source="signature",
                   signature_id=signature.id,
                   confidence=1.0
               )
           # Fall back to heuristics (Phase 7)
           return ClassificationResult(
               classification=Classification.UNKNOWN,
               source="none",
               confidence=0.0
           )
   ```

4. **Implement Pattern Matching**
   - Regex matching for names, publishers, paths
   - SHA256 hash matching for executables
   - Fuzzy matching for slight variations

5. **Create Initial Signature Database**
   - Add signatures from Appendix A (common bloatware)
   - Include Microsoft built-in bloat (Cortana, Xbox, etc.)
   - Add major OEM bloatware (HP, Dell, Lenovo)
   - Add known telemetry components

6. **Implement Related Components Linking**
   - When one component matches, check related signatures
   - Group related components for batch actions

### Deliverables
- [ ] Signature schema and validation
- [ ] Signature loader with integrity verification
- [ ] Classification engine core
- [ ] Pattern matching system
- [ ] Initial signature database (50+ entries)
- [ ] Unit tests with sample signatures

---

## Phase 7: Heuristics Engine & Risk Analyzer

### Objective
Implement confidence-based heuristic classification and risk analysis.

### Tasks

1. **Define Heuristic Rules** (`src/classification/heuristics.py`)
   ```python
   HEURISTIC_RULES = {
       "AUTOSTART_NO_UI": {
           "weight": 0.3,
           "check": lambda c: c.has_autostart and not c.has_visible_ui
       },
       "NETWORK_NO_VALUE": {
           "weight": 0.4,
           "check": lambda c: c.has_network_access and not c.provides_network_feature
       },
       "SELF_HEALING": {
           "weight": 0.5,
           "check": lambda c: c.reinstalls_after_removal
       },
       "ACCOUNT_REQUIRED": {
           "weight": 0.3,
           "check": lambda c: c.requires_login and c.is_local_only
       },
       "BUNDLED_UNRELATED": {
           "weight": 0.4,
           "check": lambda c: c.is_bundled and not c.related_to_parent
       },
       "TELEMETRY_PATTERN": {
           "weight": 0.6,
           "check": lambda c: c.matches_telemetry_behavior
       },
       "OVERLAY_INJECTOR": {
           "weight": 0.5,
           "check": lambda c: c.injects_into_processes
       }
   }
   ```

2. **Implement Scoring System**
   ```python
   def calculate_bloat_score(component: Component, triggered_rules: List[str]) -> float:
       triggered_weight = sum(HEURISTIC_RULES[r]["weight"] for r in triggered_rules)
       total_weight = sum(r["weight"] for r in HEURISTIC_RULES.values())
       return triggered_weight / total_weight

   def suggest_classification(bloat_score: float) -> Classification:
       if bloat_score >= 0.8:
           return Classification.AGGRESSIVE
       elif bloat_score >= 0.6:
           return Classification.BLOAT
       else:
           return Classification.UNKNOWN
   ```

3. **Create Risk Analyzer** (`src/analysis/risk.py`)
   - Implement 5-dimension risk assessment:
     - Boot Stability
     - Hardware Function
     - Update Pipeline
     - Security Surface
     - User Experience

4. **Build Dependency Chain Analyzer**
   ```python
   def analyze_boot_stability(component: Component) -> RiskLevel:
       # Check if component is in boot chain
       # Analyze service dependencies
       # Check for critical system dependencies
       pass

   def calculate_risk_level(component: Component) -> RiskLevel:
       risks = [
           analyze_boot_stability(component),
           analyze_hardware_function(component),
           analyze_update_pipeline(component),
           analyze_security_surface(component),
           analyze_user_experience(component)
       ]
       return max(risks)  # Highest risk wins
   ```

5. **Implement LLM Integration Layer** (`src/classification/llm_layer.py`)
   - Define input/output schemas
   - REST adapter for OpenAI/Anthropic/local models
   - Fallback to heuristics if LLM unavailable
   - Log all LLM outputs to `llm_analysis.log`
   - **Advisory only** - never auto-execute

### Deliverables
- [ ] All heuristic rules implemented
- [ ] Bloat score calculator
- [ ] Risk dimension analyzers (all 5)
- [ ] Composite risk level calculator
- [ ] LLM integration layer (optional)
- [ ] Unit tests for heuristics and risk

---

## Phase 8: Action Planner & Execution Engine

### Objective
Implement the action planning system and safe execution with transactions.

### Tasks

1. **Create Action Planner** (`src/actions/planner.py`)
   ```python
   class ActionPlanner:
       def get_available_actions(self, component: Component) -> List[ActionType]:
           """Return actions permitted by safety rules."""
           if component.classification == Classification.CORE:
               return []  # Locked

           available = []
           if component.risk_level <= RiskLevel.MEDIUM:
               available.append(ActionType.DISABLE)
           if component.risk_level <= RiskLevel.LOW:
               available.append(ActionType.REMOVE)
           # ... more rules
           return available

       def create_action_plan(self, component: Component, action: ActionType) -> ActionPlan:
           """Generate detailed execution plan."""
           pass
   ```

2. **Implement Action Handlers**

   **Disable Action** (`src/actions/disable.py`):
   ```python
   def disable_service(service: WindowsService) -> ActionResult:
       # Stop service
       # Set StartupType to Disabled
       # Return result with rollback info
       pass

   def disable_task(task: ScheduledTask) -> ActionResult:
       # Disable-ScheduledTask
       pass

   def disable_startup(entry: StartupEntry) -> ActionResult:
       # Registry: rename or clear value
       # Folder: move to quarantine
       pass
   ```

   **Contain Action** (`src/actions/contain.py`):
   ```python
   def contain_with_firewall(component: Component) -> ActionResult:
       # Create outbound block rule
       pass

   def contain_with_acl(component: Component) -> ActionResult:
       # Add deny execute ACL
       pass
   ```

   **Remove Action** (`src/actions/remove.py`):
   ```python
   def remove_program(program: InstalledProgram) -> ActionResult:
       if program.is_uwp:
           # Remove-AppxPackage
           pass
       elif program.uninstall_string:
           # Execute uninstaller silently
           pass
       else:
           # Manual file deletion (with caution)
           pass
   ```

3. **Create Execution Engine** (`src/actions/executor.py`)
   ```python
   class ExecutionEngine:
       def __init__(self, mode: ExecutionMode = ExecutionMode.DRY_RUN):
           self.mode = mode
           self.rollback_manager = RollbackManager()

       def execute(self, plan: ActionPlan) -> ExecutionResult:
           if self.mode == ExecutionMode.DRY_RUN:
               return self._simulate(plan)

           # Create snapshot before mutation
           snapshot = self.rollback_manager.create_snapshot(plan.component)

           try:
               result = self._execute_action(plan)
               self._log_action(plan, result)
               return result
           except Exception as e:
               self.rollback_manager.rollback(snapshot)
               raise
   ```

4. **Implement Safety Rules**
   - Core components are read-only
   - Drivers require disable before remove
   - OEM tools require 7-day staging
   - Batch operations need explicit confirmation

5. **Create Execution Modes**
   - `SCAN_ONLY`: Discovery and classification only
   - `DRY_RUN`: Generate plan, no execution
   - `INTERACTIVE`: Prompt before each action
   - `BATCH_CONFIRM`: Confirm batch, execute all

### Deliverables
- [ ] Action planner with safety rules
- [ ] Disable action handler (services, tasks, startup)
- [ ] Contain action handler (firewall, ACL)
- [ ] Remove action handler (programs, UWP)
- [ ] Execution engine with modes
- [ ] Action logging system
- [ ] Unit tests for all actions

---

## Phase 9: Rollback & Recovery System

### Objective
Implement comprehensive rollback capabilities and recovery mechanisms.

### Tasks

1. **Create Snapshot System** (`src/core/snapshot.py`)
   ```python
   @dataclass
   class Snapshot:
       snapshot_id: str  # UUID
       timestamp: datetime
       component_id: str
       action: ActionType
       captured_state: dict  # Registry, service config, files, ACLs

   class SnapshotManager:
       def capture(self, component: Component, action: ActionType) -> Snapshot:
           state = {
               "registry_keys": self._capture_registry(component),
               "service_config": self._capture_service(component),
               "task_definition": self._capture_task(component),
               "file_hashes": self._capture_files(component),
               "acl_state": self._capture_acls(component)
           }
           return Snapshot(
               snapshot_id=str(uuid4()),
               timestamp=datetime.now(),
               component_id=component.id,
               action=action,
               captured_state=state
           )
   ```

2. **Implement Rollback Manager** (`src/core/rollback.py`)
   ```python
   class RollbackManager:
       def rollback(self, snapshot: Snapshot) -> RollbackResult:
           # Restore registry keys
           # Re-enable services
           # Restore files from quarantine
           # Remove firewall/ACL rules
           pass

       def rollback_session(self, session_id: str) -> List[RollbackResult]:
           # Get all snapshots for session
           # Rollback in reverse order
           pass
   ```

3. **Create System Restore Point Integration**
   ```python
   def create_restore_point(name: str) -> bool:
       # Create Windows System Restore point
       # Named: "Debloat-Session-{timestamp}"
       pass
   ```

4. **Implement Session Management**
   ```python
   class SessionManager:
       def list_sessions(self) -> List[Session]:
           """List all debloat sessions with timestamps."""
           pass

       def get_session_actions(self, session_id: str) -> List[ActionRecord]:
           """List all actions in a session."""
           pass

       def undo_action(self, session_id: str, action_id: str) -> RollbackResult:
           """Rollback a single action."""
           pass

       def undo_session(self, session_id: str) -> List[RollbackResult]:
           """Rollback entire session in reverse order."""
           pass
   ```

5. **Implement Boot-Safe Recovery**
   - Detect boot failures after debloat
   - Safe mode recovery command: `debloatd --recovery --last-session`
   - Automatic rollback of most recent session

6. **Create Quarantine System**
   - Dedicated quarantine folder with restricted ACLs
   - Move files instead of deleting
   - Restore from quarantine capability

### Deliverables
- [ ] Snapshot capture for all component types
- [ ] Rollback for all action types
- [ ] System Restore point integration
- [ ] Session management commands
- [ ] Boot-safe recovery mode
- [ ] Quarantine folder system
- [ ] Unit tests for rollback scenarios

---

## Phase 10: User Interface (CLI & GUI)

### Objective
Build complete user interfaces for all functionality.

### Tasks

1. **Create CLI Interface** (`src/ui/cli.py`)
   ```python
   # Using argparse or click

   # Main commands:
   debloatd scan                    # Run discovery + classification
   debloatd scan --json             # Output as JSON
   debloatd scan --type services    # Scan specific module

   debloatd list                    # List all discovered components
   debloatd list --filter bloat     # Filter by classification
   debloatd list --risk high        # Filter by risk level

   debloatd plan <component_id>     # Show action plan for component
   debloatd disable <component_id>  # Disable component
   debloatd remove <component_id>   # Remove component

   debloatd sessions                # List all sessions
   debloatd undo <session_id>       # Rollback session
   debloatd undo --last             # Rollback last session

   debloatd --recovery              # Boot recovery mode
   ```

2. **Create Entry Point** (`debloatd.py`)
   ```python
   def main():
       parser = create_argument_parser()
       args = parser.parse_args()

       if args.command == "scan":
           run_scan(args)
       elif args.command == "list":
           list_components(args)
       # ... etc
   ```

3. **Build GUI Framework** (`src/ui/gui/`)
   - Use PySide6 (Qt6) for cross-platform support
   - Main window with tabbed interface

4. **Implement GUI Views**

   **Dashboard View**:
   - Bloat score summary
   - Category counts (pie chart)
   - One-click safe debloat button
   - Recent activity timeline

   **Component Tree View**:
   - Hierarchical tree (by category or publisher)
   - Expandable nodes with details
   - Filters: classification, risk, type
   - Search functionality

   **Risk Heatmap View**:
   - Grid layout by category and risk
   - Color-coded cells (green to red)
   - Click to drill down

   **Diff View**:
   - Before/after state comparison
   - Side-by-side or inline diff
   - Export capability

   **Session History View**:
   - Timeline of past sessions
   - Expandable action details
   - Per-action undo buttons

5. **Implement Component Detail Panel**
   - Component name and publisher
   - Classification badge (colored)
   - Risk level indicator
   - "Why this classification?" expandable
   - Available actions (buttons)
   - Related components list
   - Execution history

6. **Add Interaction Patterns**
   - Safe debloat: Button → Confirmation → Progress
   - Manual selection: Checkboxes → Review → Execute
   - Explain: "Why?" button → Modal with evidence
   - Undo: Per-action undo in history
   - Export: JSON/HTML report generation

7. **Implement Progress & Feedback**
   - Progress bars for scans
   - Action execution feedback
   - Error dialogs with details
   - Success notifications

### Deliverables
- [ ] Complete CLI with all commands
- [ ] JSON/text output formatting
- [ ] GUI main window framework
- [ ] Dashboard view
- [ ] Component tree view with filters
- [ ] Risk heatmap visualization
- [ ] Diff view
- [ ] Session history view
- [ ] Component detail panel
- [ ] All interaction patterns
- [ ] Export functionality (JSON/HTML)
- [ ] Integration tests for UI

---

## Testing Strategy

### Unit Tests
- Each module should have corresponding test file
- Mock Windows APIs for cross-platform testing
- Aim for >80% code coverage

### Integration Tests
- End-to-end scan tests (on Windows)
- Action execution tests (in VM)
- Rollback verification tests

### Test Data
- Create mock registry data
- Sample signature databases
- Known bloatware samples (for classification testing)

---

## Development Order Summary

| Phase | Focus | Dependencies |
|-------|-------|--------------|
| 1 | Infrastructure | None |
| 2 | Programs Scanner | Phase 1 |
| 3 | Services Scanner | Phase 1 |
| 4 | Tasks & Startup | Phase 1 |
| 5 | Drivers & Telemetry | Phase 1 |
| 6 | Signatures & Classification | Phases 2-5 |
| 7 | Heuristics & Risk | Phase 6 |
| 8 | Actions & Execution | Phase 7 |
| 9 | Rollback & Recovery | Phase 8 |
| 10 | User Interfaces | All previous |

---

## Key Technical Decisions

1. **Language**: Python 3.10+ for rapid development
2. **Windows API Access**: `pywin32` for native Windows integration
3. **GUI Framework**: PySide6 (Qt6) for professional cross-platform UI
4. **Data Validation**: Pydantic for schema validation
5. **Configuration**: JSON files with schema validation
6. **Testing**: pytest with Windows API mocking
7. **Logging**: Python logging with rotation
8. **Packaging**: PyInstaller for standalone executable

---

## Security Considerations

- All signature database updates must be cryptographically signed
- Quarantine folder has restricted ACLs (SYSTEM + Administrators only)
- No telemetry or data collection by the tool itself
- All mutations logged for auditability
- Privilege escalation handled via Windows UAC

---

*Guide Version: 1.0*
*Compatible with Specification v1.0*
