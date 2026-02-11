# Bloatware Scanner & Debloater

**Specification v0.1.0-alpha** | Status: Active Development

---

## 1. Purpose

Detect, classify, and optionally remove or neutralize non-essential software, services, tasks, and integrations that degrade system performance, privacy, or user control—without breaking core OS or hardware functionality.

### Design Principles

| Principle | Description |
|-----------|-------------|
| Determinism | Signature-based classification over heuristic guessing |
| Reversibility | Every action must be undoable; snapshots before changes |
| Evidence-backed | Classifications require documented rationale |
| Human-auditable | All decisions logged with reasoning visible to user |

---

## 2. Definitions

### Bloatware (Operational Definition)

Software or system components meeting **one or more** criteria:

- Not required for core OS stability or hardware function
- Provides secondary or marketing value (upsells, promotions)
- Installs persistent background execution without user benefit
- Enables telemetry without explicit consent
- Cannot justify its runtime cost (CPU, memory, disk, network)

---

## 3. System Architecture

```
┌─────────────────────────────────────┐
│        Scan Orchestrator            │
│   (coordinates all modules)         │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│        Discovery Modules            │
│  ┌─────────────┬─────────────┐      │
│  │ Programs    │ Services    │      │
│  │ Tasks       │ Startup     │      │
│  │ Drivers     │ UWP Apps    │      │
│  └─────────────┴─────────────┘      │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      Classification Engine          │
│  ┌─────────────────────────────┐    │
│  │ Signature DB (deterministic)│    │
│  │ Rule Engine (heuristic)     │    │
│  └─────────────────────────────┘    │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      Risk & Impact Analyzer         │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│         Action Planner              │
│   [Disable|Remove|Contain|Ignore]   │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│       Execution Engine              │
│      + Rollback Manager             │
└─────────────────────────────────────┘
```

---

## 4. Discovery Modules

### 4.1 Installed Software Scanner

**Data Sources:**
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
- MSI database (`%WINDIR%\Installer`)
- Windows Store packages (`Get-AppxPackage`)
- Portable app detection via filesystem heuristics

**Metadata Collected:**

| Field | Source | Required |
|-------|--------|----------|
| `display_name` | Registry/manifest | Yes |
| `publisher` | Registry/manifest | Yes |
| `install_date` | Registry | No |
| `install_path` | Registry/filesystem | Yes |
| `size_bytes` | Calculated | Yes |
| `executables[]` | Filesystem scan | Yes |
| `update_mechanism` | Heuristic detection | No |
| `uninstall_string` | Registry | Yes |

### 4.2 Services Scanner

**Enumeration Method:** `Get-Service` + WMI `Win32_Service`

**Metadata Collected:**

| Field | Source | Required |
|-------|--------|----------|
| `service_name` | SCM | Yes |
| `display_name` | SCM | Yes |
| `start_type` | SCM (Auto/Manual/Disabled/Boot) | Yes |
| `binary_path` | Registry | Yes |
| `account_context` | SCM (LocalSystem/NetworkService/etc) | Yes |
| `network_access` | Firewall rules + port scan | No |
| `restart_behavior` | Recovery options | No |
| `dependencies[]` | SCM | Yes |

### 4.3 Scheduled Tasks Scanner

**Enumeration Method:** `Get-ScheduledTask` + Task Scheduler COM

**Metadata Collected:**

| Field | Source | Required |
|-------|--------|----------|
| `task_name` | Scheduler | Yes |
| `task_path` | Scheduler | Yes |
| `trigger_type` | XML definition | Yes |
| `execution_frequency` | Calculated from triggers | Yes |
| `action_path` | XML definition | Yes |
| `is_hidden` | Task flags | Yes |
| `is_self_healing` | Heuristic (reinstall patterns) | No |
| `author` | XML definition | No |

### 4.4 Startup Entries Scanner

**Data Sources:**
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
- `%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
- Shell extensions (`HKCR\*\shellex`)
- Winlogon hooks (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`)

**Metadata Collected:**

| Field | Source | Required |
|-------|--------|----------|
| `entry_name` | Registry/folder | Yes |
| `entry_type` | (Run/RunOnce/Shell/Winlogon) | Yes |
| `target_path` | Registry value | Yes |
| `arguments` | Registry value | No |
| `scope` | (Machine/User) | Yes |

### 4.5 Drivers & Helpers Scanner

**Scope:**
- Kernel drivers not signed by Microsoft
- User-mode helper services
- Overlay injectors (DLL injection patterns)

**Enumeration Method:** `driverquery /v` + `Get-WindowsDriver`

**Metadata Collected:**

| Field | Source | Required |
|-------|--------|----------|
| `driver_name` | System | Yes |
| `driver_type` | (Kernel/Filesystem/User) | Yes |
| `signer` | Catalog signature | Yes |
| `associated_hardware` | PnP device mapping | No |
| `load_order` | Registry | No |

### 4.6 Telemetry & Network Hooks Scanner

**Detection Methods:**
- Known telemetry endpoint list (hosts file candidates)
- Persistent socket enumeration (`netstat -b`)
- Background web helper process identification

**Metadata Collected:**

| Field | Source | Required |
|-------|--------|----------|
| `process_name` | Netstat/handle | Yes |
| `remote_endpoints[]` | Socket enumeration | Yes |
| `connection_type` | (Persistent/Periodic) | No |
| `bytes_transferred` | Performance counters | No |

---

## 5. Classification Engine

### 5.1 Classification Levels

| Level | Code | Meaning | Default Action |
|-------|------|---------|----------------|
| Core | `CORE` | Required for OS or hardware function | Locked (no action) |
| Essential | `ESSENTIAL` | User-facing critical functionality | Warn before action |
| Optional | `OPTIONAL` | Legitimate but nonessential | User choice |
| Bloat | `BLOAT` | Safe to disable/remove | Recommend disable |
| Aggressive Bloat | `AGGRESSIVE` | Actively harmful to UX/privacy | Recommend remove |
| Unknown | `UNKNOWN` | Insufficient data for classification | Manual review |

### 5.2 Signature Database Schema

```json
{
  "signature_id": "string (UUID)",
  "publisher": "string",
  "component_name": "string",
  "component_type": "enum (program|service|task|startup|driver|uwp)",
  "match_rules": {
    "name_pattern": "regex",
    "publisher_pattern": "regex",
    "path_pattern": "regex",
    "hash_sha256": ["string"]
  },
  "classification": "enum (CORE|ESSENTIAL|OPTIONAL|BLOAT|AGGRESSIVE)",
  "related_components": ["signature_id"],
  "safe_actions": ["enum (disable|remove|contain)"],
  "unsafe_actions": ["enum (disable|remove|contain)"],
  "reinstall_behavior": "enum (none|self_healing|update_restored)",
  "breakage_notes": "string",
  "evidence_url": "string",
  "last_updated": "ISO8601 date"
}
```

**Example Signature:**

```json
{
  "signature_id": "nvidia-telemetry-001",
  "publisher": "NVIDIA Corporation",
  "component_name": "NVIDIA Telemetry Container",
  "component_type": "service",
  "match_rules": {
    "name_pattern": "^NvTelemetry.*",
    "publisher_pattern": "NVIDIA",
    "path_pattern": ".*\\\\NVIDIA Corporation\\\\NvTelemetry\\\\.*"
  },
  "classification": "BLOAT",
  "related_components": ["nvidia-driver-core"],
  "safe_actions": ["disable"],
  "unsafe_actions": ["remove"],
  "reinstall_behavior": "update_restored",
  "breakage_notes": "Removing may break driver update process. Disable only.",
  "evidence_url": "https://example.com/nvidia-telemetry-analysis",
  "last_updated": "2025-01-15"
}
```

### 5.3 Rule-Based Heuristics

Heuristic flags produce **confidence scores** (0.0–1.0), not final decisions.

| Flag | Weight | Condition |
|------|--------|-----------|
| `AUTOSTART_NO_UI` | 0.3 | Auto-starts but has no visible interface |
| `NETWORK_NO_VALUE` | 0.4 | Network access without clear user benefit |
| `SELF_HEALING` | 0.5 | Reinstalls itself after removal |
| `ACCOUNT_REQUIRED` | 0.3 | Requires account login for local functionality |
| `BUNDLED_UNRELATED` | 0.4 | Bundled with unrelated driver/software |
| `TELEMETRY_PATTERN` | 0.6 | Matches known telemetry behavior patterns |
| `OVERLAY_INJECTOR` | 0.5 | Injects into other processes |

**Scoring Formula:**
```
bloat_score = sum(triggered_weights) / sum(all_weights)
if bloat_score >= 0.6: suggest BLOAT
if bloat_score >= 0.8: suggest AGGRESSIVE
else: suggest UNKNOWN (manual review)
```

---

## 6. Risk & Impact Analyzer

### 6.1 Impact Dimensions

Each component evaluated across five dimensions:

| Dimension | Description | Assessment Method |
|-----------|-------------|-------------------|
| Boot Stability | Can removal prevent boot? | Dependency chain analysis |
| Hardware Function | Required for device operation? | PnP device association |
| Update Pipeline | Part of Windows Update chain? | Service dependency mapping |
| Security Surface | Provides security functionality? | Known security component list |
| User Experience | Visible user-facing feature? | UI element detection |

### 6.2 Risk Matrix

| Risk Level | Code | Criteria | UI Indicator |
|------------|------|----------|--------------|
| None | `NONE` | No dependencies, isolated component | Green |
| Low | `LOW` | Optional feature, easily restored | Light green |
| Medium | `MEDIUM` | Has dependents, available via reinstall | Yellow |
| High | `HIGH` | System feature, complex restoration | Orange |
| System-Critical | `CRITICAL` | Boot/security/hardware required | Red (locked) |

### 6.3 Risk Calculation

```
risk_level = max(
  boot_stability_risk,
  hardware_function_risk,
  update_pipeline_risk,
  security_surface_risk,
  user_experience_risk
)
```

---

## 7. Action Planner

### 7.1 Supported Actions

| Action | Code | Description | Reversibility |
|--------|------|-------------|---------------|
| Disable | `DISABLE` | Stop service/task/startup; prevent auto-start | Full (re-enable) |
| Contain | `CONTAIN` | Firewall block, ACL deny, execution prevention | Full (remove rules) |
| Remove | `REMOVE` | Uninstall via native method or delete files | Partial (reinstall) |
| Ignore | `IGNORE` | Mark reviewed, take no action | N/A |

### 7.2 Action Implementation Details

**DISABLE:**
```powershell
# Services
Set-Service -Name $serviceName -StartupType Disabled
Stop-Service -Name $serviceName -Force

# Scheduled Tasks
Disable-ScheduledTask -TaskPath $taskPath -TaskName $taskName

# Startup entries
# Registry: rename key or set value to empty
# Folder: move to quarantine directory
```

**CONTAIN:**
```powershell
# Firewall block (outbound)
New-NetFirewallRule -DisplayName "Bloat-Block-$name" `
  -Direction Outbound -Program $exePath -Action Block

# ACL deny execution
$acl = Get-Acl $exePath
$denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
  "Everyone", "ExecuteFile", "Deny"
)
$acl.AddAccessRule($denyRule)
Set-Acl $exePath $acl
```

**REMOVE:**
```powershell
# MSI-based
msiexec /x $productCode /quiet /norestart

# UWP/Store apps
Remove-AppxPackage -Package $packageFullName

# Registry-based uninstall
Start-Process -FilePath $uninstallString -ArgumentList "/S" -Wait
```

### 7.3 Safety Rules (Enforced)

| Rule | Implementation |
|------|----------------|
| Core components are read-only | `CORE` classification blocks all actions |
| Driver helpers: disable-first | Force `DISABLE` before `REMOVE` allowed |
| OEM tools: staged removal | Require `DISABLE` + 7-day wait before `REMOVE` |
| Store apps: reversible | Log package name for reinstall command |
| No batch remove without confirmation | Batch operations require explicit user approval |

---

## 8. Execution Engine

### 8.1 Execution Model

- **Transactional:** Each action wrapped in try/catch with rollback
- **Sequential:** One component at a time (no parallel mutations)
- **Logged:** Every action recorded with timestamp and result

### 8.2 Pre-Action Snapshot

Before any mutating action:

```json
{
  "snapshot_id": "UUID",
  "timestamp": "ISO8601",
  "component_id": "string",
  "action": "enum",
  "captured_state": {
    "registry_keys": [ ],
    "service_config": { },
    "task_definition": { },
    "file_hashes": { },
    "acl_state": { }
  }
}
```

### 8.3 Execution Modes

| Mode | Description | Mutations |
|------|-------------|-----------|
| `SCAN_ONLY` | Discovery and classification only | None |
| `DRY_RUN` | Generate action plan, no execution | None |
| `INTERACTIVE` | Prompt before each action | Per-approval |
| `BATCH_CONFIRM` | Confirm batch, execute all | After approval |

**Default mode:** `DRY_RUN` (mandatory first run)

---

## 9. Rollback & Recovery

### 9.1 Automatic Restore Points

- Create Windows System Restore point before any batch operation
- Named: `Debloat-Session-{timestamp}`

### 9.2 Component-Level Undo

```powershell
# Undo registry change
Restore-RegistryKey -SnapshotId $snapshotId

# Re-enable service
Set-Service -Name $serviceName -StartupType $originalStartType

# Restore file from quarantine
Move-Item -Path "$quarantine\$file" -Destination $originalPath
```

### 9.3 Session Management

| Command | Function |
|---------|----------|
| `List-DebloatSessions` | Show all sessions with timestamps |
| `Get-SessionActions -Id $id` | List all actions in session |
| `Undo-SessionAction -Id $id -ActionId $aid` | Rollback single action |
| `Undo-Session -Id $id` | Rollback entire session (reverse order) |

### 9.4 Boot-Safe Recovery

If system fails to boot after debloat:

1. Boot to Safe Mode
2. Run: `debloatd --recovery --last-session`
3. Automatic rollback of most recent session

---

## 10. User Interface Requirements

### 10.1 Views

| View | Purpose | Components |
|------|---------|------------|
| Dashboard | Summary stats and quick actions | Bloat score, category counts, one-click safe debloat |
| Component Tree | Hierarchical browse all discovered items | Expandable tree, filters, search |
| Risk Heatmap | Visual risk distribution | Color-coded grid by category and risk |
| Diff View | Before/after comparison | Side-by-side state comparison |
| Session History | Past debloat sessions | Timeline with undo options |

### 10.2 Component Detail Panel

Required elements:
- Component name and publisher
- Classification badge with color
- Risk level indicator
- "Why this classification?" expandable (signature or heuristic source)
- Available actions (filtered by safety rules)
- Related components list
- Execution history for this component

### 10.3 Interaction Patterns

| Action | UI Pattern |
|--------|------------|
| Safe debloat (one-click) | Single button → confirmation dialog → progress |
| Manual selection | Checkbox per component → review panel → execute |
| Explain classification | "Why?" button → modal with evidence |
| Undo action | Per-action undo button in history |
| Export report | Generate JSON/HTML summary |

---

## 11. Security & Trust Model

### 11.1 Operational Principles

| Principle | Implementation |
|-----------|----------------|
| Offline-capable | Full functionality without network |
| No cloud dependency | All classification local; cloud optional for updates |
| Signed updates | Signature database updates require valid signature |
| No silent actions | Every mutation requires explicit user trigger |
| No self-telemetry | Tool collects zero usage data by default |

### 11.2 Privilege Model

| Operation | Required Privilege |
|-----------|-------------------|
| Scan | Standard user (limited) or Admin (full) |
| Disable service | Administrator |
| Remove program | Administrator |
| Modify startup | Administrator (HKLM) or User (HKCU) |
| Create restore point | Administrator |

### 11.3 Integrity Checks

- Signature database: SHA256 hash verified on load
- Rule updates: Signed with release key
- Quarantine folder: ACL restricted to SYSTEM and Administrators

---

## 12. Extensibility

### 12.1 Plugin Interfaces

| Interface | Purpose | Method |
|-----------|---------|--------|
| `IDiscoveryModule` | Add custom discovery sources | DLL plugin |
| `IClassificationProvider` | Additional signature sources | JSON feed URL |
| `IActionHandler` | Custom action implementations | DLL plugin |
| `ISignatureProvider` | Additional signature sources | JSON feed URL |

### 12.2 Configuration Profiles

```json
{
  "profile_name": "Enterprise-Strict",
  "description": "Aggressive debloat for managed workstations",
  "auto_classify_unknown_as": "BLOAT",
  "allowed_actions": ["DISABLE", "CONTAIN"],
  "blocked_publishers": ["Contoso"],
  "protected_components": ["CompanyVPN", "MDMAgent"],
  "require_approval_above_risk": "LOW"
}
```

### 12.3 Signature Feed Format

External feeds must provide:
- HTTPS endpoint
- JSON array of signature objects
- Valid cryptographic signature
- Version number for differential updates

---

## 13. Development Phases

| Phase | Grade | Features | Scope |
|-------|-------|----------|-------|
| 1 | Sketch | Scanner + JSON output | Discovery modules only |
| 2 | Garage | + Disable + Rollback | Core actions |
| 3 | Shop | + OEM profiles + expanded signatures | Full classification |
| 4 | Industrial | + Fleet policies + CI image integration | Enterprise |

### Phase 1 Deliverables (Sketch Grade)
- [ ] Installed software scanner
- [ ] Services scanner
- [ ] Scheduled tasks scanner
- [ ] Startup entries scanner
- [ ] JSON report output
- [ ] Basic CLI interface

### Phase 2 Deliverables (Garage Grade)
- [ ] Signature database loader
- [ ] Classification engine (signatures only)
- [ ] Disable action implementation
- [ ] Snapshot/rollback system
- [ ] Basic GUI (component list + actions)

### Phase 3 Deliverables (Shop Grade)
- [ ] Full heuristic rule engine
- [ ] Risk analyzer
- [ ] OEM profile support
- [ ] Complete GUI with all views
- [ ] Session management
- [ ] Expanded signature database (150+)

---

## 14. Explicit Non-Goals

This tool intentionally does **not**:

- Replace antivirus/antimalware software
- Perform registry "cleaning" or "optimization"
- Apply performance placebo tweaks
- Make silent/unattended system modifications
- Guarantee removal of all bloatware
- Provide real-time protection

---

## 15. File & Directory Structure

```
debloatd/
├── src/
│   ├── core/
│   │   ├── orchestrator.py
│   │   ├── snapshot.py
│   │   └── rollback.py
│   ├── discovery/
│   │   ├── programs.py
│   │   ├── services.py
│   │   ├── tasks.py
│   │   ├── startup.py
│   │   ├── drivers.py
│   │   └── telemetry.py
│   ├── classification/
│   │   ├── engine.py
│   │   ├── signatures.py
│   │   └── heuristics.py
│   ├── analysis/
│   │   └── risk.py
│   ├── actions/
│   │   ├── planner.py
│   │   ├── disable.py
│   │   ├── contain.py
│   │   ├── remove.py
│   │   └── executor.py
│   └── ui/
│       ├── cli.py
│       └── gui/
├── data/
│   ├── signatures/
│   │   └── default.json
│   └── profiles/
│       └── default.json
├── tests/
├── docs/
└── debloatd.py (entry point)
```

---

## 16. Technical Requirements

| Requirement | Specification |
|-------------|---------------|
| Platform | Windows 10 (1903+), Windows 11 |
| Runtime | Python 3.10+ or compiled executable |
| Privileges | Standard user (scan) / Administrator (actions) |
| Dependencies | pywin32, psutil, winreg (stdlib) |
| GUI Framework | Qt6 (PySide6) or tkinter |
| Storage | ~50MB base + signature database |

---

## Appendix A: Common Bloatware Signatures (Starter Set)

| Publisher | Component | Classification | Safe Action |
|-----------|-----------|----------------|-------------|
| Microsoft | Cortana | BLOAT | DISABLE |
| Microsoft | Xbox Game Bar | OPTIONAL | DISABLE |
| Microsoft | OneDrive (preinstalled) | OPTIONAL | DISABLE |
| Microsoft | Teams (personal) | BLOAT | REMOVE |
| HP | HP Support Assistant | BLOAT | REMOVE |
| Dell | Dell SupportAssist | BLOAT | REMOVE |
| Lenovo | Lenovo Vantage | OPTIONAL | DISABLE |
| NVIDIA | NVIDIA Telemetry | BLOAT | DISABLE |
| Intel | Intel Driver Update Utility | BLOAT | REMOVE |
| McAfee | McAfee LiveSafe (trial) | AGGRESSIVE | REMOVE |
| Norton | Norton Security (trial) | AGGRESSIVE | REMOVE |

---

*Specification version: 0.1.0-alpha*
*Last updated: 2026-02-11*
*Target implementation: Shop Grade*
