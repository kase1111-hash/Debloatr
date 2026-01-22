# Changelog

All notable changes to Debloatr will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Project documentation (CONTRIBUTING.md, SECURITY.md, issue templates)

## [0.1.0] - 2025-01-16

### Added

#### Core Infrastructure (Phase 1)
- Project structure with modular architecture
- Core data models: `ComponentType`, `Classification`, `RiskLevel`, `ActionType`
- `Component` dataclass for representing discovered system components
- Configuration management system with profile support
- Logging infrastructure

#### Discovery Modules (Phases 2-5)
- **Installed Software Scanner** - Detects programs from Windows Registry, MSI database, and UWP packages
- **Windows Services Scanner** - Enumerates services with metadata (start type, account context, dependencies)
- **Scheduled Tasks Scanner** - Discovers scheduled tasks with trigger and execution details
- **Startup Entries Scanner** - Finds startup entries from Registry and startup folders
- **Drivers Scanner** - Identifies kernel and user-mode drivers with signature verification
- **Telemetry Scanner** - Detects background processes with network activity

#### Classification System (Phases 6-7)
- Signature database with 55+ predefined bloatware signatures
- Signature matching engine for deterministic classification
- Heuristic rules engine with confidence scoring
- Optional LLM integration layer for advisory analysis
- Risk analyzer evaluating boot stability, hardware function, and security impact

#### Action System (Phase 8)
- Action planner with safety rules enforcement
- Execution engine with transactional model
- Disable handler for services, tasks, and startup entries
- Remove handler for uninstallation
- Contain handler for firewall and ACL-based isolation

#### Rollback & Recovery (Phase 9)
- Pre-action snapshot system capturing full component state
- Per-action undo operations
- Full session rollback (reverse order execution)
- Windows system restore point integration
- Boot-safe recovery mode

#### User Interfaces (Phase 10)
- **CLI Interface** with commands:
  - `scan` - Run system scan
  - `list` - List discovered components with filters
  - `plan` - Show action plan for a component
  - `disable` / `remove` - Execute actions
  - `sessions` - List debloat sessions
  - `undo` - Rollback actions
  - `recovery` - Boot recovery mode
  - `config` - Manage configuration
- **GUI Interface** (PySide6/Qt6):
  - Dashboard with scan statistics
  - Component tree browser with filters and search
  - Risk heatmap visualization
  - Before/after diff view
  - Session history with undo options

#### Data Files
- Default signature database covering Microsoft, HP, Dell, Lenovo, NVIDIA, Intel, McAfee, and Norton components
- Default configuration profile (balanced settings)

### Technical Details
- Python 3.10+ required
- Windows 10 (1903+) and Windows 11 supported
- Dependencies: pywin32, psutil, pydantic
- Optional: PySide6 for GUI

[Unreleased]: https://github.com/debloatr/debloatr/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/debloatr/debloatr/releases/tag/v0.1.0
