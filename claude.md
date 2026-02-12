# Claude.md - Debloatr Development Guide

## Project Overview

Debloatr is a Windows bloatware scanner and debloater tool that detects, classifies, and safely removes non-essential software, services, tasks, and system components. The tool prioritizes **determinism**, **reversibility**, and **safety** over aggressive optimization.

**Target Platform:** Windows 10 (1903+) and Windows 11
**Language:** Python 3.10+
**Current Phase:** Shop Grade (Phase 3 of 4)

## Core Design Principles

1. **Determinism** - Signature-based classification over heuristic guessing
2. **Reversibility** - Every action is undoable through snapshots and rollback
3. **Evidence-backed** - All classifications require documented rationale
4. **Human-auditable** - All decisions logged and visible to users
5. **Safety-first** - CORE components are locked; ESSENTIAL requires confirmation

## Architecture

```
Scan Orchestrator (src/core/orchestrator.py)
    ↓
Discovery Modules (src/discovery/*.py)
    ↓
Classification Engine (src/classification/engine.py)
    ↓
Risk Analyzer (src/analysis/risk.py)
    ↓
Action Planner (src/actions/planner.py)
    ↓
Execution Engine (src/actions/executor.py)
    ↓
Rollback Manager (src/core/rollback.py)
```

## Key Directories and Files

| Path | Purpose |
|------|---------|
| `src/core/` | Core infrastructure: models, orchestrator, config, session, snapshot, rollback |
| `src/discovery/` | 6 discovery modules: programs, services, tasks, startup, drivers, telemetry |
| `src/classification/` | Classification engine, signature database, heuristics |
| `src/analysis/` | Risk assessment (5 dimensions) |
| `src/actions/` | Action handlers: planner, executor, disable, remove, contain |
| `src/ui/cli/` | Command-line interface |
| `src/ui/gui/` | PySide6/Qt6 GUI |
| `data/signatures/` | Bloatware signature definitions (default: 51, expanded: 152) |
| `data/profiles/` | Configuration profiles |
| `tests/` | 18 test modules with 100+ test cases |
| `debloatd.py` | Main entry point |

## Important Models (src/core/models.py)

- **ComponentType**: PROGRAM, SERVICE, TASK, STARTUP, DRIVER, TELEMETRY
- **Classification**: CORE, ESSENTIAL, OPTIONAL, BLOAT, AGGRESSIVE, UNKNOWN
- **RiskLevel**: NONE, LOW, MEDIUM, HIGH, CRITICAL
- **ActionType**: DISABLE, CONTAIN, REMOVE, REPLACE, IGNORE

## Commands

```bash
# Development setup
pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -e .

# Code quality
black src tests          # Format
ruff check src tests     # Lint
mypy src                 # Type check

# Testing
pytest                   # Run all tests
pytest --cov=src         # With coverage
pytest tests/test_*.py   # Specific tests
pytest -v                # Verbose

# CLI usage
debloatd scan            # Scan system
debloatd list --filter bloat  # List bloatware
debloatd plan <id>       # Show action plan
debloatd --gui           # Launch GUI
```

## Code Style

- **Formatter:** Black (line length 100)
- **Linter:** Ruff
- **Type Checking:** mypy (strict mode)
- Use type hints for all function signatures
- Follow existing patterns in the codebase
- Keep functions focused and single-purpose

## Safety Rules for Code Changes

### Critical Safety Constraints

1. **Never auto-execute actions without user confirmation** - All mutations require explicit approval
2. **CORE components are read-only** - Never allow modifications to CORE-classified items
3. **ESSENTIAL requires confirmation** - Always prompt before acting on ESSENTIAL components
4. **CRITICAL risk blocks all actions** - Components with CRITICAL risk cannot be modified
5. **Snapshots before mutations** - Always create a snapshot before any state-changing operation
6. **Transactional execution** - Wrap actions in transactions with rollback capability

### Protected Component Patterns

Do not allow removal/disable of components matching:
- `ntoskrnl`, `hal.dll`, `winlogon`, `csrss`, `smss`, `wininit`
- `services.exe`, `lsass`, `svchost` (core instances)
- Boot-critical drivers and services
- Windows Update components (`wuauserv`, `UsoSvc`)
- Security components (Windows Defender, Firewall)

## Testing Requirements

- All new features must have corresponding tests
- Maintain test coverage for critical paths
- Use `conftest.py` fixtures for common test setup
- Mock Windows APIs when testing on non-Windows platforms
- Test both success and failure scenarios

## Common Development Tasks

### Adding a New Discovery Module

1. Create new file in `src/discovery/`
2. Inherit from `DiscoveryModule` base class in `src/discovery/base.py`
3. Implement `discover()` method returning `List[DiscoveredComponent]`
4. Register in orchestrator's module list
5. Add corresponding tests in `tests/`

### Adding a New Bloatware Signature

1. Edit `data/signatures/default.json`
2. Include: `name`, `patterns`, `classification`, `rationale`, `evidence_urls`
3. Patterns support regex matching against component names/paths
4. Test signature matching in `tests/test_signatures.py`

### Adding a New Action Handler

1. Create handler in `src/actions/`
2. Implement `execute()` and `undo()` methods
3. Register action type in `ActionType` enum
4. Update planner safety rules if needed
5. Add snapshot integration for rollback support

## Error Handling

- Use specific exception types from `src/core/exceptions.py`
- Log errors with appropriate severity levels
- Never silently swallow exceptions in action execution
- Provide actionable error messages for users
- Include component context in error logs

## Configuration

- User config stored in `%APPDATA%/Debloatr/config.json`
- Session data in `%APPDATA%/Debloatr/sessions/`
- Snapshots in `%APPDATA%/Debloatr/snapshots/`
- Quarantine in `%APPDATA%/Debloatr/quarantine/` (ACL-protected)

## What NOT to Do

- Do NOT replace antivirus/antimalware functionality
- Do NOT perform registry "cleaning" or optimization
- Do NOT apply performance placebo tweaks
- Do NOT make silent/unattended modifications
- Do NOT bypass user confirmation for risky operations
- Do NOT modify boot-critical components under any circumstances

## Dependencies

**Core:** pywin32 (305+), psutil (5.9.0+), pydantic (2.0+)
**GUI:** PySide6 (optional)
**Dev:** pytest, pytest-cov, pytest-mock, black, ruff, mypy

## Documentation

- `README.md` - Complete specification
- `CONTRIBUTING.md` - Contribution guidelines
- `CODING_GUIDE.md` - 10-phase development breakdown
- `SECURITY.md` - Security policies and privilege model
- `AUDIT_REPORT.md` - Software correctness audit
- `EVALUATION_REPORT.md` - Project evaluation report
- `REFOCUS_PLAN.md` - Strategic refocus plan
- `CHANGELOG.md` - Version history
