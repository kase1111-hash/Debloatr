# Dependency Audit & Reduction Report

**Project:** Debloatr
**Date:** 2026-03-12
**Auditor:** Automated (Dependency Audit v1.0)

---

## Summary

| Metric | Before | After |
|--------|--------|-------|
| Direct runtime dependencies | 3 | 0 |
| Optional runtime dependencies | 1 | 1 |
| Dev dependencies | 8 | 7 |
| Build dependencies | 2 | 2 |
| Removed | — | 4 |
| Replaced with stdlib | — | 1 |
| Transitive deps eliminated | — | ~8 (pywin32 tree, psutil, pydantic-core, annotated-types, typing-extensions, typing-inspection) |

**The project now has zero mandatory runtime dependencies.** All functionality is implemented using the Python standard library and subprocess calls to Windows system utilities.

---

## Dependency Table

### Runtime Dependencies

| Dependency | Version | Classification | Usage | Action |
|---|---|---|---|---|
| **pywin32** | >=305 | DEAD | Never imported. Codebase uses stdlib `winreg`. | **Removed** |
| **psutil** | >=5.9.0 | DEAD | Never imported. Uses PowerShell/subprocess for system info. | **Removed** |
| **pydantic** | >=2.0 | REPLACEABLE | 1 file (`session.py`), 2 simple schema classes, 1 `model_validate` call. | **Replaced with stdlib** |

### Optional Dependencies

| Dependency | Version | Classification | Usage | Action |
|---|---|---|---|---|
| **PySide6** | >=6.5.0 (gui extra) | ESSENTIAL | Pervasive in `src/ui/gui/main.py` (32 Qt classes imported, 8 widget classes defined). Properly gated behind optional extra with lazy loading. | Kept |

### Dev Dependencies

| Dependency | Version | Classification | Usage | Action |
|---|---|---|---|---|
| **pytest** | >=7.0.0 | ESSENTIAL | 21 test files, extensive fixture usage. | Kept |
| **pytest-cov** | >=4.0.0 | JUSTIFIED | Coverage reporting in CI and local dev. | Kept |
| **pytest-mock** | >=3.10.0 | DEAD | `mocker` fixture never used (0 matches). All tests use `unittest.mock`. | **Removed** |
| **black** | >=23.0.0 | JUSTIFIED | Formatting enforced in CI. Configured in `pyproject.toml`. | Kept |
| **ruff** | >=0.1.0 | JUSTIFIED | Linting enforced in CI. 7 rule categories configured. | Kept |
| **mypy** | >=1.0.0 | JUSTIFIED | Type checking with strict config. Type annotations used throughout. | Kept |
| **bandit** | >=1.7.0 | JUSTIFIED | Security scanning in CI workflow. | Kept |
| **pip-audit** | >=2.6.0 | JUSTIFIED | Dependency vulnerability scanning in CI workflow. | Kept |

### Build Dependencies

| Dependency | Version | Classification | Usage | Action |
|---|---|---|---|---|
| **setuptools** | >=61.0 | ESSENTIAL | Build backend. | Kept |
| **wheel** | (unpinned) | ESSENTIAL | Wheel building. | Kept |

---

## Changes Made

### 1. Removed `pywin32` (DEAD)

**What:** Removed `pywin32>=305` from `dependencies` in `pyproject.toml` and `requirements.txt`.

**Why:** Exhaustive search found zero imports of any pywin32 module (`win32api`, `win32com`, `win32con`, `win32gui`, `win32process`, `win32security`, `win32service`, `pywintypes`, etc.). All Windows registry access uses the **stdlib `winreg` module** (available on all Windows Python installations without additional packages). The dependency was likely added speculatively during initial project setup.

**Files modified:** `pyproject.toml`, `requirements.txt`
**Risk:** NONE
**Test results:** 460 passed, 35 skipped

### 2. Removed `psutil` (DEAD)

**What:** Removed `psutil>=5.9.0` from `dependencies` in `pyproject.toml` and `requirements.txt`.

**Why:** Exhaustive search found zero imports of `psutil` anywhere in the source code. The project gathers system information through alternative means:
- PowerShell commands (`Get-CimInstance`, `Get-ScheduledTask`, `Get-NetTCPConnection`)
- Windows CLI tools via subprocess (`netstat`, `driverquery`, `sc.exe`, `schtasks`)
- Stdlib `winreg` for registry queries

The dependency was listed but never integrated.

**Files modified:** `pyproject.toml`, `requirements.txt`
**Risk:** NONE
**Test results:** 460 passed, 35 skipped

### 3. Removed `pytest-mock` (DEAD)

**What:** Removed `pytest-mock>=3.10.0` from `dev` dependencies in `pyproject.toml`, `requirements.txt`, and `requirements-dev.txt`.

**Why:** The `mocker` fixture (pytest-mock's primary API) has zero usages across all 21 test files. All mocking is done via `unittest.mock` (`patch`, `MagicMock`, `Mock`), which is part of Python's standard library.

**Files modified:** `pyproject.toml`, `requirements.txt`, `requirements-dev.txt`
**Risk:** NONE
**Test results:** 460 passed, 35 skipped

### 4. Replaced `pydantic` with stdlib validation (REPLACEABLE)

**What:** Removed `pydantic>=2.0` from `dependencies` and replaced its usage in `src/core/session.py` with two stdlib validation functions (`_validate_session_file`, `_validate_session_action`).

**Why:** Pydantic was used in a single file for 2 simple flat schema classes (`SessionActionSchema`, `SessionFileSchema`) and one `model_validate()` call. This minimal usage pulled in 4 transitive dependencies:
- `pydantic-core` (compiled Rust binary, ~5MB)
- `annotated-types`
- `typing-extensions`
- `typing-inspection`

The replacement is ~45 lines of straightforward type-checking code that validates dict keys and types. The schemas are simple flat structures with no nested complexity, custom validators, or serialization logic — exactly the case where a stdlib replacement is appropriate.

**Files modified:** `src/core/session.py`, `pyproject.toml`, `requirements.txt`
**Replacement code:** Two functions that check required keys exist with correct types, optional fields are `str | None`, and nested action objects are validated individually. Raises `ValueError` (caught the same way `ValidationError` was).
**Risk:** LOW — schemas are flat with basic type checks only
**Test results:** 460 passed, 35 skipped

### 5. Synced requirements files

**What:** Updated `requirements.txt` and `requirements-dev.txt` to match `pyproject.toml`, added missing `bandit` and `pip-audit` to both, removed `pre-commit` (not in pyproject.toml, no `.pre-commit-config.yaml` found).

**Files modified:** `requirements.txt`, `requirements-dev.txt`

---

## Kept With Reservations

### black + ruff overlap

Both `black` (formatter) and `ruff` (linter) are kept. Ruff can also format code (`ruff format`), which would make `black` redundant. However:
- Both are lightweight and well-maintained
- The project explicitly uses both in CI with separate roles
- Consolidating to `ruff format` would require CI config changes and team alignment
- **Future consideration:** Migrate formatting to `ruff format` and drop `black`

### PySide6 (optional)

PySide6 is a heavy dependency (~150MB installed) but is properly isolated:
- Listed as an optional extra (`pip install debloatr[gui]`)
- Lazy-loaded with graceful ImportError handling
- Only one source file depends on it
- No lighter Qt alternative exists for the functionality provided

---

## Health Warnings

| Dependency | Status | Notes |
|---|---|---|
| **PySide6** | Active | Maintained by Qt Company. Large footprint but optional. No CVEs. LGPL-3.0 license — compatible with CC0-1.0 project license. |
| **pytest** | Active | Latest: 9.0.2 (Jan 2026). No issues. |
| **pytest-cov** | Active | Latest: 7.0.0. No issues. |
| **black** | Active | Latest: 25.x. No issues. |
| **ruff** | Active | Latest: 0.9.x. Very actively maintained by Astral. |
| **mypy** | Active | Latest: 1.15.x. No issues. |
| **bandit** | Active | Latest: 1.8.x. No issues. |
| **pip-audit** | Active | Latest: 2.9.x. Maintained by Google/PyPA. |
| **setuptools** | Active | Latest: 76.x. Core Python packaging tool. |

No dependencies have known CVEs, abandonment risk, or license incompatibilities.

---

## Final Status

**LEANER** — 4 dependencies removed (3 dead, 1 replaced with ~45 lines of stdlib code). Zero mandatory runtime dependencies remain. ~8 transitive dependencies eliminated. All 460 tests pass with no functional impact.
