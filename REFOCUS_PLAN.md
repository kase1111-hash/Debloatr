# REFOCUS PLAN

Based on the [Evaluation Report](./EVALUATION_REPORT.md). Three phases, ordered by impact. Each phase must be completed and validated before starting the next.

---

## PHASE 1: SURGERY — Remove dead weight, fix lies (est. ~2 hours of changes)

**Goal:** Make the codebase honest about what it can and cannot do. Remove every reference to unimplemented features. Fix version numbers. Eliminate false confidence.

### 1.1 Remove all LLM references

The LLM layer was never built. Every reference to it creates a false promise. Remove it entirely — if it's wanted later, it belongs in a plugin.

**Files to modify:**

| File | Lines | Change |
|------|-------|--------|
| `src/classification/engine.py` | 4, 31, 73 | Remove `LLM = "llm"` from `ClassificationSource` enum. Update docstrings to say "two-tier" (signatures + heuristics), not "three-tier". |
| `src/core/config.py` | 56-58, 165-166, 222-224 | Remove `use_llm`, `llm_endpoint`, `llm_api_key` from `ClassificationConfig`. Remove from `to_dict()` and `from_dict()`. |
| `src/core/logging_config.py` | 4, 30, 96, 140-151, 170, 210, 261-278 | Remove `_setup_llm_logger()` method. Remove call on line 96. Remove `log_llm_query()` function. Remove LLM from docstrings and comments. |
| `src/core/models.py` | 170, 178 | Remove `"llm"` from the `source` field comment. Update to `"signature", "heuristic", "none"`. |
| `tests/test_engine.py` | 27 | Remove or update the `ClassificationSource.LLM` assertion. |
| `tests/test_config.py` | 64-65 | Remove `assert config.use_llm is False` and `assert config.llm_endpoint == ""`. |

### 1.2 Remove REPLACE action from executor

The action type enum can stay (it's part of the data model), but the executor should not pretend it's in progress.

**Files to modify:**

| File | Lines | Change |
|------|-------|--------|
| `src/actions/executor.py` | 354-360 | Change the REPLACE branch to raise `NotImplementedError("REPLACE action is not supported in this version")` instead of silently returning a failed result. This makes it explicit. |

### 1.3 Fix version mismatch

**Files to modify:**

| File | Line | Change |
|------|------|--------|
| `debloatd.py` | 29 | Change `version="%(prog)s 1.0.0"` to `version="%(prog)s 0.1.0-alpha"` |
| `AUDIT_REPORT.md` | 5 | Change `**Software Version:** 1.0.0` to `**Software Version:** 0.1.0-alpha` |

### 1.4 Disable portable app scanning by default

Portable app detection is speculative (scans arbitrary directories for executables) and adds noise to scan results. Keep the code but flip the default.

**Files to modify:**

| File | Line | Change |
|------|------|--------|
| `src/discovery/programs.py` | 116 | Change `scan_portable: bool = True` to `scan_portable: bool = False` |
| `src/core/config.py` | 35 | Change `include_portable: bool = True` to `include_portable: bool = False` |

### 1.5 Mark GUI actions as explicitly unimplemented

**Files to modify:**

| File | Lines | Change |
|------|-------|--------|
| `src/ui/gui/main.py` | 420-430 | Replace the three `pass` stubs with `QMessageBox.warning(self, "Not Available", f"'{comp.display_name}' action not yet implemented in GUI. Use the CLI instead:\n\ndebloatd disable {comp.id}")` (or contain/remove respectively). |

### 1.6 Fix the 4 failing tests

| Test | File | Issue | Fix |
|------|------|-------|-----|
| `test_format_portable_display_name` | `tests/test_programs.py:159-165` | Regex `r"[-_]?\d+(\.\d+)*$"` strips `v2` from `"MyProgram_v2"`. | Change regex in `src/discovery/programs.py:619` to `r"[-_]?\d+(\.\d+)+$"` (require at least one dot to match version strings, so `1.0.0` matches but bare `2` does not). |
| Path assertion tests | Multiple test files | `PosixPath` vs `C:\` backslash assumptions | Use `Path()` constructor in assertions instead of hardcoded string comparisons. Normalize paths with `str(path)` consistently. |
| System Restore return value | `tests/test_rollback.py` or `tests/test_actions.py` | Returns `None` on non-Windows instead of expected `0` | Guard the assertion with a platform check or mock the return value consistently. |

### 1.7 Tighten `Any` types in orchestrator

**Files to modify:**

| File | Lines | Change |
|------|-------|--------|
| `src/core/orchestrator.py` | 1, 114, 116, 121, 199 | Import `BaseDiscoveryModule` from `src.discovery.base`. Change `self.modules: list` to `self.modules: list[BaseDiscoveryModule]`. Change `_classification_engine: Any` to `_classification_engine: ClassificationEngine | None`. Update method signatures for `module` parameters. |

---

## PHASE 2: VALIDATE — Prove the core loop works on Windows (est. ~1-2 days)

**Goal:** Run the tool on a real Windows 10/11 system. Fix every failure. Prove the scan → classify → disable → verify → rollback cycle works end-to-end.

**Prerequisite:** A Windows 10 (build 1903+) or Windows 11 VM with stock OEM bloatware. An HP or Dell consumer laptop image is ideal — they ship with the most bloatware.

### 2.1 Validate discovery modules one at a time

Run each scanner independently and fix what breaks:

```
debloatd scan --type programs -vv --json > programs_output.json
debloatd scan --type services -vv --json > services_output.json
debloatd scan --type tasks -vv --json > tasks_output.json
debloatd scan --type startup -vv --json > startup_output.json
debloatd scan --type drivers -vv --json > drivers_output.json
debloatd scan --type telemetry -vv --json > telemetry_output.json
```

**Expected issues (prepare for these):**

| Module | Likely failure | Why |
|--------|---------------|-----|
| `programs.py` | UWP `ConvertTo-Json` parsing errors | PowerShell output may contain BOM or unexpected encoding on real systems. |
| `programs.py` | Registry key access denied | Some HKLM keys require elevated privileges. The scanner says `requires_admin: False` but HKLM scanning effectively needs it. |
| `services.py` | WMI query timeout | Some systems have hundreds of services. The 60s timeout in `ActionConfig` may not apply to discovery. |
| `tasks.py` | `Get-ScheduledTask` returns XML, not clean objects | Task trigger parsing may fail on complex schedules. |
| `drivers.py` | `driverquery` output format varies by locale | Non-English Windows will have different column headers. |
| `telemetry.py` | False positives on common Microsoft endpoints | `settings-win.data.microsoft.com` is telemetry, but some endpoints are required for Windows Update. |

### 2.2 Validate classification against real data

After scanning produces real components, verify classification accuracy:

1. Run full scan: `debloatd scan -vv`
2. Export component list: `debloatd list --json > all_components.json`
3. Manually review every classification — check for:
   - **False CORE**: non-essential software classified as CORE (should never happen with signature DB)
   - **False AGGRESSIVE**: essential software classified as AGGRESSIVE (dangerous — would be removed)
   - **Missing matches**: known bloatware classified as UNKNOWN (signature gap)

### 2.3 Prove the disable → verify → rollback cycle

Pick one safe target (e.g., `Microsoft.BingWeather` UWP app) and run the full cycle:

```bash
# 1. Scan and identify the component
debloatd scan --type programs -vv

# 2. Get the component ID from output, check its plan
debloatd plan <component_id>

# 3. Disable it (interactive mode)
debloatd disable <component_id>

# 4. Verify it's disabled (re-scan should show changed state)
debloatd scan --type programs -vv

# 5. Undo the action
debloatd undo --last

# 6. Verify it's restored
debloatd scan --type programs -vv
```

If any step fails, that's the highest-priority fix.

### 2.4 Add Windows integration tests

Create `tests/integration/` directory with tests that:
- Actually run on Windows (not mocked)
- Skip on non-Windows with `@pytest.mark.windows`
- Test real registry reads, real PowerShell execution, real service enumeration
- Run in CI via a Windows runner (GitHub Actions `windows-latest`)

**New files to create:**

| File | Purpose |
|------|---------|
| `tests/integration/__init__.py` | Package init |
| `tests/integration/test_programs_live.py` | Run ProgramsScanner.scan() on real Windows |
| `tests/integration/test_services_live.py` | Run ServicesScanner.scan() on real Windows |
| `tests/integration/test_classification_live.py` | Classify real components, verify known signatures match |
| `tests/integration/test_disable_rollback_live.py` | Full disable → rollback cycle on a safe UWP app |

---

## PHASE 3: STRENGTHEN — Expand the signature database and harden (est. ongoing)

**Goal:** Once the core loop is proven, make the tool useful for more users by covering more bloatware and hardening edge cases.

### 3.1 Expand signature database to 200+

The 55 existing signatures cover major cases. Expand systematically:

| Category | Current | Target | Priority |
|----------|---------|--------|----------|
| Microsoft built-in UWP | 12 | 30 | High — most common complaints |
| OEM (HP, Dell, Lenovo, Asus, Acer) | 10 | 40 | High — biggest pain point for consumers |
| Antivirus trials (McAfee, Norton, etc.) | 4 | 12 | High — most hated bloatware category |
| Telemetry/tracking services | 5 | 20 | Medium — privacy-focused users |
| Pre-installed games | 4 | 10 | Medium — low risk, easy wins |
| Browser add-ons/updaters | 4 | 15 | Medium — updater services persist |
| Social media apps (UWP) | 4 | 8 | Low — not common on new installs anymore |
| Regional/carrier bloatware | 0 | 20 | Low — varies by market |

**For each new signature, require:**
- `evidence_url` pointing to community documentation of the software's bloatware behavior
- Tested `name_pattern` regex against real component names from Phase 2 output
- `breakage_notes` documenting what breaks when disabled/removed
- `reinstall_behavior` based on real observation (does it come back after Windows Update?)

### 3.2 Add signature contribution workflow

Create a template and validation script for community signature contributions:

| File | Purpose |
|------|---------|
| `data/signatures/TEMPLATE.json` | Single-signature template with all required fields and comments |
| `scripts/validate_signature.py` | Script that loads a signature file, validates regex patterns compile, checks required fields are non-empty, tests match rules against sample data |
| `CONTRIBUTING.md` update | Add "Adding Signatures" section with the template and validation steps |

### 3.3 Harden action handlers for edge cases

Based on Phase 2 findings, add handling for:

- **Services with dependencies**: Before disabling a service, check `DependentServices`. Warn if other services depend on it.
- **UWP app removal for all users vs. current user**: `Remove-AppxPackage` vs `Remove-AppxPackage -AllUsers`. Default to current user only.
- **Self-healing apps**: After disabling, verify the component stays disabled. Some OEM tools re-enable via scheduled tasks. Flag these with `reinstall_behavior: self_healing`.
- **Reboot requirements**: Track which actions actually require a reboot (service startup type changes take effect immediately; driver removals don't).

### 3.4 Wire up GUI action handlers (if GUI is kept)

Only after the CLI action pipeline is battle-tested in Phase 2:

| File | Method | Wire to |
|------|--------|---------|
| `src/ui/gui/main.py:420` | `_action_disable()` | `ExecutionEngine.execute()` with `ActionType.DISABLE` |
| `src/ui/gui/main.py:424` | `_action_contain()` | `ExecutionEngine.execute()` with `ActionType.CONTAIN` |
| `src/ui/gui/main.py:428` | `_action_remove()` | `ExecutionEngine.execute()` with `ActionType.REMOVE` |
| `src/ui/gui/main.py` (dashboard) | "Safe Debloat" button | Batch disable all AGGRESSIVE + BLOAT components in DRY_RUN mode first, show results, then offer to execute |

Each GUI action should:
1. Show a confirmation dialog with risk level and breakage notes
2. Run in a worker thread (not blocking the UI)
3. Show a progress dialog
4. Display result with rollback option

---

## EXECUTION ORDER

```
Phase 1 (Surgery)          Phase 2 (Validate)              Phase 3 (Strengthen)
─────────────────          ──────────────────              ────────────────────
1.1 Remove LLM refs   →   2.1 Test each scanner      →   3.1 Expand signatures
1.2 Fix REPLACE        →   2.2 Verify classifications  →   3.2 Contribution workflow
1.3 Fix versions       →   2.3 Prove disable/rollback  →   3.3 Harden edge cases
1.4 Disable portable   →   2.4 Integration tests       →   3.4 Wire GUI actions
1.5 Fix GUI stubs      →
1.6 Fix failing tests  →
1.7 Tighten types      →
```

**Phase 1** can be done entirely in this environment (Linux, no Windows needed).
**Phase 2** requires a Windows VM — this is the critical gate.
**Phase 3** is ongoing work that builds on Phase 2 findings.

---

## SUCCESS CRITERIA

| Phase | Done when... |
|-------|-------------|
| 1 | All tests pass. No references to LLM, REPLACE is explicitly unsupported. Version says `0.1.0-alpha`. `mypy --strict` passes with no `Any` in orchestrator. |
| 2 | `debloatd scan` runs on a real Windows 10/11 machine and discovers 50+ components. Classification matches expectations for known bloatware (HP Support Assistant → BLOAT, McAfee → AGGRESSIVE). One full disable → rollback cycle completes without error. |
| 3 | Signature database has 150+ signatures. Community contribution workflow exists. GUI actions invoke real execution engine. No known edge cases in action handlers. |
