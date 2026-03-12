# Agentic Security Audit Report — Debloatr

## AUDIT METADATA

```
Project:       Debloatr
Date:          2026-03-12
Auditor:       claude-opus-4-6
Commit:        c0103bd584c5507e317f0bc4671c62740ba4ccee
Strictness:    STANDARD
Context:       PRODUCTION
```

## PROVENANCE ASSESSMENT

```
Vibe-Code Confidence:   35%
Human Review Evidence:   MODERATE
```

**Rationale:** The codebase shows mixed authorship (62.5% Claude, 37.5% human) with iterative development across 40 commits. Commit messages are specific and technical, not boilerplate. However, large structural commits and AI-driven implementation phases are visible. Human review evidence is **MODERATE** — there are security-focused commits, an existing audit report, a SECURITY.md, and CI/CD, but no pre-commit hooks, no semgrep/bandit, and no SAST tooling in the pipeline.

## LAYER VERDICTS

```
L1 Provenance:       WARN
L2 Credentials:      PASS
L3 Agent Boundaries: N/A (not an agentic application)
L4 Supply Chain:     WARN
L5 Infrastructure:   WARN
```

---

## L1: PROVENANCE & TRUST ORIGIN

### 1.1 Vibe-Code Indicators

- [x] **AI authorship dominant**: 25/40 commits from Claude (noreply@anthropic.com)
- [ ] **No tests**: Tests PRESENT — 18+ test modules, 460+ tests passing
- [ ] **No security config**: SECURITY.md exists with comprehensive policy
- [x] **AI boilerplate**: Some phase-based commit messages ("Phase 1: Surgery", "Phase 3: Strengthen") follow a coding guide structure
- [x] **Rapid commit history**: Large structural commits (e.g., "Phase 4: Polish" touching signatures, handlers, GUI)
- [ ] **Polished README, hollow codebase**: README matches actual implementation
- [ ] **Bloated deps**: 3 core deps (pywin32, psutil, pydantic) — appropriate for scope

**Assessment:** This is AI-*assisted* development, not pure vibe-coding. The human contributor provides direction, merges PRs, and reviews. The AI implements. Key distinguishing factors: iterative bug-fix commits exist, security audit was performed mid-development, and test coverage is substantive.

### 1.2 Human Review Evidence

- [x] Security-focused commits exist (`feb1871` — "Fix all issues identified in software audit")
- [x] SECURITY.md with privilege model, threat model, and reporting process
- [ ] No SAST tooling in CI (no semgrep, bandit, or equivalent)
- [x] `.gitignore` excludes `.env`, credentials, logs, quarantine data
- [x] CI/CD with lint + test pipeline (`.github/workflows/ci.yml`)
- [ ] No pre-commit hooks (`.pre-commit-config.yaml` absent)

### 1.3 The "Tech Preview" Trap

- [ ] No production deployment detected
- [ ] No real user credentials handled (this is a local desktop tool)
- [ ] No disclaimers shifting responsibility

**L1 Verdict: WARN** — AI-assisted development with moderate human oversight. Not pure vibe-code, but SAST tooling gaps mean security findings below should be taken seriously.

---

## L2: CREDENTIAL & SECRET HYGIENE

### 2.1 Secret Storage

- [x] No plaintext credentials in source code
- [x] No API keys in any files
- [x] `.gitignore` properly configured
- [x] No secrets in git history (verified via grep)
- [x] Previously-existing `llm_api_key` config field was removed in refocus phase
- [x] Environment variables used only for safe system paths (`APPDATA`, `USERPROFILE`, etc.)

### 2.2 Credential Scoping & Lifecycle

- N/A — Tool does not manage credentials. It reads Windows registry and system state.

### 2.3 Machine Credential Exposure

- N/A — No API keys, no OAuth tokens, no cloud services.

**L2 Verdict: PASS** — Clean. No secrets in code, config, or history.

---

## L3: AGENT BOUNDARY ENFORCEMENT

**N/A** — Debloatr is not an agentic application. It is a local desktop tool that performs system administration tasks with explicit user confirmation. No AI agents, no LLM integration, no agent-to-agent communication.

The previously-planned LLM classification feature was explicitly removed (see `REFOCUS_PLAN.md`).

**L3 Verdict: N/A**

---

## L4: SUPPLY CHAIN & DEPENDENCY TRUST

### 4.1 Plugin/Skill Supply Chain

- N/A — No plugin system. Signature databases are local JSON files.
- [x] `scripts/validate_signature.py` exists for signature file validation
- [x] SECURITY.md documents SHA256 integrity verification for signature databases

### 4.2 Dependency Audit

- [ ] No lock file present (no `poetry.lock`, `Pipfile.lock`, or `pip-compile` output)
- [x] Core dependencies use minimum version pins (`>=`) in `pyproject.toml`
- [ ] Versions are floor-pinned, not ceiling-pinned — `pywin32>=305` allows any future version
- [ ] No `pip audit` or `safety` in CI pipeline
- [ ] Transitive dependencies not audited

### 4.3 External Code/Data

- [x] No remote URL fetching in application code
- [x] No `eval()`, `exec()`, or `importlib` dynamic loading
- [x] No pickle deserialization
- [ ] `subprocess.run(..., shell=True)` used in 6 locations (see L5 findings)

**L4 Verdict: WARN** — Dependencies lack pinning and automated vulnerability scanning.

### Findings

```
[MEDIUM] — No dependency lock file
Layer:     4
Location:  pyproject.toml, requirements.txt
Evidence:  Dependencies use floor pins (>=) with no upper bound or lock file.
           pywin32>=305, psutil>=5.9.0, pydantic>=2.0
Risk:      A compromised or buggy future release of any dependency will be
           automatically pulled on fresh install. Supply chain attack vector.
Fix:       Add requirements.lock via pip-compile or switch to poetry with
           poetry.lock committed. Pin exact versions for production builds.
```

```
[LOW] — No automated dependency vulnerability scanning
Layer:     4
Location:  .github/workflows/ci.yml
Evidence:  CI runs pytest + ruff + black. No pip-audit, safety, or Dependabot.
Risk:      Known CVEs in dependencies go undetected.
Fix:       Add pip-audit or safety to CI. Enable GitHub Dependabot alerts.
```

---

## L5: INFRASTRUCTURE & RUNTIME

### 5.1 Command Injection via `shell=True`

This is the most significant finding cluster in the audit. Debloatr executes system commands (PowerShell, cmd, schtasks, sc.exe) with user-controllable data interpolated into command strings.

```
[HIGH] — Uninstall string passed directly to shell
Layer:     5
Location:  src/actions/remove.py:683-692
Evidence:  subprocess.run(uninstall_string, shell=True, ...) where
           uninstall_string comes from Windows registry UninstallString values.
           No validation or sanitization of the string contents.
Risk:      A trojanized installer that writes a malicious UninstallString
           (e.g., "cmd /c net user attacker P@ss /add & msiexec /X{GUID}")
           would execute arbitrary commands as the current user (likely admin).
           This is partially mitigated by the fact that registry write access
           already implies local admin — but it enables privilege persistence
           and lateral movement from a compromised registry.
Fix:       Parse the uninstall string into components. For MSI, extract the
           GUID and call msiexec directly via subprocess.run(["msiexec", ...]).
           For other patterns, maintain a whitelist of known uninstaller formats.
           Reject or prompt the user for unrecognized patterns.
```

```
[MEDIUM] — PowerShell command construction via f-string interpolation
Layer:     5
Location:  src/actions/disable.py:180,187,272-286,590,605,630,683-700
           src/actions/remove.py:234,514-516
           src/actions/contain.py:374-381,407
           src/core/rollback.py:380-381,444,448-449,514-517,680
           src/core/snapshot.py (via _run_powershell)
           src/core/restore.py (via _run_powershell and _run_command)
Evidence:  Service names, task paths, registry keys, and component names are
           interpolated into PowerShell command strings using f-strings.
           Escaping is limited to replace("'", "''") — PowerShell single-quote
           doubling.
Risk:      While PowerShell single-quoted strings don't expand variables,
           edge cases exist: names containing backticks (`) or null bytes
           could cause unexpected behavior. The _run_command() helper at
           restore.py:434 uses shell=True with no PowerShell quoting at all.
           Service names come from the Windows SCM (trusted), but the pattern
           is fragile and violates defense-in-depth.
Fix:       Centralize all PowerShell execution into a single helper that uses
           -EncodedCommand (Base64) to avoid quoting issues entirely.
           Alternatively, use PowerShell's -ArgumentList with proper parameter
           binding. For _run_command(), split into argument lists and use
           shell=False.
```

```
[MEDIUM] — Registry path used without validation in Remove handler
Layer:     5
Location:  src/actions/remove.py:736-740
Evidence:  registry_key = context.get("registry_key", "")
           Passed directly to Remove-Item -Path '{registry_key}' -Recurse -Force
           No validation that the key is within expected hives or paths.
Risk:      If context is tampered (e.g., via modified session file), arbitrary
           registry trees could be deleted.
Fix:       Validate registry paths against an allowlist of expected hive
           prefixes (HKCU:\Software\, HKLM:\Software\, etc.).
```

### 5.2 Session File Integrity

```
[MEDIUM] — Session files loaded without schema validation
Layer:     5
Location:  src/core/session.py:495-550
Evidence:  JSON session files are loaded with json.load() and field values
           are accessed by key without schema validation. ActionType is
           validated against enum values (good), but other fields like
           component_id, plan_id, and snapshot_id are used as-is.
Risk:      A crafted session file could inject unexpected values into the
           rollback pipeline, potentially causing rollback of unintended
           components. Attack requires local file write access.
Fix:       Validate session files against a pydantic schema (already a
           project dependency). Add HMAC or checksum to session files to
           detect tampering.
```

### 5.3 Path Traversal

```
[MEDIUM] — File paths from context used without normalization
Layer:     5
Location:  src/actions/remove.py:518-520
           src/actions/disable.py:725-729
Evidence:  shortcut_path from component context used directly with
           Path(shortcut_path).exists() and subsequent operations.
           No path normalization, symlink resolution, or directory
           traversal protection.
Risk:      If a component's metadata contains a crafted path
           (../../sensitive_file), the quarantine or disable operation
           could affect unintended files. Requires a malicious component
           entry, which means a compromised discovery module or signature.
Fix:       Resolve paths with Path.resolve() and verify they fall within
           expected directories (Program Files, AppData, etc.).
```

### 5.4 Error Handling — Silent Failures

```
[LOW] — JSON parsing failures silently swallowed
Layer:     5
Location:  src/discovery/services.py, src/discovery/programs.py (multiple)
Evidence:  PowerShell output parsed as JSON with broad except clauses that
           log warnings but return empty results. Components may be silently
           missed during discovery.
Risk:      A service or program that causes malformed PowerShell JSON output
           would be invisible to the scanner — potentially hiding malware.
Fix:       Log full PowerShell stdout/stderr on parse failure. Consider
           failing the scan module rather than returning partial results,
           with a user-visible warning.
```

### 5.5 No Pre-Commit Security Hooks

```
[LOW] — No SAST or secret scanning in development workflow
Layer:     5
Location:  (missing .pre-commit-config.yaml)
Evidence:  No pre-commit hooks configured. No semgrep, bandit, or gitleaks
           in CI or local workflow.
Risk:      Security regressions can be introduced without automated detection.
           The AI-assisted development pattern makes this more likely, as
           AI-generated code may introduce subtle vulnerabilities.
Fix:       Add .pre-commit-config.yaml with: bandit (Python SAST),
           gitleaks (secret detection), ruff (already in CI, add locally).
           Add bandit to CI pipeline.
```

**L5 Verdict: WARN** — No critical exploitable vulnerabilities in the current threat model (local desktop tool requiring admin), but the `shell=True` + f-string interpolation pattern is a systemic concern that should be addressed.

---

## OVERALL RISK ASSESSMENT

### Threat Model Context

Debloatr runs as a **local desktop application with administrator privileges** on Windows. Its attack surface is:

1. **Registry data as input** — Component metadata comes from the Windows registry, which is writable only by admin users. This means most injection vectors require pre-existing admin access, reducing their practical severity.

2. **Local file system** — Session files, signatures, and quarantine data are stored locally. Tampering requires local access.

3. **No network exposure** — No listening ports, no API endpoints, no remote connections.

This context means the `shell=True` findings are **MEDIUM rather than CRITICAL** in practice — an attacker who can write malicious registry values already has admin access. However, the pattern should still be fixed because:
- Defense-in-depth matters for tools that modify system state
- Debloatr could be used in enterprise deployment where registry pre-seeding by another tool is common
- The codebase sets a pattern that could be replicated in a networked context

### Summary of Findings

| # | Severity | Title | Layer |
|---|----------|-------|-------|
| 1 | HIGH | Uninstall string shell injection | L5 |
| 2 | MEDIUM | PowerShell f-string command construction | L5 |
| 3 | MEDIUM | Registry path used without validation | L5 |
| 4 | MEDIUM | Session files lack schema validation | L5 |
| 5 | MEDIUM | File path traversal in action handlers | L5 |
| 6 | MEDIUM | No dependency lock file | L4 |
| 7 | LOW | Silent JSON parsing failures | L5 |
| 8 | LOW | No dependency vulnerability scanning | L4 |
| 9 | LOW | No SAST or pre-commit security hooks | L5 |

### Recommendations — Priority Order

1. **Parse uninstall strings** instead of passing to `shell=True` (Finding 1)
2. **Centralize PowerShell execution** with `-EncodedCommand` to eliminate quoting issues (Finding 2)
3. **Add pydantic schema validation** to session file loading (Finding 4)
4. **Validate registry paths and file paths** against allowlists (Findings 3, 5)
5. **Add `pip-audit` to CI** and create a lock file (Findings 6, 8)
6. **Add bandit to CI** for ongoing SAST coverage (Finding 9)

---

## INCIDENT RELEVANCE

| Incident | Applicable? | Notes |
|----------|-------------|-------|
| Moltbook DB exposure | No | No database, no cloud backend |
| OpenClaw supply chain | Partially | Signature DB could be a vector if remote feeds are added |
| SCADA prompt injection | No | No AI/LLM processing |
| MCP sampling exploits | No | No MCP integration |
| ZombAI recruitment | No | No AI agent capabilities |

---

*Audit performed using the [Agentic Security Audit v3.0](https://github.com/kase1111-hash/Claude-prompts/blob/main/vibe-check.md) framework.*
