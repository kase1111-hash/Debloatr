# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to the project maintainers or through GitHub's private vulnerability reporting feature if available.

When reporting, please include:

1. **Description** - A clear description of the vulnerability
2. **Impact** - The potential impact and severity
3. **Steps to Reproduce** - Detailed steps to reproduce the issue
4. **Affected Versions** - Which versions are affected
5. **Possible Fix** - If you have suggestions for fixing the issue

### What to Expect

- **Acknowledgment** - We will acknowledge receipt of your report within 48 hours
- **Updates** - We will keep you informed of progress toward a fix
- **Disclosure** - We will coordinate with you on public disclosure timing
- **Credit** - We will credit you in the security advisory (unless you prefer otherwise)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Assessment**: Within 7 days
- **Fix Development**: Depends on severity and complexity
- **Public Disclosure**: After fix is released (coordinated disclosure)

## Security Design

Debloatr is designed with security as a core principle:

### Privilege Model

| Operation | Required Privilege |
|-----------|-------------------|
| Scan | Standard user (limited) or Administrator (full) |
| Disable service | Administrator |
| Remove program | Administrator |
| Modify startup | Administrator (HKLM) or User (HKCU) |
| Create restore point | Administrator |

### Security Features

1. **No Silent Actions** - Every mutation requires explicit user confirmation
2. **Snapshot Before Changes** - All actions are reversible through snapshots
3. **Transactional Execution** - Each action wrapped with rollback capability
4. **No Network Required** - Full functionality without internet access
5. **No Self-Telemetry** - The tool collects zero usage data by default
6. **Signed Updates** - Signature database updates require valid signatures

### Integrity Checks

- Signature database files are verified with SHA256 hashes on load
- Rule updates require cryptographic signatures
- Quarantine folder is ACL-restricted to SYSTEM and Administrators

## Known Security Considerations

### Elevated Privileges

Debloatr requires Administrator privileges for most mutation operations. Users should:

- Only run the tool from trusted sources
- Verify the integrity of downloaded releases
- Review proposed actions before confirming execution

### Third-Party Dependencies

The tool depends on several third-party packages:

- `pywin32` - Windows API bindings
- `psutil` - System information
- `pydantic` - Data validation
- `PySide6` - GUI framework (optional)

Keep dependencies updated to receive security patches.

### Signature Database

The signature database determines what gets classified as bloatware. Ensure:

- Signatures are loaded from trusted sources only
- External signature feeds use HTTPS and valid certificates
- Database integrity is verified before use

## Security Best Practices for Users

1. **Download from official sources** - Only use releases from the official repository
2. **Verify checksums** - Check file integrity before running
3. **Review before executing** - Use DRY_RUN mode first to review proposed changes
4. **Create restore points** - Enable automatic restore point creation
5. **Keep backups** - Maintain system backups before major debloating sessions
6. **Stay updated** - Use the latest version with security fixes
