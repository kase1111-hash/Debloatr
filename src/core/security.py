"""Security Utilities - Centralized validation and integrity functions.

This module provides shared security functions used across Debloatr:
- Registry path validation against an allowlist
- File path validation against safe directories
- Session file HMAC integrity signing and verification
"""

import hashlib
import hmac
import json
import logging
import os
import platform
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger("debloatr.core.security")


# --- Registry Path Validation ---

# Allowed registry hive prefixes for Debloatr operations.
# Paths outside these prefixes are rejected to prevent
# accidental or malicious modification of critical registry areas.
ALLOWED_REGISTRY_PREFIXES: list[str] = [
    # Software hives (where programs register)
    "HKLM:\\Software\\",
    "HKLM:\\SOFTWARE\\",
    "HKCU:\\Software\\",
    "HKCU:\\SOFTWARE\\",
    # Uninstall keys
    "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
    "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
    # Run keys (startup entries)
    "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    # Explorer startup
    "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\",
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\",
    # Services (needed for disable/rollback)
    "HKLM:\\System\\CurrentControlSet\\Services\\",
    "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\",
    # Policies (privacy hardening)
    "HKLM:\\Software\\Policies\\",
    "HKLM:\\SOFTWARE\\Policies\\",
    "HKCU:\\Software\\Policies\\",
    "HKCU:\\SOFTWARE\\Policies\\",
    # Privacy-related keys
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Privacy",
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo",
    "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo",
    "HKCU:\\Software\\Microsoft\\Input\\",
    "HKCU:\\Software\\Microsoft\\InputPersonalization",
    "HKLM:\\Software\\Microsoft\\PolicyManager\\",
    "HKLM:\\SOFTWARE\\Microsoft\\PolicyManager\\",
    # Windows NT system restore
    "HKLM:\\Software\\Microsoft\\Windows NT\\",
    "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\",
    # Content delivery (privacy hardening - advertising)
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager",
    "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\SearchSettings",
]


def validate_registry_path(registry_key: str) -> bool:
    """Validate that a registry path falls within allowed hives.

    Checks the path against ALLOWED_REGISTRY_PREFIXES using
    case-insensitive prefix matching.

    Args:
        registry_key: Registry path to validate (e.g. "HKLM:\\Software\\...")

    Returns:
        True if the path is within an allowed hive, False otherwise
    """
    if not registry_key:
        return False

    # Normalize separators
    normalized = registry_key.replace("/", "\\")

    for prefix in ALLOWED_REGISTRY_PREFIXES:
        if normalized.lower().startswith(prefix.lower()):
            return True

    logger.warning(f"Registry path rejected (outside allowed hives): {registry_key}")
    return False


# --- File Path Validation ---

# Allowed base directories for file operations
_ALLOWED_PATH_PREFIXES: list[str] = [
    os.environ.get("PROGRAMFILES", r"C:\Program Files"),
    os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
    os.environ.get("APPDATA", ""),
    os.environ.get("LOCALAPPDATA", ""),
    os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
    os.environ.get("USERPROFILE", ""),
    r"C:\Users",
]


def is_safe_path(path: Path) -> bool:
    """Check if a file path is within allowed directories.

    Resolves symlinks and normalizes the path before checking
    against the allowed prefix list.

    Args:
        path: Path to validate

    Returns:
        True if within an allowed directory
    """
    try:
        resolved = str(path.resolve()).lower()
    except (OSError, ValueError):
        return False

    for prefix in _ALLOWED_PATH_PREFIXES:
        if prefix and resolved.startswith(prefix.lower()):
            return True

    logger.warning(f"Path rejected (outside allowed directories): {path}")
    return False


# --- Session File HMAC Integrity ---

def _get_machine_key() -> bytes:
    """Derive an HMAC key from machine-specific identifiers.

    Uses a combination of machine name, OS, and processor info as
    key material. This is not cryptographic security against a
    sophisticated attacker — it's tamper detection against casual
    modification of session files.

    Returns:
        HMAC key bytes
    """
    # Combine machine-specific values
    components = [
        platform.node(),
        platform.machine(),
        os.environ.get("COMPUTERNAME", ""),
        os.environ.get("USERNAME", ""),
        # Salt with a fixed application identifier
        "debloatr-session-integrity-v1",
    ]
    material = "|".join(components).encode("utf-8")
    return hashlib.sha256(material).digest()


def sign_session_data(data: dict[str, Any]) -> str:
    """Compute an HMAC-SHA256 signature for session data.

    Signs the canonical JSON representation of the data
    (sorted keys, no whitespace) to detect tampering.

    Args:
        data: Session data dictionary (without the _hmac field)

    Returns:
        Hex-encoded HMAC-SHA256 signature
    """
    # Remove any existing signature before computing
    signable = {k: v for k, v in data.items() if k != "_hmac"}
    canonical = json.dumps(signable, sort_keys=True, separators=(",", ":"), default=str)
    key = _get_machine_key()
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_session_data(data: dict[str, Any]) -> bool:
    """Verify the HMAC-SHA256 signature of session data.

    Args:
        data: Session data dictionary (with _hmac field)

    Returns:
        True if the signature is valid, False if missing or invalid
    """
    stored_hmac = data.get("_hmac")
    if not stored_hmac:
        logger.warning("Session file has no HMAC signature — unsigned file")
        return False

    expected = sign_session_data(data)
    if not hmac.compare_digest(stored_hmac, expected):
        logger.warning("Session file HMAC verification FAILED — possible tampering")
        return False

    return True


def sanitize_powershell_string(value: str) -> str:
    """Sanitize a string for use in PowerShell single-quoted strings.

    Escapes single quotes by doubling them and strips null bytes
    and other control characters that could cause injection.

    Args:
        value: Raw string value

    Returns:
        Sanitized string safe for PowerShell single-quote interpolation
    """
    # Strip null bytes and non-printable control chars (except common whitespace)
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
    # Strip backticks which are PowerShell escape characters
    cleaned = cleaned.replace("`", "")
    # Double single quotes for PowerShell single-quoted string escaping
    cleaned = cleaned.replace("'", "''")
    return cleaned
