"""Tests for security infrastructure modules.

Tests the centralized security utilities:
- SafePowerShell executor
- Registry path validation
- File path validation
- Session HMAC integrity
- PowerShell string sanitization
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from src.core.powershell import PSResult, SafePowerShell, create_powershell
from src.core.security import (
    ALLOWED_REGISTRY_PREFIXES,
    is_safe_path,
    sanitize_powershell_string,
    sign_session_data,
    validate_registry_path,
    verify_session_data,
)


# --- SafePowerShell Tests ---


class TestSafePowerShell:
    """Tests for the SafePowerShell executor."""

    def test_create_powershell(self):
        ps = create_powershell(dry_run=True)
        assert isinstance(ps, SafePowerShell)
        assert ps.dry_run is True

    def test_dry_run_returns_success(self):
        ps = SafePowerShell(dry_run=True)
        result = ps.run("Get-Service -Name 'SomeService'")
        assert result.success is True
        assert result.output == ""

    def test_dry_run_command_returns_success(self):
        ps = SafePowerShell(dry_run=True)
        result = ps.run_command(["sc", "query", "DiagTrack"])
        assert result.success is True

    def test_non_windows_returns_error(self):
        ps = SafePowerShell(dry_run=False)
        # On Linux, this should return an error
        result = ps.run("Get-Service")
        assert result.success is False
        assert "Windows" in result.error or "No such file" in result.error

    def test_non_windows_command_returns_error(self):
        ps = SafePowerShell(dry_run=False)
        result = ps.run_command(["powershell.exe", "-Command", "echo test"])
        assert result.success is False


class TestPSResult:
    """Tests for PSResult."""

    def test_bool_true(self):
        r = PSResult(success=True, output="ok", error="")
        assert bool(r) is True

    def test_bool_false(self):
        r = PSResult(success=False, output="", error="fail")
        assert bool(r) is False

    def test_to_dict(self):
        r = PSResult(success=True, output="data", error="")
        d = r.to_dict()
        assert d == {"success": True, "output": "data", "error": ""}

    def test_repr(self):
        r = PSResult(success=True, output="hello", error="")
        assert "success=True" in repr(r)


# --- Registry Path Validation Tests ---


class TestRegistryValidation:
    """Tests for registry path validation."""

    def test_valid_software_path(self):
        assert validate_registry_path("HKLM:\\Software\\SomeApp\\Settings") is True

    def test_valid_uninstall_path(self):
        path = "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{GUID}"
        assert validate_registry_path(path) is True

    def test_valid_run_key(self):
        assert validate_registry_path("HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run") is True

    def test_valid_services_path(self):
        assert validate_registry_path("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\DiagTrack") is True

    def test_valid_policies_path(self):
        assert validate_registry_path("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection") is True

    def test_reject_empty(self):
        assert validate_registry_path("") is False

    def test_reject_system_root(self):
        assert validate_registry_path("HKLM:\\") is False

    def test_reject_sam_hive(self):
        assert validate_registry_path("HKLM:\\SAM\\SAM\\Domains") is False

    def test_reject_security_hive(self):
        assert validate_registry_path("HKLM:\\SECURITY\\Policy") is False

    def test_reject_boot_config(self):
        assert validate_registry_path("HKLM:\\BCD00000000\\") is False

    def test_forward_slash_normalized(self):
        assert validate_registry_path("HKLM:/Software/SomeApp") is True

    def test_case_insensitive(self):
        assert validate_registry_path("hklm:\\software\\someapp") is True

    def test_privacy_paths_allowed(self):
        assert validate_registry_path("HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo") is True
        assert validate_registry_path("HKCU:\\Software\\Microsoft\\InputPersonalization") is True


# --- File Path Validation Tests ---


class TestFilePathValidation:
    """Tests for file path validation."""

    @pytest.mark.skipif(
        not Path("C:\\Program Files").exists(),
        reason="Not on Windows",
    )
    def test_program_files_allowed(self):
        assert is_safe_path(Path("C:\\Program Files\\SomeApp\\app.exe")) is True

    def test_temp_path_rejected(self):
        # /tmp is not in allowed prefixes
        assert is_safe_path(Path("/tmp/malicious")) is False

    def test_system_root_rejected(self):
        assert is_safe_path(Path("C:\\Windows\\System32\\something")) is False


# --- HMAC Integrity Tests ---


class TestSessionHMAC:
    """Tests for session HMAC signing and verification."""

    def test_sign_and_verify(self):
        data = {
            "session_id": "test-123",
            "description": "Test session",
            "actions": [],
        }
        signature = sign_session_data(data)
        assert isinstance(signature, str)
        assert len(signature) == 64  # SHA256 hex digest

        data["_hmac"] = signature
        assert verify_session_data(data) is True

    def test_tampered_data_fails(self):
        data = {
            "session_id": "test-123",
            "description": "Test session",
            "actions": [],
        }
        data["_hmac"] = sign_session_data(data)

        # Tamper with data
        data["description"] = "TAMPERED"
        assert verify_session_data(data) is False

    def test_missing_hmac_fails(self):
        data = {"session_id": "test-123"}
        assert verify_session_data(data) is False

    def test_wrong_hmac_fails(self):
        data = {
            "session_id": "test-123",
            "_hmac": "0" * 64,
        }
        assert verify_session_data(data) is False

    def test_deterministic_signature(self):
        data = {"session_id": "test", "value": 42}
        sig1 = sign_session_data(data)
        sig2 = sign_session_data(data)
        assert sig1 == sig2

    def test_hmac_excluded_from_signature(self):
        data = {"session_id": "test"}
        sig1 = sign_session_data(data)

        data["_hmac"] = "old_signature"
        sig2 = sign_session_data(data)
        assert sig1 == sig2  # _hmac field should be excluded


# --- PowerShell String Sanitization Tests ---


class TestSanitization:
    """Tests for PowerShell string sanitization."""

    def test_normal_string_unchanged(self):
        assert sanitize_powershell_string("DiagTrack") == "DiagTrack"

    def test_single_quotes_doubled(self):
        assert sanitize_powershell_string("it's") == "it''s"

    def test_null_bytes_stripped(self):
        assert sanitize_powershell_string("test\x00injection") == "testinjection"

    def test_backticks_stripped(self):
        assert sanitize_powershell_string("test`command") == "testcommand"

    def test_control_chars_stripped(self):
        assert sanitize_powershell_string("test\x01\x02\x03value") == "testvalue"

    def test_newlines_preserved(self):
        # Newlines and tabs are common whitespace, should be preserved
        assert sanitize_powershell_string("line1\nline2") == "line1\nline2"

    def test_combined_attack(self):
        malicious = "test`; Remove-Item\x00 C:\\important'"
        sanitized = sanitize_powershell_string(malicious)
        assert "`" not in sanitized
        assert "\x00" not in sanitized
        # Single quotes should be doubled (escaped for PowerShell)
        assert "''" in sanitized  # The original ' becomes ''
