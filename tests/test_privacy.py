"""Tests for privacy enhancement modules.

Tests the new privacy features:
- Hosts file telemetry blocker
- DNS privacy checker
- Privacy registry hardener
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.actions.hosts_blocker import (
    BLOCK_END,
    BLOCK_START,
    SINKHOLE,
    TELEMETRY_DOMAINS,
    HostsFileBlocker,
    create_hosts_blocker,
)
from src.actions.privacy_hardener import (
    PRIVACY_TWEAKS,
    TWEAK_CATEGORIES,
    PrivacyHardener,
    PrivacyTweak,
    create_privacy_hardener,
)
from src.discovery.dns_privacy import (
    DNSPrivacyChecker,
    DNSStatus,
    SECURE_DNS_PROVIDERS,
    create_dns_checker,
)


# --- Hosts File Blocker Tests ---


class TestHostsFileBlocker:
    """Tests for the hosts file telemetry blocker."""

    def test_create_blocker(self):
        blocker = create_hosts_blocker(dry_run=True)
        assert isinstance(blocker, HostsFileBlocker)
        assert blocker.dry_run is True

    def test_get_available_categories(self):
        blocker = HostsFileBlocker(dry_run=True)
        categories = blocker.get_available_categories()
        assert "microsoft_telemetry" in categories
        assert "advertising_general" in categories
        assert all(isinstance(v, int) and v > 0 for v in categories.values())

    def test_dry_run_block_telemetry(self):
        blocker = HostsFileBlocker(dry_run=True)
        result = blocker.block_telemetry(["microsoft_telemetry"])
        assert result.success is True
        assert result.domains_blocked > 0
        assert "microsoft_telemetry" in result.categories_applied

    def test_dry_run_block_all(self):
        blocker = HostsFileBlocker(dry_run=True)
        result = blocker.block_telemetry()  # All categories
        assert result.success is True
        total = sum(len(domains) for domains in TELEMETRY_DOMAINS.values())
        assert result.domains_blocked == total

    def test_dry_run_unblock_all(self):
        blocker = HostsFileBlocker(dry_run=True)
        result = blocker.unblock_all()
        assert result.success is True

    def test_empty_categories(self):
        blocker = HostsFileBlocker(dry_run=True)
        result = blocker.block_telemetry(categories=[])
        assert result.success is False
        assert "No domains" in result.error_message

    def test_unknown_category_warns(self):
        blocker = HostsFileBlocker(dry_run=True)
        result = blocker.block_telemetry(categories=["nonexistent"])
        assert result.success is False

    def test_telemetry_domains_structure(self):
        """Verify telemetry domain lists are well-formed."""
        for category, domains in TELEMETRY_DOMAINS.items():
            assert isinstance(domains, list)
            assert len(domains) > 0
            for domain in domains:
                assert isinstance(domain, str)
                assert "." in domain  # Must be a valid-looking domain

    def test_block_markers_defined(self):
        """Verify marker comments are properly defined."""
        assert "Debloatr" in BLOCK_START
        assert "Debloatr" in BLOCK_END
        assert SINKHOLE == "0.0.0.0"

    def test_custom_domains(self):
        blocker = HostsFileBlocker(dry_run=True)
        result = blocker.block_telemetry(
            categories=["microsoft_telemetry"],
            custom_domains=["custom.tracking.example.com"],
        )
        assert result.success is True
        # Total should include microsoft_telemetry + 1 custom
        expected = len(TELEMETRY_DOMAINS["microsoft_telemetry"]) + 1
        assert result.domains_blocked == expected

    def test_get_blocked_domains_no_file(self):
        """When hosts file doesn't exist, return empty list."""
        blocker = HostsFileBlocker(dry_run=True, hosts_path=Path("/nonexistent/hosts"))
        domains = blocker.get_blocked_domains()
        assert domains == []


# --- DNS Privacy Checker Tests ---


class TestDNSPrivacyChecker:
    """Tests for the DNS privacy checker."""

    def test_create_checker(self):
        checker = create_dns_checker(dry_run=True)
        assert isinstance(checker, DNSPrivacyChecker)

    def test_secure_providers_structure(self):
        """Verify provider data is well-formed."""
        for name, config in SECURE_DNS_PROVIDERS.items():
            assert "primary_v4" in config
            assert "secondary_v4" in config
            assert "doh_template" in config
            assert "privacy_policy" in config
            # IPs should look valid
            assert config["primary_v4"].count(".") == 3

    def test_identify_provider(self):
        checker = DNSPrivacyChecker(dry_run=True)
        assert checker._identify_provider("1.1.1.1") == "Cloudflare"
        assert checker._identify_provider("8.8.8.8") == "Google"
        assert checker._identify_provider("9.9.9.9") == "Quad9"
        assert checker._identify_provider("192.168.1.1") == ""

    def test_get_secure_providers(self):
        checker = DNSPrivacyChecker(dry_run=True)
        providers = checker.get_secure_providers()
        assert "Cloudflare" in providers
        assert "Quad9" in providers
        assert "Mullvad" in providers

    def test_dns_status_defaults(self):
        status = DNSStatus(interface_name="test")
        assert status.is_plaintext is True
        assert status.doh_enabled is False
        assert status.privacy_risk == "high"

    def test_check_returns_report(self):
        checker = DNSPrivacyChecker(dry_run=True)
        report = checker.check()
        # On non-Windows, should return unknown risk
        assert report.overall_risk in ("high", "medium", "low", "unknown")


# --- Privacy Registry Hardener Tests ---


class TestPrivacyHardener:
    """Tests for the privacy registry hardener."""

    def test_create_hardener(self):
        hardener = create_privacy_hardener(dry_run=True)
        assert isinstance(hardener, PrivacyHardener)
        assert hardener.dry_run is True

    def test_tweaks_well_formed(self):
        """Verify all privacy tweaks have required fields."""
        for tweak in PRIVACY_TWEAKS:
            assert tweak.id, f"Missing ID for tweak: {tweak.name}"
            assert tweak.name, f"Missing name for tweak: {tweak.id}"
            assert tweak.description, f"Missing description for: {tweak.id}"
            assert tweak.category in TWEAK_CATEGORIES, f"Unknown category for: {tweak.id}"
            assert tweak.registry_path, f"Missing registry_path for: {tweak.id}"
            assert tweak.value_name, f"Missing value_name for: {tweak.id}"

    def test_tweak_ids_unique(self):
        """Verify all tweak IDs are unique."""
        ids = [t.id for t in PRIVACY_TWEAKS]
        assert len(ids) == len(set(ids)), "Duplicate tweak IDs found"

    def test_categories_complete(self):
        """Verify all used categories are documented."""
        used = {t.category for t in PRIVACY_TWEAKS}
        documented = set(TWEAK_CATEGORIES.keys())
        assert used <= documented, f"Undocumented categories: {used - documented}"

    def test_get_categories(self):
        hardener = PrivacyHardener(dry_run=True)
        categories = hardener.get_categories()
        assert "advertising" in categories
        assert "telemetry" in categories
        assert "tracking" in categories
        assert "ai" in categories
        for cat in categories.values():
            assert "name" in cat
            assert "tweak_count" in cat
            assert cat["tweak_count"] > 0

    def test_dry_run_harden_all(self):
        hardener = PrivacyHardener(dry_run=True)
        result = hardener.harden_all()
        assert result.success is True

    def test_dry_run_harden_by_category(self):
        hardener = PrivacyHardener(dry_run=True)
        result = hardener.harden(categories=["advertising"])
        assert result.success is True

    def test_dry_run_harden_by_id(self):
        hardener = PrivacyHardener(dry_run=True)
        result = hardener.harden(tweak_ids=["disable-advertising-id"])
        assert result.success is True

    def test_empty_tweak_ids(self):
        hardener = PrivacyHardener(dry_run=True)
        result = hardener.harden(tweak_ids=["nonexistent-id"])
        assert result.success is True
        assert result.tweaks_applied == 0

    def test_get_status_dry_run(self):
        hardener = PrivacyHardener(dry_run=True)
        status = hardener.get_status()
        assert isinstance(status, list)
        assert len(status) == len(PRIVACY_TWEAKS)
        for item in status:
            assert "id" in item
            assert "name" in item
            assert "is_hardened" in item
            assert "category" in item

    def test_advertising_tweaks_exist(self):
        ad_tweaks = [t for t in PRIVACY_TWEAKS if t.category == "advertising"]
        assert len(ad_tweaks) >= 2  # At least advertising ID + machine-wide

    def test_telemetry_tweaks_exist(self):
        tel_tweaks = [t for t in PRIVACY_TWEAKS if t.category == "telemetry"]
        assert len(tel_tweaks) >= 3  # Telemetry level, error reporting, CEIP

    def test_ai_tweaks_exist(self):
        ai_tweaks = [t for t in PRIVACY_TWEAKS if t.category == "ai"]
        assert len(ai_tweaks) >= 2  # Copilot and Recall

    def test_registry_paths_valid(self):
        """Verify all tweak registry paths pass security validation."""
        from src.core.security import validate_registry_path
        for tweak in PRIVACY_TWEAKS:
            assert validate_registry_path(tweak.registry_path), (
                f"Tweak {tweak.id} has invalid registry path: {tweak.registry_path}"
            )
