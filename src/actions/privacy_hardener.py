"""Windows Privacy Registry Hardener - Disables privacy-hostile Windows features.

Windows ships with numerous privacy-invasive settings enabled by default:
advertising ID tracking, activity history, diagnostic data collection,
tailored experiences, input personalization, Copilot, Recall, etc.

This module provides reversible registry-based hardening that disables
these features. Each tweak is documented with its purpose and the
specific registry key/value it modifies.

All changes create snapshots for full rollback support.
"""

import logging
from dataclasses import dataclass, field
from typing import Any

from src.core.models import ActionType, Snapshot
from src.core.powershell import SafePowerShell, create_powershell
from src.core.security import validate_registry_path

logger = logging.getLogger("debloatr.actions.privacy_hardener")


@dataclass
class PrivacyTweak:
    """A single privacy registry tweak.

    Attributes:
        id: Unique identifier for this tweak
        name: Human-readable name
        description: What this tweak does
        category: Category (advertising, telemetry, tracking, etc.)
        registry_path: Full registry path
        value_name: Registry value name
        desired_value: Value to set for privacy
        desired_type: Registry value type (DWord, String, etc.)
        default_value: Windows default value (for rollback reference)
        impact: What functionality is lost
        windows_versions: Which Windows versions this applies to
    """

    id: str
    name: str
    description: str
    category: str
    registry_path: str
    value_name: str
    desired_value: int | str
    desired_type: str = "DWord"
    default_value: int | str | None = None
    impact: str = ""
    windows_versions: list[str] = field(default_factory=lambda: ["10", "11"])


# All privacy tweaks organized by category
PRIVACY_TWEAKS: list[PrivacyTweak] = [
    # --- Advertising ---
    PrivacyTweak(
        id="disable-advertising-id",
        name="Disable Advertising ID",
        description="Prevents Windows from assigning a unique advertising ID to track you across apps",
        category="advertising",
        registry_path=r"HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
        value_name="Enabled",
        desired_value=0,
        default_value=1,
        impact="Apps cannot use your advertising ID for targeted ads",
    ),
    PrivacyTweak(
        id="disable-advertising-id-machine",
        name="Disable Advertising ID (Machine-wide)",
        description="Machine-wide policy to disable the advertising ID",
        category="advertising",
        registry_path=r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo",
        value_name="DisabledByGroupPolicy",
        desired_value=1,
        default_value=0,
        impact="Enforces advertising ID disabled for all users",
    ),

    # --- Telemetry & Diagnostics ---
    PrivacyTweak(
        id="minimize-telemetry",
        name="Set Telemetry to Security-only",
        description="Reduces Windows diagnostic data to the minimum required level (Security/Basic)",
        category="telemetry",
        registry_path=r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        value_name="AllowTelemetry",
        desired_value=0,  # 0=Security (Enterprise), 1=Basic, 2=Enhanced, 3=Full
        default_value=3,
        impact="Microsoft receives minimal diagnostic data. Some Windows Insider features may not work.",
    ),
    PrivacyTweak(
        id="disable-diagnostic-data-viewer",
        name="Disable Diagnostic Data Submission",
        description="Prevents sending detailed diagnostic data to Microsoft",
        category="telemetry",
        registry_path=r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        value_name="LimitDiagnosticLogCollection",
        desired_value=1,
        default_value=0,
        impact="Diagnostic log collection is limited",
    ),
    PrivacyTweak(
        id="disable-error-reporting",
        name="Disable Windows Error Reporting",
        description="Prevents automatic error report submission to Microsoft",
        category="telemetry",
        registry_path=r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting",
        value_name="Disabled",
        desired_value=1,
        default_value=0,
        impact="Crash reports are not sent to Microsoft",
    ),
    PrivacyTweak(
        id="disable-ceip",
        name="Disable Customer Experience Improvement Program",
        description="Opts out of the Windows CEIP data collection",
        category="telemetry",
        registry_path=r"HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows",
        value_name="CEIPEnable",
        desired_value=0,
        default_value=1,
        impact="No CEIP data collected",
    ),

    # --- Activity & Timeline ---
    PrivacyTweak(
        id="disable-activity-history",
        name="Disable Activity History",
        description="Prevents Windows from collecting activity history (app usage, file access, browsing)",
        category="tracking",
        registry_path=r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
        value_name="EnableActivityFeed",
        desired_value=0,
        default_value=1,
        impact="Timeline and activity history disabled",
    ),
    PrivacyTweak(
        id="disable-activity-upload",
        name="Disable Activity History Upload",
        description="Prevents uploading activity history to Microsoft cloud",
        category="tracking",
        registry_path=r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
        value_name="UploadUserActivities",
        desired_value=0,
        default_value=1,
        impact="Activity history is not synced to Microsoft account",
    ),

    # --- Input & Inking ---
    PrivacyTweak(
        id="disable-input-personalization",
        name="Disable Input Personalization",
        description="Prevents Windows from learning your typing and inking patterns",
        category="tracking",
        registry_path=r"HKCU:\Software\Microsoft\InputPersonalization",
        value_name="RestrictImplicitInkCollection",
        desired_value=1,
        default_value=0,
        impact="Typing suggestions may be less personalized",
    ),
    PrivacyTweak(
        id="disable-text-harvesting",
        name="Disable Text Input Harvesting",
        description="Prevents collecting text input data for personalization",
        category="tracking",
        registry_path=r"HKCU:\Software\Microsoft\InputPersonalization",
        value_name="RestrictImplicitTextCollection",
        desired_value=1,
        default_value=0,
        impact="Text input data not collected",
    ),
    PrivacyTweak(
        id="disable-handwriting-reporting",
        name="Disable Handwriting Error Reporting",
        description="Prevents sending handwriting recognition data to Microsoft",
        category="tracking",
        registry_path=r"HKCU:\Software\Microsoft\Input\TIPC",
        value_name="Enabled",
        desired_value=0,
        default_value=1,
        impact="Handwriting recognition errors not reported",
    ),

    # --- Tailored Experiences ---
    PrivacyTweak(
        id="disable-tailored-experiences",
        name="Disable Tailored Experiences",
        description="Prevents Microsoft from using diagnostic data to offer personalized tips and recommendations",
        category="advertising",
        registry_path=r"HKCU:\Software\Policies\Microsoft\Windows\CloudContent",
        value_name="DisableTailoredExperiencesWithDiagnosticData",
        desired_value=1,
        default_value=0,
        impact="No personalized suggestions based on diagnostic data",
    ),
    PrivacyTweak(
        id="disable-suggested-content",
        name="Disable Suggested Content in Settings",
        description="Prevents Microsoft from showing suggested content in the Settings app",
        category="advertising",
        registry_path=r"HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
        value_name="SubscribedContent-338393Enabled",
        desired_value=0,
        default_value=1,
        impact="No suggested apps or content in Settings",
    ),
    PrivacyTweak(
        id="disable-tips-notifications",
        name="Disable Tips and Suggestions Notifications",
        description="Prevents Windows from showing tips and suggestions notifications",
        category="advertising",
        registry_path=r"HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
        value_name="SubscribedContent-338389Enabled",
        desired_value=0,
        default_value=1,
        impact="No more 'Did you know?' tips",
    ),
    PrivacyTweak(
        id="disable-windows-spotlight-suggestions",
        name="Disable Windows Spotlight Suggestions",
        description="Prevents Microsoft-suggested content on the lock screen",
        category="advertising",
        registry_path=r"HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
        value_name="SubscribedContent-353698Enabled",
        desired_value=0,
        default_value=1,
        impact="Lock screen shows only your chosen background",
    ),
    PrivacyTweak(
        id="disable-preinstalled-apps",
        name="Disable Silent App Installation",
        description="Prevents Windows from silently installing promoted apps",
        category="advertising",
        registry_path=r"HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
        value_name="SilentInstalledAppsEnabled",
        desired_value=0,
        default_value=1,
        impact="Windows will not silently install apps like Candy Crush",
    ),

    # --- Location ---
    PrivacyTweak(
        id="disable-location-tracking",
        name="Disable Location Tracking",
        description="Prevents Windows and apps from accessing your location",
        category="tracking",
        registry_path=r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors",
        value_name="DisableLocation",
        desired_value=1,
        default_value=0,
        impact="Location-based features (Weather, Maps) will not know your location",
    ),

    # --- Copilot & AI (Windows 11) ---
    PrivacyTweak(
        id="disable-copilot",
        name="Disable Windows Copilot",
        description="Disables the Windows Copilot AI assistant",
        category="ai",
        registry_path=r"HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot",
        value_name="TurnOffWindowsCopilot",
        desired_value=1,
        default_value=0,
        impact="Copilot button and sidebar removed",
        windows_versions=["11"],
    ),
    PrivacyTweak(
        id="disable-recall",
        name="Disable Windows Recall",
        description="Disables the Windows Recall feature that takes periodic screenshots",
        category="ai",
        registry_path=r"HKCU:\Software\Policies\Microsoft\Windows\WindowsAI",
        value_name="DisableAIDataAnalysis",
        desired_value=1,
        default_value=0,
        impact="Recall will not take periodic screenshots of your activity",
        windows_versions=["11"],
    ),

    # --- Clipboard & Sync ---
    PrivacyTweak(
        id="disable-clipboard-history",
        name="Disable Clipboard History Cloud Sync",
        description="Prevents clipboard history from syncing across devices via Microsoft account",
        category="tracking",
        registry_path=r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
        value_name="AllowCrossDeviceClipboard",
        desired_value=0,
        default_value=1,
        impact="Clipboard data stays on this device only",
    ),

    # --- Search ---
    PrivacyTweak(
        id="disable-search-highlights",
        name="Disable Search Highlights",
        description="Removes Bing web content from Windows Search",
        category="advertising",
        registry_path=r"HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings",
        value_name="IsDynamicSearchBoxEnabled",
        desired_value=0,
        default_value=1,
        impact="Search bar shows only local results, no Bing suggestions",
    ),
    PrivacyTweak(
        id="disable-web-search",
        name="Disable Web Search in Start Menu",
        description="Prevents Start Menu searches from querying Bing",
        category="advertising",
        registry_path=r"HKCU:\Software\Policies\Microsoft\Windows\Explorer",
        value_name="DisableSearchBoxSuggestions",
        desired_value=1,
        default_value=0,
        impact="Start Menu search only searches local files and apps",
    ),

    # --- Wi-Fi Sense ---
    PrivacyTweak(
        id="disable-wifi-sense",
        name="Disable Wi-Fi Sense",
        description="Prevents automatic sharing of Wi-Fi credentials with contacts",
        category="tracking",
        registry_path=r"HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots",
        value_name="Value",
        desired_value=0,
        default_value=1,
        impact="Wi-Fi passwords are not shared with contacts",
        windows_versions=["10"],
    ),
]

# Group tweaks by category for easy access
TWEAK_CATEGORIES: dict[str, str] = {
    "advertising": "Advertising & Promoted Content",
    "telemetry": "Telemetry & Diagnostics",
    "tracking": "Tracking & Data Collection",
    "ai": "AI Features (Copilot, Recall)",
}


@dataclass
class HardeningResult:
    """Result of applying privacy hardening.

    Attributes:
        success: Whether all tweaks were applied successfully
        tweaks_applied: Number of tweaks successfully applied
        tweaks_skipped: Number of tweaks already in desired state
        tweaks_failed: Number of tweaks that failed
        errors: List of error messages
        snapshot: Snapshot for rollback
        categories_applied: Which categories were applied
    """

    success: bool
    tweaks_applied: int = 0
    tweaks_skipped: int = 0
    tweaks_failed: int = 0
    errors: list[str] = field(default_factory=list)
    snapshot: Snapshot | None = None
    categories_applied: list[str] = field(default_factory=list)
    details: list[dict[str, Any]] = field(default_factory=list)


class PrivacyHardener:
    """Applies reversible privacy hardening via Windows registry.

    Each tweak modifies a specific registry key to disable a
    privacy-invasive Windows feature. All changes are captured
    in snapshots for full rollback support.

    Example:
        hardener = PrivacyHardener()

        # Apply all privacy tweaks
        result = hardener.harden_all()

        # Or apply specific categories
        result = hardener.harden(categories=["advertising", "telemetry"])

        # Check current state
        status = hardener.get_status()

        # Undo all changes
        hardener.restore_defaults()
    """

    def __init__(self, dry_run: bool = False) -> None:
        """Initialize the privacy hardener.

        Args:
            dry_run: If True, simulate without making changes
        """
        self.dry_run = dry_run
        self._ps = create_powershell(dry_run=dry_run)

    def harden_all(self) -> HardeningResult:
        """Apply all privacy tweaks.

        Returns:
            HardeningResult with operation details
        """
        return self.harden(categories=None)

    def harden(
        self,
        categories: list[str] | None = None,
        tweak_ids: list[str] | None = None,
    ) -> HardeningResult:
        """Apply privacy tweaks by category or specific IDs.

        Args:
            categories: List of categories to apply (None = all)
            tweak_ids: Specific tweak IDs to apply (overrides categories)

        Returns:
            HardeningResult with operation details
        """
        # Select tweaks
        if tweak_ids:
            tweaks = [t for t in PRIVACY_TWEAKS if t.id in tweak_ids]
        elif categories:
            tweaks = [t for t in PRIVACY_TWEAKS if t.category in categories]
        else:
            tweaks = list(PRIVACY_TWEAKS)

        if not tweaks:
            return HardeningResult(success=True, tweaks_applied=0)

        # Capture current state for rollback
        previous_state: dict[str, Any] = {}
        for tweak in tweaks:
            current = self._read_registry_value(tweak.registry_path, tweak.value_name)
            previous_state[tweak.id] = {
                "registry_path": tweak.registry_path,
                "value_name": tweak.value_name,
                "previous_value": current,
                "previous_type": tweak.desired_type,
            }

        snapshot = Snapshot(
            component_id="privacy-hardener",
            action=ActionType.DISABLE,
            captured_state=previous_state,
        )

        applied = 0
        skipped = 0
        failed = 0
        errors: list[str] = []
        details: list[dict[str, Any]] = []
        applied_categories: set[str] = set()

        for tweak in tweaks:
            # Check current value
            current = previous_state[tweak.id]["previous_value"]

            # Skip if already in desired state
            if current is not None and str(current) == str(tweak.desired_value):
                skipped += 1
                details.append({
                    "id": tweak.id,
                    "name": tweak.name,
                    "status": "skipped",
                    "reason": "Already in desired state",
                })
                continue

            # Validate registry path
            if not validate_registry_path(tweak.registry_path):
                failed += 1
                errors.append(f"{tweak.name}: Registry path rejected by security validation")
                continue

            # Apply the tweak
            result = self._apply_tweak(tweak)

            if result:
                applied += 1
                applied_categories.add(tweak.category)
                details.append({
                    "id": tweak.id,
                    "name": tweak.name,
                    "status": "applied",
                    "previous": current,
                    "new": tweak.desired_value,
                })
                logger.info(f"Applied privacy tweak: {tweak.name}")
            else:
                failed += 1
                errors.append(f"{tweak.name}: Failed to apply")
                details.append({
                    "id": tweak.id,
                    "name": tweak.name,
                    "status": "failed",
                })

        return HardeningResult(
            success=failed == 0,
            tweaks_applied=applied,
            tweaks_skipped=skipped,
            tweaks_failed=failed,
            errors=errors,
            snapshot=snapshot,
            categories_applied=sorted(applied_categories),
            details=details,
        )

    def restore_defaults(self) -> HardeningResult:
        """Restore all tweaks to their Windows default values.

        Returns:
            HardeningResult with operation details
        """
        applied = 0
        failed = 0
        errors: list[str] = []

        for tweak in PRIVACY_TWEAKS:
            if tweak.default_value is None:
                continue

            result = self._set_registry_value(
                tweak.registry_path,
                tweak.value_name,
                tweak.default_value,
                tweak.desired_type,
            )

            if result:
                applied += 1
            else:
                failed += 1
                errors.append(f"{tweak.name}: Failed to restore default")

        return HardeningResult(
            success=failed == 0,
            tweaks_applied=applied,
            tweaks_failed=failed,
            errors=errors,
        )

    def get_status(self) -> list[dict[str, Any]]:
        """Get current status of all privacy tweaks.

        Returns:
            List of dictionaries with tweak status information
        """
        results: list[dict[str, Any]] = []

        for tweak in PRIVACY_TWEAKS:
            current = self._read_registry_value(tweak.registry_path, tweak.value_name)

            is_hardened = current is not None and str(current) == str(tweak.desired_value)

            results.append({
                "id": tweak.id,
                "name": tweak.name,
                "category": tweak.category,
                "category_name": TWEAK_CATEGORIES.get(tweak.category, tweak.category),
                "description": tweak.description,
                "impact": tweak.impact,
                "is_hardened": is_hardened,
                "current_value": current,
                "desired_value": tweak.desired_value,
                "default_value": tweak.default_value,
            })

        return results

    def get_categories(self) -> dict[str, dict[str, Any]]:
        """Get available categories with tweak counts.

        Returns:
            Dictionary of category -> info
        """
        categories: dict[str, dict[str, Any]] = {}
        for cat_id, cat_name in TWEAK_CATEGORIES.items():
            tweaks_in_cat = [t for t in PRIVACY_TWEAKS if t.category == cat_id]
            categories[cat_id] = {
                "name": cat_name,
                "tweak_count": len(tweaks_in_cat),
                "tweaks": [{"id": t.id, "name": t.name} for t in tweaks_in_cat],
            }
        return categories

    def _apply_tweak(self, tweak: PrivacyTweak) -> bool:
        """Apply a single privacy tweak."""
        return self._set_registry_value(
            tweak.registry_path,
            tweak.value_name,
            tweak.desired_value,
            tweak.desired_type,
        )

    def _set_registry_value(
        self,
        path: str,
        name: str,
        value: int | str,
        value_type: str = "DWord",
    ) -> bool:
        """Set a registry value, creating the key if it doesn't exist."""
        if self.dry_run:
            logger.debug(f"[DRY RUN] Would set {path}\\{name} = {value}")
            return True

        # Build PowerShell command to ensure key exists and set value
        cmd = (
            f"if (-not (Test-Path '{path}')) {{ "
            f"New-Item -Path '{path}' -Force | Out-Null "
            f"}}; "
            f"Set-ItemProperty -Path '{path}' -Name '{name}' "
            f"-Value {value} -Type {value_type} -Force -ErrorAction Stop"
        )

        result = self._ps.run(cmd)
        return result.success

    def _read_registry_value(self, path: str, name: str) -> Any:
        """Read a registry value, returning None if not found."""
        if self.dry_run:
            return None

        result = self._ps.run(
            f"(Get-ItemProperty -Path '{path}' -Name '{name}' "
            f"-ErrorAction SilentlyContinue).'{name}'"
        )

        if result.success and result.output.strip():
            try:
                return int(result.output.strip())
            except ValueError:
                return result.output.strip()
        return None


def create_privacy_hardener(dry_run: bool = False) -> PrivacyHardener:
    """Create a privacy hardener.

    Args:
        dry_run: If True, simulate without changes

    Returns:
        PrivacyHardener instance
    """
    return PrivacyHardener(dry_run=dry_run)
