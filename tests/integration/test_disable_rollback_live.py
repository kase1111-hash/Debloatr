"""Integration tests for the disable → rollback cycle.

IMPORTANT: These tests modify system state (disable/re-enable a UWP app).
They target a safe, non-essential UWP app that can be freely toggled.
Requires admin privileges.
"""

import sys

import pytest

pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="Requires Windows"),
    pytest.mark.slow,
]

# A safe UWP app to test against — Microsoft Bing Weather is non-essential
# and present on most Windows 10/11 installations
SAFE_TEST_APP = "Microsoft.BingWeather"


def _is_admin() -> bool:
    """Check for admin privileges."""
    try:
        import ctypes

        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class TestDisableRollbackLive:
    """Test disable and rollback against a real safe UWP app.

    These tests require admin privileges and a Windows installation
    with the target UWP app installed.
    """

    @pytest.fixture(autouse=True)
    def require_admin(self):
        if not _is_admin():
            pytest.skip("Requires admin privileges")

    @pytest.fixture
    def target_component(self, real_config):
        """Find the target UWP app for testing."""
        from src.discovery.programs import ProgramsScanner

        scanner = ProgramsScanner(scan_uwp=True, scan_portable=False)
        components = scanner.scan()

        for comp in components:
            if SAFE_TEST_APP.lower() in (comp.name or "").lower():
                return comp

        pytest.skip(f"{SAFE_TEST_APP} not installed on this system")

    def test_classify_target(self, real_config, target_component):
        """The test target should be classifiable."""
        from src.classification.engine import ClassificationEngine

        engine = ClassificationEngine(real_config)
        decision = engine.classify(target_component)

        assert decision is not None
        print(f"\n{target_component.display_name}: "
              f"{decision.classification.value} "
              f"(confidence={decision.confidence:.2f}, source={decision.source.value})")

    def test_plan_disable(self, real_config, target_component):
        """Should be able to plan a disable action."""
        from src.actions.planner import create_default_planner
        from src.core.models import ActionType

        planner = create_default_planner(real_config)
        plan = planner.create_plan(target_component, ActionType.DISABLE)

        assert plan is not None
        assert plan.action == ActionType.DISABLE
        print(f"\nPlan: {plan.action.value} {target_component.display_name}")
        print(f"  Risk: {plan.risk_level.name}")
        print(f"  Warnings: {plan.warnings}")

    def test_dry_run_disable(self, real_config, target_component):
        """Dry-run disable should succeed without changing state."""
        from src.actions.executor import create_execution_engine
        from src.core.models import ActionType, ExecutionMode

        engine = create_execution_engine(real_config, mode=ExecutionMode.DRY_RUN)
        result = engine.execute(target_component, ActionType.DISABLE)

        assert result.success, f"Dry-run failed: {result.error_message}"
        print(f"\nDry-run result: success={result.success}")
