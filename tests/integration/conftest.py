"""Shared fixtures for integration tests.

All integration tests require Windows and are skipped on other platforms.
"""

import os
import sys

import pytest

# Skip entire directory on non-Windows
pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Integration tests require Windows",
)


@pytest.fixture
def real_config():
    """Create a real Config pointing to a temporary directory."""
    import tempfile
    from pathlib import Path

    from src.core.config import Config

    with tempfile.TemporaryDirectory(prefix="debloatr_test_") as tmpdir:
        config = Config(config_dir=Path(tmpdir))
        config.ensure_directories()
        yield config


@pytest.fixture
def is_admin():
    """Check if the test is running with admin privileges."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False
