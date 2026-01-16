"""Pytest configuration and shared fixtures."""

import pytest
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def sample_component():
    """Create a sample component for testing."""
    from src.core.models import Component, ComponentType

    return Component(
        component_type=ComponentType.PROGRAM,
        name="sample-program",
        display_name="Sample Program",
        publisher="Sample Publisher",
        install_path=Path("C:/Program Files/Sample"),
    )


@pytest.fixture
def sample_components():
    """Create a list of sample components for testing."""
    from src.core.models import Component, ComponentType, Classification

    return [
        Component(
            component_type=ComponentType.PROGRAM,
            name="bloatware-1",
            display_name="Bloatware App",
            publisher="Bloat Corp",
            classification=Classification.BLOAT,
        ),
        Component(
            component_type=ComponentType.SERVICE,
            name="telemetry-service",
            display_name="Telemetry Service",
            publisher="Data Corp",
            classification=Classification.AGGRESSIVE,
        ),
        Component(
            component_type=ComponentType.STARTUP,
            name="useful-startup",
            display_name="Useful Startup",
            publisher="Good Corp",
            classification=Classification.OPTIONAL,
        ),
    ]
