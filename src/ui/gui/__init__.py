"""GUI module using PySide6 (Qt6).

This module provides the graphical user interface for Debloatr.
Requires PySide6 to be installed: pip install PySide6
"""

try:
    from .main import (
        ComponentDetailWidget,
        ComponentTreeWidget,
        DashboardWidget,
        MainWindow,
        SessionHistoryWidget,
        run_gui_app,
    )

    __all__ = [
        "MainWindow",
        "DashboardWidget",
        "ComponentTreeWidget",
        "ComponentDetailWidget",
        "SessionHistoryWidget",
        "run_gui_app",
    ]
except ImportError:
    # PySide6 not available
    __all__ = []
