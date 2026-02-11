"""Main GUI window for Debloatr.

This module provides the main application window using PySide6 (Qt6).
Requires PySide6 to be installed: pip install PySide6

This module uses lazy imports to avoid failing if PySide6 is not installed.
The actual import and class creation happens only in run_gui_app().
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.core.config import Config


def run_gui_app(config: Config) -> int:
    """Run the GUI application.

    This function lazily imports PySide6 and creates all GUI classes
    only when actually needed, allowing the module to be imported
    even when PySide6 is not installed.

    Args:
        config: Configuration object

    Returns:
        Exit code

    Raises:
        ImportError: If PySide6 is not installed
    """
    # Lazy import of PySide6 - only happens when GUI is actually started
    try:
        from PySide6.QtCore import Qt, QThread, Signal
        from PySide6.QtGui import QAction, QColor, QFont
        from PySide6.QtWidgets import (
            QApplication,
            QComboBox,
            QDialog,
            QDialogButtonBox,
            QFrame,
            QGroupBox,
            QHBoxLayout,
            QHeaderView,
            QLabel,
            QLineEdit,
            QMainWindow,
            QMenu,
            QMessageBox,
            QProgressBar,
            QPushButton,
            QSplitter,
            QStatusBar,
            QTableWidget,
            QTableWidgetItem,
            QTabWidget,
            QTextEdit,
            QToolBar,
            QTreeWidget,
            QTreeWidgetItem,
            QVBoxLayout,
            QWidget,
        )
    except ImportError as exc:
        raise ImportError("PySide6 is not installed. Install with: pip install PySide6") from exc

    # Import core modules
    from src.actions.executor import ExecutionEngine, ExecutionResult
    from src.actions.planner import ActionPlanner
    from src.core.models import (
        ActionPlan,
        ActionType,
        Classification,
        Component,
        ComponentType,
        ExecutionMode,
        RiskLevel,
    )
    from src.core.orchestrator import ScanOrchestrator
    from src.core.rollback import create_rollback_manager
    from src.core.session import create_session_manager

    # Color definitions for classifications
    CLASSIFICATION_COLORS = {
        Classification.CORE: "#3498db",  # Blue
        Classification.ESSENTIAL: "#1abc9c",  # Teal
        Classification.OPTIONAL: "#2ecc71",  # Green
        Classification.BLOAT: "#f39c12",  # Orange
        Classification.AGGRESSIVE: "#e74c3c",  # Red
        Classification.UNKNOWN: "#95a5a6",  # Gray
    }

    RISK_COLORS = {
        RiskLevel.NONE: "#2ecc71",  # Green
        RiskLevel.LOW: "#3498db",  # Blue
        RiskLevel.MEDIUM: "#f39c12",  # Orange
        RiskLevel.HIGH: "#e74c3c",  # Red
        RiskLevel.CRITICAL: "#9b59b6",  # Purple
    }

    class ScanWorker(QThread):
        """Worker thread for running scans."""

        progress = Signal(str, int)  # message, percent
        finished = Signal(object)  # result
        error = Signal(str)  # error message

        def __init__(self, cfg: Config, modules: list[str] | None = None):
            super().__init__()
            self.config = cfg
            self.modules = modules

        def run(self):
            try:
                self.progress.emit("Initializing scan...", 0)
                orchestrator = ScanOrchestrator(self.config)

                self.progress.emit("Scanning components...", 25)
                result = orchestrator.run_scan(modules=self.modules)

                self.progress.emit("Processing results...", 90)
                self.finished.emit(result)
            except Exception as e:
                self.error.emit(str(e))

    class ActionWorker(QThread):
        """Worker thread for executing actions off the GUI thread."""

        progress = Signal(str, int)  # message, percent
        finished = Signal(object)  # ExecutionResult
        error = Signal(str)  # error message

        def __init__(
            self,
            engine: ExecutionEngine,
            plan: ActionPlan,
        ):
            super().__init__()
            self.engine = engine
            self.plan = plan

        def run(self):
            try:
                self.progress.emit(
                    f"Executing {self.plan.action.value} on "
                    f"{self.plan.component.display_name}...",
                    50,
                )
                result = self.engine.execute(self.plan)
                self.finished.emit(result)
            except Exception as e:
                self.error.emit(str(e))

    class BatchActionWorker(QThread):
        """Worker thread for executing batch actions."""

        progress = Signal(str, int)  # message, percent
        finished = Signal(object)  # list[ExecutionResult]
        error = Signal(str)

        def __init__(
            self,
            engine: ExecutionEngine,
            plans: list[ActionPlan],
        ):
            super().__init__()
            self.engine = engine
            self.plans = plans

        def run(self):
            try:
                results = []
                total = len(self.plans)
                for i, plan in enumerate(self.plans):
                    percent = int((i / total) * 100)
                    self.progress.emit(
                        f"[{i + 1}/{total}] {plan.action.value} "
                        f"{plan.component.display_name}...",
                        percent,
                    )
                    result = self.engine.execute(plan)
                    results.append(result)
                self.finished.emit(results)
            except Exception as e:
                self.error.emit(str(e))

    class DashboardWidget(QWidget):
        """Dashboard view showing scan summary and quick actions."""

        def __init__(self, parent=None):
            super().__init__(parent)
            self.setup_ui()

        def setup_ui(self):
            layout = QVBoxLayout(self)

            # Title
            title = QLabel("System Overview")
            title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
            layout.addWidget(title)

            # Stats row
            stats_layout = QHBoxLayout()

            # Create stat boxes
            self.total_label = self._create_stat_box("Total Components", "0")
            self.bloat_label = self._create_stat_box("Bloatware", "0", "#f39c12")
            self.aggressive_label = self._create_stat_box("Aggressive", "0", "#e74c3c")
            self.safe_label = self._create_stat_box("Safe to Remove", "0", "#2ecc71")

            stats_layout.addWidget(self.total_label)
            stats_layout.addWidget(self.bloat_label)
            stats_layout.addWidget(self.aggressive_label)
            stats_layout.addWidget(self.safe_label)

            layout.addLayout(stats_layout)

            # Classification breakdown
            breakdown_group = QGroupBox("Classification Breakdown")
            breakdown_layout = QVBoxLayout(breakdown_group)

            self.classification_table = QTableWidget(6, 3)
            self.classification_table.setHorizontalHeaderLabels(["Classification", "Count", ""])
            self.classification_table.horizontalHeader().setSectionResizeMode(
                0, QHeaderView.ResizeMode.Stretch
            )
            self.classification_table.horizontalHeader().setSectionResizeMode(
                1, QHeaderView.ResizeMode.ResizeToContents
            )
            self.classification_table.horizontalHeader().setSectionResizeMode(
                2, QHeaderView.ResizeMode.ResizeToContents
            )
            self.classification_table.verticalHeader().setVisible(False)

            breakdown_layout.addWidget(self.classification_table)
            layout.addWidget(breakdown_group)

            # Quick actions
            actions_group = QGroupBox("Quick Actions")
            actions_layout = QHBoxLayout(actions_group)

            self.scan_btn = QPushButton("Scan System")
            self.safe_debloat_btn = QPushButton("Safe Debloat")
            self.safe_debloat_btn.setToolTip("Disable all BLOAT and AGGRESSIVE components")
            self.undo_btn = QPushButton("Undo Last Session")

            actions_layout.addWidget(self.scan_btn)
            actions_layout.addWidget(self.safe_debloat_btn)
            actions_layout.addWidget(self.undo_btn)

            layout.addWidget(actions_group)
            layout.addStretch()

        def _create_stat_box(self, title: str, value: str, color: str = "#3498db") -> QFrame:
            """Create a stat display box."""
            frame = QFrame()
            frame.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Raised)
            frame.setStyleSheet(f"""
                QFrame {{
                    background-color: {color};
                    border-radius: 8px;
                    padding: 10px;
                }}
                QLabel {{
                    color: white;
                }}
            """)

            layout = QVBoxLayout(frame)

            value_label = QLabel(value)
            value_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
            value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            value_label.setObjectName("value")

            title_label = QLabel(title)
            title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

            layout.addWidget(value_label)
            layout.addWidget(title_label)

            return frame

        def update_stats(self, components: list[Component]):
            """Update dashboard statistics."""
            total = len(components)

            # Count by classification
            counts = {}
            for classification in Classification:
                counts[classification] = sum(
                    1 for c in components if c.classification == classification
                )

            # Update stat boxes
            self.total_label.findChild(QLabel, "value").setText(str(total))
            self.bloat_label.findChild(QLabel, "value").setText(
                str(counts.get(Classification.BLOAT, 0))
            )
            self.aggressive_label.findChild(QLabel, "value").setText(
                str(counts.get(Classification.AGGRESSIVE, 0))
            )

            # Safe to remove = BLOAT + AGGRESSIVE
            safe = counts.get(Classification.BLOAT, 0) + counts.get(Classification.AGGRESSIVE, 0)
            self.safe_label.findChild(QLabel, "value").setText(str(safe))

            # Update classification table
            self.classification_table.setRowCount(len(Classification))
            for i, classification in enumerate(Classification):
                color = CLASSIFICATION_COLORS.get(classification, "#666")
                count = counts.get(classification, 0)

                name_item = QTableWidgetItem(classification.value)
                name_item.setBackground(QColor(color))
                name_item.setForeground(QColor("white"))

                count_item = QTableWidgetItem(str(count))
                count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

                # Progress bar for visual representation
                if total > 0:
                    percent = int((count / total) * 100)
                    bar_item = QTableWidgetItem(f"{percent}%")
                else:
                    bar_item = QTableWidgetItem("0%")
                bar_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

                self.classification_table.setItem(i, 0, name_item)
                self.classification_table.setItem(i, 1, count_item)
                self.classification_table.setItem(i, 2, bar_item)

    class ComponentTreeWidget(QWidget):
        """Tree view for browsing components."""

        component_selected = Signal(object)  # Component

        def __init__(self, parent=None):
            super().__init__(parent)
            self.components: list[Component] = []
            self.setup_ui()

        def setup_ui(self):
            layout = QVBoxLayout(self)

            # Filter bar
            filter_layout = QHBoxLayout()

            self.search_input = QLineEdit()
            self.search_input.setPlaceholderText("Search components...")
            self.search_input.textChanged.connect(self.apply_filter)

            self.type_filter = QComboBox()
            self.type_filter.addItem("All Types", None)
            for ct in ComponentType:
                self.type_filter.addItem(ct.name, ct)
            self.type_filter.currentIndexChanged.connect(self.apply_filter)

            self.class_filter = QComboBox()
            self.class_filter.addItem("All Classifications", None)
            for c in Classification:
                self.class_filter.addItem(c.value, c)
            self.class_filter.currentIndexChanged.connect(self.apply_filter)

            filter_layout.addWidget(QLabel("Search:"))
            filter_layout.addWidget(self.search_input)
            filter_layout.addWidget(QLabel("Type:"))
            filter_layout.addWidget(self.type_filter)
            filter_layout.addWidget(QLabel("Class:"))
            filter_layout.addWidget(self.class_filter)

            layout.addLayout(filter_layout)

            # Tree widget
            self.tree = QTreeWidget()
            self.tree.setHeaderLabels(["Name", "Type", "Classification", "Risk", "Publisher"])
            self.tree.setAlternatingRowColors(True)
            self.tree.itemSelectionChanged.connect(self._on_selection_changed)
            self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            self.tree.customContextMenuRequested.connect(self._show_context_menu)

            # Set column widths
            header = self.tree.header()
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)

            layout.addWidget(self.tree)

        def set_components(self, components: list[Component]):
            """Set the components to display."""
            self.components = components
            self.apply_filter()

        def apply_filter(self):
            """Apply current filters to the component list."""
            self.tree.clear()

            search = self.search_input.text().lower()
            type_filter = self.type_filter.currentData()
            class_filter = self.class_filter.currentData()

            # Group by type
            by_type: dict[ComponentType, list[Component]] = {}
            for comp in self.components:
                # Apply filters
                if (
                    search
                    and search not in comp.display_name.lower()
                    and search not in comp.name.lower()
                ):
                    continue
                if type_filter and comp.component_type != type_filter:
                    continue
                if class_filter and comp.classification != class_filter:
                    continue

                if comp.component_type not in by_type:
                    by_type[comp.component_type] = []
                by_type[comp.component_type].append(comp)

            # Build tree
            for comp_type, comps in sorted(by_type.items(), key=lambda x: x[0].name):
                type_item = QTreeWidgetItem([f"{comp_type.name} ({len(comps)})", "", "", "", ""])
                type_item.setExpanded(True)

                for comp in sorted(comps, key=lambda c: c.display_name):
                    class_color = CLASSIFICATION_COLORS.get(comp.classification, "#666")
                    risk_color = RISK_COLORS.get(comp.risk_level, "#666")

                    item = QTreeWidgetItem(
                        [
                            comp.display_name,
                            comp.component_type.name,
                            comp.classification.value,
                            comp.risk_level.name,
                            comp.publisher or "",
                        ]
                    )
                    item.setData(0, Qt.ItemDataRole.UserRole, comp)

                    # Set colors
                    item.setForeground(2, QColor(class_color))
                    item.setForeground(3, QColor(risk_color))

                    type_item.addChild(item)

                self.tree.addTopLevelItem(type_item)

        def _on_selection_changed(self):
            """Handle selection change."""
            items = self.tree.selectedItems()
            if items:
                comp = items[0].data(0, Qt.ItemDataRole.UserRole)
                if comp:
                    self.component_selected.emit(comp)

        def _show_context_menu(self, pos):
            """Show context menu for component."""
            item = self.tree.itemAt(pos)
            if not item:
                return

            comp = item.data(0, Qt.ItemDataRole.UserRole)
            if not comp:
                return

            menu = QMenu(self)

            disable_action = menu.addAction("Disable")
            disable_action.triggered.connect(lambda: self._action_disable(comp))

            contain_action = menu.addAction("Contain (Block Network)")
            contain_action.triggered.connect(lambda: self._action_contain(comp))

            menu.addSeparator()

            remove_action = menu.addAction("Remove")
            remove_action.triggered.connect(lambda: self._action_remove(comp))

            menu.exec(self.tree.mapToGlobal(pos))

        action_requested = Signal(object, object)  # Component, ActionType

        def _action_disable(self, comp: Component):
            """Request disable action for a component."""
            self.action_requested.emit(comp, ActionType.DISABLE)

        def _action_contain(self, comp: Component):
            """Request contain action for a component."""
            self.action_requested.emit(comp, ActionType.CONTAIN)

        def _action_remove(self, comp: Component):
            """Request remove action for a component."""
            self.action_requested.emit(comp, ActionType.REMOVE)

    class SessionHistoryWidget(QWidget):
        """Session history view."""

        def __init__(self, cfg: Config, parent=None):
            super().__init__(parent)
            self.config = cfg
            self.session_manager = create_session_manager(cfg)
            self.setup_ui()

        def setup_ui(self):
            layout = QVBoxLayout(self)

            # Title
            title = QLabel("Session History")
            title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
            layout.addWidget(title)

            # Session table
            self.table = QTableWidget()
            self.table.setColumnCount(5)
            self.table.setHorizontalHeaderLabels(
                ["Session ID", "Description", "Started", "Actions", "Status"]
            )
            self.table.horizontalHeader().setSectionResizeMode(
                0, QHeaderView.ResizeMode.ResizeToContents
            )
            self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            self.table.horizontalHeader().setSectionResizeMode(
                2, QHeaderView.ResizeMode.ResizeToContents
            )
            self.table.horizontalHeader().setSectionResizeMode(
                3, QHeaderView.ResizeMode.ResizeToContents
            )
            self.table.horizontalHeader().setSectionResizeMode(
                4, QHeaderView.ResizeMode.ResizeToContents
            )
            self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            self.table.setAlternatingRowColors(True)

            layout.addWidget(self.table)

            # Action buttons
            btn_layout = QHBoxLayout()

            self.refresh_btn = QPushButton("Refresh")
            self.refresh_btn.clicked.connect(self.refresh)

            self.undo_btn = QPushButton("Undo Selected")
            self.undo_btn.clicked.connect(self._undo_selected)

            self.details_btn = QPushButton("View Details")
            self.details_btn.clicked.connect(self._view_details)

            btn_layout.addWidget(self.refresh_btn)
            btn_layout.addWidget(self.undo_btn)
            btn_layout.addWidget(self.details_btn)
            btn_layout.addStretch()

            layout.addLayout(btn_layout)

            # Load initial data
            self.refresh()

        def refresh(self):
            """Refresh the session list."""
            sessions = self.session_manager.list_sessions()
            self.table.setRowCount(len(sessions))

            for i, session in enumerate(sessions):
                self.table.setItem(i, 0, QTableWidgetItem(session.session_id[:8] + "..."))
                self.table.setItem(i, 1, QTableWidgetItem(session.description or "(none)"))
                self.table.setItem(i, 2, QTableWidgetItem(session.started_at[:19]))
                self.table.setItem(i, 3, QTableWidgetItem(str(session.total_actions)))

                status = "Active" if session.is_active else "Ended"
                status_item = QTableWidgetItem(status)
                if session.is_active:
                    status_item.setForeground(QColor("#2ecc71"))
                self.table.setItem(i, 4, status_item)

                # Store full session ID
                self.table.item(i, 0).setData(Qt.ItemDataRole.UserRole, session.session_id)

        def _undo_selected(self):
            """Undo the selected session."""
            row = self.table.currentRow()
            if row < 0:
                QMessageBox.warning(self, "Warning", "Please select a session to undo.")
                return

            session_id = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)

            reply = QMessageBox.question(
                self,
                "Confirm Undo",
                f"Are you sure you want to undo session {session_id[:8]}...?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )

            if reply == QMessageBox.StandardButton.Yes:
                rollback_manager = create_rollback_manager(self.config)
                result = rollback_manager.rollback_session(session_id)

                if result.success:
                    QMessageBox.information(
                        self,
                        "Success",
                        f"Session rolled back successfully.\n"
                        f"Actions: {result.successful_rollbacks}/{result.total_actions}",
                    )
                else:
                    QMessageBox.warning(
                        self,
                        "Partial Failure",
                        f"Some actions could not be rolled back.\n"
                        f"Successful: {result.successful_rollbacks}\n"
                        f"Failed: {result.failed_rollbacks}",
                    )

                self.refresh()

        def _view_details(self):
            """View session details."""
            row = self.table.currentRow()
            if row < 0:
                return

            session_id = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
            actions = self.session_manager.get_session_actions(session_id)

            # Show details dialog
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Session Details: {session_id[:8]}...")
            dialog.setMinimumSize(600, 400)

            layout = QVBoxLayout(dialog)

            text = QTextEdit()
            text.setReadOnly(True)

            content = f"Session: {session_id}\n\n"
            content += "Actions:\n"
            content += "-" * 50 + "\n"

            for action in actions:
                status = "+" if action.success else "x"
                content += f"\n{status} {action.action}: {action.component_name}\n"
                if action.error_message:
                    content += f"   Error: {action.error_message}\n"
                content += f"   Rollback: {'Available' if action.rollback_available else 'Not available'}\n"

            text.setPlainText(content)
            layout.addWidget(text)

            btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
            btn_box.accepted.connect(dialog.accept)
            layout.addWidget(btn_box)

            dialog.exec()

    class ComponentDetailWidget(QWidget):
        """Detail panel for selected component."""

        action_requested = Signal(object, object)  # Component, ActionType

        def __init__(self, parent=None):
            super().__init__(parent)
            self.current_component: Component | None = None
            self.setup_ui()

        def setup_ui(self):
            layout = QVBoxLayout(self)

            # Title
            self.title_label = QLabel("Select a component")
            self.title_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
            layout.addWidget(self.title_label)

            # Details
            self.details_text = QTextEdit()
            self.details_text.setReadOnly(True)
            layout.addWidget(self.details_text)

            # Action buttons
            btn_layout = QHBoxLayout()

            self.disable_btn = QPushButton("Disable")
            self.disable_btn.setEnabled(False)
            self.disable_btn.clicked.connect(lambda: self._request_action(ActionType.DISABLE))

            self.contain_btn = QPushButton("Contain")
            self.contain_btn.setEnabled(False)
            self.contain_btn.clicked.connect(lambda: self._request_action(ActionType.CONTAIN))

            self.remove_btn = QPushButton("Remove")
            self.remove_btn.setEnabled(False)
            self.remove_btn.setStyleSheet("background-color: #e74c3c; color: white;")
            self.remove_btn.clicked.connect(lambda: self._request_action(ActionType.REMOVE))

            btn_layout.addWidget(self.disable_btn)
            btn_layout.addWidget(self.contain_btn)
            btn_layout.addWidget(self.remove_btn)

            layout.addLayout(btn_layout)

        def show_component(self, component: Component):
            """Display component details."""
            self.current_component = component
            self.title_label.setText(component.display_name)

            class_color = CLASSIFICATION_COLORS.get(component.classification, "#666")
            risk_color = RISK_COLORS.get(component.risk_level, "#666")

            details = f"""
<h3>Component Information</h3>
<table>
<tr><td><b>Name:</b></td><td>{component.name}</td></tr>
<tr><td><b>Display Name:</b></td><td>{component.display_name}</td></tr>
<tr><td><b>Publisher:</b></td><td>{component.publisher or 'Unknown'}</td></tr>
<tr><td><b>Type:</b></td><td>{component.component_type.name}</td></tr>
<tr><td><b>Classification:</b></td><td><span style="color: {class_color}; font-weight: bold;">{component.classification.value}</span></td></tr>
<tr><td><b>Risk Level:</b></td><td><span style="color: {risk_color}; font-weight: bold;">{component.risk_level.name}</span></td></tr>
<tr><td><b>Install Path:</b></td><td>{component.install_path or 'N/A'}</td></tr>
<tr><td><b>ID:</b></td><td>{component.id}</td></tr>
</table>

<h3>Why is this classified as {component.classification.value}?</h3>
<p>{self._get_classification_explanation(component)}</p>
"""
            self.details_text.setHtml(details)

            # Enable/disable buttons based on classification
            is_safe = component.classification in [
                Classification.BLOAT,
                Classification.AGGRESSIVE,
                Classification.OPTIONAL,
            ]
            is_critical = (
                component.classification == Classification.CORE
                or component.risk_level == RiskLevel.CRITICAL
            )

            self.disable_btn.setEnabled(not is_critical)
            self.contain_btn.setEnabled(not is_critical)
            self.remove_btn.setEnabled(is_safe and not is_critical)

        def _get_classification_explanation(self, component: Component) -> str:
            """Get explanation for classification."""
            explanations = {
                Classification.CORE: "This is a core Windows component required for system operation. Modifying it could cause system instability.",
                Classification.ESSENTIAL: "This component provides essential functionality. Consider carefully before disabling.",
                Classification.OPTIONAL: "This is a legitimate but non-essential component. Safe to disable if not needed.",
                Classification.BLOAT: "This component is identified as bloatware - it consumes resources without providing significant value.",
                Classification.AGGRESSIVE: "This component exhibits aggressive behavior such as excessive telemetry, ads, or unwanted background activity.",
                Classification.UNKNOWN: "Not enough information to classify this component. Manual review recommended.",
            }
            return explanations.get(component.classification, "No explanation available.")

        def _request_action(self, action: ActionType):
            """Emit action request for the current component."""
            if self.current_component:
                self.action_requested.emit(self.current_component, action)

    class MainWindow(QMainWindow):
        """Main application window."""

        def __init__(self, cfg: Config):
            super().__init__()
            self.config = cfg
            self.components: list[Component] = []
            self.scan_worker: ScanWorker | None = None
            self.action_worker: ActionWorker | None = None
            self.batch_worker: BatchActionWorker | None = None
            self._planner = ActionPlanner()
            self.setup_ui()
            self.setup_connections()

        def setup_ui(self):
            """Setup the main window UI."""
            self.setWindowTitle("Debloatr - Windows Bloatware Scanner & Debloater")
            self.setMinimumSize(1200, 800)

            # Central widget
            central = QWidget()
            self.setCentralWidget(central)
            layout = QVBoxLayout(central)

            # Create tab widget
            self.tabs = QTabWidget()

            # Dashboard tab
            self.dashboard = DashboardWidget()
            self.tabs.addTab(self.dashboard, "Dashboard")

            # Components tab with splitter
            components_widget = QWidget()
            components_layout = QHBoxLayout(components_widget)

            splitter = QSplitter(Qt.Orientation.Horizontal)

            self.component_tree = ComponentTreeWidget()
            self.component_detail = ComponentDetailWidget()

            splitter.addWidget(self.component_tree)
            splitter.addWidget(self.component_detail)
            splitter.setSizes([700, 300])

            components_layout.addWidget(splitter)
            self.tabs.addTab(components_widget, "Components")

            # Sessions tab
            self.session_history = SessionHistoryWidget(self.config)
            self.tabs.addTab(self.session_history, "Sessions")

            layout.addWidget(self.tabs)

            # Progress bar
            self.progress_bar = QProgressBar()
            self.progress_bar.setVisible(False)
            layout.addWidget(self.progress_bar)

            # Status bar
            self.status_bar = QStatusBar()
            self.setStatusBar(self.status_bar)
            self.status_bar.showMessage("Ready")

            # Toolbar
            self.setup_toolbar()

        def setup_toolbar(self):
            """Setup the toolbar."""
            toolbar = QToolBar("Main Toolbar")
            toolbar.setMovable(False)
            self.addToolBar(toolbar)

            # Scan action
            scan_action = QAction("Scan", self)
            scan_action.setToolTip("Scan system for bloatware")
            scan_action.triggered.connect(self.start_scan)
            toolbar.addAction(scan_action)

            toolbar.addSeparator()

            # Undo action
            undo_action = QAction("Undo Last", self)
            undo_action.setToolTip("Undo the last session")
            undo_action.triggered.connect(self.undo_last_session)
            toolbar.addAction(undo_action)

            # Recovery action
            recovery_action = QAction("Recovery", self)
            recovery_action.setToolTip("Open recovery mode")
            recovery_action.triggered.connect(self.open_recovery)
            toolbar.addAction(recovery_action)

        def setup_connections(self):
            """Setup signal connections."""
            # Dashboard buttons
            self.dashboard.scan_btn.clicked.connect(self.start_scan)
            self.dashboard.safe_debloat_btn.clicked.connect(self.safe_debloat)
            self.dashboard.undo_btn.clicked.connect(self.undo_last_session)

            # Component selection
            self.component_tree.component_selected.connect(self.component_detail.show_component)

            # Action requests from tree context menu and detail panel buttons
            self.component_tree.action_requested.connect(self.execute_action)
            self.component_detail.action_requested.connect(self.execute_action)

        def start_scan(self):
            """Start a system scan."""
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            self.status_bar.showMessage("Scanning...")

            self.scan_worker = ScanWorker(self.config)
            self.scan_worker.progress.connect(self._on_scan_progress)
            self.scan_worker.finished.connect(self._on_scan_finished)
            self.scan_worker.error.connect(self._on_scan_error)
            self.scan_worker.start()

        def _on_scan_progress(self, message: str, percent: int):
            """Handle scan progress update."""
            self.progress_bar.setValue(percent)
            self.status_bar.showMessage(message)

        def _on_scan_finished(self, result):
            """Handle scan completion."""
            self.progress_bar.setVisible(False)
            self.progress_bar.setValue(100)

            self.components = result.components
            self.component_tree.set_components(self.components)
            self.dashboard.update_stats(self.components)

            self.status_bar.showMessage(
                f"Scan complete: {result.total_count} components found in {result.scan_time_ms:.0f}ms"
            )

        def _on_scan_error(self, error: str):
            """Handle scan error."""
            self.progress_bar.setVisible(False)
            self.status_bar.showMessage(f"Scan failed: {error}")
            QMessageBox.critical(self, "Scan Error", f"Failed to scan: {error}")

        def execute_action(self, component: Component, action: ActionType):
            """Execute an action on a component with confirmation."""
            # Check availability via planner
            availability = self._planner.get_available_actions(component)
            if action not in availability.available_actions:
                reason = availability.blocked_actions.get(action, "Unknown reason")
                QMessageBox.warning(
                    self,
                    "Action Blocked",
                    f"Cannot {action.value} '{component.display_name}':\n\n{reason}",
                )
                return

            # Build confirmation message
            warnings = availability.warnings
            warn_text = ""
            if warnings:
                warn_text = "\n\nWarnings:\n" + "\n".join(f"  - {w}" for w in warnings)

            reply = QMessageBox.question(
                self,
                f"Confirm {action.value}",
                f"Are you sure you want to {action.value} "
                f"'{component.display_name}'?{warn_text}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )

            if reply != QMessageBox.StandardButton.Yes:
                return

            # Create plan and execute
            try:
                plan = self._planner.create_action_plan(component, action)
            except ValueError as e:
                QMessageBox.warning(self, "Plan Error", str(e))
                return

            engine = ExecutionEngine(mode=ExecutionMode.INTERACTIVE)
            engine.start_session(f"GUI: {action.value} {component.display_name}")

            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)

            self.action_worker = ActionWorker(engine, plan)
            self.action_worker.progress.connect(self._on_action_progress)
            self.action_worker.finished.connect(
                lambda result: self._on_action_finished(result, engine)
            )
            self.action_worker.error.connect(self._on_action_error)
            self.action_worker.start()

        def _on_action_progress(self, message: str, percent: int):
            """Handle action progress update."""
            self.progress_bar.setValue(percent)
            self.status_bar.showMessage(message)

        def _on_action_finished(self, result: ExecutionResult, engine: ExecutionEngine):
            """Handle action completion."""
            self.progress_bar.setVisible(False)
            engine.end_session()

            if result.success:
                msg = "Action completed successfully."
                if result.requires_reboot:
                    msg += "\n\nA system restart is required for changes to take effect."
                QMessageBox.information(self, "Success", msg)
                self.status_bar.showMessage("Action completed successfully")
            else:
                QMessageBox.warning(
                    self,
                    "Action Failed",
                    f"Action failed: {result.error_message}",
                )
                self.status_bar.showMessage(f"Action failed: {result.error_message}")

            self.session_history.refresh()

        def _on_action_error(self, error: str):
            """Handle action error."""
            self.progress_bar.setVisible(False)
            self.status_bar.showMessage(f"Action error: {error}")
            QMessageBox.critical(self, "Action Error", f"Failed to execute action: {error}")

        def safe_debloat(self):
            """Perform safe debloat on BLOAT and AGGRESSIVE components."""
            bloat = [
                c
                for c in self.components
                if c.classification in [Classification.BLOAT, Classification.AGGRESSIVE]
            ]

            if not bloat:
                QMessageBox.information(self, "Info", "No bloatware components found to disable.")
                return

            reply = QMessageBox.question(
                self,
                "Confirm Safe Debloat",
                f"This will disable {len(bloat)} bloatware components.\n\n"
                f"A System Restore point will be created first.\n\n"
                f"Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )

            if reply != QMessageBox.StandardButton.Yes:
                return

            # Create plans for all bloat components
            plans = []
            for comp in bloat:
                try:
                    plan = self._planner.create_action_plan(comp, ActionType.DISABLE)
                    plans.append(plan)
                except ValueError:
                    pass  # Skip components that can't be disabled

            if not plans:
                QMessageBox.information(
                    self, "Info", "No components are eligible for safe debloat."
                )
                return

            engine = ExecutionEngine(mode=ExecutionMode.BATCH_CONFIRM)
            engine.start_session(f"Safe Debloat: {len(plans)} components")

            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            self.status_bar.showMessage("Performing safe debloat...")

            self.batch_worker = BatchActionWorker(engine, plans)
            self.batch_worker.progress.connect(self._on_action_progress)
            self.batch_worker.finished.connect(
                lambda results: self._on_batch_finished(results, engine)
            )
            self.batch_worker.error.connect(self._on_action_error)
            self.batch_worker.start()

        def _on_batch_finished(self, results: list[ExecutionResult], engine: ExecutionEngine):
            """Handle batch action completion."""
            self.progress_bar.setVisible(False)
            engine.end_session()
            summary = engine.get_session_summary()

            succeeded = summary["successful"]
            failed = summary["failed"]
            total = summary["total_actions"]

            msg = "Safe debloat complete.\n\n"
            msg += f"Successful: {succeeded}/{total}\n"
            if failed:
                msg += f"Failed: {failed}\n"
            if summary.get("requires_reboot"):
                msg += "\nA system restart is required for some changes to take effect."

            if failed:
                QMessageBox.warning(self, "Partial Success", msg)
            else:
                QMessageBox.information(self, "Success", msg)

            self.status_bar.showMessage(f"Safe debloat: {succeeded}/{total} succeeded")
            self.session_history.refresh()

        def undo_last_session(self):
            """Undo the last session."""
            session_manager = create_session_manager(self.config)
            last_session = session_manager.get_last_session()

            if not last_session:
                QMessageBox.information(self, "Info", "No sessions to undo.")
                return

            actions = session_manager.get_rollbackable_actions(last_session.session_id)

            reply = QMessageBox.question(
                self,
                "Confirm Undo",
                f"Undo last session: {last_session.description}\n\n"
                f"This will rollback {len(actions)} actions.\n\n"
                f"Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )

            if reply == QMessageBox.StandardButton.Yes:
                rollback_manager = create_rollback_manager(self.config)
                result = rollback_manager.rollback_session(last_session.session_id)

                if result.success:
                    QMessageBox.information(self, "Success", "Session rolled back successfully.")
                else:
                    QMessageBox.warning(
                        self,
                        "Partial Failure",
                        f"Some actions could not be rolled back.\n"
                        f"Successful: {result.successful_rollbacks}\n"
                        f"Failed: {result.failed_rollbacks}",
                    )

                self.session_history.refresh()

        def open_recovery(self):
            """Open recovery mode dialog."""
            from src.core.recovery import RecoveryMode

            recovery = RecoveryMode(self.config)
            status = recovery.get_status()

            dialog = QDialog(self)
            dialog.setWindowTitle("Recovery Mode")
            dialog.setMinimumSize(500, 400)

            layout = QVBoxLayout(dialog)

            info = QTextEdit()
            info.setReadOnly(True)
            info.setHtml(f"""
<h2>Recovery Status</h2>
<table>
<tr><td><b>Sessions available:</b></td><td>{status.has_sessions}</td></tr>
<tr><td><b>Rollbackable actions:</b></td><td>{status.rollbackable_actions}</td></tr>
<tr><td><b>Debloatr restore points:</b></td><td>{status.debloatr_restore_points}</td></tr>
<tr><td><b>System Restore enabled:</b></td><td>{status.system_restore_enabled}</td></tr>
<tr><td><b>Safe Mode:</b></td><td>{status.is_safe_mode}</td></tr>
</table>

<h3>Recovery Options</h3>
<p>Use the buttons below to recover your system.</p>
""")
            layout.addWidget(info)

            btn_layout = QHBoxLayout()

            rollback_btn = QPushButton("Rollback Last Session")
            rollback_btn.setEnabled(status.rollbackable_actions > 0)
            rollback_btn.clicked.connect(lambda: self._recovery_rollback_last(dialog))

            restore_btn = QPushButton("System Restore")
            restore_btn.clicked.connect(lambda: self._open_system_restore())

            btn_layout.addWidget(rollback_btn)
            btn_layout.addWidget(restore_btn)

            layout.addLayout(btn_layout)

            close_btn = QPushButton("Close")
            close_btn.clicked.connect(dialog.accept)
            layout.addWidget(close_btn)

            dialog.exec()

        def _recovery_rollback_last(self, dialog: QDialog):
            """Rollback last session from recovery dialog."""
            from src.core.recovery import RecoveryMode

            recovery = RecoveryMode(self.config)
            result = recovery.rollback_last_session()

            if result.success:
                QMessageBox.information(dialog, "Success", "Recovery successful!")
            else:
                QMessageBox.warning(dialog, "Failed", f"Recovery failed: {result.error_message}")

            dialog.accept()
            self.session_history.refresh()

        def _open_system_restore(self):
            """Open Windows System Restore."""
            import subprocess

            try:
                subprocess.Popen(["rstrui.exe"])
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not open System Restore: {e}")

    # Create and run the application
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    window = MainWindow(config)
    window.show()

    return app.exec()
