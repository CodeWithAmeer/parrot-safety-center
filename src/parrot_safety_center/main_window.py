from .common import *
from .redaction import *
from .guides import *
from .checks import SystemChecks
from .workers import CheckWorker
from .widgets import *
from .pages import *

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.checks = SystemChecks()
        self.threadpool = QThreadPool.globalInstance()
        self.threadpool.setMaxThreadCount(THREADPOOL_MAX)
        self.current_worker = None
        self.cached_data = {}
        self.nav_buttons = []
        self.setWindowTitle(APP_TITLE)
        self.resize(1366, 820)
        self.setMinimumSize(1080, 680)
        self.selected_role = None
        self.screenshot_safe_mode = True
        self.tray_icon = None
        self.setup_actions()
        self.setup_ui()
        self.apply_style()
        self.setup_tray()
        self.start_refresh()

    def setup_actions(self):
        self.refresh_action = QAction("Refresh", self)
        self.refresh_action.triggered.connect(self.start_refresh)
        self.export_text_action = QAction("Export Redacted Text Report", self)
        self.export_text_action.triggered.connect(lambda: self.export_report("text"))
        self.export_json_action = QAction("Export JSON Report", self)
        self.export_json_action.triggered.connect(lambda: self.export_report("json"))
        self.copy_report_action = QAction("Copy Redacted Report to Clipboard", self)
        self.copy_report_action.triggered.connect(lambda: self.export_report("clipboard"))
        menu = self.menuBar().addMenu("Report")
        self.export_html_action = QAction("Export HTML Report", self)
        self.export_html_action.triggered.connect(lambda: self.export_report("html"))
        self.export_fix_action = QAction("Export Fix Plan", self)
        self.export_fix_action.triggered.connect(lambda: self.export_report("fix_text"))
        menu.addAction(self.export_text_action)
        menu.addAction(self.export_json_action)
        menu.addAction(self.export_html_action)
        menu.addAction(self.export_fix_action)
        menu.addAction(self.copy_report_action)
        help_menu = self.menuBar().addMenu("Help")
        self.about_action = QAction("About Parrot Safety Center", self)
        self.about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(self.about_action)
        self.menuBar().addAction(self.refresh_action)

    def show_about_dialog(self):
        QMessageBox.information(self, f"About {APP_TITLE}", f"{APP_TITLE}\n\nUnofficial project for Parrot OS\nCreated by CodeWithAmeer\nGitHub: https://github.com/CodeWithAmeer\nLicense: Apache-2.0\n\nRead-only local safety dashboard\nNo telemetry\nNo online API calls\nNo system modification\nNo automatic fixes\nBuilt for Parrot OS, also compatible with Debian, Kali, and Ubuntu where possible")

    def setup_ui(self):
        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(258)
        side_layout = QVBoxLayout(sidebar)
        side_layout.setContentsMargins(18, 20, 18, 18)
        side_layout.setSpacing(12)
        brand = QLabel(f"PSC  {APP_TITLE}")
        brand.setObjectName("Brand")
        brand.setWordWrap(True)
        side_layout.addWidget(brand)
        subtitle = QLabel("Local read-only safety dashboard")
        subtitle.setObjectName("SidebarSubtitle")
        subtitle.setWordWrap(True)
        side_layout.addWidget(subtitle)
        self.sidebar_score = QLabel("Safety Score: loading")
        self.sidebar_score.setObjectName("SidebarScore")
        side_layout.addWidget(self.sidebar_score)
        self.safe_mode_badge = QLabel("Screenshot Safe Mode: ON")
        self.safe_mode_badge.setObjectName("SidebarBadge")
        side_layout.addWidget(self.safe_mode_badge)
        self.readonly_badge = QLabel("Read-only: local checks only")
        self.readonly_badge.setObjectName("SidebarBadge")
        side_layout.addWidget(self.readonly_badge)
        self.role_badge = QLabel("Role: Auto-detect")
        self.role_badge.setObjectName("SidebarBadge")
        self.role_badge.setWordWrap(True)
        side_layout.addWidget(self.role_badge)
        self.role_button = QPushButton("Choose Role")
        self.role_button.setObjectName("SmallButton")
        self.role_button.setMinimumHeight(34)
        self.role_button.clicked.connect(self.choose_role_dialog)
        side_layout.addWidget(self.role_button)
        self.safe_mode_checkbox = QCheckBox("Screenshot Safe Mode")
        self.safe_mode_checkbox.setObjectName("SafeModeCheck")
        self.safe_mode_checkbox.setChecked(True)
        self.safe_mode_checkbox.stateChanged.connect(self.toggle_screenshot_safe_mode)
        side_layout.addWidget(self.safe_mode_checkbox)
        safe_note = QLabel("Screenshot Safe Mode hides sensitive system details. Turn it off for full local diagnostics.")
        safe_note.setObjectName("SidebarSubtitle")
        safe_note.setWordWrap(True)
        side_layout.addWidget(safe_note)
        self.nav = QListWidget()
        self.nav.setObjectName("NavList")
        self.nav.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        pages = ["Overview", "Parrot Baseline", "Fix Plan", "Update Guard", "Workspaces", "Security", "Privacy", "Recovery", "Updates", "Profiles", "Tools", "Logs", "Timeline", "Recommendations", "Reports", "About"]
        for page in pages:
            item = QListWidgetItem(page)
            item.setSizeHint(QSize(220, 38))
            self.nav.addItem(item)
        side_layout.addWidget(self.nav, 1)
        self.refresh_button = QPushButton("Refresh Safe Checks")
        self.refresh_button.setObjectName("RefreshButton")
        self.refresh_button.setMinimumHeight(42)
        self.refresh_button.clicked.connect(self.start_refresh)
        side_layout.addWidget(self.refresh_button)
        root.addWidget(sidebar)
        self.stack = QStackedWidget()
        root.addWidget(self.stack, 1)
        self.pages = {
            "Overview": OverviewPage(),
            "Parrot Baseline": ParrotBaselinePage(),
            "Fix Plan": FixPlanPage(),
            "Update Guard": UpdateGuardPage(),
            "Workspaces": WorkspacesPage(),
            "Security": SecurityPage(),
            "Privacy": PrivacyPage(),
            "Recovery": RecoveryPage(),
            "Updates": UpdatesPage(),
            "Profiles": ProfilesPage(),
            "Tools": ToolsPage(),
            "Logs": LogsPage(),
            "Timeline": TimelinePage(),
            "Recommendations": RecommendationsPage(),
            "Reports": ReportsPage(),
            "About": AboutPage()
        }
        for page in pages:
            self.stack.addWidget(self.pages[page])
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(0)
        self.pages["Overview"].export_text_requested.connect(lambda: self.export_report("text"))
        self.pages["Overview"].export_json_requested.connect(lambda: self.export_report("json"))
        self.pages["Overview"].copy_report_requested.connect(lambda: self.export_report("clipboard"))
        self.pages["Updates"].refresh_requested.connect(self.start_refresh)
        self.pages["Privacy"].copy_privacy_requested.connect(self.copy_privacy_report)
        self.pages["Logs"].copy_logs_requested.connect(self.copy_logs)
        self.pages["Logs"].export_logs_requested.connect(self.export_logs)
        self.pages["Reports"].export_text_requested.connect(lambda: self.export_report("text"))
        self.pages["Reports"].export_json_requested.connect(lambda: self.export_report("json"))
        self.pages["Reports"].copy_report_requested.connect(lambda: self.export_report("clipboard"))
        self.pages["Reports"].copy_safe_summary_requested.connect(self.copy_screenshot_safe_summary)
        self.pages["Reports"].export_safe_summary_requested.connect(self.export_screenshot_safe_summary)
        self.pages["Reports"].export_html_requested.connect(lambda: self.export_report("html"))
        self.pages["Reports"].export_baseline_requested.connect(lambda: self.export_report("baseline"))
        self.pages["Reports"].export_fix_plan_requested.connect(lambda: self.export_report("fix_text"))
        self.pages["Reports"].export_workspace_requested.connect(lambda: self.export_report("workspace"))
        self.pages["Reports"].export_update_guard_requested.connect(lambda: self.export_report("update_guard"))
        self.pages["Fix Plan"].copy_full_requested.connect(lambda: self.export_report("fix_clipboard"))
        self.pages["Fix Plan"].export_text_requested.connect(lambda: self.export_report("fix_text"))
        self.pages["Fix Plan"].export_json_requested.connect(lambda: self.export_report("fix_json"))
        self.pages["Fix Plan"].copy_safe_requested.connect(lambda: self.export_report("fix_safe_clipboard"))
        self.setCentralWidget(central)
        self.statusBar().showMessage("Ready")

    def choose_role_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Choose Your Role")
        dialog.resize(560, 260)
        layout = QVBoxLayout(dialog)
        title = QLabel("Choose Your Role")
        title.setObjectName("ProfileTitle")
        layout.addWidget(title)
        note = QLabel("Choose a temporary role to tune recommendations and score weighting. Select Auto-detect to let local read-only checks choose the best match. This selection is not saved to disk.")
        note.setObjectName("CardDetail")
        note.setWordWrap(True)
        layout.addWidget(note)
        combo = QComboBox()
        combo.setObjectName("ComboBox")
        roles = ["Auto-detect"] + list(self.checks.profiles.keys())
        combo.addItems(roles)
        current = self.selected_role or "Auto-detect"
        if current in roles:
            combo.setCurrentIndex(roles.index(current))
        layout.addWidget(combo)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        if dialog.exec() != QDialog.Accepted:
            return
        value = combo.currentText()
        self.selected_role = None if value == "Auto-detect" else value
        self.checks.selected_role = self.selected_role
        if hasattr(self, "role_badge"):
            self.role_badge.setText("Role: " + (self.selected_role or "Auto-detect"))
        if self.cached_data:
            self.start_refresh()

    def setup_tray(self):
        try:
            if not QSystemTrayIcon.isSystemTrayAvailable():
                return
            pixmap = QPixmap(32, 32)
            pixmap.fill(QColor(TEAL))
            painter = QPainter(pixmap)
            painter.setPen(QColor(BG))
            painter.setFont(QFont("Arial", 12, QFont.Bold))
            painter.drawText(pixmap.rect(), Qt.AlignCenter, "PSC")
            painter.end()
            self.tray_icon = QSystemTrayIcon(QIcon(pixmap), self)
            menu = QMenu(self)
            show_action = QAction("Show Parrot Safety Center", self)
            show_action.triggered.connect(self.show_normal_from_tray)
            refresh_action = QAction("Refresh Safe Checks", self)
            refresh_action.triggered.connect(self.start_refresh)
            copy_action = QAction("Copy Safety Summary", self)
            copy_action.triggered.connect(self.copy_screenshot_safe_summary)
            copy_fix_action = QAction("Copy Fix Plan", self)
            copy_fix_action.triggered.connect(lambda: self.export_report("fix_clipboard"))
            copy_safe_action = QAction("Copy Screenshot-Safe Summary", self)
            copy_safe_action.triggered.connect(self.copy_screenshot_safe_summary)
            quit_action = QAction("Quit", self)
            quit_action.triggered.connect(QApplication.quit)
            menu.addAction(show_action)
            menu.addAction(refresh_action)
            menu.addAction(copy_action)
            menu.addAction(copy_fix_action)
            menu.addAction(copy_safe_action)
            menu.addSeparator()
            menu.addAction(quit_action)
            self.tray_icon.setContextMenu(menu)
            self.tray_icon.setToolTip(APP_TITLE + "\nSafety Score: loading\nScreenshot Safe Mode: ON")
            self.tray_icon.show()
        except Exception:
            self.tray_icon = None

    def show_normal_from_tray(self):
        self.show()
        self.raise_()
        self.activateWindow()

    def toggle_screenshot_safe_mode(self, *args):
        self.screenshot_safe_mode = self.safe_mode_checkbox.isChecked()
        self.safe_mode_badge.setText("Screenshot Safe Mode: ON" if self.screenshot_safe_mode else "Screenshot Safe Mode: OFF")
        if self.cached_data:
            self.render_all_pages()

    def display_data(self):
        if not self.cached_data:
            return {}
        data = screenshot_redact_data(self.cached_data) if self.screenshot_safe_mode else redact_data(self.cached_data)
        if isinstance(data, dict):
            data["screenshot_safe_mode"] = "ON" if self.screenshot_safe_mode else "OFF"
        return data

    def render_all_pages(self):
        view = self.display_data()
        score = view.get("scores", {}).get("Safety Score", 0)
        self.sidebar_score.setText(f"Safety Score: {score}/100")
        if hasattr(self, "role_badge"):
            detected = view.get("detected_role", view.get("active_profile", {}).get("name", "Unknown"))
            selected = self.selected_role or "Auto-detect"
            scoring = view.get("scoring_profile", view.get("scores", {}).get("Scoring Profile", detected))
            label = selected if selected != "Auto-detect" else "Auto-detect -> " + str(detected)
            self.role_badge.setText("Role: " + label + " | Score: " + str(scoring))
        if self.tray_icon:
            top_count = len(view.get("top_issues", []))
            detected_role = view.get("detected_role", view.get("active_profile", {}).get("name", "Unknown"))
            scoring_profile = view.get("scoring_profile", view.get("scores", {}).get("Scoring Profile", detected_role))
            self.tray_icon.setToolTip(f"{APP_TITLE}\nSafety Score: {score}/100\nTop issue count: {top_count}\nSelected role: {self.selected_role or 'Auto-detect'}\nDetected role: {detected_role}\nScoring profile: {scoring_profile}\nScreenshot Safe Mode: {'ON' if self.screenshot_safe_mode else 'OFF'}")
        for page in self.pages.values():
            setattr(page, "screenshot_safe_mode", self.screenshot_safe_mode)
            if hasattr(page, "render"):
                page.render(view)

    def screenshot_safe_summary(self):
        report = screenshot_redact_data(self.cached_data or {})
        if not report:
            return "Parrot Safety Center summary unavailable. Run a refresh first."
        scores = report.get("scores", {})
        active = report.get("active_profile", {})
        lines = [
            f"{APP_TITLE} Screenshot-Safe Summary",
            "Created by CodeWithAmeer",
            "GitHub: https://github.com/CodeWithAmeer",
            "Version: " + str(report.get("version", APP_VERSION)),
            "License: Apache-2.0",
            "Created: " + str(report.get("created_at", "Unknown")),
            "Safety Score: " + str(scores.get("Safety Score", "Unknown")),
            "System Health Score: " + str(scores.get("System Health Score", "Unknown")),
            "Security Score: " + str(scores.get("Security Score", "Unknown")),
            "Privacy Score: " + str(scores.get("Privacy Score", "Unknown")),
            "Recovery Score: " + str(scores.get("Recovery Score", "Unknown")),
            "Tools Readiness Score: " + str(scores.get("Tools Readiness Score", "Unknown")),
            "Baseline Compliance Score: " + str(scores.get("Baseline Compliance Score", "Unknown")),
            "Update Guard: " + str(report.get("update_guard", {}).get("risk_level", "Unknown")),
            "Selected role: " + str(report.get("selected_role", "Auto-detect")),
            "Detected role: " + str(report.get("detected_role", active.get("name", "Unknown"))),
            "Scoring profile: " + str(report.get("scoring_profile", report.get("scores", {}).get("Scoring Profile", active.get("name", "Unknown")))),
            "Weights: " + str(report.get("score_weight_summary", report.get("scores", {}).get("Score Weight Summary", "Unknown"))),
            "Readiness: " + str(active.get("readiness", "Unknown")) + "%",
            "Top issues:"
        ]
        for issue in report.get("top_issues", [])[:5]:
            lines.append("- " + str(issue))
        lines.append("Recommended actions:")
        for action in report.get("top_actions", [])[:5]:
            lines.append("- " + str(action))
        lines.append("Read-only local safety dashboard. No telemetry. No online API calls. No system modification.")
        return safe_limit_text(screenshot_redact_text("\n".join(lines)), 50000)

    def copy_screenshot_safe_summary(self):
        QApplication.clipboard().setText(self.screenshot_safe_summary())
        self.statusBar().showMessage("Screenshot-safe summary copied", 5000)

    def export_screenshot_safe_summary(self):
        filename, selected = QFileDialog.getSaveFileName(self, "Export Screenshot-Safe Summary", "parrot-safety-center-screenshot-safe-summary.txt", "Text Files (*.txt)")
        if filename:
            try:
                Path(filename).write_text(safe_limit_text(self.screenshot_safe_summary(), 50000), encoding="utf-8")
                self.statusBar().showMessage("Screenshot-safe summary exported", 5000)
            except Exception as exc:
                QMessageBox.warning(self, "Export failed", screenshot_redact_text(str(exc)))

    def set_loading(self, loading):
        self.refresh_button.setEnabled(not loading)
        self.refresh_action.setEnabled(not loading)
        self.export_text_action.setEnabled(not loading and bool(self.cached_data))
        self.export_json_action.setEnabled(not loading and bool(self.cached_data))
        self.copy_report_action.setEnabled(not loading and bool(self.cached_data))
        for page in self.pages.values():
            page.set_loading(loading)
        if loading:
            self.statusBar().showMessage("Running read-only checks in background...")
        else:
            self.statusBar().showMessage("Read-only checks complete", 5000)

    def start_refresh(self):
        if self.current_worker is not None:
            return
        self.checks.selected_role = self.selected_role
        self.set_loading(True)
        worker = CheckWorker("collect", self.checks.collect_all)
        self.current_worker = worker
        worker.signals.result.connect(self.finish_refresh)
        worker.signals.error.connect(self.refresh_error)
        self.threadpool.start(worker)

    def finish_refresh(self, task_id, data):
        self.current_worker = None
        self.cached_data = redact_data(data)
        self.set_loading(False)
        self.render_all_pages()

    def refresh_error(self, task_id, error):
        self.current_worker = None
        self.set_loading(False)
        QMessageBox.warning(self, "Refresh failed", error or "The checks could not be completed.")

    def prepared_report(self):
        if not self.cached_data:
            return None
        data = redact_data(self.cached_data)
        data["screenshot_safe_mode"] = "ON" if self.screenshot_safe_mode else "OFF"
        if self.screenshot_safe_mode:
            data = screenshot_redact_data(data)
        return limit_data(data, REPORT_FIELD_LIMIT)

    def export_report(self, mode):
        report = self.prepared_report()
        if not report:
            QMessageBox.information(self, "Report unavailable", "Run a refresh before exporting a report.")
            return
        try:
            if mode == "json":
                filename, selected = QFileDialog.getSaveFileName(self, "Export JSON Report", "parrot-safety-center-report.json", "JSON Files (*.json)")
                if filename:
                    Path(filename).write_text(json.dumps(report, indent=2), encoding="utf-8")
                    self.statusBar().showMessage("Redacted JSON report exported", 5000)
            elif mode == "html":
                filename, selected = QFileDialog.getSaveFileName(self, "Export HTML Report", "parrot-safety-center-report.html", "HTML Files (*.html)")
                if filename:
                    Path(filename).write_text(self.checks.format_html_report(report), encoding="utf-8")
                    self.statusBar().showMessage("Self-contained HTML report exported", 5000)
            elif mode == "baseline":
                filename, selected = QFileDialog.getSaveFileName(self, "Export Baseline Report", "parrot-safety-center-baseline.txt", "Text Files (*.txt)")
                if filename:
                    Path(filename).write_text(self.checks.format_baseline_text(report), encoding="utf-8")
                    self.statusBar().showMessage("Baseline report exported", 5000)
            elif mode == "fix_text":
                filename, selected = QFileDialog.getSaveFileName(self, "Export Fix Plan Text", "parrot-safety-center-fix-plan.txt", "Text Files (*.txt)")
                if filename:
                    Path(filename).write_text(self.checks.format_fix_plan_text(report), encoding="utf-8")
                    self.statusBar().showMessage("Fix plan exported", 5000)
            elif mode == "fix_json":
                filename, selected = QFileDialog.getSaveFileName(self, "Export Fix Plan JSON", "parrot-safety-center-fix-plan.json", "JSON Files (*.json)")
                if filename:
                    Path(filename).write_text(json.dumps(report.get("fix_plan", {}), indent=2), encoding="utf-8")
                    self.statusBar().showMessage("Fix plan JSON exported", 5000)
            elif mode == "workspace":
                filename, selected = QFileDialog.getSaveFileName(self, "Export Workspace Readiness Report", "parrot-safety-center-workspaces.txt", "Text Files (*.txt)")
                if filename:
                    Path(filename).write_text(self.checks.format_workspace_text(report), encoding="utf-8")
                    self.statusBar().showMessage("Workspace readiness report exported", 5000)
            elif mode == "update_guard":
                filename, selected = QFileDialog.getSaveFileName(self, "Export Update Guard Report", "parrot-safety-center-update-guard.txt", "Text Files (*.txt)")
                if filename:
                    Path(filename).write_text(self.checks.format_update_guard_text(report), encoding="utf-8")
                    self.statusBar().showMessage("Update Guard report exported", 5000)
            elif mode == "fix_clipboard":
                QApplication.clipboard().setText(self.checks.format_fix_plan_text(report))
                self.statusBar().showMessage("Fix plan copied", 5000)
            elif mode == "fix_safe_clipboard":
                QApplication.clipboard().setText(screenshot_redact_text(self.checks.format_fix_plan_text(report)))
                self.statusBar().showMessage("Screenshot-safe fix plan copied", 5000)
            elif mode == "clipboard":
                QApplication.clipboard().setText(self.checks.format_text_report(report))
                self.statusBar().showMessage("Redacted report copied to clipboard", 5000)
            else:
                filename, selected = QFileDialog.getSaveFileName(self, "Export Redacted Text Report", "parrot-safety-center-report.txt", "Text Files (*.txt)")
                if filename:
                    Path(filename).write_text(self.checks.format_text_report(report), encoding="utf-8")
                    self.statusBar().showMessage("Redacted text report exported", 5000)
        except Exception as exc:
            QMessageBox.warning(self, "Report export failed", redact_text(str(exc)))

    def copy_privacy_report(self):
        if not self.cached_data:
            QMessageBox.information(self, "Privacy report unavailable", "Run a refresh before copying a privacy report.")
            return
        lines = [f"{APP_TITLE} Privacy Report", "Created by CodeWithAmeer", "Version: " + APP_VERSION, ""]
        source = screenshot_redact_data(self.cached_data) if self.screenshot_safe_mode else redact_data(self.cached_data)
        for key, value in source.get("privacy", {}).items():
            if str(key).startswith("_"):
                continue
            if isinstance(value, (list, tuple)) and len(value) >= 2:
                lines.append(f"{key}: {value[0]}")
                lines.append(str(value[1]))
                lines.append("")
        QApplication.clipboard().setText(safe_limit_text("\n".join(lines), 50000))
        self.statusBar().showMessage("Redacted privacy report copied", 5000)

    def copy_logs(self):
        if not self.cached_data:
            QMessageBox.information(self, "Logs unavailable", "Run a refresh before copying logs.")
            return
        source = screenshot_redact_data(self.cached_data) if self.screenshot_safe_mode else redact_data(self.cached_data)
        data = limit_data(source.get("logs", {}), REPORT_FIELD_LIMIT)
        text = json.dumps(data, indent=2)
        QApplication.clipboard().setText(text)
        self.statusBar().showMessage("Redacted logs copied", 5000)

    def export_logs(self):
        if not self.cached_data:
            QMessageBox.information(self, "Logs unavailable", "Run a refresh before exporting logs.")
            return
        filename, selected = QFileDialog.getSaveFileName(self, "Export Redacted Logs", "parrot-safety-center-logs.txt", "Text Files (*.txt)")
        if filename:
            source = screenshot_redact_data(self.cached_data) if self.screenshot_safe_mode else redact_data(self.cached_data)
            logs = source.get("logs", {})
            lines = []
            for key, value in logs.items():
                lines.append(str(key))
                lines.append(str(value))
                lines.append("")
            try:
                Path(filename).write_text(safe_limit_text("\n".join(lines), 50000), encoding="utf-8")
                self.statusBar().showMessage("Redacted logs exported", 5000)
            except Exception as exc:
                QMessageBox.warning(self, "Log export failed", redact_text(str(exc)))

    def apply_style(self):
        self.setStyleSheet(f'''
            QMainWindow {{ background: {BG}; color: {TEXT}; }}
            QWidget {{ color: {TEXT}; font-family: Inter, Segoe UI, Noto Sans, Arial; font-size: 13px; }}
            QMenuBar {{ background: {BG_2}; color: {TEXT}; border-bottom: 1px solid {BORDER}; padding: 4px; }}
            QMenuBar::item:selected {{ background: {PANEL_3}; border-radius: 6px; }}
            QMenu {{ background: {PANEL}; color: {TEXT}; border: 1px solid {BORDER}; }}
            QMenu::item:selected {{ background: {PANEL_3}; }}
            QStatusBar {{ background: {BG_2}; color: {MUTED}; border-top: 1px solid {BORDER}; }}
            QFrame#Sidebar {{ background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 {DARK_BLUE}, stop:1 #061014); border-right: 1px solid {BORDER}; }}
            QLabel#Brand {{ color: {TEAL}; font-size: 20px; font-weight: 800; }}
            QLabel#SidebarSubtitle {{ color: {MUTED}; font-size: 12px; }}
            QLabel#SidebarScore {{ background: rgba(34, 211, 197, 0.10); color: {GREEN}; border: 1px solid rgba(34, 211, 197, 0.35); border-radius: 12px; padding: 12px; font-size: 15px; font-weight: 800; }}
            QLabel#SidebarBadge {{ background: rgba(255,255,255,0.035); color: {MUTED}; border: 1px solid {BORDER}; border-radius: 10px; padding: 8px 10px; font-size: 12px; font-weight: 700; }}
            QCheckBox#SafeModeCheck {{ color: {TEXT}; spacing: 8px; font-weight: 700; }}
            QCheckBox#SafeModeCheck::indicator {{ width: 16px; height: 16px; border: 1px solid {BORDER}; border-radius: 5px; background: {PANEL}; }}
            QCheckBox#SafeModeCheck::indicator:checked {{ background: {TEAL}; border-color: {TEAL}; }}
            QListWidget#NavList {{ background: transparent; border: none; outline: 0; }}
            QListWidget#NavList::item {{ color: {MUTED}; padding: 10px 14px; border-radius: 10px; margin: 2px; }}
            QListWidget#NavList::item:selected {{ color: {TEXT}; background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 rgba(34,211,197,0.24), stop:1 rgba(199,146,234,0.16)); border: 1px solid rgba(34,211,197,0.35); }}
            QListWidget#NavList::item:hover {{ color: {TEXT}; background: rgba(255,255,255,0.045); }}
            QFrame#SidebarReport {{ background: rgba(255,255,255,0.035); border: 1px solid {BORDER}; border-radius: 14px; }}
            QLabel#SidebarPanelTitle {{ color: {TEXT}; font-weight: 800; }}
            QPushButton {{ background: {PANEL_2}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 10px; padding: 9px 12px; font-weight: 700; }}
            QPushButton:hover {{ background: {PANEL_3}; border-color: {TEAL}; }}
            QPushButton:pressed {{ background: #0a3338; }}
            QPushButton:disabled {{ color: #617078; background: #0a1418; border-color: #15272d; }}
            QPushButton#RefreshButton, QPushButton#AccentButton {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #0d5e63, stop:1 #234c84); border: 1px solid rgba(34,211,197,0.55); color: white; }}
            QPushButton#SidebarButton {{ text-align: left; font-size: 12px; padding-left: 10px; }}
            QPushButton#DangerButton {{ background: #2b1f22; border-color: #634048; color: {YELLOW}; }}
            QPushButton#SmallButton {{ background: rgba(255,255,255,0.04); color: {TEXT}; border: 1px solid {BORDER}; border-radius: 9px; padding: 7px 10px; font-size: 12px; font-weight: 800; }}
            QPushButton#SmallButton:hover {{ border-color: {TEAL}; background: rgba(34,211,197,0.08); }}
            QPushButton#DisabledAction {{ background: #121c21; color: #71838b; border-color: #263941; }}
            QLabel#PageTitle {{ font-size: 28px; font-weight: 900; color: {TEXT}; }}
            QLabel#PageSubtitle {{ color: {MUTED}; font-size: 13px; }}
            QScrollArea#PageScroll {{ border: none; background: {BG}; }}
            QScrollArea#PageScroll > QWidget > QWidget {{ background: {BG}; }}
            QFrame#Hero {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #102a34, stop:0.5 #101b35, stop:1 #241b3a); border: 1px solid rgba(34,211,197,0.30); border-radius: 22px; }}
            QLabel#HeroTitle {{ font-size: 32px; font-weight: 900; color: {TEXT}; }}
            QLabel#HeroSubtitle {{ font-size: 15px; color: {MUTED}; }}
            QLabel#HeroMeta {{ font-size: 16px; color: {GREEN}; font-weight: 800; }}
            QFrame#MetricCard, QFrame#ScoreCard, QFrame#SectionPanel, QFrame#ProfileCard, QFrame#RecommendationCard {{ background: rgba(13, 27, 32, 0.96); border: 1px solid {BORDER}; border-radius: 18px; }}
            QFrame#MetricCard:hover, QFrame#ProfileCard:hover, QFrame#RecommendationCard:hover {{ border-color: rgba(34, 211, 197, 0.55); }}
            QLabel#CardIcon, QLabel#PanelIcon {{ color: {TEAL}; font-size: 19px; font-weight: 900; }}
            QLabel#CardTitle {{ color: {MUTED}; font-size: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; }}
            QLabel#MetricValue {{ color: {TEXT}; font-size: 20px; font-weight: 900; }}
            QLabel#ScoreValue {{ font-size: 42px; font-weight: 900; }}
            QLabel#CardDetail {{ color: {MUTED}; line-height: 1.35; }}
            QLabel#PanelTitle {{ color: {TEXT}; font-size: 17px; font-weight: 900; }}
            QLabel#IssueText {{ color: {RED}; background: rgba(255,123,114,0.07); border-radius: 8px; padding: 8px; }}
            QLabel#ActionText {{ color: {GREEN}; background: rgba(126,231,135,0.06); border-radius: 8px; padding: 8px; }}
            QLabel#SmallGood {{ color: {GREEN}; }}
            QLabel#SmallWarn {{ color: {YELLOW}; }}
            QLabel#ProfileTitle {{ color: {TEXT}; font-size: 18px; font-weight: 900; }}
            QProgressBar#ScoreBar {{ background: #0a1418; border: 1px solid #1b333a; border-radius: 7px; height: 10px; }}
            QProgressBar#ScoreBar::chunk {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {TEAL}, stop:1 {PURPLE}); border-radius: 6px; }}
            QProgressBar#LoadingBar {{ background: #0a1418; border: 1px solid #1b333a; border-radius: 4px; height: 6px; }}
            QProgressBar#LoadingBar::chunk {{ background: {TEAL}; border-radius: 4px; }}
            QTextEdit#DetailText {{ background: #081318; border: 1px solid {BORDER}; border-radius: 12px; color: {TEXT}; padding: 10px; font-family: Noto Sans Mono, Consolas, monospace; font-size: 12px; }}
            QTableWidget#ModernTable {{ background: {PANEL}; alternate-background-color: {PANEL_2}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 14px; gridline-color: #19343c; selection-background-color: rgba(34,211,197,0.20); }}
            QHeaderView::section {{ background: #102a32; color: {TEAL}; border: none; border-right: 1px solid {BORDER}; padding: 9px; font-weight: 900; }}
            QLineEdit#SearchBox, QComboBox#ComboBox {{ background: {PANEL}; color: {TEXT}; border: 1px solid {BORDER}; border-radius: 10px; padding: 10px; }}
            QComboBox::drop-down {{ border: none; width: 24px; }}
            QFrame#AboutPanel {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #102a34, stop:0.5 #111d36, stop:1 #26183c); border: 1px solid rgba(34,211,197,0.35); border-radius: 24px; }}
            QLabel#AboutIcon {{ font-size: 70px; }}
            QLabel#AboutTitle {{ font-size: 34px; font-weight: 900; color: {TEXT}; }}
            QLabel#AboutCredit {{ color: {GREEN}; font-size: 18px; font-weight: 800; }}
            QLabel#AboutSafety {{ color: {TEAL}; font-size: 15px; font-weight: 800; }}
        ''')
