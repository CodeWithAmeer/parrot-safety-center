from .common import *
from .redaction import *
from .guides import *
from .widgets import *
from .checks import SystemChecks

class OverviewPage(PageBase):
    export_text_requested = Signal()
    export_json_requested = Signal()
    copy_report_requested = Signal()

    def __init__(self):
        super().__init__("Overview", "A modern local readiness dashboard for Parrot OS safety, privacy, recovery, updates, and tools.")
        self.render_empty()

    def render(self, data):
        self.clear_content()
        scores = data.get("scores", {})
        active = data.get("active_profile", {})
        hero = QFrame()
        hero.setObjectName("Hero")
        h = QHBoxLayout(hero)
        h.setContentsMargins(24, 22, 24, 22)
        h.setSpacing(22)
        left = QVBoxLayout()
        title = QLabel(APP_TITLE)
        title.setObjectName("HeroTitle")
        subtitle = QLabel("Read-only local dashboard for security posture, privacy signals, recovery readiness, updates, logs, and role tools.")
        subtitle.setObjectName("HeroSubtitle")
        subtitle.setWordWrap(True)
        active_label = QLabel(f"Selected role: {data.get('selected_role', 'Auto-detect')}  -  Detected role: {data.get('detected_role', active.get('name', 'Unknown'))}  -  Scoring profile: {data.get('scoring_profile', scores.get('Scoring Profile', active.get('name', 'Unknown')))}  -  Readiness: {active.get('readiness', 0)}%")
        active_label.setObjectName("HeroMeta")
        active_label.setWordWrap(True)
        why = QLabel(redact_text(active.get("why", "Unknown")))
        why.setObjectName("CardDetail")
        why.setWordWrap(True)
        left.addWidget(title)
        left.addWidget(subtitle)
        left.addWidget(active_label)
        left.addWidget(why)
        h.addLayout(left, 2)
        safety_card = ScoreCard("Safety Score", scores.get("Safety Score", 0), "SEC")
        h.addWidget(safety_card, 1)
        self.content_layout.addWidget(hero)
        score_grid = QGridLayout()
        score_grid.setSpacing(14)
        score_items = [("System Health", "System Health Score", "SYS"), ("Security", "Security Score", "SEC"), ("Privacy", "Privacy Score", "PRI"), ("Recovery", "Recovery Score", "REC"), ("Updates", "Updates Score", "UPD"), ("Tools", "Tools Readiness Score", "TOOL"), ("Baseline", "Baseline Compliance Score", "BASE")]
        for idx, (title, key, icon) in enumerate(score_items):
            score_grid.addWidget(ScoreCard(title, scores.get(key, 0), icon), idx // 3, idx % 3)
        for col in range(3):
            score_grid.setColumnStretch(col, 1)
        self.content_layout.addLayout(score_grid)
        why_panel = SectionPanel("Why this score?", "INFO")
        why_text = QLabel(redact_text(scores.get("Score Explanation", "Score weighting is unavailable until checks complete.")))
        why_text.setObjectName("CardDetail")
        why_text.setWordWrap(True)
        why_panel.layout.addWidget(why_text)
        factor_row = QHBoxLayout()
        negatives_panel = SectionPanel("Top negative factors", "WARN")
        for item in scores.get("Top Negative Factors", [])[:5]:
            label = QLabel("- " + redact_text(str(item)))
            label.setObjectName("IssueText")
            label.setWordWrap(True)
            negatives_panel.layout.addWidget(label)
        positives_panel = SectionPanel("Top positive factors", "OK")
        for item in scores.get("Top Positive Factors", [])[:5]:
            label = QLabel("- " + redact_text(str(item)))
            label.setObjectName("ActionText")
            label.setWordWrap(True)
            positives_panel.layout.addWidget(label)
        breakdown_panel = SectionPanel("Score category breakdown", "SYS")
        breakdown = scores.get("Score Breakdown", {})
        if isinstance(breakdown, dict):
            for key, value in breakdown.items():
                label = QLabel(f"{redact_text(str(key))}: {redact_text(str(value))}/100")
                label.setObjectName("CardDetail")
                label.setWordWrap(True)
                breakdown_panel.layout.addWidget(label)
        factor_row.addWidget(negatives_panel, 1)
        factor_row.addWidget(positives_panel, 1)
        factor_row.addWidget(breakdown_panel, 1)
        why_panel.layout.addLayout(factor_row)
        self.content_layout.addWidget(why_panel)
        mid = QHBoxLayout()
        issues = SectionPanel("Top issues to fix", "WARN")
        top_issues = data.get("top_issues", [])[:5]
        if top_issues:
            for idx, issue in enumerate(top_issues, 1):
                label = QLabel(f"{idx}. {redact_text(issue)}")
                label.setObjectName("IssueText")
                label.setWordWrap(True)
                issues.layout.addWidget(label)
        else:
            label = QLabel("No urgent issue was detected by safe local checks.")
            label.setObjectName("CardDetail")
            issues.layout.addWidget(label)
        actions = SectionPanel("Recommended actions", "OK")
        for idx, action in enumerate(data.get("top_actions", [])[:5], 1):
            label = QLabel(f"{idx}. {redact_text(action)}")
            label.setObjectName("ActionText")
            label.setWordWrap(True)
            actions.layout.addWidget(label)
        mid.addWidget(issues, 1)
        mid.addWidget(actions, 1)
        self.content_layout.addLayout(mid)
        overview = data.get("overview", {})
        cards = []
        icons = ["OK", "UPD", "REC", "PRI", "SYS", "TOOL", "INFO", "SYS", "NET", "SYS", "SYS", "SYS"]
        for idx, key in enumerate(["System status", "Update status", "Snapshot status", "Privacy status", "Active profile", "Installed tools count", "Parrot OS version", "Kernel version", "Desktop environment", "CPU", "RAM", "Disk usage", "Uptime"]):
            value = overview.get(key, ("Unknown", "", "info"))
            cards.append({"title": key, "value": value[0], "detail": value[1], "severity": value[2], "icon": icons[idx % len(icons)]})
        panel = SectionPanel("System Info Summary", "SYS")
        grid = QGridLayout()
        grid.setSpacing(14)
        for idx, item in enumerate(cards):
            grid.addWidget(MetricCard(item["title"], item["value"], item["detail"], item["icon"], item["severity"]), idx // 3, idx % 3)
        for col in range(3):
            grid.setColumnStretch(col, 1)
        panel.layout.addLayout(grid)
        self.content_layout.addWidget(panel)
        operations = QHBoxLayout()
        guard_panel = SectionPanel("Update Guard", "UPD")
        guard = data.get("update_guard", {})
        guard_label = QLabel(str(guard.get("risk_level", "Unknown")))
        guard_label.setObjectName("ProfileTitle")
        guard_label.setWordWrap(True)
        guard_panel.layout.addWidget(guard_label)
        for reason in guard.get("why", [])[:3]:
            item = QLabel("- " + redact_text(str(reason)))
            item.setObjectName("CardDetail")
            item.setWordWrap(True)
            guard_panel.layout.addWidget(item)
        base_panel = SectionPanel("Parrot Baseline", "BASE")
        base = data.get("parrot_baseline", {})
        base_panel.layout.addWidget(QLabel("Community recommended baseline, unofficial"))
        base_score = QLabel("Compliance: " + str(base.get("score", scores.get("Baseline Compliance Score", "Unknown"))) + "/100")
        base_score.setObjectName("ProfileTitle")
        base_panel.layout.addWidget(base_score)
        fix_panel = SectionPanel("Top Fix Plan items", "FIX")
        for idx, item in enumerate(data.get("fix_plan", {}).get("items", [])[:5], 1):
            label = QLabel(f"{idx}. [{item.get('priority')}] {redact_text(item.get('problem', 'Unknown'))}")
            label.setObjectName("IssueText")
            label.setWordWrap(True)
            fix_panel.layout.addWidget(label)
        role_panel = SectionPanel("Role workspace", "TOOL")
        role_panel.layout.addWidget(QLabel("Selected role: " + str(data.get("selected_role", "Auto-detect"))))
        role_panel.layout.addWidget(QLabel("Detected role: " + str(data.get("detected_role", active.get("name", "Unknown")))))
        role_panel.layout.addWidget(QLabel("Scoring profile: " + str(data.get("scoring_profile", scores.get("Scoring Profile", active.get("name", "Unknown"))))))
        role_panel.layout.addWidget(QLabel("Screenshot Safe Mode hides sensitive system details. Turn it off for full local diagnostics."))
        operations.addWidget(guard_panel, 1)
        operations.addWidget(base_panel, 1)
        operations.addWidget(fix_panel, 1)
        operations.addWidget(role_panel, 1)
        self.content_layout.addLayout(operations)
        export = SectionPanel("Quick actions for report export", "INFO")
        row = QHBoxLayout()
        text_btn = QPushButton("Export Redacted Text Report")
        json_btn = QPushButton("Export JSON Report")
        copy_btn = QPushButton("Copy Redacted Report to Clipboard")
        text_btn.clicked.connect(self.export_text_requested.emit)
        json_btn.clicked.connect(self.export_json_requested.emit)
        copy_btn.clicked.connect(self.copy_report_requested.emit)
        for btn in [text_btn, json_btn, copy_btn]:
            btn.setObjectName("AccentButton")
            btn.setMinimumHeight(40)
            row.addWidget(btn)
        export.layout.addLayout(row)
        self.content_layout.addWidget(export)
        self.content_layout.addStretch(1)


class ChecksPage(PageBase):
    def render_checks(self, data, section, title_icons=None):
        self.clear_content()
        checks = data.get(section, {})
        icons = title_icons or {}
        grid = QGridLayout()
        grid.setSpacing(14)
        idx = 0
        for key, value in checks.items():
            if str(key).startswith("_"):
                continue
            if isinstance(value, (list, tuple)) and len(value) >= 3:
                card = CheckCard(key, value[0], value[1], value[2], icons.get(key, "INFO"), self)
                grid.addWidget(card, idx // 2, idx % 2)
                idx += 1
        for col in range(2):
            grid.setColumnStretch(col, 1)
        self.content_layout.addLayout(grid)
        self.content_layout.addStretch(1)


class SecurityPage(ChecksPage):
    def __init__(self):
        super().__init__("Security", "Read-only checks for AppArmor, firewall posture, encryption, SSH, network exposure, services, and basic kernel hardening.")
        self.render_empty()

    def render(self, data):
        self.clear_content()
        security = data.get("security", {})
        groups = {
            "Core Protection": ["AppArmor status", "Firewall status", "Disk encryption status", "Secure Boot status"],
            "Network Exposure": ["Open listening ports", "Running network services", "SSH service status", "DNS resolver information"],
            "Hardening": ["Kernel lockdown status", "Sysctl hardening checks", "APT automatic update timer status"],
            "Services": ["USBGuard status", "Fail2ban status", "ClamAV status", "Sudo basic status"],
            "Diagnostics": ["Failed systemd units"]
        }
        for group, keys in groups.items():
            panel = SectionPanel(group, "SEC" if group != "Network Exposure" else "NET")
            grid = QGridLayout(); grid.setSpacing(14); idx = 0
            for key in keys:
                value = security.get(key)
                if isinstance(value, (list, tuple)) and len(value) >= 3:
                    grid.addWidget(CheckCard(key, value[0], value[1], value[2], "SEC" if group != "Network Exposure" else "NET", self), idx // 2, idx % 2); idx += 1
            if idx:
                for col in range(2): grid.setColumnStretch(col, 1)
                panel.layout.addLayout(grid); self.content_layout.addWidget(panel)
        self.content_layout.addStretch(1)


class PrivacyPage(ChecksPage):
    copy_privacy_requested = Signal()

    def __init__(self):
        super().__init__("Privacy", "Local privacy signals for VPN interfaces, Tor, AnonSurf, proxy settings, DNS resolver, Firefox profile hints, and leak-risk notes.")
        self.render_empty()

    def render(self, data):
        self.clear_content()
        checks = data.get("privacy", {})
        hero = SectionPanel("Clipboard-safe privacy report", "PRI")
        row = QHBoxLayout()
        btn = QPushButton("Copy Privacy Report")
        btn.setObjectName("AccentButton")
        btn.clicked.connect(self.copy_privacy_requested.emit)
        row.addWidget(btn)
        row.addStretch(1)
        hero.layout.addLayout(row)
        note = QLabel("The copied privacy report is redacted and includes only local read-only detections.")
        note.setObjectName("CardDetail")
        note.setWordWrap(True)
        hero.layout.addWidget(note)
        self.content_layout.addWidget(hero)
        grid = QGridLayout()
        grid.setSpacing(14)
        idx = 0
        for key, value in checks.items():
            if str(key).startswith("_"):
                continue
            if isinstance(value, (list, tuple)) and len(value) >= 3:
                icon = "PRI" if "Privacy" in key or "VPN" in key else "INFO"
                grid.addWidget(CheckCard(key, value[0], value[1], value[2], icon, self), idx // 2, idx % 2)
                idx += 1
        for col in range(2):
            grid.setColumnStretch(col, 1)
        self.content_layout.addLayout(grid)
        self.content_layout.addStretch(1)


class RecoveryPage(ChecksPage):
    def __init__(self):
        super().__init__("Recovery", "Snapshot and rollback readiness checks. Privileged recovery actions are planned only in this MVP.")
        self.render_empty()

    def planned_warning(self):
        QMessageBox.warning(self, "Recovery action planned", "Privileged recovery actions are not enabled in this MVP. Create, restore, and rollback operations require a future polkit backend. No destructive command was run.")

    def render(self, data):
        self.clear_content()
        actions = SectionPanel("Recovery actions", "REC")
        row = QHBoxLayout()
        for label in ["Create Snapshot: Planned", "Restore Snapshot: Planned", "Rollback System: Planned"]:
            button = QPushButton(label)
            button.setObjectName("DangerButton")
            button.setMinimumHeight(42)
            button.clicked.connect(self.planned_warning)
            row.addWidget(button)
        actions.layout.addLayout(row)
        self.content_layout.addWidget(actions)
        grid = QGridLayout()
        grid.setSpacing(14)
        idx = 0
        for key, value in data.get("recovery", {}).items():
            if str(key).startswith("_"):
                continue
            if isinstance(value, (list, tuple)) and len(value) >= 3:
                grid.addWidget(CheckCard(key, value[0], value[1], value[2], "REC", self), idx // 2, idx % 2)
                idx += 1
        for col in range(2):
            grid.setColumnStretch(col, 1)
        self.content_layout.addLayout(grid)
        self.content_layout.addStretch(1)


class UpdatesPage(ChecksPage):
    refresh_requested = Signal()

    def __init__(self):
        super().__init__("Updates", "Safe APT status checks only. This app does not run apt update, install packages, or modify repositories.")
        self.render_empty()

    def render(self, data):
        self.clear_content()
        panel = SectionPanel("Safe refresh", "UPD")
        row = QHBoxLayout()
        btn = QPushButton("Refresh safe checks only")
        btn.setObjectName("AccentButton")
        btn.clicked.connect(self.refresh_requested.emit)
        row.addWidget(btn)
        row.addStretch(1)
        panel.layout.addLayout(row)
        note = QLabel("Refresh reruns read-only checks such as apt list --upgradable, dpkg --audit, source inspection, and metadata timestamp detection.")
        note.setObjectName("CardDetail")
        note.setWordWrap(True)
        panel.layout.addWidget(note)
        self.content_layout.addWidget(panel)
        grid = QGridLayout()
        grid.setSpacing(14)
        idx = 0
        for key, value in data.get("updates", {}).items():
            if str(key).startswith("_"):
                continue
            if isinstance(value, (list, tuple)) and len(value) >= 3:
                grid.addWidget(CheckCard(key, value[0], value[1], value[2], "UPD", self), idx // 2, idx % 2)
                idx += 1
        for col in range(2):
            grid.setColumnStretch(col, 1)
        self.content_layout.addLayout(grid)
        self.content_layout.addStretch(1)


class ProfilesPage(PageBase):
    def __init__(self):
        super().__init__("Profiles", "Role-based readiness profiles based on tracked tools detected locally.")
        self.render_empty()

    def install_warning(self):
        QMessageBox.information(self, "Package installation disabled", "Package installation is disabled in this MVP. Review missing tools and install only what you need from trusted repositories using your normal package-management workflow.")

    def render(self, data):
        self.clear_content()
        profiles = data.get("profiles", [])
        active = data.get("active_profile", {})
        intro = SectionPanel("Role fit explanation", "TOOL")
        intro.layout.addWidget(QLabel("Selected role: " + str(data.get("selected_role", "Auto-detect"))))
        intro.layout.addWidget(QLabel("Detected role: " + str(data.get("detected_role", active.get("name", "Unknown")))))
        intro.layout.addWidget(QLabel("Scoring profile: " + str(data.get("scoring_profile", data.get("scores", {}).get("Scoring Profile", active.get("name", "Unknown"))))))
        why = QLabel("Why this role was selected: " + redact_text(str(active.get("why", "Unknown"))))
        why.setObjectName("CardDetail"); why.setWordWrap(True); intro.layout.addWidget(why)
        intro.layout.addWidget(QLabel("Privacy readiness is scored separately from general tool readiness."))
        self.content_layout.addWidget(intro)
        grid = QGridLayout()
        grid.setSpacing(14)
        for idx, profile in enumerate(profiles):
            card = QFrame()
            card.setObjectName("ProfileCard")
            layout = QVBoxLayout(card)
            layout.setContentsMargins(18, 16, 18, 16)
            layout.setSpacing(10)
            top = QHBoxLayout()
            title = QLabel(profile.get("name", "Unknown"))
            title.setObjectName("ProfileTitle")
            badge = StatusBadge(f"{profile.get('readiness', 0)}%", "good" if profile.get("readiness", 0) >= 70 else "warn" if profile.get("readiness", 0) >= 35 else "bad")
            top.addWidget(title, 1)
            top.addWidget(badge)
            layout.addLayout(top)
            purpose = QLabel(redact_text(profile.get("purpose", "")))
            purpose.setObjectName("CardDetail")
            purpose.setWordWrap(True)
            layout.addWidget(purpose)
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(profile.get("readiness", 0))
            bar.setTextVisible(False)
            bar.setObjectName("ScoreBar")
            layout.addWidget(bar)
            detected = QLabel("Detected tools: " + (", ".join(profile.get("detected", [])) if profile.get("detected") else "None"))
            detected.setObjectName("SmallGood")
            detected.setWordWrap(True)
            missing = QLabel("Missing tools: " + (", ".join(profile.get("missing", [])) if profile.get("missing") else "None"))
            missing.setObjectName("SmallWarn")
            missing.setWordWrap(True)
            step = QLabel("Recommended next step: " + redact_text(profile.get("next_step", "Review your workflow requirements.")))
            step.setObjectName("CardDetail")
            step.setWordWrap(True)
            layout.addWidget(detected)
            layout.addWidget(missing)
            layout.addWidget(step)
            button = QPushButton("Install tools: Disabled")
            button.setObjectName("DisabledAction")
            button.setEnabled(False)
            button.clicked.connect(self.install_warning)
            layout.addWidget(button)
            grid.addWidget(card, idx // 2, idx % 2)
        for col in range(2):
            grid.setColumnStretch(col, 1)
        self.content_layout.addLayout(grid)
        self.content_layout.addStretch(1)


class ToolsPage(PageBase):
    def __init__(self):
        super().__init__("Tools", "Tracked cybersecurity, development, DFIR, cloud, privacy, reverse engineering, and system utilities.")
        self.screenshot_safe_mode = True
        self.all_tools = []
        top = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search tools")
        self.search.setObjectName("SearchBox")
        self.category = QComboBox()
        self.category.setObjectName("ComboBox")
        self.category.addItems(["All", "Web", "Red Team", "Cloud", "DFIR", "Reverse Engineering", "Developer", "Privacy", "System"])
        self.search.textChanged.connect(self.apply_filter)
        self.category.currentTextChanged.connect(self.apply_filter)
        top.addWidget(self.search, 2)
        top.addWidget(self.category, 1)
        self.content_layout.addLayout(top)
        self.count_label = QLabel("Installed: 0  -  Missing: 0")
        self.count_label.setObjectName("PageSubtitle")
        self.content_layout.addWidget(self.count_label)
        actions = QHBoxLayout()
        self.copy_missing_btn = QPushButton("Copy missing tools list")
        self.export_tools_btn = QPushButton("Export tool readiness")
        self.copy_missing_btn.setObjectName("SmallButton")
        self.export_tools_btn.setObjectName("SmallButton")
        self.copy_missing_btn.clicked.connect(self.copy_missing_tools)
        self.export_tools_btn.clicked.connect(self.export_tool_readiness)
        actions.addWidget(self.copy_missing_btn)
        actions.addWidget(self.export_tools_btn)
        actions.addStretch(1)
        self.content_layout.addLayout(actions)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Tool", "Category", "Status", "Binary", "Path", "Package hint", "Role relevance"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setObjectName("ModernTable")
        self.content_layout.addWidget(self.table)

    def render(self, data):
        self.all_tools = data.get("tools", [])
        self.apply_filter()

    def apply_filter(self):
        query = self.search.text().strip().lower() if hasattr(self, "search") else ""
        category = self.category.currentText() if hasattr(self, "category") else "All"
        rows = []
        for item in self.all_tools:
            if category != "All" and item.get("category") != category:
                continue
            joined = " ".join([str(item.get(k, "")) for k in ["tool", "category", "status", "binary", "path"]]).lower()
            if query and query not in joined:
                continue
            rows.append(item)
        self.table.setRowCount(len(rows))
        for row, item in enumerate(rows):
            package_hint = item.get("tool", "")
            active_role = "selected role" if item.get("status") == "Installed" else "optional"
            values = [item.get("tool", ""), item.get("category", ""), item.get("status", ""), item.get("binary", ""), item.get("path", ""), package_hint, active_role]
            for col, value in enumerate(values):
                cell = QTableWidgetItem(redact_text(value))
                if col == 2:
                    cell.setForeground(QColor(severity_color("good" if value == "Installed" else "warn")))
                self.table.setItem(row, col, cell)
        installed = len([item for item in self.all_tools if item.get("status") == "Installed"])
        missing = len(self.all_tools) - installed
        self.count_label.setText(f"Installed: {installed}  -  Missing: {missing}  -  Showing: {len(rows)}")

    def copy_missing_tools(self):
        missing = [item.get("tool", "") for item in self.all_tools if item.get("status") != "Installed"]
        QApplication.clipboard().setText("\n".join(missing))

    def export_tool_readiness(self):
        filename, selected = QFileDialog.getSaveFileName(self, "Export Tool Readiness", "parrot-safety-center-tools.json", "JSON Files (*.json)")
        if filename:
            data = screenshot_redact_data(self.all_tools) if getattr(self, "screenshot_safe_mode", True) else redact_data(self.all_tools)
            data = limit_data(data, REPORT_FIELD_LIMIT)
            Path(filename).write_text(json.dumps(data, indent=2), encoding="utf-8")


class LogsPage(PageBase):
    copy_logs_requested = Signal()
    export_logs_requested = Signal()

    def __init__(self):
        super().__init__("Logs", "Recent redacted diagnostics from safe local commands. Raw output is hidden behind details dialogs.")
        self.screenshot_safe_mode = True
        self.current_logs = {}
        self.render_empty()

    def show_log_details(self, title, value):
        TextDialog(title, safe_limit_text(str(value), GUI_FIELD_LIMIT), self).exec()

    def copy_screenshot_safe_logs(self):
        data = limit_data(screenshot_redact_data(self.current_logs), REPORT_FIELD_LIMIT)
        QApplication.clipboard().setText(json.dumps(data, indent=2))

    def render(self, data):
        self.clear_content()
        self.current_logs = data.get("logs", {})
        actions = SectionPanel("Logs summary and actions", "LOG")
        summary = QLabel("Diagnostics are redacted, line-limited, and read-only. Permission denied is normal on hardened systems.")
        summary.setObjectName("CardDetail"); summary.setWordWrap(True); actions.layout.addWidget(summary)
        row = QHBoxLayout()
        copy_btn = QPushButton("Copy redacted logs")
        export_btn = QPushButton("Export redacted logs")
        copy_safe_btn = QPushButton("Copy screenshot-safe logs")
        for btn in [copy_btn, export_btn, copy_safe_btn]:
            btn.setObjectName("AccentButton" if btn is not copy_safe_btn else "SmallButton")
            row.addWidget(btn)
        copy_btn.clicked.connect(self.copy_logs_requested.emit)
        export_btn.clicked.connect(self.export_logs_requested.emit)
        copy_safe_btn.clicked.connect(self.copy_screenshot_safe_logs)
        row.addStretch(1); actions.layout.addLayout(row)
        self.content_layout.addWidget(actions)
        for key in ["systemctl failed units", "journalctl priority errors", "dmesg errors", "summary"]:
            value = self.current_logs.get(key, "Unknown")
            card = QFrame(); card.setObjectName("MetricCard")
            layout = QVBoxLayout(card); layout.setContentsMargins(18,16,18,16); layout.setSpacing(9)
            title = QLabel(key); title.setObjectName("ProfileTitle"); title.setWordWrap(True); layout.addWidget(title)
            brief = QLabel(brief_detail(str(value), 320)); brief.setObjectName("CardDetail"); brief.setWordWrap(True); layout.addWidget(brief)
            btn = QPushButton("Details"); btn.setObjectName("SmallButton"); btn.clicked.connect(lambda checked=False, k=key, v=value: self.show_log_details(k, v))
            brow = QHBoxLayout(); brow.addWidget(btn); brow.addStretch(1); layout.addLayout(brow)
            self.content_layout.addWidget(card)
        self.content_layout.addStretch(1)


class RecommendationsPage(PageBase):
    def __init__(self):
        super().__init__("Recommendations", "Ranked safe next steps built from local read-only checks.")
        self.render_empty()

    def copy_recommendation(self, rec):
        text = f"[{rec.get('priority', 'Low')}] {rec.get('category', 'General')}: {rec.get('problem', 'Unknown')}\nWhy it matters: {rec.get('why', '')}\nSafe next step: {rec.get('safe_next_step', '')}"
        text = screenshot_redact_text(text) if getattr(self, "screenshot_safe_mode", True) else redact_text(text)
        QApplication.clipboard().setText(safe_limit_text(text, REPORT_FIELD_LIMIT))

    def show_fix_guide(self, rec):
        key = rec.get("guide_key") or rec.get("problem") or "Recommendation"
        dialog = TextDialog(str(key) + " Fix Guide", fix_guide_content(str(key)), self)
        dialog.exec()

    def render(self, data):
        self.clear_content()
        for rec in data.get("recommendations", []):
            card = QFrame()
            card.setObjectName("RecommendationCard")
            layout = QVBoxLayout(card)
            layout.setContentsMargins(18, 16, 18, 16)
            layout.setSpacing(9)
            top = QHBoxLayout()
            priority = rec.get("priority", "Low")
            sev = "critical" if priority == "Critical" else "bad" if priority == "High" else "warn" if priority == "Medium" else "info"
            badge = StatusBadge(priority, sev)
            title = QLabel(f"{rec.get('category', 'General')} - {redact_text(rec.get('problem', 'Unknown'))}")
            title.setObjectName("ProfileTitle")
            title.setWordWrap(True)
            top.addWidget(title, 1)
            top.addWidget(badge)
            layout.addLayout(top)
            why = QLabel("Why it matters: " + redact_text(rec.get("why", "")))
            why.setObjectName("CardDetail")
            why.setWordWrap(True)
            step = QLabel("Safe next step: " + redact_text(rec.get("safe_next_step", "")))
            step.setObjectName("ActionText")
            step.setWordWrap(True)
            layout.addWidget(why)
            layout.addWidget(step)
            buttons = QHBoxLayout()
            guide_btn = QPushButton("Fix Guide")
            guide_btn.setObjectName("SmallButton")
            guide_btn.clicked.connect(lambda checked=False, r=rec: self.show_fix_guide(r))
            copy_btn = QPushButton("Copy recommendation")
            copy_btn.setObjectName("SmallButton")
            copy_btn.clicked.connect(lambda checked=False, r=rec: self.copy_recommendation(r))
            buttons.addWidget(guide_btn)
            buttons.addWidget(copy_btn)
            buttons.addStretch(1)
            layout.addLayout(buttons)
            self.content_layout.addWidget(card)
        self.content_layout.addStretch(1)


class ReportsPage(PageBase):
    export_text_requested = Signal()
    export_json_requested = Signal()
    copy_report_requested = Signal()
    copy_safe_summary_requested = Signal()
    export_safe_summary_requested = Signal()
    export_html_requested = Signal()
    export_baseline_requested = Signal()
    export_fix_plan_requested = Signal()
    export_workspace_requested = Signal()
    export_update_guard_requested = Signal()

    def __init__(self):
        super().__init__("Reports", "Export and copy redacted reports. Screenshot Safe Mode redaction is applied when enabled.")
        self.render_empty()

    def render(self, data):
        self.clear_content()
        panel = SectionPanel("Report actions", "INFO")
        grid = QGridLayout()
        grid.setSpacing(12)
        actions = [
            ("Export Redacted Text Report", self.export_text_requested.emit),
            ("Export JSON Report", self.export_json_requested.emit),
            ("Copy Redacted Report to Clipboard", self.copy_report_requested.emit),
            ("Copy Screenshot-Safe Summary", self.copy_safe_summary_requested.emit),
            ("Export Screenshot-Safe Summary", self.export_safe_summary_requested.emit),
            ("Export HTML Report", self.export_html_requested.emit),
            ("Export Baseline Report", self.export_baseline_requested.emit),
            ("Export Fix Plan", self.export_fix_plan_requested.emit),
            ("Export Workspace Readiness Report", self.export_workspace_requested.emit),
            ("Export Update Guard Report", self.export_update_guard_requested.emit)
        ]
        for idx, (label, slot) in enumerate(actions):
            btn = QPushButton(label)
            btn.setObjectName("AccentButton" if idx < 3 else "SmallButton")
            btn.setMinimumHeight(42)
            btn.clicked.connect(slot)
            grid.addWidget(btn, idx // 2, idx % 2)
        for col in range(2):
            grid.setColumnStretch(col, 1)
        panel.layout.addLayout(grid)
        note = QLabel("Reports include scores, top issues, recommendations, overview, security, privacy, recovery, updates, profiles, tools, and logs summary. All exports are redacted before leaving the app.")
        note.setObjectName("CardDetail")
        note.setWordWrap(True)
        panel.layout.addWidget(note)
        self.content_layout.addWidget(panel)
        scores = data.get("scores", {}) if isinstance(data, dict) else {}
        summary = SectionPanel("Current report summary", "INFO")
        summary.layout.addWidget(QLabel("Safety Score: " + str(scores.get("Safety Score", "Unknown"))))
        summary.layout.addWidget(QLabel("Selected role: " + str(data.get("selected_role", "Auto-detect"))))
        summary.layout.addWidget(QLabel("Detected role: " + str(data.get("detected_role", data.get("active_profile", {}).get("name", "Unknown")))))
        summary.layout.addWidget(QLabel("Scoring profile: " + str(data.get("scoring_profile", data.get("scores", {}).get("Scoring Profile", "Unknown")))))
        summary.layout.addWidget(QLabel("Created: " + str(data.get("created_at", "Refresh not completed"))))
        self.content_layout.addWidget(summary)
        self.content_layout.addStretch(1)



class ParrotBaselinePage(PageBase):
    def __init__(self):
        super().__init__("Parrot Baseline", "Community recommended baseline, unofficial. Role-aware read-only safety comparison for Parrot OS workflows.")
        self.render_empty()

    def show_details(self, item):
        TextDialog(str(item.get("title", "Baseline item")) + " details", json.dumps(item, indent=2), self).exec()

    def show_fix_guide(self, item):
        TextDialog(str(item.get("title", "Baseline item")) + " Fix Guide", fix_guide_content(str(item.get("fix_guide_key", item.get("title", "Recommendation")))), self).exec()

    def render(self, data):
        self.clear_content()
        baseline = data.get("parrot_baseline", {})
        hero = SectionPanel("Community recommended baseline, unofficial", "BASE")
        hero.layout.addWidget(QLabel("Baseline compliance score: " + str(baseline.get("score", "Unknown")) + "/100"))
        hero.layout.addWidget(QLabel("Checks are local, read-only, role-aware, and not an official Parrot OS policy."))
        self.content_layout.addWidget(hero)
        for item in baseline.get("items", []):
            card = QFrame(); card.setObjectName("RecommendationCard")
            layout = QVBoxLayout(card); layout.setContentsMargins(18,16,18,16); layout.setSpacing(9)
            top = QHBoxLayout()
            title = QLabel(f"{item.get('category', 'General')} - {item.get('title', 'Check')}"); title.setObjectName("ProfileTitle"); title.setWordWrap(True)
            top.addWidget(title, 1); top.addWidget(StatusBadge(str(item.get("status", "Unknown")), item.get("severity", "info")))
            layout.addLayout(top)
            for label, key in [("Why it matters", "why_it_matters"), ("Detected state", "detected_state"), ("Recommended state", "recommended_state"), ("Safe next step", "next_step")]:
                t = QLabel(label + ": " + redact_text(str(item.get(key, "")))); t.setObjectName("CardDetail"); t.setWordWrap(True); layout.addWidget(t)
            impact = QLabel("Score impact: " + str(item.get("score_impact", 0))); impact.setObjectName("CardDetail"); layout.addWidget(impact)
            buttons = QHBoxLayout()
            details = QPushButton("Details"); details.setObjectName("SmallButton"); details.clicked.connect(lambda checked=False, i=item: self.show_details(i))
            guide = QPushButton("Fix Guide"); guide.setObjectName("SmallButton"); guide.clicked.connect(lambda checked=False, i=item: self.show_fix_guide(i))
            buttons.addWidget(guide); buttons.addWidget(details); buttons.addStretch(1); layout.addLayout(buttons)
            self.content_layout.addWidget(card)
        self.content_layout.addStretch(1)


class FixPlanPage(PageBase):
    copy_full_requested = Signal()
    export_text_requested = Signal()
    export_json_requested = Signal()
    copy_safe_requested = Signal()

    def __init__(self):
        super().__init__("Fix Plan", "Ranked manual fix plan. Commands are shown as text only and are never executed by the app.")
        self.render_empty()

    def copy_item(self, item):
        data = screenshot_redact_data(item) if getattr(self, "screenshot_safe_mode", True) else redact_data(item)
        data = limit_data(data, REPORT_FIELD_LIMIT)
        QApplication.clipboard().setText(json.dumps(data, indent=2))

    def copy_command(self, item):
        text = str(item.get("manual_verification_command", ""))
        text = screenshot_redact_text(text) if getattr(self, "screenshot_safe_mode", True) else redact_text(text)
        QApplication.clipboard().setText(text)

    def show_details(self, item):
        data = screenshot_redact_data(item) if getattr(self, "screenshot_safe_mode", True) else redact_data(item)
        data = limit_data(data, GUI_FIELD_LIMIT)
        TextDialog(str(item.get("problem", "Fix item")) + " details", json.dumps(data, indent=2), self).exec()

    def show_fix_guide(self, item):
        TextDialog(str(item.get("problem", "Fix item")) + " Fix Guide", fix_guide_content(str(item.get("fix_guide_key", item.get("problem", "Recommendation")))), self).exec()

    def render(self, data):
        self.clear_content()
        actions = SectionPanel("Fix plan actions", "FIX")
        row = QHBoxLayout()
        for label, signal in [("Copy Full Fix Plan", self.copy_full_requested), ("Export Fix Plan Text", self.export_text_requested), ("Export Fix Plan JSON", self.export_json_requested), ("Copy Screenshot-Safe Fix Plan", self.copy_safe_requested)]:
            b = QPushButton(label); b.setObjectName("AccentButton" if "Export" in label or "Copy Full" in label else "SmallButton"); b.clicked.connect(signal.emit); row.addWidget(b)
        row.addStretch(1); actions.layout.addLayout(row); self.content_layout.addWidget(actions)
        for item in data.get("fix_plan", {}).get("items", []):
            card = QFrame(); card.setObjectName("RecommendationCard")
            layout = QVBoxLayout(card); layout.setContentsMargins(18,16,18,16); layout.setSpacing(9)
            top = QHBoxLayout(); title = QLabel(f"{item.get('category')}: {item.get('problem')}"); title.setObjectName("ProfileTitle"); title.setWordWrap(True)
            sev = "critical" if item.get("priority") == "Critical" else "bad" if item.get("priority") == "High" else "warn" if item.get("priority") == "Medium" else "info"
            top.addWidget(title, 1); top.addWidget(StatusBadge(item.get("priority", "Low"), sev)); layout.addLayout(top)
            for label, key in [("Risk", "risk"), ("Why it matters", "why_it_matters"), ("Manual verification command", "manual_verification_command"), ("Safe manual fix suggestion", "safe_manual_fix_suggestion"), ("Expected improvement", "expected_improvement")]:
                t = QLabel(label + ": " + redact_text(str(item.get(key, "")))); t.setObjectName("CardDetail" if key != "safe_manual_fix_suggestion" else "ActionText"); t.setWordWrap(True); layout.addWidget(t)
            buttons = QHBoxLayout()
            for label, fn in [("Copy command", self.copy_command), ("Copy item", self.copy_item), ("Fix Guide", self.show_fix_guide), ("Details", self.show_details)]:
                b = QPushButton(label); b.setObjectName("SmallButton"); b.clicked.connect(lambda checked=False, i=item, f=fn: f(i)); buttons.addWidget(b)
            buttons.addStretch(1); layout.addLayout(buttons); self.content_layout.addWidget(card)
        self.content_layout.addStretch(1)


class UpdateGuardPage(PageBase):
    def __init__(self):
        super().__init__("Update Guard", "Read-only update risk guidance. The app never runs apt update, apt upgrade, or package modifications.")
        self.render_empty()

    def render(self, data):
        self.clear_content()
        guard = data.get("update_guard", {})
        hero = SectionPanel("Current update risk", "UPD")
        risk = QLabel(str(guard.get("risk_level", "Unknown"))); risk.setObjectName("HeroTitle"); risk.setWordWrap(True); hero.layout.addWidget(risk)
        for reason in guard.get("why", []):
            t = QLabel("- " + redact_text(str(reason))); t.setObjectName("IssueText" if guard.get("severity") in ["bad", "critical"] else "CardDetail"); t.setWordWrap(True); hero.layout.addWidget(t)
        self.content_layout.addWidget(hero)
        row = QHBoxLayout()
        for title, key in [("Pre-update safety checklist", "pre_update_safety_checklist"), ("Rollback readiness checklist", "rollback_readiness_checklist"), ("Safe manual next steps", "safe_manual_next_steps")]:
            panel = SectionPanel(title, "OK")
            for value in guard.get(key, []):
                lbl = QLabel("- " + redact_text(str(value))); lbl.setWordWrap(True); lbl.setObjectName("CardDetail"); panel.layout.addWidget(lbl)
            row.addWidget(panel, 1)
        self.content_layout.addLayout(row)
        details = QPushButton("Details"); details.setObjectName("SmallButton"); details.clicked.connect(lambda: TextDialog("Update Guard details", json.dumps(redact_data(guard), indent=2), self).exec())
        guide = QPushButton("Fix Guide"); guide.setObjectName("SmallButton"); guide.clicked.connect(lambda: TextDialog("Update Guard Fix Guide", "Review package state, backups, and failed units manually before updating. This app never modifies packages.", self).exec())
        button_row = QHBoxLayout(); button_row.addWidget(guide); button_row.addWidget(details); button_row.addStretch(1); self.content_layout.addLayout(button_row)
        self.content_layout.addStretch(1)


class WorkspacesPage(PageBase):
    def __init__(self):
        super().__init__("Workspaces", "Role workspace readiness. Launchers are planned only and no tools are executed.")
        self.screenshot_safe_mode = True
        self.render_empty()

    def launch_planned(self):
        QMessageBox.information(self, "Workspace launch planned", "Workspace launchers are planned for a future version. No tools were executed.")

    def copy_checklist(self, row):
        text = f"{row.get('role')} checklist\n" + "\n".join("- " + str(x) for x in row.get("safe_workflow_checklist", []))
        text = screenshot_redact_text(text) if getattr(self, "screenshot_safe_mode", True) else redact_text(text)
        QApplication.clipboard().setText(safe_limit_text(text, REPORT_FIELD_LIMIT))

    def export_workspace(self, row):
        filename, selected = QFileDialog.getSaveFileName(self, "Export Workspace Readiness", "parrot-safety-center-workspace.json", "JSON Files (*.json)")
        if filename:
            data = screenshot_redact_data(row) if getattr(self, "screenshot_safe_mode", True) else redact_data(row)
            data = limit_data(data, REPORT_FIELD_LIMIT)
            Path(filename).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def render_template(self, row):
        data = screenshot_redact_data(row) if getattr(self, "screenshot_safe_mode", True) else redact_data(row)
        data = limit_data(data, GUI_FIELD_LIMIT)
        TextDialog(row.get("role", "Workspace") + " report template", json.dumps(data, indent=2), self).exec()

    def render(self, data):
        self.clear_content()
        grid = QGridLayout(); grid.setSpacing(14)
        for idx, row in enumerate(data.get("workspaces", [])):
            card = QFrame(); card.setObjectName("ProfileCard")
            layout = QVBoxLayout(card); layout.setContentsMargins(18,16,18,16); layout.setSpacing(9)
            top = QHBoxLayout(); title = QLabel(row.get("role", "Workspace")); title.setObjectName("ProfileTitle"); top.addWidget(title,1); top.addWidget(StatusBadge(str(row.get("role_score",0))+"%", "good" if row.get("role_score",0)>=70 else "warn" if row.get("role_score",0)>=40 else "bad")); layout.addLayout(top)
            for label, key in [("Purpose", "purpose"), ("Installed tools", "installed_tools"), ("Missing tools", "missing_tools"), ("Security risks", "security_risks"), ("Privacy risks", "privacy_risks"), ("Recovery readiness", "recovery_readiness"), ("Recommended setup", "recommended_setup")]:
                val = row.get(key, "")
                if isinstance(val, list): val = ", ".join(val) if val else "None"
                t = QLabel(label + ": " + redact_text(str(val))); t.setObjectName("CardDetail"); t.setWordWrap(True); layout.addWidget(t)
            buttons = QHBoxLayout()
            for label, fn in [("Copy role checklist", self.copy_checklist), ("Export workspace readiness", self.export_workspace), ("Report template", self.render_template)]:
                b=QPushButton(label); b.setObjectName("SmallButton"); b.clicked.connect(lambda checked=False, r=row, f=fn: f(r)); buttons.addWidget(b)
            launch=QPushButton("Launch workspace: Planned"); launch.setObjectName("DangerButton"); launch.clicked.connect(self.launch_planned); buttons.addWidget(launch); buttons.addStretch(1); layout.addLayout(buttons)
            grid.addWidget(card, idx//2, idx%2)
        for col in range(2): grid.setColumnStretch(col,1)
        self.content_layout.addLayout(grid); self.content_layout.addStretch(1)


class TimelinePage(PageBase):
    def __init__(self):
        super().__init__("Timeline", "Refresh-based local timeline of recent safety signals. No daemon and no continuous monitoring.")
        self.render_empty()

    def render(self, data):
        self.clear_content()
        for item in data.get("timeline", []):
            card = QFrame(); card.setObjectName("RecommendationCard")
            layout = QVBoxLayout(card); layout.setContentsMargins(18,16,18,16); layout.setSpacing(8)
            top = QHBoxLayout(); title=QLabel(f"{item.get('time')} - {item.get('category')}"); title.setObjectName("ProfileTitle"); title.setWordWrap(True)
            top.addWidget(title,1); top.addWidget(StatusBadge(item.get("severity","info"), item.get("severity","info"))); layout.addLayout(top)
            summary=QLabel(redact_text(str(item.get("event_summary","")))); summary.setObjectName("CardDetail"); summary.setWordWrap(True); layout.addWidget(summary)
            b=QPushButton("Details"); b.setObjectName("SmallButton"); b.clicked.connect(lambda checked=False, i=item: TextDialog("Timeline details", json.dumps(redact_data(i), indent=2), self).exec())
            row=QHBoxLayout(); row.addWidget(b); row.addStretch(1); layout.addLayout(row)
            self.content_layout.addWidget(card)
        self.content_layout.addStretch(1)


class AboutPage(PageBase):
    def __init__(self):
        super().__init__("About", "Project identity, license, and safety statement.")
        self.render({})

    def render(self, data):
        self.clear_content()
        panel = QFrame()
        panel.setObjectName("AboutPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(34, 32, 34, 32)
        layout.setSpacing(16)
        icon = QLabel("INFO")
        icon.setObjectName("AboutIcon")
        icon.setAlignment(Qt.AlignCenter)
        title = QLabel(APP_TITLE)
        title.setObjectName("AboutTitle")
        title.setAlignment(Qt.AlignCenter)
        subtitle = QLabel("Unofficial project for Parrot OS")
        subtitle.setObjectName("HeroSubtitle")
        subtitle.setAlignment(Qt.AlignCenter)
        credit = QLabel("Created by CodeWithAmeer\nGitHub: https://github.com/CodeWithAmeer\nLicense: Apache-2.0")
        credit.setObjectName("AboutCredit")
        credit.setAlignment(Qt.AlignCenter)
        safety = QLabel("Read-only local safety dashboard\nNo telemetry\nNo online API calls\nNo system modification\nNo automatic fixes\nBuilt for Parrot OS, also compatible with Debian, Kali, and Ubuntu where possible")
        safety.setObjectName("AboutSafety")
        safety.setAlignment(Qt.AlignCenter)
        layout.addWidget(icon)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(credit)
        layout.addWidget(safety)
        self.content_layout.addWidget(panel)
        self.content_layout.addStretch(1)
