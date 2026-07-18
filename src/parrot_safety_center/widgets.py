from .common import *
from .redaction import *
from .guides import *

class StatusBadge(QLabel):
    def __init__(self, text="Info", severity="info"):
        super().__init__(text)
        self.setObjectName("StatusBadge")
        self.setAlignment(Qt.AlignCenter)
        self.setMinimumHeight(26)
        self.setFont(QFont("Inter", 9, QFont.Bold))
        self.set_severity(severity, text)

    def set_severity(self, severity, text=None):
        bg = {"good": "#123726", "warn": "#332b12", "bad": "#3a1719", "critical": "#3a1719", "info": "#102842", "unknown": "#202a30"}.get(severity, "#102842")
        fg = severity_color(severity)
        border = {"good": "#2d6646", "warn": "#6b5724", "bad": "#7a3037", "critical": "#7a3037", "info": "#285d85", "unknown": "#3a4850"}.get(severity, "#285d85")
        self.setText(text or severity_label(severity))
        self.setStyleSheet(f"QLabel#StatusBadge {{ background: {bg}; color: {fg}; border: 1px solid {border}; border-radius: 13px; padding: 4px 10px; }}")


class MetricCard(QFrame):
    def __init__(self, title, value, detail="", icon="INFO", severity="info"):
        super().__init__()
        self.setObjectName("MetricCard")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)
        top = QHBoxLayout()
        icon_label = QLabel(icon)
        icon_label.setObjectName("CardIcon")
        title_label = QLabel(redact_text(title))
        title_label.setObjectName("CardTitle")
        title_label.setWordWrap(True)
        top.addWidget(icon_label, 0, Qt.AlignTop)
        top.addWidget(title_label, 1)
        self.badge = StatusBadge(severity_label(severity), severity)
        top.addWidget(self.badge, 0, Qt.AlignTop)
        layout.addLayout(top)
        self.value = QLabel(redact_text(str(value)))
        self.value.setObjectName("MetricValue")
        self.value.setWordWrap(True)
        self.value.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.value)
        self.detail = QLabel(redact_text(detail or "No additional details"))
        self.detail.setObjectName("CardDetail")
        self.detail.setWordWrap(True)
        self.detail.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.detail)


class ScoreCard(QFrame):
    def __init__(self, title, score, icon="SYS"):
        super().__init__()
        self.setObjectName("ScoreCard")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        score = clamp_score(score)
        severity = "good" if score >= 75 else "warn" if score >= 50 else "bad"
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(8)
        row = QHBoxLayout()
        icon_label = QLabel(icon)
        icon_label.setObjectName("CardIcon")
        title_label = QLabel(title)
        title_label.setObjectName("CardTitle")
        row.addWidget(icon_label)
        row.addWidget(title_label, 1)
        layout.addLayout(row)
        value = QLabel(f"{score}")
        value.setObjectName("ScoreValue")
        value.setStyleSheet(f"color: {severity_color(severity)};")
        layout.addWidget(value)
        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(score)
        bar.setTextVisible(False)
        bar.setObjectName("ScoreBar")
        layout.addWidget(bar)
        label = QLabel("/ 100")
        label.setObjectName("CardDetail")
        layout.addWidget(label)


class SectionPanel(QFrame):
    def __init__(self, title, icon="SYS"):
        super().__init__()
        self.setObjectName("SectionPanel")
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(18, 18, 18, 18)
        self.layout.setSpacing(12)
        header = QHBoxLayout()
        icon_label = QLabel(icon)
        icon_label.setObjectName("PanelIcon")
        title_label = QLabel(title)
        title_label.setObjectName("PanelTitle")
        header.addWidget(icon_label)
        header.addWidget(title_label, 1)
        self.layout.addLayout(header)


class DetailText(QTextEdit):
    def __init__(self, text=""):
        super().__init__()
        self.setObjectName("DetailText")
        self.setReadOnly(True)
        self.setPlainText(safe_limit_text(text, GUI_FIELD_LIMIT))
        self.setMinimumHeight(140)




class TextDialog(QDialog):
    def __init__(self, title, text, parent=None):
        super().__init__(parent)
        self.setWindowTitle(redact_text(title))
        self.resize(780, 520)
        layout = QVBoxLayout(self)
        header = QLabel(redact_text(title))
        header.setObjectName("ProfileTitle")
        header.setWordWrap(True)
        layout.addWidget(header)
        box = DetailText(text)
        layout.addWidget(box, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class CheckCard(QFrame):
    def __init__(self, title, value, detail, severity="info", icon="INFO", parent=None):
        super().__init__(parent)
        self.setObjectName("MetricCard")
        self.title_text = redact_text(title)
        self.detail_text = safe_limit_text(detail or "No output", 20000)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)
        top = QHBoxLayout()
        icon_label = QLabel(icon)
        icon_label.setObjectName("CardIcon")
        title_label = QLabel(self.title_text)
        title_label.setObjectName("CardTitle")
        title_label.setWordWrap(True)
        badge = StatusBadge(severity_label(severity), severity)
        top.addWidget(icon_label, 0, Qt.AlignTop)
        top.addWidget(title_label, 1)
        top.addWidget(badge, 0, Qt.AlignTop)
        layout.addLayout(top)
        value_label = QLabel(redact_text(str(value)))
        value_label.setObjectName("MetricValue")
        value_label.setWordWrap(True)
        value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(value_label)
        summary = QLabel(brief_detail(self.detail_text))
        summary.setObjectName("CardDetail")
        summary.setWordWrap(True)
        summary.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(summary)
        buttons = QHBoxLayout()
        details_btn = QPushButton("Show details")
        details_btn.setObjectName("SmallButton")
        details_btn.clicked.connect(self.show_details)
        buttons.addWidget(details_btn)
        if severity in ["warn", "bad", "critical", "unknown"]:
            guide_btn = QPushButton("Fix Guide")
            guide_btn.setObjectName("SmallButton")
            guide_btn.clicked.connect(self.show_guide)
            buttons.addWidget(guide_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

    def show_details(self):
        dialog = TextDialog(self.title_text + " details", self.detail_text, self)
        dialog.exec()

    def show_guide(self):
        dialog = TextDialog(self.title_text + " Fix Guide", fix_guide_content(self.title_text), self)
        dialog.exec()


class PageBase(QWidget):
    def __init__(self, title, subtitle=""):
        super().__init__()
        self.title = title
        self.outer = QVBoxLayout(self)
        self.outer.setContentsMargins(24, 22, 24, 22)
        self.outer.setSpacing(18)
        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title_label = QLabel(title)
        title_label.setObjectName("PageTitle")
        title_box.addWidget(title_label)
        if subtitle:
            subtitle_label = QLabel(subtitle)
            subtitle_label.setObjectName("PageSubtitle")
            subtitle_label.setWordWrap(True)
            title_box.addWidget(subtitle_label)
        header.addLayout(title_box, 1)
        self.loading_badge = StatusBadge("Idle", "info")
        header.addWidget(self.loading_badge, 0, Qt.AlignTop)
        self.outer.addLayout(header)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.setVisible(False)
        self.progress.setObjectName("LoadingBar")
        self.outer.addWidget(self.progress)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setObjectName("PageScroll")
        self.content = QWidget()
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(16)
        self.scroll.setWidget(self.content)
        self.outer.addWidget(self.scroll, 1)


    def set_loading(self, loading):
        self.progress.setVisible(loading)
        self.loading_badge.set_severity("info" if loading else "good", "Loading" if loading else "Ready")

    @classmethod
    def _clear_layout(cls, layout):
        """Remove every widget, nested layout, and spacer from a layout."""
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            child_layout = item.layout()
            if widget is not None:
                # Reparenting hides the old widget immediately.  deleteLater()
                # alone is not enough here because widgets stored in nested
                # layouts otherwise remain children of the scroll-area content
                # widget and keep painting underneath the next refresh.
                widget.hide()
                widget.setParent(None)
                widget.deleteLater()
            elif child_layout is not None:
                cls._clear_layout(child_layout)
                child_layout.deleteLater()

    def clear_content(self):
        self.content.setUpdatesEnabled(False)
        try:
            self._clear_layout(self.content_layout)
            self.content_layout.invalidate()
        finally:
            self.content.setUpdatesEnabled(True)
            self.content.updateGeometry()
            self.content.update()

    def render_empty(self, message="Run a refresh to load local read-only checks."):
        self.clear_content()
        panel = SectionPanel("Waiting for data", "INFO")
        label = QLabel(message)
        label.setObjectName("CardDetail")
        label.setWordWrap(True)
        panel.layout.addWidget(label)
        self.content_layout.addWidget(panel)
        self.content_layout.addStretch(1)

    def add_grid_cards(self, items, columns=3):
        grid = QGridLayout()
        grid.setSpacing(14)
        for idx, item in enumerate(items):
            card = MetricCard(item.get("title", "Unknown"), item.get("value", "Unknown"), item.get("detail", ""), item.get("icon", "INFO"), item.get("severity", "info"))
            row = idx // columns
            col = idx % columns
            grid.addWidget(card, row, col)
        for col in range(columns):
            grid.setColumnStretch(col, 1)
        self.content_layout.addLayout(grid)
