import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from PySide6.QtWidgets import QApplication, QLabel, QHBoxLayout, QWidget

from parrot_safety_center.widgets import PageBase


def _app():
    return QApplication.instance() or QApplication([])


def test_clear_content_removes_widgets_from_nested_layouts():
    app = _app()
    page = PageBase("Test")

    nested = QHBoxLayout()
    nested.addWidget(QLabel("old one"))
    nested.addWidget(QLabel("old two"))
    page.content_layout.addLayout(nested)
    page.content_layout.addStretch(1)

    assert len(page.content.findChildren(QLabel)) == 2
    page.clear_content()
    app.processEvents()

    assert page.content_layout.count() == 0
    assert page.content.findChildren(QLabel) == []


def test_repeated_render_does_not_stack_old_widgets():
    app = _app()
    page = PageBase("Test")

    def render_once():
        page.clear_content()
        row = QHBoxLayout()
        row.addWidget(QLabel("fresh one"))
        row.addWidget(QLabel("fresh two"))
        page.content_layout.addLayout(row)

    render_once()
    first_count = len(page.content.findChildren(QWidget))
    render_once()
    app.processEvents()
    second_count = len(page.content.findChildren(QWidget))

    assert first_count == second_count == 2
