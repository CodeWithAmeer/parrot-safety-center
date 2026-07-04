

import os
import sys
import re
import json
import shutil
import subprocess
import platform
import getpass
import grp
import pwd
import socket
import time
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass

try:
    from PySide6.QtCore import Qt, QObject, Signal, QRunnable, QThreadPool, QSize
    from PySide6.QtGui import QFont, QAction, QColor, QIcon, QPixmap, QPainter
    from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QPushButton, QFrame, QScrollArea, QListWidget, QListWidgetItem, QStackedWidget, QMessageBox, QProgressBar, QSizePolicy, QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView, QDialog, QDialogButtonBox, QFileDialog, QLineEdit, QComboBox, QAbstractItemView, QCheckBox, QSystemTrayIcon, QMenu
except Exception as exc:
    print("PySide6 is required to run Parrot Safety Center.")
    print("Install PySide6 using your trusted distribution package manager or Python environment, then start the app again.")
    print(f"Import error: {exc}")
    sys.exit(1)

APP_NAME = "Parrot Safety Center"
APP_VERSION = "1.0.0"
APP_TITLE = f"{APP_NAME} v{APP_VERSION}"
CREATOR = "CodeWithAmeer"
LICENSE = "Apache-2.0"
TEAL = "#22d3c5"
GREEN = "#7ee787"
BLUE = "#58a6ff"
YELLOW = "#f2cc60"
RED = "#ff7b72"
PURPLE = "#c792ea"
ORANGE = "#ffb86c"
BG = "#071114"
BG_2 = "#09161a"
PANEL = "#0d1b20"
PANEL_2 = "#10252b"
PANEL_3 = "#132f37"
BORDER = "#1f3b43"
TEXT = "#e6edf3"
MUTED = "#9fb3bd"
DARK_BLUE = "#0b172d"
GUI_FIELD_LIMIT = 20000
REPORT_FIELD_LIMIT = 50000
MAX_JOURNAL_LINES = 300
MAX_DMESG_LINES = 200
THREADPOOL_MAX = 3
FORBIDDEN_COMMAND_PATTERNS = [
    "apt update", "apt upgrade", "apt full-upgrade", "apt install", "apt remove", "apt purge", "dpkg -i",
    "ufw enable", "ufw disable", "ufw reset", "firewall-cmd --permanent", "nft add", "nft delete", "nft flush",
    "timeshift --create", "timeshift --restore", "snapper create", "snapper rollback", "btrfs subvolume delete",
    "dmesg --clear", "dmesg --read-clear", "pkexec", "sudo"
]

SENSITIVE_KEYS = "password|passwd|token|apikey|api_key|secret|auth|credential|bearer|authorization"
