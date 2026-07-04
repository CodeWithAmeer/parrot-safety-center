#!/usr/bin/env python3
"""Compatibility launcher for running the source tree directly."""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from parrot_safety_center.app import main


if __name__ == "__main__":
    main()
